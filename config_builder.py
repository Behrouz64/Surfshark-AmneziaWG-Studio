"""
config_builder.py: Generator for AmneziaWG Obfuscated Configurations & QR Codes

Formats WireGuard / AmneziaWG .conf files with obfuscation headers:
  [Interface]
  PrivateKey = ...
  Address = ...
  DNS = ...
  Jc = 4
  Jmin = 50
  Jmax = 1000
  S1 = 0
  S2 = 0
  H1 = 1
  H2 = 2
  H3 = 3
  H4 = 4

  [Peer]
  PublicKey = ...
  AllowedIPs = 0.0.0.0/0, ::/0
  Endpoint = <VERIFIED_RAW_IP>:51820
  PersistentKeepalive = 25

Supports:
- AmneziaWG and Standard WireGuard formats.
- Mobile import QR Code generation (Base64 data URL for Flet GUI).
- Batch Export to structured .ZIP archive with Country/City directory hierarchy.
"""

from __future__ import annotations

import base64
import io
import json
import logging
import os
import plistlib
import re
import shutil
import subprocess
import time
import urllib.parse
import uuid
import zipfile
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

try:
    import qrcode
    from PIL import Image
    _QR_AVAILABLE = True
except ImportError:
    _QR_AVAILABLE = False


def country_code_to_flag(country_code: str) -> str:
    """
    Converts an ISO 3166-1 alpha-2 country code to a flag emoji.
    Works by mapping each letter to a Unicode Regional Indicator Symbol.
    Example: 'GB' → '🇬🇧',  'US' → '🇺🇸',  'DE' → '🇩🇪'
    """
    try:
        code = country_code.strip().upper()[:2]
        if len(code) != 2 or not code.isalpha():
            return "🌐"
        return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code)
    except Exception:
        return "🌐"


def sanitize_filename_simple(name: str) -> str:
    """Simple replacement for path components — used internally by flag folder builder."""
    return re.sub(r'[\\/:*?"<>|]', "_", name).replace(" ", "_")


@dataclass
class AmneziaParams:
    jc: int = 4
    jmin: int = 50
    jmax: int = 1000
    s1: int = 0
    s2: int = 0
    h1: int = 1
    h2: int = 2
    h3: int = 3
    h4: int = 4

    @classmethod
    def iran_preset(cls) -> AmneziaParams:
        """Standard Iran censorship evasion preset."""
        return cls(jc=4, jmin=50, jmax=1000, s1=0, s2=0, h1=1, h2=2, h3=3, h4=4)

    @classmethod
    def aggressive_preset(cls) -> AmneziaParams:
        """Aggressive obfuscation preset with randomized payload padding."""
        return cls(jc=7, jmin=100, jmax=1200, s1=15, s2=15, h1=1000000001, h2=1000000002, h3=1000000003, h4=1000000004)

    @classmethod
    def standard_wireguard(cls) -> AmneziaParams:
        """Vanilla WireGuard (no obfuscation injection)."""
        return cls(jc=0, jmin=0, jmax=0, s1=0, s2=0, h1=1, h2=2, h3=3, h4=4)


def sanitize_filename(name: str) -> str:
    """Sanitizes strings for safe cross-platform folder and file paths."""
    clean = re.sub(r'[\\/*?:"<>| ]+', "_", name.strip())
    return clean.strip("._") or "server"


def derive_public_key(private_key_b64: str) -> Optional[str]:
    """
    Derives the standard Curve25519 WireGuard public key from a Base64 private key.
    Allows users to verify that their entered PrivateKey matches the PublicKey in Surfshark.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import x25519
        raw_priv = base64.b64decode(private_key_b64.strip())
        if len(raw_priv) != 32:
            return None
        priv = x25519.X25519PrivateKey.from_private_bytes(raw_priv)
        pub = priv.public_key()
        return base64.b64encode(pub.public_bytes_raw()).decode("utf-8")
    except Exception:
        return None


def is_valid_wg_key(key: str) -> bool:
    """
    Returns True if the key is a syntactically valid Base64-encoded 32-byte WireGuard key.
    Does NOT verify cryptographic validity — only format.
    """
    try:
        if not key or len(key.strip()) != 44 or not key.strip().endswith("="):
            return False
        decoded = base64.b64decode(key.strip())
        return len(decoded) == 32
    except Exception:
        return False


def build_amnezia_config(
    client_private_key: str,
    client_address: str,
    client_dns: str,
    server_public_key: str,
    endpoint_ip: str,
    endpoint_port: int = 51820,
    allowed_ips: str = "0.0.0.0/0, ::/0",
    persistent_keepalive: int = 25,
    amnezia_params: Optional[AmneziaParams] = None,
    server_preshared_key: Optional[str] = None,
    tunnel_name: Optional[str] = None,
    provider: str = "surfshark",
    netshield_level: Optional[int] = None,
    moderate_nat: Optional[bool] = None,
    nat_pmp: Optional[bool] = None,
    vpn_accelerator: Optional[bool] = None,
    routing_mode: Optional[str] = None,
) -> str:
    """
    Constructs a complete AmneziaWG configuration (.conf) file string.

    tunnel_name: Optional display name (e.g. '🇬🇧 UK — London | 82ms').
      Written as a '# Name = ...' comment, which is read by WireGuard iOS/Android
      and AmneziaWG clients to set the tunnel display name.
      Also written as a '# Tunnel: ...' description in the [Interface] block.
    """
    params = amnezia_params or AmneziaParams.iran_preset()

    # Validation: detect obviously invalid keys and prepend warning comments
    header_comments = []
    if not is_valid_wg_key(client_private_key):
        header_comments.append("# ⚠️ WARNING: PrivateKey format looks invalid. Get it from Surfshark or Proton VPN settings.")
    if not is_valid_wg_key(server_public_key):
        header_comments.append("# ⚠️ WARNING: Server PublicKey is not set or invalid. Use 'Fetch Real Keys' button or import a working .conf.")

    # Name header — read by WireGuard iOS/Android app as the tunnel display name
    # Format: "# Name = <tunnel_name>" must be the FIRST non-empty line for some clients
    if tunnel_name:
        name_lines = [
            f"# Name = {tunnel_name}",
            f"# Generated by Surfshark & Proton AmneziaWG Studio v5",
        ] + header_comments
    else:
        name_lines = ["# Generated by Surfshark & Proton AmneziaWG Studio v5"] + header_comments

    interface_lines = [
        "[Interface]",
    ]
    if provider == "proton" or netshield_level is not None:
        interface_lines.extend([
            f"# Routing = {(routing_mode or 'Standard').capitalize()}",
            f"# Bouncing = 10",
            f"# NetShield = {1 if netshield_level is None else netshield_level}",
            f"# Moderate NAT = {'on' if moderate_nat else 'off'}",
            f"# NAT-PMP (Port Forwarding) = {'on' if nat_pmp else 'off'}",
            f"# VPN Accelerator = {'off' if vpn_accelerator is False else 'on'}",
        ])
    interface_lines.extend([
        f"PrivateKey = {client_private_key.strip()}",
        f"Address = {client_address.strip()}",
        f"DNS = {client_dns.strip()}",
    ])

    lines = name_lines + interface_lines

    # Inject AmneziaWG obfuscation parameters if Jc > 0 or S/H params customized
    if params.jc > 0 or params.s1 > 0 or params.s2 > 0 or params.h1 != 1:
        lines.extend([
            f"Jc = {params.jc}",
            f"Jmin = {params.jmin}",
            f"Jmax = {params.jmax}",
            f"S1 = {params.s1}",
            f"S2 = {params.s2}",
            f"H1 = {params.h1}",
            f"H2 = {params.h2}",
            f"H3 = {params.h3}",
            f"H4 = {params.h4}",
        ])

    lines.append("")
    lines.append("[Peer]")
    lines.append(f"PublicKey = {server_public_key.strip()}")

    if server_preshared_key and server_preshared_key.strip():
        lines.append(f"PresharedKey = {server_preshared_key.strip()}")

    lines.append(f"AllowedIPs = {allowed_ips.strip()}")
    lines.append(f"Endpoint = {endpoint_ip.strip()}:{endpoint_port}")

    if persistent_keepalive > 0:
        lines.append(f"PersistentKeepalive = {persistent_keepalive}")

    lines.append("")
    return "\n".join(lines)



def generate_qr_code_base64(conf_text: str) -> Optional[str]:
    """
    Generates a high-contrast QR Code PNG image of the configuration
    and returns it as a Base64-encoded string suitable for Flet ft.Image(src_base64=...).
    """
    if not _QR_AVAILABLE:
        return None

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=6,
        border=3,
    )
    qr.add_data(conf_text.strip())
    qr.make(fit=True)

    img = qr.make_image(fill_color="#000000", back_color="#FFFFFF")
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_b64 = base64.b64encode(buffered.getvalue()).decode("utf-8")
    return img_b64


def generate_batch_zip(
    server_configs: List[dict],
    user_interface: dict,
    amnezia_params: Optional[AmneziaParams] = None,
    output_path: Optional[str] = None,
    provider: str = "surfshark",
    netshield_level: Optional[int] = None,
    moderate_nat: Optional[bool] = None,
    nat_pmp: Optional[bool] = None,
    vpn_accelerator: Optional[bool] = None,
    routing_mode: Optional[str] = None,
) -> bytes:
    """
    Generates a structured ZIP archive with configs organized by Country/City folders.
    Filenames and config headers include flag emoji, country, city, and latency.

    Example structure:
      🇩🇪 Germany/
        🇩🇪 Berlin — 185.220.101.5 — 78ms.conf
        🇩🇪 Berlin — DOMAIN — de-ber.prod.surfshark.com.conf
      🇺🇸 United States/
        🇺🇸 New York — 198.51.100.2 — 142ms.conf
      README.txt

    `server_configs` is a list of dicts with:
      - 'country': str
      - 'country_code': str (optional, for flag emoji — e.g. 'GB')
      - 'city': str
      - 'hostname': str
      - 'public_key': str
      - 'endpoint_ip': str
      - 'port': int
      - 'latency_ms': float (optional)

    Returns raw zip bytes, and optionally saves to output_path.
    """
    params = amnezia_params or AmneziaParams.iran_preset()
    priv_key = user_interface.get("private_key", "REPLACE_WITH_YOUR_PRIVATE_KEY")
    addr = user_interface.get("address", "10.14.0.2/16" if provider != "proton" else "10.2.0.2/32")
    dns = user_interface.get("dns", "162.252.172.57, 149.154.159.92" if provider != "proton" else "10.2.0.1")

    zip_buffer = io.BytesIO()

    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        # Add informative README
        prov_title = "Proton VPN" if provider == "proton" else "Surfshark"
        readme_content = (
            "=================================================================\n"
            f"{prov_title} AmneziaWG Obfuscated Configurations (Restricted Networks)\n"
            "=================================================================\n\n"
            f"Generated with Obfuscation Parameters:\n"
            f"  Jc: {params.jc} (Junk packet count)\n"
            f"  Jmin: {params.jmin} bytes\n"
            f"  Jmax: {params.jmax} bytes\n"
            f"  S1: {params.s1}, S2: {params.s2}\n"
            f"  H1: {params.h1}, H2: {params.h2}, H3: {params.h3}, H4: {params.h4}\n\n"
            "How to Use:\n"
            "1. Download and install the Amnezia VPN / AmneziaWG Client:\n"
            "   Desktop & Mobile: https://amnezia.org/ or https://github.com/amnezia-vpn/amnezia-client\n"
            "2. In Amnezia, choose 'Add Connection' -> 'Import configuration file or text' -> select any .conf file.\n"
            "3. The tunnel name shown in the client comes from the filename (e.g. '🇬🇧 London — 82ms').\n"
            "4. Raw IP endpoints bypass DNS poisoning, junk packet injection evades DPI filters.\n"
        )
        zf.writestr("README.txt", readme_content)

        seen_filenames: set = set()
        for s in server_configs:
            raw_country = s.get("country", "Unknown")
            raw_city = s.get("city", "Cluster")
            country_code = s.get("country_code", "")
            ip = s.get("endpoint_ip", "0.0.0.0")
            port = s.get("port", 51820)
            pub_key = s.get("public_key", "")
            psk = s.get("preshared_key", None)
            latency = s.get("latency_ms", None)

            # Build flag emoji from country_code
            flag = country_code_to_flag(country_code) if country_code else "🌐"

            is_domain = s.get("is_domain", False) or (ip == s.get("hostname")) or not re.match(r'^\d+\.\d+\.\d+\.\d+$', str(ip))
            latency_tag = f" — {int(latency)}ms" if latency and latency < 9000 and not is_domain else ""

            # Human-readable tunnel name (shown in WireGuard client as tunnel name)
            if is_domain:
                tunnel_name = f"{flag} {raw_city} ({raw_country}) — Domain"
            else:
                tunnel_name = f"{flag} {raw_city} ({raw_country}){latency_tag}"

            conf_str = build_amnezia_config(
                client_private_key=priv_key,
                client_address=addr,
                client_dns=dns,
                server_public_key=pub_key,
                endpoint_ip=ip,
                endpoint_port=port,
                amnezia_params=params,
                server_preshared_key=psk,
                tunnel_name=tunnel_name,
                provider=provider,
                netshield_level=netshield_level,
                moderate_nat=moderate_nat,
                nat_pmp=nat_pmp,
                vpn_accelerator=vpn_accelerator,
                routing_mode=routing_mode,
            )

            # Folder name: "🇬🇧 United_Kingdom"
            folder = sanitize_filename(f"{flag} {raw_country}")
            city_safe = sanitize_filename(raw_city)
            ip_safe = sanitize_filename(str(ip))

            if is_domain:
                base_name = f"{flag} {city_safe} — DOMAIN — {ip_safe}"
            else:
                lat_part = f" — {int(latency)}ms" if latency and latency < 9000 else ""
                base_name = f"{flag} {city_safe} — {ip_safe}{lat_part}"

            filename = f"{folder}/{base_name}.conf"

            # Avoid filename collisions
            counter = 1
            while filename in seen_filenames:
                if is_domain:
                    filename = f"{folder}/{base_name}_{counter}.conf"
                else:
                    filename = f"{folder}/{base_name}_{counter}.conf"
                counter += 1
            seen_filenames.add(filename)

            zf.writestr(filename, conf_str)

    zip_bytes = zip_buffer.getvalue()

    if output_path:
        with open(output_path, "wb") as f:
            f.write(zip_bytes)

    return zip_bytes


def build_shadowrocket_wg_url(
    server_info: dict,
    user_interface: dict,
    amnezia_params: Optional[AmneziaParams] = None,
    *,
    title_prefix: str = "🦈 ",
    show_latency: bool = True,
) -> str:
    """
    Constructs an AmneziaWG-compatible `wg://` URI for Shadowrocket Local Servers.
    Format:
      wg://{host}:{port}?publicKey={pubKey}&privateKey={privKey}&ip={ip}&dns={dns}&mtu=1280&udp=1&obfs=amneziawg&obfsParam={json_url_encoded}#{title}

    Matches exact schema of working WireGuard servers in Shadowrocket:
    - Clean IP address without CIDR mask (e.g. '10.14.0.2', not '10.14.0.2/16')
    - Lowercase obfsParam keys, in the order of the reference export: jc, jmin, jmax, s1, s2, h1..h4
    - String values inside obfsParam, e.g. {"jc":"4",...}

    The phone app passes show_latency=False so the title has no ping. The shark prefix stays
    on both, and title_prefix can be set to "" for a title without it.
    """
    params = amnezia_params or AmneziaParams.iran_preset()
    priv_key = user_interface.get("private_key", "").strip()
    addr = user_interface.get("address", "10.14.0.2").strip()
    clean_ip = addr.split("/")[0].strip() if "/" in addr else addr
    dns = user_interface.get("dns", "162.252.172.57, 149.154.159.92").strip()

    endpoint = server_info.get("endpoint_ip") or server_info.get("hostname", "0.0.0.0")
    port = server_info.get("port", 51820)
    pub_key = server_info.get("public_key", "").strip()
    psk = server_info.get("preshared_key")

    raw_country = server_info.get("country", "Unknown")
    raw_city = server_info.get("city", "Cluster")
    country_code = server_info.get("country_code", "")
    flag = country_code_to_flag(country_code) if country_code else "🌐"
    is_domain = server_info.get("is_domain", False)
    latency = server_info.get("latency_ms")
    lat_tag = f" — {int(latency)}ms" if show_latency and latency and latency < 9000 and not is_domain else ""
    title = f"{title_prefix}{flag} {raw_country} — {raw_city} ({endpoint}){lat_tag}"

    # Build obfsParam JSON structure recognized by Shadowrocket DLWAmneziaWGSettings.
    # Lowercase keys in the reference order; the values are strings, as in the reference export.
    obfs_dict = {
        "jc": str(params.jc),
        "jmin": str(params.jmin),
        "jmax": str(params.jmax),
        "s1": str(params.s1),
        "s2": str(params.s2),
        "h1": str(params.h1),
        "h2": str(params.h2),
        "h3": str(params.h3),
        "h4": str(params.h4),
    }
    obfs_json = json.dumps(obfs_dict, separators=(",", ":"))
    obfs_param_encoded = urllib.parse.quote(obfs_json)

    query_parts = [
        f"publicKey={urllib.parse.quote(pub_key)}",
        f"privateKey={urllib.parse.quote(priv_key)}",
        f"ip={urllib.parse.quote(clean_ip)}",
        f"dns={urllib.parse.quote(dns)}",
        "mtu=1280",
        "udp=1",
        "keepalive=25",
        "obfs=amneziawg",
        f"obfsParam={obfs_param_encoded}",
    ]
    if psk and psk.strip():
        query_parts.append(f"presharedKey={urllib.parse.quote(psk.strip())}")

    query_str = "&".join(query_parts)
    title_fragment = urllib.parse.quote(title)
    return f"wg://{endpoint}:{port}?{query_str}#{title_fragment}"


def generate_shadowrocket_batch_conf(
    server_configs: List[dict],
    user_interface: dict,
    amnezia_params: Optional[AmneziaParams] = None,
    output_path: Optional[str] = None,
    provider: str = "surfshark",
    netshield_level: Optional[int] = None,
    moderate_nat: Optional[bool] = None,
    nat_pmp: Optional[bool] = None,
    vpn_accelerator: Optional[bool] = None,
    routing_mode: Optional[str] = None,
) -> str:
    """
    Generates a unified WireGuard / AmneziaWG configuration file (.conf)
    containing [Interface] with Iran Balanced AmneziaWG obfuscation headers,
    followed by multiple [Peer] sections (one per server).

    Shadowrocket's `+[DLWServer parseWireGuardIni:]` natively parses this file, extracts
    the AmneziaWG parameters, and generates an individual proxy server entry for
    every [Peer] block.
    """
    params = amnezia_params or AmneziaParams.iran_preset()
    priv_key = user_interface.get("private_key", "").strip()
    addr = user_interface.get("address", "10.14.0.2/16" if provider != "proton" else "10.2.0.2/32").strip()
    dns = user_interface.get("dns", "162.252.172.57, 149.154.159.92" if provider != "proton" else "10.2.0.1").strip()

    prov_title = "Proton VPN" if provider == "proton" else "Surfshark"
    lines = [
        "# =================================================================",
        f"# {prov_title} AmneziaWG Master Configuration for Shadowrocket",
        f"# Obfuscation Preset: Iran Balanced (Jc={params.jc}, Jmin={params.jmin}, Jmax={params.jmax}, S1={params.s1}, S2={params.s2}, H1={params.h1}..H4={params.h4})",
        "# =================================================================",
        "",
        "[Interface]",
    ]
    if provider == "proton" or netshield_level is not None:
        lines.extend([
            f"# Routing = {(routing_mode or 'Standard').capitalize()}",
            f"# Bouncing = 10",
            f"# NetShield = {1 if netshield_level is None else netshield_level}",
            f"# Moderate NAT = {'on' if moderate_nat else 'off'}",
            f"# NAT-PMP (Port Forwarding) = {'on' if nat_pmp else 'off'}",
            f"# VPN Accelerator = {'off' if vpn_accelerator is False else 'on'}",
        ])
    lines.extend([
        f"PrivateKey = {priv_key}",
        f"Address = {addr}",
        f"DNS = {dns}",
    ])

    if params.jc > 0 or params.s1 > 0 or params.s2 > 0 or params.h1 != 1:
        lines.extend([
            f"Jc = {params.jc}",
            f"Jmin = {params.jmin}",
            f"Jmax = {params.jmax}",
            f"S1 = {params.s1}",
            f"S2 = {params.s2}",
            f"H1 = {params.h1}",
            f"H2 = {params.h2}",
            f"H3 = {params.h3}",
            f"H4 = {params.h4}",
        ])

    lines.append("")

    for s in server_configs:
        raw_country = s.get("country", "Unknown")
        raw_city = s.get("city", "Cluster")
        country_code = s.get("country_code", "")
        flag = country_code_to_flag(country_code) if country_code else "🌐"
        ip = s.get("endpoint_ip") or s.get("hostname", "0.0.0.0")
        port = s.get("port", 51820)
        pub_key = s.get("public_key", "").strip()
        psk = s.get("preshared_key")
        latency = s.get("latency_ms")
        is_domain = s.get("is_domain", False)
        lat_tag = f" — {int(latency)}ms" if latency and latency < 9000 and not is_domain else ""
        peer_name = f"🦈 {flag} {raw_country} — {raw_city} ({ip}){lat_tag}"

        lines.extend([
            "[Peer]",
            f"# Name = {peer_name}",
            f"PublicKey = {pub_key}",
            f"Endpoint = {ip}:{port}",
            "AllowedIPs = 0.0.0.0/0, ::/0",
            "PersistentKeepalive = 25",
        ])
        if psk and psk.strip():
            lines.append(f"PresharedKey = {psk.strip()}")
        lines.append("")

    content = "\n".join(lines)
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
    return content


def generate_shadowrocket_subscription(
    server_configs: List[dict],
    user_interface: dict,
    amnezia_params: Optional[AmneziaParams] = None,
) -> Tuple[str, str]:
    """
    Generates Shadowrocket subscription format:
    Returns (raw_text_links, base64_subscription).
    Each line of raw_text_links is a `wg://...` URL.
    base64_subscription is the Base64-encoded string suitable for direct import
    into Shadowrocket via subscription or clipboard.
    """
    urls = []
    for s in server_configs:
        url = build_shadowrocket_wg_url(s, user_interface, amnezia_params)
        urls.append(url)
    raw_text = "\n".join(urls)
    b64_sub = base64.b64encode(raw_text.encode("utf-8")).decode("utf-8")
    return raw_text, b64_sub


def export_shadowrocket_bundle(
    server_configs: List[dict],
    user_interface: dict,
    amnezia_params: Optional[AmneziaParams] = None,
    output_dir: Optional[str] = None,
    provider: str = "surfshark",
    netshield_level: Optional[int] = None,
    moderate_nat: Optional[bool] = None,
    nat_pmp: Optional[bool] = None,
    vpn_accelerator: Optional[bool] = None,
    routing_mode: Optional[str] = None,
) -> dict:
    """
    Exports a complete Shadowrocket package:
    1. {Provider}_Shadowrocket_IranBalanced.conf (Unified multi-peer configuration)
    2. Shadowrocket_Subscription_Base64.txt (Base64 subscription content)
    3. Shadowrocket_Links_Raw.txt (Raw wg:// URLs)
    4. Individual .conf files in an `Individual_Configs` subfolder
    Returns a dict with paths and summary counts.
    """
    params = amnezia_params or AmneziaParams.iran_preset()
    base_dir = output_dir or os.path.expanduser("~/Downloads")
    try:
        os.makedirs(base_dir, exist_ok=True)
        test_file = os.path.join(base_dir, ".test_write")
        with open(test_file, "w") as f:
            f.write("1")
        os.remove(test_file)
    except Exception:
        base_dir = os.getcwd()

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    prov_name = "Proton" if provider == "proton" else "Surfshark"
    folder_name = f"{prov_name}_Shadowrocket_{timestamp}"
    bundle_path = os.path.join(base_dir, folder_name)
    os.makedirs(bundle_path, exist_ok=True)

    # 1. Master multi-peer .conf file
    master_conf_path = os.path.join(bundle_path, f"{prov_name}_Shadowrocket_IranBalanced.conf")
    master_conf = generate_shadowrocket_batch_conf(
        server_configs,
        user_interface,
        params,
        master_conf_path,
        provider=provider,
        netshield_level=netshield_level,
        moderate_nat=moderate_nat,
        nat_pmp=nat_pmp,
        vpn_accelerator=vpn_accelerator,
        routing_mode=routing_mode,
    )

    # 2. Subscription files (both raw wg:// URLs and Base64 subscription)
    raw_sub, b64_sub = generate_shadowrocket_subscription(server_configs, user_interface, params)
    sub_b64_path = os.path.join(bundle_path, "Shadowrocket_Subscription_Base64.txt")
    with open(sub_b64_path, "w", encoding="utf-8") as f:
        f.write(b64_sub)

    sub_urls_path = os.path.join(bundle_path, "Shadowrocket_Links_Raw.txt")
    with open(sub_urls_path, "w", encoding="utf-8") as f:
        f.write(raw_sub)

    # 3. Individual .conf files in subfolder
    indiv_dir = os.path.join(bundle_path, "Individual_Configs")
    os.makedirs(indiv_dir, exist_ok=True)
    priv_key = user_interface.get("private_key", "").strip()
    addr = user_interface.get("address", "10.14.0.2/16" if provider != "proton" else "10.2.0.2/32").strip()
    dns = user_interface.get("dns", "162.252.172.57, 149.154.159.92" if provider != "proton" else "10.2.0.1").strip()

    seen = set()
    for s in server_configs:
        raw_country = s.get("country", "Unknown")
        raw_city = s.get("city", "Cluster")
        country_code = s.get("country_code", "")
        flag = country_code_to_flag(country_code) if country_code else "🌐"
        ip = s.get("endpoint_ip") or s.get("hostname", "0.0.0.0")
        port = s.get("port", 51820)
        pub_key = s.get("public_key", "").strip()
        psk = s.get("preshared_key")
        latency = s.get("latency_ms")
        is_domain = s.get("is_domain", False)
        lat_tag = f"_{int(latency)}ms" if latency and latency < 9000 and not is_domain else ""
        c_name = sanitize_filename(f"{country_code}_{raw_city}_{ip}{lat_tag}")
        fname = f"{c_name}.conf"
        cnt = 1
        while fname in seen:
            fname = f"{c_name}_{cnt}.conf"
            cnt += 1
        seen.add(fname)
        fpath = os.path.join(indiv_dir, fname)
        single_conf = build_amnezia_config(
            client_private_key=priv_key,
            client_address=addr,
            client_dns=dns,
            server_public_key=pub_key,
            endpoint_ip=ip,
            endpoint_port=port,
            amnezia_params=params,
            server_preshared_key=psk,
            tunnel_name=f"{flag} {raw_country} — {raw_city} ({ip})",
            provider=provider,
            netshield_level=netshield_level,
            moderate_nat=moderate_nat,
            nat_pmp=nat_pmp,
            vpn_accelerator=vpn_accelerator,
            routing_mode=routing_mode,
        )
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(single_conf)

    # 4. Generate structured ZIP archive
    zip_path = f"{bundle_path}.zip"
    try:
        shutil.make_archive(bundle_path, "zip", bundle_path)
    except Exception:
        zip_path = None

    return {
        "bundle_dir": bundle_path,
        "zip_path": zip_path,
        "master_conf_path": master_conf_path,
        "subscription_b64_path": sub_b64_path,
        "subscription_raw_path": sub_urls_path,
        "raw_subscription_text": raw_sub,
        "b64_subscription_text": b64_sub,
        "server_count": len(server_configs),
    }


# =============================================================================
# Shadowrocket Native Storage (Local Servers) Injector
# =============================================================================

class ShadowrocketStorage:
    """
    Direct reader and writer for Shadowrocket's macOS Group Container database:
    ~/Library/Group Containers/group.com.liguangming.Shadowrocket/ServerManager

    This binary plist (NSKeyedArchiver) stores the 'Local Servers' shown on the Home screen.
    """
    DEFAULT_STORAGE_PATH = os.path.expanduser(
        "~/Library/Group Containers/group.com.liguangming.Shadowrocket/ServerManager"
    )

    def __init__(self, plist_path: Optional[str] = None):
        self.plist_path = plist_path or self.DEFAULT_STORAGE_PATH
        if not os.path.exists(self.plist_path):
            raise FileNotFoundError(f"Shadowrocket ServerManager not found at {self.plist_path}")
        with open(self.plist_path, "rb") as f:
            self.raw_data = plistlib.loads(f.read())
        self.objects = self.raw_data.get("$objects", [])
        self.class_uids: Dict[str, plistlib.UID] = {}
        for i, obj in enumerate(self.objects):
            if isinstance(obj, dict) and "$classname" in obj:
                self.class_uids[obj["$classname"]] = plistlib.UID(i)
        self._ensure_classes()

    def _ensure_classes(self):
        needed = {
            "NSMutableString": ["NSMutableString", "NSString", "NSObject"],
            "NSDictionary": ["NSDictionary", "NSObject"],
            "NSDate": ["NSDate", "NSObject"],
            "DLWServer": ["DLWServer", "NSObject"],
            "NSMutableArray": ["NSMutableArray", "NSArray", "NSObject"],
        }
        for name, classes in needed.items():
            if name not in self.class_uids:
                obj = {"$classname": name, "$classes": classes}
                self.objects.append(obj)
                self.class_uids[name] = plistlib.UID(len(self.objects) - 1)

    def intern_object(self, val) -> plistlib.UID:
        """Reuses existing primitive object or appends to objects list."""
        for i, obj in enumerate(self.objects):
            if type(obj) is type(val) and obj == val:
                return plistlib.UID(i)
        self.objects.append(val)
        return plistlib.UID(len(self.objects) - 1)

    def add_ns_string(self, text: str) -> plistlib.UID:
        obj = {"$class": self.class_uids["NSMutableString"], "NS.string": text}
        self.objects.append(obj)
        return plistlib.UID(len(self.objects) - 1)

    def add_ns_date(self, apple_timestamp: float) -> plistlib.UID:
        obj = {"$class": self.class_uids["NSDate"], "NS.time": apple_timestamp}
        self.objects.append(obj)
        return plistlib.UID(len(self.objects) - 1)

    def get_empty_dict_uid(self) -> plistlib.UID:
        for i, obj in enumerate(self.objects):
            if isinstance(obj, dict) and obj.get("NS.keys") == [] and obj.get("NS.objects") == []:
                return plistlib.UID(i)
        obj = {"NS.keys": [], "NS.objects": [], "$class": self.class_uids["NSDictionary"]}
        self.objects.append(obj)
        return plistlib.UID(len(self.objects) - 1)

    def get_server_uids(self) -> list:
        if len(self.objects) > 1 and isinstance(self.objects[1], dict):
            return self.objects[1].get("NS.objects", [])
        return []

    def get_existing_server_keys(self) -> set:
        """Returns set of (host, port) for existing servers to prevent duplicate additions."""
        existing = set()
        for suid in self.get_server_uids():
            if isinstance(suid, plistlib.UID) and suid.data < len(self.objects):
                s = self.objects[suid.data]
                if isinstance(s, dict):
                    host_uid = s.get("host")
                    port_uid = s.get("port")
                    host = self.objects[host_uid.data] if isinstance(host_uid, plistlib.UID) else str(host_uid)
                    port = self.objects[port_uid.data] if isinstance(port_uid, plistlib.UID) else str(port_uid)
                    existing.add((str(host), str(port)))
        return existing

    def create_dlw_server(
        self,
        host: str,
        port: str,
        country_code: str,
        client_ip: str,
        dns: str,
        public_key: str,
        private_key: str,
        amnezia_params: AmneziaParams,
        ping: int = 0,
    ) -> dict:
        now_apple = time.time() - 978307200.0  # Apple reference epoch 2001-01-01
        created_uid = self.add_ns_date(now_apple)
        updated_uid = self.add_ns_date(now_apple)
        uuid_uid = self.add_ns_string(str(uuid.uuid4()).upper())
        ip_uid = self.add_ns_string(client_ip)

        obfs_dict = {
            "s1": str(amnezia_params.s1),
            "h2": str(amnezia_params.h2),
            "jmax": str(amnezia_params.jmax),
            "s2": str(amnezia_params.s2),
            "h3": str(amnezia_params.h3),
            "jc": str(amnezia_params.jc),
            "jmin": str(amnezia_params.jmin),
            "h1": str(amnezia_params.h1),
            "h4": str(amnezia_params.h4),
        }
        obfs_json = json.dumps(obfs_dict, separators=(",", ":"))
        empty_dict_uid = self.get_empty_dict_uid()

        flag = (country_code or "UN").upper()[:2]

        return {
            "$class": self.class_uids["DLWServer"],
            "allowInsecure": self.intern_object(0),
            "created": created_uid,
            "dns": self.intern_object(dns),
            "fails": self.intern_object(0),
            "flag": self.intern_object(flag),
            "folded": self.intern_object(False),
            "h2": self.intern_object(False),
            "host": self.intern_object(host),
            "ip": ip_uid,
            "mux": self.intern_object(False),
            "obfs": self.intern_object("amneziawg"),
            "obfsParam": self.intern_object(obfs_json),
            "ota": self.intern_object(False),
            "padding": self.intern_object(False),
            "ping": self.intern_object(ping),
            "pluginParam": empty_dict_uid,
            "port": self.intern_object(str(port)),
            "privateKey": self.intern_object(private_key),
            "publicKey": self.intern_object(public_key),
            "tfo": self.intern_object(0),
            "tls": self.intern_object(False),
            "type": self.intern_object("WireGuard"),
            "udp": self.intern_object(1),
            "uot": self.intern_object(0),
            "updated": updated_uid,
            "uuid": uuid_uid,
            "weight": self.intern_object(int(time.time())),
            "xtls": self.intern_object(0),
        }

    @staticmethod
    def is_ipv4(host: str) -> bool:
        """Returns True if host is a valid IPv4 address."""
        if not host or not isinstance(host, str):
            return False
        parts = host.strip().split(".")
        if len(parts) != 4:
            return False
        for p in parts:
            if not p.isdigit() or not (0 <= int(p) <= 255):
                return False
        return True

    def purge_failed_and_domain_servers(self, keep_only_working_ips: bool = True) -> dict:
        """
        Prunes all non-IP (subdomain/hostname) servers and/or failed servers from ServerManager.
        If keep_only_working_ips is True, only servers with valid IPv4 and ping > 0 are retained.
        """
        current_uids = self.get_server_uids()
        kept_uids = []
        removed_domains = 0
        removed_failed = 0

        for suid in current_uids:
            if isinstance(suid, plistlib.UID) and suid.data < len(self.objects):
                s = self.objects[suid.data]
                if isinstance(s, dict):
                    host_uid = s.get("host")
                    ping_uid = s.get("ping")
                    host = self.objects[host_uid.data] if isinstance(host_uid, plistlib.UID) else str(host_uid)
                    ping = self.objects[ping_uid.data] if isinstance(ping_uid, plistlib.UID) else int(ping_uid or 0)

                    is_ip = self.is_ipv4(str(host))
                    if not is_ip:
                        removed_domains += 1
                        continue
                    if keep_only_working_ips and (not ping or int(ping) <= 0):
                        removed_failed += 1
                        continue

                    kept_uids.append(suid)

        # CRITICAL SAFETY GUARD:
        # If keep_only_working_ips is True, but NO servers have ping > 0 (kept_uids is empty while total_before > 0),
        # DO NOT WIPE THE DATABASE! Abort immediately to prevent accidental data loss.
        if keep_only_working_ips and len(current_uids) > 0 and len(kept_uids) == 0:
            return {
                "success": False,
                "error": "No active servers with positive ping found in Shadowrocket database. Aborted to prevent accidental server loss.",
                "total_before": len(current_uids),
                "kept_count": len(current_uids),
                "removed_count": 0,
                "removed_domains": 0,
                "removed_failed": 0,
            }

        # Update root NSMutableArray
        if len(self.objects) > 1 and isinstance(self.objects[1], dict):
            self.objects[1]["NS.objects"] = kept_uids

        self.save()

        # Touch notify file
        notify_path = os.path.join(os.path.dirname(self.plist_path), "DLWServerNotify.nosync")
        try:
            with open(notify_path, "a"):
                os.utime(notify_path, None)
        except Exception:
            pass

        return {
            "total_before": len(current_uids),
            "kept_count": len(kept_uids),
            "removed_count": removed_domains + removed_failed,
            "removed_domains": removed_domains,
            "removed_failed": removed_failed,
        }

    def read_test_results(self) -> Dict[str, dict]:
        """
        Reads all servers and their latency / ping test results from ServerManager.
        Returns a dict mapping ip -> {'ping': int, 'flag': str, 'port': int, 'is_reachable': bool}.
        """
        results = {}
        for suid in self.get_server_uids():
            if isinstance(suid, plistlib.UID) and suid.data < len(self.objects):
                s = self.objects[suid.data]
                if isinstance(s, dict):
                    host_uid = s.get("host")
                    ping_uid = s.get("ping")
                    flag_uid = s.get("flag")
                    port_uid = s.get("port")

                    host = self.objects[host_uid.data] if isinstance(host_uid, plistlib.UID) else str(host_uid)
                    ping = self.objects[ping_uid.data] if isinstance(ping_uid, plistlib.UID) else int(ping_uid or 0)
                    flag = self.objects[flag_uid.data] if isinstance(flag_uid, plistlib.UID) else str(flag_uid or "")
                    port = self.objects[port_uid.data] if isinstance(port_uid, plistlib.UID) else str(port_uid or 51820)

                    ping_val = int(ping) if ping is not None else 0
                    results[str(host).strip()] = {
                        "host": str(host).strip(),
                        "port": int(port) if str(port).isdigit() else 51820,
                        "flag": str(flag).strip(),
                        "ping": ping_val,
                        "is_reachable": (ping_val > 0),
                        "is_ip": self.is_ipv4(str(host)),
                    }
        return results

    def update_server_pings(self, ping_map: Dict[str, int]) -> int:
        """
        Updates ping values in ServerManager objects for hosts present in ping_map.
        ping_map: mapping of host/ip -> ping_ms (positive integer, or -1/0 for timeout)
        Returns the count of updated servers.
        """
        updated = 0
        for suid in self.get_server_uids():
            if isinstance(suid, plistlib.UID) and suid.data < len(self.objects):
                s = self.objects[suid.data]
                if isinstance(s, dict):
                    host_uid = s.get("host")
                    host = self.objects[host_uid.data] if isinstance(host_uid, plistlib.UID) else str(host_uid)
                    host_str = str(host).strip()
                    if host_str in ping_map:
                        new_ping = int(ping_map[host_str])
                        self.objects.append(new_ping)
                        s["ping"] = plistlib.UID(len(self.objects) - 1)
                        updated += 1
        if updated > 0:
            self.save()
        return updated

    def add_server(self, server_dict: dict) -> plistlib.UID:
        self.objects.append(server_dict)
        suid = plistlib.UID(len(self.objects) - 1)
        if len(self.objects) > 1 and isinstance(self.objects[1], dict):
            self.objects[1]["NS.objects"].append(suid)
        return suid

    def clear_all_servers(self) -> dict:
        """
        Removes all servers from Shadowrocket's ServerManager.
        Creates a timestamped backup before clearing.
        """
        current_uids = self.get_server_uids()
        total_before = len(current_uids)

        if len(self.objects) > 1 and isinstance(self.objects[1], dict):
            self.objects[1]["NS.objects"] = []

        self.save()

        # Touch notify file
        notify_path = os.path.join(os.path.dirname(self.plist_path), "DLWServerNotify.nosync")
        try:
            with open(notify_path, "a"):
                os.utime(notify_path, None)
        except Exception:
            pass

        return {
            "total_before": total_before,
            "removed_count": total_before,
            "remaining_count": 0,
            "storage_path": self.plist_path,
        }

    def get_storage_stats(self) -> dict:
        """
        Returns summary statistics of servers currently in ServerManager.
        """
        results = self.read_test_results()
        total = len(results)
        working = sum(1 for r in results.values() if r.get("ping", 0) > 0 and r.get("is_ip", False))
        failed = sum(1 for r in results.values() if r.get("ping", 0) <= 0 and r.get("is_ip", False))
        domains = sum(1 for r in results.values() if not r.get("is_ip", False))
        return {
            "total": total,
            "working_ips": working,
            "failed_ips": failed,
            "domain_servers": domains,
            "servers": results,
        }

    def save(self, target_path: Optional[str] = None):
        out_path = target_path or self.plist_path
        if os.path.exists(out_path):
            backup_path = out_path + ".bak"
            try:
                if not os.path.exists(backup_path):
                    shutil.copy2(out_path, backup_path)
                ts_backup = out_path + f".{time.strftime('%Y%m%d_%H%M%S')}.bak"
                shutil.copy2(out_path, ts_backup)
            except Exception:
                pass
        tmp_path = out_path + ".tmp"
        with open(tmp_path, "wb") as f:
            plistlib.dump(self.raw_data, f, fmt=plistlib.FMT_BINARY)
        os.replace(tmp_path, out_path)


def inject_servers_to_shadowrocket_storage(
    server_configs: List[dict],
    user_interface: dict,
    amnezia_params: Optional[AmneziaParams] = None,
    storage_path: Optional[str] = None,
    only_raw_ips: bool = True,
) -> dict:
    """
    Directly injects the given server configurations into Shadowrocket's
    'Local Servers' database on macOS (~/Library/Group Containers/group.com.liguangming.Shadowrocket/ServerManager).

    Safety:
    - Never deletes or overwrites existing user servers.
    - Strictly filters out domain/subdomain endpoints when only_raw_ips=True.
    - Creates a .bak backup before modifying.
    - Deduplicates by (host, port).
    """
    params = amnezia_params or AmneziaParams.iran_preset()
    priv_key = user_interface.get("private_key", "").strip()
    addr = user_interface.get("address", "10.14.0.2").strip()
    clean_ip = addr.split(",")[0].strip().split("/")[0].strip()
    dns = user_interface.get("dns", "162.252.172.57, 149.154.159.92").strip()

    target_path = storage_path or ShadowrocketStorage.DEFAULT_STORAGE_PATH
    if not os.path.exists(target_path):
        return {
            "success": False,
            "error": f"Shadowrocket database not found at {target_path}",
            "added_count": 0,
            "total_count": 0,
        }

    # 1. Create backup
    backup_path = target_path + ".bak"
    try:
        if not os.path.exists(backup_path):
            shutil.copy2(target_path, backup_path)
        # Also create timestamped backup for extra safety
        ts_backup = target_path + f".{time.strftime('%Y%m%d_%H%M%S')}.bak"
        shutil.copy2(target_path, ts_backup)
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to create backup: {e}",
            "added_count": 0,
            "total_count": 0,
        }

    try:
        storage = ShadowrocketStorage(target_path)
        existing_keys = storage.get_existing_server_keys()
        added_count = 0

        for s in server_configs:
            # Enforce raw-IP-only filtering
            if only_raw_ips and s.get("is_domain", False):
                continue

            host = s.get("endpoint_ip") or s.get("hostname", "")
            if only_raw_ips and not ShadowrocketStorage.is_ipv4(host):
                continue

            port = str(s.get("port", 51820))
            if not host:
                continue
            if (host, port) in existing_keys:
                continue

            c_code = s.get("country_code", "UN")
            pub_key = s.get("public_key", "").strip()
            # NEVER pre-populate ping with old/cached latency!
            # All exported servers must start completely fresh/untested (ping=0) in Shadowrocket.
            # This ensures Shadowrocket's own live test determines real connectivity.
            s_dict = storage.create_dlw_server(
                host=host,
                port=port,
                country_code=c_code,
                client_ip=clean_ip,
                dns=dns,
                public_key=pub_key,
                private_key=priv_key,
                amnezia_params=params,
                ping=0,
            )
            storage.add_server(s_dict)
            existing_keys.add((host, port))
            added_count += 1

        storage.save()

        # Touch notify file if present
        notify_path = os.path.join(os.path.dirname(target_path), "DLWServerNotify.nosync")
        try:
            with open(notify_path, "a"):
                os.utime(notify_path, None)
        except Exception:
            pass

        return {
            "success": True,
            "added_count": added_count,
            "total_count": len(storage.get_server_uids()),
            "backup_path": backup_path,
            "storage_path": target_path,
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Failed to inject servers: {e}",
            "added_count": 0,
            "total_count": 0,
        }


def get_shadowrocket_pid() -> Optional[int]:
    """Finds the PID of the running Shadowrocket process on macOS."""
    try:
        ps = subprocess.run(["pgrep", "-f", "Shadowrocket.app"], capture_output=True, text=True)
        lines = [line.strip() for line in ps.stdout.strip().splitlines() if line.strip()]
        if lines:
            return int(lines[0])
    except Exception:
        pass
    return None


def is_shadowrocket_running() -> bool:
    """Checks if Shadowrocket macOS application is currently running."""
    return get_shadowrocket_pid() is not None


def read_shadowrocket_live_ax_results(pid: Optional[int] = None) -> Dict[str, dict]:
    """
    Directly extracts live connectivity test results from the running Shadowrocket
    Mac Catalyst application window via the macOS Accessibility API (ctypes ApplicationServices/CoreFoundation).

    Non-invasive & Non-destructive:
    - Does NOT quit, kill, or restart Shadowrocket.
    - Preserves all UI state, table views, and visible pings.
    - Automatically scrolls through the server list to extract all servers and latencies.
    - Accurately parses IP, port, latency (e.g. 76ms), and Timeout.
    """
    import ctypes
    import ctypes.util
    import re

    target_pid = pid or get_shadowrocket_pid()
    if not target_pid:
        return {}

    try:
        cf_path = ctypes.util.find_library("CoreFoundation")
        his_path = ctypes.util.find_library("ApplicationServices")
        if not cf_path or not his_path:
            return {}
        cf = ctypes.cdll.LoadLibrary(cf_path)
        his = ctypes.cdll.LoadLibrary(his_path)
    except Exception as e:
        logger.warning(f"Could not load macOS system libraries for AX extraction: {e}")
        return {}

    CFTypeRef = ctypes.c_void_p
    CFStringRef = ctypes.c_void_p
    AXUIElementRef = ctypes.c_void_p

    cf.CFStringCreateWithCString.restype = CFStringRef
    cf.CFStringCreateWithCString.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32]
    cf.CFStringGetLength.restype = ctypes.c_long
    cf.CFStringGetLength.argtypes = [CFStringRef]
    cf.CFStringGetCString.restype = ctypes.c_bool
    cf.CFStringGetCString.argtypes = [CFStringRef, ctypes.c_char_p, ctypes.c_long, ctypes.c_uint32]
    cf.CFArrayGetCount.restype = ctypes.c_long
    cf.CFArrayGetCount.argtypes = [CFTypeRef]
    cf.CFArrayGetValueAtIndex.restype = ctypes.c_void_p
    cf.CFArrayGetValueAtIndex.argtypes = [CFTypeRef, ctypes.c_long]
    cf.CFGetTypeID.restype = ctypes.c_ulong
    cf.CFGetTypeID.argtypes = [CFTypeRef]
    cf.CFStringGetTypeID.restype = ctypes.c_ulong
    cf.CFRelease.restype = None
    cf.CFRelease.argtypes = [CFTypeRef]
    cf.CFRetain.restype = CFTypeRef
    cf.CFRetain.argtypes = [CFTypeRef]

    his.AXUIElementCreateApplication.restype = AXUIElementRef
    his.AXUIElementCreateApplication.argtypes = [ctypes.c_int]
    his.AXUIElementCopyAttributeValue.restype = ctypes.c_int
    his.AXUIElementCopyAttributeValue.argtypes = [AXUIElementRef, CFStringRef, ctypes.POINTER(CFTypeRef)]
    his.AXUIElementPerformAction.restype = ctypes.c_int
    his.AXUIElementPerformAction.argtypes = [AXUIElementRef, CFStringRef]

    kCFStringEncodingUTF8 = 0x08000100
    str_type_id = cf.CFStringGetTypeID()

    def to_cfstring(s):
        return cf.CFStringCreateWithCString(None, s.encode("utf-8"), kCFStringEncodingUTF8)

    def from_cfstring(s_ref):
        if not s_ref:
            return ""
        if cf.CFGetTypeID(s_ref) != str_type_id:
            return ""
        length = cf.CFStringGetLength(s_ref)
        buf = ctypes.create_string_buffer(length * 4 + 1)
        if cf.CFStringGetCString(s_ref, buf, len(buf), kCFStringEncodingUTF8):
            return buf.value.decode("utf-8", errors="ignore")
        return ""

    def get_attr(elem, attr_name):
        cf_attr = to_cfstring(attr_name)
        val = CFTypeRef()
        err = his.AXUIElementCopyAttributeValue(elem, cf_attr, ctypes.byref(val))
        cf.CFRelease(cf_attr)
        if err == 0 and val.value:
            res = from_cfstring(val)
            cf.CFRelease(val)
            return res
        return ""

    def get_children(elem):
        cf_attr = to_cfstring("AXChildren")
        val = CFTypeRef()
        err = his.AXUIElementCopyAttributeValue(elem, cf_attr, ctypes.byref(val))
        cf.CFRelease(cf_attr)
        if err == 0 and val.value:
            count = cf.CFArrayGetCount(val)
            children = [cf.CFArrayGetValueAtIndex(val, i) for i in range(count)]
            return children, val
        return [], None

    def get_server_cells():
        app_elem = his.AXUIElementCreateApplication(target_pid)
        kAXWindows = to_cfstring("AXWindows")
        win_list = CFTypeRef()
        his.AXUIElementCopyAttributeValue(app_elem, kAXWindows, ctypes.byref(win_list))
        cf.CFRelease(kAXWindows)
        if not win_list:
            return []
        if cf.CFArrayGetCount(win_list) == 0:
            cf.CFRelease(win_list)
            return []
        window = cf.CFArrayGetValueAtIndex(win_list, 0)
        cells = []

        def crawl(elem):
            role = get_attr(elem, "AXRole")
            subrole = get_attr(elem, "AXSubrole")
            if role == "AXButton" and subrole == "":
                desc = get_attr(elem, "AXDescription")
                if desc and re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", desc):
                    cf.CFRetain(elem)
                    cells.append((elem, desc))
            children, p = get_children(elem)
            for c in children:
                crawl(c)
            if p:
                cf.CFRelease(p)

        crawl(window)
        cf.CFRelease(win_list)
        return cells

    # 1. Scroll to the top of the table
    act_up = to_cfstring("AXScrollUpByPage")
    last_top = ""
    for _ in range(30):
        cells = get_server_cells()
        if not cells:
            break
        top_desc = cells[0][1]
        if top_desc == last_top:
            for c, _ in cells:
                cf.CFRelease(c)
            break
        last_top = top_desc
        his.AXUIElementPerformAction(cells[0][0], act_up)
        for c, _ in cells:
            cf.CFRelease(c)
        time.sleep(0.06)
    cf.CFRelease(act_up)

    # 2. Scroll down page by page and extract all server test results
    all_servers = {}
    act_down = to_cfstring("AXScrollDownByPage")
    last_bottom = ""

    for _ in range(40):
        cells = get_server_cells()
        if not cells:
            break
        for c, desc in cells:
            # Extract IP from parentheses: "🇹🇷 Turkey — Istanbul (45.136.155.50) — ..."
            ip_m = re.search(r"\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)", desc)
            if not ip_m:
                # Fallback: IP anywhere in string
                ip_m = re.search(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", desc)
            if not ip_m:
                continue
            ip = ip_m.group(1)
            port_m = re.search(r":(\d{4,5})\b", desc)
            port = int(port_m.group(1)) if port_m else 51820

            # Determine actual test result from label format:
            # Format 1 (tested): "... UDP, 86ms"  → last part after final comma = "86ms" → WORKING
            # Format 2 (failed): "... UDP, Timeout" → last part = "Timeout" → FAILED
            # Format 3 (not tested yet): "... — 114ms" (no trailing comma+result) → use cached ping
            parts = desc.rsplit(",", 1)
            last_part = parts[-1].strip() if len(parts) > 1 else ""
            last_ms_m = re.match(r"^(\d+)\s*ms$", last_part, re.IGNORECASE)
            is_timeout = "timeout" in last_part.lower()

            if last_ms_m:
                # Last token is a fresh test result in ms → server is working
                ping = int(last_ms_m.group(1))
            elif is_timeout:
                # Last token is Timeout → server failed this test
                ping = -1
            else:
                # No new test result → read the cached ping from the label (format: "— Xms")
                cached_m = re.search(r"—\s*(\d+)\s*ms", desc)
                ping = int(cached_m.group(1)) if cached_m else 0

            all_servers[ip] = {
                "host": ip,
                "port": port,
                "ping": ping,
                "status": desc,
                "is_reachable": (ping > 0),
                "is_ip": True,
            }
        bottom_desc = cells[-1][1]
        if bottom_desc == last_bottom:
            for c, _ in cells:
                cf.CFRelease(c)
            break
        last_bottom = bottom_desc
        his.AXUIElementPerformAction(cells[-1][0], act_down)
        for c, _ in cells:
            cf.CFRelease(c)
        time.sleep(0.06)

    cf.CFRelease(act_down)
    return all_servers


def flush_shadowrocket_to_disk(timeout: float = 2.0) -> bool:
    """
    Non-destructive no-op.
    Never forcefully terminates or restarts Shadowrocket to avoid erasing
    in-memory ping test results from the user's screen.
    """
    return True


def flush_and_read_shadowrocket_test_results(
    storage_path: Optional[str] = None,
    reopen: bool = False,
) -> Dict[str, dict]:
    """Helper that reads Shadowrocket test results safely without quitting."""
    return read_shadowrocket_test_results(storage_path=storage_path)


def read_shadowrocket_test_results(
    storage_path: Optional[str] = None,
    flush_if_running: bool = True,
) -> Dict[str, dict]:
    """
    Reads all test results from Shadowrocket.
    If Shadowrocket is currently running on macOS, reads directly from its live UI
    using the Accessibility API without quitting or resetting it, and persists the
    discovered pings to ServerManager on disk.
    If Shadowrocket is not running or AX read returns no positive pings, reads from ServerManager on disk.
    """
    is_live = (storage_path is None or storage_path == ShadowrocketStorage.DEFAULT_STORAGE_PATH)
    if is_live and is_shadowrocket_running():
        try:
            live_results = read_shadowrocket_live_ax_results()
            if live_results and any(r.get("ping", 0) > 0 for r in live_results.values()):
                # Persist discovered pings to disk so disk backup has real data
                try:
                    storage = ShadowrocketStorage(storage_path)
                    ping_map = {ip: r["ping"] for ip, r in live_results.items() if r.get("ping", 0) > 0}
                    storage.update_server_pings(ping_map)
                    # Merge flags & details from storage if needed
                    disk_results = storage.read_test_results()
                    for ip, info in disk_results.items():
                        if ip in live_results:
                            live_results[ip]["flag"] = info.get("flag", "")
                        else:
                            live_results[ip] = info
                except Exception as e:
                    logger.debug(f"Failed to update ServerManager on disk with live pings: {e}")
                return live_results
        except Exception as e:
            logger.warning(f"Failed to read live Shadowrocket AX results: {e}")

    storage = ShadowrocketStorage(storage_path)
    return storage.read_test_results()


def purge_shadowrocket_failed_servers(
    storage_path: Optional[str] = None,
    keep_only_working_ips: bool = True,
    flush_if_running: bool = True,
) -> dict:
    """
    Helper to purge all subdomains and failed servers from Shadowrocket's ServerManager.
    Safely modifies the database on disk without force-killing the app.
    """
    storage = ShadowrocketStorage(storage_path)
    return storage.purge_failed_and_domain_servers(keep_only_working_ips=keep_only_working_ips)


def clear_shadowrocket_all_servers(storage_path: Optional[str] = None) -> dict:
    """Helper to remove all local servers from Shadowrocket's ServerManager."""
    storage = ShadowrocketStorage(storage_path)
    return storage.clear_all_servers()


def get_shadowrocket_storage_stats(
    storage_path: Optional[str] = None,
    flush_if_running: bool = True,
) -> dict:
    """Helper to get server statistics from Shadowrocket's ServerManager."""
    storage = ShadowrocketStorage(storage_path)
    return storage.get_storage_stats()



if __name__ == "__main__":
    # Quick module sanity test
    test_conf = build_amnezia_config(
        client_private_key="a" * 44,
        client_address="10.14.0.2/16",
        client_dns="162.252.172.57",
        server_public_key="b" * 44,
        endpoint_ip="185.220.101.5",
        endpoint_port=51820,
    )
    print("Sample Config Output:\n", test_conf)

    qr_b64 = generate_qr_code_base64(test_conf)
    print("QR Code generated successfully? Base64 length:", len(qr_b64) if qr_b64 else "N/A")
