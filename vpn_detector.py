"""
vpn_detector.py: Network Interface & Active VPN Detection Utility

Before scanning and testing raw IP reachability from restricted networks (such as Iran),
any active VPN client (ExpressVPN, OpenVPN, WireGuard, v2ray, Clash, etc.) MUST be turned off.
Otherwise, the reachability test packets will be routed through the existing VPN tunnel
rather than the user's domestic ISP network, producing false-positive results.

This module detects:
1. If the primary default gateway routes through a virtual tunnel (utun, tun, tap, wg, ppp).
2. The active physical interface (e.g., en0, eth0, wlan0) vs virtual interface.
3. Provides localized (Persian and English) guidance for users.
"""

from __future__ import annotations

import platform
import re
import subprocess
from dataclasses import dataclass
from typing import Optional, Tuple


VPN_INTERFACE_PREFIXES = (
    "utun",      # macOS / iOS virtual tunnels (WireGuard, OpenVPN, IPSec)
    "tun",       # Linux / Unix standard tunnel
    "tap",       # Linux / Unix tap adapter
    "wg",        # WireGuard native interface
    "ppp",       # Point-to-Point Protocol / L2TP / PPTP
    "ipsec",     # IPSec tunnel
    "tailscale", # Tailscale overlay
    "zerotier",  # ZeroTier overlay
    "proton",    # ProtonVPN adapter
    "nord",      # NordVPN adapter
    "mullvad",   # Mullvad adapter
    "surfshark", # Surfshark virtual adapter
    "warp",      # Cloudflare WARP
)


@dataclass
class VpnStatus:
    is_vpn_active: bool
    interface: str
    gateway: str
    summary_fa: str
    summary_en: str
    warning_fa: str
    warning_en: str


def detect_active_vpn() -> VpnStatus:
    """
    Inspects the system's routing table to determine if default internet traffic
    is currently routed through a VPN interface.
    """
    system = platform.system().lower()

    if system == "darwin":
        return _detect_macos()
    elif system == "linux":
        return _detect_linux()
    elif system == "windows":
        return _detect_windows()
    else:
        return _fallback_generic()


def _detect_macos() -> VpnStatus:
    primary_netif = ""
    primary_gw = "0.0.0.0"
    try:
        # 1. Authoritative kernel routing query (fastest, direct resolution)
        try:
            r_out = subprocess.check_output(["route", "-n", "get", "default"], text=True, stderr=subprocess.DEVNULL)
            m_if = re.search(r"interface:\s*([^\s]+)", r_out)
            m_gw = re.search(r"gateway:\s*([^\s]+)", r_out)
            if m_if:
                primary_netif = m_if.group(1).strip()
            if m_gw:
                primary_gw = m_gw.group(1).strip()
        except Exception:
            pass

        # 2. Fallback to netstat if route query was empty
        if not primary_netif:
            out = subprocess.check_output(["netstat", "-rn", "-f", "inet"], text=True, stderr=subprocess.DEVNULL)
            default_routes = []
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 4 and parts[0] == "default":
                    gw = parts[1]
                    netif = parts[3]
                    flags = parts[2]
                    default_routes.append((netif, gw, flags))
            if default_routes:
                primary_netif, primary_gw, _ = default_routes[0]

        if primary_netif:
            is_vpn = any(primary_netif.lower().startswith(p) for p in VPN_INTERFACE_PREFIXES)

            if is_vpn:
                return VpnStatus(
                    is_vpn_active=True,
                    interface=primary_netif,
                    gateway=primary_gw,
                    summary_fa=f"⚠️ Active VPN ({primary_netif})",
                    summary_en=f"⚠️ Active VPN Tunnel Detected ({primary_netif})",
                    warning_fa=(
                        f"Warning: Your network is currently routing through an active VPN tunnel ({primary_netif}).\n\n"
                        "To discover which raw server IPs are truly reachable, "
                        "disconnect your VPN before running this test."
                    ),
                    warning_en=(
                        f"Warning: Your network is currently routing through an active VPN tunnel ({primary_netif}).\n\n"
                        "To discover which raw server IPs are truly reachable from within your local restricted network, "
                        "you MUST turn off / disconnect your VPN before running this test.\n\n"
                        "Testing while a VPN is active routes packets through foreign servers, resulting in false positives!"
                    ),
                )
            else:
                return VpnStatus(
                    is_vpn_active=False,
                    interface=primary_netif,
                    gateway=primary_gw,
                    summary_fa=f"🟢 Direct Network ({primary_netif}) - Ready",
                    summary_en=f"🟢 Direct Local Network ({primary_netif}) - Ready",
                    warning_fa="No active VPN detected. Tests will route directly through your local network.",
                    warning_en="No active VPN detected on your default route. Testing will execute directly through your local network.",
                )
    except Exception as e:
        pass

    return _fallback_generic()


def _detect_linux() -> VpnStatus:
    try:
        out = subprocess.check_output(["ip", "route", "show", "default"], text=True, stderr=subprocess.DEVNULL)
        # format: default via 192.168.1.1 dev eno1 proto dhcp metric 100
        match = re.search(r"default\s+via\s+([^\s]+)\s+dev\s+([^\s]+)", out)
        if match:
            gw = match.group(1)
            netif = match.group(2)
            is_vpn = any(netif.lower().startswith(p) for p in VPN_INTERFACE_PREFIXES)
            return VpnStatus(
                is_vpn_active=is_vpn,
                interface=netif,
                gateway=gw,
                summary_fa=f"⚠️ Active VPN ({netif})" if is_vpn else f"🟢 Direct Network ({netif})",
                summary_en=f"⚠️ Active VPN ({netif})" if is_vpn else f"🟢 Direct Network ({netif})",
                warning_fa="Please disconnect VPN before testing." if is_vpn else "Ready for direct test.",
                warning_en="Please disconnect VPN before testing." if is_vpn else "Ready for direct test.",
            )
    except Exception:
        pass

    return _fallback_generic()


def _detect_windows() -> VpnStatus:
    try:
        out = subprocess.check_output(["route", "print", "0.0.0.0"], text=True, stderr=subprocess.DEVNULL)
        # Look for default routes in IPv4 Route Table
        is_vpn = any(x in out.lower() for x in ["wintun", "tap-windows", "wireguard", "openvpn", "nord", "surfshark"])
        return VpnStatus(
            is_vpn_active=is_vpn,
            interface="Windows Adapter",
            gateway="0.0.0.0",
            summary_fa="⚠️ Potential Active VPN" if is_vpn else "🟢 Direct Network",
            summary_en="⚠️ Potential Active VPN" if is_vpn else "🟢 Direct Network",
            warning_fa="Please turn off your VPN before scanning.",
            warning_en="Please turn off your VPN before scanning.",
        )
    except Exception:
        pass

    return _fallback_generic()


def _fallback_generic() -> VpnStatus:
    return VpnStatus(
        is_vpn_active=False,
        interface="unknown",
        gateway="unknown",
        summary_fa="Network Status: Unknown",
        summary_en="Network Status: Unknown",
        warning_fa="Please ensure your VPN is turned off before scanning.",
        warning_en="Please ensure your VPN is turned off before scanning.",
    )


if __name__ == "__main__":
    status = detect_active_vpn()
    print("Is VPN Active:", status.is_vpn_active)
    print("Interface:   ", status.interface)
    print("Summary FA:  ", status.summary_fa)
    print("Warning FA:\n", status.warning_fa)
