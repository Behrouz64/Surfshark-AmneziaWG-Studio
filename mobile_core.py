"""
mobile_core.py: Flet-free core logic for the phone-friendly Studio.

Everything the phone UI needs lives here so it can be unit-tested without a
browser or a Flet page:
  - Endpoint model built from the last scan cache (working IPs only).
  - AmneziaWG config text for one endpoint, a group of endpoints, or an
    endpoint list (the copy formats).
  - wg:// links for Shadowrocket (iPhone), one per endpoint or one per line for
    a group. The link comes from config_builder.build_shadowrocket_wg_url, the
    same builder the desktop app uses, so both produce identical links.
  - CopyQueue: walks a selection one config at a time, because the Amnezia
    mobile app imports one config per paste.
  - run_mobile_scan: headless DoH resolution + UDP 51820 reachability scan.
  - Access-token check for the browser UI served on the local network.

This module never touches Shadowrocket itself: no ServerManager storage, no
app control, no pbcopy. It only builds text. Those stay in the desktop ui.py.
"""

from __future__ import annotations

import hmac
import logging
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from browser_harvest import BlueprintData, UserInterfaceConfig, is_placeholder_key
from checker import CheckResult, ScanMode, run_udp_scan_sync
from config_builder import (
    AmneziaParams,
    build_amnezia_config,
    build_shadowrocket_wg_url,
    country_code_to_flag,
    is_valid_wg_key,
)
from dns_resolver import resolve_servers_sync
from scan_cache import DEFAULT_SCAN_CACHE_FILE, save_scan_cache

logger = logging.getLogger(__name__)

DEFAULT_ADDRESS = "10.14.0.2/16"
DEFAULT_DNS = "162.252.172.57, 149.154.159.92"
DEFAULT_PORT = 51820
LATENCY_CEILING_MS = 9000.0
UNKNOWN_LATENCY_MS = 9999.0

# Obfuscation presets selectable on the phone. Keys are stable identifiers,
# labels are what the user sees.
PRESETS: Dict[str, Tuple[str, Callable[[], AmneziaParams]]] = {
    "iran": ("Iran Balanced", AmneziaParams.iran_preset),
    "aggressive": ("Iran Aggressive", AmneziaParams.aggressive_preset),
    "standard": ("Standard WireGuard", AmneziaParams.standard_wireguard),
}
DEFAULT_PRESET = "iran"


def params_for_preset(preset_key: str) -> AmneziaParams:
    """Returns the obfuscation parameters for a preset key, falling back to Iran Balanced."""
    _, factory = PRESETS.get(preset_key, PRESETS[DEFAULT_PRESET])
    return factory()


@dataclass(frozen=True)
class Endpoint:
    """One verified raw-IP endpoint from the last scan."""

    country: str
    country_code: str
    city: str
    hostname: str
    ip: str
    port: int
    public_key: str
    latency_ms: float = UNKNOWN_LATENCY_MS

    @property
    def key(self) -> str:
        """Stable identifier used for selection state (unique per hostname + endpoint)."""
        return f"{self.hostname}|{self.ip}:{self.port}"

    @property
    def has_latency(self) -> bool:
        return self.latency_ms < LATENCY_CEILING_MS

    @property
    def latency_label(self) -> str:
        return f"{int(self.latency_ms)}ms" if self.has_latency else "—"

    @property
    def tunnel_name(self) -> str:
        """Display name written into the config as '# Name = ...'."""
        flag = country_code_to_flag(self.country_code)
        latency = f" — {int(self.latency_ms)}ms" if self.has_latency else ""
        return f"{flag} {self.city} ({self.country}){latency}"


def endpoints_from_working_configs(working_configs: Iterable[dict]) -> List[Endpoint]:
    """
    Converts the 'working_configs' list stored in scan_cache.json into Endpoint
    objects. Entries without an IP are skipped and duplicates are removed.
    The result is sorted by latency, then country and IP.
    """
    seen: set = set()
    endpoints: List[Endpoint] = []
    for raw in working_configs:
        ip = str(raw.get("endpoint_ip", "") or "").strip()
        if not ip:
            continue
        try:
            port = int(raw.get("port") or DEFAULT_PORT)
        except (TypeError, ValueError):
            port = DEFAULT_PORT
        try:
            latency = float(raw.get("latency_ms") or UNKNOWN_LATENCY_MS)
        except (TypeError, ValueError):
            latency = UNKNOWN_LATENCY_MS

        endpoint = Endpoint(
            country=raw.get("country") or "Unknown",
            country_code=raw.get("country_code") or "",
            city=raw.get("city") or "Cluster",
            hostname=raw.get("hostname") or "",
            ip=ip,
            port=port,
            public_key=raw.get("public_key") or "",
            latency_ms=latency,
        )
        if endpoint.key in seen:
            continue
        seen.add(endpoint.key)
        endpoints.append(endpoint)

    return sorted(endpoints, key=lambda e: (e.latency_ms, e.country, e.ip))


def group_by_country(endpoints: Sequence[Endpoint]) -> List[Tuple[str, List[Endpoint]]]:
    """
    Groups endpoints by country. Countries are ordered by their fastest endpoint,
    and endpoints inside a country are ordered by latency.
    """
    groups: Dict[str, List[Endpoint]] = {}
    for endpoint in endpoints:
        groups.setdefault(endpoint.country, []).append(endpoint)

    ordered = sorted(groups.items(), key=lambda item: min(e.latency_ms for e in item[1]))
    return [(name, sorted(items, key=lambda e: e.latency_ms)) for name, items in ordered]


def build_endpoint_config(endpoint: Endpoint, ui: UserInterfaceConfig, params: AmneziaParams) -> str:
    """Builds the full AmneziaWG .conf text for a single endpoint."""
    return build_amnezia_config(
        client_private_key=ui.private_key or "",
        client_address=ui.address or DEFAULT_ADDRESS,
        client_dns=ui.dns or DEFAULT_DNS,
        server_public_key=endpoint.public_key or "YOUR_SERVER_PUBLIC_KEY",
        endpoint_ip=endpoint.ip,
        endpoint_port=endpoint.port,
        amnezia_params=params,
        tunnel_name=endpoint.tunnel_name,
    )


def _wg_user_interface(ui: UserInterfaceConfig) -> dict:
    """The wg:// builder takes plain dicts; these defaults match the .conf builder."""
    return {
        "private_key": ui.private_key or "",
        "address": ui.address or DEFAULT_ADDRESS,
        "dns": ui.dns or DEFAULT_DNS,
    }


def build_endpoint_wg_link(endpoint: Endpoint, ui: UserInterfaceConfig, params: AmneziaParams) -> str:
    """One wg:// link for Shadowrocket. Paste it into Shadowrocket to add this server."""
    server_info = {
        "endpoint_ip": endpoint.ip,
        "port": endpoint.port,
        "hostname": endpoint.hostname,
        "public_key": endpoint.public_key,
        "country": endpoint.country,
        "country_code": endpoint.country_code,
        "city": endpoint.city,
        "latency_ms": endpoint.latency_ms if endpoint.has_latency else None,
        "is_domain": False,
    }
    return build_shadowrocket_wg_url(server_info, _wg_user_interface(ui), params)


def build_group_wg_links_text(endpoints: Sequence[Endpoint], ui: UserInterfaceConfig, params: AmneziaParams) -> str:
    """One wg:// link per line, the same format the desktop 'Copy wg:// Links' button produces."""
    return "\n".join(build_endpoint_wg_link(endpoint, ui, params) for endpoint in endpoints)


def build_group_config_text(endpoints: Sequence[Endpoint], ui: UserInterfaceConfig, params: AmneziaParams) -> str:
    """
    Joins the configs of a selection into one text block, each preceded by a
    numbered separator line. Useful for saving or sending a whole selection at
    once. The Amnezia app imports one config per paste, so use CopyQueue to
    import them one by one.
    """
    total = len(endpoints)
    blocks = []
    for index, endpoint in enumerate(endpoints, start=1):
        separator = f"# ===== [{index}/{total}] {endpoint.tunnel_name} ====="
        blocks.append(separator + "\n" + build_endpoint_config(endpoint, ui, params))
    return "\n".join(blocks)


def build_endpoint_list_text(endpoints: Sequence[Endpoint]) -> str:
    """One line per endpoint: 'Country - City | IP:port | latency'."""
    return "\n".join(
        f"{e.country} - {e.city} | {e.ip}:{e.port} | {e.latency_label}"
        for e in endpoints
    )


class CopyQueue:
    """
    Walks a selection one config at a time. Each step copies the current config
    so it can be pasted into the Amnezia app, then the user comes back for the next.
    """

    def __init__(self, endpoints: Sequence[Endpoint]):
        self._endpoints: List[Endpoint] = list(endpoints)
        self._index = 0

    @property
    def total(self) -> int:
        return len(self._endpoints)

    @property
    def position(self) -> int:
        """1-based position of the current item (0 when the queue is empty)."""
        return self._index + 1 if self._endpoints else 0

    @property
    def current(self) -> Optional[Endpoint]:
        return self._endpoints[self._index] if self._endpoints else None

    @property
    def has_next(self) -> bool:
        return self._index + 1 < len(self._endpoints)

    def advance(self) -> bool:
        """Moves to the next item. Returns False when already at the last item."""
        if not self.has_next:
            return False
        self._index += 1
        return True


@dataclass
class MobileScanResult:
    hostnames_checked: int = 0
    discovered_ips: int = 0
    working_configs: List[dict] = field(default_factory=list)
    scan_results: Dict[str, List[CheckResult]] = field(default_factory=dict)


def run_mobile_scan(
    blueprint: BlueprintData,
    cache_path: str = DEFAULT_SCAN_CACHE_FILE,
    on_log: Optional[Callable[[str], None]] = None,
    on_progress: Optional[Callable[[str, int, int], None]] = None,
    timeout: float = 2.0,
    mode: str = ScanMode.SMART,
    probe_count: int = 3,
) -> MobileScanResult:
    """
    Headless scan: resolves every cluster hostname over DoH (bypassing the local
    resolver), probes each raw IP on UDP 51820, and saves the reachable ones to
    the scan cache. on_progress receives (phase, done, total) with phase 'dns' or 'udp'.
    """
    log = on_log or (lambda message: None)
    progress = on_progress or (lambda phase, done, total: None)

    hostnames = [s.hostname for s in blueprint.servers if s.hostname]
    log(f"DNS: بررسی {len(hostnames)} هاست با DoH")

    def _dns_cb(done: int, total: int, host: str, ips: List[str]):
        progress("dns", done, total)
        if ips:
            log(f"[{done}/{total}] {host} → {len(ips)} آی‌پی")
        else:
            log(f"[{done}/{total}] {host} → بدون آی‌پی")

    resolved = resolve_servers_sync(hostnames, on_progress=_dns_cb) if hostnames else {}

    targets: List[tuple] = []
    discovered = 0
    for server in blueprint.servers:
        endpoint = resolved.get(server.hostname)
        if not endpoint or not endpoint.ips:
            continue
        discovered += len(endpoint.ips)
        info = {
            "country": server.country,
            "country_code": server.country_code,
            "city": server.city,
            "hostname": server.hostname,
            "public_key": server.public_key,
            "port": server.port,
        }
        for ip in endpoint.ips:
            targets.append((ip, server.port, blueprint.user_interface.private_key, server.public_key, info))

    log(f"UDP: تست {len(targets)} آی‌پی روی پورت {DEFAULT_PORT}")

    def _udp_cb(done: int, total: int, res: CheckResult):
        progress("udp", done, total)
        if res.is_reachable:
            log(f"✅ {res.ip}:{res.port} ({int(res.latency_ms)}ms)")

    results = (
        run_udp_scan_sync(targets, on_progress=_udp_cb, timeout=timeout, mode=mode, probe_count=probe_count)
        if targets else []
    )

    working: List[dict] = []
    by_hostname: Dict[str, List[CheckResult]] = {}
    for res in results:
        info = res.server_info or {}
        by_hostname.setdefault(info.get("hostname", ""), []).append(res)
        if res.is_reachable and info:
            working.append({
                "country": info.get("country", ""),
                "country_code": info.get("country_code", ""),
                "city": info.get("city", ""),
                "hostname": info.get("hostname", ""),
                "public_key": info.get("public_key", ""),
                "endpoint_ip": res.ip,
                "port": res.port,
                "latency_ms": res.latency_ms,
                "packet_loss": res.packet_loss,
                "jitter_ms": res.jitter_ms,
                "deep_verified": res.deep_verified,
                "status": res.status,
            })

    save_scan_cache(by_hostname, working, filepath=cache_path)
    log(f"پایان اسکن: {len(working)} آی‌پی سالم از {len(targets)} تست")

    return MobileScanResult(
        hostnames_checked=len(hostnames),
        discovered_ips=discovered,
        working_configs=working,
        scan_results=by_hostname,
    )


def has_usable_private_key(ui: UserInterfaceConfig) -> bool:
    """True when the stored PrivateKey is a well-formed, non-placeholder WireGuard key."""
    key = (ui.private_key or "").strip()
    return is_valid_wg_key(key) and not is_placeholder_key(key)


def is_access_token_valid(given: Optional[str], expected: str) -> bool:
    """Constant-time comparison of the URL token against the one printed at startup."""
    if not given or not expected:
        return False
    return hmac.compare_digest(given.encode("utf-8"), expected.encode("utf-8"))
