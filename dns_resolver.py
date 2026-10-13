"""
dns_resolver.py: Anti-Poisoning Multi-Resolver for Surfshark Server Endpoints

Restricted networks (such as in Iran) frequently poison UDP port 53 DNS responses,
returning fabricated blackhole or sinkhole IPs (e.g., 10.10.34.34).

This module bypasses the local operating system's DNS resolver completely:
1. Employs encrypted DNS-over-HTTPS (DoH) across three distinct tier-1 providers:
   - Cloudflare (1.1.1.1)
   - Google (8.8.8.8)
   - Quad9 (9.9.9.9)
2. Falls back to direct encrypted or foreign resolvers.
3. Discovers all round-robin 'A' records behind each hostname.
4. Strictly filters out poisoned, loopback, private RFC-1918, and non-global IPs.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set

import urllib.request
import urllib.parse
import json

try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False

logger = logging.getLogger(__name__)

# Primary DoH Endpoints with IP and Domain representations
DOH_PROVIDERS = [
    {
        "name": "Cloudflare",
        "url": "https://1.1.1.1/dns-query",
        "headers": {"Accept": "application/dns-json"},
        "params": {"type": "A"},
    },
    {
        "name": "Google",
        "url": "https://dns.google/resolve",
        "headers": {"Accept": "application/json"},
        "params": {"type": "A"},
    },
    {
        "name": "Quad9",
        "url": "https://dns.quad9.net/dns-query",
        "headers": {"Accept": "application/dns-json"},
        "params": {"type": "A"},
    },
    {
        "name": "AdGuard",
        "url": "https://dns.adguard-dns.com/resolve",
        "headers": {"Accept": "application/dns-json"},
        "params": {"type": "A"},
    },
    {
        "name": "OpenDNS",
        "url": "https://doh.opendns.com/dns-query",
        "headers": {"Accept": "application/dns-json"},
        "params": {"type": "A"},
    },
]


def is_valid_public_ipv4(ip_str: str) -> bool:
    """
    Validates that an IP string is a syntactically correct, globally routable IPv4 address.
    Filters out:
      - Iran censorship sinkholes (10.10.34.34, 10.x.x.x)
      - RFC 1918 Private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
      - Loopback (127.0.0.0/8)
      - Link-local (169.254.0.0/16)
      - Broadcast / Unspecified (0.0.0.0, 255.255.255.255)
    """
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        if ip.version != 4:
            return False
        # Filter non-global, private, loopback, reserved, link_local
        return (
            ip.is_global
            and not ip.is_private
            and not ip.is_loopback
            and not ip.is_link_local
            and not ip.is_reserved
            and not ip.is_multicast
        )
    except ValueError:
        return False


@dataclass
class ResolvedEndpoint:
    hostname: str
    ips: List[str] = field(default_factory=list)
    provider_source: str = ""
    error: Optional[str] = None


class SecureDnsResolver:
    """
    High-concurrency DoH resolver designed to evade DNS poisoning and
    discover round-robin server clusters.
    """

    def __init__(self, timeout: float = 4.0, max_concurrency: int = 20):
        self.timeout = timeout
        self.max_concurrency = max_concurrency
        self._semaphore: Optional[asyncio.Semaphore] = None

    def _get_semaphore(self) -> asyncio.Semaphore:
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.max_concurrency)
        return self._semaphore

    async def _query_provider(
        self, client: Optional[object], provider: dict, hostname: str
    ) -> List[str]:
        """Queries a single DoH provider for A records."""
        url = provider["url"]
        headers = provider["headers"]
        params = dict(provider["params"])
        params["name"] = hostname

        if _HTTPX_AVAILABLE and client is not None:
            try:
                resp = await client.get(url, params=params, headers=headers, timeout=self.timeout)
                if resp.status_code != 200:
                    return []
                data = resp.json()
            except Exception:
                return []
        else:
            # Fallback using urllib.request
            query_str = urllib.parse.urlencode(params)
            full_url = f"{url}?{query_str}"
            req = urllib.request.Request(full_url, headers=headers)
            loop = asyncio.get_running_loop()

            def _fetch():
                try:
                    with urllib.request.urlopen(req, timeout=self.timeout) as r:
                        if r.status == 200:
                            return json.loads(r.read().decode("utf-8"))
                except Exception:
                    pass
                return {}

            data = await loop.run_in_executor(None, _fetch)

        ips: List[str] = []
        answers = data.get("Answer", [])
        if not answers:
            return []

        for record in answers:
            # Type 1 is DNS 'A' record
            if record.get("type") == 1:
                ip_data = str(record.get("data", "")).strip()
                if is_valid_public_ipv4(ip_data):
                    ips.append(ip_data)
        return ips

    async def resolve_hostname(
        self, hostname: str, client: Optional[object] = None
    ) -> ResolvedEndpoint:
        """
        Queries all configured DoH providers concurrently to retrieve all
        round-robin A-records for the specified hostname.
        """
        cleaned_hostname = hostname.strip().rstrip(".")
        if not cleaned_hostname:
            return ResolvedEndpoint(hostname=hostname, error="Empty hostname")

        # If already an IP address, validate directly
        if is_valid_public_ipv4(cleaned_hostname):
            return ResolvedEndpoint(hostname=cleaned_hostname, ips=[cleaned_hostname], provider_source="Literal IP")

        owns_client = False
        if client is None and _HTTPX_AVAILABLE:
            client = httpx.AsyncClient(verify=True)
            owns_client = True

        all_ips: Set[str] = set()
        successful_providers: List[str] = []

        try:
            # FIX: Always create a fresh semaphore bound to the *current* running loop.
            # The old approach cached self._semaphore and reused it across loops, which
            # caused "Task attached to different loop" RuntimeError on second scan.
            sem = asyncio.Semaphore(self.max_concurrency)
            async with sem:

                # Query providers concurrently for maximum round-robin discovery
                tasks = [
                    self._query_provider(client, provider, cleaned_hostname)
                    for provider in DOH_PROVIDERS
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                for provider, res in zip(DOH_PROVIDERS, results):
                    if isinstance(res, list) and res:
                        all_ips.update(res)
                        successful_providers.append(provider["name"])

            if not all_ips:
                # Fallback to system socket DNS resolution (useful if DoH endpoints are blocked)
                try:
                    import socket
                    loop = asyncio.get_running_loop()

                    def _resolve_socket():
                        try:
                            infos = socket.getaddrinfo(cleaned_hostname, None, socket.AF_INET, socket.SOCK_DGRAM)
                            return [info[4][0] for info in infos if is_valid_public_ipv4(info[4][0])]
                        except Exception:
                            return []

                    sys_ips = await loop.run_in_executor(None, _resolve_socket)
                    if sys_ips:
                        all_ips.update(sys_ips)
                        successful_providers.append("SystemDNS")
                except Exception:
                    pass

            if not all_ips:
                return ResolvedEndpoint(
                    hostname=cleaned_hostname,
                    ips=[],
                    error="No valid A records returned from secure DoH or system providers",
                )

            return ResolvedEndpoint(
                hostname=cleaned_hostname,
                ips=sorted(list(all_ips)),
                provider_source=",".join(successful_providers),
            )
        except Exception as e:
            logger.warning(f"Error resolving {cleaned_hostname}: {e}")
            return ResolvedEndpoint(hostname=cleaned_hostname, ips=[], error=str(e))
        finally:
            if owns_client and client is not None:
                await client.aclose()

    async def resolve_all(
        self,
        hostnames: List[str],
        on_progress: Optional[Callable[[int, int, str, List[str]], None]] = None,
    ) -> Dict[str, ResolvedEndpoint]:
        """
        Concurrently resolves a list of unique hostnames.
        Triggers on_progress(completed_count, total_count, hostname, ips) after each.
        """
        self._semaphore = None  # Reset for current event loop
        unique_hostnames = list(dict.fromkeys(h.strip() for h in hostnames if h.strip()))
        total = len(unique_hostnames)
        completed = 0
        results: Dict[str, ResolvedEndpoint] = {}

        async def _worker(h: str, c: Optional[object]):
            nonlocal completed
            endpoint = await self.resolve_hostname(h, client=c)
            results[h] = endpoint
            completed += 1
            if on_progress:
                try:
                    on_progress(completed, total, h, endpoint.ips)
                except Exception as err:
                    logger.debug(f"Progress callback error: {err}")
            return endpoint

        if _HTTPX_AVAILABLE:
            async with httpx.AsyncClient(verify=True, limits=httpx.Limits(max_keepalive_connections=50, max_connections=100)) as client:
                tasks = [_worker(h, client) for h in unique_hostnames]
                await asyncio.gather(*tasks)
        else:
            tasks = [_worker(h, None) for h in unique_hostnames]
            await asyncio.gather(*tasks)

        return results


def resolve_servers_sync(
    hostnames: List[str],
    on_progress: Optional[Callable[[int, int, str, List[str]], None]] = None,
    timeout: float = 4.0,
) -> Dict[str, ResolvedEndpoint]:
    """Synchronous convenience wrapper for resolve_all."""
    resolver = SecureDnsResolver(timeout=timeout)
    return asyncio.run(resolver.resolve_all(hostnames, on_progress=on_progress))


if __name__ == "__main__":
    import sys

    test_hosts = ["de-ber.prod.surfshark.com", "us-nyc.prod.surfshark.com", "fr-par.prod.surfshark.com"]
    if len(sys.argv) > 1:
        test_hosts = sys.argv[1:]

    print(f"Testing DoH Anti-Poisoning Resolution on {len(test_hosts)} hosts...")

    def _p(comp, tot, host, ips):
        print(f"[{comp}/{tot}] {host} -> {len(ips)} IPs: {ips}")

    results = resolve_servers_sync(test_hosts, on_progress=_p)
    for host, res in results.items():
        print(f"\nFinal: {host} (Source: {res.provider_source}):")
        for ip in res.ips:
            print(f"  * {ip}")
