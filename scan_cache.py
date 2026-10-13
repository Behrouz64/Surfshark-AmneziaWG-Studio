"""
scan_cache.py: Persistence and Ranking Manager for Surfshark Scan Results (v4)

Manages saving and loading the previous scan results to disk (scan_cache.json).
Provides extraction and ranking of the Top 5 fastest reachable servers.
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime
from typing import Dict, List, Optional

from checker import CheckResult

logger = logging.getLogger(__name__)

DEFAULT_SCAN_CACHE_FILE = "scan_cache.json"


def extract_top_servers(working_configs: List[dict], limit: int = 5) -> List[dict]:
    """
    Returns the top N reachable servers sorted by lowest latency.
    Prioritizes deep verified servers with 0% packet loss, then lowest latency.
    Adds a 'rank' key (1-indexed) to each server entry.
    """
    if not working_configs:
        return []

    # Filter only configs with valid numeric latency
    valid = [
        c for c in working_configs
        if isinstance(c.get("latency_ms"), (int, float)) and c.get("latency_ms", 9999) < 9000
    ]
    # Sort: deep-verified & 0% loss first, then lowest latency
    sorted_servers = sorted(
        valid,
        key=lambda x: (
            not x.get("deep_verified", False),
            x.get("packet_loss", 0.0),
            x["latency_ms"],
        ),
    )[:limit]

    ranked = []
    for idx, s in enumerate(sorted_servers, start=1):
        item = dict(s)
        item["rank"] = idx
        ranked.append(item)
    return ranked


def save_scan_cache(
    scan_results: Dict[str, List[CheckResult]],
    working_configs: List[dict],
    filepath: str = DEFAULT_SCAN_CACHE_FILE,
) -> dict:
    """
    Serializes and saves current scan results and working configs to disk.
    Includes top 5 best servers and timestamp.
    """
    now = datetime.now()
    top_5 = extract_top_servers(working_configs, limit=5)

    # Count total scanned targets
    total_scanned = sum(len(res_list) for res_list in scan_results.values())

    # Serialize scan_results safely (excluding raw ServerMetadata objects)
    serialized_results: Dict[str, List[dict]] = {}
    for hostname, res_list in scan_results.items():
        serialized_results[hostname] = []
        for r in res_list:
            serialized_results[hostname].append({
                "ip": r.ip,
                "port": r.port,
                "is_reachable": r.is_reachable,
                "latency_ms": r.latency_ms,
                "status": r.status,
                "error": r.error,
                "packet_loss": r.packet_loss,
                "jitter_ms": r.jitter_ms,
                "deep_verified": r.deep_verified,
            })

    # Serialize working configs
    clean_working_configs = []
    for c in working_configs:
        clean_working_configs.append({
            "country": c.get("country", ""),
            "country_code": c.get("country_code", ""),
            "city": c.get("city", ""),
            "hostname": c.get("hostname", ""),
            "public_key": c.get("public_key", ""),
            "endpoint_ip": c.get("endpoint_ip", ""),
            "port": c.get("port", 51820),
            "latency_ms": c.get("latency_ms", 9999.0),
            "packet_loss": c.get("packet_loss", 0.0),
            "jitter_ms": c.get("jitter_ms", 0.0),
            "deep_verified": c.get("deep_verified", False),
            "status": c.get("status", "responsive"),
        })

    cache_data = {
        "timestamp": now.isoformat(),
        "formatted_time": now.strftime("%Y-%m-%d %H:%M:%S"),
        "working_count": len(working_configs),
        "total_scanned": total_scanned,
        "top_5": top_5,
        "working_configs": clean_working_configs,
        "scan_results": serialized_results,
    }

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(cache_data, f, indent=2, ensure_ascii=False)
        logger.info("Saved scan cache to %s with %d working configs", filepath, len(working_configs))
    except Exception as err:
        logger.error("Failed to save scan cache: %s", err)

    return cache_data


def load_scan_cache(filepath: str = DEFAULT_SCAN_CACHE_FILE) -> Optional[dict]:
    """
    Loads previous scan results from disk if the cache file exists.
    Returns None if file does not exist or is invalid.
    """
    if not os.path.exists(filepath):
        return None

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        logger.info("Loaded scan cache from %s (from %s)", filepath, data.get("formatted_time", "unknown"))
        return data
    except Exception as err:
        logger.warning("Failed to read scan cache file %s: %s", filepath, err)
        return None


def reconstruct_check_results(
    cached_results: Dict[str, List[dict]],
    servers_by_hostname: dict,
) -> Dict[str, List[CheckResult]]:
    """
    Converts serialized scan result dictionaries back into CheckResult objects
    with the server_info attached for the UI to function smoothly.
    """
    reconstructed: Dict[str, List[CheckResult]] = {}
    for hostname, r_list in cached_results.items():
        server_obj = servers_by_hostname.get(hostname)
        reconstructed[hostname] = []
        for d in r_list:
            cr = CheckResult(
                ip=d["ip"],
                port=d["port"],
                is_reachable=d["is_reachable"],
                latency_ms=d.get("latency_ms", 9999.0),
                status=d.get("status", "timed_out"),
                error=d.get("error"),
                packet_loss=d.get("packet_loss", 0.0),
                jitter_ms=d.get("jitter_ms", 0.0),
                deep_verified=d.get("deep_verified", False),
                server_info={"server": server_obj, "hostname": hostname} if server_obj else {"hostname": hostname},
            )
            reconstructed[hostname].append(cr)
    return reconstructed

