#!/usr/bin/env python3
"""
scripts/mac_copy_check.py: checks the phone app's copy text in Terminal, without a browser.

It builds the same text the phone copies (one wg:// link, or one link per line for a group),
puts it on the macOS clipboard with pbcopy, reads it back with pbpaste, and checks every
link field by field against the reference export that Shadowrocket accepted.

Run it from the project folder, on a computer where a scan has been saved (scan_cache.json):
  .venv/bin/python scripts/mac_copy_check.py
  .venv/bin/python scripts/mac_copy_check.py --count 2
  .venv/bin/python scripts/mac_copy_check.py --no-clipboard

It writes the checked links to copy_check_links.txt, one per line, so you can also add a
single line to Shadowrocket by hand.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import re
import subprocess
import sys
import urllib.parse
from typing import List, Optional, Sequence, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

REQUIRED_QUERY_KEYS = ("publicKey", "privateKey", "ip", "dns", "mtu", "udp", "keepalive", "obfs", "obfsParam")
REQUIRED_OBFS_KEYS = ("jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4")
IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def check_wg_link(link: str, private_key: str) -> List[str]:
    """Returns the problems found in one wg:// link. An empty list means it matches the format."""
    problems: List[str] = []
    if not link.startswith("wg://"):
        return ["does not start with wg://"]
    if any(ch.isspace() for ch in link):
        problems.append("contains a space or a line break")

    body, _, fragment = link.partition("#")
    if not fragment:
        problems.append("no title after #")
    title = urllib.parse.unquote(fragment)
    if not title.strip():
        problems.append("title is empty")

    address, _, query = body[len("wg://"):].partition("?")
    host, _, port = address.rpartition(":")
    if not host or not port.isdigit():
        problems.append(f"host:port is wrong: {address!r}")
    if "+" in query:
        problems.append("a raw '+' is in the query; it must be %2B")

    pairs = dict(urllib.parse.parse_qsl(query, keep_blank_values=True))
    for key in REQUIRED_QUERY_KEYS:
        if key not in pairs:
            problems.append(f"missing {key}")
    if problems:
        return problems

    if pairs["privateKey"] != private_key:
        problems.append("privateKey is not the key entered in the app")
    for key in ("publicKey", "privateKey"):
        value = pairs[key]
        if len(value) != 44 or not value.endswith("="):
            problems.append(f"{key} is not a 44-character WireGuard key")
        else:
            try:
                if len(base64.b64decode(value, validate=True)) != 32:
                    problems.append(f"{key} does not decode to 32 bytes")
            except ValueError:
                problems.append(f"{key} is not base64")
    if not IPV4.match(pairs["ip"]):
        problems.append(f"ip must be a plain IPv4 address, got {pairs['ip']!r}")
    expected_fixed = {"mtu": "1280", "udp": "1", "keepalive": "25", "obfs": "amneziawg"}
    for key, value in expected_fixed.items():
        if pairs[key] != value:
            problems.append(f"{key} should be {value!r}, got {pairs[key]!r}")

    try:
        obfs = json.loads(pairs["obfsParam"])
    except json.JSONDecodeError:
        problems.append("obfsParam is not JSON")
        return problems
    if sorted(obfs) != sorted(REQUIRED_OBFS_KEYS):
        problems.append(f"obfsParam keys are {sorted(obfs)}")
    if not all(isinstance(value, str) for value in obfs.values()):
        problems.append("obfsParam values must be strings, as in the reference export")
    return problems


def copy_roundtrip(text: str, copy_cmd: Sequence[str], paste_cmd: Sequence[str]) -> Tuple[bool, str]:
    """Puts text on the clipboard with copy_cmd, reads it back with paste_cmd and compares."""
    copied = subprocess.run(list(copy_cmd), input=text.encode("utf-8"), capture_output=True)
    if copied.returncode != 0:
        return False, f"copy command failed: {copied.stderr.decode('utf-8', 'replace').strip()}"
    pasted = subprocess.run(list(paste_cmd), capture_output=True)
    if pasted.returncode != 0:
        return False, f"paste command failed: {pasted.stderr.decode('utf-8', 'replace').strip()}"
    got = pasted.stdout.decode("utf-8", "replace")
    if got.rstrip("\n") == text.rstrip("\n"):
        return True, "the clipboard holds exactly the copied text"
    return False, f"the clipboard text differs: copied {len(text)} characters, read back {len(got)}"


def _load_inputs(count: int, private_key_arg: Optional[str]):
    from browser_harvest import DEFAULT_DATA_FILE, load_blueprint
    from config_builder import is_valid_wg_key
    from mobile_core import DEFAULT_PRESET, endpoints_from_working_configs, params_for_preset
    from scan_cache import DEFAULT_SCAN_CACHE_FILE, load_scan_cache

    blueprint = load_blueprint(DEFAULT_DATA_FILE)
    ui = blueprint.user_interface
    key = (private_key_arg or ui.private_key or "").strip()
    if not key or not is_valid_wg_key(key):
        key = getpass.getpass("PrivateKey from Surfshark (44 characters, hidden): ").strip()
    if not is_valid_wg_key(key):
        raise SystemExit("The PrivateKey is not a 44-character WireGuard key.")
    ui.private_key = key

    data = load_scan_cache(DEFAULT_SCAN_CACHE_FILE) or {}
    endpoints = endpoints_from_working_configs(data.get("working_configs", []))
    if not endpoints:
        raise SystemExit(
            f"No working servers in {DEFAULT_SCAN_CACHE_FILE}. Run a scan first, then run this again."
        )
    return ui, endpoints[:count], params_for_preset(DEFAULT_PRESET), key


def main(argv: Optional[Sequence[str]] = None) -> int:
    from mobile_core import build_endpoint_wg_link, build_group_wg_links_text

    parser = argparse.ArgumentParser(description="Check the phone's wg:// copy text through the macOS clipboard.")
    parser.add_argument("--count", type=int, default=3, help="how many servers to copy as a group (default 3)")
    parser.add_argument("--no-clipboard", action="store_true", help="check the text only, do not touch the clipboard")
    parser.add_argument("--key", help="PrivateKey; if omitted, the saved key is used or you are asked")
    args = parser.parse_args(argv)

    ui, endpoints, params, key = _load_inputs(max(1, args.count), args.key)
    group_text = build_group_wg_links_text(endpoints, ui, params)
    single_text = build_endpoint_wg_link(endpoints[0], ui, params)

    failures = 0
    print(f"Checking {len(endpoints)} links, the way the phone's group copy builds them:")
    for number, (endpoint, link) in enumerate(zip(endpoints, group_text.split("\n")), start=1):
        problems = check_wg_link(link, key)
        status = "OK " if not problems else "BAD"
        print(f"  [{status}] {number}. {endpoint.country} — {endpoint.city} ({endpoint.ip})")
        for problem in problems:
            print(f"        - {problem}")
        failures += bool(problems)

    single_problems = check_wg_link(single_text, key)
    print(f"  [{'OK ' if not single_problems else 'BAD'}] single copy: {endpoints[0].ip}")
    failures += bool(single_problems)

    with open("copy_check_links.txt", "w", encoding="utf-8") as handle:
        handle.write(group_text + "\n")
    print("Links written to copy_check_links.txt (one per line).")

    if args.no_clipboard:
        print("Clipboard: skipped (--no-clipboard).")
    elif sys.platform != "darwin":
        print("Clipboard: skipped, pbcopy and pbpaste exist only on macOS.")
    else:
        ok, detail = copy_roundtrip(group_text, ["pbcopy"], ["pbpaste"])
        print(f"Clipboard, group text: {'OK' if ok else 'FAILED'}: {detail}")
        failures += not ok

    print("ALL CHECKS PASSED" if failures == 0 else f"{failures} CHECK(S) FAILED")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
