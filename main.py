#!/usr/bin/env python3
"""
main.py: Main Entrypoint for Surfshark AmneziaWG Studio

Can be run in GUI mode (default) or CLI mode for headless automated scans.

Usage:
  python3 main.py               # Launches Desktop GUI (Flet)
  python3 main.py --cli-scan    # Runs DoH resolution and UDP reachability scan from terminal
  python3 main.py --export-zip  # Directly exports all valid configs to a ZIP file
  python3 main.py --mobile      # Serves the phone-friendly UI on the LAN (open the printed URL on the phone)
"""

from __future__ import annotations

import argparse
import sys
import logging
import os

# Auto-switch to local .venv if current Python environment lacks dependencies
_venv_python = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".venv", "bin", "python")
if not os.path.exists(_venv_python):
    _parent_venv = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "Surfshark_AmneziaWG", ".venv", "bin", "python")
    if os.path.exists(_parent_venv):
        _venv_python = _parent_venv
if os.path.exists(_venv_python) and os.path.realpath(sys.executable) != os.path.realpath(_venv_python):
    try:
        import flet
    except ImportError:
        os.execv(_venv_python, [_venv_python] + sys.argv)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("SurfsharkAmnezia")


def run_cli_scan(output_zip: bool = False, force: bool = False):
    """Headless CLI scan mode for automation or headless environments."""
    from browser_harvest import DEFAULT_DATA_FILE, load_blueprint, save_blueprint
    from dns_resolver import resolve_servers_sync
    from checker import run_udp_scan_sync
    from config_builder import generate_batch_zip, AmneziaParams
    from vpn_detector import detect_active_vpn

    print("=" * 65)
    print(" Surfshark AmneziaWG Scanner & Generator v5.1 (CLI Mode)")
    print("=" * 65)

    # Active VPN Pre-Flight Check
    vpn_status = detect_active_vpn()
    if vpn_status.is_vpn_active:
        print("\n" + "!" * 65)
        print(" [!] CRITICAL WARNING: Active VPN tunnel detected!")
        print(f" [!] Default internet route uses interface: {vpn_status.interface}")
        print(" [!] To accurately measure server accessibility, please disconnect your VPN.")
        print(" [!] Otherwise, reachability packets route through foreign servers (false positives).")
        print("!" * 65)
        if not force:
            try:
                ans = input("\n[?] Do you want to continue despite active VPN? (y/N): ").strip().lower()
                if ans not in ("y", "yes"):
                    print("[*] Scan cancelled. Please disconnect your VPN and re-run.")
                    sys.exit(0)
            except (KeyboardInterrupt, EOFError):
                print("\n[*] Operation cancelled.")
                sys.exit(0)
    else:
        print(f"[*] Direct ISP connection confirmed ({vpn_status.interface}). VPN is inactive.")

    bp = load_blueprint(DEFAULT_DATA_FILE)
    print(f"[*] Loaded {len(bp.servers)} server clusters from {DEFAULT_DATA_FILE}")

    hostnames = [s.hostname for s in bp.servers]
    print(f"[*] Starting Anti-Poisoning DoH Resolution across {len(hostnames)} hostnames...")

    def _dns_cb(comp, tot, host, ips):
        if ips:
            print(f"  [{comp}/{tot}] {host} -> {len(ips)} IPs: {', '.join(ips[:3])}{'...' if len(ips) > 3 else ''}")
        else:
            print(f"  [{comp}/{tot}] {host} -> 0 IPs (Failed or filtered)")

    resolved_map = resolve_servers_sync(hostnames, on_progress=_dns_cb)

    total_discovered = 0
    udp_targets = []
    for s in bp.servers:
        ep = resolved_map.get(s.hostname)
        if ep and ep.ips:
            s.resolved_ips = ep.ips
            total_discovered += len(ep.ips)
            for ip in ep.ips:
                udp_targets.append((
                    ip,
                    s.port,
                    bp.user_interface.private_key,
                    s.public_key,
                    {"country": s.country, "city": s.city, "hostname": s.hostname, "public_key": s.public_key, "port": s.port}
                ))

    save_blueprint(bp, DEFAULT_DATA_FILE)
    print(f"\n[*] Discovered {total_discovered} raw IPv4 addresses across all clusters.")
    print(f"[*] Beginning concurrent UDP port 51820 reachability check ({len(udp_targets)} targets)...")

    working_configs = []

    def _udp_cb(comp, tot, res):
        if res.is_reachable:
            lat = f"{int(res.latency_ms)}ms"
            print(f"  [+] REACHABLE [{comp}/{tot}] {res.ip}:{res.port} ({lat})")
        else:
            # Print periodic progress
            if comp % 20 == 0 or comp == tot:
                print(f"  [-] Testing [{comp}/{tot}]... ({len(working_configs)} responsive so far)")

    results = run_udp_scan_sync(udp_targets, on_progress=_udp_cb, timeout=2.0)
    for r in results:
        if r.is_reachable and r.server_info:
            working_configs.append({
                "country": r.server_info["country"],
                "city": r.server_info["city"],
                "hostname": r.server_info["hostname"],
                "public_key": r.server_info["public_key"],
                "endpoint_ip": r.ip,
                "port": r.port,
                "latency_ms": r.latency_ms,
            })

    print(f"\n[+] Scan Complete! Verified {len(working_configs)} reachable server IPs.")

    if output_zip or working_configs:
        zip_name = "surfshark_amneziawg_verified.zip"
        generate_batch_zip(
            server_configs=working_configs,
            user_interface=bp.to_dict()["user_interface"],
            amnezia_params=AmneziaParams.iran_preset(),
            output_path=zip_name,
        )
        print(f"[+] Successfully exported {len(working_configs)} configs to: {os.path.abspath(zip_name)}")


def _guess_lan_ip() -> str:
    """Returns the address this machine uses on the local network (no packets are sent)."""
    import socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("10.255.255.255", 1))
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def run_mobile(port: int = 8550):
    """
    Serves the phone-friendly UI over the local network. Requests from other machines must
    carry the random token printed here (?t=...), because the page can copy WireGuard keys.
    Requests from this computer (127.0.0.1) do not need it.
    """
    import functools
    import secrets

    try:
        import flet as ft
        from mobile_app import main as mobile_main
    except ImportError as e:
        print(f"[!] Could not start the mobile UI: {e}")
        print("[!] Please ensure dependencies are installed: pip install -r requirements.txt")
        sys.exit(1)

    token = secrets.token_urlsafe(16)
    lan_ip = _guess_lan_ip()
    print("=" * 65)
    print(" Surfshark AmneziaWG Studio — Mobile UI")
    print("=" * 65)
    print(f" Phone (same Wi-Fi/hotspot): http://{lan_ip}:{port}/?t={token}")
    print(f" This computer:              http://127.0.0.1:{port}/?t={token}")
    print(" Keep these links private: they grant access to your WireGuard key.")
    print(" The page uses plain HTTP. Use it only on your home Wi-Fi or your own hotspot.")
    print("=" * 65)

    # view=None serves the page without opening a browser window; the printed links are used instead.
    ft.app(
        target=functools.partial(mobile_main, token=token),
        view=None,
        host="0.0.0.0",
        port=port,
    )


def run_gui():
    """Launches the modern Flet GUI."""
    try:
        import flet as ft

        # Backward compatibility aliases for Flet 0.23 - 0.28+
        if not hasattr(ft, "icons") and hasattr(ft, "Icons"):
            ft.icons = ft.Icons
        if not hasattr(ft, "colors") and hasattr(ft, "Colors"):
            ft.colors = ft.Colors

        # Hotfix for Flet 0.28.x on Python 3.9: Tab.before_update subscripted generic instance check
        try:
            from flet.core.tabs import Tab
            def _safe_tab_before_update(self):
                super(Tab, self).before_update()
                self._set_attr_json("iconMargin", getattr(self, "_Tab__icon_margin", None))
                icon = getattr(self, "_Tab__icon", None)
                if icon is not None and not isinstance(icon, ft.Control):
                    try:
                        from flet.core.types import IconEnums
                        self._set_enum_attr("icon", icon, IconEnums)
                    except Exception:
                        self._set_attr("icon", str(icon))
            Tab.before_update = _safe_tab_before_update
        except Exception:
            pass

        from ui import main as ui_main
        print("[*] Starting Surfshark AmneziaWG Desktop GUI v5.1...")
        try:
            ft.app(target=ui_main)
        except Exception as e:
            print(f"[!] Desktop native view notice: {e}")
            print("[*] Opening in browser mode (Web UI)...")
            ft.app(target=ui_main, view=ft.AppView.WEB_BROWSER)
    except ImportError as e:
        print(f"[!] Could not start GUI: {e}")
        print("[!] Please ensure dependencies are installed: pip install -r requirements.txt")
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Surfshark AmneziaWG Studio")
    parser.add_argument("--cli-scan", action="store_true", help="Run DNS resolution and UDP reachability scan in CLI mode")
    parser.add_argument("--export-zip", action="store_true", help="Export valid configs to a ZIP archive during CLI scan")
    parser.add_argument("--force", "--ignore-vpn", action="store_true", help="Bypass active VPN warning prompt in CLI mode")
    parser.add_argument("--mobile", action="store_true", help="Serve the phone-friendly UI on the local network")
    parser.add_argument("--port", type=int, default=8550, help="Port for --mobile (default 8550)")
    args = parser.parse_args()

    if args.cli_scan or args.export_zip:
        run_cli_scan(output_zip=args.export_zip, force=args.force)
    elif args.mobile:
        run_mobile(port=args.port)
    else:
        run_gui()
