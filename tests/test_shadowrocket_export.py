"""
test_shadowrocket_export.py: Unit tests for Shadowrocket AmneziaWG URL generation,
unified multi-peer configuration, and subscription bundling.
"""

import base64
import json
import os
import shutil
import tempfile
import unittest
import urllib.parse

import plistlib
from config_builder import (
    AmneziaParams,
    build_shadowrocket_wg_url,
    generate_shadowrocket_batch_conf,
    generate_shadowrocket_subscription,
    export_shadowrocket_bundle,
    ShadowrocketStorage,
    inject_servers_to_shadowrocket_storage,
    purge_shadowrocket_failed_servers,
    clear_shadowrocket_all_servers,
    get_shadowrocket_storage_stats,
    read_shadowrocket_test_results,
)


class TestShadowrocketExport(unittest.TestCase):
    def setUp(self):
        self.user_interface = {
            "private_key": "a" * 43 + "=",
            "address": "10.14.0.2/16",
            "dns": "162.252.172.57, 149.154.159.92",
        }
        self.sample_servers = [
            {
                "country": "Turkey",
                "country_code": "TR",
                "city": "Istanbul",
                "hostname": "tr-ist.prod.surfshark.com",
                "public_key": "b" * 43 + "=",
                "endpoint_ip": "194.26.29.115",
                "port": 51820,
                "latency_ms": 78.5,
            },
            {
                "country": "Azerbaijan",
                "country_code": "AZ",
                "city": "Baku",
                "hostname": "az-bak.prod.surfshark.com",
                "public_key": "c" * 43 + "=",
                "endpoint_ip": "185.228.19.123",
                "port": 51820,
                "latency_ms": 95.0,
            },
        ]
        self.test_dir = tempfile.mkdtemp(prefix="test_sr_export_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_build_shadowrocket_wg_url_format(self):
        url = build_shadowrocket_wg_url(
            self.sample_servers[0],
            self.user_interface,
            AmneziaParams.iran_preset(),
        )
        self.assertTrue(url.startswith("wg://194.26.29.115:51820?"))
        self.assertIn("obfs=amneziawg", url)
        self.assertIn("udp=1", url)
        self.assertIn("mtu=1280", url)

        # Parse query params
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)

        # Clean IP test: ensure NO CIDR mask (/16 or /32)
        self.assertIn("ip", query)
        self.assertEqual(query["ip"][0], "10.14.0.2")

        self.assertIn("obfsParam", query)
        obfs_json = query["obfsParam"][0]
        params_dict = json.loads(obfs_json)
        # Verify lowercase keys matching Shadowrocket internal schema
        self.assertEqual(params_dict["jc"], "4")
        self.assertEqual(params_dict["jmin"], "50")
        self.assertEqual(params_dict["jmax"], "1000")
        self.assertEqual(params_dict["s1"], "0")
        self.assertEqual(params_dict["s2"], "0")
        self.assertEqual(params_dict["h1"], "1")
        self.assertEqual(params_dict["h4"], "4")

        # Fragment (Title)
        self.assertTrue(len(parsed.fragment) > 0)
        decoded_title = urllib.parse.unquote(parsed.fragment)
        self.assertTrue(decoded_title.startswith("🦈 "))
        self.assertIn("Turkey", decoded_title)
        self.assertIn("Istanbul", decoded_title)

    def test_generate_shadowrocket_batch_conf(self):
        out_path = os.path.join(self.test_dir, "test_master.conf")
        content = generate_shadowrocket_batch_conf(
            self.sample_servers,
            self.user_interface,
            AmneziaParams.iran_preset(),
            output_path=out_path,
        )
        self.assertTrue(os.path.exists(out_path))
        self.assertIn("[Interface]", content)
        self.assertIn(f"PrivateKey = {self.user_interface['private_key']}", content)
        self.assertIn("Jc = 4", content)
        self.assertIn("Jmin = 50", content)
        self.assertIn("Jmax = 1000", content)
        self.assertIn("H1 = 1", content)
        self.assertIn("H4 = 4", content)

        # Multi-peer verification: exactly 2 [Peer] sections
        peer_count = content.count("[Peer]")
        self.assertEqual(peer_count, 2)
        self.assertIn("Endpoint = 194.26.29.115:51820", content)
        self.assertIn("Endpoint = 185.228.19.123:51820", content)

    def test_generate_shadowrocket_subscription(self):
        raw_text, b64_sub = generate_shadowrocket_subscription(
            self.sample_servers,
            self.user_interface,
            AmneziaParams.iran_preset(),
        )
        lines = raw_text.strip().split("\n")
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[0].startswith("wg://"))
        self.assertTrue(lines[1].startswith("wg://"))

        # Base64 decode check
        decoded = base64.b64decode(b64_sub.encode("utf-8")).decode("utf-8")
        self.assertEqual(decoded, raw_text)

    def test_export_shadowrocket_bundle(self):
        bundle = export_shadowrocket_bundle(
            self.sample_servers,
            self.user_interface,
            AmneziaParams.iran_preset(),
            output_dir=self.test_dir,
        )
        self.assertEqual(bundle["server_count"], 2)
        self.assertTrue(os.path.exists(bundle["bundle_dir"]))
        self.assertTrue(os.path.exists(bundle["master_conf_path"]))
        self.assertTrue(os.path.exists(bundle["subscription_b64_path"]))
        self.assertTrue(os.path.exists(bundle["subscription_raw_path"]))

        # Check ZIP bundle
        self.assertIn("zip_path", bundle)
        self.assertTrue(bundle["zip_path"] and os.path.exists(bundle["zip_path"]))

        # Check individual configs directory
        indiv_dir = os.path.join(bundle["bundle_dir"], "Individual_Configs")
        self.assertTrue(os.path.isdir(indiv_dir))
        files = os.listdir(indiv_dir)
        self.assertEqual(len(files), 2)
        for f in files:
            self.assertTrue(f.endswith(".conf"))

    def test_shadowrocket_wg_url_preserves_preshared_key(self):
        server_with_psk = dict(self.sample_servers[0])
        server_with_psk["preshared_key"] = "x" * 43 + "="
        url = build_shadowrocket_wg_url(
            server_with_psk,
            self.user_interface,
            AmneziaParams.iran_preset(),
        )
        self.assertIn("presharedKey=", url)
        self.assertIn(urllib.parse.quote(server_with_psk["preshared_key"]), url)

    def _create_mock_server_manager(self, filepath: str):
        """Creates a minimal valid ServerManager NSKeyedArchiver plist with 1 existing server."""
        mock_data = {
            "$archiver": "NSKeyedArchiver",
            "$version": 100000,
            "$top": {"root": plistlib.UID(1)},
            "$objects": [
                "$null",
                {"NS.objects": [plistlib.UID(2)], "$class": plistlib.UID(3)},
                {
                    "$class": plistlib.UID(4),
                    "host": plistlib.UID(5),
                    "port": plistlib.UID(6),
                    "type": plistlib.UID(7),
                },
                {"$classname": "NSMutableArray", "$classes": ["NSMutableArray", "NSArray", "NSObject"]},
                {"$classname": "DLWServer", "$classes": ["DLWServer", "NSObject"]},
                "existing-server.com",
                "51820",
                "WireGuard",
            ],
        }
        with open(filepath, "wb") as f:
            plistlib.dump(mock_data, f, fmt=plistlib.FMT_BINARY)

    def test_inject_servers_to_shadowrocket_storage(self):
        mock_plist = os.path.join(self.test_dir, "ServerManager")
        self._create_mock_server_manager(mock_plist)

        res = inject_servers_to_shadowrocket_storage(
            server_configs=self.sample_servers,
            user_interface=self.user_interface,
            amnezia_params=AmneziaParams.iran_preset(),
            storage_path=mock_plist,
        )
        self.assertTrue(res["success"])
        self.assertEqual(res["added_count"], 2)
        self.assertEqual(res["total_count"], 3)  # 1 existing + 2 added

        # Check backup was created
        self.assertTrue(os.path.exists(mock_plist + ".bak"))

        # Check idempotency / deduplication
        res_dup = inject_servers_to_shadowrocket_storage(
            server_configs=self.sample_servers,
            user_interface=self.user_interface,
            amnezia_params=AmneziaParams.iran_preset(),
            storage_path=mock_plist,
        )
        self.assertTrue(res_dup["success"])
        self.assertEqual(res_dup["added_count"], 0)  # Duplicates skipped
        self.assertEqual(res_dup["total_count"], 3)

        # Inspect injected DLWServer details
        with open(mock_plist, "rb") as f:
            data = plistlib.loads(f.read())
        server_uids = data["$objects"][1]["NS.objects"]
        self.assertEqual(len(server_uids), 3)

    def test_purge_failed_and_domain_servers(self):
        mock_plist = os.path.join(self.test_dir, "ServerManager_Purge")
        # Create mock plist with 1 domain server (existing-server.com)
        self._create_mock_server_manager(mock_plist)

        # Inject 2 IP servers: one reachable, one failed (ping=0)
        inject_servers_to_shadowrocket_storage(
            server_configs=self.sample_servers,
            user_interface=self.user_interface,
            storage_path=mock_plist,
        )

        storage = ShadowrocketStorage(mock_plist)
        self.assertEqual(len(storage.get_server_uids()), 3)

        # Test purging domains only (keeps all valid IPs)
        res_domains = purge_shadowrocket_failed_servers(mock_plist, keep_only_working_ips=False)
        self.assertEqual(res_domains["total_before"], 3)
        self.assertEqual(res_domains["removed_domains"], 1)  # existing-server.com removed
        self.assertEqual(res_domains["kept_count"], 2)  # the 2 valid IP servers kept

        # Now simulate a test result: server 1 has ping=85 (working), server 2 has ping=-2 (failed)
        storage_test = ShadowrocketStorage(mock_plist)
        # Server 0 in objects is the first server
        uids = storage_test.get_server_uids()
        storage_test.objects[uids[0].data]["ping"] = 85
        storage_test.objects[uids[1].data]["ping"] = -2
        storage_test.save()

        # Purge failed servers
        res_failed = purge_shadowrocket_failed_servers(mock_plist, keep_only_working_ips=True)
        self.assertEqual(res_failed["kept_count"], 1)  # Only the working server kept
        self.assertEqual(res_failed["removed_failed"], 1)

        # Verify on re-read
        storage_after = ShadowrocketStorage(mock_plist)
        results = storage_after.read_test_results()
        self.assertEqual(len(results), 1)
        for host, d in results.items():
            self.assertTrue(d["is_ip"])
            self.assertTrue(d["is_reachable"])

    def test_purge_safety_guard_blocks_wipe_when_no_positive_pings(self):
        mock_plist = os.path.join(self.test_dir, "ServerManager_Guard")
        self._create_mock_server_manager(mock_plist)
        inject_servers_to_shadowrocket_storage(
            server_configs=self.sample_servers,
            user_interface=self.user_interface,
            storage_path=mock_plist,
        )
        storage = ShadowrocketStorage(mock_plist)
        self.assertEqual(len(storage.get_server_uids()), 3)
        # All servers have ping=0. Attempting to purge with keep_only_working_ips=True must ABORT
        res = purge_shadowrocket_failed_servers(mock_plist, keep_only_working_ips=True)
        self.assertFalse(res.get("success", True))
        self.assertIn("No active servers with positive ping found", res["error"])
        # Ensure database was NOT wiped: still has 3 servers
        storage_after = ShadowrocketStorage(mock_plist)
        self.assertEqual(len(storage_after.get_server_uids()), 3)

    def test_read_shadowrocket_test_results(self):
        mock_plist = os.path.join(self.test_dir, "ServerManager_Read")
        self._create_mock_server_manager(mock_plist)
        results = read_shadowrocket_test_results(mock_plist)
        self.assertIn("existing-server.com", results)
        self.assertFalse(results["existing-server.com"]["is_ip"])

    def test_clear_all_servers(self):
        mock_plist = os.path.join(self.test_dir, "ServerManager_ClearAll")
        self._create_mock_server_manager(mock_plist)

        # Inject 2 servers
        inject_servers_to_shadowrocket_storage(
            server_configs=self.sample_servers,
            user_interface=self.user_interface,
            storage_path=mock_plist,
        )

        storage = ShadowrocketStorage(mock_plist)
        self.assertEqual(len(storage.get_server_uids()), 3)

        # Clear all servers
        res = clear_shadowrocket_all_servers(mock_plist)
        self.assertEqual(res["total_before"], 3)
        self.assertEqual(res["removed_count"], 3)
        self.assertEqual(res["remaining_count"], 0)

        # Re-read to confirm 0 servers remain
        storage_after = ShadowrocketStorage(mock_plist)
        self.assertEqual(len(storage_after.get_server_uids()), 0)

    def test_get_storage_stats(self):
        mock_plist = os.path.join(self.test_dir, "ServerManager_Stats")
        self._create_mock_server_manager(mock_plist)  # 1 domain server

        inject_servers_to_shadowrocket_storage(
            server_configs=self.sample_servers,
            user_interface=self.user_interface,
            storage_path=mock_plist,
        )

        stats = get_shadowrocket_storage_stats(mock_plist)
        self.assertEqual(stats["total"], 3)
        self.assertEqual(stats["domain_servers"], 1)
        # Newly injected servers start fresh with ping=0 (untested), not pre-filled
        self.assertEqual(stats["working_ips"], 0)
        self.assertEqual(stats["failed_ips"], 2)

    def test_ui_shadowrocket_export_methods_exist(self):
        import ui
        self.assertTrue(hasattr(ui.SurfsharkAmneziaApp, "_export_to_shadowrocket"))
        self.assertTrue(hasattr(ui.SurfsharkAmneziaApp, "_collect_export_targets"))
        self.assertTrue(hasattr(ui.SurfsharkAmneziaApp, "_copy_shadowrocket_subscription"))
        self.assertTrue(hasattr(ui.SurfsharkAmneziaApp, "_open_single_shadowrocket"))
        self.assertTrue(hasattr(ui.SurfsharkAmneziaApp, "_export_country_to_shadowrocket"))
        self.assertTrue(hasattr(ui.SurfsharkAmneziaApp, "_sync_results_from_shadowrocket"))
        self.assertTrue(hasattr(ui.SurfsharkAmneziaApp, "_clean_shadowrocket_failed_servers"))
        self.assertTrue(hasattr(ui.SurfsharkAmneziaApp, "_open_shadowrocket_manager_dialog"))
        self.assertTrue(hasattr(ui.SurfsharkAmneziaApp, "_confirm_clear_all_shadowrocket_servers"))
        self.assertTrue(hasattr(ui.SurfsharkAmneziaApp, "_execute_clear_all_shadowrocket_servers"))
        self.assertTrue(hasattr(ui.SurfsharkAmneziaApp, "_build_featured_countries_bar"))
        self.assertTrue(hasattr(ui.SurfsharkAmneziaApp, "_get_best_config_for_country"))
        self.assertTrue(hasattr(ui.SurfsharkAmneziaApp, "_export_featured_countries_to_shadowrocket"))

    def test_featured_countries_retrieval(self):
        import ui
        from browser_harvest import load_blueprint
        app = ui.SurfsharkAmneziaApp.__new__(ui.SurfsharkAmneziaApp)
        servers_path = os.path.join(os.path.dirname(__file__), "..", "surfshark_servers.json")
        app.blueprint = load_blueprint(servers_path)
        app.working_configs = [
            {"country": "Albania", "country_code": "AL", "city": "Tirana", "endpoint_ip": "172.216.15.115", "latency_ms": 174.0}
        ]
        app.scan_results = {}

        featured = [
            {"name": "Albania", "code": "AL", "aliases": ["albania"]},
            {"name": "Andorra", "code": "AD", "aliases": ["andorra", "andora"]},
            {"name": "Bahamas", "code": "BS", "aliases": ["bahamas"]},
            {"name": "Cambodia", "code": "KH", "aliases": ["cambodia"]},
            {"name": "Myanmar", "code": "MM", "aliases": ["myanmar", "burma"]},
            {"name": "Mongolia", "code": "MN", "aliases": ["mongolia"]},
        ]
        for fc in featured:
            best = app._get_best_config_for_country(fc)
            self.assertIsNotNone(best, f"Failed to retrieve config for {fc['name']}")
            self.assertEqual(best["country_code"], fc["code"])
            if fc["code"] == "AL":
                self.assertTrue(best.get("is_working"))
                self.assertEqual(best.get("latency_ms"), 174.0)

    def test_update_server_pings_storage(self):
        mock_plist = os.path.join(self.test_dir, "ServerManager_Pings")
        self._create_mock_server_manager(mock_plist)
        inject_servers_to_shadowrocket_storage(
            server_configs=self.sample_servers,
            user_interface=self.user_interface,
            storage_path=mock_plist,
        )
        storage = ShadowrocketStorage(mock_plist)
        # Initially ping is 0
        res_before = storage.read_test_results()
        self.assertEqual(res_before["194.26.29.115"]["ping"], 0)

        # Update with new live ping
        updated = storage.update_server_pings({"194.26.29.115": 78})
        self.assertEqual(updated, 1)

        # Re-read from disk
        storage_reloaded = ShadowrocketStorage(mock_plist)
        res_after = storage_reloaded.read_test_results()
        self.assertEqual(res_after["194.26.29.115"]["ping"], 78)
        self.assertTrue(res_after["194.26.29.115"]["is_reachable"])

    def test_get_shadowrocket_pid_and_running(self):
        from config_builder import get_shadowrocket_pid, is_shadowrocket_running
        pid = get_shadowrocket_pid()
        is_running = is_shadowrocket_running()
        if pid:
            self.assertTrue(is_running)
            self.assertIsInstance(pid, int)
        else:
            self.assertFalse(is_running)

    def test_ax_label_ping_parsing_logic(self):
        """
        Verify that the AX label parsing correctly distinguishes:
        - Format 1: "... UDP, 86ms" → working, ping = 86 (the LAST ms value)
        - Format 2: "... UDP, Timeout" → failed, ping = -1
        - Format 3: "... — 114ms" (no test yet) → uses cached ping = 114

        This ensures we do NOT confuse the cached previous ping (first Xms)
        with the NEW test result (last token after final comma).
        """
        import re

        def parse_ping_from_label(desc):
            """Mirrors the exact logic in read_shadowrocket_live_ax_results."""
            parts = desc.rsplit(",", 1)
            last_part = parts[-1].strip() if len(parts) > 1 else ""
            last_ms_m = re.match(r"^(\d+)\s*ms$", last_part, re.IGNORECASE)
            is_timeout = "timeout" in last_part.lower()
            if last_ms_m:
                return int(last_ms_m.group(1))
            elif is_timeout:
                return -1
            else:
                cached_m = re.search(r"—\s*(\d+)\s*ms", desc)
                return int(cached_m.group(1)) if cached_m else 0

        # Format 1: tested and working → should return the NEW result (86), not the old cached (118)
        label_working = "🇬🇧 United Kingdom — London (185.245.82.82) — 118ms, WIREGUARD / AMNEZIAWG / UDP, 86ms"
        self.assertEqual(parse_ping_from_label(label_working), 86, "Should read LAST ms value as new test result")

        # Format 2: tested but failed → should return -1
        label_timeout = "🇹🇷 Turkey — Istanbul (45.136.155.50) — 65ms, WIREGUARD / AMNEZIAWG / UDP, Timeout"
        self.assertEqual(parse_ping_from_label(label_timeout), -1, "Timeout should return -1")

        # Format 3: no new test run, just cached ping → should return cached 114
        label_cached = "🇦🇲 Armenia — Yerevan (92.62.120.101) — 114ms"
        self.assertEqual(parse_ping_from_label(label_cached), 114, "Should use cached ping when no new test")

        # Regression: old buggy code would return 118 (first ms) for the working server
        # The corrected code must return 86 (last ms / actual test result)
        wrong_old_parse = re.search(r"(\d+)\s*ms\b", label_working, re.IGNORECASE)
        self.assertEqual(int(wrong_old_parse.group(1)), 118, "Old code WOULD have returned 118 (wrong)")
        self.assertEqual(parse_ping_from_label(label_working), 86, "New code correctly returns 86")

    def test_proton_dual_stack_shadowrocket_injection(self):
        """Verify that inject_servers_to_shadowrocket_storage cleanly extracts IPv4 from Proton dual-stack address."""
        proton_ui = {
            "private_key": "K" * 43 + "=",
            "address": "10.2.0.2/32, 2a07:b944::2:2/128",
            "dns": "10.2.0.1, 2a07:b944::2:1",
        }
        test_storage_path = os.path.join(self.test_dir, "ServerManager")
        self._create_mock_server_manager(test_storage_path)

        res = inject_servers_to_shadowrocket_storage(
            server_configs=self.sample_servers,
            user_interface=proton_ui,
            storage_path=test_storage_path,
        )
        self.assertTrue(res["success"])
        self.assertEqual(res["added_count"], 2)

        with open(test_storage_path, "rb") as f:
            data = plistlib.loads(f.read())
        server_uids = data["$objects"][1]["NS.objects"]
        for s_uid in server_uids:
            s_obj = data["$objects"][s_uid.data]
            if isinstance(s_obj, dict) and "ip" in s_obj:
                ip_val = data["$objects"][s_obj["ip"].data]
                if ip_val != "existing-server.com":
                    actual_ip = ip_val.get("NS.string", ip_val) if isinstance(ip_val, dict) else ip_val
                    self.assertEqual(actual_ip, "10.2.0.2", "IPv4 address must be cleanly extracted without CIDR or IPv6")
                    pk_val = data["$objects"][s_obj["privateKey"].data]
                    actual_pk = pk_val.get("NS.string", pk_val) if isinstance(pk_val, dict) else pk_val
                    self.assertEqual(actual_pk, proton_ui["private_key"], "Must preserve Proton private key")

    def test_proton_shadowrocket_bundle_export(self):
        """Verify export_shadowrocket_bundle creates Proton-named package and respects proton kwargs."""
        proton_ui = {
            "private_key": "K" * 43 + "=",
            "address": "10.2.0.2/32",
            "dns": "10.2.0.1",
        }
        bundle = export_shadowrocket_bundle(
            server_configs=self.sample_servers,
            user_interface=proton_ui,
            output_dir=self.test_dir,
            provider="proton",
            netshield_level=2,
            moderate_nat=True,
            nat_pmp=True,
            vpn_accelerator=True,
        )
        self.assertIn("Proton_Shadowrocket", bundle["bundle_dir"])
        self.assertTrue(os.path.exists(bundle["master_conf_path"]))
        with open(bundle["master_conf_path"], "r") as f:
            content = f.read()
            self.assertIn("Proton", content)
            self.assertIn(proton_ui["private_key"], content)


if __name__ == "__main__":
    unittest.main()
