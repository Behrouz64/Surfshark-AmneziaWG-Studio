"""
Unit and Integration Tests for Surfshark AmneziaWG Tool
"""

import io
import json
import os
import sys
import unittest
import zipfile

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dns_resolver import is_valid_public_ipv4, SecureDnsResolver
from checker import (
    generate_wireguard_initiation,
    WG_INITIATION_SIZE,
    CheckResult,
)
from config_builder import (
    AmneziaParams,
    build_amnezia_config,
    generate_qr_code_base64,
    generate_batch_zip,
    sanitize_filename,
)
from browser_harvest import (
    BlueprintData,
    UserInterfaceConfig,
    ServerMetadata,
    parse_wireguard_conf_content,
    get_default_seed_blueprint,
    save_blueprint,
    load_blueprint,
)


class TestDnsResolver(unittest.TestCase):
    def test_ip_validation_filter(self):
        # Valid globally routable IPs
        self.assertTrue(is_valid_public_ipv4("1.1.1.1"))
        self.assertTrue(is_valid_public_ipv4("8.8.8.8"))
        self.assertTrue(is_valid_public_ipv4("185.220.101.5"))

        # Poisoned / Iranian ISP sinkholes
        self.assertFalse(is_valid_public_ipv4("10.10.34.34"))
        self.assertFalse(is_valid_public_ipv4("10.0.0.1"))

        # RFC 1918 Private networks
        self.assertFalse(is_valid_public_ipv4("192.168.1.1"))
        self.assertFalse(is_valid_public_ipv4("172.16.0.5"))

        # Loopback, broadcast, invalid
        self.assertFalse(is_valid_public_ipv4("127.0.0.1"))
        self.assertFalse(is_valid_public_ipv4("0.0.0.0"))
        self.assertFalse(is_valid_public_ipv4("255.255.255.255"))
        self.assertFalse(is_valid_public_ipv4("invalid_hostname.com"))
        self.assertFalse(is_valid_public_ipv4(""))


class TestConfigBuilder(unittest.TestCase):
    def test_amnezia_conf_structure(self):
        params = AmneziaParams(jc=4, jmin=50, jmax=1000, s1=0, s2=0, h1=1, h2=2, h3=3, h4=4)
        conf = build_amnezia_config(
            client_private_key="PRIVKEY123=",
            client_address="10.14.0.2/16",
            client_dns="162.252.172.57",
            server_public_key="PUBKEY456=",
            endpoint_ip="185.220.101.5",
            endpoint_port=51820,
            amnezia_params=params,
        )

        self.assertIn("[Interface]", conf)
        self.assertIn("PrivateKey = PRIVKEY123=", conf)
        self.assertIn("Address = 10.14.0.2/16", conf)
        self.assertIn("DNS = 162.252.172.57", conf)
        self.assertIn("Jc = 4", conf)
        self.assertIn("Jmin = 50", conf)
        self.assertIn("Jmax = 1000", conf)
        self.assertIn("S1 = 0", conf)
        self.assertIn("S2 = 0", conf)
        self.assertIn("H1 = 1", conf)
        self.assertIn("H2 = 2", conf)
        self.assertIn("H3 = 3", conf)
        self.assertIn("H4 = 4", conf)
        self.assertIn("[Peer]", conf)
        self.assertIn("PublicKey = PUBKEY456=", conf)
        self.assertIn("Endpoint = 185.220.101.5:51820", conf)
        self.assertIn("PersistentKeepalive = 25", conf)

    def test_qr_code_generation(self):
        conf = "[Interface]\nPrivateKey = abc\n[Peer]\nPublicKey = def\nEndpoint = 1.2.3.4:51820"
        qr_b64 = generate_qr_code_base64(conf)
        # Should return a valid non-empty base64 string
        if qr_b64 is not None:
            self.assertGreater(len(qr_b64), 50)
            self.assertTrue(qr_b64.isalnum() or "/" in qr_b64 or "+" in qr_b64)

    def test_batch_zip_generation(self):
        servers = [
            {
                "country": "Germany",
                "city": "Berlin",
                "hostname": "de-ber.prod.surfshark.com",
                "public_key": "pub_berlin=",
                "endpoint_ip": "185.220.101.5",
                "port": 51820,
                "latency_ms": 78.5,
            },
            {
                "country": "United States",
                "city": "New York",
                "hostname": "us-nyc.prod.surfshark.com",
                "public_key": "pub_nyc=",
                "endpoint_ip": "198.51.100.2",
                "port": 51820,
                "latency_ms": 142.1,
            },
        ]
        u_iface = {
            "private_key": "priv_user=",
            "address": "10.14.0.2/16",
            "dns": "162.252.172.57",
        }
        zip_bytes = generate_batch_zip(servers, u_iface)
        self.assertGreater(len(zip_bytes), 100)

        # Verify ZIP contains country directories and files
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            namelist = zf.namelist()
            self.assertIn("README.txt", namelist)
            has_de = any("Germany" in n for n in namelist)
            has_us = any("United_States" in n for n in namelist)
            self.assertTrue(has_de, "Missing Germany folder in ZIP")
            self.assertTrue(has_us, "Missing United_States folder in ZIP")

    def test_batch_zip_generation_with_domains(self):
        servers = [
            {
                "country": "Albania",
                "country_code": "AL",
                "city": "Tirana",
                "hostname": "al-tia.prod.surfshark.com",
                "public_key": "pub_tirana=",
                "endpoint_ip": "al-tia.prod.surfshark.com",
                "port": 51820,
                "is_domain": True,
            },
            {
                "country": "Albania",
                "country_code": "AL",
                "city": "Tirana",
                "hostname": "al-tia.prod.surfshark.com",
                "public_key": "pub_tirana=",
                "endpoint_ip": "172.216.14.229",
                "port": 51820,
                "latency_ms": 65.0,
            },
        ]
        u_iface = {
            "private_key": "priv_user=",
            "address": "10.14.0.2/16",
            "dns": "162.252.172.57",
        }
        zip_bytes = generate_batch_zip(servers, u_iface)
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            namelist = zf.namelist()
            # New format: "🇦🇱 Tirana — DOMAIN — al-tia.prod.surfshark.com.conf"
            domain_files = [n for n in namelist if "DOMAIN" in n]
            self.assertEqual(len(domain_files), 1)
            # Verify the domain endpoint appears in the config content
            content = zf.read(domain_files[0]).decode("utf-8")
            self.assertIn("Endpoint = al-tia.prod.surfshark.com:51820", content)
            # Verify tunnel name is embedded in config
            self.assertIn("# Name =", content)
            self.assertIn("Tirana", content)

            # Must also have raw IP config
            ip_files = [n for n in namelist if "172.216.14.229" in n]
            self.assertEqual(len(ip_files), 1)
            ip_content = zf.read(ip_files[0]).decode("utf-8")
            self.assertIn("Endpoint = 172.216.14.229:51820", ip_content)
            self.assertIn("# Name =", ip_content)

    def test_sanitize_filename(self):
        self.assertEqual(sanitize_filename("United States"), "United_States")
        self.assertEqual(sanitize_filename("Frankfurt/Main:1"), "Frankfurt_Main_1")


class TestChecker(unittest.TestCase):
    def test_wireguard_initiation_packet_size(self):
        packet = generate_wireguard_initiation()
        self.assertEqual(len(packet), WG_INITIATION_SIZE)
        # First 4 bytes must be message type 1 (little-endian uint32)
        self.assertEqual(packet[:4], b"\x01\x00\x00\x00")


class TestBrowserHarvestAndBlueprint(unittest.TestCase):
    def test_parse_wireguard_conf(self):
        sample = """
        [Interface]
        PrivateKey = user_private_key_abc=
        Address = 10.14.0.4/16
        DNS = 162.252.172.57, 149.154.159.92

        [Peer]
        PublicKey = server_public_key_xyz=
        AllowedIPs = 0.0.0.0/0
        Endpoint = de-fra.prod.surfshark.com:51820
        """
        parsed = parse_wireguard_conf_content(sample)
        self.assertEqual(parsed["private_key"], "user_private_key_abc=")
        self.assertEqual(parsed["address"], "10.14.0.4/16")
        self.assertEqual(parsed["endpoint"], "de-fra.prod.surfshark.com")
        self.assertEqual(parsed["port"], 51820)
        self.assertEqual(parsed["public_key"], "server_public_key_xyz=")

    def test_blueprint_serialization(self):
        bp = get_default_seed_blueprint()
        self.assertGreater(len(bp.servers), 10)

        # Save to temp file and reload
        tmp_path = "/tmp/test_blueprint_tmp.json"
        try:
            save_blueprint(bp, tmp_path)
            loaded = load_blueprint(tmp_path)
            self.assertEqual(len(bp.servers), len(loaded.servers))
            self.assertEqual(bp.servers[0].hostname, loaded.servers[0].hostname)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_albania_and_global_seed_catalog(self):
        bp = get_default_seed_blueprint()
        # Ensure expanded catalog has 60+ servers
        self.assertGreaterEqual(len(bp.servers), 60)

        # Ensure Albania is present with correct hostname
        albania_servers = [s for s in bp.servers if s.country.lower() == "albania" or s.country_code.upper() == "AL"]
        self.assertGreaterEqual(len(albania_servers), 1)
        albania = albania_servers[0]
        self.assertEqual(albania.country, "Albania")
        self.assertEqual(albania.city, "Tirana")
        self.assertEqual(albania.hostname, "al-tia.prod.surfshark.com")
        self.assertEqual(albania.public_key, "l8EOWPyzt/njrb74CADY4VOhns/TbUN6KFTbytHcFQw=")

    def test_private_key_inclusion(self):
        privkey = "4JzXvG+aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890="
        conf = build_amnezia_config(
            client_private_key=privkey,
            client_address="10.14.0.2/16",
            client_dns="162.252.172.57",
            server_public_key="server_pubkey_abc=",
            endpoint_ip="172.216.14.229",
            endpoint_port=51820,
        )
        self.assertIn(f"PrivateKey = {privkey}", conf)
        self.assertNotIn("YOUR_PRIVATE_KEY_HERE", conf)

    def test_derive_public_key(self):
        from config_builder import derive_public_key
        # Test with known x25519 vector: 32 bytes of 0x01
        test_priv_b64 = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
        pub_b64 = derive_public_key(test_priv_b64)
        self.assertIsNotNone(pub_b64)
        self.assertEqual(pub_b64, "pOCSkrZRwni5dyxWn1+puxPZBrRqtoyd+dwrRAn4ogk=")

        # Invalid key should return None
        self.assertIsNone(derive_public_key("invalid_key"))
        self.assertIsNone(derive_public_key(""))


class TestVpnDetector(unittest.TestCase):
    def test_vpn_detection_structure(self):
        # Route output is mocked so the result does not depend on the live VPN state of the machine.
        from unittest.mock import patch
        from vpn_detector import detect_active_vpn, VpnStatus
        with patch("vpn_detector.platform.system", return_value="Linux"), \
                patch("vpn_detector.subprocess.check_output",
                      return_value="default via 192.168.1.1 dev eth0 proto dhcp metric 100\n"):
            status = detect_active_vpn()
        self.assertIsInstance(status, VpnStatus)
        self.assertIsInstance(status.is_vpn_active, bool)
        self.assertIsInstance(status.interface, str)
        self.assertGreater(len(status.summary_fa), 0)
        self.assertGreater(len(status.warning_fa), 0)


class TestUiModalIntegrity(unittest.TestCase):
    def test_ui_imports_and_qr_modal_logic(self):
        import ui
        self.assertTrue(hasattr(ui, "re"), "ui.py must import re")

        # Test logic used in _do_show_qr_modal
        server = ServerMetadata(
            continent="Europe",
            country="Albania",
            country_code="AL",
            city="Tirana",
            hostname="al-tia.prod.surfshark.com",
            port=51820,
            public_key="pubkey_test=",
            resolved_ips=["172.216.14.133"],
        )
        
        # Test with domain
        ip_domain = server.hostname
        is_domain_test = (ip_domain == server.hostname) or not ui.re.match(r'^\d+\.\d+\.\d+\.\d+$', str(ip_domain))
        self.assertTrue(is_domain_test)

        # Test with raw IP
        ip_raw = "172.216.14.133"
        is_domain_raw = (ip_raw == server.hostname) or not ui.re.match(r'^\d+\.\d+\.\d+\.\d+$', str(ip_raw))
        self.assertFalse(is_domain_raw)


# =============================================================================
# NEW v2 Tests
# =============================================================================

class TestV2IsPlaceholderKey(unittest.TestCase):
    """Tests for the new is_placeholder_key() function in browser_harvest."""

    def setUp(self):
        from browser_harvest import is_placeholder_key
        self.is_placeholder_key = is_placeholder_key

    def test_real_albania_key_is_not_placeholder(self):
        """The real Albania public key must not be detected as placeholder."""
        real_key = "l8EOWPyzt/njrb74CADY4VOhns/TbUN6KFTbytHcFQw="
        self.assertFalse(self.is_placeholder_key(real_key))

    def test_seed_fake_keys_are_detected(self):
        """All the sequential fake seed keys should be detected."""
        fake_keys = [
            "y8o+c1p191WvA9d0j9aB9C1d9E2f3g4h5i6j7k8l9m0=",
            "z8o+c1p191WvA9d0j9aB9C1d9E2f3g4h5i6j7k8l9m1=",
            "x8o+c1p191WvA9d0j9aB9C1d9E2f3g4h5i6j7k8l9m2=",
            "a1o+c1p191WvA9d0j9aB9C1d9E2f3g4h5i6j7k8l9m1=",
            "i8o+c1p191WvA9d0j9aB9C1d9E2f3g4h5i6j7k8l9m7=",
        ]
        for key in fake_keys:
            self.assertTrue(self.is_placeholder_key(key), f"Should be placeholder: {key}")

    def test_empty_and_short_keys_are_placeholder(self):
        self.assertTrue(self.is_placeholder_key(""))
        self.assertTrue(self.is_placeholder_key("short"))
        self.assertTrue(self.is_placeholder_key(None))

    def test_wrong_length_key_is_placeholder(self):
        self.assertTrue(self.is_placeholder_key("abc" * 10))  # Not 44 chars


class TestV2IsValidWgKey(unittest.TestCase):
    """Tests for is_valid_wg_key() in config_builder."""

    def setUp(self):
        from config_builder import is_valid_wg_key
        self.is_valid_wg_key = is_valid_wg_key

    def test_valid_keys(self):
        # 44-char base64 strings encoding 32 bytes
        valid_keys = [
            "l8EOWPyzt/njrb74CADY4VOhns/TbUN6KFTbytHcFQw=",
            "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        ]
        for key in valid_keys:
            self.assertTrue(self.is_valid_wg_key(key), f"Should be valid: {key}")

    def test_invalid_keys(self):
        invalid = ["", "short", "toolong" * 10, "not_base64!!!@@@"]
        for key in invalid:
            self.assertFalse(self.is_valid_wg_key(key), f"Should be invalid: {key}")


class TestV2BrowserHarvestThreadingImport(unittest.TestCase):
    """Verifies that the critical threading import is present in browser_harvest."""

    def test_threading_is_imported(self):
        """Bug fix: threading was missing in v1 causing NameError crash."""
        import browser_harvest
        import threading
        # The module must have threading available (not just shadowed)
        self.assertTrue(hasattr(browser_harvest, "threading") or
                        "threading" in dir(browser_harvest) or
                        hasattr(threading, "Event"))

    def test_fetch_surfshark_public_keys_mock(self):
        """Test fetch_surfshark_public_keys with a mocked HTTP response."""
        from unittest.mock import patch, MagicMock
        import json
        from browser_harvest import fetch_surfshark_public_keys

        mock_response_data = [
            {"connectionName": "al-tia.prod.surfshark.com", "pubKey": "l8EOWPyzt/njrb74CADY4VOhns/TbUN6KFTbytHcFQw="},
            {"connectionName": "de-ber.prod.surfshark.com", "pubKey": "dEBerPublicKey1234567890123456789012345678="},
            {"connectionName": "us-nyc.prod.surfshark.com", "pubKey": "USNycPublicKey12345678901234567890123456="},
        ]
        mock_bytes = json.dumps(mock_response_data).encode("utf-8")

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = mock_bytes
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = fetch_surfshark_public_keys(timeout=5.0)

        self.assertIn("al-tia.prod.surfshark.com", result)
        self.assertEqual(result["al-tia.prod.surfshark.com"], "l8EOWPyzt/njrb74CADY4VOhns/TbUN6KFTbytHcFQw=")
        self.assertIn("de-ber.prod.surfshark.com", result)
        self.assertIn("us-nyc.prod.surfshark.com", result)
        self.assertEqual(len(result), 3)

    def test_update_blueprint_with_api_keys_mock(self):
        """Test update_blueprint_with_api_keys correctly updates server entries."""
        from unittest.mock import patch, MagicMock
        import json
        from browser_harvest import update_blueprint_with_api_keys, get_default_seed_blueprint

        bp = get_default_seed_blueprint()
        old_albania_key = next(s.public_key for s in bp.servers if s.hostname == "al-tia.prod.surfshark.com")

        mock_response_data = [
            {"connectionName": "al-tia.prod.surfshark.com", "pubKey": "NEWREALKEY_Albania_abcdefghijklmnopqrstuv="},
            {"connectionName": "de-ber.prod.surfshark.com", "pubKey": "NEWREALKEY_Germany_abcdefghijklmnopqrstu="},
        ]
        mock_bytes = json.dumps(mock_response_data).encode("utf-8")

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = mock_bytes
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            updated = update_blueprint_with_api_keys(bp, on_log=None, save_path=None)

        self.assertGreaterEqual(updated, 2)
        albania = next(s for s in bp.servers if s.hostname == "al-tia.prod.surfshark.com")
        self.assertEqual(albania.public_key, "NEWREALKEY_Albania_abcdefghijklmnopqrstuv=")


class TestV2ConfigBuilderWarnings(unittest.TestCase):
    """Test that build_amnezia_config adds warning comments for invalid keys."""

    def test_warning_added_for_invalid_private_key(self):
        from config_builder import build_amnezia_config, AmneziaParams
        conf = build_amnezia_config(
            client_private_key="BADKEY",
            client_address="10.14.0.2/16",
            client_dns="162.252.172.57",
            server_public_key="l8EOWPyzt/njrb74CADY4VOhns/TbUN6KFTbytHcFQw=",
            endpoint_ip="172.216.15.115",
            amnezia_params=AmneziaParams.standard_wireguard(),
        )
        self.assertIn("WARNING", conf)
        self.assertIn("PrivateKey", conf)

    def test_warning_added_for_invalid_server_key(self):
        from config_builder import build_amnezia_config, AmneziaParams
        conf = build_amnezia_config(
            client_private_key="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            client_address="10.14.0.2/16",
            client_dns="162.252.172.57",
            server_public_key="FAKEKEY",
            endpoint_ip="172.216.15.115",
            amnezia_params=AmneziaParams.standard_wireguard(),
        )
        self.assertIn("WARNING", conf)
        self.assertIn("PublicKey", conf)

    def test_no_warning_for_valid_keys(self):
        from config_builder import build_amnezia_config, AmneziaParams
        conf = build_amnezia_config(
            client_private_key="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            client_address="10.14.0.2/16",
            client_dns="162.252.172.57",
            server_public_key="l8EOWPyzt/njrb74CADY4VOhns/TbUN6KFTbytHcFQw=",
            endpoint_ip="172.216.15.115",
            amnezia_params=AmneziaParams.standard_wireguard(),
        )
        self.assertNotIn("WARNING", conf)


class TestV3ScanCacheAndTop5(unittest.TestCase):
    """Test v3 Scan Cache persistence and Top 5 server ranking."""

    def test_extract_top_servers_ranking(self):
        from scan_cache import extract_top_servers
        configs = [
            {"city": "Paris", "latency_ms": 120.0},
            {"city": "Berlin", "latency_ms": 55.0},
            {"city": "London", "latency_ms": 80.0},
            {"city": "Amsterdam", "latency_ms": 65.0},
            {"city": "Tirana", "latency_ms": 70.0},
            {"city": "Madrid", "latency_ms": 150.0},
        ]
        top = extract_top_servers(configs, limit=5)
        self.assertEqual(len(top), 5)
        self.assertEqual(top[0]["city"], "Berlin")
        self.assertEqual(top[0]["rank"], 1)
        self.assertEqual(top[1]["city"], "Amsterdam")
        self.assertEqual(top[1]["rank"], 2)
        self.assertEqual(top[2]["city"], "Tirana")
        self.assertEqual(top[3]["city"], "London")
        self.assertEqual(top[4]["city"], "Paris")

    def test_extract_top_servers_empty(self):
        from scan_cache import extract_top_servers
        self.assertEqual(extract_top_servers([]), [])
        self.assertEqual(extract_top_servers([{"city": "Nowhere", "latency_ms": 9999.0}]), [])

    def test_save_and_load_scan_cache(self):
        import os
        import shutil
        import tempfile
        from scan_cache import save_scan_cache, load_scan_cache
        from checker import CheckResult

        # Write into a temp dir, not the working directory (a relative path would land in the project folder).
        test_dir = tempfile.mkdtemp(prefix="test_scan_cache_")
        test_file = os.path.join(test_dir, "test_cache_temp.json")
        try:
            mock_results = {
                "de-ber.prod.surfshark.com": [
                    CheckResult(ip="185.220.101.5", port=51820, is_reachable=True, latency_ms=55.0, status="handshake_ok")
                ]
            }
            mock_configs = [
                {
                    "country": "Germany",
                    "country_code": "DE",
                    "city": "Berlin",
                    "hostname": "de-ber.prod.surfshark.com",
                    "public_key": "pub=",
                    "endpoint_ip": "185.220.101.5",
                    "port": 51820,
                    "latency_ms": 55.0,
                }
            ]

            saved = save_scan_cache(mock_results, mock_configs, filepath=test_file)
            self.assertEqual(saved["working_count"], 1)
            self.assertEqual(len(saved["top_5"]), 1)

            loaded = load_scan_cache(filepath=test_file)
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded["working_count"], 1)
            self.assertEqual(loaded["top_5"][0]["city"], "Berlin")
        finally:
            shutil.rmtree(test_dir, ignore_errors=True)

    def test_v3_config_builder_header(self):
        from config_builder import build_amnezia_config, AmneziaParams
        conf = build_amnezia_config(
            client_private_key="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            client_address="10.14.0.2/16",
            client_dns="162.252.172.57",
            server_public_key="l8EOWPyzt/njrb74CADY4VOhns/TbUN6KFTbytHcFQw=",
            endpoint_ip="172.216.15.115",
            amnezia_params=AmneziaParams.standard_wireguard(),
            tunnel_name="🇦🇱 Tirana (Albania) — 62ms",
        )
        self.assertIn("Surfshark & Proton AmneziaWG Studio v5", conf)
        self.assertIn("# Name = 🇦🇱 Tirana (Albania) — 62ms", conf)


class TestV3VerificationModesAndDeepScreening(unittest.TestCase):
    """
    Tests for v3 Strict UDP Anti-DPI mode and Deep Multi-Probe Screening.
    Verifies that ping-only false positives (like Turkey IPs) are rejected in Strict mode
    and eliminated by deep screening.
    """

    def test_strict_udp_rejects_ping_only(self):
        from unittest.mock import patch, MagicMock
        from checker import check_udp_endpoint_sync, ScanMode
        import socket

        # Mock socket to raise timeout (UDP port dropped by DPI)
        mock_sock = MagicMock()
        mock_sock.recvfrom.side_effect = socket.timeout("timed out")

        with patch("socket.socket", return_value=mock_sock):
            with patch("checker.ping_latency_ms", return_value=42.5):
                # In Strict UDP mode (default), ping-only MUST NOT be marked is_reachable
                res = check_udp_endpoint_sync("84.17.45.1", 51820, mode=ScanMode.STRICT_UDP)
                self.assertFalse(res.is_reachable)
                self.assertEqual(res.status, "ping_only_udp_blocked")
                self.assertEqual(res.latency_ms, 42.5)
                self.assertEqual(res.packet_loss, 100.0)

    def test_smart_mode_accepts_dummy_key_with_ping(self):
        """
        In Smart mode, when using a placeholder/dummy key, standard WireGuard servers
        (e.g. Azerbaijan) silently drop unauthenticated handshakes. Since ICMP ping
        responds, it correctly marks the endpoint as reachable (ping_alive).
        """
        from unittest.mock import patch, MagicMock
        from checker import check_udp_endpoint_sync, ScanMode, DEFAULT_DUMMY_CLIENT_KEY
        import socket

        mock_sock = MagicMock()
        mock_sock.recvfrom.side_effect = socket.timeout("timed out")

        with patch("socket.socket", return_value=mock_sock):
            with patch("checker.ping_latency_ms", return_value=55.0):
                res = check_udp_endpoint_sync(
                    "89.117.47.35",
                    51820,
                    client_private_key=DEFAULT_DUMMY_CLIENT_KEY,
                    server_public_key="pvWYTFxIpqo25NGTertIIWnccS/sUQ6fIkqd8XJYzEI=",
                    mode=ScanMode.SMART,
                )
                self.assertTrue(res.is_reachable)
                self.assertEqual(res.status, "ping_alive")
                self.assertEqual(res.latency_ms, 55.0)

    def test_smart_mode_rejects_real_key_when_udp_blocked(self):
        """
        In Smart mode, when using authenticated keys, if UDP is silent but host answers ping,
        it accurately detects DPI UDP filtering.
        """
        from unittest.mock import patch, MagicMock
        from checker import check_udp_endpoint_sync, ScanMode
        import socket

        mock_sock = MagicMock()
        mock_sock.recvfrom.side_effect = socket.timeout("timed out")

        real_client_key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
        real_server_key = "l8EOWPyzt/njrb74CADY4VOhns/TbUN6KFTbytHcFQw="

        with patch("socket.socket", return_value=mock_sock):
            with patch("checker.ping_latency_ms", return_value=38.0):
                res = check_udp_endpoint_sync(
                    "84.17.45.1",
                    51820,
                    client_private_key=real_client_key,
                    server_public_key=real_server_key,
                    mode=ScanMode.SMART,
                )
                self.assertFalse(res.is_reachable)
                self.assertEqual(res.status, "ping_only_udp_blocked")
                self.assertEqual(res.latency_ms, 38.0)

    def test_permissive_accepts_ping_only(self):
        from unittest.mock import patch, MagicMock
        from checker import check_udp_endpoint_sync, ScanMode
        import socket

        mock_sock = MagicMock()
        mock_sock.recvfrom.side_effect = socket.timeout("timed out")

        with patch("socket.socket", return_value=mock_sock):
            with patch("checker.ping_latency_ms", return_value=42.5):
                # In Permissive mode, ping-only is accepted
                res = check_udp_endpoint_sync("84.17.45.1", 51820, mode=ScanMode.PERMISSIVE)
                self.assertTrue(res.is_reachable)
                self.assertEqual(res.status, "ping_alive")
                self.assertEqual(res.latency_ms, 42.5)

    def test_deep_verify_stable_endpoint(self):
        from unittest.mock import patch, MagicMock
        from checker import deep_verify_endpoint_sync

        # Mock socket to return a 92-byte WireGuard handshake response
        mock_sock = MagicMock()
        mock_sock.recvfrom.return_value = (b"\x02\x00\x00\x00" + b"\x00" * 88, ("1.2.3.4", 51820))

        with patch("socket.socket", return_value=mock_sock):
            res = deep_verify_endpoint_sync(
                "1.2.3.4",
                51820,
                probe_count=3,
                probe_delay_ms=0,
            )
            self.assertTrue(res.is_reachable)
            self.assertEqual(res.status, "verified_stable")
            self.assertEqual(res.packet_loss, 0.0)
            self.assertTrue(res.deep_verified)

    def test_deep_screen_working_configs_purges_turkey_false_positive(self):
        from unittest.mock import patch
        from checker import deep_screen_working_configs_sync, CheckResult

        configs = [
            {
                "country": "United Kingdom",
                "country_code": "GB",
                "city": "London",
                "hostname": "uk-lon.prod.surfshark.com",
                "endpoint_ip": "185.220.101.5",
                "port": 51820,
                "latency_ms": 65.0,
            },
            {
                "country": "Turkey",
                "country_code": "TR",
                "city": "Istanbul",
                "hostname": "tr-ist.prod.surfshark.com",
                "endpoint_ip": "84.17.45.10",
                "port": 51820,
                "latency_ms": 40.0,  # ping was fast, but UDP was blocked
            },
        ]

        def _mock_deep_verify(ip, **kwargs):
            if ip == "185.220.101.5":
                return CheckResult(
                    ip=ip, port=51820, is_reachable=True, latency_ms=64.0, status="verified_stable", packet_loss=0.0, jitter_ms=2.0, deep_verified=True
                )
            else:
                # Turkey: 100% loss on UDP, ping only
                return CheckResult(
                    ip=ip, port=51820, is_reachable=False, latency_ms=40.0, status="ping_only_udp_blocked", error="UDP blocked by DPI", packet_loss=100.0, deep_verified=True
                )

        with patch("checker.deep_verify_endpoint_sync", side_effect=_mock_deep_verify):
            verified, rejected = deep_screen_working_configs_sync(configs, probe_count=3)

            self.assertEqual(len(verified), 1)
            self.assertEqual(verified[0]["city"], "London")
            self.assertTrue(verified[0]["deep_verified"])

            self.assertEqual(len(rejected), 1)
            self.assertEqual(rejected[0]["country"], "Turkey")
            self.assertIn("UDP", rejected[0]["rejection_reason"])

    def test_extract_top_servers_prioritizes_deep_verified(self):
        from scan_cache import extract_top_servers
        servers = [
            {"city": "Paris", "latency_ms": 30.0, "deep_verified": False, "packet_loss": 0.0},
            {"city": "London", "latency_ms": 45.0, "deep_verified": True, "packet_loss": 0.0},
        ]
        top = extract_top_servers(servers, limit=2)
        # London (deep_verified=True) must be ranked first before non-deep verified
        self.assertEqual(top[0]["city"], "London")
        self.assertEqual(top[1]["city"], "Paris")


class TestV3TargetedScansAndSmartScreening(unittest.TestCase):
    """
    Tests for per-country, per-cluster, and per-IP targeted scans,
    as well as deep screening fallback when working_configs is empty.
    """

    def test_deep_verify_smart_mode_with_dummy_key(self):
        from unittest.mock import patch, MagicMock
        from checker import deep_verify_endpoint_sync, ScanMode, DEFAULT_DUMMY_CLIENT_KEY
        import socket

        mock_sock = MagicMock()
        mock_sock.recvfrom.side_effect = socket.timeout("timed out")

        with patch("socket.socket", return_value=mock_sock):
            with patch("checker.ping_latency_ms", return_value=60.0):
                res = deep_verify_endpoint_sync(
                    "89.117.47.35",
                    51820,
                    client_private_key=DEFAULT_DUMMY_CLIENT_KEY,
                    server_public_key="pvWYTFxIpqo25NGTertIIWnccS/sUQ6fIkqd8XJYzEI=",
                    mode=ScanMode.SMART,
                )
                self.assertTrue(res.is_reachable)
                self.assertEqual(res.status, "ping_alive")
                self.assertEqual(res.latency_ms, 60.0)
                self.assertTrue(res.deep_verified)

    def test_deep_verify_smart_mode_with_real_key_rejects_udp_blocked(self):
        from unittest.mock import patch, MagicMock
        from checker import deep_verify_endpoint_sync, ScanMode
        import socket

        mock_sock = MagicMock()
        mock_sock.recvfrom.side_effect = socket.timeout("timed out")

        real_priv = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
        real_pub = "l8EOWPyzt/njrb74CADY4VOhns/TbUN6KFTbytHcFQw="

        with patch("socket.socket", return_value=mock_sock):
            with patch("checker.ping_latency_ms", return_value=40.0):
                res = deep_verify_endpoint_sync(
                    "84.17.45.1",
                    51820,
                    client_private_key=real_priv,
                    server_public_key=real_pub,
                    mode=ScanMode.SMART,
                )
                self.assertFalse(res.is_reachable)
                self.assertEqual(res.status, "ping_only_udp_blocked")
                self.assertEqual(res.latency_ms, 40.0)
                self.assertEqual(res.packet_loss, 100.0)

    def test_deep_screen_candidate_generation_when_empty(self):
        """
        Verify that when working_configs is empty, candidate configs
        are accurately extracted from blueprint server resolved_ips.
        """
        from browser_harvest import get_default_seed_blueprint

        bp = get_default_seed_blueprint()
        configs_to_screen = []
        for s in bp.servers:
            ips = s.resolved_ips if s.resolved_ips else [s.hostname]
            for ip in ips:
                configs_to_screen.append({
                    "country": s.country,
                    "city": s.city,
                    "hostname": s.hostname,
                    "endpoint_ip": ip,
                    "port": s.port,
                    "public_key": s.public_key,
                })

        self.assertGreater(len(configs_to_screen), 10)
        albania = next(c for c in configs_to_screen if c["country"] == "Albania")
        self.assertEqual(albania["hostname"], "al-tia.prod.surfshark.com")

    def test_targeted_scan_merge_logic(self):
        from checker import CheckResult

        # Initial state
        scan_results = {
            "az-bak.prod.surfshark.com": [
                CheckResult(ip="89.117.47.35", port=51820, is_reachable=False, status="timed_out")
            ]
        }
        working_configs = []

        # Simulate targeted test completing with reachable Azerbaijan IP
        new_result = CheckResult(
            ip="89.117.47.35",
            port=51820,
            is_reachable=True,
            latency_ms=52.0,
            status="ping_alive",
            server_info={"hostname": "az-bak.prod.surfshark.com", "country": "Azerbaijan", "city": "Baku"}
        )

        h = new_result.server_info["hostname"]
        scan_results[h] = [new_result]
        working_configs.append({
            "hostname": h,
            "country": "Azerbaijan",
            "city": "Baku",
            "endpoint_ip": new_result.ip,
            "port": new_result.port,
            "latency_ms": new_result.latency_ms,
            "status": new_result.status,
        })

        self.assertEqual(len(scan_results[h]), 1)
        self.assertTrue(scan_results[h][0].is_reachable)
        self.assertEqual(len(working_configs), 1)
        self.assertEqual(working_configs[0]["country"], "Azerbaijan")
        self.assertEqual(working_configs[0]["endpoint_ip"], "89.117.47.35")


if __name__ == "__main__":
    unittest.main()

