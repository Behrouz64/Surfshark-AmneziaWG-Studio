"""
test_live_sync.py: Tests for fast VPN detection and real-time Shadowrocket sync integration.
"""

import os
import sys
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from vpn_detector import detect_active_vpn, VpnStatus
from browser_harvest import ServerMetadata, BlueprintData
from checker import CheckResult
from ui import SurfsharkAmneziaApp


class TestLiveSync(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_live_sync_")
        self.cache_file = os.path.join(self.test_dir, "test_cache.json")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_detect_active_vpn_structure(self):
        """Verify detect_active_vpn returns valid VpnStatus with non-empty descriptions."""
        status = detect_active_vpn()
        self.assertIsInstance(status, VpnStatus)
        self.assertIsInstance(status.is_vpn_active, bool)
        self.assertIsInstance(status.interface, str)
        self.assertTrue(len(status.summary_fa) > 0)
        self.assertTrue(len(status.summary_en) > 0)

    def test_apply_shadowrocket_results_logic(self):
        """Verify _apply_shadowrocket_results parses results and updates cache and state."""
        app = SurfsharkAmneziaApp.__new__(SurfsharkAmneziaApp)
        app.current_scan_cache_file = self.cache_file
        app.scan_results = {}
        app.working_configs = []
        app.last_scan_data = None
        app.page = MagicMock()
        app.lbl_status = MagicMock()
        app._show_toast = MagicMock()
        app._update_prev_scan_card = MagicMock()
        app._refresh_summary_cards = MagicMock()
        app._render_server_list = MagicMock()

        # Mock blueprint with servers
        s1 = ServerMetadata(
            continent="Americas",
            country="United States",
            country_code="US",
            city="Salt Lake City",
            hostname="us-slc.prod.surfshark.com",
            public_key="pub123=",
            port=51820,
            resolved_ips=["198.44.139.75"],
        )
        s2 = ServerMetadata(
            continent="Europe",
            country="Germany",
            country_code="DE",
            city="Frankfurt",
            hostname="de-fra.prod.surfshark.com",
            public_key="pub456=",
            port=51820,
            resolved_ips=["185.228.19.100"],
        )
        app.blueprint = MagicMock()
        app.blueprint.servers = [s1, s2]

        sr_results = {
            "198.44.139.75": {
                "ping": 120,
                "is_reachable": True,
                "is_ip": True,
                "port": 51820,
                "flag": "US",
            },
            "185.228.19.100": {
                "ping": 0,
                "is_reachable": False,
                "is_ip": True,
                "port": 51820,
                "flag": "DE",
            },
        }

        working_cnt = app._apply_shadowrocket_results(sr_results, is_auto=True)
        self.assertEqual(working_cnt, 1)
        self.assertEqual(len(app.working_configs), 1)
        self.assertEqual(app.working_configs[0]["endpoint_ip"], "198.44.139.75")
        self.assertEqual(app.working_configs[0]["latency_ms"], 120.0)
        self.assertTrue(os.path.exists(self.cache_file))

        app._update_prev_scan_card.assert_called_once()
        app._refresh_summary_cards.assert_called_once()
        app._render_server_list.assert_called_once()

    def test_apply_shadowrocket_results_zero_pings_ignored(self):
        """Verify _apply_shadowrocket_results returns 0 when no servers have positive pings."""
        app = SurfsharkAmneziaApp.__new__(SurfsharkAmneziaApp)
        app.current_scan_cache_file = self.cache_file
        app.scan_results = {}
        app.working_configs = []
        app.lbl_status = MagicMock()
        app._show_toast = MagicMock()

        sr_results = {
            "1.1.1.1": {
                "ping": 0,
                "is_reachable": False,
                "is_ip": True,
            }
        }
        res = app._apply_shadowrocket_results(sr_results, is_auto=True)
        self.assertEqual(res, 0)
        self.assertEqual(len(app.working_configs), 0)

    @patch("ui.read_shadowrocket_test_results")
    def test_sync_results_from_shadowrocket_async(self, mock_read_results):
        """Verify _sync_results_from_shadowrocket executes in background thread without blocking."""
        import time
        mock_read_results.return_value = {
            "198.44.139.75": {
                "ping": 150,
                "is_reachable": True,
                "is_ip": True,
            }
        }
        app = SurfsharkAmneziaApp.__new__(SurfsharkAmneziaApp)
        app.btn_sync_shadowrocket = MagicMock()
        app.lbl_status = MagicMock()
        app.page = MagicMock()
        app._apply_shadowrocket_results = MagicMock(return_value=1)
        app._show_toast = MagicMock()

        app._sync_results_from_shadowrocket()
        # Wait briefly for worker thread to complete
        time.sleep(0.15)

        app._apply_shadowrocket_results.assert_called_once()
        self.assertFalse(getattr(app, "_is_syncing_sr", True))
        self.assertFalse(app.btn_sync_shadowrocket.disabled)


if __name__ == "__main__":
    unittest.main()
