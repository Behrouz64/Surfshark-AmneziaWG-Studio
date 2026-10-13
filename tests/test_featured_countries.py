"""
test_featured_countries.py: Unit tests for featured countries filtering and settings persistence in ui.py.
"""

import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import ui
from config_builder import ShadowrocketStorage
from ui import SurfsharkAmneziaApp, DEFAULT_FEATURED_COUNTRIES
from vpn_detector import VpnStatus

_NO_VPN = VpnStatus(
    is_vpn_active=False, interface="en0", gateway="192.168.1.1",
    summary_fa="", summary_en="", warning_fa="", warning_en="",
)


class TestFeaturedCountries(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_featured_")
        self.orig_settings_file = ui.DEFAULT_USER_SETTINGS_FILE
        self.test_settings_file = os.path.join(self.test_dir, "user_settings.json")
        ui.DEFAULT_USER_SETTINGS_FILE = self.test_settings_file

        # The app reads and writes relative files (scan_cache.json, surfshark_servers.json),
        # so run inside the temp dir. Its background monitor would otherwise call pgrep,
        # read the live Shadowrocket UI and write ServerManager, so it is not started here.
        # VPN state and the Shadowrocket storage path are fixed for the same reason.
        self.cwd = os.getcwd()
        os.chdir(self.test_dir)
        self._patches = [
            patch.object(SurfsharkAmneziaApp, "_start_background_monitors", lambda self: None),
            patch.object(ui, "detect_active_vpn", return_value=_NO_VPN),
            patch.object(ui, "is_shadowrocket_running", return_value=False),
            patch.object(ShadowrocketStorage, "DEFAULT_STORAGE_PATH", os.path.join(self.test_dir, "ServerManager")),
        ]
        for p in self._patches:
            p.start()

        self.mock_page = MagicMock()
        self.app = SurfsharkAmneziaApp(self.mock_page)

    def tearDown(self):
        for p in reversed(self._patches):
            p.stop()
        os.chdir(self.cwd)
        ui.DEFAULT_USER_SETTINGS_FILE = self.orig_settings_file
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_default_featured_countries_initialized(self):
        self.assertEqual(
            self.app.featured_countries,
            ["Albania", "Andorra", "Bahamas", "Cambodia", "Myanmar", "Mongolia"],
        )

    def test_resolve_country_identifier(self):
        # Case insensitivity and aliases
        r1 = self.app._resolve_country_identifier("andora")
        self.assertIsNotNone(r1)
        self.assertEqual(r1["code"], "AD")
        self.assertEqual(r1["name"], "Andorra")

        r2 = self.app._resolve_country_identifier("burma")
        self.assertIsNotNone(r2)
        self.assertEqual(r2["code"], "MM")
        self.assertEqual(r2["name"], "Myanmar")

        # ISO 2-letter codes
        r3 = self.app._resolve_country_identifier("al")
        self.assertIsNotNone(r3)
        self.assertEqual(r3["code"], "AL")
        self.assertEqual(r3["name"], "Albania")

        r4 = self.app._resolve_country_identifier("DE")
        self.assertIsNotNone(r4)
        self.assertEqual(r4["code"], "DE")
        self.assertEqual(r4["name"], "Germany")

    def test_filter_only_active_servers(self):
        # Isolate working configs and scan results: Albania is working, Andorra is not
        self.app.working_configs = [
            {"country": "Albania", "country_code": "AL", "city": "Tirana", "endpoint_ip": "172.216.15.115", "latency_ms": 174.0, "is_working": True}
        ]
        self.app.scan_results = {}
        al_best = self.app._get_best_config_for_country("Albania", only_working=True)
        self.assertIsNotNone(al_best)
        self.assertTrue(al_best.get("is_working"))
        self.assertLess(al_best.get("latency_ms"), 9000)

        ad_best = self.app._get_best_config_for_country("Andorra", only_working=True)
        self.assertIsNone(ad_best)

    def test_build_featured_countries_bar_active_only(self):
        # Explicitly control working configs to isolate test
        self.app.working_configs = [
            {"country": "Albania", "country_code": "AL", "city": "Tirana", "endpoint_ip": "172.216.15.115", "latency_ms": 174.0, "is_working": True}
        ]
        self.app.scan_results = {}
        bar = self.app._build_featured_countries_bar()
        col = bar.content
        body = col.controls[1]
        # Body should be a Row containing exactly 1 pill (Albania)
        self.assertTrue(hasattr(body, "controls"))
        self.assertEqual(len(body.controls), 1)

    def test_settings_save_and_load(self):
        custom_list = ["Germany", "Switzerland", "Albania"]
        self.app.featured_countries = custom_list
        self.app.scan_mode = "permissive"
        self.app._save_user_settings()

        self.assertTrue(os.path.exists(self.test_settings_file))
        with open(self.test_settings_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data.get("featured_countries"), custom_list)
        self.assertEqual(data.get("scan_mode"), "permissive")

        # Create new app instance to test loading
        app2 = SurfsharkAmneziaApp(MagicMock())
        self.assertEqual(app2.featured_countries, custom_list)
        self.assertEqual(app2.scan_mode, "permissive")

    def test_open_settings_modal_tabs(self):
        # Verify modal opens without error and has 3 tabs
        self.app._open_settings_modal()
        # Retrieve the passed dialog
        if self.mock_page.open.called:
            modal = self.mock_page.open.call_args[0][0]
        else:
            modal = self.mock_page.dialog

        container = modal.content
        self.assertEqual(container.width, 680)
        tabs_control = container.content
        self.assertEqual(len(tabs_control.tabs), 4)
        self.assertIn("Credentials", tabs_control.tabs[0].text)
        self.assertIn("Obfuscation", tabs_control.tabs[1].text)
        self.assertIn("Verification", tabs_control.tabs[2].text)
        self.assertIn("Featured", tabs_control.tabs[3].text)

    def test_save_active_blueprint(self):
        """Verify _save_active_blueprint correctly saves self.blueprint without AttributeError."""
        from unittest.mock import patch
        with patch("ui.save_blueprint") as mock_save:
            self.app._save_active_blueprint()
            mock_save.assert_called_once_with(self.app.blueprint, ui.DEFAULT_DATA_FILE)


if __name__ == "__main__":
    unittest.main()
