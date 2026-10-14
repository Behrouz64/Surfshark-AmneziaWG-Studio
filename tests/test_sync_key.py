"""The phone bundle never carries the user's PrivateKey, and the Mac copy check compares with the builder."""

import importlib.util
import json
import os
import tempfile
import unittest

from tests.test_mobile import TEST_KEY

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(name, relative):
    spec = importlib.util.spec_from_file_location(name, os.path.join(REPO_ROOT, relative))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sync_phone = _load("sync_phone", "scripts/sync_phone.py")
copy_check = _load("mac_copy_check", "scripts/mac_copy_check.py")


class TestPhoneBundleKey(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.folder = self._dir.name
        self.source = os.path.join(self.folder, "surfshark_servers.json")
        with open(self.source, "w", encoding="utf-8") as handle:
            json.dump({
                "user_interface": {"private_key": TEST_KEY, "address": "10.2.0.2/32", "dns": "10.2.0.1"},
                "servers": [{"country": "Italy", "hostname": "it-mil.prod.surfshark.com"}],
            }, handle)

    def tearDown(self):
        self._dir.cleanup()

    def test_the_user_key_is_replaced_in_the_phone_copy(self):
        text = sync_phone.phone_blueprint_text(self.source)
        self.assertNotIn(TEST_KEY, text)
        data = json.loads(text)
        self.assertEqual(data["user_interface"]["private_key"], sync_phone.PHONE_BLANK_KEY)
        self.assertEqual(data["servers"][0]["hostname"], "it-mil.prod.surfshark.com")
        self.assertEqual(data["user_interface"]["address"], "10.2.0.2/32")

    def test_the_bundled_key_is_blank_and_not_usable(self):
        from mobile_core import is_usable_client_key
        self.assertEqual(sync_phone.PHONE_BLANK_KEY, "")
        self.assertFalse(is_usable_client_key(sync_phone.PHONE_BLANK_KEY))

    def test_a_full_sync_writes_no_user_key_into_phone(self):
        phone_dir = os.path.join(self.folder, "phone")
        original_root = sync_phone.ROOT
        try:
            sync_phone.ROOT = self.folder
            os.makedirs(os.path.join(self.folder, "assets", "fonts"))
            for name in sync_phone.PHONE_MODULES:
                with open(os.path.join(self.folder, name), "w", encoding="utf-8") as handle:
                    handle.write("# stub\n")
            with open(os.path.join(self.folder, "assets", "fonts", "x.txt"), "w", encoding="utf-8") as handle:
                handle.write("font")
            sync_phone.sync(phone_dir)
        finally:
            sync_phone.ROOT = original_root
        with open(os.path.join(phone_dir, "surfshark_servers.json"), encoding="utf-8") as handle:
            self.assertNotIn(TEST_KEY, handle.read())


class TestCopyCheckAgainstBuilder(unittest.TestCase):
    def _fixture(self):
        from browser_harvest import UserInterfaceConfig
        from config_builder import AmneziaParams
        from mobile_core import Endpoint
        endpoint = Endpoint(country="Italy", country_code="IT", city="Milan", hostname="it-mil.prod.surfshark.com",
                            ip="195.86.6.249", port=51820,
                            public_key="9h4WUC/U+Wnr58UAqZCitc5Cl0nf3D9IzFQMT4IsmUk=")
        ui = UserInterfaceConfig(private_key=TEST_KEY, address="10.2.0.2/32", dns="10.2.0.1, 2a07:b944::2:1")
        return endpoint, ui, AmneziaParams.iran_preset()

    def test_the_builders_own_link_passes(self):
        from mobile_core import build_endpoint_wg_link
        endpoint, ui, params = self._fixture()
        link = build_endpoint_wg_link(endpoint, ui, params)
        self.assertEqual(copy_check.check_against_builder(link, endpoint, ui, params, TEST_KEY), [])

    def test_a_wrong_title_is_reported(self):
        from mobile_core import build_endpoint_wg_link
        endpoint, ui, params = self._fixture()
        link = build_endpoint_wg_link(endpoint, ui, params) + "%20%E2%80%94%20120ms"
        problems = copy_check.check_against_builder(link, endpoint, ui, params, TEST_KEY)
        self.assertTrue(any("builder output" in p for p in problems), problems)

    def test_a_wrong_dns_is_reported(self):
        from mobile_core import build_endpoint_wg_link
        endpoint, ui, params = self._fixture()
        link = build_endpoint_wg_link(endpoint, ui, params).replace(
            "dns=10.2.0.1%2C%202a07%3Ab944%3A%3A2%3A1", "dns=1.1.1.1")
        problems = copy_check.check_against_builder(link, endpoint, ui, params, TEST_KEY)
        self.assertTrue(any("builder output" in p for p in problems), problems)


if __name__ == "__main__":
    unittest.main()
