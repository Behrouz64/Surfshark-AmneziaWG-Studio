"""Tests for scripts/mac_copy_check.py: the link checker and the clipboard round trip (no browser, no real clipboard)."""

import importlib.util
import os
import sys
import tempfile
import unittest

from tests.test_mobile import TEST_KEY

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_checker():
    spec = importlib.util.spec_from_file_location(
        "mac_copy_check", os.path.join(REPO_ROOT, "scripts", "mac_copy_check.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checker = _load_checker()


def _good_link():
    from browser_harvest import UserInterfaceConfig
    from config_builder import AmneziaParams
    from mobile_core import Endpoint, build_endpoint_wg_link

    endpoint = Endpoint(country="Italy", country_code="IT", city="Milan", hostname="it-mil.prod.surfshark.com",
                        ip="195.86.6.249", port=51820, public_key="9h4WUC/U+Wnr58UAqZCitc5Cl0nf3D9IzFQMT4IsmUk=")
    ui = UserInterfaceConfig(private_key=TEST_KEY, address="10.2.0.2/32", dns="10.2.0.1, 2a07:b944::2:1")
    return build_endpoint_wg_link(endpoint, ui, AmneziaParams.iran_preset())


class TestCheckWgLink(unittest.TestCase):
    def test_a_link_from_the_app_passes(self):
        self.assertEqual(checker.check_wg_link(_good_link(), TEST_KEY), [])

    def test_a_wrong_private_key_is_reported(self):
        problems = checker.check_wg_link(_good_link(), "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh7=")
        self.assertTrue(any("privateKey" in p for p in problems), problems)

    def test_a_raw_plus_in_the_query_is_reported(self):
        bad = _good_link().replace("%2B", "+", 1)
        self.assertTrue(any("raw '+'" in p for p in checker.check_wg_link(bad, TEST_KEY)))

    def test_a_cidr_mask_in_ip_is_reported(self):
        bad = _good_link().replace("ip=10.2.0.2&", "ip=10.2.0.2%2F32&")
        self.assertTrue(any("ip must be" in p for p in checker.check_wg_link(bad, TEST_KEY)))

    def test_a_line_break_is_reported(self):
        self.assertTrue(any("line break" in p for p in checker.check_wg_link(_good_link() + "\n", TEST_KEY)))

    def test_a_string_that_is_not_a_link_is_reported(self):
        self.assertEqual(checker.check_wg_link("https://example.com", TEST_KEY), ["does not start with wg://"])


class TestClipboardRoundTrip(unittest.TestCase):
    def _commands(self, path):
        copy_cmd = [sys.executable, "-c",
                    f"import sys, pathlib; pathlib.Path({path!r}).write_bytes(sys.stdin.buffer.read())"]
        paste_cmd = [sys.executable, "-c",
                     f"import sys, pathlib; sys.stdout.buffer.write(pathlib.Path({path!r}).read_bytes())"]
        return copy_cmd, paste_cmd

    def test_group_text_with_emoji_comes_back_unchanged(self):
        from mobile_core import build_group_wg_links_text
        from browser_harvest import UserInterfaceConfig
        from config_builder import AmneziaParams
        from mobile_core import Endpoint

        endpoints = [
            Endpoint(country="Italy", country_code="IT", city="Milan", hostname="a", ip="195.86.6.249",
                     port=51820, public_key="9h4WUC/U+Wnr58UAqZCitc5Cl0nf3D9IzFQMT4IsmUk="),
            Endpoint(country="Italy", country_code="IT", city="Palermo", hostname="b", ip="149.22.91.161",
                     port=51820, public_key="4D4PkMrszUx3+Rj4qLZIH1r7s6VAjS28sl34VG5+JyE="),
        ]
        ui = UserInterfaceConfig(private_key=TEST_KEY, address="10.2.0.2/32", dns="10.2.0.1, 2a07:b944::2:1")
        text = build_group_wg_links_text(endpoints, ui, AmneziaParams.iran_preset())
        with tempfile.TemporaryDirectory() as folder:
            copy_cmd, paste_cmd = self._commands(os.path.join(folder, "clip.txt"))
            ok, detail = checker.copy_roundtrip(text, copy_cmd, paste_cmd)
        self.assertTrue(ok, detail)
        self.assertEqual(text.count("\n"), 1)

    def test_a_clipboard_that_changes_the_text_is_reported(self):
        with tempfile.TemporaryDirectory() as folder:
            clip = os.path.join(folder, "clip.txt")
            other = os.path.join(folder, "other.txt")
            with open(other, "w", encoding="utf-8") as handle:
                handle.write("changed by something else")
            copy_cmd, _ = self._commands(clip)
            _, paste_other = self._commands(other)
            ok, detail = checker.copy_roundtrip("wg://x", copy_cmd, paste_other)
        self.assertFalse(ok)
        self.assertIn("differs", detail)


if __name__ == "__main__":
    unittest.main()
