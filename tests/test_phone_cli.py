"""Tests for phone_cli.py: the phone's flows in the terminal, driven by scripted answers and a fake clipboard."""

import json
import os
import tempfile
import unittest

from tests.test_mobile import TEST_KEY
from browser_harvest import UserInterfaceConfig
from config_builder import AmneziaParams
from mobile_core import (
    build_endpoint_config,
    endpoints_from_working_configs,
    build_endpoint_wg_link,
    build_group_wg_links_text,
    params_for_preset,
    qr_available,
    qr_matrix,
    DEFAULT_PRESET,
)
from phone_cli import PhoneCli, parse_selection, render_qr_lines

WORKING = [
    {"country": "Italy", "country_code": "IT", "city": "Milan", "hostname": "it-mil.prod.surfshark.com",
     "endpoint_ip": "195.86.6.249", "port": 51820, "public_key": "9h4WUC/U+Wnr58UAqZCitc5Cl0nf3D9IzFQMT4IsmUk=",
     "latency_ms": 41.0, "status": "ok"},
    {"country": "Italy", "country_code": "IT", "city": "Palermo", "hostname": "it-pal.prod.surfshark.com",
     "endpoint_ip": "149.22.91.161", "port": 51820, "public_key": "4D4PkMrszUx3+Rj4qLZIH1r7s6VAjS28sl34VG5+JyE=",
     "latency_ms": 57.0, "status": "ok"},
    {"country": "Turkey", "country_code": "TR", "city": "Istanbul", "hostname": "tr-ist.prod.surfshark.com",
     "endpoint_ip": "185.1.1.9", "port": 51820, "public_key": "Qm9iIGlzIGEgdGVzdCBrZXkgaGVyZSAxMjM0NTY3ODk=",
     "latency_ms": 90.0, "status": "ok"},
]


class Script:
    """Answers the prompts in order. When the answers run out, it ends the input (EOF)."""

    def __init__(self, answers):
        self.answers = list(answers)

    def __call__(self, prompt):
        if not self.answers:
            raise EOFError
        return self.answers.pop(0)


class PhoneCliTestCase(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.folder = self._dir.name
        self.data_file = os.path.join(self.folder, "surfshark_servers.json")  # does not exist: seed data is used
        self.cache_file = os.path.join(self.folder, "scan_cache.json")
        with open(self.cache_file, "w", encoding="utf-8") as handle:
            json.dump({"working_configs": WORKING}, handle)
        self.lines = []
        self.clipboard_calls = []

    def tearDown(self):
        self._dir.cleanup()

    def make(self, answers, secret=TEST_KEY, **kwargs):
        self.script = Script(answers)
        return PhoneCli(
            self.data_file,
            self.cache_file,
            input_fn=self.script,
            output_fn=self.lines.append,
            secret_fn=lambda prompt: secret,
            clipboard=self.clipboard_calls.append,
            vpn_fn=lambda: None,
            **kwargs,
        )

    def expected_ui(self):
        return UserInterfaceConfig(private_key=TEST_KEY, address="10.14.0.2/16", dns="162.252.172.57, 149.154.159.92")


class TestParseSelection(unittest.TestCase):
    def test_numbers_ranges_and_repeats(self):
        self.assertEqual(parse_selection("1,3, 5-7, 3", 6), [0, 2, 4, 5])

    def test_out_of_range_and_junk_are_ignored(self):
        self.assertEqual(parse_selection("0, 9, abc, 2", 3), [1])


class TestQrLines(unittest.TestCase):
    def test_two_module_rows_per_line(self):
        matrix = [[True, False, True, False], [False, True, False, True],
                  [True, True, False, False], [False, False, True, True]]
        lines = render_qr_lines(matrix)
        self.assertEqual(len(lines), 2)
        self.assertTrue(all(len(line) == 4 for line in lines))
        self.assertEqual(lines[0][0], "▀")

    def test_a_config_qr_fits_a_terminal(self):
        if not qr_available():
            self.skipTest("qrcode is not installed")
        text = build_endpoint_config(
            endpoints_from_working_configs(WORKING)[0],
            UserInterfaceConfig(private_key=TEST_KEY, address="10.14.0.2/16", dns="162.252.172.57"),
            AmneziaParams.iran_preset(),
        )
        matrix = qr_matrix(text)
        lines = render_qr_lines(matrix)
        self.assertEqual(len(lines), (len(matrix) + 1) // 2)
        self.assertLessEqual(len(lines[0]), 120)


class TestPhoneCliFlows(PhoneCliTestCase):
    def test_group_wg_copy_puts_the_app_text_on_the_clipboard(self):
        # set key, select all shown, copy group wg:// links, exit
        cli = self.make(["1", "4", "a", "5", "2", "0"])
        cli.run()
        self.assertEqual(len(self.clipboard_calls), 1)
        expected = build_group_wg_links_text(cli.endpoints, self.expected_ui(), params_for_preset(DEFAULT_PRESET))
        self.assertEqual(self.clipboard_calls[0], expected)
        self.assertEqual(self.clipboard_calls[0].count("\n"), 2)
        self.assertTrue(all(line.startswith("wg://") for line in self.clipboard_calls[0].split("\n")))

    def test_single_config_copy_matches_the_app_builder(self):
        # set key, tick the first shown server (Milan), copy its AmneziaWG config
        cli = self.make(["1", "4", "1", "5", "1", "0"])
        cli.run()
        milan = [e for e in cli.endpoints if e.city == "Milan"][0]
        expected = build_endpoint_config(milan, self.expected_ui(), params_for_preset(DEFAULT_PRESET))
        self.assertEqual(self.clipboard_calls, [expected])

    def test_copy_without_a_key_asks_for_it_and_copies_nothing(self):
        cli = self.make(["5", "", "0"], secret="")
        cli.run()
        self.assertEqual(self.clipboard_calls, [])
        self.assertTrue(any("فرمت کلید درست نیست" in line for line in self.lines))

    def test_queue_copies_one_link_at_a_time(self):
        # set key, select all, queue wg:// links, Enter after each of the first two, then the last one ends it
        cli = self.make(["1", "4", "a", "6", "2", "", "", "0"])
        cli.run()
        params = params_for_preset(DEFAULT_PRESET)
        expected = [build_endpoint_wg_link(e, self.expected_ui(), params) for e in cli.endpoints]
        self.assertEqual(self.clipboard_calls, expected)

    def test_the_key_and_the_export_never_touch_the_disk(self):
        cli = self.make(["1", "4", "a", "5", "2", "0"])
        before = sorted(os.listdir(self.folder))
        cli.run()
        after = sorted(os.listdir(self.folder))
        self.assertEqual(before, after)
        self.assertEqual(after, ["scan_cache.json"])
        with open(self.cache_file, encoding="utf-8") as handle:
            self.assertNotIn(TEST_KEY, handle.read())

    def test_continent_search_narrows_the_list(self):
        cli = self.make([])
        cli.query = "Palermo"
        self.assertEqual([e.city for e in cli.visible()], ["Palermo"])
        cli.query = ""
        cli.continent = cli.mapping.get("TR", "")
        self.assertTrue(cli.visible())
        self.assertTrue(all(cli.mapping.get(e.country_code) == cli.continent for e in cli.visible()))

    def test_scan_uses_the_scanner_and_reloads_the_cache(self):
        def fake_scan(blueprint, cache_path, on_log, on_progress):
            with open(cache_path, "w", encoding="utf-8") as handle:
                json.dump({"working_configs": WORKING[:1]}, handle)
            on_log("fake scan ran")

            class Result:
                working_configs = WORKING[:1]
            return Result()

        # set key, scan, exit
        cli = self.make(["1", "2", "0"], scan_fn=fake_scan)
        self.assertEqual(len(cli.endpoints), 3)
        cli.run()
        self.assertEqual(len(cli.endpoints), 1)
        self.assertTrue(any("fake scan ran" in line for line in self.lines))
        self.assertTrue(any("اسکن تمام شد" in line for line in self.lines))

    def test_vpn_on_warns_and_stops_the_scan_when_declined(self):
        class Status:
            is_vpn_active = True
            interface = "utun3"

        calls = []
        cli = self.make(["1", "2", "n", "0"], scan_fn=lambda *a, **k: calls.append(1))
        cli.vpn_fn = lambda: Status()
        cli.run()
        self.assertEqual(calls, [])
        self.assertTrue(any("utun3" in line for line in self.lines))


if __name__ == "__main__":
    unittest.main()
