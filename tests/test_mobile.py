"""
test_mobile.py: Unit tests for the phone-friendly UI (mobile_core + mobile_app).

Covers the copy formats (AmneziaWG config, wg:// links, group text, endpoint list),
the one-at-a-time copy queue for both formats, the headless scan path (network
calls mocked), the access token, the help guide, handler-level behaviour of the
phone UI against a mock Flet page, and a guard that the phone code never touches
Shadowrocket itself (it only builds wg:// link text).
"""

import ast
import base64
import os
import shutil
import sys
import tempfile
import unittest
import urllib.parse
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import flet as ft

import mobile_core
from browser_harvest import DEFAULT_DATA_FILE, BlueprintData, ServerMetadata, UserInterfaceConfig
from checker import CheckResult
from config_builder import AmneziaParams
from dns_resolver import ResolvedEndpoint
from mobile_core import (
    CopyQueue,
    build_endpoint_config,
    build_endpoint_list_text,
    build_endpoint_wg_link,
    build_group_config_text,
    build_group_wg_links_text,
    endpoints_from_working_configs,
    continent_by_country_code,
    is_mobile_platform,
    qr_dark_runs,
    qr_matrix,
    prepare_data_folder,
    continents_present,
    filter_endpoints,
    group_by_country,
    has_usable_private_key,
    is_access_token_valid,
    params_for_preset,
    run_mobile_scan,
)
from scan_cache import load_scan_cache

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REAL_KEY = base64.b64encode(bytes(range(32))).decode("ascii")  # 44 chars, decodes to 32 bytes
SERVER_KEY = base64.b64encode(bytes(range(1, 33))).decode("ascii")


def _ui() -> UserInterfaceConfig:
    return UserInterfaceConfig(private_key=REAL_KEY, address="10.14.0.2/16", dns="162.252.172.57")


def _working(**overrides) -> dict:
    base = {
        "country": "Germany",
        "country_code": "DE",
        "city": "Berlin",
        "hostname": "de-ber.prod.surfshark.com",
        "public_key": SERVER_KEY,
        "endpoint_ip": "185.1.1.1",
        "port": 51820,
        "latency_ms": 78.4,
    }
    base.update(overrides)
    return base


class TestEndpointModel(unittest.TestCase):
    def test_dedupes_skips_missing_ip_and_sorts_by_latency(self):
        configs = [
            _working(endpoint_ip="185.1.1.2", latency_ms=150.0),
            _working(endpoint_ip="185.1.1.1", latency_ms=60.0),
            _working(endpoint_ip="185.1.1.1", latency_ms=60.0),  # duplicate
            _working(endpoint_ip="", latency_ms=5.0),            # no IP -> skipped
        ]
        endpoints = endpoints_from_working_configs(configs)
        self.assertEqual([e.ip for e in endpoints], ["185.1.1.1", "185.1.1.2"])

    def test_bad_port_and_latency_fall_back_to_defaults(self):
        endpoints = endpoints_from_working_configs([_working(port="abc", latency_ms=None)])
        self.assertEqual(endpoints[0].port, 51820)
        self.assertFalse(endpoints[0].has_latency)
        self.assertEqual(endpoints[0].latency_label, "—")

    def test_tunnel_name_has_flag_city_country_and_latency(self):
        ep = endpoints_from_working_configs([_working()])[0]
        self.assertEqual(ep.tunnel_name, "🇩🇪 Berlin (Germany) — 78ms")

    def test_group_by_country_orders_countries_by_fastest_endpoint(self):
        endpoints = endpoints_from_working_configs([
            _working(country="Germany", country_code="DE", endpoint_ip="1.1.1.1", latency_ms=200.0),
            _working(country="Albania", country_code="AL", city="Tirana", endpoint_ip="2.2.2.2", latency_ms=90.0),
            _working(country="Germany", country_code="DE", endpoint_ip="1.1.1.2", latency_ms=50.0),
        ])
        groups = group_by_country(endpoints)
        self.assertEqual([name for name, _ in groups], ["Germany", "Albania"])
        self.assertEqual([e.ip for e in groups[0][1]], ["1.1.1.2", "1.1.1.1"])


class TestCopyFormats(unittest.TestCase):
    def setUp(self):
        self.endpoints = endpoints_from_working_configs([
            _working(endpoint_ip="185.1.1.1", latency_ms=60.0),
            _working(endpoint_ip="185.1.1.2", latency_ms=90.0, city="Frankfurt"),
        ])
        self.params = AmneziaParams.iran_preset()

    def test_single_config_has_interface_peer_and_obfuscation(self):
        text = build_endpoint_config(self.endpoints[0], _ui(), self.params)
        self.assertIn("# Name = 🇩🇪 Berlin (Germany) — 60ms", text)
        self.assertIn(f"PrivateKey = {REAL_KEY}", text)
        self.assertIn(f"PublicKey = {SERVER_KEY}", text)
        self.assertIn("Endpoint = 185.1.1.1:51820", text)
        self.assertIn("Jc = 4", text)
        self.assertIn("H4 = 4", text)

    def test_standard_preset_omits_obfuscation_lines(self):
        text = build_endpoint_config(self.endpoints[0], _ui(), params_for_preset("standard"))
        self.assertNotIn("Jc = ", text)

    def test_group_text_has_one_block_per_endpoint_in_order(self):
        text = build_group_config_text(self.endpoints, _ui(), self.params)
        self.assertEqual(text.count("[Interface]"), 2)
        self.assertEqual(text.count("[Peer]"), 2)
        self.assertIn("# ===== [1/2]", text)
        self.assertIn("# ===== [2/2]", text)
        self.assertLess(text.index("185.1.1.1:51820"), text.index("185.1.1.2:51820"))

    def test_endpoint_list_is_one_line_per_endpoint(self):
        lines = build_endpoint_list_text(self.endpoints).splitlines()
        self.assertEqual(lines, [
            "Germany - Berlin | 185.1.1.1:51820 | 60ms",
            "Germany - Frankfurt | 185.1.1.2:51820 | 90ms",
        ])

    def test_missing_public_key_uses_visible_placeholder(self):
        ep = endpoints_from_working_configs([_working(public_key="")])[0]
        text = build_endpoint_config(ep, _ui(), self.params)
        self.assertIn("YOUR_SERVER_PUBLIC_KEY", text)

    def test_wg_link_has_shadowrocket_fields_and_no_cidr_mask(self):
        link = build_endpoint_wg_link(self.endpoints[0], _ui(), self.params)
        self.assertTrue(link.startswith("wg://185.1.1.1:51820?"))
        self.assertIn("privateKey=" + urllib.parse.quote(REAL_KEY), link)
        self.assertIn("publicKey=" + urllib.parse.quote(SERVER_KEY), link)
        self.assertIn("ip=10.14.0.2&", link)  # /16 removed, as Shadowrocket expects
        self.assertIn("obfs=amneziawg", link)
        self.assertIn("obfsParam=", link)
        self.assertIn("#", link)  # title fragment

    def test_wg_link_uses_desktop_builder_output(self):
        from config_builder import build_shadowrocket_wg_url
        ep = self.endpoints[1]
        expected = build_shadowrocket_wg_url(
            {
                "endpoint_ip": ep.ip, "port": ep.port, "hostname": ep.hostname, "public_key": ep.public_key,
                "country": ep.country, "country_code": ep.country_code, "city": ep.city,
                "latency_ms": ep.latency_ms, "is_domain": False,
            },
            {"private_key": REAL_KEY, "address": "10.14.0.2/16", "dns": "162.252.172.57"},
            self.params,
            show_latency=False,
        )
        self.assertEqual(build_endpoint_wg_link(ep, _ui(), self.params), expected)

    def test_group_wg_links_are_one_per_line(self):
        lines = build_group_wg_links_text(self.endpoints, _ui(), self.params).splitlines()
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[0].startswith("wg://185.1.1.1:51820?"))
        self.assertTrue(lines[1].startswith("wg://185.1.1.2:51820?"))


class TestContinents(unittest.TestCase):
    def setUp(self):
        self.endpoints = endpoints_from_working_configs([
            _working(endpoint_ip="185.1.1.1", latency_ms=78.0),
            _working(endpoint_ip="5.2.3.4", country="Albania", country_code="AL", city="Tirana", latency_ms=240.0),
            _working(country="Japan", country_code="JP", city="Tokyo", endpoint_ip="203.0.113.5", latency_ms=150.0),
        ])
        self.mapping = {"DE": "Europe", "AL": "Europe", "JP": "Asia"}

    def test_mapping_comes_from_blueprint_servers(self):
        servers = [
            ServerMetadata(continent="Europe", country="Germany", country_code="de", city="Berlin", hostname="a"),
            ServerMetadata(continent="", country="Nowhere", country_code="XX", city="x", hostname="b"),
        ]
        self.assertEqual(continent_by_country_code(servers), {"DE": "Europe"})

    def test_filter_by_continent_and_query(self):
        europe = filter_endpoints(self.endpoints, self.mapping, "Europe")
        self.assertEqual([e.country_code for e in europe], ["DE", "AL"])
        self.assertEqual(len(filter_endpoints(self.endpoints, self.mapping)), 3)
        self.assertEqual([e.city for e in filter_endpoints(self.endpoints, self.mapping, "Asia", "tokyo")], ["Tokyo"])
        self.assertEqual(filter_endpoints(self.endpoints, self.mapping, "Europe", "tokyo"), [])

    def test_counts_per_continent_largest_first(self):
        self.assertEqual(continents_present(self.endpoints, self.mapping), [("Europe", 2), ("Asia", 1)])

    def test_unknown_country_goes_to_other(self):
        self.assertEqual(continents_present(self.endpoints, {}), [("Other", 3)])


class TestCopyQueue(unittest.TestCase):
    def test_walks_items_in_order_and_stops_at_end(self):
        eps = endpoints_from_working_configs([
            _working(endpoint_ip="1.1.1.1", latency_ms=10.0),
            _working(endpoint_ip="1.1.1.2", latency_ms=20.0),
        ])
        queue = CopyQueue(eps)
        self.assertEqual((queue.position, queue.total), (1, 2))
        self.assertEqual(queue.current.ip, "1.1.1.1")
        self.assertTrue(queue.has_next)
        self.assertTrue(queue.advance())
        self.assertEqual((queue.position, queue.current.ip), (2, "1.1.1.2"))
        self.assertFalse(queue.has_next)
        self.assertFalse(queue.advance())
        self.assertEqual(queue.current.ip, "1.1.1.2")

    def test_empty_queue_has_no_current(self):
        queue = CopyQueue([])
        self.assertIsNone(queue.current)
        self.assertEqual(queue.position, 0)
        self.assertFalse(queue.advance())


class TestKeysAndToken(unittest.TestCase):
    def test_usable_private_key(self):
        self.assertTrue(has_usable_private_key(_ui()))
        self.assertFalse(has_usable_private_key(UserInterfaceConfig(private_key="")))
        self.assertFalse(has_usable_private_key(UserInterfaceConfig(private_key="not-a-key")))

    def test_access_token_requires_exact_match(self):
        self.assertFalse(is_access_token_valid(None, "secret"))
        self.assertFalse(is_access_token_valid("", "secret"))
        self.assertFalse(is_access_token_valid("wrong", "secret"))
        self.assertFalse(is_access_token_valid("secret", ""))
        self.assertTrue(is_access_token_valid("secret", "secret"))


class TestHeadlessScan(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cache_path = os.path.join(self.tmp, "scan_cache.json")
        self.blueprint = BlueprintData(
            user_interface=_ui(),
            servers=[
                ServerMetadata(
                    continent="Europe", country="Germany", country_code="DE", city="Berlin",
                    hostname="de-ber.prod.surfshark.com", public_key=SERVER_KEY,
                ),
                ServerMetadata(
                    continent="Europe", country="Albania", country_code="AL", city="Tirana",
                    hostname="al-tia.prod.surfshark.com", public_key=SERVER_KEY,
                ),
            ],
        )

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_scan_saves_only_reachable_endpoints_to_cache(self):
        resolved = {
            "de-ber.prod.surfshark.com": ResolvedEndpoint(hostname="de-ber.prod.surfshark.com", ips=["185.1.1.1", "185.1.1.2"]),
            "al-tia.prod.surfshark.com": ResolvedEndpoint(hostname="al-tia.prod.surfshark.com", ips=["5.5.5.5"]),
        }

        def fake_udp(targets, on_progress=None, **kwargs):
            results = []
            for index, (ip, port, _priv, _pub, info) in enumerate(targets, start=1):
                reachable = ip != "5.5.5.5"
                res = CheckResult(
                    ip=ip, port=port, is_reachable=reachable, latency_ms=70.0 if reachable else 9999.0,
                    status="responsive" if reachable else "timed_out", server_info=info,
                )
                results.append(res)
                if on_progress:
                    on_progress(index, len(targets), res)
            return results

        logs, progress_calls = [], []
        with patch.object(mobile_core, "resolve_servers_sync", return_value=resolved), \
                patch.object(mobile_core, "run_udp_scan_sync", side_effect=fake_udp):
            result = run_mobile_scan(
                self.blueprint,
                cache_path=self.cache_path,
                on_log=logs.append,
                on_progress=lambda phase, done, total: progress_calls.append((phase, done, total)),
            )

        self.assertEqual(result.discovered_ips, 3)
        self.assertEqual(len(result.working_configs), 2)
        self.assertEqual(result.hostnames_checked, 2)
        self.assertTrue(any(line.startswith("✅ 185.1.1.1") for line in logs))
        self.assertIn(("udp", 3, 3), progress_calls)

        cache = load_scan_cache(self.cache_path)
        self.assertIsNotNone(cache)
        with open(self.cache_path, encoding="utf-8") as f:
            self.assertNotIn(REAL_KEY, f.read(), "the scan cache must never hold the PrivateKey")
        endpoints = endpoints_from_working_configs(cache["working_configs"])
        self.assertEqual({e.ip for e in endpoints}, {"185.1.1.1", "185.1.1.2"})
        self.assertEqual(endpoints[0].country_code, "DE")
        self.assertEqual(endpoints[0].public_key, SERVER_KEY)

    def test_scan_with_no_hostnames_does_not_call_network(self):
        empty = BlueprintData(user_interface=_ui(), servers=[])
        with patch.object(mobile_core, "resolve_servers_sync") as resolver, \
                patch.object(mobile_core, "run_udp_scan_sync") as scanner:
            result = run_mobile_scan(empty, cache_path=self.cache_path)
        resolver.assert_not_called()
        scanner.assert_not_called()
        self.assertEqual(result.working_configs, [])


class TestShadowrocketIsolation(unittest.TestCase):
    """
    The phone version may build wg:// link text (Shadowrocket's import format), but it
    must never touch Shadowrocket: no ServerManager storage, no process checks, no app
    control, no shadowrocket:// URL scheme. The check walks the AST so it looks at
    identifiers, imports and string literals only; docstrings and comments are ignored.
    """

    FORBIDDEN = (
        "shadowrocketstorage", "servermanager", "shadowrocket://", "pbcopy", "osascript",
        "get_shadowrocket_pid", "is_shadowrocket_running", "read_shadowrocket", "inject_servers",
        "pgrep",
    )
    FORBIDDEN_MODULES = ("ui", "subprocess")  # the desktop Flet screen module, and process control

    def _code_tokens(self, name: str):
        with open(os.path.join(REPO_ROOT, name), encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=name)

        docstring_nodes = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                body = node.body
                if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant):
                    docstring_nodes.add(id(body[0].value))

        tokens, modules = [], []
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                tokens.append(node.id)
            elif isinstance(node, ast.Attribute):
                tokens.append(node.attr)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                tokens.append(node.name)
            elif isinstance(node, ast.arg):
                tokens.append(node.arg)
            elif isinstance(node, ast.alias):
                tokens.append(node.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.append(node.module)
            elif isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstring_nodes:
                tokens.append(node.value)
        return [t.lower() for t in tokens], modules

    def test_mobile_modules_have_no_shadowrocket_code(self):
        for name in ("mobile_core.py", "mobile_app.py"):
            tokens, modules = self._code_tokens(name)
            for token in tokens:
                for forbidden in self.FORBIDDEN:
                    self.assertNotIn(forbidden, token, f"{name} code must not use {forbidden!r} (found {token!r})")
            for module in modules:
                self.assertNotIn(module, self.FORBIDDEN_MODULES, f"{name} must not import {module!r}")


class _FakeQuery:
    """Mirrors flet's QueryString: get() raises KeyError for a missing key."""

    def __init__(self, data: dict):
        self._data = data

    def __call__(self):
        return None

    def get(self, key: str) -> str:
        return self._data[key]


def _fake_page(client_ip, query=None) -> MagicMock:
    page = MagicMock()
    page.client_ip = client_ip
    page.query = _FakeQuery(query or {})
    return page


class TestMobileUiWithMockPage(unittest.TestCase):
    """Exercises the phone UI's handlers against a mock Flet page; no browser needed."""

    def setUp(self):
        import mobile_app

        self.cwd = os.getcwd()
        self.tmp = tempfile.mkdtemp()
        os.chdir(self.tmp)  # keep the real scan cache / blueprint out of the test run
        # The phone UI reads the live VPN state at startup. Fix it so the result does not
        # depend on the VPN state of the machine running the tests.
        self._vpn_patch = patch.object(mobile_app, "_safe_vpn_status", return_value=None)
        self._vpn_patch.start()

    def tearDown(self):
        self._vpn_patch.stop()
        os.chdir(self.cwd)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _app(self):
        import mobile_app

        page = _fake_page("127.0.0.1")
        app = mobile_app.MobileStudioApp(page)
        app.blueprint.user_interface.private_key = REAL_KEY
        app.endpoints = endpoints_from_working_configs([
            _working(endpoint_ip="185.1.1.1", latency_ms=78.0),
            _working(endpoint_ip="185.1.1.2", city="Frankfurt", latency_ms=121.0),
            _working(endpoint_ip="5.2.3.4", country="Albania", country_code="AL", city="Tirana", latency_ms=240.0),
        ])
        app.cache_time = "2026-10-13 22:00:00"
        app._render_servers()
        return app, page

    def _last_dialog(self, page):
        """Most recent AlertDialog opened (toasts are SnackBars and are skipped)."""
        for call in reversed(page.open.call_args_list):
            if isinstance(call.args[0], ft.AlertDialog):
                return call.args[0]
        raise AssertionError("no dialog was opened")

    def test_builds_screens_and_switches_tabs(self):
        app, page = self._app()
        self.assertEqual(app.current_tab, 0)
        self.assertEqual(len(page.navigation_bar.destinations), 4)
        self.assertEqual(len(app.country_list.controls), 2)  # Germany and Albania

        app._toggle(app.endpoints[0].key, True)
        self.assertTrue(app.fab.visible)
        self.assertEqual(app.fab.text, "1 انتخاب‌شده")

        app._show_tab(1)
        self.assertFalse(app.fab.visible)
        app._show_tab(2)
        self.assertEqual(app.current_tab, 2)
        app._show_tab(3)
        self.assertEqual(app.current_tab, 3)

    def test_country_tile_remembers_collapsed_state(self):
        app, _ = self._app()
        germany_tile = app.country_list.controls[0]
        self.assertTrue(germany_tile.initially_expanded)  # first country opens by default
        germany_tile.on_change(SimpleNamespace(data="false", control=germany_tile))
        app._render_servers()
        self.assertFalse(app.country_list.controls[0].initially_expanded)

    def test_search_filters_by_city_ip_and_country(self):
        app, _ = self._app()
        app.search_text = "frank"
        app._render_servers()
        self.assertEqual(len(app.country_list.controls), 1)
        app.search_text = "5.2.3"
        app._render_servers()
        self.assertEqual(app.country_list.controls[0].title.value, "🇦🇱  Albania")
        app.search_text = "nothing-matches"
        app._render_servers()
        self.assertEqual(len(app.country_list.controls), 1)  # the empty-state card

    def test_select_all_in_country_then_group_text_copy(self):
        app, page = self._app()
        germany = [e for e in app.endpoints if e.country == "Germany"]
        app._select_many(germany, True)
        self.assertTrue(all(e.key in app.selected for e in germany))
        self.assertEqual(len(app.selected), 2)

        app._copy_group(MagicMock(), app._selected_endpoints())
        copied = page.set_clipboard.call_args[0][0]
        self.assertEqual(copied.count("[Interface]"), 2)
        self.assertIn("185.1.1.2:51820", copied)
        self.assertNotIn("5.2.3.4", copied)

    def test_copy_queue_steps_through_selection_and_stops_at_end(self):
        app, page = self._app()
        items = app.endpoints[:3]
        app._start_queue(MagicMock(), items)
        self.assertEqual(page.set_clipboard.call_count, 1)  # first config copied on open
        self.assertIn("185.1.1.1", page.set_clipboard.call_args[0][0])

        queue_dialog = self._last_dialog(page)
        next_button = queue_dialog.actions[1]
        next_button.on_click(None)
        next_button.on_click(None)
        self.assertEqual(page.set_clipboard.call_count, 3)
        self.assertIn("5.2.3.4", page.set_clipboard.call_args[0][0])

        next_button.on_click(None)  # already at the last item: no new copy
        self.assertEqual(page.set_clipboard.call_count, 3)

    def test_config_dialog_draws_the_qr_code_on_a_canvas(self):
        import flet.canvas as cv

        app, page = self._app()
        app._open_config_dialog(app.endpoints[0])
        dialog = self._last_dialog(page)
        self.assertTrue(any(isinstance(c, cv.Canvas) for c in dialog.content.content.controls))

    def test_single_config_dialog_copy_button_copies_its_config(self):
        app, page = self._app()
        app._open_config_dialog(app.endpoints[1])
        dialog = self._last_dialog(page)
        dialog.actions[1].on_click(None)
        copied = page.set_clipboard.call_args[0][0]
        self.assertIn("Endpoint = 185.1.1.2:51820", copied)
        self.assertIn(f"PrivateKey = {REAL_KEY}", copied)

    def test_single_config_dialog_offers_wg_link_as_second_mode(self):
        app, page = self._app()
        app._open_config_dialog(app.endpoints[1])
        dialog = self._last_dialog(page)
        self.assertEqual(len(dialog.actions), 3)  # close, config, wg link
        dialog.actions[2].on_click(None)
        copied = page.set_clipboard.call_args[0][0]
        self.assertTrue(copied.startswith("wg://185.1.1.2:51820?"))
        self.assertNotIn("[Interface]", copied)

    def test_single_wg_copy_puts_link_on_clipboard(self):
        app, page = self._app()
        app._with_private_key(lambda: app._copy_single_wg(app.endpoints[0]))
        copied = page.set_clipboard.call_args[0][0]
        self.assertTrue(copied.startswith("wg://185.1.1.1:51820?"))

    def test_group_wg_copy_puts_one_link_per_line_on_clipboard(self):
        app, page = self._app()
        app._copy_group_wg(MagicMock(), app.endpoints[:2])
        copied = page.set_clipboard.call_args[0][0]
        lines = copied.splitlines()
        self.assertEqual(len(lines), 2)
        self.assertTrue(all(line.startswith("wg://") for line in lines))

    def test_copy_queue_wg_mode_copies_links_one_by_one(self):
        app, page = self._app()
        app._start_queue(MagicMock(), app.endpoints[:2], mode="wg")
        self.assertTrue(page.set_clipboard.call_args[0][0].startswith("wg://185.1.1.1:"))
        queue_dialog = self._last_dialog(page)
        queue_dialog.actions[1].on_click(None)  # "بعدی"
        self.assertEqual(page.set_clipboard.call_count, 2)
        self.assertTrue(page.set_clipboard.call_args[0][0].startswith("wg://185.1.1.2:"))

    def test_group_actions_offer_both_copy_modes(self):
        app, page = self._app()
        app.selected = {app.endpoints[0].key, app.endpoints[1].key}
        app._open_group_actions()
        dialog = self._last_dialog(page)
        labels = []
        for control in dialog.content.content.controls:
            if isinstance(control, (ft.ElevatedButton, ft.OutlinedButton)):
                labels.append(control.text)
        joined = " | ".join(str(label) for label in labels)
        self.assertIn("AmneziaWG", joined)
        self.assertIn("wg://", joined)
        self.assertEqual(len(labels), 6)
        self.assertIn("کپی اشتراک Shadowrocket", joined)

    def test_phone_skips_desktop_vpn_probe_and_keeps_content_clear_of_notch(self):
        import mobile_app
        from flet.core.types import PagePlatform

        self._vpn_patch.stop()  # setUp hides the probe; this test needs the real call path
        page = _fake_page("127.0.0.1")
        page.platform = PagePlatform.IOS
        with patch.object(mobile_app, "detect_active_vpn", side_effect=AssertionError("must not probe on phones")):
            app = mobile_app.MobileStudioApp(page)
        self.assertTrue(app.is_mobile)
        self.assertIsNone(app.vpn)
        self.assertTrue(any(isinstance(c.args[0], ft.SafeArea) for c in page.add.call_args_list))
        self.assertTrue(app.scan_view.controls[2].visible if hasattr(app.scan_view.controls[2], "visible") else True)

    def test_desktop_still_probes_vpn(self):
        import mobile_app
        from flet.core.types import PagePlatform
        from vpn_detector import VpnStatus

        self._vpn_patch.stop()  # setUp hides the probe; this test needs the real call path
        page = _fake_page("127.0.0.1")
        page.platform = PagePlatform.MACOS
        status = VpnStatus(is_vpn_active=False, interface="en0", gateway="x",
                           summary_fa="", summary_en="", warning_fa="", warning_en="")
        with patch.object(mobile_app, "detect_active_vpn", return_value=status) as probe:
            app = mobile_app.MobileStudioApp(page)
        probe.assert_called()
        self.assertFalse(app.is_mobile)

    def test_dashboard_tiles_and_appbar(self):
        app, page = self._app()
        self.assertIsInstance(app.header, ft.Container)
        self.assertIsInstance(page.add.call_args_list[0].args[0], ft.SafeArea)  # header inside SafeArea
        tiles = app.dashboard_row.controls
        self.assertEqual(len(tiles), 5)
        self.assertEqual(tiles[0].content.controls[1].value, "3")  # healthy endpoints in _app()
        app._toggle(app.endpoints[0].key, True)
        app._render_servers()
        self.assertEqual(app.dashboard_row.controls[4].content.controls[1].value, "1")

    def test_continent_chip_filters_list_and_select_visible_is_scoped(self):
        app, page = self._app()
        app.endpoints = endpoints_from_working_configs([
            _working(endpoint_ip="185.1.1.1", latency_ms=78.0),
            _working(endpoint_ip="5.2.3.4", country="Albania", country_code="AL", city="Tirana", latency_ms=240.0),
            _working(country="Japan", country_code="JP", city="Tokyo", endpoint_ip="203.0.113.5", latency_ms=150.0),
        ])
        app.continent_map = {"DE": "Europe", "AL": "Europe", "JP": "Asia"}
        app._render_servers()
        self.assertEqual(len(app.continent_row.controls), 3)  # all, Europe, Asia

        app._set_continent("Asia")
        self.assertEqual([t.title.value for t in app.country_list.controls], ["🇯🇵  Japan"])

        app._set_continent("Europe")
        europe = filter_endpoints(app.endpoints, app.continent_map, "Europe")
        app._select_visible(europe)
        self.assertEqual(app.selected, {e.key for e in europe})
        self.assertEqual(len(app.selected), 2)

        app._clear_selection_now()
        self.assertEqual(app.selected, set())

    def test_guide_tab_switches_language_and_disables_active_button(self):
        app, page = self._app()
        app._show_tab(2)
        self.assertIs(app.host.content, app.guide_view)
        self.assertEqual(app.guide_language, "fa")
        app._set_guide_language("en")
        titles = [getattr(c, "value", "") for c in app.guide_body.controls]
        self.assertIn("What this version does", titles)
        self.assertTrue(app.guide_buttons["en"].disabled)
        self.assertFalse(app.guide_buttons["fa"].disabled)

    def test_guide_is_bilingual_and_covers_both_copy_modes(self):
        from mobile_guide import check_guide_parity, guide_sections

        self.assertEqual(check_guide_parity(), [])
        for lang in ("fa", "en"):
            parts = []
            for section in guide_sections(lang):
                parts.append(section["title"])
                for _kind, value in section["blocks"]:
                    parts.extend([value] if isinstance(value, str) else value)
            text = "\n".join(parts)
            self.assertIn("AmneziaWG", text, lang)
            self.assertIn("wg://", text, lang)
            self.assertIn("Shadowrocket", text, lang)
            self.assertIn("PrivateKey", text, lang)

    def test_guide_parity_check_reports_mismatch(self):
        import mobile_guide

        original = mobile_guide.GUIDE["en"]
        try:
            mobile_guide.GUIDE["en"] = original[:-1]
            self.assertTrue(mobile_guide.check_guide_parity())
        finally:
            mobile_guide.GUIDE["en"] = original

    def test_key_dialog_rejects_bad_key_then_keeps_good_key_in_memory_only(self):
        app, page = self._app()
        app.blueprint.user_interface.private_key = ""
        with open(DEFAULT_DATA_FILE, "w", encoding="utf-8") as f:
            f.write('{"sentinel": true}')
        saved_callback = MagicMock()
        app._open_key_dialog(on_saved=saved_callback)
        dialog = self._last_dialog(page)
        key_field, error_text = dialog.content.content.controls[1], dialog.content.content.controls[2]
        save_button = dialog.actions[1]

        key_field.value = "too-short"
        save_button.on_click(None)
        self.assertIn("فرمت کلید", error_text.value)
        saved_callback.assert_not_called()

        key_field.value = REAL_KEY
        save_button.on_click(None)
        saved_callback.assert_called_once()
        self.assertTrue(has_usable_private_key(app.blueprint.user_interface))
        # The phone UI must not write the private key to disk: the data file is byte-for-byte unchanged.
        with open(DEFAULT_DATA_FILE, encoding="utf-8") as f:
            self.assertEqual(f.read(), '{"sentinel": true}')

    def test_copy_requires_key_first(self):
        app, page = self._app()
        app.blueprint.user_interface.private_key = ""
        app._with_private_key(lambda: app._copy_single(app.endpoints[0]))
        page.set_clipboard.assert_not_called()
        self.assertIsNotNone(page.open.call_args)  # the key dialog opened instead

    def test_scan_worker_reports_success_and_failure(self):
        import mobile_app

        app, page = self._app()
        ok = mobile_core.MobileScanResult(working_configs=[_working()])
        with patch.object(mobile_app, "run_mobile_scan", return_value=ok):
            app._scan_worker()
        self.assertFalse(app.scanning)
        self.assertTrue(any("1 آی‌پی سالم" in line for line in app.log_lines))

        with patch.object(mobile_app, "run_mobile_scan", side_effect=RuntimeError("dns down")), \
                self.assertLogs("SurfsharkAmneziaMobile", level="ERROR"):
            app._scan_worker()
        self.assertFalse(app.scanning)
        self.assertTrue(any("dns down" in line for line in app.log_lines))
        self.assertFalse(app.scan_button.disabled)

    def test_vpn_warning_is_shown_before_scan(self):
        app, page = self._app()
        app.vpn = SimpleNamespace(is_vpn_active=True, interface="utun3")
        with patch.object(app, "_start_scan") as start:
            app._on_scan_click()
            start.assert_not_called()
            dialog = self._last_dialog(page)
            dialog.actions[1].on_click(None)  # "ادامه"
            start.assert_called_once()


class TestQrCode(unittest.TestCase):
    def test_runs_cover_exactly_the_dark_modules(self):
        matrix = qr_matrix(_working()["endpoint_ip"] + " " + "x" * 300)
        side = 240
        cell, runs = qr_dark_runs(matrix, side)
        dark = sum(sum(1 for c in row if c) for row in matrix)
        covered = sum(width // cell for _x, _y, width in runs)
        self.assertEqual(covered, dark)
        self.assertLess(len(runs), dark, "horizontal runs must be merged")
        for x, y, width in runs:
            self.assertTrue(0 <= x and x + width <= side and 0 <= y and y + cell <= side)

    def test_matrix_is_square_with_a_white_border(self):
        matrix = qr_matrix("hello")
        self.assertEqual(len(matrix), len(matrix[0]))
        self.assertFalse(any(matrix[0]))  # top border row is light


class TestPersianText(unittest.TestCase):
    def test_persian_font_is_bundled_and_wired(self):
        font = os.path.join(REPO_ROOT, "assets", "fonts", "Vazirmatn-NL-Regular.ttf")
        self.assertTrue(os.path.exists(font))
        self.assertGreater(os.path.getsize(font), 10000)
        self.assertTrue(os.path.exists(os.path.join(REPO_ROOT, "assets", "fonts", "OFL-Vazirmatn.txt")))
        with open(os.path.join(REPO_ROOT, "mobile_app.py"), encoding="utf-8") as f:
            source = f.read()
        self.assertIn('page.fonts = {"Vazirmatn": "fonts/Vazirmatn-NL-Regular.ttf"}', source)
        self.assertIn('font_family="Vazirmatn"', source)

    def test_latin_fragments_are_isolated_and_persian_is_untouched(self):
        from mobile_core import isolate_ltr

        text = "برای Shadowrocket از wg:// استفاده کنید و python3 main.py --mobile را بزنید."
        out = isolate_ltr(text)
        self.assertIn("\u2066wg://\u2069", out)
        self.assertIn("\u2066python3 main.py --mobile\u2069", out)
        self.assertEqual(isolate_ltr("متن فارسی بدون لاتین"), "متن فارسی بدون لاتین")
        self.assertIn("\u2066.conf\u2069", isolate_ltr("فایل .conf"))

    def test_list_lines_keep_the_number_and_bullet_in_order(self):
        from mobile_core import format_bullet, format_step

        step = format_step(1, "لینک wg:// را کپی کنید")
        self.assertTrue(step.startswith("\u20661.\u2069 "))
        self.assertIn("\u2066wg://\u2069", step)
        self.assertEqual(format_bullet("wg://x"), "• \u2066wg://x\u2069")

    def test_group_subscription_decodes_to_one_wg_link_per_line(self):
        from mobile_core import build_group_wg_subscription

        eps = endpoints_from_working_configs([
            _working(endpoint_ip="185.1.1.1"), _working(endpoint_ip="185.1.1.2", city="Frankfurt"),
        ])
        raw, encoded = build_group_wg_subscription(eps, _ui(), AmneziaParams.iran_preset())
        decoded = base64.b64decode(encoded).decode("utf-8")
        self.assertEqual(decoded, raw)
        lines = decoded.split("\n")
        self.assertEqual(len(lines), 2)
        self.assertTrue(all(line.startswith("wg://") for line in lines))


class TestShadowrocketReferenceLinks(unittest.TestCase):
    """The phone's wg:// links must match this reference export byte for byte."""

    REFERENCE = [
        "wg://195.86.6.249:51820?publicKey=9h4WUC/U%2BWnr58UAqZCitc5Cl0nf3D9IzFQMT4IsmUk%3D&privateKey=cF4B4RXTVug8PI2%2BmDxm8f1G/Ro0NHuWeO6jyOWRp18%3D&ip=10.2.0.2&dns=10.2.0.1%2C%202a07%3Ab944%3A%3A2%3A1&mtu=1280&udp=1&keepalive=25&obfs=amneziawg&obfsParam=%7B%22jc%22%3A%224%22%2C%22jmin%22%3A%2250%22%2C%22jmax%22%3A%221000%22%2C%22s1%22%3A%220%22%2C%22s2%22%3A%220%22%2C%22h1%22%3A%221%22%2C%22h2%22%3A%222%22%2C%22h3%22%3A%223%22%2C%22h4%22%3A%224%22%7D#%F0%9F%A6%88%20%F0%9F%87%AE%F0%9F%87%B9%20Italy%20%E2%80%94%20Milan%20%28195.86.6.249%29",
        "wg://149.22.91.161:51820?publicKey=4D4PkMrszUx3%2BRj4qLZIH1r7s6VAjS28sl34VG5%2BJyE%3D&privateKey=cF4B4RXTVug8PI2%2BmDxm8f1G/Ro0NHuWeO6jyOWRp18%3D&ip=10.2.0.2&dns=10.2.0.1%2C%202a07%3Ab944%3A%3A2%3A1&mtu=1280&udp=1&keepalive=25&obfs=amneziawg&obfsParam=%7B%22jc%22%3A%224%22%2C%22jmin%22%3A%2250%22%2C%22jmax%22%3A%221000%22%2C%22s1%22%3A%220%22%2C%22s2%22%3A%220%22%2C%22h1%22%3A%221%22%2C%22h2%22%3A%222%22%2C%22h3%22%3A%223%22%2C%22h4%22%3A%224%22%7D#%F0%9F%A6%88%20%F0%9F%87%AE%F0%9F%87%B9%20Italy%20%E2%80%94%20Palermo%20%28149.22.91.161%29",
    ]

    def _endpoints(self, latency=0.0):
        from mobile_core import Endpoint
        return [
            Endpoint(country="Italy", country_code="IT", city="Milan", hostname="it-mil.prod.surfshark.com",
                     ip="195.86.6.249", port=51820, public_key="9h4WUC/U+Wnr58UAqZCitc5Cl0nf3D9IzFQMT4IsmUk=",
                     latency_ms=latency),
            Endpoint(country="Italy", country_code="IT", city="Palermo", hostname="it-pal.prod.surfshark.com",
                     ip="149.22.91.161", port=51820, public_key="4D4PkMrszUx3+Rj4qLZIH1r7s6VAjS28sl34VG5+JyE=",
                     latency_ms=latency),
        ]

    def _ui(self):
        from browser_harvest import UserInterfaceConfig
        return UserInterfaceConfig(private_key="cF4B4RXTVug8PI2+mDxm8f1G/Ro0NHuWeO6jyOWRp18=",
                                   address="10.2.0.2/32", dns="10.2.0.1, 2a07:b944::2:1")

    def test_each_link_matches_the_reference_export(self):
        from mobile_core import build_endpoint_wg_link
        from config_builder import AmneziaParams
        for endpoint, reference in zip(self._endpoints(), self.REFERENCE):
            self.assertEqual(build_endpoint_wg_link(endpoint, self._ui(), AmneziaParams.iran_preset()), reference)

    def test_group_text_is_the_reference_lines_joined_by_newlines(self):
        from mobile_core import build_group_wg_links_text
        from config_builder import AmneziaParams
        text = build_group_wg_links_text(self._endpoints(), self._ui(), AmneziaParams.iran_preset())
        self.assertEqual(text, "\n".join(self.REFERENCE))

    def test_measured_ping_does_not_change_the_title(self):
        from mobile_core import build_endpoint_wg_link
        from config_builder import AmneziaParams
        link = build_endpoint_wg_link(self._endpoints(latency=120.0)[0], self._ui(), AmneziaParams.iran_preset())
        self.assertEqual(link, self.REFERENCE[0])


class TestGuideMatchesUi(unittest.TestCase):
    BUTTON_LABELS = (
        "صف کپی کانفیگ",
        "صف کپی لینک wg://",
        "کپی متن ترکیبی",
        "کپی همه لینک‌های wg://",
        "کپی اشتراک Shadowrocket",
        "کپی لیست کشور، شهر و آی‌پی",
        "انتخاب همه‌ی نمایش‌داده‌شده",
        "انتخاب کل کشور",
        "لغو انتخاب کشور",
        "پاک کردن انتخاب",
        "همه‌ی قاره‌ها",
        "شروع اسکن",
        "بعدی",
    )

    def setUp(self):
        from mobile_guide import GUIDE
        with open(os.path.join(REPO_ROOT, "mobile_app.py"), encoding="utf-8") as f:
            self.ui_source = f.read()
        self.guide_fa = " ".join(
            str(value) if not isinstance(value, list) else " ".join(value)
            for section in GUIDE["fa"]
            for _kind, value in section["blocks"]
        )

    def test_every_button_the_guide_names_exists_in_the_app(self):
        for label in self.BUTTON_LABELS:
            self.assertIn(label, self.ui_source, label)

    def test_guide_names_the_group_copy_options(self):
        for label in ("صف کپی کانفیگ", "صف کپی لینک wg://", "کپی اشتراک Shadowrocket", "کپی لیست کشور، شهر و آی‌پی"):
            self.assertIn(label, self.guide_fa, label)


class TestMobilePlatform(unittest.TestCase):
    def test_mobile_platforms_are_detected_from_enum_or_string(self):
        from flet.core.types import PagePlatform

        self.assertTrue(is_mobile_platform(PagePlatform.IOS))
        self.assertTrue(is_mobile_platform(PagePlatform.ANDROID))
        self.assertTrue(is_mobile_platform("android"))
        self.assertFalse(is_mobile_platform(PagePlatform.MACOS))
        self.assertFalse(is_mobile_platform(PagePlatform.WINDOWS))
        self.assertFalse(is_mobile_platform(None))
        self.assertFalse(is_mobile_platform(MagicMock()))

    def test_first_writable_folder_is_chosen_and_seed_copied(self):
        tmp = tempfile.mkdtemp()
        try:
            blocker = os.path.join(tmp, "a_file")
            with open(blocker, "w", encoding="utf-8") as f:
                f.write("not a folder")
            seed = os.path.join(tmp, "seed.json")
            with open(seed, "w", encoding="utf-8") as f:
                f.write('{"seed": true}')
            good = os.path.join(tmp, "data")

            chosen = prepare_data_folder([os.path.join(blocker, "sub"), "", good], seed)
            self.assertEqual(chosen, good)
            with open(os.path.join(good, "seed.json"), encoding="utf-8") as f:
                self.assertEqual(f.read(), '{"seed": true}')
            self.assertIsNone(prepare_data_folder([os.path.join(blocker, "sub")], seed))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestPhoneBundle(unittest.TestCase):
    """The iOS/Android build packages only phone/. Every module the phone app imports must be in the sync list."""

    def _local_imports(self, name, root_modules):
        import ast

        with open(os.path.join(REPO_ROOT, name), encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=name)
        found = set()
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                names = [node.module.split(".")[0]]
            for module in names:
                if module + ".py" in root_modules:
                    found.add(module + ".py")
        return found

    def test_sync_list_covers_every_local_import_of_the_phone_app(self):
        import runpy

        sync = runpy.run_path(os.path.join(REPO_ROOT, "scripts", "sync_phone.py"), run_name="sync_phone")
        listed = set(sync["PHONE_MODULES"])
        root_modules = {n for n in os.listdir(REPO_ROOT) if n.endswith(".py")}

        needed, queue = set(), ["mobile_app.py"]
        while queue:
            name = queue.pop()
            if name in needed:
                continue
            needed.add(name)
            queue.extend(self._local_imports(name, root_modules))

        self.assertEqual(needed - listed, set(), "phone app imports modules that scripts/sync_phone.py does not copy")
        for name in listed:
            self.assertTrue(os.path.exists(os.path.join(REPO_ROOT, name)), f"{name} is listed but missing")
        self.assertIn("surfshark_servers.json", sync["PHONE_DATA"])

    def test_phone_entry_point_is_tracked_and_calls_the_app(self):
        with open(os.path.join(REPO_ROOT, "phone", "main.py"), encoding="utf-8") as f:
            source = f.read()
        self.assertIn("prepare_data_folder", source)
        self.assertIn("from mobile_app import main as mobile_main", source)
        self.assertIn("ft.app(target=mobile_main, assets_dir=", source)


class TestTokenGate(unittest.TestCase):
    def test_reconnect_with_token_in_new_route_unlocks_the_app(self):
        """A reconnected browser keeps its session. A route change carrying ?t= must unlock it."""
        import mobile_app
        from flet.core.querystring import QueryString

        page = MagicMock()
        page.client_ip = "100.64.0.1"
        page.url = "http://100.64.0.1:8550"
        page.route = "/"
        page.query = QueryString(page=page)
        page.controls = []
        mobile_app.main(page, token="tok")
        self.assertIsNotNone(page.on_route_change)  # the gate listens for route changes
        self.assertNotIsInstance(page.navigation_bar, ft.NavigationBar, "no app screen before the token is accepted")
        self.assertTrue(any(
            "دسترسی ممنوع" in str(getattr(c.args[0], "value", "")) for c in page.add.call_args_list
        ))

        page.route = "/?t=tok"
        page.on_route_change(None)
        self.assertIsNotNone(page.navigation_bar)
        self.assertEqual(len(page.navigation_bar.destinations), 4)

    def test_token_is_read_from_real_flet_query_after_refresh(self):
        """Flet's QueryString is empty until refreshed, so a token in the route must still be seen."""
        import mobile_app
        from flet.core.querystring import QueryString

        page = MagicMock()
        page.client_ip = "192.168.1.20"
        page.url = "http://192.168.1.5:8550"
        page.route = "/?t=tok"
        page.query = QueryString(page=page)
        self.assertTrue(mobile_app._is_authorized(page, "tok"))

        page.route = "/?t=wrong"
        self.assertFalse(mobile_app._is_authorized(page, "tok"))

        page.route = "/"
        self.assertFalse(mobile_app._is_authorized(page, "tok"))

    def test_token_gate_allows_local_and_valid_token_only(self):
        import mobile_app

        self.assertFalse(mobile_app._is_authorized(_fake_page("192.168.1.20", {}), "tok"))  # bare URL: no crash
        self.assertTrue(mobile_app._is_authorized(_fake_page("192.168.1.20", {"t": "tok"}), "tok"))
        self.assertFalse(mobile_app._is_authorized(_fake_page("192.168.1.20", {"t": "nope"}), "tok"))
        self.assertFalse(mobile_app._is_authorized(_fake_page("127.0.0.1", {}), "tok"))  # local needs the token too
        self.assertTrue(mobile_app._is_authorized(_fake_page("127.0.0.1", {"t": "tok"}), "tok"))
        self.assertFalse(mobile_app._is_authorized(_fake_page(None, {}), "tok"))

    def test_unauthorized_visitor_gets_denied_page_not_an_error(self):
        import mobile_app

        page = _fake_page("192.168.1.20", {})
        mobile_app.main(page, token="tok")
        texts = [getattr(call.args[0], "value", "") for call in page.add.call_args_list]
        self.assertTrue(any("دسترسی ممنوع" in str(t) for t in texts))
        self.assertEqual(page.add.call_count, 2)  # only the two denial texts, no app screens


if __name__ == "__main__":
    unittest.main()
