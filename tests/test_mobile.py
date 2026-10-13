"""
test_mobile.py: Unit tests for the phone-friendly UI (mobile_core + mobile_app).

Covers the copy formats (single, group text, endpoint list), the one-at-a-time
copy queue, the headless scan path (network calls mocked), the access token,
handler-level behaviour of the phone UI against a mock Flet page, and a guard
that the mobile version does not depend on Shadowrocket.
"""

import ast
import base64
import os
import shutil
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import flet as ft

import mobile_core
from browser_harvest import DEFAULT_DATA_FILE, BlueprintData, ServerMetadata, UserInterfaceConfig, load_blueprint
from checker import CheckResult
from config_builder import AmneziaParams
from dns_resolver import ResolvedEndpoint
from mobile_core import (
    CopyQueue,
    build_endpoint_config,
    build_endpoint_list_text,
    build_group_config_text,
    endpoints_from_working_configs,
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
    The phone version must not depend on Shadowrocket. The check walks the AST so it
    looks at identifiers, imports and string literals only; docstrings and comments
    are ignored, so a sentence that explains the rule does not trip it.
    """

    FORBIDDEN = ("shadowrocket", "wg://", "pbcopy", "servermanager")
    FORBIDDEN_MODULES = ("ui",)  # the desktop Flet screen module

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
        self.cwd = os.getcwd()
        self.tmp = tempfile.mkdtemp()
        os.chdir(self.tmp)  # keep the real scan cache / blueprint out of the test run

    def tearDown(self):
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
        self.assertEqual(len(page.navigation_bar.destinations), 3)
        self.assertEqual(len(app.country_list.controls), 2)  # Germany and Albania

        app._toggle(app.endpoints[0].key, True)
        self.assertTrue(app.fab.visible)
        self.assertEqual(app.fab.text, "1 انتخاب‌شده")

        app._show_tab(1)
        self.assertFalse(app.fab.visible)
        app._show_tab(2)
        self.assertEqual(app.current_tab, 2)

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

    def test_single_config_dialog_copy_button_copies_its_config(self):
        app, page = self._app()
        app._open_config_dialog(app.endpoints[1])
        dialog = self._last_dialog(page)
        dialog.actions[1].on_click(None)
        copied = page.set_clipboard.call_args[0][0]
        self.assertIn("Endpoint = 185.1.1.2:51820", copied)
        self.assertIn(f"PrivateKey = {REAL_KEY}", copied)

    def test_key_dialog_rejects_bad_key_then_saves_good_key(self):
        app, page = self._app()
        app.blueprint.user_interface.private_key = ""
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
        stored = load_blueprint(DEFAULT_DATA_FILE)
        self.assertEqual(stored.user_interface.private_key, REAL_KEY)

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


class TestTokenGate(unittest.TestCase):
    def test_token_gate_allows_local_and_valid_token_only(self):
        import mobile_app

        self.assertFalse(mobile_app._is_authorized(_fake_page("192.168.1.20", {}), "tok"))  # bare URL: no crash
        self.assertTrue(mobile_app._is_authorized(_fake_page("192.168.1.20", {"t": "tok"}), "tok"))
        self.assertFalse(mobile_app._is_authorized(_fake_page("192.168.1.20", {"t": "nope"}), "tok"))
        self.assertTrue(mobile_app._is_authorized(_fake_page("127.0.0.1", {}), "tok"))
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
