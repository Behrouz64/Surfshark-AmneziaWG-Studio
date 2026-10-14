"""
mobile_app.py: Phone-friendly Flet UI for Surfshark AmneziaWG Studio.

Start it with `python3 main.py --mobile`. The app is served over the local
network, so the phone's browser can open it (the URL with its access token is
printed at startup). All logic comes from mobile_core.py; this file only builds
the screens. Both copy formats are always available: the AmneziaWG config and
the wg:// link for Shadowrocket. The app never talks to Shadowrocket itself.

Screens (bottom navigation):
  - سرورها: working endpoints grouped by country. Each row has copy-config,
    copy-wg:// link and QR/text. Multi-select gives the group actions for both
    formats (queue, combined text, wg:// lines, endpoint list).
  - اسکن: headless DoH + UDP scan with a live log.
  - تنظیمات: obfuscation preset, PrivateKey, data reload. The help guide is its own tab.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable, Dict, List, Optional

import flet as ft
import flet.canvas as cv

from browser_harvest import DEFAULT_DATA_FILE, BlueprintData, is_placeholder_key, load_blueprint
from config_builder import country_code_to_flag, is_valid_wg_key
from mobile_core import (
    ANY_CONTINENT,
    qr_available,
    qr_dark_runs,
    qr_matrix,
    is_mobile_platform,
    continent_by_country_code,
    continents_present,
    filter_endpoints,
    DEFAULT_PRESET,
    PRESETS,
    CopyQueue,
    Endpoint,
    build_endpoint_config,
    build_endpoint_list_text,
    build_endpoint_wg_link,
    build_group_config_text,
    build_group_wg_links_text,
    endpoints_from_working_configs,
    group_by_country,
    has_usable_private_key,
    is_access_token_valid,
    params_for_preset,
    run_mobile_scan,
)
from scan_cache import DEFAULT_SCAN_CACHE_FILE, load_scan_cache
from mobile_guide import DEFAULT_GUIDE_LANGUAGE, GUIDE_LANGUAGE_NAMES, GUIDE_LANGUAGES, guide_sections
from vpn_detector import VpnStatus, detect_active_vpn

logger = logging.getLogger("SurfsharkAmneziaMobile")

BG = "#0B1620"
CARD = "#16222F"
LOG_BG = "#0E1A24"
ACCENT = "#00E676"
WARN_BG = "#3A2E00"
WARN = "#FFD54F"
ERROR = "#FF8A80"
MUTED = "#90A4AE"
TEXT = "#FFFFFF"
MONO = "monospace"

PROGRESS_THROTTLE_S = 0.3
MAX_LOG_LINES = 300
SHOWN_LOG_LINES = 200

# Copy formats. Both are always offered; the mode only decides what a queue step copies.
COPY_MODE_CONFIG = "config"  # AmneziaWG .conf text (Amnezia app)
COPY_MODE_WG = "wg"          # wg:// link (Shadowrocket on iPhone)


QR_SIDE_PX = 240


def _qr_canvas(matrix, side: int = QR_SIDE_PX) -> ft.Control:
    """Draws the QR code with canvas rectangles. No image library is needed, so it works on phones."""
    cell, runs = qr_dark_runs(matrix, side)
    dark = ft.Paint(color="#000000", style=ft.PaintingStyle.FILL)
    background = ft.Paint(color="#FFFFFF", style=ft.PaintingStyle.FILL)
    shapes = [cv.Rect(0, 0, side, side, paint=background)]
    shapes += [cv.Rect(x, y, width, cell, paint=dark) for x, y, width in runs]
    return cv.Canvas(shapes=shapes, width=side, height=side)


def _latency_color(latency_ms: float) -> str:
    if latency_ms < 150:
        return "#1B5E20"
    if latency_ms < 280:
        return "#5D4037"
    return "#37474F"


def _safe_vpn_status() -> Optional[VpnStatus]:
    try:
        return detect_active_vpn()
    except Exception as err:  # Android/iOS do not expose `netstat`/`ip route` the same way
        logger.warning("VPN detection unavailable: %s", err)
        return None


class MobileStudioApp:
    """Owns the page, the three screens and the scan worker."""

    def __init__(self, page: ft.Page):
        self.page = page
        self.blueprint: BlueprintData = load_blueprint(DEFAULT_DATA_FILE)
        self.preset_key: str = DEFAULT_PRESET
        self.endpoints: List[Endpoint] = []
        self.cache_time: str = ""
        self.selected: set = set()
        self.expanded_countries: set = set()
        self._default_expansion_applied: bool = False
        self.search_text: str = ""
        self.continent_filter: str = ANY_CONTINENT
        self.continent_map: Dict[str, str] = continent_by_country_code(self.blueprint.servers)
        self.current_tab: int = 0
        self.is_mobile: bool = is_mobile_platform(page.platform)
        self.vpn: Optional[VpnStatus] = None if self.is_mobile else _safe_vpn_status()

        self.scanning: bool = False
        self.scan_phase: str = ""
        self.scan_done: int = 0
        self.scan_total: int = 0
        self.log_lines: List[str] = []
        self._last_progress_render: float = 0.0

        self._load_cache()
        self._init_page()
        self._build_views()
        self._show_tab(0)

    # ------------------------------------------------------------------
    # Page & navigation
    # ------------------------------------------------------------------
    def _init_page(self):
        page = self.page
        page.title = "Surfshark AmneziaWG Studio"
        page.rtl = True
        page.theme_mode = ft.ThemeMode.DARK
        page.bgcolor = BG
        page.padding = 0
        page.theme = ft.Theme(color_scheme_seed=ACCENT)

        page.navigation_bar = ft.NavigationBar(
            selected_index=0,
            bgcolor=CARD,
            on_change=self._on_nav,
            destinations=[
                ft.NavigationBarDestination(icon=ft.Icons.CLOUD_OUTLINED, selected_icon=ft.Icons.CLOUD_ROUNDED, label="سرورها"),
                ft.NavigationBarDestination(icon=ft.Icons.RADAR, label="اسکن"),
                ft.NavigationBarDestination(icon=ft.Icons.MENU_BOOK_ROUNDED, label="راهنما"),
                ft.NavigationBarDestination(icon=ft.Icons.TUNE, label="تنظیمات"),
            ],
        )
        self.fab = ft.FloatingActionButton(
            text="انتخاب",
            icon=ft.Icons.PLAYLIST_ADD_CHECK_ROUNDED,
            bgcolor=ACCENT,
            foreground_color="#000000",
            visible=False,
            on_click=self._open_group_actions,
        )
        page.floating_action_button = self.fab

        self.host = ft.Container(expand=True, padding=ft.padding.symmetric(horizontal=14, vertical=12))
        # The header lives inside SafeArea with the content, so it never sits under the status bar.
        self.header = ft.Container(
            bgcolor=CARD,
            padding=ft.padding.symmetric(horizontal=14, vertical=10),
            content=ft.Row(
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                controls=[
                    ft.Icon(ft.Icons.SHIELD_ROUNDED, color=ACCENT, size=26),
                    ft.Column(expand=True, spacing=0, tight=True, controls=[
                        ft.Text("Surfshark AmneziaWG Studio", size=16, weight=ft.FontWeight.BOLD),
                        ft.Text("نسخه‌ی گوشی", size=11, color=MUTED),
                    ]),
                    ft.IconButton(icon=ft.Icons.REFRESH_ROUNDED, tooltip="بارگذاری مجدد", on_click=self._reload_all),
                ],
            ),
        )
        page.add(ft.SafeArea(
            content=ft.Column(spacing=0, expand=True, controls=[self.header, self.host]),
            expand=True,
        ))

    def _on_nav(self, e):
        self._show_tab(int(e.control.selected_index))

    def _show_tab(self, index: int):
        self.current_tab = index
        views = [self.servers_view, self.scan_view, self.guide_view, self.settings_view]
        self.host.content = views[index]
        self.page.navigation_bar.selected_index = index
        self._refresh_fab()
        self._update()

    def _refresh_fab(self):
        self.fab.text = f"{len(self.selected)} انتخاب‌شده"
        self.fab.visible = self.current_tab == 0 and bool(self.selected)

    # ------------------------------------------------------------------
    # Small helpers
    # ------------------------------------------------------------------
    def _update(self):
        try:
            self.page.update()
        except Exception as err:  # the browser tab may have closed while a scan was running
            logger.debug("page update skipped: %s", err)

    def _toast(self, message: str, is_error: bool = False):
        snack = ft.SnackBar(
            content=ft.Text(message, color="#FFFFFF"),
            bgcolor="#C62828" if is_error else "#2E7D32",
            duration=3500,
        )
        self._open_control(snack)

    def _open_control(self, control):
        if hasattr(self.page, "open"):
            self.page.open(control)
        else:
            self.page.dialog = control
            control.open = True
            self._update()

    def _close_control(self, control):
        if hasattr(self.page, "close"):
            self.page.close(control)
        else:
            control.open = False
            self._update()

    def _copy(self, text: str, success_message: str):
        """
        Copies text through the browser clipboard. Flet does not report whether the
        browser allowed it, and plain-HTTP pages on a LAN often refuse clipboard
        access, so the config is always also shown in a selectable box.
        """
        try:
            self.page.set_clipboard(text)
            self._toast(success_message)
        except Exception as err:
            logger.warning("clipboard copy failed: %s", err)
            self._toast(f"کپی خودکار ممکن نشد ({err}). متن را از کادر کانفیگ دستی کپی کنید.", is_error=True)

    def _params(self):
        return params_for_preset(self.preset_key)

    def _config_text(self, endpoint: Endpoint) -> str:
        return build_endpoint_config(endpoint, self.blueprint.user_interface, self._params())

    def _wg_text(self, endpoint: Endpoint) -> str:
        return build_endpoint_wg_link(endpoint, self.blueprint.user_interface, self._params())

    def _text_for_mode(self, endpoint: Endpoint, mode: str) -> str:
        return self._wg_text(endpoint) if mode == COPY_MODE_WG else self._config_text(endpoint)

    def _selected_endpoints(self) -> List[Endpoint]:
        return [e for e in self.endpoints if e.key in self.selected]

    def _with_private_key(self, action: Callable[[], None]):
        """Runs action once a usable PrivateKey exists; otherwise asks for it first."""
        if has_usable_private_key(self.blueprint.user_interface):
            action()
            return
        self._toast("ابتدا PrivateKey را ثبت کنید", is_error=True)
        self._open_key_dialog(on_saved=action)

    # ------------------------------------------------------------------
    # Data
    # ------------------------------------------------------------------
    def _load_cache(self):
        data = load_scan_cache(DEFAULT_SCAN_CACHE_FILE) or {}
        self.endpoints = endpoints_from_working_configs(data.get("working_configs", []))
        self.cache_time = data.get("formatted_time", "")
        self.selected &= {e.key for e in self.endpoints}

    def _reload_all(self, e=None):
        self.blueprint = load_blueprint(DEFAULT_DATA_FILE)
        self.continent_map = continent_by_country_code(self.blueprint.servers)
        self._load_cache()
        self.vpn = None if self.is_mobile else _safe_vpn_status()
        self._render_servers()
        self._render_settings()
        self._refresh_fab()
        self._toast("داده‌ها دوباره خوانده شد")
        self._update()

    # ------------------------------------------------------------------
    # Servers screen
    # ------------------------------------------------------------------
    def _build_views(self):
        self.vpn_banner = self._banner(
            "⚠️ VPN روشن است؛ نتایج اسکن ممکن است اشتباه باشد. قبل از اسکن خاموشش کنید.", WARN_BG, WARN
        )
        self.key_banner = ft.Container(
            visible=False,
            bgcolor=WARN_BG,
            border_radius=10,
            padding=10,
            on_click=self._open_key_dialog,
            content=ft.Text("🔑 PrivateKey ثبت نشده. برای کپی کانفیگ لازم است؛ اینجا بزنید.", color=WARN, size=12),
        )
        self.summary_text = ft.Text(size=12, color=MUTED)
        self.search_field = ft.TextField(
            hint_text="جستجو: کشور، شهر یا آی‌پی",
            prefix_icon=ft.Icons.SEARCH_ROUNDED,
            dense=True,
            border_radius=12,
            bgcolor=CARD,
            on_change=self._on_search,
        )
        self.country_list = ft.Column(spacing=8)
        self.dashboard_row = ft.Row(wrap=True, spacing=8, run_spacing=8)
        self.continent_row = ft.Row(wrap=True, spacing=6, run_spacing=6)
        self.bulk_row = ft.Row(wrap=True, spacing=8, run_spacing=8)

        self.servers_view = ft.Column(
            expand=True,
            scroll=ft.ScrollMode.AUTO,
            spacing=10,
            controls=[
                ft.Text("سرورهای سالم", size=20, weight=ft.FontWeight.BOLD),
                self.summary_text,
                self.vpn_banner,
                self.key_banner,
                self.dashboard_row,
                self.continent_row,
                self.search_field,
                self.bulk_row,
                self.country_list,
                ft.Container(height=72),
            ],
        )

        self.scan_status = ft.Text("آماده برای اسکن", size=16, weight=ft.FontWeight.BOLD)
        self.scan_detail = ft.Text("", size=12, color=MUTED)
        self.scan_progress = ft.ProgressBar(value=0, color=ACCENT, bgcolor="#243447", visible=False)
        self.scan_button = ft.ElevatedButton(
            "شروع اسکن", icon=ft.Icons.PLAY_ARROW_ROUNDED, on_click=self._on_scan_click
        )
        self.scan_vpn_banner = self._banner(
            "⚠️ VPN روشن است. اسکن را با VPN خاموش انجام دهید.", WARN_BG, WARN
        )
        self.log_column = ft.Column(spacing=2, auto_scroll=True)

        self.scan_view = ft.Column(
            expand=True,
            scroll=ft.ScrollMode.AUTO,
            spacing=12,
            controls=[
                ft.Text("اسکن آی‌پی‌ها", size=20, weight=ft.FontWeight.BOLD),
                self.scan_vpn_banner,
                ft.Container(
                    visible=self.is_mobile,
                    bgcolor=WARN_BG,
                    border_radius=10,
                    padding=10,
                    content=ft.Text(
                        "VPN را خودتان خاموش کنید. برنامه روی گوشی وضعیت VPN را نمی‌بیند.",
                        color=WARN,
                        size=12,
                    ),
                ),
                ft.Container(
                    bgcolor=CARD,
                    border_radius=14,
                    padding=14,
                    content=ft.Column(
                        spacing=8,
                        controls=[self.scan_status, self.scan_detail, self.scan_progress, self.scan_button],
                    ),
                ),
                ft.Text("گزارش زنده", size=13, color=MUTED),
                ft.Container(
                    height=280,
                    bgcolor=LOG_BG,
                    border_radius=12,
                    padding=10,
                    content=ft.Column(scroll=ft.ScrollMode.AUTO, controls=[self.log_column]),
                ),
            ],
        )

        self.preset_dropdown = ft.Dropdown(
            label="پروفایل Obfuscation",
            value=self.preset_key,
            options=[ft.dropdown.Option(key=key, text=label) for key, (label, _) in PRESETS.items()],
            on_change=self._on_preset_change,
        )
        self.key_status = ft.Text(size=13)
        self.data_info = ft.Text(size=12, color=MUTED)
        self.settings_view = ft.Column(
            expand=True,
            scroll=ft.ScrollMode.AUTO,
            spacing=12,
            controls=[
                ft.Text("تنظیمات", size=20, weight=ft.FontWeight.BOLD),
                self.preset_dropdown,
                ft.Container(
                    bgcolor=CARD,
                    border_radius=14,
                    padding=14,
                    content=ft.Column(
                        spacing=10,
                        controls=[
                            ft.Text("PrivateKey", weight=ft.FontWeight.BOLD),
                            self.key_status,
                            ft.OutlinedButton(
                                "ثبت یا تغییر PrivateKey",
                                icon=ft.Icons.VPN_KEY_ROUNDED,
                                on_click=self._open_key_dialog,
                            ),
                        ],
                    ),
                ),
                ft.Container(
                    bgcolor=CARD,
                    border_radius=14,
                    padding=14,
                    content=ft.Column(
                        spacing=10,
                        controls=[
                            ft.Text("داده‌ها", weight=ft.FontWeight.BOLD),
                            self.data_info,
                            ft.OutlinedButton(
                                "بارگذاری مجدد داده‌ها",
                                icon=ft.Icons.REFRESH_ROUNDED,
                                on_click=self._reload_all,
                            ),
                        ],
                    ),
                ),
            ],
        )

        self.guide_view = self._build_guide_view()
        self._render_servers()
        self._render_scan_state()
        self._render_settings()

    def _build_guide_view(self) -> ft.Column:
        self.guide_language: str = DEFAULT_GUIDE_LANGUAGE
        self.guide_body = ft.Column(spacing=10)
        self.guide_buttons = {
            code: ft.ElevatedButton(
                GUIDE_LANGUAGE_NAMES[code],
                on_click=lambda e, c=code: self._set_guide_language(c),
            )
            for code in GUIDE_LANGUAGES
        }
        view = ft.Column(
            expand=True,
            scroll=ft.ScrollMode.AUTO,
            spacing=12,
            controls=[
                ft.Text("راهنما", size=20, weight=ft.FontWeight.BOLD),
                ft.Row(spacing=8, controls=list(self.guide_buttons.values())),
                self.guide_body,
                ft.Container(height=72),
            ],
        )
        self._render_guide()
        return view

    def _set_guide_language(self, code: str):
        self.guide_language = code
        self._render_guide()
        self._update()

    def _render_guide(self):
        controls: List[ft.Control] = []
        for section in guide_sections(self.guide_language):
            controls.append(ft.Text(section["title"], weight=ft.FontWeight.BOLD, size=14))
            for kind, value in section["blocks"]:
                controls.append(self._guide_block(kind, value))
        self.guide_body.controls = controls
        for code, button in self.guide_buttons.items():
            button.disabled = code == self.guide_language  # the active language is shown as pressed

    def _guide_block(self, kind: str, value) -> ft.Control:
        if kind == "p":
            return ft.Text(value, size=13, color=MUTED)
        if kind == "note":
            return ft.Container(
                bgcolor=WARN_BG,
                border_radius=10,
                padding=10,
                content=ft.Text(value, size=12, color=WARN),
            )
        if kind == "ol":
            rows = [ft.Text(f"{n}. {text}", size=13, color=MUTED) for n, text in enumerate(value, start=1)]
        else:
            rows = [ft.Text(f"• {text}", size=13, color=MUTED) for text in value]
        return ft.Column(spacing=6, controls=rows)


    def _banner(self, text: str, bgcolor: str, color: str) -> ft.Container:
        return ft.Container(
            visible=self.vpn is not None and self.vpn.is_vpn_active,
            bgcolor=bgcolor,
            border_radius=10,
            padding=10,
            content=ft.Text(text, color=color, size=12),
        )

    def _refresh_banners(self):
        vpn_on = self.vpn is not None and bool(self.vpn.is_vpn_active)
        self.vpn_banner.visible = vpn_on
        self.scan_vpn_banner.visible = vpn_on
        self.key_banner.visible = not has_usable_private_key(self.blueprint.user_interface)

    def _on_search(self, e):
        self.search_text = e.control.value or ""
        self._render_servers()
        self._update()

    def _render_servers(self):
        self._refresh_banners()
        if self.cache_time:
            self.summary_text.value = f"{len(self.endpoints)} آی‌پی سالم · آخرین اسکن: {self.cache_time}"
        else:
            self.summary_text.value = "هنوز اسکنی ذخیره نشده. به تب «اسکن» بروید."

        if not self.endpoints:
            self.country_list.controls = [self._empty_card("هنوز آی‌پی سالمی نداریم. از تب «اسکن» شروع کنید.")]
            return

        query = self.search_text.strip().lower()
        visible = filter_endpoints(self.endpoints, self.continent_map, self.continent_filter, self.search_text)
        self._render_dashboard(visible)
        self._render_continent_chips()
        self._render_bulk_actions(visible)
        if not visible:
            self.country_list.controls = [self._empty_card("موردی با این فیلتر یا جستجو پیدا نشد.")]
            return

        groups = group_by_country(visible)
        if not self._default_expansion_applied and groups:
            # Open the fastest country on first view so the list is not all collapsed.
            self.expanded_countries.add(groups[0][0])
            self._default_expansion_applied = True
        self.country_list.controls = [
            self._country_tile(country, items, expanded=bool(query) or country in self.expanded_countries)
            for country, items in groups
        ]

    def _stat_tile(self, label: str, value: str, color: str = TEXT) -> ft.Container:
        return ft.Container(
            bgcolor=CARD,
            border_radius=12,
            padding=ft.padding.symmetric(horizontal=12, vertical=10),
            width=150,
            content=ft.Column(spacing=2, tight=True, controls=[
                ft.Text(label, size=11, color=MUTED),
                ft.Text(value, size=20, weight=ft.FontWeight.BOLD, color=color),
            ]),
        )

    def _render_dashboard(self, visible: List[Endpoint]):
        countries = {e.country for e in self.endpoints}
        fastest = min((e.latency_ms for e in self.endpoints if e.has_latency), default=None)
        self.dashboard_row.controls = [
            self._stat_tile("سرورهای سالم", str(len(self.endpoints)), ACCENT),
            self._stat_tile("کشورها", str(len(countries))),
            self._stat_tile("سریع‌ترین", f"{int(fastest)}ms" if fastest is not None else "—", ACCENT),
            self._stat_tile("نمایش داده‌شده", str(len(visible))),
            self._stat_tile("انتخاب‌شده", str(len(self.selected)), WARN if self.selected else TEXT),
        ]

    def _set_continent(self, name: str):
        self.continent_filter = name
        self._render_servers()
        self._update()

    def _render_continent_chips(self):
        options = [(ANY_CONTINENT, len(self.endpoints))] + continents_present(self.endpoints, self.continent_map)
        self.continent_row.controls = [
            ft.Chip(
                label=ft.Text(f"{'همه‌ی قاره‌ها' if name == ANY_CONTINENT else name} ({count})", size=12),
                selected=self.continent_filter == name,
                on_select=lambda e, n=name: self._set_continent(n),
            )
            for name, count in options
        ]

    def _render_bulk_actions(self, visible: List[Endpoint]):
        self.bulk_row.controls = [
            ft.ElevatedButton(
                f"انتخاب همه‌ی نمایش‌داده‌شده ({len(visible)})",
                icon=ft.Icons.DONE_ALL_ROUNDED,
                disabled=not visible,
                on_click=lambda e: self._select_visible(visible),
            ),
            ft.OutlinedButton(
                "پاک کردن انتخاب",
                icon=ft.Icons.CLEAR_ALL_ROUNDED,
                disabled=not self.selected,
                on_click=lambda e: self._clear_selection_now(),
            ),
        ]

    def _select_visible(self, visible: List[Endpoint]):
        self.selected.update(e.key for e in visible)
        self._render_servers()
        self._refresh_fab()
        self._update()

    def _clear_selection_now(self):
        self.selected.clear()
        self._render_servers()
        self._refresh_fab()
        self._update()

    def _empty_card(self, text: str) -> ft.Container:
        return ft.Container(
            bgcolor=CARD,
            border_radius=12,
            padding=16,
            content=ft.Text(text, color=MUTED, size=13),
        )

    def _country_tile(self, country: str, items: List[Endpoint], expanded: bool) -> ft.ExpansionTile:
        all_selected = all(e.key in self.selected for e in items)
        action = ft.TextButton(
            "لغو انتخاب کشور" if all_selected else "انتخاب کل کشور",
            icon=ft.Icons.CHECKLIST_ROUNDED,
            on_click=lambda e, its=items, sel=not all_selected: self._select_many(its, sel),
        )
        return ft.ExpansionTile(
            title=ft.Text(f"{country_code_to_flag(items[0].country_code)}  {country}", weight=ft.FontWeight.BOLD),
            subtitle=ft.Text(f"{len(items)} آی‌پی · سریع‌ترین: {items[0].latency_label}", size=12, color=MUTED),
            initially_expanded=expanded,
            bgcolor=CARD,
            collapsed_bgcolor=CARD,
            on_change=lambda e, name=country: self._on_tile_toggle(e, name),
            controls=[
                ft.Row(alignment=ft.MainAxisAlignment.END, controls=[action]),
                *[self._endpoint_row(ep) for ep in items],
            ],
        )

    def _on_tile_toggle(self, e, country: str):
        expanded = str(e.data).lower() == "true"
        if expanded:
            self.expanded_countries.add(country)
        else:
            self.expanded_countries.discard(country)

    def _endpoint_row(self, ep: Endpoint) -> ft.Control:
        return ft.Container(
            padding=ft.padding.symmetric(horizontal=4, vertical=2),
            content=ft.Row(
                spacing=4,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                controls=[
                    ft.Checkbox(
                        value=ep.key in self.selected,
                        on_change=lambda e, k=ep.key: self._toggle(k, bool(e.control.value)),
                    ),
                    ft.Column(
                        expand=True,
                        spacing=0,
                        controls=[
                            ft.Text(ep.city, size=14, weight=ft.FontWeight.W_600, overflow=ft.TextOverflow.ELLIPSIS),
                            ft.Text(f"{ep.ip}:{ep.port}", size=12, color=MUTED, font_family=MONO),
                        ],
                    ),
                    ft.Container(
                        padding=ft.padding.symmetric(horizontal=6, vertical=2),
                        bgcolor=_latency_color(ep.latency_ms),
                        border_radius=6,
                        content=ft.Text(ep.latency_label, size=11, color="#B9F6CA", weight=ft.FontWeight.BOLD),
                    ),
                    ft.IconButton(
                        icon=ft.Icons.CONTENT_COPY_ROUNDED,
                        tooltip="کپی کانفیگ AmneziaWG",
                        on_click=lambda e, x=ep: self._with_private_key(lambda: self._copy_single(x)),
                    ),
                    ft.IconButton(
                        icon=ft.Icons.LINK_ROUNDED,
                        tooltip="کپی لینک wg:// برای Shadowrocket",
                        on_click=lambda e, x=ep: self._with_private_key(lambda: self._copy_single_wg(x)),
                    ),
                    ft.IconButton(
                        icon=ft.Icons.QR_CODE_ROUNDED,
                        tooltip="متن و QR کانفیگ",
                        on_click=lambda e, x=ep: self._with_private_key(lambda: self._open_config_dialog(x)),
                    ),
                ],
            ),
        )

    def _toggle(self, key: str, value: bool):
        if value:
            self.selected.add(key)
        else:
            self.selected.discard(key)
        self._refresh_fab()
        self._update()

    def _select_many(self, items: List[Endpoint], select: bool):
        for ep in items:
            if select:
                self.selected.add(ep.key)
            else:
                self.selected.discard(ep.key)
        self._render_servers()
        self._refresh_fab()
        self._update()

    def _copy_single(self, ep: Endpoint):
        self._copy(self._config_text(ep), f"کانفیگ {ep.city} کپی شد")

    def _copy_single_wg(self, ep: Endpoint):
        self._copy(self._wg_text(ep), f"لینک wg:// {ep.city} کپی شد")

    # ------------------------------------------------------------------
    # Single config dialog (text + QR)
    # ------------------------------------------------------------------
    def _open_config_dialog(self, ep: Endpoint):
        text = self._config_text(ep)
        wg_text = self._wg_text(ep)
        content: List[ft.Control] = [
            ft.Text(ep.tunnel_name, weight=ft.FontWeight.BOLD),
            ft.Text("متن کانفیگ (برای انتخاب دستی لمس طولانی کنید):", size=12, color=MUTED),
            ft.Container(
                height=200,
                bgcolor=LOG_BG,
                border_radius=8,
                padding=8,
                content=ft.Column(
                    scroll=ft.ScrollMode.AUTO,
                    controls=[ft.SelectionArea(content=ft.Text(text, size=11, font_family=MONO))],
                ),
            ),
        ]
        if qr_available():
            content.append(_qr_canvas(qr_matrix(text)))
        else:
            content.append(ft.Text("QR در دسترس نیست (کتابخانه qrcode نصب نیست).", size=12, color=ERROR))

        dialog = ft.AlertDialog(
            title=ft.Text("کانفیگ و QR"),
            content=ft.Container(
                width=300,
                height=460,
                content=ft.Column(scroll=ft.ScrollMode.AUTO, spacing=8, controls=content),
            ),
            actions=[
                ft.TextButton("بستن", on_click=lambda e: self._close_control(dialog)),
                ft.ElevatedButton(
                    "کپی کانفیگ",
                    icon=ft.Icons.CONTENT_COPY_ROUNDED,
                    on_click=lambda e: self._copy(text, f"کانفیگ {ep.city} کپی شد"),
                ),
                ft.OutlinedButton(
                    "کپی wg://",
                    icon=ft.Icons.LINK_ROUNDED,
                    on_click=lambda e: self._copy(wg_text, f"لینک wg:// {ep.city} کپی شد"),
                ),
            ],
        )
        self._open_control(dialog)

    # ------------------------------------------------------------------
    # Group actions (selection FAB)
    # ------------------------------------------------------------------
    def _open_group_actions(self, e=None):
        items = self._selected_endpoints()
        if not items:
            self._toast("ابتدا چند کانفیگ را انتخاب کنید", is_error=True)
            return
        self._with_private_key(lambda: self._show_group_actions(items))

    def _show_group_actions(self, items: List[Endpoint]):
        dialog = ft.AlertDialog(
            title=ft.Text(f"{len(items)} کانفیگ انتخاب شده"),
            content=ft.Container(
                width=290,
                content=ft.Column(
                    tight=True,
                    spacing=10,
                    controls=[
                        ft.Text(
                            "اپ AmneziaWG و Shadowrocket هر بار یک کانفیگ یا لینک وارد می‌کنند. "
                            "برای این کار «صف کپی» را استفاده کنید.",
                            size=12,
                            color=MUTED,
                        ),
                        ft.ElevatedButton(
                            "صف کپی کانفیگ: یکی‌یکی برای AmneziaWG",
                            icon=ft.Icons.SKIP_NEXT_ROUNDED,
                            on_click=lambda e: self._start_queue(dialog, items, mode=COPY_MODE_CONFIG),
                        ),
                        ft.ElevatedButton(
                            "صف کپی لینک wg://: یکی‌یکی برای Shadowrocket",
                            icon=ft.Icons.LINK_ROUNDED,
                            on_click=lambda e: self._start_queue(dialog, items, mode=COPY_MODE_WG),
                        ),
                        ft.OutlinedButton(
                            "کپی متن ترکیبی همه کانفیگ‌ها",
                            icon=ft.Icons.CONTENT_COPY_ROUNDED,
                            on_click=lambda e: self._copy_group(dialog, items),
                        ),
                        ft.OutlinedButton(
                            "کپی همه لینک‌های wg:// (هر خط یک لینک)",
                            icon=ft.Icons.COPY_ALL_ROUNDED,
                            on_click=lambda e: self._copy_group_wg(dialog, items),
                        ),
                        ft.OutlinedButton(
                            "کپی لیست کشور، شهر و آی‌پی",
                            icon=ft.Icons.LIST_ALT_ROUNDED,
                            on_click=lambda e: self._copy_endpoint_list(dialog, items),
                        ),
                        ft.TextButton(
                            "پاک کردن انتخاب",
                            icon=ft.Icons.CLEAR_ALL_ROUNDED,
                            on_click=lambda e: self._clear_selection(dialog),
                        ),
                    ],
                ),
            ),
            actions=[ft.TextButton("بستن", on_click=lambda e: self._close_control(dialog))],
        )
        self._open_control(dialog)

    def _copy_group(self, dialog, items: List[Endpoint]):
        self._close_control(dialog)
        text = build_group_config_text(items, self.blueprint.user_interface, self._params())
        self._copy(text, f"{len(items)} کانفیگ به‌صورت متن ترکیبی کپی شد")

    def _copy_group_wg(self, dialog, items: List[Endpoint]):
        self._close_control(dialog)
        text = build_group_wg_links_text(items, self.blueprint.user_interface, self._params())
        self._copy(text, f"{len(items)} لینک wg:// کپی شد (هر خط یک لینک)")

    def _copy_endpoint_list(self, dialog, items: List[Endpoint]):
        self._close_control(dialog)
        self._copy(build_endpoint_list_text(items), f"لیست {len(items)} آی‌پی کپی شد")

    def _clear_selection(self, dialog):
        self._close_control(dialog)
        self.selected.clear()
        self._render_servers()
        self._refresh_fab()
        self._update()

    def _start_queue(self, parent_dialog, items: List[Endpoint], mode: str = COPY_MODE_CONFIG):
        self._close_control(parent_dialog)
        queue = CopyQueue(items)
        is_wg = mode == COPY_MODE_WG
        noun = "لینک" if is_wg else "کانفیگ"
        info = ft.Text(size=14, weight=ft.FontWeight.BOLD)
        hint = ft.Text(
            f"۱) {noun} کپی می‌شود.\n"
            + (
                "۲) در Shadowrocket سرور جدید را از کلیپ‌بورد وارد کنید.\n"
                if is_wg else
                "۲) در اپ AmneziaWG تونل جدید را از متن وارد کنید.\n"
            )
            + "۳) برگردید و «بعدی» را بزنید.",
            size=12,
            color=MUTED,
        )

        def _refresh_info():
            current = queue.current
            info.value = f"{noun} {queue.position} از {queue.total}\n{current.tunnel_name if current else ''}"

        def _copy_current(e=None):
            current = queue.current
            if current:
                self._copy(self._text_for_mode(current, mode), f"{noun} {queue.position} از {queue.total} کپی شد")

        def _next(e):
            if queue.advance():
                _refresh_info()
                _copy_current()
                self._update()
            else:
                self._toast("این آخرین کانفیگ صف بود")

        dialog = ft.AlertDialog(
            title=ft.Text("صف کپی"),
            content=ft.Container(width=290, content=ft.Column(tight=True, spacing=10, controls=[info, hint])),
            actions=[
                ft.TextButton("کپی همین", on_click=_copy_current),
                ft.ElevatedButton("بعدی", icon=ft.Icons.SKIP_NEXT_ROUNDED, on_click=_next),
                ft.TextButton("بستن", on_click=lambda e: self._close_control(dialog)),
            ],
        )
        _refresh_info()
        self._open_control(dialog)
        _copy_current()

    # ------------------------------------------------------------------
    # PrivateKey dialog
    # ------------------------------------------------------------------
    def _open_key_dialog(self, e=None, on_saved: Optional[Callable[[], None]] = None):
        key_field = ft.TextField(
            label="PrivateKey (Base64)",
            hint_text="۴۴ کاراکتر که با = تمام می‌شود",
            password=True,
            can_reveal_password=True,
        )
        error_text = ft.Text("", color=ERROR, size=12)

        def _save(_e):
            key = (key_field.value or "").strip()
            if not is_valid_wg_key(key) or is_placeholder_key(key):
                error_text.value = "فرمت کلید درست نیست. کلید WireGuard باید ۴۴ کاراکتری باشد."
                self._update()
                return
            self.blueprint.user_interface.private_key = key
            self._close_control(dialog)
            self._refresh_banners()
            self._render_settings()
            self._toast("PrivateKey فقط در همین اجرا ثبت شد")
            self._update()
            if on_saved:
                on_saved()

        dialog = ft.AlertDialog(
            title=ft.Text("PrivateKey"),
            content=ft.Container(
                width=290,
                content=ft.Column(
                    tight=True,
                    spacing=10,
                    controls=[
                        ft.Text(
                            "کلید خصوصی WireGuard حساب Surfshark خود را وارد کنید. "
                            "فقط در همین اجرای برنامه نگه داشته می‌شود و روی دیسک نوشته نمی‌شود.",
                            size=12,
                            color=MUTED,
                        ),
                        key_field,
                        error_text,
                    ],
                ),
            ),
            actions=[
                ft.TextButton("انصراف", on_click=lambda e: self._close_control(dialog)),
                ft.ElevatedButton("ذخیره", on_click=_save),
            ],
        )
        self._open_control(dialog)

    # ------------------------------------------------------------------
    # Scan screen
    # ------------------------------------------------------------------
    def _on_scan_click(self, e=None):
        if self.scanning:
            return
        if self.vpn is not None and self.vpn.is_vpn_active:
            dialog = ft.AlertDialog(
                title=ft.Text("VPN روشن است"),
                content=ft.Text(
                    "اسکن باید مستقیم از اینترنت محلی انجام شود. با VPN روشن، نتایج اشتباه می‌شوند. ادامه می‌دهید؟",
                    size=13,
                ),
                actions=[
                    ft.TextButton("لغو", on_click=lambda e: self._close_control(dialog)),
                    ft.ElevatedButton(
                        "ادامه",
                        on_click=lambda e: (self._close_control(dialog), self._start_scan()),
                    ),
                ],
            )
            self._open_control(dialog)
            return
        self._start_scan()

    def _start_scan(self):
        self.scanning = True
        self.log_lines.clear()
        self.log_column.controls = []
        self.scan_phase = ""
        self.scan_done = self.scan_total = 0
        self._render_scan_state()
        self._update()
        threading.Thread(target=self._scan_worker, name="mobile-scan", daemon=True).start()

    def _scan_worker(self):
        try:
            result = run_mobile_scan(
                self.blueprint,
                cache_path=DEFAULT_SCAN_CACHE_FILE,
                on_log=self._log,
                on_progress=self._on_progress,
            )
            self._load_cache()
            self._log(f"✅ {len(result.working_configs)} آی‌پی سالم ذخیره شد")
            self._toast(f"اسکن تمام شد: {len(result.working_configs)} آی‌پی سالم")
        except Exception as err:
            logger.exception("mobile scan failed")
            self._log(f"❌ خطا: {err}")
            self._toast(f"اسکن ناموفق بود: {err}", is_error=True)
        finally:
            self.scanning = False
            self._render_scan_state()
            self._render_servers()
            self._refresh_fab()
            self._update()

    def _on_progress(self, phase: str, done: int, total: int):
        self.scan_phase = phase
        self.scan_done = done
        self.scan_total = total
        now = time.monotonic()
        if done >= total or now - self._last_progress_render >= PROGRESS_THROTTLE_S:
            self._last_progress_render = now
            self._render_scan_state()
            self._update()

    def _log(self, message: str):
        self.log_lines.append(message)
        del self.log_lines[:-MAX_LOG_LINES]
        self.log_column.controls = [
            ft.Text(line, size=11, font_family=MONO, color="#CFD8DC")
            for line in self.log_lines[-SHOWN_LOG_LINES:]
        ]
        self._update()

    def _render_scan_state(self):
        self._refresh_banners()
        self.scan_button.disabled = self.scanning
        if self.scanning:
            label = {"dns": "DNS (DoH)", "udp": "تست UDP"}.get(self.scan_phase, "آماده‌سازی")
            self.scan_status.value = f"در حال اسکن: {label}"
            self.scan_detail.value = f"{self.scan_done} از {self.scan_total}" if self.scan_total else ""
            self.scan_progress.visible = True
            self.scan_progress.value = (self.scan_done / self.scan_total) if self.scan_total else None
        else:
            self.scan_status.value = "اسکن تمام شد" if self.cache_time else "آماده برای اسکن"
            self.scan_detail.value = (
                f"{len(self.endpoints)} آی‌پی سالم · آخرین اسکن: {self.cache_time}" if self.cache_time else ""
            )
            self.scan_progress.visible = False
            self.scan_progress.value = 0

    # ------------------------------------------------------------------
    # Settings screen
    # ------------------------------------------------------------------
    def _on_preset_change(self, e):
        self.preset_key = e.control.value or DEFAULT_PRESET
        label = PRESETS[self.preset_key][0]
        self._toast(f"پروفایل فعال: {label}")


    def _render_settings(self):
        key_ok = has_usable_private_key(self.blueprint.user_interface)
        self.key_status.value = "✅ ثبت شده" if key_ok else "❌ ثبت نشده"
        self.key_status.color = None if key_ok else ERROR
        self.data_info.value = (
            f"فایل سرورها: {DEFAULT_DATA_FILE}\n"
            f"تعداد سرورهای ثبت‌شده: {len(self.blueprint.servers)}\n"
            f"آخرین اسکن: {self.cache_time or '—'}"
        )


def main(page: ft.Page, token: str = ""):
    """
    Flet entry point. When a token is set, every visitor must present it as ?t=<token>.

    A browser that reconnects keeps its Flet session, so main() runs only once per session.
    The check therefore runs again on every route change, which Flet sends when the reconnecting
    browser's route (with ?t=...) differs from the stored one.
    """
    if not token:
        MobileStudioApp(page)
        return

    state = {"app": None, "denied": False}

    def _gate(_e=None):
        if state["app"] is not None:
            return
        if _is_authorized(page, token):
            page.controls.clear()
            state["app"] = MobileStudioApp(page)
            return
        if not state["denied"]:
            state["denied"] = True
            _show_denied(page)
            page.update()

    page.on_route_change = _gate
    _gate()


def _show_denied(page: ft.Page):
    page.title = "Surfshark AWG"
    page.theme_mode = ft.ThemeMode.DARK
    page.bgcolor = BG
    page.padding = 24
    page.add(ft.Text("دسترسی ممنوع", size=22, weight=ft.FontWeight.BOLD, color=ERROR))
    page.add(ft.Text(
        "آدرس کامل را که در ترمینال کامپیوتر نمایش داده شده (شامل ?t=...) در مرورگر باز کنید.",
        color=MUTED,
    ))


def _query_token(page: ft.Page) -> Optional[str]:
    # Flet fills the query only when it refreshes it (on route events), so refresh it first.
    # QueryString.get raises KeyError for a missing key instead of returning None.
    try:
        page.query()
        return page.query.get("t")
    except (KeyError, AttributeError):
        return None


def _is_authorized(page: ft.Page, token: str) -> bool:
    # Every visitor needs the token, this computer included. Trusting an IP is not safe:
    # a relay on the same machine makes remote traffic look like 127.0.0.1.
    return is_access_token_valid(_query_token(page), token)