"""
ui.py: Modern Desktop GUI for Surfshark AmneziaWG Generator & Scanner
Built with Flet (Flutter-powered Python desktop framework).
"""

from __future__ import annotations

import base64
import json
import os
import re
import threading
import time
from typing import Dict, List, Optional

import flet as ft

# Compatibility aliases across Flet versions (0.23 through 0.28+)
if not hasattr(ft, "icons") and hasattr(ft, "Icons"):
    ft.icons = ft.Icons
if not hasattr(ft, "colors") and hasattr(ft, "Colors"):
    ft.colors = ft.Colors

# Hotfix for Flet 0.28.x on Python 3.9: Tab.before_update subscripted generic instance check
try:
    from flet.core.tabs import Tab
    def _safe_tab_before_update(self):
        super(Tab, self).before_update()
        self._set_attr_json("iconMargin", getattr(self, "_Tab__icon_margin", None))
        icon = getattr(self, "_Tab__icon", None)
        if icon is not None and not isinstance(icon, ft.Control):
            try:
                from flet.core.types import IconEnums
                self._set_enum_attr("icon", icon, IconEnums)
            except Exception:
                self._set_attr("icon", str(icon))
    Tab.before_update = _safe_tab_before_update
except Exception:
    pass

from browser_harvest import (
    DEFAULT_DATA_FILE,
    BlueprintData,
    ServerMetadata,
    UserInterfaceConfig,
    get_default_seed_blueprint,
    import_conf_file,
    is_placeholder_key,
    load_blueprint,
    run_attended_browser_harvest,
    save_blueprint,
    update_blueprint_with_api_keys,
)
from checker import (
    CheckResult,
    FastUdpScanner,
    ScanMode,
    deep_screen_working_configs_sync,
    deep_verify_endpoint_sync,
)
from config_builder import (
    AmneziaParams,
    build_amnezia_config,
    build_shadowrocket_wg_url,
    country_code_to_flag,
    derive_public_key,
    export_shadowrocket_bundle,
    generate_batch_zip,
    generate_qr_code_base64,
    generate_shadowrocket_batch_conf,
    generate_shadowrocket_subscription,
    inject_servers_to_shadowrocket_storage,
    is_valid_wg_key,
    purge_shadowrocket_failed_servers,
    clear_shadowrocket_all_servers,
    get_shadowrocket_storage_stats,
    read_shadowrocket_test_results,
    is_shadowrocket_running,
    ShadowrocketStorage,
)
from dns_resolver import SecureDnsResolver
from vpn_detector import detect_active_vpn, VpnStatus
from scan_cache import (
    DEFAULT_SCAN_CACHE_FILE,
    extract_top_servers,
    load_scan_cache,
    reconstruct_check_results,
    save_scan_cache,
)
DEFAULT_USER_SETTINGS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "user_settings.json")

DEFAULT_FEATURED_COUNTRIES = [
    "Albania",
    "Andorra",
    "Bahamas",
    "Cambodia",
    "Myanmar",
    "Mongolia",
]

COUNTRY_ALIASES: Dict[str, tuple[str, str]] = {
    "andora": ("Andorra", "AD"),
    "burma": ("Myanmar", "MM"),
    "usa": ("United States", "US"),
    "us": ("United States", "US"),
    "united states": ("United States", "US"),
    "uk": ("United Kingdom", "GB"),
    "gb": ("United Kingdom", "GB"),
    "united kingdom": ("United Kingdom", "GB"),
    "uae": ("United Arab Emirates", "AE"),
    "emirates": ("United Arab Emirates", "AE"),
    "united arab emirates": ("United Arab Emirates", "AE"),
    "korea": ("South Korea", "KR"),
    "south korea": ("South Korea", "KR"),
    "czech": ("Czech Republic", "CZ"),
    "macedonia": ("North Macedonia", "MK"),
    "north macedonia": ("North Macedonia", "MK"),
    "deutschland": ("Germany", "DE"),
    "germany": ("Germany", "DE"),
    "switzerland": ("Switzerland", "CH"),
    "turkey": ("Turkey", "TR"),
    "turkiye": ("Turkey", "TR"),
    "albania": ("Albania", "AL"),
    "andorra": ("Andorra", "AD"),
    "bahamas": ("Bahamas", "BS"),
    "cambodia": ("Cambodia", "KH"),
    "myanmar": ("Myanmar", "MM"),
    "mongolia": ("Mongolia", "MN"),
}


class SurfsharkAmneziaApp:
    def __init__(self, page: ft.Page):
        self.page = page

        # Provider State (v5.1 Standalone Surfshark Engine)
        self.active_provider: str = "surfshark"
        self.blueprint: BlueprintData = load_blueprint(DEFAULT_DATA_FILE)
        self.current_scan_cache_file: str = DEFAULT_SCAN_CACHE_FILE

        # Scanning State
        self.is_scanning = False
        self.is_deep_screening = False
        self.scan_results: Dict[str, List[CheckResult]] = {}  # hostname -> list of CheckResult
        self.working_configs: List[dict] = []  # configs ready for batch export

        # Verification & Testing Mode State (v5)
        self.scan_mode: str = ScanMode.SMART  # "smart", "strict_udp", "deep", "permissive"
        self.scan_timeout: float = 2.0
        self.probe_count: int = 3

        # User Settings & Featured Countries (v5)
        self.featured_countries: List[str] = list(DEFAULT_FEATURED_COUNTRIES)
        self._load_user_settings()

        # Set active blueprint and cache for Surfshark
        self.blueprint = load_blueprint(DEFAULT_DATA_FILE)
        self.current_scan_cache_file = DEFAULT_SCAN_CACHE_FILE

        # Load Previous Scan Cache for active provider
        self.last_scan_data: Optional[dict] = load_scan_cache(self.current_scan_cache_file)
        if self.last_scan_data:
            servers_by_hostname = {s.hostname: s for s in self.blueprint.servers}
            self.scan_results = reconstruct_check_results(
                self.last_scan_data.get("scan_results", {}),
                servers_by_hostname,
            )
            self.working_configs = self.last_scan_data.get("working_configs", [])

        # Obfuscation Parameters State
        self.params = AmneziaParams.iran_preset()
        self.current_preset: str = "iran"

        # Active Network & VPN Interface Detection
        self.vpn_status: VpnStatus = detect_active_vpn()

        # Debounce timer for credential saves
        self._save_debounce_timer: Optional[threading.Timer] = None
        self._search_timer: Optional[threading.Timer] = None
        self._expanded_countries: set = set()
        self._last_sr_mtime: float = 0.0
        self._active_prescan_controls: Optional[tuple] = None
        self._is_syncing_sr: bool = False

        # UI Setup
        self._init_page()
        self._build_ui()
        self._refresh_summary_cards()
        self._render_server_list()

        # Start Real-Time Background Monitors (Live VPN status & Shadowrocket watcher)
        self._start_background_monitors()

    def _init_page(self):
        self.page.title = "Surfshark AmneziaWG Studio v5.1"
        self.page.theme_mode = ft.ThemeMode.DARK
        self.page.window.width = 1180
        self.page.window.height = 840
        self.page.window.min_width = 900
        self.page.window.min_height = 650
        self.page.padding = 20
        self.page.theme = ft.Theme(
            color_scheme_seed="#00D09C",  # Surfshark teal/emerald
            visual_density=ft.VisualDensity.COMPACT,
        )

    def _build_ui(self):
        # 1. Compact Header Bar
        has_priv = bool(self.blueprint.user_interface.private_key and len(self.blueprint.user_interface.private_key.strip()) > 20)
        self.badge_privkey = ft.Container(
            bgcolor="#1B5E20" if has_priv else "#7F1D1D",
            border=ft.border.all(1, "#2E7D32" if has_priv else "#B71C1C"),
            border_radius=6,
            padding=ft.padding.symmetric(horizontal=10, vertical=5),
            tooltip="Click to enter or modify client PrivateKey",
            on_click=self._open_credentials_modal,
            content=ft.Row(
                tight=True,
                spacing=5,
                controls=[
                    ft.Icon(ft.icons.KEY_ROUNDED, size=14, color="#A5D6A7" if has_priv else "#FFCDD2"),
                    ft.Text(
                        "PrivateKey: Ready" if has_priv else "⚠️ Key Missing",
                        size=11,
                        color="#A5D6A7" if has_priv else "#FFCDD2",
                        weight=ft.FontWeight.BOLD,
                    ),
                ],
            ),
        )

        is_active = self.vpn_status.is_vpn_active
        self.vpn_chip = ft.Container(
            bgcolor="#7F1D1D" if is_active else "#1B3B2B",
            border=ft.border.all(1, "#B71C1C" if is_active else "#00C853"),
            border_radius=6,
            padding=ft.padding.symmetric(horizontal=10, vertical=5),
            tooltip="VPN connection status. Click to recheck.",
            on_click=self._refresh_vpn_status,
            content=ft.Row(
                tight=True,
                spacing=5,
                controls=[
                    ft.Icon(
                        ft.icons.WARNING_AMBER_ROUNDED if is_active else ft.icons.CHECK_CIRCLE_ROUNDED,
                        size=14,
                        color="#FF8A80" if is_active else "#69F0AE",
                    ),
                    ft.Text(
                        f"VPN Active ({self.vpn_status.interface})" if is_active else "Direct Connection (No VPN)",
                        size=11,
                        color="#FF8A80" if is_active else "#69F0AE",
                        weight=ft.FontWeight.BOLD,
                    ),
                ],
            ),
        )

        is_surf = (True)
        self.lbl_app_title = ft.Text("Surfshark AmneziaWG Studio v5.1", size=17, weight=ft.FontWeight.BOLD, color="#FFFFFF")

        header = ft.Row(
            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
            controls=[
                ft.Row(
                    spacing=10,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                    controls=[
                        ft.Icon(ft.icons.SHIELD_ROUNDED, color="#00D09C", size=26),
                        self.lbl_app_title,
                    ],
                ),
                ft.Row(
                    spacing=8,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                    controls=[
                        self.vpn_chip,
                        self.badge_privkey,
                        ft.IconButton(
                            icon=ft.icons.REFRESH_ROUNDED,
                            tooltip="Refresh VPN Status & Sync Shadowrocket",
                            icon_color="#00E5FF",
                            icon_size=20,
                            on_click=self._force_full_refresh,
                        ),
                        ft.IconButton(
                            icon=ft.icons.SETTINGS_ROUNDED,
                            tooltip="Application Settings & Preferences",
                            icon_color="#00D09C",
                            icon_size=20,
                            on_click=self._open_settings_modal,
                        ),
                        ft.IconButton(
                            icon=ft.icons.HELP_OUTLINE_ROUNDED,
                            tooltip="User Guide & Documentation",
                            icon_color="#90A4AE",
                            icon_size=20,
                            on_click=self._open_help_modal,
                        ),
                    ],
                ),
            ],
        )

        # 2. Compact Combined Metrics & Previous Scan Strip (Saves 200+ pixels!)
        self.lbl_metric_clusters = ft.Text("0", size=12, weight=ft.FontWeight.BOLD, color="#4DD0E1")
        self.lbl_metric_ips = ft.Text("0", size=12, weight=ft.FontWeight.BOLD, color="#BA68C8")
        self.lbl_metric_working = ft.Text("0", size=12, weight=ft.FontWeight.BOLD, color="#69F0AE")
        self.lbl_metric_latency = ft.Text("—", size=12, weight=ft.FontWeight.BOLD, color="#FFD54F")

        # Compatibility mock cards for any external references
        self.card_total_servers = type("dummy", (), {"content": type("c", (), {"content": type("c2", (), {"controls": [type("r", (), {"controls": [None, self.lbl_metric_clusters]})()]})()})()})()
        self.card_discovered_ips = type("dummy", (), {"content": type("c", (), {"content": type("c2", (), {"controls": [type("r", (), {"controls": [None, self.lbl_metric_ips]})()]})()})()})()
        self.card_working_ips = type("dummy", (), {"content": type("c", (), {"content": type("c2", (), {"controls": [type("r", (), {"controls": [None, self.lbl_metric_working]})()]})()})()})()
        self.card_avg_latency = type("dummy", (), {"content": type("c", (), {"content": type("c2", (), {"controls": [type("r", (), {"controls": [None, self.lbl_metric_latency]})()]})()})()})()

        self.prev_scan_card = self._build_prev_scan_card()

        metrics_strip = ft.Container(
            padding=ft.padding.symmetric(horizontal=12, vertical=6),
            bgcolor="#151E27",
            border_radius=6,
            border=ft.border.all(1, "#263238"),
            content=ft.Row(
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                controls=[
                    ft.Row(
                        spacing=18,
                        controls=[
                            ft.Row(spacing=5, tight=True, controls=[ft.Icon(ft.icons.DNS_ROUNDED, size=15, color="#0288D1"), ft.Text("Clusters:", size=11, color="#90A4AE"), self.lbl_metric_clusters]),
                            ft.Row(spacing=5, tight=True, controls=[ft.Icon(ft.icons.HUB_ROUNDED, size=15, color="#7B1FA2"), ft.Text("IPs:", size=11, color="#90A4AE"), self.lbl_metric_ips]),
                            ft.Row(spacing=5, tight=True, controls=[ft.Icon(ft.icons.CHECK_CIRCLE_ROUNDED, size=15, color="#00C853"), ft.Text("Working:", size=11, color="#90A4AE"), self.lbl_metric_working]),
                            ft.Row(spacing=5, tight=True, controls=[ft.Icon(ft.icons.SPEED_ROUNDED, size=15, color="#FFB300"), ft.Text("Avg Latency:", size=11, color="#90A4AE"), self.lbl_metric_latency]),
                        ],
                    ),
                    ft.Text("AmneziaWG Anti-DPI Protocol", size=11, color="#546E7A", italic=True),
                ],
            ),
        )

        # 3. Hidden/Modal Credential Fields (instantiated in memory so all logic continues to work)
        self.txt_client_privkey = ft.TextField(
            value=self.blueprint.user_interface.private_key,
            password=True,
            can_reveal_password=True,
            on_change=self._on_dashboard_creds_changed,
        )
        self.txt_client_addr = ft.TextField(
            value=self.blueprint.user_interface.address or "10.14.0.2/16",
            on_change=self._on_dashboard_creds_changed,
        )
        self.txt_client_dns = ft.TextField(
            value=self.blueprint.user_interface.dns or "162.252.172.57, 149.154.159.92",
            on_change=self._on_dashboard_creds_changed,
        )
        self.lbl_derived_pubkey = ft.Text(size=11, color="#90A4AE", selectable=True)
        self.credentials_card = ft.Container(visible=False)

        # 4. Obfuscation Parameters (instantiated in memory for _get_current_params)
        self.txt_jc = ft.TextField(label="Jc (Junk Packets)", value=str(self.params.jc), width=140, text_size=12)
        self.txt_jmin = ft.TextField(label="Jmin (bytes)", value=str(self.params.jmin), width=120, text_size=12)
        self.txt_jmax = ft.TextField(label="Jmax (bytes)", value=str(self.params.jmax), width=120, text_size=12)
        self.txt_s1 = ft.TextField(label="S1 (Padding)", value=str(self.params.s1), width=110, text_size=12)
        self.txt_s2 = ft.TextField(label="S2 (Padding)", value=str(self.params.s2), width=110, text_size=12)
        self.txt_h1 = ft.TextField(label="H1", value=str(self.params.h1), width=90, text_size=12)
        self.txt_h2 = ft.TextField(label="H2", value=str(self.params.h2), width=90, text_size=12)
        self.txt_h3 = ft.TextField(label="H3", value=str(self.params.h3), width=90, text_size=12)
        self.txt_h4 = ft.TextField(label="H4", value=str(self.params.h4), width=90, text_size=12)

        # Obfuscation preset selection and Amnezia headers are in Settings -> Obfuscation & Presets

        # 5. Compact Action Toolbar (All primary buttons on one sleek row with wrapping)
        self.btn_scan = ft.ElevatedButton(
            text="Scan & Verify Servers",
            icon=ft.icons.RADAR_ROUNDED,
            style=ft.ButtonStyle(bgcolor="#00C853", color="#FFFFFF"),
            on_click=self._prompt_pre_scan_vpn_check,
            height=36,
        )

        self.dd_scan_mode = ft.Dropdown(
            width=215,
            text_size=11,
            dense=True,
            value=self.scan_mode,
            tooltip="Server testing mode (Smart Anti-DPI recommended)",
            options=[
                ft.dropdown.Option("smart", "🧠 Smart Anti-DPI (Recommended)"),
                ft.dropdown.Option("permissive", "⚡ Permissive Mode"),
            ],
            on_change=self._on_scan_mode_change,
        )

        
        self.btn_export_shadowrocket = ft.ElevatedButton(
            text="🚀 Export to Shadowrocket",
            icon=ft.icons.ROCKET_LAUNCH_ROUNDED,
            style=ft.ButtonStyle(bgcolor="#E65100", color="#FFFFFF"),
            on_click=self._export_to_shadowrocket,
            tooltip="Export all servers with Iran Balanced settings to Shadowrocket and run URL test",
            height=36,
        )

        self.btn_sync_shadowrocket = ft.ElevatedButton(
            text="🔄 Sync from Shadowrocket",
            icon=ft.icons.SYNC_ROUNDED,
            style=ft.ButtonStyle(bgcolor="#00897B", color="#FFFFFF"),
            on_click=self._sync_results_from_shadowrocket,
            tooltip="Sync verified test results and live pings from Shadowrocket",
            height=36,
        )

        self.btn_manage_shadowrocket = ft.ElevatedButton(
            text="⚙️ Shadowrocket Manager",
            icon=ft.icons.CLEANING_SERVICES_ROUNDED,
            style=ft.ButtonStyle(bgcolor="#37474F", color="#FFFFFF"),
            on_click=self._open_shadowrocket_manager_dialog,
            tooltip="Manage Shadowrocket servers, purge unreachable endpoints, or clear local storage",
            height=36,
        )

        
        
        self.btn_fetch_keys = ft.OutlinedButton(
            text="🔑 Update Keys (API)",
            icon=ft.icons.CLOUD_DOWNLOAD_ROUNDED,
            on_click=self._fetch_real_public_keys,
            tooltip="Fetch official public keys directly from Surfshark API",
            style=ft.ButtonStyle(color="#FFB300"),
            height=36,
            visible=(True),
        )

        self.btn_export_all = ft.ElevatedButton(
            text="Export ZIP",
            icon=ft.icons.FOLDER_ZIP_ROUNDED,
            style=ft.ButtonStyle(bgcolor="#1E88E5", color="#FFFFFF"),
            on_click=self._export_batch_zip,
            tooltip="Export all verified working servers to a categorized ZIP archive",
            height=36,
        )

        self.btn_harvest = ft.ElevatedButton(
            text="Login Browser",
            icon=ft.icons.OPEN_IN_BROWSER_ROUNDED,
            visible=False,
            on_click=self._start_browser_harvest,
        )



        self.menu_item_harvest = ft.PopupMenuItem(
            text="Surfshark Browser Harvest (Login)",
            icon=ft.icons.OPEN_IN_BROWSER_ROUNDED,
            on_click=self._start_browser_harvest,
        )

        btn_more_menu = ft.PopupMenuButton(
            icon=ft.icons.MORE_HORIZ_ROUNDED,
            tooltip="Preferences",
            items=[
                ft.PopupMenuItem(
                    text="⚙️ Shadowrocket Local Server Manager...",
                    icon=ft.icons.SETTINGS_APPLICATIONS_ROUNDED,
                    on_click=self._open_shadowrocket_manager_dialog,
                ),
                ft.PopupMenuItem(
                    text="🧹 Purge Failed & Domain Servers in Shadowrocket",
                    icon=ft.icons.CLEANING_SERVICES_ROUNDED,
                    on_click=self._clean_shadowrocket_failed_servers,
                ),
                ft.PopupMenuItem(
                    text="🗑️ Clear All Local Servers in Shadowrocket",
                    icon=ft.icons.DELETE_FOREVER_ROUNDED,
                    on_click=self._confirm_clear_all_shadowrocket_servers,
                ),
                ft.PopupMenuItem(
                    text="🔄 Sync Results",
                    icon=ft.icons.SYNC_ROUNDED,
                    on_click=self._sync_results_from_shadowrocket,
                ),
                ft.PopupMenuItem(
                    text="🚀 Export to Shadowrocket (Iran Balanced)",
                    icon=ft.icons.ROCKET_LAUNCH_ROUNDED,
                    on_click=self._export_to_shadowrocket,
                ),
                ft.PopupMenuItem(
                    text="📋 Copy Subscription URL",
                    icon=ft.icons.COPY_ALL_ROUNDED,
                    on_click=self._copy_shadowrocket_subscription,
                ),
                ft.PopupMenuItem(
                    text="Open Shadowrocket Configs Folder",
                    icon=ft.icons.FOLDER_ROUNDED,
                    on_click=self._open_shadowrocket_folder,
                ),
                ft.PopupMenuItem(
                    text="Settings & Configuration",
                    icon=ft.icons.SETTINGS_ROUNDED,
                    on_click=self._open_settings_modal,
                ),
                self.menu_item_harvest,
                ft.PopupMenuItem(
                    text="Import .conf or JSON",
                    icon=ft.icons.FILE_UPLOAD_ROUNDED,
                    on_click=self._open_import_dialog,
                ),
            ],
        )

        action_toolbar = ft.Row(
            spacing=8,
            wrap=True,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
            controls=[
                self.btn_scan,
                self.btn_export_shadowrocket,
                self.btn_sync_shadowrocket,
                self.btn_manage_shadowrocket,
                self.btn_export_all,
                self.btn_fetch_keys,
                btn_more_menu,
            ],
        )

        # 6. Live Status and Search / Filter Bar with Continent Selection
        self.progress_bar = ft.ProgressBar(value=0.0, visible=False, color="#00C853", bgcolor="#263238", height=3)
        self.lbl_status = ft.Text("Ready. Click 'Scan & Verify Servers' to start testing.", size=11, color="#90A4AE")

        self.search_field = ft.TextField(
            hint_text="Search servers, cities, countries, or IPs...",
            height=38,
            text_size=12,
            on_change=self._filter_servers,
            expand=True,
            dense=True,
        )

        self.dd_continent = ft.Dropdown(
            value="all",
            width=175,
            text_size=11,
            dense=True,
            tooltip="Filter by continent / region",
            options=[
                ft.dropdown.Option("all", "🌍 All Continents"),
                ft.dropdown.Option("Europe", "🇪🇺 Europe"),
                ft.dropdown.Option("Asia", "🌏 Asia"),
                ft.dropdown.Option("Americas", "🌎 Americas"),
                ft.dropdown.Option("Africa", "🌍 Africa"),
                ft.dropdown.Option("Oceania", "🌊 Oceania"),
            ],
            on_change=self._filter_servers,
        )

        self.filter_working_only = ft.Switch(
            label="Show working only",
            value=False,
            on_change=self._filter_servers,
        )

        search_and_status_row = ft.Row(
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=10,
            controls=[
                self.search_field,
                self.dd_continent,
                self.filter_working_only,
                self.lbl_status,
            ],
        )

        # 7. Expanded Server & Country Tree List (Takes 75%+ of the vertical space!)
        self.server_tree_view = ft.Column(
            scroll=ft.ScrollMode.AUTO,
            expand=True,
            spacing=4,
        )

        # Main Layout Container
        self.page.add(
            ft.Column(
                expand=True,
                spacing=8,
                controls=[
                    header,
                    metrics_strip,
                    self.prev_scan_card,
                    action_toolbar,
                    search_and_status_row,
                    self.progress_bar,
                    ft.Container(
                        content=self.server_tree_view,
                        expand=True,
                        border=ft.border.all(1, "#37474F"),
                        border_radius=8,
                        padding=6,
                    ),
                ],
            )
        )

    def _create_metric_card(self, title: str, value: str, icon: str, color: str) -> ft.Card:
        return ft.Card(
            elevation=2,
            expand=True,
            content=ft.Container(
                padding=14,
                border_radius=8,
                bgcolor="#1E242B",
                content=ft.Row(
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                    controls=[
                        ft.Column(
                            spacing=2,
                            controls=[
                                ft.Text(title, size=12, color="#9E9E9E", weight=ft.FontWeight.W_500),
                                ft.Text(value, size=20, weight=ft.FontWeight.BOLD, color="#FFFFFF"),
                            ],
                        ),
                        ft.Icon(icon, size=28, color=color),
                    ],
                ),
            ),
        )

    def _refresh_summary_cards(self):
        try:
            total_clusters = len(self.blueprint.servers)
            all_discovered = sum(len(s.resolved_ips) for s in self.blueprint.servers)

            # Working IPs
            working_count = 0
            latencies = []
            for res_list in self.scan_results.values():
                for r in res_list:
                    if r.is_reachable:
                        working_count += 1
                        if r.latency_ms < 9000:
                            latencies.append(r.latency_ms)

            avg_lat_str = f"{int(sum(latencies) / len(latencies))} ms" if latencies else "—"

            # Update controls
            if hasattr(self, "lbl_metric_clusters") and self.lbl_metric_clusters:
                self.lbl_metric_clusters.value = str(total_clusters)
            if hasattr(self, "lbl_metric_ips") and self.lbl_metric_ips:
                self.lbl_metric_ips.value = str(all_discovered)
            if hasattr(self, "lbl_metric_working") and self.lbl_metric_working:
                self.lbl_metric_working.value = str(working_count)
            if hasattr(self, "lbl_metric_latency") and self.lbl_metric_latency:
                self.lbl_metric_latency.value = avg_lat_str
            if hasattr(self, "card_total_servers") and self.card_total_servers:
                self.card_total_servers.content.content.controls[0].controls[1].value = str(total_clusters)
            if hasattr(self, "card_discovered_ips") and self.card_discovered_ips:
                self.card_discovered_ips.content.content.controls[0].controls[1].value = str(all_discovered)
            if hasattr(self, "card_working_ips") and self.card_working_ips:
                self.card_working_ips.content.content.controls[0].controls[1].value = str(working_count)
            if hasattr(self, "card_avg_latency") and self.card_avg_latency:
                self.card_avg_latency.content.content.controls[0].controls[1].value = avg_lat_str
            if hasattr(self, "page") and self.page:
                self.page.update()
        except Exception as ex:
            logger.debug(f"Error refreshing summary cards: {ex}")

    def _on_preset_change(self, e):
        choice = e.control.value
        if choice == "iran":
            self.params = AmneziaParams.iran_preset()
        elif choice == "aggressive":
            self.params = AmneziaParams.aggressive_preset()
        elif choice == "vanilla":
            self.params = AmneziaParams.standard_wireguard()

        self.txt_jc.value = str(self.params.jc)
        self.txt_jmin.value = str(self.params.jmin)
        self.txt_jmax.value = str(self.params.jmax)
        self.txt_s1.value = str(self.params.s1)
        self.txt_s2.value = str(self.params.s2)
        self.txt_h1.value = str(self.params.h1)
        self.txt_h2.value = str(self.params.h2)
        self.txt_h3.value = str(self.params.h3)
        self.txt_h4.value = str(self.params.h4)
        self.page.update()

    def _get_current_params(self) -> AmneziaParams:
        try:
            return AmneziaParams(
                jc=int(self.txt_jc.value or 4),
                jmin=int(self.txt_jmin.value or 50),
                jmax=int(self.txt_jmax.value or 1000),
                s1=int(self.txt_s1.value or 0),
                s2=int(self.txt_s2.value or 0),
                h1=int(self.txt_h1.value or 1),
                h2=int(self.txt_h2.value or 2),
                h3=int(self.txt_h3.value or 3),
                h4=int(self.txt_h4.value or 4),
            )
        except Exception:
            return AmneziaParams.iran_preset()

    def _render_server_list(self, filter_query: str = "", only_working: bool = False, continent_filter: str = "all"):
        self.server_tree_view.controls.clear()
        query = filter_query.strip().lower()
        selected_continent = continent_filter or (self.dd_continent.value if hasattr(self, "dd_continent") and self.dd_continent.value else "all")

        # Group servers by Continent -> Country -> List of Servers
        grouped: Dict[str, Dict[str, List[ServerMetadata]]] = {}
        for s in self.blueprint.servers:
            cont = s.continent or "Global"
            cntry = s.country or "Other"
            if selected_continent != "all":
                if selected_continent == "Americas":
                    if cont not in ("Americas", "North America", "South America"):
                        continue
                elif cont != selected_continent:
                    continue
            if cont not in grouped:
                grouped[cont] = {}
            if cntry not in grouped[cont]:
                grouped[cont][cntry] = []
            grouped[cont][cntry].append(s)

        total_matching_clusters = 0

        for continent, countries in sorted(grouped.items()):
            continent_tiles = []

            for country, servers in sorted(countries.items()):
                country_matching_servers = []

                for server in servers:
                    # Check if matches query
                    server_results = self.scan_results.get(server.hostname, [])
                    working_ips = [r for r in server_results if r.is_reachable]

                    if only_working and not working_ips:
                        continue

                    matches = (
                        not query
                        or query in server.country.lower()
                        or query in server.city.lower()
                        or query in server.hostname.lower()
                        or (getattr(server, "server_name", "") and query in server.server_name.lower())
                        or any(query in ip.lower() for ip in server.resolved_ips)
                    )

                    if not matches:
                        continue

                    country_matching_servers.append((server, server_results))

                if country_matching_servers:
                    total_matching_clusters += len(country_matching_servers)
                    # Count total IPs and working IPs in this country
                    country_total_ips = sum(len(s.resolved_ips) for s, _ in country_matching_servers)
                    country_working_ips = sum(
                        len([r for r in res if r.is_reachable])
                        for _, res in country_matching_servers
                    )
                    badge_color = "#A5D6A7" if country_working_ips > 0 else "#90A4AE"
                    badge_bg = "#1B5E20" if country_working_ips > 0 else "#263238"

                    matching_svrs_only = [s for s, _ in country_matching_servers]
                    country_title_row = ft.Row(
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        controls=[
                            ft.Row(
                                spacing=6,
                                controls=[
                                    ft.Text(f"{country} ({len(country_matching_servers)})", weight=ft.FontWeight.W_500, size=13),
                                    ft.Container(
                                        padding=ft.padding.symmetric(horizontal=6, vertical=1),
                                        bgcolor=badge_bg,
                                        border_radius=4,
                                        content=ft.Text(f"{country_working_ips}/{country_total_ips} Active", size=10, color=badge_color, weight=ft.FontWeight.BOLD),
                                    ) if country_total_ips > 0 else ft.Container(),
                                ],
                            ),
                            ft.Row(
                                spacing=2,
                                controls=[
                                    ft.IconButton(
                                        icon=ft.icons.FLASH_ON_ROUNDED,
                                        icon_size=17,
                                        icon_color="#00D09C",
                                        tooltip=f"Test all servers in {country} ({self.scan_mode} mode)",
                                        on_click=lambda e, c=country, svrs=matching_svrs_only: self._test_country(c, svrs, mode=self.scan_mode),
                                    ),
                                    ft.PopupMenuButton(
                                        icon=ft.icons.MORE_VERT_ROUNDED,
                                        icon_size=17,
                                        icon_color="#80CBC4",
                                        tooltip=f"Select test mode for {country}",
                                        items=[
                                            ft.PopupMenuItem(
                                                text="🧠 Smart Anti-DPI Test (Recommended)",
                                                icon=ft.icons.PSYCHOLOGY_ROUNDED,
                                                on_click=lambda e, c=country, svrs=matching_svrs_only: self._test_country(c, svrs, mode=ScanMode.SMART),
                                            ),
                                            ft.PopupMenuItem(
                                                text="⚡ Permissive Mode (Ping Fallback)",
                                                icon=ft.icons.SPEED_ROUNDED,
                                                on_click=lambda e, c=country, svrs=matching_svrs_only: self._test_country(c, svrs, mode=ScanMode.PERMISSIVE),
                                            ),
                                            ft.PopupMenuItem(
                                                text="🚀 Export to Shadowrocket",
                                                icon=ft.icons.ROCKET_LAUNCH_ROUNDED,
                                                on_click=lambda e, c=country, svrs=matching_svrs_only: self._export_country_to_shadowrocket(c, svrs),
                                            ),
                                        ],
                                    ),
                                ],
                            ),
                        ],
                    )

                    # Lazy Rendering: only eagerly build children if query active or country was explicitly expanded
                    is_initially_expanded = bool(query) or (country in self._expanded_countries)
                    country_tiles = []
                    if is_initially_expanded:
                        country_tiles = [
                            self._build_cluster_tile(srv, res)
                            for srv, res in country_matching_servers
                        ]

                    c_expansion = ft.ExpansionTile(
                        title=country_title_row,
                        leading=ft.Icon(ft.icons.LOCATION_ON_ROUNDED, color="#26A69A", size=18),
                        initially_expanded=is_initially_expanded,
                        controls=country_tiles,
                        on_change=lambda e, c=country, svrs=country_matching_servers: self._on_country_expand(e, c, svrs),
                    )
                    continent_tiles.append(c_expansion)

            if continent_tiles:
                continent_all_servers = [s for sub in countries.values() for s in sub]
                cont_title_row = ft.Row(
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                    controls=[
                        ft.Text(f"{continent} ({len(continent_all_servers)} servers, {len(countries)} countries)", weight=ft.FontWeight.BOLD, size=13, color="#00D09C"),
                        ft.Row(
                            spacing=2,
                            controls=[
                                ft.IconButton(
                                    icon=ft.icons.FLASH_ON_ROUNDED,
                                    icon_size=17,
                                    icon_color="#00D09C",
                                    tooltip=f"Test all servers in {continent}",
                                    on_click=lambda e, cont=continent, svrs=continent_all_servers: self._test_country(f"Continent {cont}", svrs, mode=self.scan_mode),
                                ),
                                ft.IconButton(
                                    icon=ft.icons.ROCKET_LAUNCH_ROUNDED,
                                    icon_size=17,
                                    icon_color="#FFB300",
                                    tooltip=f"Export all servers in {continent} to Shadowrocket",
                                    on_click=lambda e, cont=continent, svrs=continent_all_servers: self._export_country_to_shadowrocket(f"Continent {cont}", svrs),
                                ),
                            ],
                        ),
                    ],
                )
                cont_expansion = ft.ExpansionTile(
                    leading=ft.Icon(ft.icons.PUBLIC_ROUNDED, color="#00D09C", size=20),
                    title=cont_title_row,
                    initially_expanded=True,
                    controls=continent_tiles,
                )
                self.server_tree_view.controls.append(cont_expansion)

        if total_matching_clusters == 0:
            self.server_tree_view.controls.append(
                ft.Container(
                    alignment=ft.alignment.center,
                    padding=40,
                    content=ft.Column(
                        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                        controls=[
                            ft.Icon(ft.icons.SEARCH_OFF_ROUNDED, size=48, color="#546E7A"),
                            ft.Text("No servers match your current filter.", color="#90A4AE", size=14),
                        ],
                    ),
                )
            )

        self.page.update()

    def _on_country_expand(self, e, country: str, servers_with_res: list):
        is_exp = (e.data is True) or (str(e.data).lower() == "true")
        if is_exp:
            self._expanded_countries.add(country)
            if not e.control.controls:
                e.control.controls = [
                    self._build_cluster_tile(srv, res)
                    for srv, res in servers_with_res
                ]
                try:
                    e.control.update()
                except Exception:
                    try:
                        self.page.update()
                    except Exception:
                        pass
        else:
            self._expanded_countries.discard(country)

    def _copy_text_to_clipboard(self, text: str, toast_msg: str):
        self.page.set_clipboard(text)
        self._show_toast(toast_msg)

    def _build_cluster_tile(self, server: ServerMetadata, results: List[CheckResult]) -> ft.Container:
        ip_rows = []

        # ── ORDER OF DISPLAY ──────────────────────────────────────────────────
        # 1. Reachable IPs (sorted by latency, best first) ← most useful in Iran
        # 2. Unreachable IPs (scanned but failed)
        # 3. Unscanned resolved IPs
        # 4. Domain / Subdomain endpoint LAST (DNS may be poisoned in Iran)
        # ─────────────────────────────────────────────────────────────────────

        if results:
            reachable = sorted([r for r in results if r.is_reachable], key=lambda r: r.latency_ms)
            unreachable = [r for r in results if not r.is_reachable]

            rank_icons = ["🥇", "🥈", "🥉"]

            for idx, r in enumerate(reachable):
                latency_color = "#00C853" if r.latency_ms < 150 else ("#FFB300" if r.latency_ms < 280 else "#E53935")
                rank = rank_icons[idx] if idx < 3 else f"#{idx+1}"
                lat_text = f"{int(r.latency_ms)} ms"

                if r.deep_verified and r.packet_loss == 0.0:
                    status_label = f"🔬 Deep (±{int(r.jitter_ms)}ms)"
                    badge_bg = "#004D40"
                    badge_fg = "#80DEEA"
                elif r.status == "handshake_ok":
                    status_label = "✓ Handshake OK"
                    badge_bg = "#1B5E20"
                    badge_fg = "#A5D6A7"
                elif r.status == "responsive":
                    status_label = "✓ UDP Open"
                    badge_bg = "#1B5E20"
                    badge_fg = "#81C784"
                elif r.status == "ping_alive":
                    status_label = "⚠️ Ping Only"
                    badge_bg = "#E65100"
                    badge_fg = "#FFE082"
                else:
                    status_label = "✓ Verified"
                    badge_bg = "#1B5E20"
                    badge_fg = "#A5D6A7"

                row = ft.Container(
                    padding=ft.padding.symmetric(horizontal=12, vertical=6),
                    bgcolor="#1A2E1A",
                    border=ft.border.all(1, "#2E7D32"),
                    border_radius=6,
                    margin=ft.margin.only(left=24, right=10, bottom=4),
                    content=ft.Row(
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        controls=[
                            ft.Row(
                                spacing=8,
                                controls=[
                                    ft.Text(rank, size=15),
                                    ft.Icon(ft.icons.CHECK_CIRCLE, color="#00C853", size=16),
                                    ft.Text(f"{r.ip}:{r.port}", font_family="monospace", size=12, weight=ft.FontWeight.W_500, color="#E8F5E9"),
                                    ft.Container(
                                        padding=ft.padding.symmetric(horizontal=6, vertical=2),
                                        border_radius=4,
                                        bgcolor="#263238",
                                        content=ft.Text(lat_text, size=11, color=latency_color, weight=ft.FontWeight.BOLD),
                                    ),
                                    ft.Container(
                                        padding=ft.padding.symmetric(horizontal=5, vertical=2),
                                        border_radius=4,
                                        bgcolor=badge_bg,
                                        content=ft.Text(status_label, size=10, color=badge_fg, weight=ft.FontWeight.BOLD),
                                    ),
                                ],
                            ),
                            ft.Row(
                                spacing=3,
                                controls=[
                                    ft.IconButton(
                                        icon=ft.icons.REFRESH_ROUNDED,
                                        tooltip=f"Re-test this IP ({r.ip})",
                                        icon_size=16,
                                        icon_color="#81C784",
                                        on_click=lambda e, ip=r.ip, s=server: self._test_single_ip(s, ip, mode=self.scan_mode),
                                    ),
                                    ft.IconButton(
                                        icon=ft.icons.QR_CODE_ROUNDED,
                                        tooltip=f"QR Code — {r.ip} ({int(r.latency_ms)}ms)",
                                        icon_size=18,
                                        icon_color="#00D09C",
                                        on_click=lambda e, ip=r.ip, s=server, lat=r.latency_ms: self._show_qr_modal(s, ip, lat),
                                    ),
                                    ft.IconButton(
                                        icon=ft.icons.CONTENT_COPY_ROUNDED,
                                        tooltip="Copy AmneziaWG Config",
                                        icon_size=18,
                                        icon_color="#64B5F6",
                                        on_click=lambda e, ip=r.ip, s=server: self._copy_config_to_clipboard(s, ip),
                                    ),
                                    ft.IconButton(
                                        icon=ft.icons.ROCKET_LAUNCH_ROUNDED,
                                        tooltip=f"Copy & Test in Shadowrocket ({r.ip})",
                                        icon_size=18,
                                        icon_color="#FFA726",
                                        on_click=lambda e, ip=r.ip, s=server, lat=r.latency_ms: self._open_single_shadowrocket(s, ip, lat),
                                    ),
                                ],
                            ),
                        ],
                    ),
                )
                ip_rows.append(row)

            for r in unreachable:
                if r.status == "ping_only_udp_blocked":
                    status_widget = ft.Container(
                        padding=ft.padding.symmetric(horizontal=6, vertical=2),
                        border_radius=4,
                        bgcolor="#3E2723",
                        border=ft.border.all(1, "#FF8F00"),
                        tooltip="Server responds to ping, but WireGuard UDP port 51820 is blocked by DPI filtering.",
                        content=ft.Text(f"⚠️ Ping OK ({int(r.latency_ms)}ms) | UDP Blocked", size=10, color="#FFD54F", weight=ft.FontWeight.BOLD),
                    )
                    icon_ctrl = ft.Icon(ft.icons.WARNING_AMBER_ROUNDED, color="#FFB300", size=15)
                    ip_color = "#B0BEC5"
                else:
                    status_widget = ft.Text("Blocked / Timed Out", size=10, color="#616161", italic=True)
                    icon_ctrl = ft.Icon(ft.icons.CANCEL, color="#424242", size=15)
                    ip_color = "#616161"

                row = ft.Container(
                    padding=ft.padding.symmetric(horizontal=12, vertical=5),
                    bgcolor="#1C1C1C",
                    border_radius=6,
                    margin=ft.margin.only(left=24, right=10, bottom=4),
                    content=ft.Row(
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        controls=[
                            ft.Row(
                                spacing=8,
                                controls=[
                                    icon_ctrl,
                                    ft.Text(f"{r.ip}:{r.port}", font_family="monospace", size=11, color=ip_color),
                                    status_widget,
                                ],
                            ),
                            ft.Row(
                                spacing=2,
                                controls=[
                                    ft.IconButton(
                                        icon=ft.icons.REFRESH_ROUNDED,
                                        tooltip=f"Re-test this IP ({r.ip})",
                                        icon_size=15,
                                        icon_color="#FFB300",
                                        on_click=lambda e, ip=r.ip, s=server: self._test_single_ip(s, ip, mode=self.scan_mode),
                                    ),
                                    ft.IconButton(
                                        icon=ft.icons.QR_CODE_ROUNDED,
                                        tooltip="View Config (IP may be blocked)",
                                        icon_size=16,
                                        icon_color="#546E7A",
                                        on_click=lambda e, ip=r.ip, s=server: self._show_qr_modal(s, ip, None),
                                    ),
                                ],
                            ),
                        ],
                    ),
                )
                ip_rows.append(row)


        elif server.resolved_ips:
            # IPs resolved by DoH but not yet UDP-scanned
            for ip in server.resolved_ips:
                row = ft.Container(
                    padding=ft.padding.symmetric(horizontal=12, vertical=6),
                    bgcolor="#212930",
                    border_radius=6,
                    margin=ft.margin.only(left=24, right=10, bottom=4),
                    content=ft.Row(
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        controls=[
                            ft.Row(
                                spacing=8,
                                controls=[
                                    ft.Icon(ft.icons.RADIO_BUTTON_UNCHECKED, color="#90A4AE", size=16),
                                    ft.Text(f"{ip}:{server.port}", font_family="monospace", size=12),
                                    ft.Text("(Not tested yet)", size=11, color="#78909C"),
                                ],
                            ),
                            ft.Row(
                                spacing=2,
                                controls=[
                                    ft.IconButton(
                                        icon=ft.icons.PLAY_ARROW_ROUNDED,
                                        tooltip=f"Test this IP ({ip})",
                                        icon_size=16,
                                        icon_color="#00D09C",
                                        on_click=lambda e, ip=ip, s=server: self._test_single_ip(s, ip, mode=self.scan_mode),
                                    ),
                                    ft.IconButton(
                                        icon=ft.icons.QR_CODE_ROUNDED,
                                        tooltip="View Config & QR Code",
                                        icon_size=18,
                                        icon_color="#00D09C",
                                        on_click=lambda e, ip=ip, s=server: self._show_qr_modal(s, ip, None),
                                    ),
                                ],
                            ),
                        ],
                    ),
                )
                ip_rows.append(row)
        else:
            ip_rows.append(
                ft.Container(
                    padding=ft.padding.only(left=28, top=4, bottom=4),
                    content=ft.Text(f"Hostname: {server.hostname} (Unresolved — run scan first)", size=12, color="#78909C", italic=True),
                )
            )

        # Domain / Subdomain endpoint — shown LAST with a note about DNS poisoning
        # In Iran, the subdomain DNS is typically poisoned → domain endpoint fails.
        # Raw IPs (above) are what actually work inside Iran.
        domain_row = ft.Container(
            padding=ft.padding.symmetric(horizontal=12, vertical=6),
            bgcolor="#161E2A",
            border=ft.border.all(1, "#37474F"),
            border_radius=6,
            margin=ft.margin.only(left=24, right=10, bottom=4, top=2),
            content=ft.Row(
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                controls=[
                    ft.Row(
                        spacing=8,
                        controls=[
                            ft.Icon(ft.icons.LANGUAGE_ROUNDED, color="#546E7A", size=16),
                            ft.Text(f"{server.hostname}:{server.port}", font_family="monospace", size=11, color="#90A4AE"),
                            ft.Container(
                                tooltip="In restricted networks (Iran), this domain's DNS is usually poisoned and fails.\nUse verified IP endpoints above instead.",
                                padding=ft.padding.symmetric(horizontal=5, vertical=2),
                                border_radius=4,
                                bgcolor="#263238",
                                content=ft.Row(
                                    spacing=4,
                                    controls=[
                                        ft.Icon(ft.icons.INFO_OUTLINE_ROUNDED, size=11, color="#78909C"),
                                        ft.Text("Domain (DNS may be poisoned)", size=10, color="#607D8B"),
                                    ],
                                ),
                            ),
                        ],
                    ),
                    ft.Row(
                        spacing=4,
                        controls=[
                            ft.IconButton(
                                icon=ft.icons.COPY_ALL_ROUNDED,
                                tooltip=f"Copy subdomain address",
                                icon_size=16,
                                icon_color="#546E7A",
                                on_click=lambda e, h=server.hostname: self._copy_text_to_clipboard(h, f"Subdomain copied: {h}"),
                            ),
                            ft.IconButton(
                                icon=ft.icons.QR_CODE_ROUNDED,
                                tooltip="View config with domain endpoint",
                                icon_size=16,
                                icon_color="#546E7A",
                                on_click=lambda e, s=server: self._show_qr_modal(s, s.hostname, None),
                            ),
                        ],
                    ),
                ],
            ),
        )
        ip_rows.append(domain_row)

        # Build the key verification status badge for this server
        key_is_fake = is_placeholder_key(server.public_key)
        key_badge_controls = []
        if key_is_fake:
            key_badge_controls.append(
                ft.Container(
                    tooltip="Server public key is unverified (Placeholder). Click '🔑 Update Keys (API)' to fetch official keys.",
                    padding=ft.padding.symmetric(horizontal=6, vertical=2),
                    border_radius=4,
                    bgcolor="#5D4037",
                    border=ft.border.all(1, "#FFB300"),
                    content=ft.Row(
                        spacing=4,
                        controls=[
                            ft.Icon(ft.icons.WARNING_AMBER_ROUNDED, size=12, color="#FFB300"),
                            ft.Text("Unverified Key", size=10, color="#FFB300", weight=ft.FontWeight.BOLD),
                        ],
                    ),
                )
            )

        flag = country_code_to_flag(server.country_code)

        return ft.Container(
            padding=ft.padding.symmetric(horizontal=10, vertical=4),
            content=ft.Column(
                spacing=2,
                controls=[
                    ft.Row(
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        controls=[
                            ft.Row(
                                spacing=6,
                                controls=[
                                    ft.Text(flag, size=18),
                                    ft.Text(f"{server.city}, {server.country}", size=13, weight=ft.FontWeight.W_500),
                                    ft.Text(f"({server.hostname})", size=11, color="#78909C"),
                                ] + key_badge_controls,
                            ),
                            ft.Row(
                                spacing=3,
                                controls=[
                                    ft.Text(f"{len(server.resolved_ips)} IPs", size=11, color="#9E9E9E"),
                                    ft.IconButton(
                                        icon=ft.icons.FLASH_ON_ROUNDED,
                                        icon_size=16,
                                        icon_color="#00E5FF",
                                        tooltip=f"Test this cluster ({server.hostname}) with {self.scan_mode} mode",
                                        on_click=lambda e, s=server: self._test_cluster(s, mode=self.scan_mode),
                                    ),
                                    ft.PopupMenuButton(
                                        icon=ft.icons.MORE_VERT_ROUNDED,
                                        icon_size=16,
                                        icon_color="#90A4AE",
                                        tooltip=f"Testing options for cluster {server.city}",
                                        items=[
                                            ft.PopupMenuItem(
                                                text="🧠 Smart Anti-DPI (Recommended)",
                                                icon=ft.icons.PSYCHOLOGY_ROUNDED,
                                                on_click=lambda e, s=server: self._test_cluster(s, mode=ScanMode.SMART),
                                            ),
                                            ft.PopupMenuItem(
                                                text="⚡ Permissive Mode (Ping Fallback)",
                                                icon=ft.icons.SPEED_ROUNDED,
                                                on_click=lambda e, s=server: self._test_cluster(s, mode=ScanMode.PERMISSIVE),
                                            ),
                                            ft.PopupMenuItem(
                                                text="🚀 Export to Shadowrocket",
                                                icon=ft.icons.ROCKET_LAUNCH_ROUNDED,
                                                on_click=lambda e, s=server: self._export_country_to_shadowrocket(s.country, [s]),
                                            ),
                                        ],
                                    ),
                                ],
                            ),
                        ],
                    ),
                    ft.Column(controls=ip_rows, spacing=2),
                ],
            ),
        )


    def _filter_servers(self, e):
        # Debounce text search by 300ms to avoid freezing on keystrokes
        if hasattr(self, "_search_timer") and self._search_timer:
            try:
                self._search_timer.cancel()
            except Exception:
                pass
        self._search_timer = threading.Timer(0.3, self._do_filter_servers)
        self._search_timer.daemon = True
        self._search_timer.start()

    def _do_filter_servers(self):
        query = self.search_field.value if hasattr(self, "search_field") and self.search_field.value else ""
        only_work = self.filter_working_only.value if hasattr(self, "filter_working_only") and self.filter_working_only.value else False
        continent = self.dd_continent.value if hasattr(self, "dd_continent") and self.dd_continent.value else "all"
        self._render_server_list(
            filter_query=query,
            only_working=only_work,
            continent_filter=continent,
        )

    # -------------------------------------------------------------------------
    # Surfshark Engine Settings
    # -------------------------------------------------------------------------
    def _update_privkey_badge(self):
        has_priv = bool(
            self.blueprint.user_interface.private_key
            and len(self.blueprint.user_interface.private_key.strip()) > 20
        )
        self.badge_privkey.bgcolor = "#1B5E20" if has_priv else "#7F1D1D"
        self.badge_privkey.border = ft.border.all(1, "#2E7D32" if has_priv else "#B71C1C")
        if hasattr(self.badge_privkey, "content") and hasattr(self.badge_privkey.content, "controls"):
            self.badge_privkey.content.controls[0].color = "#A5D6A7" if has_priv else "#FFCDD2"
            self.badge_privkey.content.controls[1].value = "PrivateKey: Ready" if has_priv else "⚠️ Key Missing"
            self.badge_privkey.content.controls[1].color = "#A5D6A7" if has_priv else "#FFCDD2"
        try:
            self.badge_privkey.update()
        except Exception:
            pass

    def _build_prev_scan_card(self) -> ft.Container:
        self.prev_scan_card_column = ft.Column(spacing=6)
        self.prev_scan_card = ft.Container(
            padding=ft.padding.symmetric(horizontal=14, vertical=10),
            border_radius=8,
            bgcolor="#13202E",
            border=ft.border.all(1, "#00ACC1"),
            content=self.prev_scan_card_column,
        )
        self._update_prev_scan_card()
        return self.prev_scan_card

    def _update_prev_scan_card(self):
        self.prev_scan_card_column.controls.clear()
        if self.last_scan_data:
            dt_str = self.last_scan_data.get("formatted_time", "Unknown date")
            w_count = self.last_scan_data.get("working_count", 0)
            top_5 = self.last_scan_data.get("top_5", [])

            # Header Row
            header_row = ft.Row(
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                controls=[
                    ft.Row(
                        spacing=8,
                        controls=[
                            ft.Icon(ft.icons.HISTORY_ROUNDED, color="#00E5FF", size=22),
                            ft.Text("📊 Previous Scan History:", size=13, weight=ft.FontWeight.BOLD, color="#E0F7FA"),
                            ft.Container(
                                padding=ft.padding.symmetric(horizontal=8, vertical=3),
                                bgcolor="#004D40",
                                border_radius=4,
                                content=ft.Text(f"🕒 {dt_str}", size=11, color="#80CBC4", weight=ft.FontWeight.BOLD),
                            ),
                            ft.Container(
                                padding=ft.padding.symmetric(horizontal=8, vertical=3),
                                bgcolor="#1B5E20",
                                border_radius=4,
                                content=ft.Text(f"🟢 {w_count} Working Servers", size=11, color="#A5D6A7", weight=ft.FontWeight.BOLD),
                            ),
                        ],
                    ),
                    ft.Row(
                        spacing=6,
                        controls=[
                            ft.IconButton(
                                icon=ft.icons.SYNC_ROUNDED,
                                icon_color="#00E5FF",
                                icon_size=20,
                                tooltip="Sync results and pings from Shadowrocket",
                                on_click=self._sync_results_from_shadowrocket,
                            ),
                            ft.ElevatedButton(
                                text="🏆 Top 5 Servers",
                                icon=ft.icons.EMOJI_EVENTS_ROUNDED,
                                style=ft.ButtonStyle(bgcolor="#FF8F00", color="#000000"),
                                on_click=lambda e: self._show_top5_announcement_modal(top_5),
                                tooltip="View Top 5 fastest servers modal",
                            ) if top_5 else ft.Container(),
                        ],
                    ),
                ],
            )
            self.prev_scan_card_column.controls.append(header_row)

            # Quick clickable pills for Top 5
            if top_5:
                medal_icons = ["🥇", "🥈", "🥉", "4️⃣", "5️⃣"]
                pills = []
                for idx, item in enumerate(top_5):
                    rank_icon = medal_icons[idx] if idx < len(medal_icons) else f"#{idx+1}"
                    flag = country_code_to_flag(item.get("country_code", ""))
                    city = item.get("city", "")
                    ping = int(item.get("latency_ms", 0))
                    pills.append(
                        ft.Container(
                            padding=ft.padding.symmetric(horizontal=8, vertical=4),
                            bgcolor="#1E2F3E",
                            border=ft.border.all(1, "#00E5FF" if idx == 0 else "#37474F"),
                            border_radius=6,
                            content=ft.Row(
                                tight=True,
                                spacing=6,
                                controls=[
                                    ft.Text(rank_icon, size=13),
                                    ft.Text(f"{flag} {city}", size=11, weight=ft.FontWeight.W_500, color="#FFFFFF"),
                                    ft.Container(
                                        padding=ft.padding.symmetric(horizontal=4, vertical=1),
                                        bgcolor="#1B5E20",
                                        border_radius=3,
                                        content=ft.Text(f"{ping}ms", size=10, color="#69F0AE", weight=ft.FontWeight.BOLD),
                                    ),
                                    ft.IconButton(
                                        icon=ft.icons.CONTENT_COPY_ROUNDED,
                                        icon_size=13,
                                        tooltip="Quick copy config",
                                        on_click=lambda e, s=item: self._copy_config_from_dict(s),
                                    ),
                                    ft.IconButton(
                                        icon=ft.icons.QR_CODE_ROUNDED,
                                        icon_size=13,
                                        tooltip="Show QR Code",
                                        on_click=lambda e, s=item: self._show_qr_from_dict(s),
                                    ),
                                ],
                            ),
                        )
                    )
                self.prev_scan_card_column.controls.append(
                    ft.Row(
                        wrap=True,
                        spacing=8,
                        controls=pills,
                    )
                )

            # Always add the Featured Countries Bar (Albania, Andorra, Bahamas, Cambodia, Myanmar, Mongolia)
            featured_bar = self._build_featured_countries_bar()
            if featured_bar:
                self.prev_scan_card_column.controls.append(featured_bar)
        else:
            self.prev_scan_card_column.controls.append(
                ft.Row(
                    spacing=8,
                    controls=[
                        ft.Icon(ft.icons.INFO_OUTLINE_ROUNDED, color="#78909C", size=18),
                        ft.Text(
                            "No scan history yet. Click 'Scan & Verify Servers' to discover reachable endpoints and save the Top 5.",
                            size=12,
                            color="#90A4AE",
                        ),
                    ],
                )
            )
            featured_bar = self._build_featured_countries_bar()
            if featured_bar:
                self.prev_scan_card_column.controls.append(featured_bar)
        if hasattr(self, "page") and self.page:
            try:
                self.prev_scan_card.update()
            except Exception:
                pass

    def _load_user_settings(self):
        """Loads user settings from user_settings.json if available."""
        self.featured_countries = list(DEFAULT_FEATURED_COUNTRIES)
        if os.path.exists(DEFAULT_USER_SETTINGS_FILE):
            try:
                with open(DEFAULT_USER_SETTINGS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if "featured_countries" in data and isinstance(data["featured_countries"], list):
                    fc = [str(x).strip() for x in data["featured_countries"] if str(x).strip()]
                    if fc:
                        self.featured_countries = fc
                if "scan_mode" in data and data["scan_mode"]:
                    self.scan_mode = str(data["scan_mode"])
                if "scan_timeout" in data:
                    self.scan_timeout = float(data["scan_timeout"])
                if "probe_count" in data:
                    self.probe_count = int(data["probe_count"])
            except Exception:
                pass

    def _save_user_settings(self):
        """Persists current user settings and featured countries to user_settings.json."""
        try:
            data = {
                "featured_countries": self.featured_countries,
                "scan_mode": self.scan_mode,
                "scan_timeout": self.scan_timeout,
                "probe_count": self.probe_count,
            }
            with open(DEFAULT_USER_SETTINGS_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def _resolve_country_identifier(self, token: str) -> Optional[dict]:
        """
        Resolves a country input string (name, code, or alias) into canonical name and 2-letter ISO code.
        Example: 'andora' -> {'name': 'Andorra', 'code': 'AD', 'aliases': [...]}
        """
        t = str(token).strip().lower()
        if not t:
            return None

        # 1. Direct check in known aliases
        if t in COUNTRY_ALIASES:
            c_name, c_code = COUNTRY_ALIASES[t]
            return {
                "name": c_name,
                "code": c_code.upper(),
                "aliases": [c_name.lower(), t, c_code.lower()],
            }

        # 2. Match against blueprint server database
        code_map = {}
        name_map = {}
        for s in self.blueprint.servers:
            code = s.country_code.upper()
            name = s.country
            code_map[code] = (name, code)
            name_map[name.lower()] = (name, code)

        if len(t) == 2 and t.upper() in code_map:
            c_name, c_code = code_map[t.upper()]
            return {
                "name": c_name,
                "code": c_code.upper(),
                "aliases": [c_name.lower(), t, c_code.lower()],
            }

        if t in name_map:
            c_name, c_code = name_map[t]
            return {
                "name": c_name,
                "code": c_code.upper(),
                "aliases": [c_name.lower(), t, c_code.lower()],
            }

        # Prefix matching across known countries
        for kn, (c_name, c_code) in name_map.items():
            if kn.startswith(t):
                return {
                    "name": c_name,
                    "code": c_code.upper(),
                    "aliases": [c_name.lower(), t, c_code.lower()],
                }

        # Fallback if unknown
        return {
            "name": str(token).strip().title(),
            "code": str(token).strip()[:2].upper(),
            "aliases": [t],
        }

    def _get_best_config_for_country(self, country_input, only_working: bool = False) -> Optional[dict]:
        """
        Returns the best server config for the given country.
        If only_working is True, strictly returns a server with an active connection (latency_ms < 9000).
        """
        if isinstance(country_input, dict):
            c_meta = country_input
        else:
            c_meta = self._resolve_country_identifier(str(country_input))
            if not c_meta:
                return None

        code = c_meta["code"].upper()
        aliases = [a.lower() for a in c_meta.get("aliases", [c_meta["name"].lower()])]
        c_name = c_meta.get("name", "").lower()

        # 1. Search in working_configs (verified active servers)
        working_matches = []
        for c in self.working_configs:
            c_code = c.get("country_code", "").upper()
            c_cname = c.get("country", "").lower()
            if c_code == code or c_cname in aliases or c_cname == c_name:
                working_matches.append(c)

        if working_matches:
            working_matches.sort(key=lambda x: x.get("latency_ms", 9999.0))
            best = dict(working_matches[0])
            best["is_working"] = True
            return best

        # 2. Search in scan_results
        scanned_matches = []
        for h, res_list in self.scan_results.items():
            server = next((s for s in self.blueprint.servers if s.hostname == h), None)
            if not server:
                continue
            s_code = server.country_code.upper()
            s_name = server.country.lower()
            if s_code == code or s_name in aliases or s_name == c_name:
                for r in res_list:
                    is_w = bool(r.is_reachable and r.latency_ms < 9000)
                    if only_working and not is_w:
                        continue
                    scanned_matches.append({
                        "country": server.country,
                        "country_code": server.country_code,
                        "city": server.city,
                        "hostname": server.hostname,
                        "public_key": server.public_key,
                        "endpoint_ip": r.ip,
                        "port": r.port,
                        "latency_ms": r.latency_ms,
                        "status": r.status,
                        "is_reachable": r.is_reachable,
                        "is_working": is_w,
                    })

        if scanned_matches:
            scanned_matches.sort(key=lambda x: (not x.get("is_working", False), x.get("latency_ms", 9999.0)))
            return scanned_matches[0]

        if only_working:
            return None

        # 3. Fallback to blueprint server (only when untested servers are accepted)
        bp_server = next(
            (s for s in self.blueprint.servers if s.country_code.upper() == code or s.country.lower() in aliases or s.country.lower() == c_name),
            None
        )
        if bp_server:
            primary_ip = bp_server.resolved_ips[0] if bp_server.resolved_ips else bp_server.hostname
            return {
                "country": bp_server.country,
                "country_code": bp_server.country_code,
                "city": bp_server.city,
                "hostname": bp_server.hostname,
                "public_key": bp_server.public_key,
                "endpoint_ip": primary_ip,
                "port": bp_server.port,
                "latency_ms": 9999.0,
                "status": "untested",
                "is_reachable": False,
                "is_working": False,
            }

        return None

    def _build_featured_countries_bar(self) -> ft.Container:
        """
        Builds the featured countries bar.
        STRICT REQUIREMENT: Only countries with an ACTIVE / WORKING server are displayed.
        """
        pills = []
        for fc in self.featured_countries:
            best = self._get_best_config_for_country(fc, only_working=True)
            if not best:
                continue

            flag = country_code_to_flag(best.get("country_code", ""))
            c_name = best.get("country", "")
            city = best.get("city", "")
            endpoint = best.get("endpoint_ip", "")
            lat = best.get("latency_ms", 9999.0)

            status_badge = ft.Container(
                padding=ft.padding.symmetric(horizontal=5, vertical=1),
                bgcolor="#1B5E20",
                border_radius=3,
                content=ft.Text(f"{int(lat)}ms", size=10, color="#69F0AE", weight=ft.FontWeight.BOLD),
            )
            border_color = "#00E676"

            pill = ft.Container(
                padding=ft.padding.symmetric(horizontal=8, vertical=4),
                bgcolor="#16222F",
                border=ft.border.all(1, border_color),
                border_radius=6,
                content=ft.Row(
                    tight=True,
                    spacing=6,
                    controls=[
                        ft.Text(f"{flag} {c_name}", size=11, weight=ft.FontWeight.W_500, color="#FFFFFF"),
                        ft.Text(f"({city or endpoint})", size=10, color="#B0BEC5"),
                        status_badge,
                        ft.IconButton(
                            icon=ft.icons.CONTENT_COPY_ROUNDED,
                            icon_size=13,
                            tooltip=f"Copy config for {c_name} ({endpoint})",
                            on_click=lambda e, s=best: self._copy_config_from_dict(s),
                        ),
                        ft.IconButton(
                            icon=ft.icons.QR_CODE_ROUNDED,
                            icon_size=13,
                            tooltip=f"Show QR Code for {c_name}",
                            on_click=lambda e, s=best: self._show_qr_from_dict(s),
                        ),
                    ],
                ),
            )
            pills.append(pill)

        header_subtitle = f"{len(pills)} active countries out of {len(self.featured_countries)} featured" if pills else f"Total {len(self.featured_countries)} featured countries configured"

        body_control = (
            ft.Row(
                wrap=True,
                spacing=8,
                controls=pills,
            )
            if pills
            else ft.Container(
                padding=ft.padding.symmetric(horizontal=12, vertical=8),
                bgcolor="#1A222C",
                border=ft.border.all(1, "#37474F"),
                border_radius=6,
                content=ft.Row(
                    spacing=8,
                    controls=[
                        ft.Icon(ft.icons.INFO_OUTLINE_ROUNDED, color="#FFA726", size=16),
                        ft.Text(
                            f"No active verified servers currently found for featured countries ({', '.join(self.featured_countries)}).\n"
                            "Export to Shadowrocket or run a scan to identify live servers.",
                            size=11,
                            color="#CFD8DC",
                        ),
                    ],
                ),
            )
        )

        return ft.Container(
            padding=ft.padding.only(top=6),
            content=ft.Column(
                spacing=5,
                controls=[
                    ft.Row(
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        controls=[
                            ft.Row(
                                spacing=6,
                                controls=[
                                    ft.Icon(ft.icons.EXPLORE_ROUNDED, color="#FFD54F", size=16),
                    ft.Text("🌟 Top Configs for Featured Countries:", size=11, weight=ft.FontWeight.BOLD, color="#80CBC4"),
                                    ft.Text(f"({header_subtitle})", size=10, color="#80DEEA" if pills else "#FFB74D"),
                                ],
                            ),
                            ft.Row(
                                spacing=4,
                                controls=[
                                    ft.TextButton(
                                        content=ft.Row(
                                            spacing=4,
                                            controls=[
                                                ft.Icon(ft.icons.SETTINGS_OUTLINED, size=13, color="#80CBC4"),
                                                ft.Text("Edit Countries", size=11, color="#80CBC4"),
                                            ],
                                        ),
                                        on_click=self._open_settings_modal,
                                        tooltip="Customize featured countries list in Settings",
                                    ),
                                    ft.TextButton(
                                        content=ft.Row(
                                            spacing=4,
                                            controls=[
                                                ft.Icon(ft.icons.ROCKET_LAUNCH_ROUNDED, size=13, color="#00E5FF"),
                                                ft.Text("Export to Shadowrocket", size=11, color="#80DEEA"),
                                            ],
                                        ),
                                        on_click=self._export_featured_countries_to_shadowrocket,
                                        tooltip="Export featured countries configs to Shadowrocket for connection testing",
                                    ),
                                ],
                            ),
                        ],
                    ),
                    body_control,
                ],
            ),
        )

    def _export_featured_countries_to_shadowrocket(self, e=None):
        """Exports configs for all currently configured featured countries to Shadowrocket."""
        self._ensure_private_key(self._do_export_featured_countries_to_shadowrocket)

    def _do_export_featured_countries_to_shadowrocket(self):
        featured_codes = set()
        for fc in self.featured_countries:
            info = self._resolve_country_identifier(fc)
            if info:
                featured_codes.add(info["code"].upper())

        targets = []
        for s in self.blueprint.servers:
            if s.country_code.upper() in featured_codes:
                for ip in s.resolved_ips:
                    if ShadowrocketStorage.is_ipv4(ip):
                        targets.append({
                            "country": s.country,
                            "city": s.city,
                            "country_code": s.country_code,
                            "hostname": s.hostname,
                            "public_key": s.public_key,
                            "endpoint_ip": ip,
                            "port": s.port,
                            "is_domain": False,
                        })

        if not targets:
            self._show_toast("No servers found for featured countries.", is_error=True)
            return

        params = self._get_current_params()
        self._kill_shadowrocket_if_running()
        res = inject_servers_to_shadowrocket_storage(
            server_configs=targets,
            user_interface=self.blueprint.to_dict()["user_interface"],
            amnezia_params=params,
        )
        self._launch_shadowrocket()
        if res.get("success"):
            cnt = res.get("added_count", len(targets))
            countries_str = ", ".join(self.featured_countries)
            self._show_toast(f"✅ {cnt} servers for featured countries ({countries_str}) exported to Shadowrocket.")
        else:
            self._show_toast(f"Error exporting to Shadowrocket: {res.get('error')}", is_error=True)

    def _get_server_obj(self, hostname: str, country: str = "", city: str = "", public_key: str = "", port: int = 51820) -> ServerMetadata:
        for s in self.blueprint.servers:
            if s.hostname == hostname:
                return s
        return ServerMetadata(
            continent="Global",
            country=country,
            country_code=country[:2].upper() if country else "UN",
            city=city,
            hostname=hostname,
            port=port,
            public_key=public_key,
        )

    def _copy_config_from_dict(self, s: dict):
        srv = self._get_server_obj(
            s.get("hostname", ""),
            s.get("country", ""),
            s.get("city", ""),
            s.get("public_key", ""),
            s.get("port", 51820),
        )
        self._copy_config_to_clipboard(srv, s.get("endpoint_ip", ""))

    def _show_qr_from_dict(self, s: dict):
        srv = self._get_server_obj(
            s.get("hostname", ""),
            s.get("country", ""),
            s.get("city", ""),
            s.get("public_key", ""),
            s.get("port", 51820),
        )
        self._show_qr_modal(srv, s.get("endpoint_ip", ""), s.get("latency_ms"))

    def _show_top5_announcement_modal(self, top_5: List[dict]):
        if not top_5:
            self._show_toast("No active servers found for Top 5.", is_error=True)
            return

        medal_icons = ["🥇", "🥈", "🥉", "4️⃣", "5️⃣"]
        top_rows = []

        for idx, item in enumerate(top_5):
            medal = medal_icons[idx] if idx < len(medal_icons) else f"#{idx+1}"
            flag = country_code_to_flag(item.get("country_code", ""))
            country = item.get("country", "")
            city = item.get("city", "")
            ip = item.get("endpoint_ip", "")
            port = item.get("port", 51820)
            ping = int(item.get("latency_ms", 0))

            row = ft.Container(
                padding=ft.padding.symmetric(horizontal=12, vertical=8),
                bgcolor="#163024" if idx == 0 else "#1A2634",
                border=ft.border.all(1, "#00C853" if idx == 0 else "#37474F"),
                border_radius=8,
                content=ft.Row(
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                    controls=[
                        ft.Row(
                            spacing=10,
                            controls=[
                                ft.Text(medal, size=20),
                                ft.Text(flag, size=22),
                                ft.Column(
                                    spacing=2,
                                    controls=[
                                        ft.Text(f"{city}, {country}", size=13, weight=ft.FontWeight.BOLD, color="#FFFFFF"),
                                        ft.Text(f"{ip}:{port}", font_family="monospace", size=11, color="#90A4AE"),
                                    ],
                                ),
                                ft.Container(
                                    padding=ft.padding.symmetric(horizontal=8, vertical=3),
                                    bgcolor="#1B5E20" if ping < 150 else "#5D4037",
                                    border_radius=4,
                                    content=ft.Text(f"{ping} ms", size=11, color="#69F0AE" if ping < 150 else "#FFB300", weight=ft.FontWeight.BOLD),
                                ),
                                ft.Container(
                                    padding=ft.padding.symmetric(horizontal=6, vertical=2),
                                    bgcolor="#004D40",
                                    border_radius=4,
                                    visible=bool(item.get("deep_verified")),
                                    content=ft.Text(f"0% Loss • ±{int(item.get('jitter_ms', 0))}ms", size=10, color="#80DEEA", weight=ft.FontWeight.BOLD),
                                ),
                            ],
                        ),
                        ft.Row(
                            spacing=6,
                            controls=[
                                ft.ElevatedButton(
                                    text="QR Code",
                                    icon=ft.icons.QR_CODE_ROUNDED,
                                    style=ft.ButtonStyle(bgcolor="#00D09C", color="#000000"),
                                    on_click=lambda e, s=item: self._show_qr_from_dict(s),
                                ),
                                ft.OutlinedButton(
                                    text="Copy Config",
                                    icon=ft.icons.CONTENT_COPY_ROUNDED,
                                    style=ft.ButtonStyle(color="#64B5F6"),
                                    on_click=lambda e, s=item: self._copy_config_from_dict(s),
                                ),
                            ],
                        ),
                    ],
                ),
            )
            top_rows.append(row)

        def _export_top5_action(e):
            self._close_dialog(modal)
            self._do_export_top5_zip(top_5)

        modal = ft.AlertDialog(
            title=ft.Row(
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                controls=[
                    ft.Row(
                        spacing=8,
                        controls=[
                            ft.Icon(ft.icons.EMOJI_EVENTS_ROUNDED, color="#FFD700", size=28),
                            ft.Text("🏆 Top 5 Best & Fastest Servers", size=16, weight=ft.FontWeight.BOLD),
                        ],
                    ),
                    ft.Container(
                        padding=ft.padding.symmetric(horizontal=8, vertical=4),
                        bgcolor="#004D40",
                        border_radius=4,
                        content=ft.Text("Lowest Latency Verified", size=11, color="#80CBC4", weight=ft.FontWeight.BOLD),
                    ),
                ],
            ),
            content=ft.Container(
                width=680,
                content=ft.Column(
                    tight=True,
                    spacing=6,
                    controls=[
                        ft.Text(
                "These 5 servers demonstrated the lowest latency and highest stability during scanning:",
                            size=12,
                            color="#B0BEC5",
                        ),
                        ft.Divider(height=10, color="#37474F"),
                        ft.Column(controls=top_rows, spacing=4),
                    ],
                ),
            ),
            actions=[
                ft.ElevatedButton(
                    text="📦 Download Top 5 ZIP",
                    icon=ft.icons.FOLDER_ZIP_ROUNDED,
                    style=ft.ButtonStyle(bgcolor="#FF8F00", color="#000000"),
                    on_click=_export_top5_action,
                ),
                ft.ElevatedButton(
                    text="📦 Download All Servers ZIP",
                    icon=ft.icons.DOWNLOAD_ROUNDED,
                    style=ft.ButtonStyle(bgcolor="#1E88E5", color="#FFFFFF"),
                    on_click=lambda e: (self._close_dialog(modal), self._export_batch_zip(e)),
                ),
                ft.TextButton(text="Close (Close)", on_click=lambda e: self._close_dialog(modal)),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
        )
        self._open_dialog(modal)

    def _do_export_top5_zip(self, top_5: List[dict]):
        export_dir = os.path.expanduser("~/Downloads")
        if not os.path.exists(export_dir):
            export_dir = os.getcwd()

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        prov_prefix = "surfshark"
        zip_filename = f"{prov_prefix}_top5_servers_{timestamp}.zip"
        target_path = os.path.join(export_dir, zip_filename)

        params = self._get_current_params()
        generate_batch_zip(
            server_configs=top_5,
            user_interface=self.blueprint.to_dict()["user_interface"],
            amnezia_params=params,
            output_path=target_path,
        )
        self._show_toast(f"Top 5 configs exported to: {target_path}")
        self._reveal_file_in_finder(target_path)

    # -------------------------------------------------------------------------
    # Active Network & VPN Detection Banner & Safety Pre-Check
    # -------------------------------------------------------------------------
    def _create_vpn_status_banner(self) -> ft.Container:
        self.vpn_status = detect_active_vpn()
        is_active = self.vpn_status.is_vpn_active

        bg_color = "#3E2723" if is_active else "#1B3B2B"
        border_color = "#FFA000" if is_active else "#00C853"
        icon_color = "#FFA000" if is_active else "#00C853"
        icon_name = ft.icons.WARNING_AMBER_ROUNDED if is_active else ft.icons.CHECK_CIRCLE_OUTLINE_ROUNDED

        title_fa = (
            f"⚠️ Active VPN Detected ({self.vpn_status.interface}) — Please disconnect VPN before testing server IPs!"
            if is_active
            else f"🟢 Direct Connection ({self.vpn_status.interface}) — VPN is OFF. Ready for authentic local network testing."
        )
        sub_fa = (
            "To accurately discover unblocked IPs, reachability packets must route directly through your ISP."
            if is_active
            else "Packets route directly through your local ISP (Direct Connection)."
        )

        self.vpn_banner_icon = ft.Icon(icon_name, color=icon_color, size=24)
        self.vpn_banner_title = ft.Text(title_fa, size=12, weight=ft.FontWeight.BOLD, color="#FFFFFF")
        self.vpn_banner_sub = ft.Text(sub_fa, size=11, color="#B0BEC5")

        self.vpn_banner_container = ft.Container(
            padding=ft.padding.symmetric(horizontal=14, vertical=10),
            border_radius=8,
            bgcolor=bg_color,
            border=ft.border.all(1, border_color),
            content=ft.Row(
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                controls=[
                    ft.Row(
                        spacing=12,
                        controls=[
                            self.vpn_banner_icon,
                            ft.Column(
                                spacing=1,
                                controls=[
                                    self.vpn_banner_title,
                                    self.vpn_banner_sub,
                                ],
                            ),
                        ],
                    ),
                    ft.OutlinedButton(
                        text="Check VPN Status",
                        icon=ft.icons.REFRESH_ROUNDED,
                        on_click=self._refresh_vpn_status,
                        style=ft.ButtonStyle(color="#ECEFF1"),
                    ),
                ],
            ),
        )
        return self.vpn_banner_container

    def _apply_vpn_status_to_banner(self, status: VpnStatus):
        """Silently and smoothly applies VPN status to the main page banner."""
        is_active = status.is_vpn_active
        bg_color = "#3E2723" if is_active else "#1B3B2B"
        border_color = "#FFA000" if is_active else "#00C853"
        icon_color = "#FFA000" if is_active else "#00C853"
        icon_name = ft.icons.WARNING_AMBER_ROUNDED if is_active else ft.icons.CHECK_CIRCLE_OUTLINE_ROUNDED

        title_fa = (
            f"⚠️ Active VPN Detected ({status.interface}) — Please disconnect VPN before testing!"
            if is_active
            else f"🟢 Direct Connection ({status.interface}) — VPN is OFF. Ready for direct testing."
        )
        sub_fa = (
            "To accurately discover unblocked IPs, reachability packets must route directly through your ISP."
            if is_active
            else "Packets route directly through your local ISP (Direct Connection)."
        )

        if hasattr(self, "vpn_banner_container") and self.vpn_banner_container:
            self.vpn_banner_container.bgcolor = bg_color
            self.vpn_banner_container.border = ft.border.all(1, border_color)
        if hasattr(self, "vpn_banner_icon") and self.vpn_banner_icon:
            self.vpn_banner_icon.name = icon_name
            self.vpn_banner_icon.color = icon_color
        if hasattr(self, "vpn_banner_title") and self.vpn_banner_title:
            self.vpn_banner_title.value = title_fa
        if hasattr(self, "vpn_banner_sub") and self.vpn_banner_sub:
            self.vpn_banner_sub.value = sub_fa
        try:
            self.page.update()
        except Exception:
            pass

    def _update_prescan_modal_ui(self, status: VpnStatus):
        """Silently and live-updates pre-scan modal controls if visible."""
        if not hasattr(self, "_active_prescan_controls") or not self._active_prescan_controls:
            return
        try:
            status_text_ctrl, status_box_ctrl, chk_ctrl, title_icon_ctrl = self._active_prescan_controls
            is_active = status.is_vpn_active
            status_text_ctrl.value = (
                f"⚠️ Active VPN Detected: {status.interface}"
                if is_active
                else f"🟢 VPN is OFF (Direct connection via {status.interface})"
            )
            status_box_ctrl.bgcolor = "#3E2723" if is_active else "#1B3B2B"
            status_box_ctrl.border = ft.border.all(1, "#FFA000" if is_active else "#00C853")
            if title_icon_ctrl:
                title_icon_ctrl.name = ft.icons.WARNING_ROUNDED if is_active else ft.icons.SHIELD_MOON_ROUNDED
                title_icon_ctrl.color = "#FFA000" if is_active else "#00C853"
            chk_ctrl.value = not is_active
            self.page.update()
        except Exception:
            pass

    def _refresh_vpn_status(self, e=None):
        """Explicit manual button click to refresh VPN status with toast feedback."""
        self.vpn_status = detect_active_vpn()
        self._apply_vpn_status_to_banner(self.vpn_status)
        self._update_prescan_modal_ui(self.vpn_status)
        msg = "VPN is OFF." if not self.vpn_status.is_vpn_active else f"VPN is active ({self.vpn_status.interface})."
        self._show_toast(f"Connection status: {msg}")

    def _start_background_monitors(self):
        """
        Starts lightweight daemon threads for:
        1. Live VPN status monitoring (every 2 seconds)
        2. Shadowrocket disk mtime watcher (auto-sync when Shadowrocket updates)
        3. Shadowrocket live memory crawler (every 8 seconds when Shadowrocket runs)
        """
        def _monitor_loop():
            last_live_poll_time = 0.0
            while True:
                time.sleep(2.0)
                try:
                    # 1. Live VPN Status Check
                    fresh_vpn = detect_active_vpn()
                    if (
                        fresh_vpn.is_vpn_active != self.vpn_status.is_vpn_active
                        or fresh_vpn.interface != self.vpn_status.interface
                    ):
                        self.vpn_status = fresh_vpn
                        self._apply_vpn_status_to_banner(fresh_vpn)
                        self._update_prescan_modal_ui(fresh_vpn)
                    elif hasattr(self, "_active_prescan_controls") and self._active_prescan_controls:
                        self._update_prescan_modal_ui(fresh_vpn)

                    # 2. Shadowrocket Disk File Watcher
                    storage_path = ShadowrocketStorage.DEFAULT_STORAGE_PATH
                    if os.path.exists(storage_path):
                        mtime = os.path.getmtime(storage_path)
                        if getattr(self, "_last_sr_mtime", 0.0) == 0.0:
                            self._last_sr_mtime = mtime
                            if not self.working_configs:
                                self._sync_shadowrocket_from_disk_background()
                        elif mtime > self._last_sr_mtime:
                            self._last_sr_mtime = mtime
                            self._sync_shadowrocket_from_disk_background()

                    # 3. Live in-memory Shadowrocket polling
                    now = time.time()
                    if (now - last_live_poll_time) >= 8.0:
                        last_live_poll_time = now
                        if is_shadowrocket_running() and not self.is_scanning and not getattr(self, "_is_syncing_sr", False):
                            self._poll_shadowrocket_live_background()

                except Exception as ex:
                    logger.debug(f"Background monitor loop error: {ex}")

        t = threading.Thread(target=_monitor_loop, daemon=True)
        t.start()

    def _sync_shadowrocket_from_disk_background(self):
        """Silently reads updated Shadowrocket ServerManager from disk and updates UI."""
        if getattr(self, "_is_syncing_sr", False) or self.is_scanning:
            return
        try:
            storage = ShadowrocketStorage()
            disk_results = storage.read_test_results()
            if disk_results and any(r.get("is_reachable") for r in disk_results.values()):
                self._apply_shadowrocket_results(disk_results, is_auto=True)
        except Exception as e:
            logger.debug(f"Background disk sync failed: {e}")

    def _poll_shadowrocket_live_background(self):
        """Polls live Shadowrocket AX window for new in-memory test results."""
        if getattr(self, "_is_syncing_sr", False) or self.is_scanning:
            return
        try:
            sr_results = read_shadowrocket_test_results()
            working_now = sum(1 for r in sr_results.values() if r.get("is_reachable"))
            prev_working = len(self.working_configs)
            if working_now > 0 and working_now != prev_working:
                self._apply_shadowrocket_results(sr_results, is_auto=True)
        except Exception as e:
            logger.debug(f"Background live AX poll error: {e}")

    def _prompt_pre_scan_vpn_check(self, e):
        """
        Pre-scan validation: Alert user if VPN is active so they don't get false positives.
        Live-updates in real-time as user disconnects VPN.
        """
        if self.is_scanning:
            self._show_toast("Scan is already in progress.")
            return

        self.vpn_status = detect_active_vpn()
        is_active = self.vpn_status.is_vpn_active

        status_text = (
            f"⚠️ Active VPN Tunnel Detected: {self.vpn_status.interface}"
            if is_active
            else f"🟢 VPN Disconnected (Direct connection via {self.vpn_status.interface})"
        )

        chk_confirm = ft.Checkbox(
            label="My VPN is disconnected and I am ready for direct testing.",
            value=not is_active,
        )

        lbl_warning_desc = ft.Text(
            "CRITICAL NOTICE BEFORE TESTING:\n"
            "To accurately verify which server IPs are directly reachable from your network, "
            "reachability test packets (UDP / WireGuard Handshake) must be sent directly through your ISP.\n\n"
            "⚠️ If an active VPN or proxy tunnel is running, packets route through external foreign servers, "
            "giving false positive results that will fail when disconnected.\n\n"
            "👉 Please disconnect your VPN now (this indicator updates automatically).",
            size=12,
            color="#ECEFF1",
        )

        modal_status_text = ft.Text(status_text, size=13, weight=ft.FontWeight.BOLD, color="#FFFFFF")
        modal_status_box = ft.Container(
            padding=10,
            border_radius=6,
            bgcolor="#3E2723" if is_active else "#1B3B2B",
            border=ft.border.all(1, "#FFA000" if is_active else "#00C853"),
            content=ft.Row(
                alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                controls=[
                    modal_status_text,
                    ft.TextButton("🔄 Recheck", on_click=lambda ev: self._refresh_vpn_status(ev)),
                ],
            ),
        )

        modal_title_icon = ft.Icon(
            ft.icons.SHIELD_MOON_ROUNDED if not is_active else ft.icons.WARNING_ROUNDED,
            color="#00C853" if not is_active else "#FFA000",
            size=26,
        )

        # Register controls for live background auto-updates
        self._active_prescan_controls = (modal_status_text, modal_status_box, chk_confirm, modal_title_icon)

        def _close_modal(ev=None):
            self._active_prescan_controls = None
            self._close_dialog(modal)

        def _proceed(ev):
            # Live verification right before starting test
            fresh_status = detect_active_vpn()
            self.vpn_status = fresh_status
            self._apply_vpn_status_to_banner(fresh_status)
            if fresh_status.is_vpn_active and not chk_confirm.value:
                self._update_prescan_modal_ui(fresh_status)
                self._show_toast("⚠️ VPN is still active! Please disconnect your VPN before testing.", is_error=True)
                return
            self._active_prescan_controls = None
            self._close_dialog(modal)
            self._start_dns_and_reachability_scan(ev)

        prev_scan_info_controls = []
        if self.last_scan_data:
            dt_str = self.last_scan_data.get("formatted_time", "Unknown")
            w_count = self.last_scan_data.get("working_count", 0)
            top_5 = self.last_scan_data.get("top_5", [])
            top_summary = ""
            if top_5:
                top_items = [f"{country_code_to_flag(t.get('country_code', ''))} {t.get('city')}: {int(t.get('latency_ms', 0))}ms" for t in top_5[:3]]
                top_summary = " (Best: " + " | ".join(top_items) + ")"
            prev_scan_info_controls.append(
                ft.Container(
                    padding=10,
                    border_radius=6,
                    bgcolor="#0E2333",
                    border=ft.border.all(1, "#00ACC1"),
                    content=ft.Row(
                        spacing=10,
                        controls=[
                            ft.Icon(ft.icons.HISTORY_ROUNDED, color="#00E5FF", size=24),
                            ft.Column(
                                spacing=2,
                                expand=True,
                                controls=[
                                    ft.Text("📊 Previous Scan Result:", size=12, weight=ft.FontWeight.BOLD, color="#E0F7FA"),
                                    ft.Text(
                                        f"Date: {dt_str}  •  {w_count} working servers{top_summary}\n"
                                        "Starting a new scan will re-verify all servers and highlight the top 5 fastest endpoints.",
                                        size=11, color="#80DEEA",
                                    ),
                                ],
                            ),
                        ],
                    ),
                )
            )

        modal = ft.AlertDialog(
            title=ft.Row(
                controls=[
                    modal_title_icon,
                    ft.Text("Important: Disconnect VPN Before Testing", weight=ft.FontWeight.BOLD, size=16),
                ]
            ),
            content=ft.Container(
                width=580,
                content=ft.Column(
                    tight=True,
                    spacing=12,
                    controls=prev_scan_info_controls + [
                        modal_status_box,
                        lbl_warning_desc,
                        ft.Divider(),
                        chk_confirm,
                    ],
                ),
            ),
            actions=[
                ft.ElevatedButton(
                    text="Start Scan & Verify Servers",
                    icon=ft.icons.PLAY_ARROW_ROUNDED,
                    style=ft.ButtonStyle(bgcolor="#00C853", color="#FFFFFF"),
                    on_click=_proceed,
                ),
                ft.TextButton(text="Cancel", on_click=_close_modal),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
        )

        self._open_dialog(modal)

    # -------------------------------------------------------------------------
    # Client Credentials & PrivateKey Dashboard State Management
    # -------------------------------------------------------------------------
    def _update_privkey_badge(self):
        has_priv = bool(self.blueprint.user_interface.private_key and len(self.blueprint.user_interface.private_key.strip()) > 20)
        derived_pk = derive_public_key(self.blueprint.user_interface.private_key) if has_priv else None

        if has_priv:
            self.badge_privkey.bgcolor = "#1B5E20"
            self.badge_privkey.content.value = "✅ PrivateKey Configured"
            self.badge_privkey.content.color = "#A5D6A7"
        else:
            self.badge_privkey.bgcolor = "#B71C1C"
            self.badge_privkey.content.value = "⚠️ PrivateKey Missing (Required for connection)"
            self.badge_privkey.content.color = "#FFCDD2"

        if derived_pk:
            self.lbl_derived_pubkey.value = f"🔑 Client PublicKey: {derived_pk} (Matches Surfshark dashboard)"
            self.lbl_derived_pubkey.color = "#81C784"
        else:
            self.lbl_derived_pubkey.value = "🔑 Client PublicKey: Automatically derived once PrivateKey is entered."
            self.lbl_derived_pubkey.color = "#90A4AE"

        self.page.update()

    def _save_active_blueprint(self):
        """Saves blueprint for Surfshark."""
        save_blueprint(self.blueprint, DEFAULT_DATA_FILE)

    def _on_dashboard_creds_changed(self, e):
        self.blueprint.user_interface.private_key = self.txt_client_privkey.value.strip()
        self.blueprint.user_interface.address = self.txt_client_addr.value.strip()
        self.blueprint.user_interface.dns = self.txt_client_dns.value.strip()
        self._update_privkey_badge()
        if self._save_debounce_timer is not None:
            self._save_debounce_timer.cancel()
        self._save_debounce_timer = threading.Timer(0.6, self._save_active_blueprint)
        self._save_debounce_timer.daemon = True
        self._save_debounce_timer.start()

    def _save_dashboard_creds(self, e):
        # Immediate save on explicit button press
        if self._save_debounce_timer is not None:
            self._save_debounce_timer.cancel()
            self._save_debounce_timer = None
        self._on_dashboard_creds_changed(e)
        self._save_active_blueprint()
        self._show_toast("Client PrivateKey saved successfully.")

    def _ensure_private_key(self, on_success):
        """
        Guarantees a valid PrivateKey exists before generating or exporting configs.
        If missing, prompts the user with a focused modal dialog.
        """
        curr_key = self.blueprint.user_interface.private_key.strip() if self.blueprint.user_interface.private_key else ""
        if curr_key and len(curr_key) > 20 and not is_placeholder_key(curr_key):
            if hasattr(self, "txt_client_privkey") and self.txt_client_privkey.value != curr_key:
                self.txt_client_privkey.value = curr_key
            on_success()
            return

        ui_key = self.txt_client_privkey.value.strip() if hasattr(self, "txt_client_privkey") and self.txt_client_privkey.value else ""
        if ui_key and len(ui_key) > 20 and not is_placeholder_key(ui_key):
            self.blueprint.user_interface.private_key = ui_key
            self._save_active_blueprint()
            self._update_privkey_badge()
            on_success()
            return

        txt_key_input = ft.TextField(
            label="Client WireGuard PrivateKey (Base64)",
            hint_text="e.g. v1o+c1p191WvA9d0j9aB9C1d9E2f3g4h5i6j7k8l9m0=",
            password=True,
            can_reveal_password=True,
            text_size=12,
            autofocus=True,
            expand=True,
        )

        modal = None

        def _save_and_continue(ev):
            key = txt_key_input.value.strip()
            if not key or len(key) < 20:
                self._show_toast("Please enter a valid WireGuard PrivateKey (Base64).", is_error=True)
                return
            self.blueprint.user_interface.private_key = key
            if hasattr(self, "txt_client_privkey"):
                self.txt_client_privkey.value = key
            self._save_active_blueprint()
            self._update_privkey_badge()
            if modal:
                self._close_dialog(modal)
            self._show_toast("PrivateKey saved successfully!")
            on_success()

        prov_name = "Surfshark"
        modal = ft.AlertDialog(
            title=ft.Row(
                controls=[
                    ft.Icon(ft.icons.KEY_ROUNDED, color="#FFA000", size=24),
                    ft.Text("Client PrivateKey Required", weight=ft.FontWeight.BOLD, size=16),
                ]
            ),
            content=ft.Container(
                width=540,
                content=ft.Column(
                    tight=True,
                    spacing=12,
                    controls=[
                        ft.Text(
            "To generate working AmneziaWG configs and handshake packets, your Surfshark WireGuard PrivateKey is required.\n"
            "Configs without this key cannot establish a connection.",
                            size=13,
                        ),
                        ft.Container(
                            padding=10,
                            bgcolor="#1E293B",
                            border_radius=6,
                            content=ft.Text(
            "📌 How to obtain from Surfshark:\n"
            "Log in to my.surfshark.com > VPN > Manual setup > WireGuard > Generate key pair or view existing keys.",
                                size=11,
                                color="#94A3B8",
                            ),
                        ),
                        txt_key_input,
                    ],
                ),
            ),
            actions=[
                ft.ElevatedButton(
                    text="Save & Continue",
                    icon=ft.icons.CHECK_CIRCLE_ROUNDED,
                    style=ft.ButtonStyle(bgcolor="#00C853", color="#FFFFFF"),
                    on_click=_save_and_continue,
                ),
                ft.TextButton(text="Cancel", on_click=lambda ev: self._close_dialog(modal)),
            ],
            actions_alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
        )

        self._open_dialog(modal)

    # -------------------------------------------------------------------------
    # Stage A: Attended Browser Harvest Workflow
    # -------------------------------------------------------------------------
    def _start_browser_harvest(self, e):
        if self.is_scanning:
            self._show_toast("Another task is currently executing.")
            return

        stop_event = threading.Event()
        cancel_event = threading.Event()

        modal = None

        def _confirm_done(ev):
            stop_event.set()
            if modal:
                self._close_dialog(modal)
            self._show_toast("Finalizing and loading servers...")

        def _cancel_harvest(ev):
            cancel_event.set()
            if modal:
                self._close_dialog(modal)
            self._show_toast("Browser operation cancelled.")

        modal = ft.AlertDialog(
            title=ft.Row(
                controls=[
                    ft.Icon(ft.icons.OPEN_IN_BROWSER_ROUNDED, color="#00D09C", size=24),
                    ft.Text("Surfshark Account Login (Browser)", weight=ft.FontWeight.BOLD, size=16),
                ]
            ),
            content=ft.Container(
                width=550,
                content=ft.Column(
                    tight=True,
                    spacing=12,
                    controls=[
                        ft.Text(
                            "A Chromium browser window is open. Follow these steps:",
                            size=13,
                        ),
                        ft.Container(
                            padding=12,
                            bgcolor="#1E293B",
                            border_radius=6,
                            content=ft.Column(
                                spacing=6,
                                controls=[
                                    ft.Text("1. Enter your Surfshark email and password.", size=12),
                                    ft.Text("2. Complete any 2FA or CAPTCHA verification.", size=12),
                                    ft.Text("3. Once logged in, navigate to Manual Setup to capture server and key details.", size=12),
                                    ft.Text("4. The browser will remain open until you confirm.", size=12, color="#00D09C", weight=ft.FontWeight.BOLD),
                                ],
                            ),
                        ),
                        ft.Text(
                            "Once logged in and loaded, click '✅ Confirm Login & Harvest Data' below.",
                            size=12,
                            color="#94A3B8",
                        ),
                    ],
                ),
            ),
            actions=[
                ft.ElevatedButton(
                    text="✅ Confirm Login & Harvest Data",
                    icon=ft.icons.CHECK_CIRCLE_ROUNDED,
                    style=ft.ButtonStyle(bgcolor="#00C853", color="#FFFFFF"),
                    on_click=_confirm_done,
                ),
                ft.TextButton(text="Cancel (Cancel)", on_click=_cancel_harvest),
            ],
            actions_alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
        )

        self._open_dialog(modal)

        self.btn_harvest.disabled = True
        self.progress_bar.visible = True
        self.progress_bar.value = None  # indeterminate
        self.lbl_status.value = "Launching Chromium browser session for Surfshark login..."
        self.page.update()

        def _worker():
            try:
                def _log_cb(msg: str):
                    self.lbl_status.value = msg
                    self.page.update()

                new_bp = run_attended_browser_harvest(
                    on_log=_log_cb,
                    headless=False,
                    stop_event=stop_event,
                    cancel_event=cancel_event,
                )
                self.blueprint = new_bp
                # Update inputs if keys were extracted
                self.txt_client_privkey.value = self.blueprint.user_interface.private_key
                self.txt_client_addr.value = self.blueprint.user_interface.address
                self.txt_client_dns.value = self.blueprint.user_interface.dns

                self.lbl_status.value = f"Harvest complete! Loaded {len(new_bp.servers)} servers."
                self._show_toast(f"Operation completed! {len(new_bp.servers)} servers loaded.")
            except Exception as err:
                self.lbl_status.value = f"Browser harvest error: {err}"
                self._show_toast(f"Harvest error: {err}", is_error=True)
            finally:
                self.btn_harvest.disabled = False
                self.progress_bar.visible = False
                self._update_privkey_badge()
                self._refresh_summary_cards()
                self._render_server_list()

        threading.Thread(target=_worker, daemon=True).start()

    def _start_dns_and_reachability_scan(self, e):
        if self.is_scanning:
            self._show_toast("Scan is already in progress.")
            return

        sel_cont = self.dd_continent.value if hasattr(self, "dd_continent") and self.dd_continent.value else "all"

        def _cont_matches(c_val: str) -> bool:
            if sel_cont == "all":
                return True
            if sel_cont == "Americas":
                return c_val in ("Americas", "North America", "South America")
            return c_val == sel_cont

        servers_to_scan = [s for s in self.blueprint.servers if _cont_matches(s.continent)]
        if not servers_to_scan:
            self._show_toast(f"No servers found for continent {sel_cont}.", is_error=True)
            return

        self.is_scanning = True
        self.btn_scan.disabled = True
        self.progress_bar.visible = True
        self.progress_bar.value = 0.0
        if sel_cont != "all":
            self.lbl_status.value = f"Starting Anti-Poisoning DoH resolution for {sel_cont} ({len(servers_to_scan)} servers)..."
        else:
            self.lbl_status.value = "Starting Anti-Poisoning DoH resolution (Cloudflare, Google, Quad9)..."
        self.page.update()

        def _worker():
            loop = None
            top_5 = []
            try:
                hostnames = [s.hostname for s in servers_to_scan]
                total_hosts = len(hostnames)
                resolver = SecureDnsResolver(timeout=3.5, max_concurrency=25)

                # 1. DNS Resolution Phase
                import asyncio
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

                def _dns_prog(completed, total, host, ips):
                    fraction = (completed / total) * 0.4  # First 40% of progress
                    self.progress_bar.value = fraction
                    self.lbl_status.value = f"Resolving DoH [{completed}/{total}]: {host} -> {len(ips)} IPs"
                    self.page.update()

                resolved_map = loop.run_until_complete(resolver.resolve_all(hostnames, on_progress=_dns_prog))

                # Update blueprint with discovered IPs
                total_ips_discovered = 0
                for s in servers_to_scan:
                    endpoint = resolved_map.get(s.hostname)
                    if endpoint and endpoint.ips:
                        s.resolved_ips = endpoint.ips
                        total_ips_discovered += len(endpoint.ips)

                self._save_active_blueprint()
                self._refresh_summary_cards()

                # 2. UDP 51820 Reachability & Latency Phase
                self.lbl_status.value = f"Discovered {total_ips_discovered} raw IPs. Testing UDP 51820 reachability..."
                self.page.update()

                udp_targets = []
                for s in servers_to_scan:
                    for ip in s.resolved_ips:
                        udp_targets.append((
                            ip,
                            s.port,
                            self.blueprint.user_interface.private_key,
                            s.public_key,
                            {"server": s, "hostname": s.hostname},
                        ))

                total_targets = len(udp_targets)
                scanner = FastUdpScanner(
                    timeout=self.scan_timeout,
                    max_concurrency=40,
                    mode=self.scan_mode,
                    probe_count=self.probe_count,
                )
                self.scan_results.clear()
                self.working_configs.clear()

                def _udp_prog(completed, total, res: CheckResult):
                    fraction = 0.4 + ((completed / total) * 0.6)
                    self.progress_bar.value = fraction
                    lat_str = f"{int(res.latency_ms)}ms" if res.is_reachable else "Dead"
                    self.lbl_status.value = f"Testing UDP [{completed}/{total}]: {res.ip}:{res.port} -> {lat_str}"
                    self.page.update()

                all_res = scanner.scan_all_sync(udp_targets, on_progress=_udp_prog)

                # Aggregate results by hostname
                # FIX: Guard against None hostname to prevent KeyError / None dict key
                for r in all_res:
                    s_info = r.server_info
                    if s_info:
                        h = s_info.get("hostname")
                        if h is None:
                            continue  # FIX: skip entries with no hostname
                        if h not in self.scan_results:
                            self.scan_results[h] = []
                        self.scan_results[h].append(r)

                        if r.is_reachable:
                            srv = s_info["server"]
                            self.working_configs.append({
                                "country": srv.country,
                                "country_code": srv.country_code,
                                "city": srv.city,
                                "hostname": srv.hostname,
                                "public_key": srv.public_key,
                                "endpoint_ip": r.ip,
                                "port": r.port,
                                "latency_ms": r.latency_ms,
                                "packet_loss": r.packet_loss,
                                "jitter_ms": r.jitter_ms,
                                "deep_verified": r.deep_verified,
                                "status": r.status,
                            })

                working_count = len(self.working_configs)
                self.lbl_status.value = f"Scan complete! Found {working_count} verified working IPs across {len(self.scan_results)} clusters."
                self._show_toast(f"Scan finished: {working_count} reachable IPs verified!")

                # Save scan results to active provider cache & extract Top 5
                self.last_scan_data = save_scan_cache(self.scan_results, self.working_configs, filepath=self.current_scan_cache_file)
                top_5 = extract_top_servers(self.working_configs, limit=5)

            except Exception as err:
                self.lbl_status.value = f"Scan error: {err}"
                self._show_toast(f"Scan error: {err}", is_error=True)
            finally:
                # FIX: Always close the event loop to prevent resource leak
                if loop is not None:
                    try:
                        loop.close()
                    except Exception:
                        pass
                self.is_scanning = False
                self.btn_scan.disabled = False
                if hasattr(self, "btn_deep_screen"):
                    self.btn_deep_screen.disabled = False
                self.progress_bar.visible = False
                self._refresh_summary_cards()
                self._update_prev_scan_card()
                self._render_server_list()
                # v3: Automatically announce Top 5 Best Servers
                if top_5:
                    self._show_top5_announcement_modal(top_5)

        threading.Thread(target=_worker, daemon=True).start()


    # -------------------------------------------------------------------------
    # QR Code & Single Config Viewer Modal
    # -------------------------------------------------------------------------
    def _show_qr_modal(self, server: ServerMetadata, ip: str, latency: Optional[float]):
        try:
            self._ensure_private_key(lambda: self._do_show_qr_modal(server, ip, latency))
        except Exception as err:
            self._show_toast(f"Error displaying QR Code: {err}", is_error=True)

    def _do_show_qr_modal(self, server: ServerMetadata, ip: str, latency: Optional[float]):
        try:
            params = self._get_current_params()
            flag = country_code_to_flag(server.country_code)

            # Build a human-readable tunnel name that will appear in the WireGuard/AmneziaWG client
            is_domain_endpoint = (ip == server.hostname) or not re.match(r'^\d+\.\d+\.\d+\.\d+$', str(ip))
            if is_domain_endpoint:
                tunnel_name = f"{flag} {server.city} ({server.country}) — Domain"
            elif latency is not None and isinstance(latency, (int, float)) and 0 <= latency < 9000:
                tunnel_name = f"{flag} {server.city} ({server.country}) — {int(latency)}ms"
            else:
                tunnel_name = f"{flag} {server.city} ({server.country})"

            # 1. Standard WireGuard (for official WireGuard apps on iOS/Android/Windows/Mac)
            conf_standard = build_amnezia_config(
                client_private_key=self.blueprint.user_interface.private_key,
                client_address=self.blueprint.user_interface.address or ("10.2.0.2/32" if False else "10.14.0.2/16"),
                client_dns=self.blueprint.user_interface.dns or ("10.2.0.1" if False else "162.252.172.57"),
                server_public_key=server.public_key or "YOUR_SERVER_PUBLIC_KEY",
                endpoint_ip=ip,
                endpoint_port=server.port,
                amnezia_params=AmneziaParams.standard_wireguard(),
                tunnel_name=tunnel_name,
            )

            # 2. AmneziaWG Obfuscated (with Jc junk packets and scrambled headers for restricted DPI networks)
            conf_amnezia = build_amnezia_config(
                client_private_key=self.blueprint.user_interface.private_key,
                client_address=self.blueprint.user_interface.address or ("10.2.0.2/32" if False else "10.14.0.2/16"),
                client_dns=self.blueprint.user_interface.dns or ("10.2.0.1" if False else "162.252.172.57"),
                server_public_key=server.public_key or "YOUR_SERVER_PUBLIC_KEY",
                endpoint_ip=ip,
                endpoint_port=server.port,
                amnezia_params=params,
                tunnel_name=tunnel_name,
            )

            active_is_standard = (params.jc == 0 and params.s1 == 0 and params.s2 == 0 and params.h1 == 1)
            active_conf = [conf_standard if active_is_standard else conf_amnezia]

            qr_b64 = generate_qr_code_base64(active_conf[0])
            qr_image = ft.Image(src_base64=qr_b64, width=220, height=220) if qr_b64 else ft.Text("QR Code unavailable")
            qr_caption = ft.Text(
                "Scan with Official WireGuard App" if active_is_standard else "Scan with AmneziaWG App (Anti-DPI Headers)",
                size=11,
                color="#90A4AE",
            )

            txt_preview = ft.TextField(
                value=active_conf[0],
                multiline=True,
                read_only=True,
                text_size=11,
                text_style=ft.TextStyle(font_family="monospace"),
                height=210,
                expand=True,
            )

            is_domain = (ip == server.hostname) or not re.match(r'^\d+\.\d+\.\d+\.\d+$', str(ip))
            if is_domain:
                lat_badge = "🌐 Domain Endpoint"
            elif latency is not None and isinstance(latency, (int, float)) and 0 <= latency < 9000:
                lat_badge = f"{int(latency)} ms"
            else:
                lat_badge = "Tested IP"
            badge_bg = "#00838F" if is_domain else "#00C853"

            format_selector = ft.SegmentedButton(
                selected={"standard"} if active_is_standard else {"amnezia"},
                allow_multiple_selection=False,
                segments=[
                    ft.Segment(value="standard", label=ft.Text("Standard WireGuard")),
                    ft.Segment(value="amnezia", label=ft.Text("AmneziaWG (Anti-DPI)")),
                ],
            )

            def _on_format_select(e):
                val = list(format_selector.selected)[0] if format_selector.selected else "standard"
                if val == "standard":
                    active_conf[0] = conf_standard
                    qr_caption.value = "Scan with Official WireGuard App"
                else:
                    active_conf[0] = conf_amnezia
                    qr_caption.value = "Scan with AmneziaWG App (Anti-DPI Obfuscation)"
                txt_preview.value = active_conf[0]
                new_b64 = generate_qr_code_base64(active_conf[0])
                qr_image.src_base64 = new_b64
                modal.update()

            format_selector.on_change = _on_format_select

            def _copy_and_close(e):
                self.page.set_clipboard(active_conf[0])
                fmt_name = "Standard WireGuard" if active_conf[0] == conf_standard else "AmneziaWG"
                self._show_toast(f"Config {fmt_name} copied to clipboard!")
                self._close_dialog(modal)

            modal = ft.AlertDialog(
                title=ft.Row(
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                    controls=[
                        ft.Text(f"{server.country} - {server.city} ({ip})", size=16, weight=ft.FontWeight.BOLD),
                        ft.Container(
                            padding=ft.padding.symmetric(horizontal=8, vertical=3),
                            bgcolor=badge_bg,
                            border_radius=4,
                            content=ft.Text(lat_badge, size=11, color="#FFFFFF", weight=ft.FontWeight.BOLD),
                        ),
                    ],
                ),
                content=ft.Container(
                    width=700,
                    height=400 if is_placeholder_key(server.public_key) else 370,
                    content=ft.Column(
                        spacing=10,
                        controls=[
                            # FIX: Show clear warning when server public key is fake/placeholder
                            *(
                                [ft.Container(
                                    padding=ft.padding.symmetric(horizontal=12, vertical=8),
                                    bgcolor="#4E342E",
                                    border_radius=6,
                                    border=ft.border.all(1, "#FFB300"),
                                    content=ft.Row(
                                        spacing=8,
                                        controls=[
                                            ft.Icon(ft.icons.WARNING_AMBER_ROUNDED, color="#FFB300", size=20),
                                            ft.Column(
                                                spacing=2,
                                                expand=True,
                                                controls=[
                                                    ft.Text("Server Public Key Unverified!", size=12, weight=ft.FontWeight.BOLD, color="#FFB300"),
                                                    ft.Text(
            "This config uses an unverified placeholder key and may not connect. "
            "Click '🔑 Update Keys' first to fetch verified server public keys.",
                                                        size=11, color="#FFCC80",
                                                    ),
                                                ],
                                            ),
                                        ],
                                    ),
                                )]
                                if is_placeholder_key(server.public_key) else []
                            ),
                            ft.Row(
                                alignment=ft.MainAxisAlignment.CENTER,
                                controls=[format_selector],
                            ),
                            ft.Row(
                                spacing=16,
                                controls=[
                                    ft.Column(
                                        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                                        spacing=8,
                                        controls=[
                                            qr_image,
                                            qr_caption,
                                        ],
                                    ),
                                    ft.Column(
                                        expand=True,
                                        spacing=8,
                                        controls=[
                                            ft.Text("Generated Configuration Preview:", size=12, weight=ft.FontWeight.W_500),
                                            txt_preview,
                                        ],
                                    ),
                                ],
                            ),
                        ],
                    ),
                ),
                actions=[
                    ft.ElevatedButton(
                        text="Copy Config to Clipboard",
                        icon=ft.icons.CONTENT_COPY_ROUNDED,
                        style=ft.ButtonStyle(bgcolor="#00D09C", color="#000000"),
                        on_click=_copy_and_close,
                    ),
                    ft.TextButton(text="Close", on_click=lambda e: self._close_dialog(modal)),
                ],
                actions_alignment=ft.MainAxisAlignment.END,
            )

            self._open_dialog(modal)
        except Exception as err:
            self._show_toast(f"Error displaying QR dialog: {err}", is_error=True)

    def _copy_config_to_clipboard(self, server: ServerMetadata, ip: str):
        try:
            self._ensure_private_key(lambda: self._do_copy_config_to_clipboard(server, ip))
        except Exception as err:
            self._show_toast(f"Error copying config: {err}", is_error=True)

    def _do_copy_config_to_clipboard(self, server: ServerMetadata, ip: str):
        try:
            params = self._get_current_params()
            flag = country_code_to_flag(server.country_code)
            is_domain = (ip == server.hostname) or not re.match(r'^\d+\.\d+\.\d+\.\d+$', str(ip))
            tunnel_name = f"{flag} {server.city} ({server.country}){' — Domain' if is_domain else ''}"
            conf_text = build_amnezia_config(
                client_private_key=self.blueprint.user_interface.private_key,
                client_address=self.blueprint.user_interface.address or ("10.2.0.2/32" if False else "10.14.0.2/16"),
                client_dns=self.blueprint.user_interface.dns or ("10.2.0.1" if False else "162.252.172.57"),
                server_public_key=server.public_key or "YOUR_SERVER_PUBLIC_KEY",
                endpoint_ip=ip,
                endpoint_port=server.port,
                amnezia_params=params,
                tunnel_name=tunnel_name,
            )
            self.page.set_clipboard(conf_text)
            tag = "Domain" if is_domain else "IP"
            self._show_toast(f"Config {tunnel_name} ({ip}) copied to clipboard!")
        except Exception as err:
            self._show_toast(f"Error copying config: {err}", is_error=True)

    # -------------------------------------------------------------------------
    # Batch ZIP Export
    # -------------------------------------------------------------------------
    def _export_batch_zip(self, e):
        self._ensure_private_key(lambda: self._do_export_batch_zip(e))

    def _do_export_batch_zip(self, e):
        targets_to_export = []
        seen_domains = set()

        # 1. Always include Subdomain / Hostname Endpoint config for every cluster
        for s in self.blueprint.servers:
            if s.hostname and s.hostname not in seen_domains:
                seen_domains.add(s.hostname)
                targets_to_export.append({
                    "country": s.country,
                    "city": s.city,
                    "hostname": s.hostname,
                    "public_key": s.public_key,
                    "endpoint_ip": s.hostname,
                    "port": s.port,
                    "is_domain": True,
                })

        # 2. Include tested working raw IPs (or all resolved IPs if scan hasn't run)
        if self.working_configs:
            targets_to_export.extend(self.working_configs)
        else:
            for s in self.blueprint.servers:
                for ip in s.resolved_ips:
                    targets_to_export.append({
                        "country": s.country,
                        "city": s.city,
                        "hostname": s.hostname,
                        "public_key": s.public_key,
                        "endpoint_ip": ip,
                        "port": s.port,
                        "is_domain": False,
                    })

        if not targets_to_export:
            self._show_toast("No servers found to export.", is_error=True)
            return

        export_dir = os.path.expanduser("~/Downloads")
        if not os.path.exists(export_dir):
            export_dir = os.getcwd()

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        prov_prefix = "surfshark"
        zip_filename = f"{prov_prefix}_amneziawg_{timestamp}.zip"
        target_path = os.path.join(export_dir, zip_filename)

        params = self._get_current_params()
        generate_batch_zip(
            server_configs=targets_to_export,
            user_interface=self.blueprint.to_dict()["user_interface"],
            amnezia_params=params,
            output_path=target_path,
        )

        domain_count = len(seen_domains)
        ip_count = len(targets_to_export) - domain_count
        self._show_toast(f"Exported {len(targets_to_export)} configs to: {target_path}")

        # Inform modal
        modal = ft.AlertDialog(
            title=ft.Text("Batch Export Successful", weight=ft.FontWeight.BOLD),
            content=ft.Column(
                tight=True,
                spacing=8,
                controls=[
                    ft.Text(f"ZIP archive generated with {len(targets_to_export)} AmneziaWG configs:"),
                    ft.Text(f"• {domain_count} configs using official domain endpoints", size=12, color="#26C6DA"),
                    ft.Text(f"• {ip_count} configs using raw IP endpoints", size=12, color="#00C853"),
                    ft.Text(f"Saved file path:\n{target_path}", font_family="monospace", size=11, color="#00D09C"),
                ],
            ),
            actions=[
                ft.ElevatedButton(
                    text="Open Containing Folder",
                    icon=ft.icons.FOLDER_OPEN_ROUNDED,
                    on_click=lambda e: self._reveal_file_in_finder(target_path),
                ),
                ft.TextButton(text="OK", on_click=lambda e: self._close_dialog(modal)),
            ],
        )
        self._open_dialog(modal)

    def _reveal_file_in_finder(self, path: str):
        import subprocess
        try:
            subprocess.run(["open", "-R", path])
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # Shadowrocket Integration (Iran Balanced AmneziaWG)
    # -------------------------------------------------------------------------
    def _kill_shadowrocket_if_running(self, wait_sec: float = 0.5):
        """Force-quits running Shadowrocket so file modifications to ServerManager are cleanly applied."""
        import subprocess, time
        try:
            subprocess.run("killall -9 Shadowrocket 2>/dev/null || pkill -9 -f Shadowrocket 2>/dev/null || true", shell=True)
            time.sleep(wait_sec)
        except Exception:
            pass

    def _launch_shadowrocket(self):
        """Launches Shadowrocket or brings its window to the front."""
        import subprocess
        try:
            subprocess.Popen(["open", "-a", "Shadowrocket"])
        except Exception:
            pass

    def _collect_export_targets(self, only_ips: bool = True) -> Tuple[List[dict], int, int]:
        """
        Collects server targets for export.
        Returns (targets_to_export, domain_count, ip_count).
        ONLY raw IP addresses are exported. Subdomains are strictly excluded
        because domain endpoints are blocked and never connect in Iran.
        Respects active continent filter if set.
        """
        targets_to_export = []
        sel_cont = self.dd_continent.value if hasattr(self, "dd_continent") and self.dd_continent.value else "all"

        def _cont_matches(c_val: str) -> bool:
            if sel_cont == "all":
                return True
            if sel_cont == "Americas":
                return c_val in ("Americas", "North America", "South America")
            return c_val == sel_cont

        if self.working_configs:
            for c in self.working_configs:
                endpoint = c.get("endpoint_ip") or c.get("hostname", "")
                if only_ips and (c.get("is_domain", False) or not ShadowrocketStorage.is_ipv4(endpoint)):
                    continue
                if not _cont_matches(c.get("continent", "")):
                    continue
                targets_to_export.append(c)
        else:
            for s in self.blueprint.servers:
                if not _cont_matches(s.continent):
                    continue
                for ip in s.resolved_ips:
                    if ShadowrocketStorage.is_ipv4(ip):
                        targets_to_export.append({
                            "continent": s.continent,
                            "country": s.country,
                            "city": s.city,
                            "country_code": s.country_code,
                            "hostname": s.hostname,
                            "public_key": s.public_key,
                            "endpoint_ip": ip,
                            "port": s.port,
                            "is_domain": False,
                        })

        domain_count = 0
        ip_count = len(targets_to_export)
        return targets_to_export, domain_count, ip_count

    def _export_to_shadowrocket(self, e=None):
        """Primary action: Exports all servers to Shadowrocket with Iran Balanced obfuscation."""
        self._ensure_private_key(lambda: self._do_export_to_shadowrocket(e))

    def _do_export_to_shadowrocket(self, e=None):
        import subprocess

        targets_to_export, domain_count, ip_count = self._collect_export_targets()
        if not targets_to_export:
            self._show_toast("No servers found to export.", is_error=True)
            return

        params = self._get_current_params()
        export_dir = os.path.expanduser("~/Downloads")

        bundle = export_shadowrocket_bundle(
            server_configs=targets_to_export,
            user_interface=self.blueprint.to_dict()["user_interface"],
            amnezia_params=params,
            output_dir=export_dir,
        )
        self._last_sr_bundle = bundle

        # 1. Close running Shadowrocket so file write is clean
        self._kill_shadowrocket_if_running()

        # 2. Direct injection into Shadowrocket's native Local Servers database
        inject_res = inject_servers_to_shadowrocket_storage(
            server_configs=targets_to_export,
            user_interface=self.blueprint.to_dict()["user_interface"],
            amnezia_params=params,
        )

        # 3. Copy raw wg:// URLs to macOS clipboard as seamless fallback
        try:
            self.page.set_clipboard(bundle["raw_subscription_text"])
            p = subprocess.Popen(["pbcopy"], stdin=subprocess.PIPE)
            p.communicate(input=bundle["raw_subscription_text"].encode("utf-8"))
        except Exception:
            pass

        # 4. Relaunch Shadowrocket with fresh servers
        self._launch_shadowrocket()

        added_cnt = inject_res.get("added_count", len(targets_to_export))
        total_cnt = inject_res.get("total_count", added_cnt)
        self._show_toast(f"✅ {added_cnt} servers exported to Shadowrocket!")

        storage_info_text = (
            f"✅ Shadowrocket database updated directly:\n"
            f"• {added_cnt} new servers added to Local Servers.\n"
            f"• Existing servers preserved (Total Clusters: {total_cnt}).\n"
            f"• Automatic backup saved in Group Containers."
            if inject_res.get("success")
            else "⚠️ Local database not found; wg:// links copied to clipboard."
        )

        zip_btn = ft.ElevatedButton(
            text="Open ZIP File",
            icon=ft.icons.FOLDER_ZIP_ROUNDED,
            style=ft.ButtonStyle(bgcolor="#00897B", color="#FFFFFF"),
            on_click=lambda e, zp=bundle.get("zip_path"): self._reveal_file_in_finder(zp) if zp else None,
        ) if bundle.get("zip_path") else ft.Container()

        modal = ft.AlertDialog(
            title=ft.Row(
                spacing=8,
                controls=[
                    ft.Icon(ft.icons.ROCKET_LAUNCH_ROUNDED, color="#FF6F00", size=24),
                    ft.Text("Export Servers to Shadowrocket Local Servers", weight=ft.FontWeight.BOLD, size=15),
                ],
            ),
            content=ft.Column(
                tight=True,
                spacing=10,
                width=560,
                controls=[
                    ft.Container(
                        padding=10,
                        bgcolor="#1B5E20" if inject_res.get("success") else "#2E1C0A",
                        border=ft.border.all(1, "#00E676" if inject_res.get("success") else "#FF8F00"),
                        border_radius=8,
                        content=ft.Column(
                            spacing=4,
                            controls=[
                                ft.Row(
                                    spacing=6,
                                    controls=[
                                        ft.Icon(ft.icons.CHECK_CIRCLE_ROUNDED, color="#00E676", size=18),
                                        ft.Text("Servers injected directly into Shadowrocket Local Servers:", weight=ft.FontWeight.BOLD, size=13, color="#E8F5E9"),
                                    ],
                                ),
                                ft.Text(storage_info_text, size=11, color="#C8E6C9"),
                                ft.Text(f"• {domain_count} domain configs + {ip_count} raw IP configs", size=11, color="#B9F6CA"),
                                ft.Text(
                                    f"• Obfuscation: Iran Balanced (Jc={params.jc}, Jmin={params.jmin}, Jmax={params.jmax}, S1={params.s1}, S2={params.s2}, H1={params.h1}..H4={params.h4})",
                                    size=10,
                                    color="#FFF59D",
                                    font_family="monospace",
                                ),
                            ],
                        ),
                    ),
                    ft.Container(
                        padding=10,
                        bgcolor="#1C2833",
                        border_radius=8,
                        content=ft.Column(
                            spacing=6,
                            controls=[
                                ft.Text("⚡ Shadowrocket URL Test Guide:", weight=ft.FontWeight.BOLD, size=12, color="#90CAF9"),
                                ft.Text(
                                    "1. Shadowrocket refreshed and servers are listed in Local Servers.\n"
                                    "2. Click 'Test Latency' at the top of the server list.\n"
                                    "3. Servers showing green numerical latency (e.g. 120ms) are live and accessible.\n"
                                    "4. wg:// links copied to clipboard, and ZIP package is in Downloads.",
                                    size=11,
                                    color="#ECEFF1",
                                ),
                            ],
                        ),
                    ),
                    ft.Text(f"File path: {bundle['bundle_dir']}", size=10, color="#78909C", font_family="monospace"),
                ],
            ),
            actions=[
                ft.ElevatedButton(
                    text="Launch Shadowrocket",
                    icon=ft.icons.ROCKET_LAUNCH_ROUNDED,
                    style=ft.ButtonStyle(bgcolor="#FF6F00", color="#FFFFFF"),
                    on_click=lambda e: subprocess.Popen(["open", "-a", "Shadowrocket"]),
                ),
                zip_btn,
                ft.ElevatedButton(
                    text="Reveal in Finder",
                    icon=ft.icons.FOLDER_OPEN_ROUNDED,
                    on_click=lambda e: self._reveal_file_in_finder(bundle["bundle_dir"]),
                ),
                ft.ElevatedButton(
                    text="Copy wg:// Links",
                    icon=ft.icons.COPY_ALL_ROUNDED,
                    style=ft.ButtonStyle(bgcolor="#00897B", color="#FFFFFF"),
                    on_click=lambda e: self._copy_text_to_clipboard(bundle["raw_subscription_text"], "All wg:// links copied to clipboard!"),
                ),
                ft.TextButton(text="Close", on_click=lambda e: self._close_dialog(modal)),
            ],
        )
        self._open_dialog(modal)

    def _copy_shadowrocket_subscription(self, e=None):
        """Generates and copies the Shadowrocket subscription string to clipboard."""
        self._ensure_private_key(lambda: self._do_copy_shadowrocket_subscription())

    def _do_copy_shadowrocket_subscription(self):
        import subprocess

        targets_to_export, _, _ = self._collect_export_targets()
        if not targets_to_export:
            self._show_toast("No servers found to generate subscription.", is_error=True)
            return

        params = self._get_current_params()
        _, b64_sub = generate_shadowrocket_subscription(
            server_configs=targets_to_export,
            user_interface=self.blueprint.to_dict()["user_interface"],
            amnezia_params=params,
        )
        try:
            self.page.set_clipboard(b64_sub)
            p = subprocess.Popen(["pbcopy"], stdin=subprocess.PIPE)
            p.communicate(input=b64_sub.encode("utf-8"))
        except Exception:
            pass
        self._show_toast(f"📋 Subscription URL with {len(targets_to_export)} servers copied to clipboard!")

    def _open_shadowrocket_folder(self, e=None):
        """Opens the last exported Shadowrocket folder or the Downloads directory."""
        if hasattr(self, "_last_sr_bundle") and self._last_sr_bundle.get("bundle_dir"):
            self._reveal_file_in_finder(self._last_sr_bundle["bundle_dir"])
        else:
            self._export_to_shadowrocket(e)

    def _open_single_shadowrocket(self, server: ServerMetadata, ip: str, latency: Optional[float] = None):
        """Exports a single IP config directly into Shadowrocket Local Servers and opens it."""
        import subprocess

        priv_key = self.blueprint.user_interface.private_key
        if not priv_key or len(priv_key.strip()) < 20:
            self._ensure_private_key(lambda: self._open_single_shadowrocket(server, ip, latency))
            return

        server_info = {
            "country": server.country,
            "country_code": server.country_code,
            "city": server.city,
            "hostname": server.hostname,
            "public_key": server.public_key,
            "endpoint_ip": ip,
            "port": server.port,
            "latency_ms": latency,
            "is_domain": False,
        }
        params = self._get_current_params()
        url = build_shadowrocket_wg_url(server_info, self.blueprint.to_dict()["user_interface"], params)

        try:
            self.page.set_clipboard(url)
            p = subprocess.Popen(["pbcopy"], stdin=subprocess.PIPE)
            p.communicate(input=url.encode("utf-8"))
        except Exception:
            pass

        # Direct injection into Local Servers
        self._kill_shadowrocket_if_running()
        inject_res = inject_servers_to_shadowrocket_storage(
            server_configs=[server_info],
            user_interface=self.blueprint.to_dict()["user_interface"],
            amnezia_params=params,
        )

        if inject_res.get("success"):
            self._launch_shadowrocket()
            self._show_toast(f"🚀 Server {server.city} ({ip}) exported to Shadowrocket!")
        else:
            try:
                subprocess.Popen(["open", f"shadowrocket://add/{url}"])
            except Exception:
                self._launch_shadowrocket()
            self._show_toast(f"🚀 Shadowrocket link for {server.city} ({ip}) opened!")

    def _export_country_to_shadowrocket(self, country: str, servers: List[ServerMetadata]):
        """Exports all servers of a specific country directly to Shadowrocket Local Servers."""
        self._ensure_private_key(lambda: self._do_export_country_to_shadowrocket(country, servers))

    def _do_export_country_to_shadowrocket(self, country: str, servers: List[ServerMetadata]):
        import subprocess

        targets = []
        for s in servers:
            results = self.scan_results.get(s.hostname, [])
            working = [r for r in results if r.is_reachable]
            if working:
                for r in working:
                    targets.append({
                        "country": s.country,
                        "country_code": s.country_code,
                        "city": s.city,
                        "hostname": s.hostname,
                        "public_key": s.public_key,
                        "endpoint_ip": r.ip,
                        "port": r.port,
                        "latency_ms": r.latency_ms,
                        "is_domain": False,
                    })
            else:
                for ip in s.resolved_ips:
                    targets.append({
                        "country": s.country,
                        "country_code": s.country_code,
                        "city": s.city,
                        "hostname": s.hostname,
                        "public_key": s.public_key,
                        "endpoint_ip": ip,
                        "port": s.port,
                        "is_domain": False,
                    })

        if not targets:
            self._show_toast(f"No servers found for {country}.", is_error=True)
            return

        params = self._get_current_params()
        export_dir = os.path.expanduser("~/Downloads")
        bundle = export_shadowrocket_bundle(
            server_configs=targets,
            user_interface=self.blueprint.to_dict()["user_interface"],
            amnezia_params=params,
            output_dir=export_dir,
        )

        # Direct injection into Local Servers database
        self._kill_shadowrocket_if_running()
        inject_res = inject_servers_to_shadowrocket_storage(
            server_configs=targets,
            user_interface=self.blueprint.to_dict()["user_interface"],
            amnezia_params=params,
        )

        try:
            self.page.set_clipboard(bundle["raw_subscription_text"])
            p = subprocess.Popen(["pbcopy"], stdin=subprocess.PIPE)
            p.communicate(input=bundle["raw_subscription_text"].encode("utf-8"))
        except Exception:
            pass

        self._launch_shadowrocket()
        added_cnt = inject_res.get("added_count", len(targets))
        self._show_toast(f"🚀 {added_cnt} servers of {country} added to Shadowrocket!")

    # -------------------------------------------------------------------------
    # Shadowrocket Test Results Sync, Management & Cleanup (Two-Way Integration)
    # -------------------------------------------------------------------------
    def _apply_shadowrocket_results(self, sr_results: dict, is_auto: bool = False) -> int:
        """
        Processes Shadowrocket test results, maps IPs to servers, updates scan_results,
        rebuilds working_configs, persists cache, and refreshes UI controls.
        Returns the number of working servers found.
        """
        if not sr_results:
            return 0

        # Check if any IP in results actually has a positive ping
        has_any_positive_pings = any(r.get("ping", 0) > 0 for r in sr_results.values() if r.get("is_ip"))
        if not has_any_positive_pings:
            if not is_auto:
                self.lbl_status.value = "⚠️ No positive pings recorded in Shadowrocket database (all pings are 0ms)."
                self.lbl_status.color = "#FFA726"
                try:
                    self.lbl_status.update()
                except Exception:
                    pass
                self._show_toast(
                    "⚠️ No working pings found in Shadowrocket. Ensure tests completed inside Shadowrocket.",
                    is_error=True,
                )
            return 0

        # Map IP -> Cluster ServerMetadata & CC -> Country
        ip_to_server = {}
        cc_to_country = {}
        for s in self.blueprint.servers:
            if s.country_code:
                cc_to_country[s.country_code.upper().strip()] = s.country
            for ip in s.resolved_ips:
                ip_to_server[ip] = s
        for _, (c_name, c_code) in COUNTRY_ALIASES.items():
            cc_to_country[c_code.upper().strip()] = c_name

        updated_ips_count = 0
        working_count = 0

        try:
            # Update self.scan_results with Shadowrocket's real latency
            for ip, res_info in sr_results.items():
                if not res_info.get("is_ip", False):
                    continue

                ping = res_info.get("ping", 0)
                is_reach = res_info.get("is_reachable", False)
                if is_reach:
                    working_count += 1

                server = ip_to_server.get(ip)
                h = server.hostname if server else f"custom_{ip}"

                if h not in self.scan_results:
                    self.scan_results[h] = []

                flag_cc = (res_info.get("flag") or (server.country_code if server else "UN")).upper().strip()
                country_name = server.country if server else cc_to_country.get(flag_cc, "Unknown")
                city_name = server.city if server else "Cluster"

                server_dict = {
                    "continent": server.continent if server else "Global",
                    "country": country_name,
                    "country_code": flag_cc,
                    "city": city_name,
                    "hostname": h,
                    "public_key": server.public_key if server else "",
                    "port": res_info.get("port", 51820),
                }

                check_res = CheckResult(
                    ip=ip,
                    port=res_info.get("port", 51820),
                    is_reachable=is_reach,
                    latency_ms=float(ping) if is_reach else 9999.0,
                    status="handshake_ok" if is_reach else "timed_out",
                    server_info=server_dict,
                )

                existing_idx = next((i for i, ex in enumerate(self.scan_results[h]) if ex.ip == ip), None)
                if existing_idx is not None:
                    self.scan_results[h][existing_idx] = check_res
                else:
                    self.scan_results[h].append(check_res)
                updated_ips_count += 1

            # Re-build self.working_configs with reachable IP configs
            self.working_configs = []
            for h, res_list in self.scan_results.items():
                server = next((s for s in self.blueprint.servers if s.hostname == h), None)
                for r in res_list:
                    if r.is_reachable and r.latency_ms < 9000:
                        s_info = r.server_info or {}
                        c_code = (server.country_code if server else s_info.get("country_code", "UN")).upper().strip()
                        c_name = server.country if server else s_info.get("country", cc_to_country.get(c_code, "Unknown"))
                        c_city = server.city if server else s_info.get("city", "Cluster")
                        self.working_configs.append({
                            "country": c_name,
                            "country_code": c_code,
                            "city": c_city,
                            "hostname": h,
                            "public_key": server.public_key if server else s_info.get("public_key", ""),
                            "endpoint_ip": r.ip,
                            "port": r.port,
                            "latency_ms": r.latency_ms,
                            "packet_loss": 0.0,
                            "is_domain": False,
                        })

            # Save to active provider scan cache
            self.last_scan_data = save_scan_cache(self.scan_results, self.working_configs, filepath=self.current_scan_cache_file)

            # Update UI components
            self._update_prev_scan_card()
            self._refresh_summary_cards()
            self._render_server_list(
                filter_query=self.search_field.value if hasattr(self, "search_field") else "",
                only_working=self.filter_working_only.value if hasattr(self, "filter_working_only") else False,
            )

            top_5 = self.last_scan_data.get("top_5", [])

            if is_auto:
                self.lbl_status.value = f"⚡ Shadowrocket auto-updated: {working_count} working servers verified."
                self.lbl_status.color = "#00E676"
                try:
                    self.lbl_status.update()
                except Exception:
                    pass
                self._show_toast(f"⚡ Fresh results received from Shadowrocket ({working_count} servers).")
            else:
                self.lbl_status.value = f"✅ Sync complete: {working_count} verified working servers."
                self.lbl_status.color = "#00C853"
                try:
                    self.lbl_status.update()
                except Exception:
                    pass

                self._show_toast(f"✅ Successfully synced {working_count} working servers from Shadowrocket!")

                # Show Informative Modal with results & Top 5
                top_items = []
                for s in top_5:
                    flag = country_code_to_flag(s.get("country_code", ""))
                    top_items.append(
                        ft.Text(
                            f"• {flag} {s.get('country')} — {s.get('city')} ({s.get('endpoint_ip')}): {int(s.get('latency_ms', 0))} ms",
                            size=12,
                            color="#A5D6A7",
                            weight=ft.FontWeight.BOLD,
                        )
                    )

                sync_dialog = ft.AlertDialog(
                    title=ft.Row(
                        spacing=8,
                        controls=[
                            ft.Icon(ft.icons.SYNC_ROUNDED, color="#00E5FF", size=24),
                            ft.Text("Shadowrocket Synchronization", weight=ft.FontWeight.BOLD, size=15),
                        ],
                    ),
                    content=ft.Column(
                        tight=True,
                        spacing=10,
                        width=520,
                        controls=[
                            ft.Container(
                                padding=10,
                                bgcolor="#13202E",
                                border=ft.border.all(1, "#00ACC1"),
                                border_radius=8,
                                content=ft.Column(
                                    spacing=4,
                                    controls=[
                                        ft.Row(
                                            spacing=6,
                                            controls=[
                                                ft.Icon(ft.icons.CHECK_CIRCLE_ROUNDED, color="#00E676", size=18),
                                                ft.Text("Synchronization Successful:", weight=ft.FontWeight.BOLD, size=13),
                                            ],
                                        ),
                                        ft.Text(f"• Verified working servers imported: {working_count}", size=12, color="#80DEEA"),
                                        ft.Text("• Latencies updated from accurate URL Request tests in Shadowrocket.", size=11, color="#B0BEC5"),
                                    ],
                                ),
                            ),
                            ft.Container(
                                padding=10,
                                bgcolor="#1C2833",
                                border_radius=8,
                                content=ft.Column(
                                    spacing=6,
                                    controls=[
                                        ft.Text("🏆 Top 5 Servers with Lowest Latency:", weight=ft.FontWeight.BOLD, size=12, color="#FFD54F"),
                                        ft.Column(controls=top_items, spacing=3),
                                    ],
                                ),
                            ) if top_items else ft.Container(),
                        ],
                    ),
                    actions=[
                        ft.ElevatedButton(
                            text="🏆 View Top 5 Modal",
                            icon=ft.icons.EMOJI_EVENTS_ROUNDED,
                            style=ft.ButtonStyle(bgcolor="#FF8F00", color="#000000"),
                            on_click=lambda e: (self._close_dialog(sync_dialog), self._show_top5_announcement_modal(top_5)),
                        ) if top_5 else ft.Container(),
                        ft.ElevatedButton(
                            text="⚙️ Shadowrocket Manager",
                            icon=ft.icons.SETTINGS_APPLICATIONS_ROUNDED,
                            style=ft.ButtonStyle(bgcolor="#455A64", color="#FFFFFF"),
                            on_click=lambda e: (self._close_dialog(sync_dialog), self._open_shadowrocket_manager_dialog()),
                        ),
                        ft.TextButton(text="Close", on_click=lambda e: self._close_dialog(sync_dialog)),
                    ],
                )
                self._open_dialog(sync_dialog)

            return working_count
        except Exception as ex:
            logger.error(f"Error during shadowrocket sync: {ex}", exc_info=True)
            if not is_auto:
                self._show_toast(f"Error processing sync data: {ex}", is_error=True)
            return 0

    def _sync_results_from_shadowrocket(self, e=None):
        """
        Reads actual latency and connection test results from Shadowrocket's ServerManager,
        and updates the app's server status, latencies, working count, and Top 5 in background.
        """
        if getattr(self, "_is_syncing_sr", False):
            self._show_toast("Sync in progress...")
            return

        self._is_syncing_sr = True
        self.btn_sync_shadowrocket.disabled = True
        self.btn_sync_shadowrocket.text = "🔄 Syncing..."
        self.lbl_status.value = "🔄 Reading test results from Shadowrocket..."
        self.lbl_status.color = "#00E5FF"
        try:
            self.lbl_status.update()
            self.btn_sync_shadowrocket.update()
        except Exception:
            pass

        def _worker():
            try:
                sr_results = read_shadowrocket_test_results()
                if not sr_results:
                    self._show_toast("Shadowrocket test database not found or empty.", is_error=True)
                    self.lbl_status.value = "Shadowrocket database is empty."
                    self.lbl_status.color = "#FF5252"
                    try:
                        self.lbl_status.update()
                    except Exception:
                        pass
                    return

                self._apply_shadowrocket_results(sr_results, is_auto=False)
            except Exception as ex:
                logger.error(f"Failed to read Shadowrocket results: {ex}", exc_info=True)
                self._show_toast(f"Error reading Shadowrocket results: {ex}", is_error=True)
                self.lbl_status.value = f"Error reading results: {ex}"
                self.lbl_status.color = "#FF5252"
                try:
                    self.lbl_status.update()
                except Exception:
                    pass
            finally:
                self._is_syncing_sr = False
                self.btn_sync_shadowrocket.disabled = False
                self.btn_sync_shadowrocket.text = "🔄 Sync from Shadowrocket"
                try:
                    self.btn_sync_shadowrocket.update()
                    self.page.update()
                except Exception:
                    pass

        threading.Thread(target=_worker, daemon=True).start()

    def _open_shadowrocket_manager_dialog(self, e=None):
        """
        Comprehensive manager for Shadowrocket's Local Servers:
        - Displays live counts (total, working, failed, subdomains)
        - Purges failed and domain servers
        - Clears all local servers with confirmation
        - Triggers sync and opens app
        """
        import subprocess

        try:
            stats = get_shadowrocket_storage_stats()
        except Exception as ex:
            self._show_toast(f"Error reading Shadowrocket status: {ex}", is_error=True)
            return

        total = stats.get("total", 0)
        working = stats.get("working_ips", 0)
        failed = stats.get("failed_ips", 0)
        domains = stats.get("domain_servers", 0)

        manager_dialog = ft.AlertDialog(
            title=ft.Row(
                spacing=8,
                controls=[
                    ft.Icon(ft.icons.SETTINGS_APPLICATIONS_ROUNDED, color="#00E5FF", size=24),
                    ft.Text("Shadowrocket Local Server Manager", weight=ft.FontWeight.BOLD, size=15),
                ],
            ),
            content=ft.Column(
                tight=True,
                spacing=12,
                width=520,
                controls=[
                    # Current Status Box
                    ft.Container(
                        padding=12,
                        bgcolor="#13202E",
                        border=ft.border.all(1, "#00ACC1"),
                        border_radius=8,
                        content=ft.Column(
                            spacing=6,
                            controls=[
                                ft.Text("📊 Current Local Servers Database Status:", weight=ft.FontWeight.BOLD, size=13, color="#E0F7FA"),
                                ft.Row(
                                    spacing=8,
                                    wrap=True,
                                    controls=[
                                        ft.Container(
                                            padding=ft.padding.symmetric(horizontal=8, vertical=4),
                                            bgcolor="#263238",
                                            border_radius=4,
                                            content=ft.Text(f"Total Clusters: {total}", size=11, color="#B0BEC5", weight=ft.FontWeight.BOLD),
                                        ),
                                        ft.Container(
                                            padding=ft.padding.symmetric(horizontal=8, vertical=4),
                                            bgcolor="#1B5E20",
                                            border_radius=4,
                                            content=ft.Text(f"🟢 Working IPs: {working}", size=11, color="#A5D6A7", weight=ft.FontWeight.BOLD),
                                        ),
                                        ft.Container(
                                            padding=ft.padding.symmetric(horizontal=8, vertical=4),
                                            bgcolor="#B71C1C",
                                            border_radius=4,
                                            content=ft.Text(f"🔴 Failed / 0ms: {failed}", size=11, color="#FFCDD2", weight=ft.FontWeight.BOLD),
                                        ),
                                        ft.Container(
                                            padding=ft.padding.symmetric(horizontal=8, vertical=4),
                                            bgcolor="#E65100",
                                            border_radius=4,
                                            content=ft.Text(f"🌐 Subdomain Endpoints: {domains}", size=11, color="#FFE082", weight=ft.FontWeight.BOLD),
                                        ) if domains > 0 else ft.Container(),
                                    ],
                                ),
                            ],
                        ),
                    ),
                    # Action Cards
                    ft.Container(
                        padding=10,
                        bgcolor="#1C2833",
                        border_radius=8,
                        content=ft.Column(
                            spacing=8,
                            controls=[
                                ft.Text("Management & Cleanup Actions:", size=12, weight=ft.FontWeight.BOLD, color="#B0BEC5"),
                                ft.Row(
                                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                                    controls=[
                                        ft.Column(
                                            spacing=2,
                                            controls=[
                                                ft.Text("🧹 Purge Failed & Domain Servers", weight=ft.FontWeight.BOLD, size=12, color="#FFB74D"),
                                                ft.Text("Purge all servers with 0ms or failed pings while keeping working servers", size=11, color="#90A4AE"),
                                            ],
                                        ),
                                        ft.ElevatedButton(
                                            text="Purge Failed & Domains",
                                            icon=ft.icons.CLEANING_SERVICES_ROUNDED,
                                            style=ft.ButtonStyle(bgcolor="#E65100", color="#FFFFFF"),
                                            on_click=lambda e: (self._close_dialog(manager_dialog), self._clean_shadowrocket_failed_servers()),
                                        ),
                                    ],
                                ),
                                ft.Divider(height=1, color="#37474F"),
                                ft.Row(
                                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                                    controls=[
                                        ft.Column(
                                            spacing=2,
                                            controls=[
                                                ft.Text("🗑️ Clear All Local Servers", weight=ft.FontWeight.BOLD, size=12, color="#EF5350"),
                                                ft.Text("Delete all local servers from Shadowrocket database", size=11, color="#90A4AE"),
                                            ],
                                        ),
                                        ft.ElevatedButton(
                                            text="Clear All Servers",
                                            icon=ft.icons.DELETE_FOREVER_ROUNDED,
                                            style=ft.ButtonStyle(bgcolor="#C62828", color="#FFFFFF"),
                                            on_click=lambda e: (self._close_dialog(manager_dialog), self._confirm_clear_all_shadowrocket_servers()),
                                        ),
                                    ],
                                ),
                                ft.Divider(height=1, color="#37474F"),
                                ft.Row(
                                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                                    controls=[
                                        ft.Column(
                                            spacing=2,
                                            controls=[
                                                ft.Text("🔄 Sync Latency & Results", weight=ft.FontWeight.BOLD, size=12, color="#80DEEA"),
                                                ft.Text("Read test pings from Shadowrocket and update app", size=11, color="#90A4AE"),
                                            ],
                                        ),
                                        ft.ElevatedButton(
                                            text="Sync Now",
                                            icon=ft.icons.SYNC_ROUNDED,
                                            style=ft.ButtonStyle(bgcolor="#00897B", color="#FFFFFF"),
                                            on_click=lambda e: (self._close_dialog(manager_dialog), self._sync_results_from_shadowrocket()),
                                        ),
                                    ],
                                ),
                            ],
                        ),
                    ),
                ],
            ),
            actions=[
                ft.ElevatedButton(
                    text="🚀 Launch Shadowrocket",
                    icon=ft.icons.ROCKET_LAUNCH_ROUNDED,
                    style=ft.ButtonStyle(bgcolor="#FF6F00", color="#FFFFFF"),
                    on_click=lambda e: subprocess.Popen(["open", "-a", "Shadowrocket"]),
                ),
                ft.TextButton(text="Close", on_click=lambda e: self._close_dialog(manager_dialog)),
            ],
        )
        self._open_dialog(manager_dialog)

    def _confirm_clear_all_shadowrocket_servers(self, e=None):
        """
        Asks for user confirmation before clearing all local servers from Shadowrocket.
        """
        confirm_dlg = ft.AlertDialog(
            title=ft.Row(
                spacing=8,
                controls=[
                    ft.Icon(ft.icons.WARNING_AMBER_ROUNDED, color="#F44336", size=24),
                    ft.Text("Confirm Clear All Servers", weight=ft.FontWeight.BOLD, size=15),
                ],
            ),
            content=ft.Column(
                tight=True,
                spacing=10,
                width=460,
                controls=[
                    ft.Text(
                        "⚠️ Are you sure you want to remove ALL servers from Shadowrocket's Local Servers?",
                        size=13,
                        weight=ft.FontWeight.BOLD,
                        color="#FFCDD2",
                    ),
                    ft.Text(
                        "• All local servers will be removed, allowing a clean export.\n"
                        "• An automatic backup will be created in Group Containers before removal.",
                        size=12,
                        color="#B0BEC5",
                    ),
                ],
            ),
            actions=[
                ft.ElevatedButton(
                    text="Yes, Clear All Servers",
                    icon=ft.icons.DELETE_FOREVER_ROUNDED,
                    style=ft.ButtonStyle(bgcolor="#D32F2F", color="#FFFFFF"),
                    on_click=lambda e: (self._close_dialog(confirm_dlg), self._execute_clear_all_shadowrocket_servers()),
                ),
                ft.TextButton(text="Cancel", on_click=lambda e: self._close_dialog(confirm_dlg)),
            ],
        )
        self._open_dialog(confirm_dlg)

    def _execute_clear_all_shadowrocket_servers(self):
        """
        Executes removal of all local servers from Shadowrocket's ServerManager without restriction.
        """
        import subprocess

        try:
            self._kill_shadowrocket_if_running()
            res = clear_shadowrocket_all_servers()
            removed = res.get("removed_count", 0)
            self._launch_shadowrocket()

            self._show_toast(f"🗑️ All {removed} local servers cleared from Shadowrocket.")

            done_dialog = ft.AlertDialog(
                title=ft.Row(
                    spacing=8,
                    controls=[
                        ft.Icon(ft.icons.CHECK_CIRCLE_ROUNDED, color="#00E676", size=24),
                        ft.Text("Clear All Servers Completed", weight=ft.FontWeight.BOLD, size=15),
                    ],
                ),
                content=ft.Column(
                    tight=True,
                    spacing=8,
                    width=440,
                    controls=[
                        ft.Text(f"Removed {removed} local servers from Shadowrocket.", size=13),
                        ft.Text("Shadowrocket local list refreshed.", size=12, color="#80DEEA"),
                    ft.Text("You can now export fresh servers using 'Export to Shadowrocket'.", size=11, color="#90A4AE"),
                    ],
                ),
                actions=[
                    ft.ElevatedButton(
                        text="Launch Shadowrocket",
                        icon=ft.icons.ROCKET_LAUNCH_ROUNDED,
                        style=ft.ButtonStyle(bgcolor="#FF6F00", color="#FFFFFF"),
                        on_click=lambda e: self._launch_shadowrocket(),
                    ),
                    ft.TextButton(text="Close", on_click=lambda e: self._close_dialog(done_dialog)),
                ],
            )
            self._open_dialog(done_dialog)
        except Exception as ex:
            self._show_toast(f"Error clearing Shadowrocket servers: {ex}", is_error=True)

    def _clean_shadowrocket_failed_servers(self, e=None):
        """
        Removes all failed servers (ping <= 0) and any subdomains from Shadowrocket's ServerManager.
        """
        import subprocess

        try:
            # 1. First sync live test results if Shadowrocket is running
            if is_shadowrocket_running():
                try:
                    read_shadowrocket_test_results()
                except Exception:
                    pass

            # 2. Kill Shadowrocket so ServerManager modifications are applied cleanly
            self._kill_shadowrocket_if_running()

            res = purge_shadowrocket_failed_servers()
            if not res.get("success", True):
                self._launch_shadowrocket()
                err_msg = res.get("error", "No working servers with positive pings found.")
                self._show_toast(f"⚠️ {err_msg}", is_error=True)
                warn_dialog = ft.AlertDialog(
                    title=ft.Row(
                        spacing=8,
                        controls=[
                            ft.Icon(ft.icons.WARNING_AMBER_ROUNDED, color="#FFA000", size=24),
                            ft.Text("Cleanup Aborted (Safety Guard)", weight=ft.FontWeight.BOLD, size=15),
                        ],
                    ),
                    content=ft.Column(
                        tight=True,
                        spacing=8,
                        width=460,
                        controls=[
                            ft.Text(err_msg, size=13),
                            ft.Text(
                                "Abort Reason: No positive pings recorded yet. To prevent accidental loss of all servers, purge was aborted.",
                                size=12,
                                color="#B0BEC5",
                            ),
                            ft.Text(
                                "Hint: Click 'Sync from Shadowrocket' or run server tests first so working servers are registered.",
                                size=11,
                                color="#80DEEA",
                            ),
                        ],
                    ),
                    actions=[
                        ft.TextButton(text="Got it", on_click=lambda ev: self._close_dialog(warn_dialog)),
                    ],
                )
                self._open_dialog(warn_dialog)
                return

            removed = res.get("removed_count", 0)
            kept = res.get("kept_count", 0)
            removed_domains = res.get("removed_domains", 0)
            removed_failed = res.get("removed_failed", 0)

            self._launch_shadowrocket()

            self._show_toast(f"🧹 {removed} dead servers purged ({kept} working retained)")

            info_modal = ft.AlertDialog(
                title=ft.Row(
                    spacing=8,
                    controls=[
                        ft.Icon(ft.icons.CLEANING_SERVICES_ROUNDED, color="#00E676", size=24),
                        ft.Text("Purge Shadowrocket Servers", weight=ft.FontWeight.BOLD, size=15),
                    ],
                ),
                content=ft.Column(
                    tight=True,
                    spacing=8,
                    width=460,
                    controls=[
                        ft.Text("Shadowrocket Local Servers cleaned:", size=13, weight=ft.FontWeight.BOLD),
                        ft.Text(f"• Blocked domain servers removed: {removed_domains}", size=12, color="#FFAB91"),
                        ft.Text(f"• Failed / 0ms servers removed: {removed_failed}", size=12, color="#EF9A9A"),
                        ft.Text(f"• Working servers retained: {kept}", size=12, color="#A5D6A7", weight=ft.FontWeight.BOLD),
                    ],
                ),
                actions=[
                    ft.ElevatedButton(
                        text="Launch Shadowrocket",
                        icon=ft.icons.ROCKET_LAUNCH_ROUNDED,
                        style=ft.ButtonStyle(bgcolor="#FF6F00", color="#FFFFFF"),
                        on_click=lambda e: subprocess.Popen(["open", "-a", "Shadowrocket"]),
                    ),
                    ft.ElevatedButton(
                        text="⚙️ Manage Servers",
                        icon=ft.icons.SETTINGS_APPLICATIONS_ROUNDED,
                        style=ft.ButtonStyle(bgcolor="#455A64", color="#FFFFFF"),
                        on_click=lambda e: (self._close_dialog(info_modal), self._open_shadowrocket_manager_dialog()),
                    ),
                    ft.TextButton(text="Got it", on_click=lambda e: self._close_dialog(info_modal)),
                ],
            )
            self._open_dialog(info_modal)
        except Exception as ex:
            self._show_toast(f"Error purging Shadowrocket: {ex}", is_error=True)


    # -------------------------------------------------------------------------
    # Fetch Real Server Public Keys from Surfshark API (v2 feature)
    # -------------------------------------------------------------------------
    def _fetch_real_public_keys(self, e):
        """
        Fetches real WireGuard public keys for all servers from Surfshark's
        public API endpoint (no login required). Updates blueprint and re-renders
        server list with real keys marked (no more ⚠️ badges).
        """
        if self.is_scanning:
            self._show_toast("Scan in progress. Please wait.")
            return

        self.btn_fetch_keys.disabled = True
        self.progress_bar.visible = True
        self.progress_bar.value = None  # indeterminate
        self.lbl_status.value = "Fetching real public keys from Surfshark API..."
        self.page.update()

        def _worker():
            try:
                def _log(msg: str):
                    self.lbl_status.value = msg
                    self.page.update()

                updated = update_blueprint_with_api_keys(
                    blueprint=self.blueprint,
                    on_log=_log,
                    save_path=DEFAULT_DATA_FILE,
                )

                if updated > 0:
                    self._show_toast(f"✅ {updated} official server keys fetched and saved!")
                    self.lbl_status.value = f"Real keys fetched: {updated} servers updated."
                else:
                    # API might have changed response format — show detailed guidance
                    self._show_toast(
                        "⚠️ No keys updated. API may be temporarily unavailable."
                        "Or use 'Browser Harvest (Login)'.",
                        is_error=True,
                    )
                    self.lbl_status.value = "API key fetch: no keys updated. Check network or use Browser Harvest."

            except Exception as err:
                self._show_toast(f"Error fetching keys: {err}", is_error=True)
                self.lbl_status.value = f"Fetch keys error: {err}"
            finally:
                self.btn_fetch_keys.disabled = False
                self.progress_bar.visible = False
                self._refresh_summary_cards()
                self._render_server_list()

        threading.Thread(target=_worker, daemon=True).start()

    # -------------------------------------------------------------------------
    # Import Dialog (.conf or JSON)
    # -------------------------------------------------------------------------
    def _open_import_dialog(self, e):
        txt_paste = ft.TextField(
            label="Paste WireGuard Configuration Content (.conf)",
            multiline=True,
            min_lines=4,
            max_lines=7,
            text_size=11,
            hint_text="[Interface]\nPrivateKey = ...\n[Peer]\nPublicKey = ...\nEndpoint = ...",
        )
        txt_path = ft.TextField(
            label="Or File / Folder Path",
            hint_text="/path/to/surfshark.conf or directory",
        )

        def _do_import(e):
            conf_str = txt_paste.value.strip()
            p = txt_path.value.strip()

            if conf_str:
                from browser_harvest import parse_wireguard_conf_content
                parsed = parse_wireguard_conf_content(conf_str)
                if not parsed.get("endpoint"):
                    self._show_toast("Invalid configuration (No Endpoint found).", is_error=True)
                    return

                # Update credentials if present
                if parsed.get("private_key"):
                    self.blueprint.user_interface.private_key = parsed["private_key"]
                    self.txt_client_privkey.value = parsed["private_key"]
                if parsed.get("address"):
                    self.blueprint.user_interface.address = parsed["address"]
                    self.txt_client_addr.value = parsed["address"]
                if parsed.get("dns"):
                    self.blueprint.user_interface.dns = parsed["dns"]
                    self.txt_client_dns.value = parsed["dns"]

                ep = parsed["endpoint"]
                pub_key = parsed.get("public_key", "")
                port = parsed.get("port", 51820)

                matched = False
                for s in self.blueprint.servers:
                    if s.hostname == ep or ep in s.resolved_ips:
                        if pub_key:
                            s.public_key = pub_key
                        if re.match(r'^\d+\.\d+\.\d+\.\d+$', ep) and ep not in s.resolved_ips:
                            s.resolved_ips.insert(0, ep)
                        matched = True
                        break

                if not matched:
                    # Match by IP subnet
                    for s in self.blueprint.servers:
                        if s.resolved_ips and any(s_ip.rsplit('.', 1)[0] == ep.rsplit('.', 1)[0] for s_ip in s.resolved_ips if '.' in s_ip and '.' in ep):
                            if pub_key:
                                s.public_key = pub_key
                            s.resolved_ips.insert(0, ep)
                            matched = True
                            break

                if not matched:
                    new_s = ServerMetadata(
                        continent="Imported",
                        country="Custom",
                        country_code="CU",
                        city="Imported",
                        hostname=ep,
                        port=port,
                        public_key=pub_key,
                        resolved_ips=[ep] if re.match(r'^\d+\.\d+\.\d+\.\d+$', ep) else [],
                    )
                    self.blueprint.servers.insert(0, new_s)

                self._save_active_blueprint()
                self._update_privkey_badge()
                self._refresh_summary_cards()
                self._render_server_list()
                self._close_dialog(modal)
                self._show_toast("Config successfully imported, merged, and saved!")
                return

            if not p or not os.path.exists(p):
                self._show_toast("Please paste config text or provide a valid file path.", is_error=True)
                return

            imported_count = 0
            if os.path.isfile(p):
                if p.endswith(".json"):
                    try:
                        self.blueprint = load_blueprint(p)
                        self._save_active_blueprint()
                        imported_count = len(self.blueprint.servers)
                    except Exception as err:
                        self._show_toast(f"JSON load error: {err}", is_error=True)
                        return
                elif p.endswith(".conf"):
                    res = import_conf_file(p)
                    if res:
                        self.blueprint.servers.append(res)
                        imported_count = 1
            elif os.path.isdir(p):
                for fname in os.listdir(p):
                    if fname.endswith(".conf"):
                        full_f = os.path.join(p, fname)
                        res = import_conf_file(full_f)
                        if res:
                            self.blueprint.servers.append(res)
                            imported_count += 1

            self._save_active_blueprint()
            self._show_toast(f"Imported {imported_count} server profile(s)!")
            self._close_dialog(modal)
            self.txt_client_privkey.value = self.blueprint.user_interface.private_key
            self.txt_client_addr.value = self.blueprint.user_interface.address
            self.txt_client_dns.value = self.blueprint.user_interface.dns
            self._update_privkey_badge()
            self._refresh_summary_cards()
            self._render_server_list()

        modal = ft.AlertDialog(
            title=ft.Text("Import WireGuard Configuration / Blueprint", weight=ft.FontWeight.BOLD),
            content=ft.Container(
                width=560,
                content=ft.Column(
                    tight=True,
                    spacing=12,
                    controls=[
                    ft.Text("Paste downloaded Surfshark WireGuard config text or file path below:", size=11, color="#B0BEC5"),
                        txt_paste,
                        ft.Divider(),
                        txt_path,
                    ],
                ),
            ),
            actions=[
                ft.ElevatedButton(text="Import & Apply", icon=ft.icons.DOWNLOAD_DONE, on_click=_do_import),
                ft.TextButton(text="Cancel", on_click=lambda e: self._close_dialog(modal)),
            ],
        )
        self._open_dialog(modal)

    def _on_scan_mode_change(self, e):
        self.scan_mode = self.dd_scan_mode.value
        mode_names = {
            "smart": "Smart Anti-DPI Mode (Recommended)",
            "strict_udp": "Strict UDP Mode",
            "deep": "Deep Screening Mode",
            "permissive": "Permissive Mode (Ping Fallback)",
        }
        self._show_toast(f"Test mode selected: {mode_names.get(self.scan_mode, self.scan_mode)}")

    def _run_targeted_scan(
        self,
        targets: List[Tuple[str, int, Optional[str], Optional[str], Optional[dict]]],
        mode: str = "smart",
        title: str = "",
    ):
        if not targets:
            self._show_toast("No target IPs selected for testing.", is_error=True)
            return

        if self.is_scanning or self.is_deep_screening:
            self._show_toast("Another scan is currently in progress. Please wait.", is_error=True)
            return

        self.is_scanning = True
        self.btn_scan.disabled = True
        if hasattr(self, "btn_deep_screen"):
            self.btn_deep_screen.disabled = True
        self.progress_bar.visible = True
        self.progress_bar.value = 0.0
        self.lbl_status.value = f"Running test for {title} ({len(targets)} IPs) with mode '{mode}'..."
        self.page.update()

        def _worker():
            try:
                scanner = FastUdpScanner(
                    timeout=self.scan_timeout,
                    max_concurrency=20,
                    mode=mode,
                    probe_count=self.probe_count,
                )

                def _prog(completed, total, res: CheckResult):
                    frac = completed / total
                    self.progress_bar.value = frac
                    st = f"Live ✓ ({int(res.latency_ms)}ms)" if res.is_reachable else f"Failed ✗ ({res.status})"
                    self.lbl_status.value = f"Testing {title} [{completed}/{total}]: {res.ip} -> {st}"
                    self.page.update()

                results = scanner.scan_all_sync(targets, on_progress=_prog)

                # Merge results into self.scan_results & self.working_configs
                new_reach_count = 0
                for r in results:
                    s_info = r.server_info or {}
                    h = s_info.get("hostname")
                    if not h:
                        continue
                    if h not in self.scan_results:
                        self.scan_results[h] = []

                    # Update or append in self.scan_results
                    existing_idx = next((i for i, ex in enumerate(self.scan_results[h]) if ex.ip == r.ip), None)
                    if existing_idx is not None:
                        self.scan_results[h][existing_idx] = r
                    else:
                        self.scan_results[h].append(r)

                    # Update or remove in self.working_configs
                    cfg_idx = next((i for i, c in enumerate(self.working_configs) if c.get("endpoint_ip") == r.ip), None)
                    if r.is_reachable:
                        new_reach_count += 1
                        srv = s_info.get("server")
                        entry = {
                            "country": srv.country if srv else s_info.get("country", ""),
                            "country_code": srv.country_code if srv else s_info.get("country_code", ""),
                            "city": srv.city if srv else s_info.get("city", ""),
                            "hostname": h,
                            "public_key": srv.public_key if srv else s_info.get("public_key", ""),
                            "endpoint_ip": r.ip,
                            "port": r.port,
                            "latency_ms": r.latency_ms,
                            "packet_loss": r.packet_loss,
                            "jitter_ms": r.jitter_ms,
                            "deep_verified": r.deep_verified,
                            "status": r.status,
                        }
                        if cfg_idx is not None:
                            self.working_configs[cfg_idx] = entry
                        else:
                            self.working_configs.append(entry)
                    else:
                        if cfg_idx is not None:
                            self.working_configs.pop(cfg_idx)

                # Re-sort working configs
                self.working_configs.sort(key=lambda x: (x.get("packet_loss", 0), x.get("latency_ms", 9999)))
                self.last_scan_data = save_scan_cache(self.scan_results, self.working_configs, filepath=self.current_scan_cache_file)

                self.lbl_status.value = f"Test {title} completed: {new_reach_count} live servers identified."
                self._show_toast(f"Test {title} finished: {new_reach_count} live servers found out of {len(targets)} IPs.")

            except Exception as err:
                self.lbl_status.value = f"Error during test {title}: {err}"
                self._show_toast(f"Test error: {err}", is_error=True)
            finally:
                self.is_scanning = False
                self.btn_scan.disabled = False
                if hasattr(self, "btn_deep_screen"):
                    self.btn_deep_screen.disabled = False
                self.progress_bar.visible = False
                self._refresh_summary_cards()
                self._update_prev_scan_card()
                self._render_server_list()

        threading.Thread(target=_worker, daemon=True).start()

    def _test_country(self, country: str, servers: List[ServerMetadata], mode: str = "smart"):
        self._expanded_countries.add(country)
        targets = []
        privkey = self.blueprint.user_interface.private_key
        for s in servers:
            ips = s.resolved_ips if s.resolved_ips else [s.hostname]
            for ip in ips:
                targets.append((
                    ip,
                    s.port,
                    privkey,
                    s.public_key,
                    {"server": s, "hostname": s.hostname, "country": s.country, "city": s.city},
                ))
        if not targets:
            self._show_toast(f"No servers found for {country}.", is_error=True)
            return
        self._run_targeted_scan(targets, mode=mode, title=f"Country {country}")

    def _test_cluster(self, server: ServerMetadata, mode: str = "smart"):
        targets = []
        privkey = self.blueprint.user_interface.private_key
        ips = server.resolved_ips if server.resolved_ips else [server.hostname]
        for ip in ips:
            targets.append((
                ip,
                server.port,
                privkey,
                server.public_key,
                {"server": server, "hostname": server.hostname, "country": server.country, "city": server.city},
            ))
        if not targets:
            self._show_toast(f"No resolved endpoints found for cluster {server.hostname}.", is_error=True)
            return
        self._run_targeted_scan(targets, mode=mode, title=f"Cluster {server.city} ({server.hostname})")

    def _test_single_ip(self, server: ServerMetadata, ip: str, mode: str = "smart"):
        privkey = self.blueprint.user_interface.private_key
        targets = [(
            ip,
            server.port,
            privkey,
            server.public_key,
            {"server": server, "hostname": server.hostname, "country": server.country, "city": server.city},
        )]
        self._run_targeted_scan(targets, mode=mode, title=f"IP {ip}")

    # -------------------------------------------------------------------------
    # Application Settings & Credentials Modal (v3: Integrated Verification Settings)
    # -------------------------------------------------------------------------
    # -------------------------------------------------------------------------
    # Application Settings & Credentials Modal (v5: Unified Tabbed System)
    # -------------------------------------------------------------------------
    def _open_settings_modal(self, e=None):
        """Settings & Preferences modal for Surfshark AmneziaWG Studio v5.1."""
        has_surf_key = bool(self.blueprint.user_interface.private_key)
        badge_surf = ft.Container(
            content=ft.Text("✅ Active Key" if has_surf_key else "⚠️ Missing Key", size=10, weight=ft.FontWeight.BOLD, color="#FFFFFF"),
            bgcolor="#2E7D32" if has_surf_key else "#E65100",
            border_radius=8,
            padding=ft.padding.symmetric(horizontal=8, vertical=3),
        )

        txt_surf_priv = ft.TextField(
            label="User PrivateKey (Surfshark Client Key)",
            value=self.blueprint.user_interface.private_key or "",
            password=True,
            can_reveal_password=True,
            text_size=12,
            helper_text="WireGuard private key used to construct Noise_IK handshake and AmneziaWG configs",
        )
        txt_surf_addr = ft.TextField(
            label="Client Interface Address",
            value=self.blueprint.user_interface.address or "10.14.0.2/16",
            text_size=12,
            expand=True,
        )
        txt_surf_dns = ft.TextField(
            label="DNS Resolvers",
            value=self.blueprint.user_interface.dns or "162.252.172.57, 149.154.159.92",
            text_size=12,
            expand=True,
        )

        def _on_surf_harvest_clicked(ev):
            self._close_dialog(modal)
            self._start_browser_harvest(ev)

        surfshark_card = ft.Container(
            bgcolor="#13232C",
            border=ft.border.all(1, "#00897B"),
            border_radius=8,
            padding=12,
            content=ft.Column(
                spacing=10,
                controls=[
                    ft.Row(
                        alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                        controls=[
                            ft.Row(
                                spacing=6,
                                controls=[
                                    ft.Icon(ft.icons.SHIELD_ROUNDED, color="#00D09C", size=20),
                                    ft.Text("Surfshark Account Credentials (WireGuard)", size=13, weight=ft.FontWeight.BOLD, color="#80CBC4"),
                                ],
                            ),
                            badge_surf,
                        ],
                    ),
                    txt_surf_priv,
                    ft.Row(spacing=10, controls=[txt_surf_addr, txt_surf_dns]),
                    ft.Row(
                        alignment=ft.MainAxisAlignment.END,
                        controls=[
                            ft.OutlinedButton(
                                text="🔑 Automatic Key Extraction via Browser Login (Harvest)",
                                icon=ft.icons.KEY_ROUNDED,
                                on_click=_on_surf_harvest_clicked,
                                style=ft.ButtonStyle(color="#00D09C"),
                            ),
                        ],
                    ),
                ],
            ),
        )

        # Tab 2: Verification Method
        dd_scan_mode_setting = ft.Dropdown(
            label="Server Verification Method",
            value=self.scan_mode if self.scan_mode in ("smart", "permissive") else "smart",
            text_size=12,
            options=[
                ft.dropdown.Option("smart", "🧠 Smart Anti-DPI (WireGuard Handshake Protocol Validation) [Recommended]"),
                ft.dropdown.Option("permissive", "⚡ Permissive Mode (Fast UDP + ICMP Ping Fallback)"),
            ],
            expand=True,
        )

        txt_timeout = ft.TextField(
            label="UDP Packet Timeout (seconds)",
            value=str(self.scan_timeout),
            text_size=12,
            width=180,
            keyboard_type=ft.KeyboardType.NUMBER,
        )

        txt_probe_count = ft.TextField(
            label="Handshake Probe Packets Count",
            value=str(self.probe_count),
            text_size=12,
            width=180,
            keyboard_type=ft.KeyboardType.NUMBER,
        )

        verification_guide = ft.Container(
            bgcolor="#1A2634",
            border=ft.border.all(1, "#0288D1"),
            border_radius=6,
            padding=10,
            content=ft.Column(
                spacing=4,
                controls=[
                    ft.Row(
                        spacing=6,
                        controls=[
                            ft.Icon(ft.icons.INFO_ROUNDED, color="#29B6F6", size=16),
                            ft.Text("Understanding Anti-DPI Verification:", size=11, weight=ft.FontWeight.BOLD, color="#81D4FA"),
                        ],
                    ),
                    ft.Text(
                        "• In restricted networks (such as Iran), ICMP echo (ping) to neighboring countries may be unblocked, but raw UDP port 51820 packets are actively inspected and dropped by Deep Packet Inspection (DPI).\n"
                        "• In 'Smart Anti-DPI' mode, the application verifies genuine WireGuard handshake responses to avoid false positives, ensuring that only endpoints genuinely capable of establishing an encrypted tunnel are verified.\n"
                        "• In 'Permissive Mode', fast UDP reachability is measured with ping fallback for rapid assessment.",
                        size=10,
                        color="#B0BEC5",
                    ),
                ],
            ),
        )

        # Tab 3: Featured Countries
        current_fc_str = ", ".join(self.featured_countries)
        txt_featured_countries = ft.TextField(
            label="Featured Countries List (Displayed on Home Bar)",
            value=current_fc_str,
            text_size=12,
            helper_text="Separate country names or 2-letter ISO codes with commas",
            expand=True,
        )

        chips_row = ft.Row(wrap=True, spacing=6)

        def _rebuild_chips():
            tokens = [t.strip() for t in txt_featured_countries.value.split(",") if t.strip()]
            active_set = set(t.lower() for t in tokens)
            chips = []
            for cname in DEFAULT_FEATURED_COUNTRIES:
                is_sel = (cname.lower() in active_set)
                chip = ft.Chip(
                    label=ft.Text(cname, size=11, color="#FFFFFF" if is_sel else "#B0BEC5"),
                    selected=is_sel,
                    selected_color="#00897B",
                    bgcolor="#263238",
                    on_select=lambda ev, name=cname: _toggle_country(name),
                    tooltip=f"Click to add or remove {cname}",
                )
                chips.append(chip)
            chips_row.controls = chips
            try:
                chips_row.update()
            except Exception:
                pass

        def _toggle_country(cname: str):
            tokens = [t.strip() for t in txt_featured_countries.value.split(",") if t.strip()]
            lower_tokens = [t.lower() for t in tokens]
            if cname.lower() in lower_tokens:
                tokens = [t for t in tokens if t.lower() != cname.lower()]
            else:
                tokens.append(cname)
            txt_featured_countries.value = ", ".join(tokens)
            txt_featured_countries.update()
            _rebuild_chips()

        def _set_default_countries(ev):
            txt_featured_countries.value = ", ".join(DEFAULT_FEATURED_COUNTRIES)
            txt_featured_countries.update()
            _rebuild_chips()

        _rebuild_chips()

        # Tab 2: Obfuscation & Presets
        dd_preset_setting = ft.Dropdown(
            label="Anti-Censorship Profile",
            value=self.current_preset,
            text_size=12,
            options=[
                ft.dropdown.Option("iran", "Iran Balanced (Recommended)"),
                ft.dropdown.Option("aggressive", "Aggressive Anti-DPI (High Jitter)"),
                ft.dropdown.Option("vanilla", "Vanilla WireGuard (Standard)"),
                ft.dropdown.Option("custom", "Custom Parameters"),
            ],
            expand=True,
        )

        txt_modal_jc = ft.TextField(label="Jc (Junk Packets)", value=str(self.params.jc), width=130, text_size=12)
        txt_modal_jmin = ft.TextField(label="Jmin (Bytes)", value=str(self.params.jmin), width=130, text_size=12)
        txt_modal_jmax = ft.TextField(label="Jmax (Bytes)", value=str(self.params.jmax), width=130, text_size=12)
        txt_modal_s1 = ft.TextField(label="S1 (Init Junk)", value=str(self.params.s1), width=130, text_size=12)
        txt_modal_s2 = ft.TextField(label="S2 (Resp Junk)", value=str(self.params.s2), width=130, text_size=12)
        txt_modal_h1 = ft.TextField(label="H1 Header", value=str(self.params.h1), width=95, text_size=12)
        txt_modal_h2 = ft.TextField(label="H2 Header", value=str(self.params.h2), width=95, text_size=12)
        txt_modal_h3 = ft.TextField(label="H3 Header", value=str(self.params.h3), width=95, text_size=12)
        txt_modal_h4 = ft.TextField(label="H4 Header", value=str(self.params.h4), width=95, text_size=12)

        def _on_modal_preset_change(ev):
            val = dd_preset_setting.value
            if val == "iran":
                p = AmneziaParams.iran_preset()
            elif val == "aggressive":
                p = AmneziaParams.aggressive_preset()
            elif val == "vanilla":
                p = AmneziaParams.vanilla_preset()
            else:
                return
            txt_modal_jc.value = str(p.jc)
            txt_modal_jmin.value = str(p.jmin)
            txt_modal_jmax.value = str(p.jmax)
            txt_modal_s1.value = str(p.s1)
            txt_modal_s2.value = str(p.s2)
            txt_modal_h1.value = str(p.h1)
            txt_modal_h2.value = str(p.h2)
            txt_modal_h3.value = str(p.h3)
            txt_modal_h4.value = str(p.h4)
            for ctrl in (txt_modal_jc, txt_modal_jmin, txt_modal_jmax, txt_modal_s1, txt_modal_s2, txt_modal_h1, txt_modal_h2, txt_modal_h3, txt_modal_h4):
                try:
                    ctrl.update()
                except Exception:
                    pass

        dd_preset_setting.on_change = _on_modal_preset_change

        tabs = ft.Tabs(
            selected_index=0,
            animation_duration=200,
            tabs=[
                ft.Tab(
                    text="Credentials & Keys",
                    icon=ft.icons.VPN_KEY_ROUNDED,
                    content=ft.Container(
                        padding=12,
                        content=ft.Column(
                            scroll=ft.ScrollMode.AUTO,
                            spacing=12,
                            controls=[
                                surfshark_card,
                            ],
                        ),
                    ),
                ),
                ft.Tab(
                    text="Obfuscation & Presets",
                    icon=ft.icons.TUNE_ROUNDED,
                    content=ft.Container(
                        padding=12,
                        content=ft.Column(
                            scroll=ft.ScrollMode.AUTO,
                            spacing=12,
                            controls=[
                                ft.Text("⚡ Anti-Censorship Profiles & AmneziaWG Headers:", size=13, weight=ft.FontWeight.BOLD, color="#80CBC4"),
                                dd_preset_setting,
                                ft.Divider(height=1),
                                ft.Text("Junk Packet & Header Customization:", size=12, weight=ft.FontWeight.BOLD, color="#ECEFF1"),
                                ft.Row(spacing=8, controls=[txt_modal_jc, txt_modal_jmin, txt_modal_jmax]),
                                ft.Row(spacing=8, controls=[txt_modal_s1, txt_modal_s2]),
                                ft.Row(spacing=8, controls=[txt_modal_h1, txt_modal_h2, txt_modal_h3, txt_modal_h4]),
                                ft.Text(
                                    "💡 Iran Balanced preset injects random junk packets (Jc=4, 50-1000 bytes) and mutates handshake headers (H1-H4) to evade Deep Packet Inspection (DPI).",
                                    size=11,
                                    color="#81C784",
                                ),
                            ],
                        ),
                    ),
                ),
                ft.Tab(
                    text="Verification Settings",
                    icon=ft.icons.SECURITY_ROUNDED,
                    content=ft.Container(
                        padding=12,
                        content=ft.Column(
                            scroll=ft.ScrollMode.AUTO,
                            spacing=12,
                            controls=[
                                ft.Text("📡 Server Verification & Anti-DPI Screening:", size=13, weight=ft.FontWeight.BOLD, color="#80CBC4"),
                                dd_scan_mode_setting,
                                ft.Row(spacing=10, controls=[txt_timeout, txt_probe_count]),
                                verification_guide,
                            ],
                        ),
                    ),
                ),
                ft.Tab(
                    text="Featured Countries",
                    icon=ft.icons.STAR_ROUNDED,
                    content=ft.Container(
                        padding=12,
                        content=ft.Column(
                            scroll=ft.ScrollMode.AUTO,
                            spacing=12,
                            controls=[
                                ft.Text("Manage Featured Countries (Home Bar):", size=13, weight=ft.FontWeight.BOLD, color="#80CBC4"),
                                txt_featured_countries,
                                ft.Row(
                                    spacing=8,
                                    controls=[
                                        ft.TextButton(
                                            text="Reset to Defaults (6 Countries)",
                                            icon=ft.icons.RESTORE_ROUNDED,
                                            on_click=_set_default_countries,
                                        ),
                                    ],
                                ),
                                ft.Text("Quick toggle (click to add/remove):", size=11, color="#90A4AE"),
                                chips_row,
                            ],
                        ),
                    ),
                ),
            ],
            expand=True,
        )

        def _save_settings(ev):
            # Save Surfshark Credentials
            priv = txt_surf_priv.value.strip()
            self.blueprint.user_interface.private_key = priv
            self.blueprint.user_interface.address = txt_surf_addr.value.strip() or "10.14.0.2/16"
            self.blueprint.user_interface.dns = txt_surf_dns.value.strip() or "162.252.172.57, 149.154.159.92"
            save_blueprint(self.blueprint, DEFAULT_DATA_FILE)

            # Save Obfuscation & Presets
            self.current_preset = dd_preset_setting.value or "iran"
            try:
                self.params.jc = int(txt_modal_jc.value or 4)
                self.params.jmin = int(txt_modal_jmin.value or 50)
                self.params.jmax = int(txt_modal_jmax.value or 1000)
                self.params.s1 = int(txt_modal_s1.value or 0)
                self.params.s2 = int(txt_modal_s2.value or 0)
                self.params.h1 = int(txt_modal_h1.value or 1)
                self.params.h2 = int(txt_modal_h2.value or 2)
                self.params.h3 = int(txt_modal_h3.value or 3)
                self.params.h4 = int(txt_modal_h4.value or 4)
                self.txt_jc.value = str(self.params.jc)
                self.txt_jmin.value = str(self.params.jmin)
                self.txt_jmax.value = str(self.params.jmax)
                self.txt_s1.value = str(self.params.s1)
                self.txt_s2.value = str(self.params.s2)
                self.txt_h1.value = str(self.params.h1)
                self.txt_h2.value = str(self.params.h2)
                self.txt_h3.value = str(self.params.h3)
                self.txt_h4.value = str(self.params.h4)
            except Exception as e:
                logger.error(f"Error saving params: {e}")

            # Save Verification Settings
            self.scan_mode = dd_scan_mode_setting.value or "smart"
            try:
                self.scan_timeout = max(0.5, float(txt_timeout.value or 2.0))
            except ValueError:
                self.scan_timeout = 2.0
            try:
                self.probe_count = max(1, int(txt_probe_count.value or 3))
            except ValueError:
                self.probe_count = 3

            # Save Featured Countries
            new_fc = [t.strip() for t in txt_featured_countries.value.split(",") if t.strip()]
            if new_fc:
                self.featured_countries = new_fc

            # Save user settings JSON
            self._save_user_settings()

            if hasattr(self, "dd_scan_mode"):
                self.dd_scan_mode.value = self.scan_mode
                try:
                    self.dd_scan_mode.update()
                except Exception:
                    pass

            self._update_privkey_badge()
            self._refresh_summary_cards()
            self._render_server_list()
            self._close_dialog(modal)
            self._show_toast("Surfshark credentials and preferences saved successfully.")

        modal = ft.AlertDialog(
            modal=True,
            title=ft.Row(
                spacing=8,
                controls=[
                    ft.Icon(ft.icons.SETTINGS_ROUNDED, color="#00D09C", size=22),
                    ft.Text("Surfshark Studio Settings", size=16, weight=ft.FontWeight.BOLD),
                ],
            ),
            content=ft.Container(
                width=680,
                height=480,
                content=tabs,
            ),
            actions=[
                ft.ElevatedButton(
                    text="Save Settings",
                    icon=ft.icons.SAVE_ROUNDED,
                    style=ft.ButtonStyle(bgcolor="#00897B", color="#FFFFFF"),
                    on_click=_save_settings,
                ),
                ft.TextButton(text="Cancel", on_click=lambda ev: self._close_dialog(modal)),
            ],
        )
        self._open_dialog(modal)
    def _open_credentials_modal(self, e):
        """Backward-compatible alias for opening the full settings modal."""
        self._open_settings_modal(e)


    def _open_obfuscation_modal(self, e):
        def _apply_params(e):
            try:
                self.params.jc = int(self.txt_jc.value or 4)
                self.params.jmin = int(self.txt_jmin.value or 40)
                self.params.jmax = int(self.txt_jmax.value or 70)
                self.params.s1 = int(self.txt_s1.value or 0)
                self.params.s2 = int(self.txt_s2.value or 0)
                self.params.h1 = int(self.txt_h1.value or 1)
                self.params.h2 = int(self.txt_h2.value or 2)
                self.params.h3 = int(self.txt_h3.value or 3)
                self.params.h4 = int(self.txt_h4.value or 4)
                self._show_toast("AmneziaWG header parameters saved.")
                self._close_dialog(modal)
            except Exception as err:
                self._show_toast(f"Value error: {err}", is_error=True)

        modal = ft.AlertDialog(
            title=ft.Row(
                spacing=8,
                controls=[
                    ft.Icon(ft.icons.TUNE_ROUNDED, color="#00D09C", size=22),
                    ft.Text("Advanced AmneziaWG Obfuscation Headers", size=15, weight=ft.FontWeight.BOLD),
                ],
            ),
            content=ft.Container(
                width=540,
                content=ft.Column(
                    tight=True,
                    spacing=12,
                    controls=[
                        ft.Text(
                            "These headers disguise initial WireGuard handshake packets to bypass Deep Packet Inspection (DPI):",
                            size=12,
                            color="#B0BEC5",
                        ),
                        ft.Row(spacing=8, controls=[self.txt_jc, self.txt_jmin, self.txt_jmax]),
                        ft.Row(spacing=8, controls=[self.txt_s1, self.txt_s2]),
                        ft.Row(spacing=8, controls=[self.txt_h1, self.txt_h2, self.txt_h3, self.txt_h4]),
                        ft.Text(
                            "💡 Tip: The default 'Iran Balanced' profile provides optimal stability in most networks.",
                            size=11,
                            color="#81C784",
                        ),
                    ],
                ),
            ),
            actions=[
                ft.ElevatedButton(
                    text="Apply & Save",
                    style=ft.ButtonStyle(bgcolor="#00D09C", color="#000000"),
                    on_click=_apply_params,
                ),
                ft.TextButton(text="Cancel", on_click=lambda e: self._close_dialog(modal)),
            ],
        )
        self._open_dialog(modal)

    # -------------------------------------------------------------------------
    # Help & Documentation Modal
    # -------------------------------------------------------------------------
    def _open_help_modal(self, e):
        modal = ft.AlertDialog(
            title=ft.Text("About & Usage Guide", weight=ft.FontWeight.BOLD),
            content=ft.Container(
                width=560,
                content=ft.Column(
                    tight=True,
                    spacing=10,
                    controls=[
                        ft.Text("Stage A: Server Harvest", weight=ft.FontWeight.BOLD, color="#00D09C"),
                        ft.Text("Click 'Update Server Metadata' to launch an interactive Chromium browser. Log in to Surfshark so the app captures your WireGuard keypair and the latest server cluster catalog."),
                        ft.Divider(),
                        ft.Text("Stage B: Anti-Poisoning & Scanning", weight=ft.FontWeight.BOLD, color="#00D09C"),
                        ft.Text("In restricted networks (like Iran), system DNS is poisoned to redirect VPNs to blackhole IPs (e.g. 10.10.34.34). This tool uses encrypted DoH queries (Cloudflare 1.1.1.1, Google 8.8.8.8, Quad9) to extract real backend server IPs."),
                        ft.Divider(),
                        ft.Text("Stage C: AmneziaWG Obfuscation", weight=ft.FontWeight.BOLD, color="#00D09C"),
                        ft.Text("AmneziaWG injects junk packets (Jc, Jmin, Jmax) and custom headers (H1-H4) to disguise WireGuard's 148-byte handshake from Deep Packet Inspection (DPI)."),
                    ],
                ),
            ),
            actions=[ft.TextButton(text="Close", on_click=lambda e: self._close_dialog(modal))],
        )
        self._open_dialog(modal)

    # -------------------------------------------------------------------------
    # Utility Helpers & Dialog Handlers (Cross-Version Flet Support)
    # -------------------------------------------------------------------------
    def _show_toast(self, message: str, is_error: bool = False):
        snack = ft.SnackBar(
            content=ft.Text(message, color="#FFFFFF"),
            bgcolor="#C62828" if is_error else "#2E7D32",
            duration=3500,
        )
        if hasattr(self.page, "open"):
            self.page.open(snack)
        elif hasattr(self.page, "overlay"):
            self.page.overlay.append(snack)
            snack.open = True
            self.page.update()

    def _open_dialog(self, dialog: ft.AlertDialog):
        try:
            if hasattr(self.page, "open"):
                self.page.open(dialog)
            elif hasattr(self.page, "dialog"):
                self.page.dialog = dialog
                dialog.open = True
                self.page.update()
            else:
                if dialog not in self.page.overlay:
                    self.page.overlay.append(dialog)
                dialog.open = True
                self.page.update()
        except Exception as e:
            try:
                if hasattr(self.page, "overlay"):
                    if dialog not in self.page.overlay:
                        self.page.overlay.append(dialog)
                    dialog.open = True
                    self.page.update()
            except Exception as e2:
                print(f"Error opening dialog: {e}, {e2}")

    def _close_dialog(self, dialog: ft.AlertDialog):
        try:
            if hasattr(self.page, "close"):
                self.page.close(dialog)
            else:
                dialog.open = False
                self.page.update()
        except Exception:
            try:
                dialog.open = False
                self.page.update()
            except Exception:
                pass


    def _force_full_refresh(self, e=None):
        """Forces immediate re-check of VPN status, reloads Shadowrocket results, and updates UI."""
        self._refresh_vpn_status(e)
        self._sync_results_from_shadowrocket(e)
        self._show_toast("Refreshed network status and synced Shadowrocket.")


def main(page: ft.Page):
    SurfsharkAmneziaApp(page)


if __name__ == "__main__":
    ft.app(target=main)
