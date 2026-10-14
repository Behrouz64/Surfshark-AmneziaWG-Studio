#!/usr/bin/env python3
"""
phone_cli.py: the phone version in the terminal. No browser and no Flet.

It uses the same logic as the phone app (mobile_core): scan, continent and search filters,
selection, copy text for AmneziaWG and Shadowrocket, the copy queue, a QR code, and the guide.
The PrivateKey is kept only in memory for this run and is never written to a file.

  .venv/bin/python phone_cli.py
"""

from __future__ import annotations

import getpass
import re
import subprocess
import sys
from typing import Callable, List, Optional, Sequence

from browser_harvest import DEFAULT_DATA_FILE, is_placeholder_key, load_blueprint
from config_builder import country_code_to_flag, is_valid_wg_key
from mobile_core import (
    ANY_CONTINENT,
    DEFAULT_PRESET,
    CopyQueue,
    Endpoint,
    build_endpoint_config,
    build_endpoint_list_text,
    build_endpoint_wg_link,
    build_group_config_text,
    build_group_wg_links_text,
    build_group_wg_subscription,
    continent_by_country_code,
    continents_present,
    endpoints_from_working_configs,
    filter_endpoints,
    group_by_country,
    has_usable_private_key,
    params_for_preset,
    qr_available,
    qr_matrix,
    run_mobile_scan,
)
from mobile_guide import GUIDE_LANGUAGES, guide_sections
from scan_cache import DEFAULT_SCAN_CACHE_FILE, load_scan_cache
from vpn_detector import detect_active_vpn

MENU = """
 1) وارد کردن PrivateKey (فقط در حافظه‌ی همین اجرا)
 2) اسکن سرورها (VPN خاموش باشد)
 3) فیلتر قاره و جستجو
 4) انتخاب سرورها
 5) کپی: کانفیگ، wg://، اشتراک Shadowrocket، لیست
 6) صف کپی یکی‌یکی (AmneziaWG یا Shadowrocket)
 7) QR یک سرور
 8) راهنما
 9) حالت ترمینال برای QR (روشن / تیره)
 0) خروج"""


def parse_selection(text: str, count: int) -> List[int]:
    """'1, 3, 5-7' -> 0-based indexes below count, in the order typed, without repeats."""
    indexes: List[int] = []
    for part in re.split(r"[,\s]+", text.strip()):
        match = re.fullmatch(r"(\d+)(?:-(\d+))?", part)
        if not match:
            continue
        start = int(match.group(1))
        end = int(match.group(2) or start)
        for number in range(start, end + 1):
            if 1 <= number <= count and (number - 1) not in indexes:
                indexes.append(number - 1)
    return indexes


def render_qr_lines(matrix: List[List[bool]]) -> List[str]:
    """
    Half-block QR: two module rows per text line, so a config QR fits a normal terminal.
    Dark modules are drawn as blocks, which is the usual look on a light terminal.
    """
    rows = len(matrix)
    cols = len(matrix[0]) if matrix else 0
    lines = []
    for top in range(0, rows, 2):
        bottom = top + 1
        chars = []
        for col in range(cols):
            upper = matrix[top][col]
            lower = matrix[bottom][col] if bottom < rows else False
            chars.append("█" if upper and lower else "▀" if upper else "▄" if lower else " ")
        lines.append("".join(chars))
    return lines


def _plain(text: str) -> str:
    """Removes the bidi isolation marks the phone UI adds; a terminal does not need them."""
    return text.replace("⁦", "").replace("⁩", "")


def _pbcopy(text: str) -> None:
    subprocess.run(["pbcopy"], input=text.encode("utf-8"), check=True)


class PhoneCli:
    def __init__(
        self,
        data_file: str = DEFAULT_DATA_FILE,
        cache_file: str = DEFAULT_SCAN_CACHE_FILE,
        *,
        input_fn: Callable[[str], str] = input,
        output_fn: Callable[[str], None] = print,
        secret_fn: Callable[[str], str] = getpass.getpass,
        clipboard: Optional[Callable[[str], None]] = _pbcopy if sys.platform == "darwin" else None,
        scan_fn=run_mobile_scan,
        vpn_fn: Optional[Callable] = None,
        preset_key: str = DEFAULT_PRESET,
    ):
        self.blueprint = load_blueprint(data_file)
        self.cache_file = cache_file
        self._ask_fn = input_fn
        self._out = output_fn
        self._secret = secret_fn
        self.clipboard = clipboard
        self.scan_fn = scan_fn
        self.vpn_fn = vpn_fn or detect_active_vpn
        self.preset_key = preset_key
        self.continent = ANY_CONTINENT
        self.query = ""
        self.dark_terminal = False
        self.selected: set = set()
        self.endpoints: List[Endpoint] = []
        self.mapping = continent_by_country_code(self.blueprint.servers)
        self._load_cache()

    # ----- small helpers -------------------------------------------------------

    def _say(self, text: str = "") -> None:
        self._out(text)

    def _ask(self, prompt: str) -> str:
        return self._ask_fn(prompt).strip()

    def _params(self):
        return params_for_preset(self.preset_key)

    def _ui(self):
        return self.blueprint.user_interface

    def _load_cache(self) -> None:
        data = load_scan_cache(self.cache_file) or {}
        self.endpoints = endpoints_from_working_configs(data.get("working_configs", []))
        valid = {e.key for e in self.endpoints}
        self.selected &= valid

    def visible(self) -> List[Endpoint]:
        """The servers on screen: continent and search applied, grouped by country like the app."""
        filtered = filter_endpoints(self.endpoints, self.mapping, self.continent, self.query)
        return [endpoint for _, items in group_by_country(filtered) for endpoint in items]

    def copy_text(self, text: str, label: str) -> None:
        if self.clipboard is None:
            self._say("این ترمینال کلیپ‌بورد ندارد (فقط مک). متن زیر را دستی کپی کنید:")
            self._say(text)
            return
        try:
            self.clipboard(text)
        except (OSError, subprocess.CalledProcessError) as err:
            self._say(f"کپی نشد: {err}")
            return
        self._say(f"کپی شد: {label} ({text.count(chr(10)) + 1} خط)")

    def _vpn_interface(self) -> Optional[str]:
        try:
            status = self.vpn_fn()
        except Exception:
            return None
        if status and status.is_vpn_active:
            return status.interface
        return None

    # ----- key -----------------------------------------------------------------

    def set_key(self) -> bool:
        key = self._secret("PrivateKey (۴۴ کاراکتر، پنهان): ").strip()
        if not is_valid_wg_key(key) or is_placeholder_key(key):
            self._say("فرمت کلید درست نیست؛ کلید WireGuard باید ۴۴ کاراکتر باشد و با = تمام شود.")
            return False
        self._ui().private_key = key
        self._say("کلید فقط در حافظه‌ی همین اجرا نگه داشته می‌شود و روی دیسک نوشته نمی‌شود.")
        return True

    def ensure_key(self) -> bool:
        if has_usable_private_key(self._ui()):
            return True
        self._say("اول کلید را وارد کنید.")
        return self.set_key()

    # ----- screens -------------------------------------------------------------

    def _status(self) -> None:
        key = "ثبت شده" if has_usable_private_key(self._ui()) else "ثبت نشده"
        continent = self.continent or "همه"
        self._say(
            f"\nکلید: {key} | سرورهای سالم: {len(self.endpoints)} | "
            f"انتخاب‌شده: {len(self.selected)} | قاره: {continent} | جستجو: {self.query or '-'}"
        )

    def show_servers(self) -> List[Endpoint]:
        if not self.endpoints:
            self._say("هنوز سرور سالمی نیست. گزینه‌ی 2 (اسکن) را اجرا کنید.")
            return []
        shown = self.visible()
        if not shown:
            self._say("با این فیلتر سروری نیست.")
            return []
        last_country = None
        for number, endpoint in enumerate(shown, start=1):
            if endpoint.country != last_country:
                self._say(f"\n{country_code_to_flag(endpoint.country_code)} {endpoint.country}")
                last_country = endpoint.country
            mark = "[x]" if endpoint.key in self.selected else "[ ]"
            self._say(f"{mark} {number:>3}. {endpoint.city:<14} {endpoint.ip:<16} {endpoint.latency_label}")
        return shown

    def filter_menu(self) -> None:
        options = continents_present(self.endpoints, self.mapping)
        self._say("قاره (Enter = بدون تغییر):")
        self._say(f"  0. همه‌ی قاره‌ها ({len(self.endpoints)})")
        for number, (name, count) in enumerate(options, start=1):
            self._say(f"  {number}. {name} ({count})")
        choice = self._ask("شماره‌ی قاره: ")
        if choice.isdigit() and int(choice) == 0:
            self.continent = ANY_CONTINENT
        elif choice.isdigit() and 1 <= int(choice) <= len(options):
            self.continent = options[int(choice) - 1][0]
        self.query = self._ask("جستجو (کشور، شهر یا آی‌پی؛ خالی = بدون جستجو): ")
        self.show_servers()

    def select_menu(self) -> None:
        shown = self.show_servers()
        if not shown:
            return
        self._say("شماره‌ها: 1,3,5-8 (تیک می‌زند) | a = همه‌ی نمایش‌داده‌شده | k = یک کشور | c = پاک کردن | Enter = برگشت")
        answer = self._ask("انتخاب: ").lower()
        if not answer:
            return
        if answer == "c":
            self.selected.clear()
        elif answer == "a":
            self.selected.update(endpoint.key for endpoint in shown)
        elif answer == "k":
            self._toggle_country(shown)
        else:
            for index in parse_selection(answer, len(shown)):
                key = shown[index].key
                if key in self.selected:
                    self.selected.discard(key)
                else:
                    self.selected.add(key)

    def _toggle_country(self, shown: List[Endpoint]) -> None:
        groups = group_by_country(shown)
        for number, (name, items) in enumerate(groups, start=1):
            self._say(f"  {number}. {name} ({len(items)})")
        choice = self._ask("شماره‌ی کشور: ")
        if not choice.isdigit() or not 1 <= int(choice) <= len(groups):
            return
        keys = {endpoint.key for endpoint in groups[int(choice) - 1][1]}
        if keys <= self.selected:
            self.selected -= keys
        else:
            self.selected |= keys

    def targets(self) -> List[Endpoint]:
        """The selection, or one or more servers picked now when nothing is selected."""
        if self.selected:
            return [endpoint for endpoint in self.endpoints if endpoint.key in self.selected]
        shown = self.show_servers()
        if not shown:
            return []
        answer = self._ask("شماره‌ی سرور (یا چند شماره با کاما): ")
        return [shown[index] for index in parse_selection(answer, len(shown))]

    def copy_menu(self) -> None:
        if not self.ensure_key():
            return
        targets = self.targets()
        if not targets:
            return
        one = len(targets) == 1
        ui, params = self._ui(), self._params()
        self._say(f"{len(targets)} سرور انتخاب شده")
        self._say("  1. کانفیگ AmneziaWG" + ("" if one else " (متن ترکیبی، هر کانفیگ با جداکننده)"))
        self._say("  2. لینک wg:// برای Shadowrocket" + ("" if one else " (هر خط یک لینک)"))
        self._say("  3. اشتراک Shadowrocket (base64، همه‌ی سرورها)")
        self._say("  4. لیست کشور، شهر و آی‌پی (بدون کلید)")
        choice = self._ask("انتخاب: ")
        if choice == "1":
            text = build_endpoint_config(targets[0], ui, params) if one else build_group_config_text(targets, ui, params)
            self.copy_text(text, f"{len(targets)} کانفیگ")
        elif choice == "2":
            text = build_endpoint_wg_link(targets[0], ui, params) if one else build_group_wg_links_text(targets, ui, params)
            self.copy_text(text, f"{len(targets)} لینک wg://")
        elif choice == "3":
            _raw, encoded = build_group_wg_subscription(targets, ui, params)
            self.copy_text(encoded, f"اشتراک {len(targets)} سرور")
        elif choice == "4":
            self.copy_text(build_endpoint_list_text(targets), f"لیست {len(targets)} آی‌پی")

    def queue_copy(self) -> None:
        if not self.ensure_key():
            return
        targets = self.targets()
        if not targets:
            return
        self._say("  1. کانفیگ AmneziaWG (یکی‌یکی)")
        self._say("  2. لینک wg:// Shadowrocket (یکی‌یکی)")
        mode = self._ask("انتخاب: ")
        if mode not in ("1", "2"):
            return
        ui, params = self._ui(), self._params()
        queue = CopyQueue(targets)
        while queue.current is not None:
            endpoint = queue.current
            if mode == "1":
                text = build_endpoint_config(endpoint, ui, params)
            else:
                text = build_endpoint_wg_link(endpoint, ui, params)
            self.copy_text(text, f"{queue.position}/{queue.total} — {endpoint.city}")
            if queue.position == queue.total:
                self._say("آخرین مورد بود.")
                break
            if self._ask("اپ را باز کنید، مورد را وارد کنید، برگردید و Enter بزنید (q = پایان): ").lower() == "q":
                break
            queue.advance()

    def show_qr(self) -> None:
        if not qr_available():
            self._say("کتابخانه‌ی qrcode نصب نیست. با pip install -r requirements.txt نصبش کنید.")
            return
        if not self.ensure_key():
            return
        targets = self.targets()[:1]
        if not targets:
            return
        matrix = qr_matrix(build_endpoint_config(targets[0], self._ui(), self._params()))
        if self.dark_terminal:
            matrix = [[not cell for cell in row] for row in matrix]
        for line in render_qr_lines(matrix):
            self._say(line)
        self._say(f"QR کانفیگ {targets[0].city}. اگر اسکن نشد، گزینه‌ی 9 را بزنید و دوباره امتحان کنید.")

    def scan(self) -> None:
        interface = self._vpn_interface()
        if interface:
            self._say(f"VPN روشن است ({interface}). برای اسکن درست، اول VPN را خاموش کنید.")
            if self._ask("با VPN روشن ادامه می‌دهید؟ (y/N): ").lower() not in ("y", "yes"):
                return
        if not self.ensure_key():
            return
        try:
            result = self.scan_fn(
                self.blueprint,
                cache_path=self.cache_file,
                on_log=self._say,
                on_progress=self._progress,
            )
        except Exception as err:
            self._say(f"اسکن خطا داد: {err}")
            return
        self._load_cache()
        self._say(f"اسکن تمام شد: {len(result.working_configs)} آی‌پی سالم ذخیره شد.")

    def _progress(self, phase: str, done: int, total: int) -> None:
        if total and (done == total or done % max(1, total // 10) == 0):
            self._say(f"{phase}: {done}/{total}")

    def guide(self) -> None:
        language = self._ask("زبان (fa / en، Enter = fa): ").lower() or "fa"
        if language not in GUIDE_LANGUAGES:
            language = "fa"
        for section in guide_sections(language):
            self._say(f"\n== {section['title']}")
            for kind, value in section["blocks"]:
                if kind == "p":
                    self._say(_plain(value))
                elif kind == "note":
                    self._say(f"! {_plain(value)}")
                elif kind == "ol":
                    for number, item in enumerate(value, start=1):
                        self._say(f"  {number}. {_plain(item)}")
                elif kind == "ul":
                    for item in value:
                        self._say(f"  • {_plain(item)}")

    # ----- loop ----------------------------------------------------------------

    def run(self) -> int:
        self._say("Surfshark AmneziaWG Studio: نسخه‌ی ترمینالی (مثل گوشی)")
        actions = {
            "1": self.set_key,
            "2": self.scan,
            "3": self.filter_menu,
            "4": self.select_menu,
            "5": self.copy_menu,
            "6": self.queue_copy,
            "7": self.show_qr,
            "8": self.guide,
            "9": self._toggle_terminal,
        }
        try:
            while True:
                self._status()
                self._say(MENU)
                choice = self._ask("انتخاب: ")
                if choice in ("0", "q"):
                    return 0
                action = actions.get(choice)
                if action is None:
                    self._say("گزینه‌ی درست را انتخاب کنید.")
                    continue
                action()
        except (EOFError, KeyboardInterrupt):
            self._say("")
            return 0

    def _toggle_terminal(self) -> None:
        self.dark_terminal = not self.dark_terminal
        self._say("QR برای ترمینال تیره ساخته می‌شود." if self.dark_terminal else "QR برای ترمینال روشن ساخته می‌شود.")


def main(argv: Optional[Sequence[str]] = None) -> int:
    return PhoneCli().run()


if __name__ == "__main__":
    sys.exit(main())
