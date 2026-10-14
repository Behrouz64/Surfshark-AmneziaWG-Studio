"""
mobile_guide.py: In-app guide for the phone UI, in Persian and English.

Each language has the same sections in the same order, and every section is a
list of blocks: ('p', text), ('ol', [steps]), ('ul', [items]), ('note', text).
check_guide_parity() reports any mismatch; tests/test_mobile.py runs it.

The guide describes the phone UI in mobile_app.py. Keep the two in step.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

Block = Tuple[str, object]
Section = Dict[str, object]

GUIDE_LANGUAGES = ("fa", "en")
DEFAULT_GUIDE_LANGUAGE = "fa"
GUIDE_LANGUAGE_NAMES = {"fa": "فارسی", "en": "English"}

GUIDE: Dict[str, List[Section]] = {
    "fa": [
        {
            "title": "این نسخه چه کاری می‌کند",
            "blocks": [
                ("p", "این نسخه‌ی گوشی سرورهای Surfshark را اسکن می‌کند، سرعت هر سرور را با پینگ می‌سنجد و سریع‌ترین‌ها را نشان می‌دهد. برای هر سرور می‌توانید کانفیگ AmneziaWG یا لینک wg:// بگیرید."),
                ("p", "برنامه روی کامپیوتر اجرا می‌شود و از گوشی، با همان Wi-Fi یا هات‌اسپات، باز می‌شود. اسکن از اینترنت همان کامپیوتر انجام می‌شود."),
                ("note", "«پینگ» یعنی زمانی که یک پیام کوچک لازم دارد تا به سرور برسد و برگردد. عدد کمتر یعنی سرور سریع‌تر."),
            ],
        },
        {
            "title": "قبل از شروع",
            "blocks": [
                ("ol", [
                    "VPN را کاملاً خاموش کنید. اگر VPN روشن باشد، پینگ‌ها واقعی نیستند.",
                    "کلید PrivateKey اکانت Surfshark خود را (۴۴ کاراکتر) آماده کنید. بدون آن کپی کانفیگ کار نمی‌کند.",
                    "کامپیوتر و گوشی را به یک Wi-Fi یا هات‌اسپات وصل کنید.",
                    "این نسخه با HTTP ساده کار می‌کند. فقط در Wi-Fi خانگی یا هات‌اسپات شخصی خودتان استفاده کنید، نه در Wi-Fi عمومی.",
                ]),
            ],
        },
        {
            "title": "مراحل کار",
            "blocks": [
                ("ol", [
                    "روی کامپیوتر دستور python3 main.py --mobile را اجرا کنید. آدرسی شبیه http://<IP>:8550/?t=... چاپ می‌شود.",
                    "همان آدرس کامل (با ?t=...) را در مرورگر گوشی باز کنید.",
                    "در تب «تنظیمات» کلید PrivateKey را وارد کنید.",
                    "در تب «اسکن» با VPN خاموش، اسکن را بزنید. تا پایان اسکن صبر کنید.",
                    "در تب «سرورها» سرورهای سالم را بر اساس کشور ببینید.",
                    "دکمه‌های کپی هر سرور را بزنید، یا چند سرور را تیک بزنید و از دکمه‌ی پایین صفحه گروهی کپی کنید.",
                ]),
            ],
        },
        {
            "title": "کپی تکی: کانفیگ، wg:// و QR",
            "blocks": [
                ("ul", [
                    "کپی کانفیگ (AmneziaWG): متن کامل کانفیگ یک سرور را کپی می‌کند. در اپ AmneziaWG تونل جدید را از متن وارد کنید.",
                    "کپی wg:// (Shadowrocket): لینک wg:// همان سرور را کپی می‌کند. در Shadowrocket از کلیپ‌بورد وارد کنید.",
                    "متن و QR: کانفیگ را نشان می‌دهد و کد QR آن را می‌سازد. متن را می‌توانید با لمس طولانی دستی انتخاب و کپی کنید.",
                ]),
                ("note", "کانفیگ و لینک wg:// هر دو کلید خصوصی شما را دارند. آن‌ها را جای عمومی نفرستید."),
            ],
        },
        {
            "title": "کپی گروهی",
            "blocks": [
                ("p", "سرورها را تیک بزنید، یا دکمه «انتخاب کل کشور» را بزنید. سپس دکمه‌ی انتخاب پایین صفحه را بزنید:"),
                ("ul", [
                    "صف کپی کانفیگ: یکی‌یکی کپی می‌کند. هر کانفیگ را وارد کنید، برگردید و «بعدی» را بزنید. اپ AmneziaWG هر بار یک کانفیگ می‌گیرد.",
                    "صف کپی wg://: همین کار را برای لینک‌های wg:// با Shadowrocket انجام می‌دهد.",
                    "متن ترکیبی: همه‌ی کانفیگ‌های انتخاب‌شده در یک متن، با جداکننده‌ی شماره‌دار. برای ذخیره یا ارسال خوب است، اما هیچ کلاینتی آن را یکجا وارد نمی‌کند.",
                    "همه‌ی لینک‌های wg://: هر خط یک لینک. برای وارد کردن در Shadowrocket، هر خط را جدا کپی کنید یا از صف استفاده کنید.",
                    "لیست کشور و آی‌پی: فقط نام کشور، شهر، آی‌پی و پینگ را کپی می‌کند، بدون کلید.",
                ]),
            ],
        },
        {
            "title": "تست واقعی با یک کلاینت",
            "blocks": [
                ("p", "سروری که «سالم» نشان داده می‌شود فقط از آزمون پینگ گذشته است. برای اطمینان آن را در یک کلاینت واقعی وصل کنید:"),
                ("ul", [
                    "AmneziaWG: در اپ، «افزودن تونل» را بزنید و کانفیگ را از متن وارد کنید.",
                    "Shadowrocket: لینک wg:// را کپی کنید. Shadowrocket هنگام کپی آن را از کلیپ‌بورد می‌خواند.",
                ]),
            ],
        },
        {
            "title": "کلید و امنیت",
            "blocks": [
                ("ul", [
                    "کلید PrivateKey که در تب تنظیمات وارد می‌کنید فقط در حافظه‌ی همین اجرای برنامه نگه داشته می‌شود و روی دیسک نوشته نمی‌شود. با بستن برنامه باید دوباره وارد کنید.",
                    "اگر کلید را در نسخه‌ی دسکتاپ هم وارد کرده باشید، در فایل surfshark_servers.json روی کامپیوتر همچنان هست.",
                    "آدرس همراه با ?t=... را به کسی ندهید. با آن می‌توان کپی کانفیگ و کلید را گرفت. هر بار اجرای دوباره، توکن تازه می‌سازد.",
                    "بعد از وارد کردن کانفیگ یا لینک در اپ، کلیپ‌بورد را پاک کنید: یک متن بی‌خطر را کپی کنید.",
                ]),
            ],
        },
        {
            "title": "مشکل‌های رایج",
            "blocks": [
                ("ul", [
                    "گوشی صفحه را باز نمی‌کند: مطمئن شوید هر دو به یک Wi-Fi یا هات‌اسپات وصل‌اند، و فایروال کامپیوتر پورت ۸۵۵۰ را نبندد.",
                    "«دسترسی ممنوع» می‌بینید: آدرس کامل با ?t=... را از ترمینال کامپیوتر کپی کنید.",
                    "کپی خودکار کار نمی‌کند: مرورگر روی آدرس بدون HTTPS کپی را مسدود می‌کند. متن را در کادر کانفیگ لمس طولانی کنید و دستی کپی کنید.",
                    "هیچ سروری نیست: اسکن را با VPN خاموش دوباره اجرا کنید.",
                ]),
            ],
        },
    ],
    "en": [
        {
            "title": "What this version does",
            "blocks": [
                ("p", "The phone version scans Surfshark servers, measures each server's ping, and shows the fastest first. For each server you can copy an AmneziaWG config or a wg:// link."),
                ("p", "The app runs on your computer and you open it on your phone over the same Wi-Fi or hotspot. The scan runs from the computer's internet connection."),
                ("note", "Ping is the time a small message needs to reach the server and come back. A lower number means a faster server."),
            ],
        },
        {
            "title": "Before you start",
            "blocks": [
                ("ol", [
                    "Turn your VPN fully OFF. While a VPN is on, the pings are not real.",
                    "Have your Surfshark WireGuard PrivateKey ready (44 characters). Copying a config does not work without it.",
                    "Connect the computer and the phone to the same Wi-Fi or hotspot.",
                    "This version uses plain HTTP. Use it only on your home Wi-Fi or your own hotspot, never on public Wi-Fi.",
                ]),
            ],
        },
        {
            "title": "Steps",
            "blocks": [
                ("ol", [
                    "On the computer, run python3 main.py --mobile. It prints an address like http://<IP>:8550/?t=...",
                    "Open that full address (with ?t=...) in the phone's browser.",
                    "In the Settings tab, enter your PrivateKey.",
                    "In the Scan tab, with the VPN off, tap scan and wait for it to finish.",
                    "In the Servers tab, see the working servers grouped by country.",
                    "Tap a server's copy button, or tick several servers and use the button at the bottom for a group copy.",
                ]),
            ],
        },
        {
            "title": "Single copy: config, wg:// and QR",
            "blocks": [
                ("ul", [
                    "Copy config (AmneziaWG): copies the full config of one server. In the AmneziaWG app, add a tunnel from text.",
                    "Copy wg:// (Shadowrocket): copies the wg:// link of that server. In Shadowrocket, add it from the clipboard.",
                    "Text and QR: shows the config and builds its QR code. You can also long-press the text to select and copy it by hand.",
                ]),
                ("note", "Both the config and the wg:// link contain your private key. Do not send them to anyone."),
            ],
        },
        {
            "title": "Group copy",
            "blocks": [
                ("p", "Tick servers, or tap \"select whole country\". Then tap the selection button at the bottom of the screen:"),
                ("ul", [
                    "Config queue: copies one config at a time. Import it, come back, and tap Next. The AmneziaWG app takes one config per paste.",
                    "wg:// queue: the same, for wg:// links in Shadowrocket.",
                    "Combined text: all selected configs in one text, with numbered separators. Good for saving or sending, but no client imports it in one go.",
                    "All wg:// links: one link per line. In Shadowrocket, copy them one by one, or use the queue.",
                    "Country and IP list: only the country, city, IP and ping, with no key.",
                ]),
            ],
        },
        {
            "title": "Test for real with a client app",
            "blocks": [
                ("p", "A server shown as working has only passed the ping test. Connect it in a real client to be sure:"),
                ("ul", [
                    "AmneziaWG: in the app, add a tunnel and paste the config text.",
                    "Shadowrocket: copy the wg:// link. Shadowrocket reads it from the clipboard when you add it.",
                ]),
            ],
        },
        {
            "title": "Key and safety",
            "blocks": [
                ("ul", [
                    "The PrivateKey you enter in Settings is kept only in memory for this run of the app. It is not written to disk, and you enter it again after a restart.",
                    "If you also entered the key in the desktop version, it is still in surfshark_servers.json on the computer.",
                    "Do not share the address with ?t=... . Anyone who has it can copy configs and the key. Each new start creates a new token.",
                    "After you import a config or link into the app, clear the clipboard by copying some harmless text.",
                ]),
            ],
        },
        {
            "title": "Common problems",
            "blocks": [
                ("ul", [
                    "The phone cannot open the page: check that both devices are on the same Wi-Fi or hotspot, and that the computer's firewall allows port 8550.",
                    "You see \"Access denied\": copy the full address with ?t=... from the computer's terminal.",
                    "Automatic copy does not work: the browser blocks clipboard access on a plain HTTP address. Long-press the text in the config box and copy it by hand.",
                    "No servers appear: run the scan again with the VPN off.",
                ]),
            ],
        },
    ],
}


def guide_sections(language: str) -> List[Section]:
    """Sections for a language, falling back to the default language."""
    return GUIDE.get(language) or GUIDE[DEFAULT_GUIDE_LANGUAGE]


def check_guide_parity() -> List[str]:
    """Returns a list of problems. An empty list means both languages match."""
    problems: List[str] = []
    fa, en = GUIDE["fa"], GUIDE["en"]
    if len(fa) != len(en):
        problems.append(f"section count differs: fa={len(fa)} en={len(en)}")
    for index, (fa_section, en_section) in enumerate(zip(fa, en), start=1):
        fa_blocks = [kind for kind, _ in fa_section["blocks"]]
        en_blocks = [kind for kind, _ in en_section["blocks"]]
        if fa_blocks != en_blocks:
            problems.append(f"section {index}: block kinds differ {fa_blocks} vs {en_blocks}")
        for kind, value in fa_section["blocks"] + en_section["blocks"]:
            if kind in ("ol", "ul") and (not isinstance(value, list) or not value):
                problems.append(f"section {index}: empty {kind} list")
            if kind in ("p", "note") and (not isinstance(value, str) or not value.strip()):
                problems.append(f"section {index}: empty {kind} text")
    return problems
