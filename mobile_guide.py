"""
mobile_guide.py: In-app guide for the phone UI, in Persian and English.

Each language has the same sections in the same order, and every section is a
list of blocks: ('p', text), ('ol', [steps]), ('ul', [items]), ('note', text).
check_guide_parity() reports any mismatch; tests/test_mobile.py runs it.

The guide describes the phone UI in mobile_app.py. Keep the two in step: the
button labels quoted here must match the labels in mobile_app.py.
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
                ("p", "این نسخه‌ی گوشی سرورهای Surfshark را اسکن می‌کند، پینگ هر سرور را می‌سنجد و سریع‌ترین‌ها را نشان می‌دهد. برای هر سرور می‌توانید کانفیگ AmneziaWG یا لینک wg:// بگیرید."),
                ("p", "نسخه‌ی نصب‌شده روی گوشی (IPA یا APK) مستقل است و به کامپیوتر نیاز ندارد. اسکن از اینترنت خود گوشی انجام می‌شود. اگر نسخه‌ی کامپیوتر را در شبکه‌ی محلی باز می‌کنید، برنامه روی کامپیوتر اجرا می‌شود و از گوشی با همان Wi-Fi باز می‌شود."),
                ("note", "«پینگ» زمانی است که یک پیام کوچک لازم دارد تا به سرور برسد و برگردد. عدد کمتر یعنی سرور سریع‌تر."),
            ],
        },
        {
            "title": "قبل از شروع",
            "blocks": [
                ("ol", [
                    "VPN را کاملاً خاموش کنید. اگر VPN روشن باشد، پینگ‌ها واقعی نیستند.",
                    "کلید PrivateKey اکانت Surfshark خود را (۴۴ کاراکتر) آماده کنید. بدون آن کپی کانفیگ کار نمی‌کند.",
                    "اگر نسخه‌ی کامپیوتر را استفاده می‌کنید، کامپیوتر و گوشی را به یک Wi-Fi یا هات‌اسپات وصل کنید.",
                    "نسخه‌ی کامپیوتر با HTTP ساده کار می‌کند. فقط در Wi-Fi خانگی یا هات‌اسپات شخصی خودتان استفاده کنید، نه در Wi-Fi عمومی.",
                ]),
            ],
        },
        {
            "title": "مراحل کار",
            "blocks": [
                ("ol", [
                    "برنامه‌ی نصب‌شده را روی گوشی باز کنید. اگر از نسخه‌ی کامپیوتر استفاده می‌کنید، در ترمینال کامپیوتر دستور python3 main.py --mobile را اجرا کنید و آدرس کامل را در مرورگر گوشی باز کنید.",
                    "در تب «تنظیمات» کلید PrivateKey را وارد کنید.",
                    "در تب «اسکن» با VPN خاموش، «شروع اسکن» را بزنید و تا پایان صبر کنید.",
                    "در تب «سرورها» سرورهای سالم را بر اساس کشور ببینید.",
                    "دکمه‌ی کپی هر سرور را بزنید، یا چند سرور را تیک بزنید. وقتی سروری انتخاب شده باشد، دکمه‌ی «انتخاب» پایین صفحه ظاهر می‌شود؛ آن را برای کپی گروهی بزنید.",
                ]),
            ],
        },
        {
            "title": "فیلتر قاره و انتخاب گروهی",
            "blocks": [
                ("p", "بالای فهرست سرورها این بخش‌ها هستند:"),
                ("ul", [
                    "دکمه‌های قاره: فقط سرورهای همان قاره را نشان می‌دهند. «همه‌ی قاره‌ها» یعنی بدون فیلتر. عدد کنار هر قاره تعداد سرورهای آن است.",
                    "کادر جستجو: نام کشور، شهر یا آی‌پی را بنویسید.",
                    "«انتخاب همه‌ی نمایش‌داده‌شده»: همه‌ی سرورهایی را که الان روی صفحه‌اند (بعد از فیلتر قاره و جستجو) انتخاب می‌کند.",
                    "«انتخاب کل کشور» در هر کشور: همه‌ی سرورهای همان کشور را انتخاب می‌کند. اگر همه انتخاب باشند، همین دکمه «لغو انتخاب کشور» می‌شود.",
                    "«پاک کردن انتخاب»: همه‌ی تیک‌ها را برمی‌دارد.",
                ]),
            ],
        },
        {
            "title": "کپی تکی: کانفیگ، wg:// و QR",
            "blocks": [
                ("ul", [
                    "کپی کانفیگ (AmneziaWG): متن کامل کانفیگ یک سرور را کپی می‌کند. در اپ AmneziaWG تونل جدید را از متن وارد کنید.",
                    "کپی wg:// (Shadowrocket): لینک wg:// همان سرور را کپی می‌کند. در Shadowrocket آن را از کلیپ‌بورد اضافه کنید.",
                    "متن و QR: کانفیگ را نشان می‌دهد و کد QR آن را روی صفحه می‌سازد. کد QR را از گوشی دیگری اسکن کنید. متن را هم می‌توانید با لمس طولانی دستی کپی کنید.",
                ]),
                ("note", "کانفیگ و لینک wg:// هر دو کلید خصوصی شما را دارند. آن‌ها را برای کسی نفرستید."),
            ],
        },
        {
            "title": "کپی گروهی",
            "blocks": [
                ("p", "سرورها را تیک بزنید، سپس دکمه‌ی «انتخاب» پایین صفحه را بزنید. گزینه‌ها:"),
                ("ul", [
                    "صف کپی کانفیگ (یکی‌یکی برای AmneziaWG): هر بار یک کانفیگ کپی می‌شود. آن را در اپ وارد کنید، برگردید و «بعدی» را بزنید. اپ AmneziaWG هر بار یک کانفیگ می‌گیرد.",
                    "صف کپی لینک wg:// (یکی‌یکی برای Shadowrocket): همین کار را برای لینک‌های wg:// انجام می‌دهد. برای Shadowrocket مطمئن‌ترین روش همین صف است.",
                    "کپی متن ترکیبی همه کانفیگ‌ها: همه‌ی کانفیگ‌ها در یک متن، با جداکننده‌ی شماره‌دار. برای ذخیره یا ارسال خوب است، اما کلاینت‌ها آن را یکجا وارد نمی‌کنند.",
                    "کپی همه لینک‌های wg:// (هر خط یک لینک): همه‌ی لینک‌ها در متن چندخطی. Shadowrocket ممکن است چنین متنی را یکجا وارد نکند.",
                    "کپی اشتراک Shadowrocket (base64، همه‌ی سرورها): همه‌ی لینک‌ها به‌صورت یک متن base64 برای ساخت اشتراک. اگر Shadowrocket آن را از کلیپ‌بورد نپذیرفت، از صف لینک wg:// استفاده کنید.",
                    "کپی لیست کشور، شهر و آی‌پی: فقط نام کشور، شهر، آی‌پی و پینگ را کپی می‌کند، بدون کلید.",
                ]),
                ("note", "گزینه‌های گروهی برای Shadowrocket روی گوشی واقعی هنوز کامل تست نشده‌اند. هر گزینه را یک بار امتحان کنید و ببینید کدام وارد می‌شود."),
            ],
        },
        {
            "title": "تست واقعی با یک کلاینت",
            "blocks": [
                ("p", "سروری که «سالم» نشان داده می‌شود فقط از آزمون پینگ گذشته است. برای اطمینان آن را در یک کلاینت واقعی وصل کنید:"),
                ("ul", [
                    "AmneziaWG: در اپ، افزودن تونل را بزنید و متن کانفیگ را وارد کنید.",
                    "Shadowrocket: لینک wg:// یک سرور را کپی کنید و از کلیپ‌بورد اضافه کنید. اگر نسخه‌ی Shadowrocket شما این کار را نکرد، همان لینک را از گزینه‌ی دیگری در Shadowrocket وارد کنید.",
                ]),
                ("note", "اگر بعد از اتصال اینترنت قطع شد یا سایت‌ها باز نشدند، سرور دیگری را امتحان کنید. پینگ خوب همیشه تضمین اتصال نیست."),
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
                ("p", "The installed app (IPA or APK) is standalone and needs no computer. The scan runs from the phone's own connection. If you open the computer version over the local network, it runs on the computer and you open it on the phone over the same Wi-Fi."),
                ("note", "Ping is the time a small message needs to reach the server and come back. A lower number means a faster server."),
            ],
        },
        {
            "title": "Before you start",
            "blocks": [
                ("ol", [
                    "Turn your VPN fully OFF. While a VPN is on, the pings are not real.",
                    "Have your Surfshark WireGuard PrivateKey ready (44 characters). Copying a config does not work without it.",
                    "If you use the computer version, connect the computer and the phone to the same Wi-Fi or hotspot.",
                    "The computer version uses plain HTTP. Use it only on your home Wi-Fi or your own hotspot, never on public Wi-Fi.",
                ]),
            ],
        },
        {
            "title": "Steps",
            "blocks": [
                ("ol", [
                    "Open the installed app on the phone. If you use the computer version: run python3 main.py --mobile and open the full address in the phone's browser.",
                    "In the Settings tab, enter your PrivateKey.",
                    "In the Scan tab, with the VPN off, tap Start scan and wait for it to finish.",
                    "In the Servers tab, see the working servers grouped by country.",
                    "Tap a server's copy button, or tick several servers. Once a server is selected, the Select button at the bottom of the screen appears; tap it for a group copy.",
                ]),
            ],
        },
        {
            "title": "Filter by continent and select in bulk",
            "blocks": [
                ("p", "At the top of the server list you will find these controls:"),
                ("ul", [
                    "Continent buttons: show only the servers of that continent. \"All continents\" means no filter. The number next to each continent is its server count.",
                    "Search box: type a country, city or IP.",
                    "\"Select all shown\": selects every server currently on the screen (after the continent filter and the search).",
                    "\"Select whole country\" on each country: selects all servers of that country. When they are all selected, the button becomes \"Deselect country\".",
                    "\"Clear selection\": removes all ticks.",
                ]),
            ],
        },
        {
            "title": "Single copy: config, wg:// and QR",
            "blocks": [
                ("ul", [
                    "Copy config (AmneziaWG): copies the full config of one server. In the AmneziaWG app, add a tunnel from text.",
                    "Copy wg:// (Shadowrocket): copies the wg:// link of that server. In Shadowrocket, add it from the clipboard.",
                    "Text and QR: shows the config and draws its QR code on the screen. Scan the QR code with another phone. You can also long-press the text to select and copy it by hand.",
                ]),
                ("note", "Both the config and the wg:// link contain your private key. Do not send them to anyone."),
            ],
        },
        {
            "title": "Group copy",
            "blocks": [
                ("p", "Tick servers, then tap the Select button at the bottom of the screen. The options:"),
                ("ul", [
                    "Config queue (one at a time for AmneziaWG): copies one config at a time. Import it in the app, come back, and tap Next. The AmneziaWG app takes one config per paste.",
                    "wg:// queue (one at a time for Shadowrocket): the same, for wg:// links. For Shadowrocket this is the safest group method.",
                    "Combined text: all selected configs in one text, with numbered separators. Good for saving or sending, but no client imports it in one go.",
                    "All wg:// links (one link per line): all links in one multi-line text. Shadowrocket may not import a multi-line text in one go.",
                    "Shadowrocket subscription (base64, all servers): all links encoded as one base64 text, for making a subscription. If Shadowrocket does not accept it from the clipboard, use the wg:// queue.",
                    "Country, city and IP list: only the country, city, IP and ping, with no key.",
                ]),
                ("note", "The group options for Shadowrocket have not been fully tested on a real phone yet. Try each one once and see which one imports."),
            ],
        },
        {
            "title": "Test for real with a client app",
            "blocks": [
                ("p", "A server shown as working has only passed the ping test. Connect it in a real client to be sure:"),
                ("ul", [
                    "AmneziaWG: in the app, add a tunnel and paste the config text.",
                    "Shadowrocket: copy the wg:// link of one server and add it from the clipboard. If your Shadowrocket version does not accept it that way, add it with another method that Shadowrocket offers.",
                ]),
                ("note", "If the connection drops or sites do not open after connecting, try another server. A good ping does not guarantee a working connection."),
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
                    "You see \"دسترسی ممنوع\" (access denied): copy the full address with ?t=... from the computer's terminal.",
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
