"""
Copies the shared modules into phone/ so that `flet build` can package them.

flet build only packages the project folder (phone/), so the phone app needs its own
copies of the modules it imports. Run this before building, locally or in CI:

    python3 scripts/sync_phone.py
"""

import json
import os
import shutil

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PHONE_DIR = os.path.join(ROOT, "phone")

# Every root-level module the phone app imports, plus the blueprint it reads.
# tests/test_mobile.py checks this list against the real imports.
PHONE_MODULES = (
    "mobile_app.py",
    "mobile_core.py",
    "mobile_guide.py",
    "checker.py",
    "config_builder.py",
    "browser_harvest.py",
    "dns_resolver.py",
    "scan_cache.py",
    "vpn_detector.py",
)
PHONE_DATA = ("surfshark_servers.json",)
PHONE_ASSETS = "assets"  # fonts, copied as a folder

# The phone bundle ships with no key. The user enters their own key in the app, and the scanner
# falls back to its dummy probe key (mobile_core.scan_probe_key) when none is stored.
PHONE_BLANK_KEY = ""


def phone_blueprint_text(source_path: str) -> str:
    """
    The blueprint as the phone bundle gets it: the same servers, with the PrivateKey left blank. A key
    the user saved on the computer must never end up inside the IPA or APK.
    """
    with open(source_path, encoding="utf-8") as handle:
        data = json.load(handle)
    if isinstance(data.get("user_interface"), dict):
        data["user_interface"]["private_key"] = PHONE_BLANK_KEY
    return json.dumps(data, ensure_ascii=False, indent=2) + "\n"


def sync(phone_dir: str = PHONE_DIR):
    copied = []
    os.makedirs(phone_dir, exist_ok=True)
    for name in PHONE_MODULES:
        shutil.copyfile(os.path.join(ROOT, name), os.path.join(phone_dir, name))
        copied.append(name)
    for name in PHONE_DATA:
        with open(os.path.join(phone_dir, name), "w", encoding="utf-8") as handle:
            handle.write(phone_blueprint_text(os.path.join(ROOT, name)))
        copied.append(name + " (key replaced)")
    shutil.copytree(os.path.join(ROOT, PHONE_ASSETS), os.path.join(phone_dir, PHONE_ASSETS), dirs_exist_ok=True)
    copied.append(PHONE_ASSETS + "/")
    return copied


if __name__ == "__main__":
    for name in sync():
        print("copied", name)
