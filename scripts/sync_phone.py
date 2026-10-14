"""
Copies the shared modules into phone/ so that `flet build` can package them.

flet build only packages the project folder (phone/), so the phone app needs its own
copies of the modules it imports. Run this before building, locally or in CI:

    python3 scripts/sync_phone.py
"""

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


def sync():
    copied = []
    for name in PHONE_MODULES + PHONE_DATA:
        shutil.copyfile(os.path.join(ROOT, name), os.path.join(PHONE_DIR, name))
        copied.append(name)
    shutil.copytree(os.path.join(ROOT, PHONE_ASSETS), os.path.join(PHONE_DIR, PHONE_ASSETS), dirs_exist_ok=True)
    copied.append(PHONE_ASSETS + "/")
    return copied


if __name__ == "__main__":
    for name in sync():
        print("copied", name)
