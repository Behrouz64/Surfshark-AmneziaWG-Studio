"""
Entry point of the phone app (iOS and Android). The shared modules are copied next to this file
by scripts/sync_phone.py before the build.

The app bundle is read-only on mobile, so the app works in the first writable folder it finds.
The blueprint (surfshark_servers.json) is copied there on the first run.
"""

import os

import flet as ft

from mobile_core import prepare_data_folder

_HERE = os.path.dirname(os.path.abspath(__file__))
_CANDIDATES = [
    os.path.join(os.path.expanduser("~"), "Documents"),
    os.path.expanduser("~"),
    os.environ.get("FLET_APP_STORAGE_DATA", ""),
    _HERE,
]
_folder = prepare_data_folder(_CANDIDATES, os.path.join(_HERE, "surfshark_servers.json"))
if _folder:
    os.chdir(_folder)

from mobile_app import main as mobile_main  # noqa: E402  (imported after chdir: data paths are relative)

# Called at module level, not under __main__: mobile platforms load this file under another name.
ft.app(target=mobile_main, assets_dir=os.path.join(_HERE, "assets"))
