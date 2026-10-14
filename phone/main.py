"""
Entry point of the phone app (iOS and Android). The shared modules are copied next to this file
by scripts/sync_phone.py before the build.

The app bundle is read-only on iOS, so the app works in a writable folder: the first of
~/Documents or ~ that accepts a file. The blueprint is copied there on the first run.
"""

import os
import shutil

import flet as ft


def _prepare_writable_folder():
    here = os.path.dirname(os.path.abspath(__file__))
    for candidate in (os.path.join(os.path.expanduser("~"), "Documents"), os.path.expanduser("~")):
        try:
            os.makedirs(candidate, exist_ok=True)
            probe = os.path.join(candidate, ".write_test")
            with open(probe, "w", encoding="utf-8") as f:
                f.write("ok")
            os.remove(probe)
        except OSError:
            continue
        seed = os.path.join(here, "surfshark_servers.json")
        target = os.path.join(candidate, "surfshark_servers.json")
        if not os.path.exists(target) and os.path.exists(seed):
            shutil.copyfile(seed, target)
        os.chdir(candidate)
        return candidate
    return here


_prepare_writable_folder()

from mobile_app import main as mobile_main  # noqa: E402  (imported after chdir: paths are relative)

# Called at module level, not under __main__: mobile platforms load this file under another name.
ft.app(target=mobile_main)
