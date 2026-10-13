#!/usr/bin/env bash
# Runs the unit tests in a fresh .venv on Python 3.11 (macOS, or any Unix shell).
#
#   ./scripts/mac_test.sh
#   PYTHON=/opt/homebrew/bin/python3.11 ./scripts/mac_test.sh   # if python3.11 is not on PATH
#
# The tests do not start the GUI and do not touch Shadowrocket. They only use temp dirs.
set -euo pipefail

cd "$(dirname "$0")/.."
PYTHON_BIN="${PYTHON:-python3.11}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "[!] $PYTHON_BIN was not found. On macOS run: brew install python@3.11"
    exit 1
fi

if [ -d .venv ] && ! .venv/bin/python -c 'import sys; sys.exit(0 if sys.version_info[:2] == (3, 11) else 1)' 2>/dev/null; then
    echo "[!] .venv exists but was not made with Python 3.11. Delete the .venv folder and run this again."
    exit 1
fi

echo "[*] Using $("$PYTHON_BIN" --version)"
if [ ! -d .venv ]; then
    "$PYTHON_BIN" -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

echo "[*] Running tests"
python -m unittest -v
