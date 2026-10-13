#!/bin/bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

echo "========================================================="
echo " Starting Surfshark AmneziaWG Studio for Restricted Networks"
echo "========================================================="

# Check Python 3
if ! command -v python3 &> /dev/null; then
    echo "Error: python3 is not installed or not in PATH."
    exit 1
fi

# Set up virtual environment if not already present
VENV_DIR="$DIR/.venv"
if [ ! -d "$VENV_DIR" ]; then
    echo "[*] Creating virtual environment at .venv..."
    python3 -m venv "$VENV_DIR"
    "$VENV_DIR/bin/pip" install --upgrade pip
    echo "[*] Installing dependencies from requirements.txt..."
    "$VENV_DIR/bin/pip" install -r requirements.txt
fi

# Run application
echo "[*] Launching application..."
"$VENV_DIR/bin/python" main.py "$@"
