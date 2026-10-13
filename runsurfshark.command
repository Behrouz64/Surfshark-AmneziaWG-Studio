#!/bin/bash
# Local launcher for Surfshark AmneziaWG Studio v5.1
cd "$(dirname "$0")"
VENV="../../Surfshark_AmneziaWG/.venv"
if [ -f "$VENV/bin/python" ]; then
    "$VENV/bin/python" main.py
else
    python3 main.py
fi
