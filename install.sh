#!/usr/bin/env bash
set -euo pipefail

command -v python3 >/dev/null || { echo "Python 3 is required" >&2; exit 1; }
python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,12) else 1)' || { echo "Python 3.12+ is required" >&2; exit 1; }
command -v nmap >/dev/null || echo "Warning: Nmap is not installed; demo and XML import remain available." >&2
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e .
echo "Installed. Run: source .venv/bin/activate && nexhost-hsa gui"

