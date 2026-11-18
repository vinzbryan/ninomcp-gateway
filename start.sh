#!/usr/bin/env bash
# Start NinoMCP Gateway (creates .venv on first run).
set -e
cd "$(dirname "$0")"
if [ ! -d .venv ]; then
  python3 -m venv .venv
  .venv/bin/pip install -r requirements.txt
fi
export GATEWAY_PUBLIC_BASE="${GATEWAY_PUBLIC_BASE:-http://localhost:8000}"
exec .venv/bin/python app.py
