#!/usr/bin/env bash
# sherlock-web launcher: creates/uses the local venv, installs deps, starts uvicorn.
set -euo pipefail

cd "$(dirname "$0")"

if [ ! -d venv ]; then
  echo "Creating virtual environment..."
  python3 -m venv venv
fi

# Install/refresh dependencies only if something is missing.
if ! ./venv/bin/python -c "import fastapi, uvicorn, sherlock_project" 2>/dev/null; then
  echo "Installing dependencies..."
  ./venv/bin/pip install -q --upgrade pip
  ./venv/bin/pip install -q -r requirements.txt
fi

PORT="${PORT:-8420}"
echo "Starting sherlock-web on http://127.0.0.1:${PORT}"
exec ./venv/bin/uvicorn app:app --host 127.0.0.1 --port "${PORT}"
