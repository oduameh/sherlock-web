#!/usr/bin/env bash
# sherlock-web launcher: creates/uses the local venv, installs deps, starts uvicorn.
set -euo pipefail

cd "$(dirname "$0")"

if [ ! -d venv ]; then
  echo "Creating virtual environment..."
  python3 -m venv venv
fi

# Install/refresh dependencies when the requirements changed since the last
# install (hash stamp) or when the core imports are missing. The old check only
# looked for three packages, so dependencies added later never reached an
# existing venv and features silently degraded to "unavailable".
#
# The hash-pinned lock is preferred: every wheel pip downloads must match a
# recorded sha256, so a compromised or substituted package cannot install
# (target architecture §8 decision 10). requirements.txt is the fallback only
# when the lock is absent.
if [ -f requirements.lock ]; then
  REQ=requirements.lock; INSTALL=(--require-hashes -r requirements.lock)
else
  REQ=requirements.txt; INSTALL=(-r requirements.txt)
fi
STAMP="venv/.requirements.sha256"
WANT="$(shasum -a 256 "$REQ" | cut -d' ' -f1)"
HAVE="$(cat "$STAMP" 2>/dev/null || true)"
if [ "$WANT" != "$HAVE" ] || ! ./venv/bin/python -c "import fastapi, uvicorn, sherlock_project" 2>/dev/null; then
  echo "Installing dependencies from $REQ (changed or core packages missing)..."
  ./venv/bin/pip install -q --upgrade pip
  ./venv/bin/pip install -q "${INSTALL[@]}"
  echo "$WANT" > "$STAMP"
fi
# The stealth ladder (Scrapling + patchright Chromium) is an optional extra:
#   ./venv/bin/pip install -r requirements-stealth.txt && ./venv/bin/patchright install chromium

PORT="${PORT:-8420}"
echo "Starting sherlock-web on http://127.0.0.1:${PORT}"
exec ./venv/bin/uvicorn app:app --host 127.0.0.1 --port "${PORT}"
