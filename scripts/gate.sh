#!/usr/bin/env bash
# The merge gate: every check the CI runs, in one command, exiting non-zero on
# the first failure. Run it before every commit that is meant to merge.
#
#   ./scripts/gate.sh            # lint + frontend syntax + full test suite
#
# Exists because on 2026-09-06 a change was squash-merged with two failing
# tests: a multi-step shell script continued past an aborted patch step and
# the merge command ran regardless. A single gated entry point removes that
# failure mode.
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PY:-./venv/bin/python}"
if [ ! -x "$PY" ]; then
  echo "gate: python not found at $PY (set PY=/path/to/python)" >&2
  exit 2
fi
echo "== ruff"
"$PY" -m ruff check .
echo "== lockcheck"
"$PY" scripts/lockcheck.py
echo "== node --check static/js/app.js"
node --check static/js/app.js
echo "== pytest"
"$PY" -m pytest -q
echo "== gate passed"
