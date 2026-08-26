#!/usr/bin/env bash
# Launch God's Eye View (github.com/bilawalsidhu/gods-eye-view, MIT) as
# sherlock-web's geospatial "God's Eye View" workspace.
#
# It runs as its OWN service (a Vite/Node server that proxies ~15 live data
# feeds); sherlock-web's [GODSEYE] tab embeds it. This script clones it once
# into ./godseye (gitignored), installs its deps, and starts its dev server.
#
# Keys stay with you. At minimum set GOOGLE_MAPS_API_KEY (Google Cloud -> Map
# Tiles API) — it is the only *required* key and is client-exposed by design, so
# scope it (HTTP-referrer + API restriction). Everything else is optional; the
# free/anonymous layers (flights via anon OpenSky, satellites, fires, quakes,
# radio, launches, ...) work with no keys. OpenAI (voice) and OpenSky OAuth are
# opt-in.
set -euo pipefail
cd "$(dirname "$0")/.."

REPO="https://github.com/bilawalsidhu/gods-eye-view.git"
DIR="godseye"
PORT="${GODSEYE_PORT:-4173}"

if [ ! -d "$DIR/.git" ]; then
  echo "==> Cloning God's Eye View into ./$DIR"
  git clone --depth 1 "$REPO" "$DIR"
fi

cd "$DIR"

if [ ! -d node_modules ]; then
  echo "==> Installing dependencies (Puppeteer browser download skipped)"
  PUPPETEER_SKIP_DOWNLOAD=1 npm install
fi

if [ ! -f .env ]; then
  cp .env.example .env
  echo "==> Created godseye/.env from the template — edit it and add your"
  echo "    GOOGLE_MAPS_API_KEY before the 3D globe will render."
fi

# Lean on the free/anonymous data sources by default (no OpenSky account needed).
export OPENSKY_AUTH_MODE="${OPENSKY_AUTH_MODE:-anon}"

echo "==> Starting God's Eye View on http://localhost:${PORT}"
echo "    (sherlock-web's [GODSEYE] tab embeds this; set GODSEYE_URL if you"
echo "     run it elsewhere.)"
exec npm run dev -- --host localhost --port "${PORT}"
