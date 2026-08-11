# sherlock-web

A polished local web UI around [Sherlock](https://github.com/sherlock-project/sherlock) —
the OSINT tool that hunts social media accounts by username across ~400 sites.

## Features

- Single or bulk username search (comma/newline-separated) in one run
- Live results over Server-Sent Events: found profiles appear as each site is checked,
  with per-user progress bars and an overall progress bar
- Site filtering via a searchable multi-select (empty selection = all sites)
- NSFW toggle, configurable per-site timeout, stop button
- Error surfacing: rate-limited / WAF-blocked sites show up as dimmed "error" rows
- Export the current results as CSV or JSON (client-side)
- Search history persisted in `history.db` (SQLite); click a past run to reload its results

## Run

```bash
cd sherlock-web
./run.sh
```

Then open <http://127.0.0.1:8420>.

`run.sh` creates a local `venv` on first use, installs `requirements.txt`
(FastAPI, uvicorn, `sherlock-project`), and starts uvicorn. Set `PORT=9000 ./run.sh`
to use a different port.

## Access gate (optional)

Set the `APP_PASSWORD` environment variable to put the whole app behind HTTP
Basic auth — every route, including `/` and the SSE stream, then requires that
password (any username works). Leave it unset and the app is fully open.

```bash
APP_PASSWORD=secret ./run.sh
```

## Deploy to Railway

Railway auto-detects the Python app (Nixpacks). `railway.json` pins the start
command `uvicorn app:app --host 0.0.0.0 --port ${PORT:-8420}` and
`.python-version` pins Python 3.12.

**A) Railway dashboard (recommended)**

1. <https://railway.com> → New Project → **Deploy from GitHub repo** → pick
   `oduameh/sherlock-web`.
2. In the service's **Variables** tab add `APP_PASSWORD` (strongly recommended —
   otherwise anyone with the URL can run searches from your deployment).
3. Railway assigns a public domain under **Settings → Networking → Generate
   Domain**. Copy the URL.
4. Optional, for the Android build: in the GitHub repo go to
   **Settings → Secrets and variables → Actions → Variables** and set
   `SERVER_URL` to that Railway URL, then run the **Android APK** workflow
   (see [android/README.md](android/README.md)).

**B) Railway CLI**

```bash
npm i -g @railway/cli
railway login          # or: export RAILWAY_TOKEN=<project token>
railway init           # link/create a project
railway variables set APP_PASSWORD=your-password
railway up             # deploys the current directory
railway domain         # get a public URL
```

## Android app

`android/` contains a minimal Kotlin WebView wrapper. The APK is built in the
cloud by the **Android APK** GitHub Actions workflow — no local Android SDK
needed. See [android/README.md](android/README.md) for how to set the
`SERVER_URL` repo variable, run the workflow, and install the APK.

The web app is also an installable PWA (manifest + service worker under
`static/`): open the deployed URL in a mobile browser and "Add to Home Screen".

## Usage notes

- Type one or more usernames, optionally narrow the site list, and hit **Start search**.
- Green rows are found profiles (links open in a new tab); dimmed rows are sites that
  errored out (rate limit, WAF, illegal username for that site).
- Default timeout is 10s per site. Scanning all ~400 sites for several usernames takes
  a while — narrowing the site selection speeds things up a lot.
- The backend uses Sherlock as a library (`sherlock_project.sherlock.sherlock` with a
  custom `QueryNotify` subclass), not the CLI.
- The site list honors Sherlock's upstream exclusion list (`SitesInformation` default),
  so sites Sherlock flags as dead (e.g. Reddit in 0.16.0) are not offered: 433 of 481
  sites are scan-enabled.
- Sherlock's bundled `data.json` in this version carries no category/tags per site,
  only an `isNSFW` flag — that flag is what the UI shows.

## API

- `GET /api/sites` — full site list (`name`, `nsfw`)
- `GET /api/search/stream?usernames=alice,bob&timeout=10&nsfw=false&sites=github,twitter` — SSE stream
  (`meta`, `user_start`, `found`, `error`, `progress`, `user_done`, `done` events)
- `GET /api/history` — recent runs (includes `kind`: `sherlock` or `recon`)
- `GET /api/history/{id}` — full stored results of one run

## v2 — Deep recon

Beyond the classic Sherlock quick scan, the app now has a **Deep recon** mode
(tab in the UI) that turns it into a broader OSINT reconnaissance tool. All of
it uses **public data only** — no logins, no CAPTCHA solving, no breach
databases.

New capabilities:

- **Dual-engine username search** — runs Sherlock (sync, in a thread) and
  [Maigret](https://github.com/soxoj/maigret) (async, ~3200-site database,
  top ~1200 by rank) at the same time. Results are tagged with their engine
  and merged when both engines find the same site (the row lists both).
- **Username permutations** (`recon/permutations.py`) — separator swaps,
  reversed word order, vowel-stripped forms, and common affixes
  (`the`, `real`, `1`, `01`, `123`, `_official`, `tv`, `hq`, …), capped at 24.
  Variants are scanned against a curated ~40-site high-value list only, and
  results are tagged with `variant_of`.
- **Email pivot** (`recon/email_pivot.py`) — given an email: (a) public
  Gravatar profile lookup (display name, avatar, linked accounts), and
  (b) [holehe](https://github.com/megadose/holehe) registered-account checks
  across ~120 sites, run sequentially with delays to be rate-friendly. If only
  an email is given, its local part is scanned as the username.
- **Profile enrichment** (`recon/enrich.py`) — fetches each found public
  profile page (max 40/run, 5 concurrent, 512 KB cap per page) and extracts
  `<title>`, Open Graph tags, and JSON-LD Person fields. Shown inline in the
  UI (avatar + name + bio snippet).
- **Correlation** (`recon/correlate.py`) — clusters found accounts by avatar
  perceptual hash (8x8 average hash, Pillow), display-name similarity
  (difflib), and bio word overlap (Jaccard). Confidence = avatar 50 / name 30 /
  bio 20. Emitted as a final `correlation` event and rendered with confidence
  bars. Heuristic — expect false positives; verify manually.
- **HTML report** — `GET /api/recon/report/{history_id}` returns a
  self-contained dark-theme report (accounts table with engine badges and
  enrichment, variant matches, email pivot, correlation clusters). Works for
  classic sherlock runs too, in a reduced form.

New endpoints:

- `GET /api/recon/stream?usernames=alice&email=a@b.c&variants=true&timeout=10&nsfw=false&sites=`
  — SSE stream (`meta`, `engine_start`, `found`, `merged`, `error`, `progress`,
  `engine_done`, `engine_error`, `variants_planned`, `phase`, `enriched`,
  `email`, `email_done`, `correlation`, `done`, `fatal` events). The `done`
  event carries `history_id` for report download. `sites` is an optional
  case-insensitive subset applied to both engines.
- `GET /api/recon/report/{history_id}` — self-contained HTML report.

Storage: recon runs share the `runs` table (new `kind` column, added by an
automatic migration on startup — existing rows keep working). Enrichment,
email, and correlation results are stored in the run's JSON blob.

Graceful degradation: if `maigret` or `holehe` fail to import, the app still
boots — the recon endpoint runs with whatever engines are available and logs
a warning.

### Responsible use

Deep recon is for legitimate security research, journalism, and checking your
**own** footprint. It only touches public pages and public APIs, but
registered-account checks (holehe) can reveal where an email has accounts —
use it only on addresses you are authorized to investigate, respect site rate
limits and terms of service, and comply with applicable law (GDPR and
similar). Correlation results are statistical guesses, not proof of identity.

## Usage notes
