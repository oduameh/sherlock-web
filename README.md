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
- `GET /api/history` — recent runs
- `GET /api/history/{id}` — full stored results of one run
