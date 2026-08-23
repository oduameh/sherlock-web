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

## Development & tests

Install the dev dependencies and run the test suite (pure-function and
security-guard coverage for the recon engines — no network required):

```bash
./venv/bin/pip install -r requirements-dev.txt
./venv/bin/python -m pytest -q
```

## Persistence — SQLite or Postgres

The backend is chosen by the `DATABASE_URL` environment variable:

- **Unset (default)** — SQLite (`history.db`), zero-config for local development.
- **A `postgres://` / `postgresql://` URL** — Postgres, the production backend.

All application SQL is written once in the SQLite idiom; `dbconn.py` translates
placeholders and primary keys for Postgres so the two stay in sync. **This
matters on Railway:** its disk is ephemeral, so SQLite there loses every
investigation, watchlist, and alert on each redeploy — point `DATABASE_URL` at
the Railway Postgres add-on and casework survives.

```bash
# Railway: add the Postgres plugin, then it injects DATABASE_URL automatically.
# Local, against a throwaway Postgres:
DATABASE_URL=postgresql://postgres:pass@localhost:5432/sherlock ./run.sh

# One-shot import of an existing history.db into Postgres:
DATABASE_URL=postgresql://... ./venv/bin/python migrate_to_postgres.py history.db
```

CI runs the suite against SQLite and a separate boot + persistence check against
real Postgres, so both backends stay green.

## Reliability & security hardening

- **Concurrent SQLite** — all connections go through `dbconn.connect()`, which
  enables WAL journaling and a busy timeout so the background watchlist monitor
  and live scans no longer race into `database is locked`.
- **SSRF-guarded fetches** — every outbound request the app makes for
  enrichment, avatar hashing, and email pivots goes through
  `recon/safeweb.py`, which follows redirects but refuses any host that
  resolves to private / loopback / link-local / reserved IP space (blocking the
  cloud-metadata and internal-service SSRF class on deployments). Response
  bodies are size-capped while streaming.
- **Input validation** — email inputs are format-checked before any pivot runs,
  so a malformed address can't trigger a wasted holehe run or a misleading
  graph node.

`run.sh` creates a local `venv` on first use, installs `requirements.txt`
(FastAPI, uvicorn, `sherlock-project`), and starts uvicorn. Set `PORT=9000 ./run.sh`
to use a different port.

## Adaptive routing

On datacenter deployments (Railway's IPs have poor reputation) a large share of
site checks fail: WAF blocks and 429s, transient connect/DNS timeouts, and site
detectors that have gone stale. The routing layer (`recon/router.py`) classifies
every failure, remembers per-site health, stops hammering dead sites, and
retries the failures that are actually worth retrying.

**Error taxonomy.** Every per-site result (both engines, plus the watchlist
monitor's light scans) is classified from its status + context into:
`timeout`, `dns`, `tls`, `conn_reset`, `http_429` (rate limit),
`http_403_waf` (WAF/block page), `http_5xx`, `detector_stale` (e.g. an
ILLEGAL status or a detector regex that no longer matches), or `unknown`.

**Circuit breaker.** Observations are kept in a `site_health` table (sliding
window of the last 50 per site+engine, EWMA latency, consecutive failures).
A site trips open after **5 consecutive failures**, or when its failure rate
exceeds **60% over the last 20 observations** (min 10 observations). Open
sites are excluded from scans — the full pipeline, the quick scan, *and* the
monitor's light scans — for a **15-minute cooldown that doubles on each
re-trip, up to 4 hours**. After the cooldown the site is half-open: it is
scanned once; success closes the circuit (cooldown resets), failure re-trips
it with the doubled cooldown. Skips are never silent: scans emit a
`skipped_degraded` SSE event listing the excluded sites.

Every check is recorded, but not on the hot path: observations are buffered in
memory during a run and flushed to `site_health` in a single transaction at the
end. This keeps the per-check callback (called thousands of times per run, some
on the async event loop) free of blocking SQLite I/O and free of the
lost-update race that concurrent per-observation writes would otherwise hit.
Circuit state only takes effect at the *start* of the next run, so end-of-run
persistence is behaviourally identical.

**Smart retries.** After each engine pass, failures classed as transient
(`timeout`, `conn_reset`, `http_5xx`, `dns`) are retried **once** after a
jittered 5–15s delay, sequentially, capped at **40 retries per run**; each
attempt emits a `retry` SSE event. 429/WAF-class failures are *not* retried
in-run (immediate retries are pointless) — the circuit breaker handles them
across runs.

**Observability.**

- `GET /api/health/sources` — per-site failure rate, dominant error class,
  circuit state (open/half-open/closed + cooldown remaining), EWMA latency,
  sorted worst-first, plus aggregate stats. The UI's **Health** tab renders it.
- The run's final `done` payload gains `error_breakdown` (counts per class)
  and `degraded_sources` — additive only; all existing event names/fields are
  unchanged.

**Optional proxy pool (off by default).** Set `PROXY_LIST` to a
comma-separated list of proxy URLs, e.g.
`PROXY_LIST=http://user:pass@host:8080,socks5://host:1080`. When set, one
proxy is picked per run (round-robin) and passed to both engines
(Sherlock's `proxy=` and maigret's `proxy=`). Per-proxy health is tracked in
a `proxy_health` table; a proxy whose failure rate exceeds **70% over 10+
uses** is benched for 30 minutes, then automatically re-tried. With no
proxies configured, behavior is exactly as before — zero overhead.

Two honest caveats:

- **Good proxies cost money.** Free proxy lists are worse than nothing —
  slow, dead, or already burned by the same WAFs you're trying to avoid.
- WAF-class blocks are an **IP-reputation problem**. Routing detects them,
  stops wasting requests on them, and reports them honestly — but the only
  full fix is egress through residential proxies, which are a paid service.

Everything degrades gracefully: if the `site_health` table is unavailable the
app logs one warning and scans run unrouted, exactly as before.

## Stealth fetch ladder (optional)

Plain-HTTP enrichment fails silently on modern sites: a non-browser TLS
handshake gets reset, and JS-rendered or Cloudflare-fronted profiles return an
empty shell or an interstitial — so verification degrades to "indeterminate"
and runs lose leads they actually found. With [Scrapling](https://github.com/D4Vinci/Scrapling)
installed, profile fetching (`recon/enrich.py`) escalates blocked or empty
fetches up a three-tier ladder:

1. **Guarded httpx** (always, unchanged) — fast path.
2. **TLS impersonation** (`scrapling` `AsyncFetcher`, `impersonate='chrome'`)
   — one cheap request with a real browser fingerprint; fixes TLS/JA3-class
   blocks. No browser needed.
3. **Headless stealth browser** (`AsyncStealthySession`, Cloudflare solving) —
   seconds per page, so it's budgeted per run (`RECON_STEALTH_BUDGET`,
   default 8 fetches).

A tier result displaces the plain fetch only when it yields *real* content;
a decisive status seen through a better fingerprint (e.g. a genuine 404) still
upgrades the verdict. Verification also recognises anti-bot interstitials
explicitly now ("indeterminate", not a misleading "unconfirmed").

```bash
./venv/bin/pip install -r requirements-stealth.txt
./venv/bin/scrapling install   # once — downloads browsers for tier 3 only
```

Without this install the ladder is inert and behaviour is exactly as before;
`RECON_STEALTH=off` disables it even when installed. Every URL handed to
Scrapling is pre-validated by the same SSRF guard as plain traffic
(`recon/safeweb.assert_public_url`). Railway note: tier 2 works in Nixpacks
as-is; tier 3 needs the browser download plus headroom (~1 GB RAM) — test
locally before enabling it on a small instance.

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
  (`meta`, `user_start`, `found`, `error`, `progress`, `user_done`, `done` events;
  adaptive routing may add `skipped_degraded` / `retry` events and extends
  `done` with `error_breakdown` + `degraded_sources`)
- `GET /api/health/sources` — per-site reliability summary (see Adaptive routing)
- `GET /api/history` — recent runs (includes `kind`: `sherlock` or `recon`)
- `GET /api/history/{id}` — full stored results of one run

## v2 — Deep recon

Beyond the classic Sherlock quick scan, the app now has a **Deep recon** mode
(tab in the UI) that turns it into a broader OSINT reconnaissance tool. All of
it uses **public data only** — no logins, no CAPTCHA solving, no breach
databases.

New capabilities:

- **Tri-engine username search** — runs Sherlock (sync, in a thread),
  [Maigret](https://github.com/soxoj/maigret) (async, ~3200-site database,
  top ~1200 by rank, or all in Thorough mode), and
  [WhatsMyName](https://github.com/WebBreacher/WhatsMyName)
  (`recon/whatsmyname.py`, ~685 categorized sites) at the same time. Results are
  tagged with their engine and merged when engines agree on a site — a match
  confirmed by more engines scores higher confidence, and WhatsMyName adds a
  category (social / coding / gaming …) per account. The WhatsMyName dataset is
  vendored at `recon/data/wmn-data.json`, © Micah Hoffman & contributors,
  licensed [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/).
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

## v3 — Investigations

v3 turns the app from a scanner into an investigation product: **one clue in
(name, username, email, or phone) → automated investigation → interactive
identity graph → professional dossier → continuous monitoring.**

- **Name → username candidates** (`recon/names.py`) — a 2-4 word full name
  generates up to 24 ranked candidate handles (`firstlast`, `first.last`,
  `flast`, `firstl`, `f.last`, `lastfirst`, … **plus nickname expansions** —
  `Robert Smith` → `bobsmith`/`robsmith`/`bob.smith`, `Elizabeth Jones` →
  `lizjones`/`bethjones`, from a curated diminutive table — plus only the
  common digit suffixes `1`/`01`/`123`, no speculative birth years). Lowercase
  ASCII, transliteration-safe. Candidates are scanned against the curated
  ~40-site high-value list and results are tagged `from_name` / `candidate`.
- **Phone pivot** (`recon/phone_pivot.py`) — offline `phonenumbers` parsing:
  validity, E.164, country/region, carrier, line type, timezones. No
  WhatsApp/Telegram presence checks (those need APIs we don't have).
- **Unified investigation** (`recon/pipeline.py`) — one SSE pipeline runs all
  of it: name-candidate scan, dual-engine username scan, variants, email
  pivot, phone intel, enrichment, correlation. Name candidates are fanned out
  across 3 Sherlock threads / 3 concurrent Maigret scans to keep wall time
  sane.
- **Identity graph** (`recon/graph.py` + vendored Cytoscape 3.30.4 and the
  fcose layout chain in `static/vendor/`) — person node in the center;
  **handle pivot nodes** group accounts reusing the same handle across
  sites; account nodes sized by confidence, colored by verification verdict,
  with **age rings** when an adapter reported an creation date; email/
  phone/registration nodes; edges carry confidence + rationale from the
  correlator. Toolbar instruments: node search, type-group toggles
  (accounts / handles / contacts / infra), two-click path tracing between
  any nodes, PNG export, confidence sliders, and a **timeline scrubber**
  that grows the graph as dated accounts were created (appears at ≥3 dated
  nodes). Click a node for a detail panel; sliders hide low-confidence
  edges.
- **Dossier report** (`recon/dossier.py`) — print-friendly
  (`@media print`, no external assets) professional report: CONFIDENTIAL cover
  block, auto-generated executive summary, digital-footprint score (0-100,
  documented heuristic: 4/account cap 40, 5/email-registration cap 25, 10
  Gravatar, 2/enriched-profile cap 15, 10 valid phone), identity-graph edge
  table, confirmed accounts, name-candidate matches, email pivot, phone intel,
  methodology, limitations, responsible-use footer.
- **Watchlist monitoring** (`recon/monitor.py`) — watches re-scan the
  subject's usernames/email against the high-value sites only (no enrichment)
  on a configurable interval (min 6h). A background asyncio task (60s tick)
  picks due watches, diffs the found-set against the stored signature, and
  writes alert rows ("new account: X on GitHub", "account gone: Y",
  "new holehe hit: Z"). The first run establishes the baseline silently.
  State lives in SQLite, so the monitor resumes across restarts (Railway's
  ephemeral disk means history/alerts reset on redeploy — accepted).

New/changed endpoints:

- `POST /api/investigate` — JSON `{name?, usernames?, email?, phone?,
  variants?, timeout?}` (at least one clue required) → `{investigation_id}`
- `GET /api/investigate/{id}` — stored investigation (inputs, summary, status)
- `POST /api/investigate/{id}/rerun` — clone an investigation's inputs into a
  fresh run → `{investigation_id, inputs, rerun_of}`; stream the new id like any
  investigation. Each run is its own history entry, so a subject becomes a
  living case file you can re-scan and diff over time.
- `GET /api/investigate/{id}/stream?nsfw=false` — SSE stream of the full
  pipeline (`meta_run`, `meta`, `candidates`, `found`, `merged`, `error`,
  `progress`, `engine_*`, `variants_planned`, `phase`, `enriched`, `email`,
  `email_done`, `phone_intel`, `correlation`, `saved`, `done`, `fatal`)
- `GET /api/investigate/{id}/graph` — `{nodes, edges}` JSON for the identity
  graph (nodes: `person`/`account`/`email`/`phone`/`registration`, with
  `label`, `url`, `avatar`, `confidence`, `engines`; edges: `source`,
  `target`, `confidence`, `rationale`)
- `GET /api/investigate/{id}/report` — the dossier (HTML)
- `GET/POST /api/watchlist`, `POST /api/watchlist/{id}/toggle`,
  `DELETE /api/watchlist/{id}`
- `GET /api/alerts?unseen=1`, `POST /api/alerts/mark_seen`

Storage: new `investigations`, `watchlist`, and `watch_alerts` tables, plus a
nullable `runs.investigation_id` column linking history rows to
investigations — all created by automatic migrations on startup; existing
rows keep working. `/api/recon/stream` and the classic endpoints are
unchanged.

Graceful degradation: `phonenumbers` missing → phone pivot returns an
"unavailable" result; `cytoscape.min.js` missing → the graph panel shows a
fallback notice; everything else already degraded per-engine.

### Investigation intelligence: exposure, timeline, connections

An analysis layer over the stored investigation data — three pure-function
cores (no paid APIs, no secrets) that also enrich the dossier report:

- **Exposure profile** (`recon/exposure.py`) — the digital-footprint score
  (now the single source of truth, imported by the dossier) plus a structured
  breakdown: qualitative band (minimal → extensive), platform-category counts
  (development / social / professional / creative / media / …), identity
  signals (real name exposed, avatar, Gravatar, valid phone, owned domain),
  the highest-confidence accounts, and human-readable exposure factors.
- **Subject timeline** (`recon/timeline.py`) — a chronology built from the
  investigation-opened time, each scan run against it, matching watchlist
  alert events, and **public account-creation dates** (GitHub's keyless
  `api.github.com/users/{login}` `created_at`, fetched through the SSRF-guarded
  `recon/safeweb.py`). Assembly/parse/account-event helpers are pure; the
  GitHub enrichment is best-effort and never raises.
- **Cross-investigation connections** (`recon/connections.py`) — link analysis
  across saved cases: "this email / phone / domain / account also appears in
  case #N". Overlaps are weighted (email/phone strong, reused handle weak) into
  a 0-100 strength and ranked.

New endpoints (all additive; `404` for a missing investigation, otherwise a
well-formed `200` even before the investigation has run):

- `GET /api/investigate/{id}/exposure` — `{investigation_id, status, exposure}`
- `GET /api/investigate/{id}/timeline` — `{investigation_id, generated_at,
  timeline: [{date, kind, title, detail, dated}]}` (kinds: `opened`, `scan`,
  `alert`, `account_created`)
- `GET /api/investigate/{id}/connections` — `{investigation_id, checked,
  connections: [{investigation_id, label, strength, shared, summary}]}`

The dossier (`GET /api/investigate/{id}/report`) now folds all three in as
extra sections (exposure profile, subject timeline, cross-case connections).
No new tables — these read the existing `investigations`, `runs`, and
`watch_alerts` rows.

### Accuracy: verification + unified confidence

- **Profile verification** (`recon/verify.py`) — Sherlock/Maigret report a hit
  from an HTTP signal, and some sites answer 200 for any path (false positives).
  During enrichment, each fetched profile is cross-checked for the scanned
  handle: found in the title/OG/JSON-LD/body → **confirmed**; a soft-404 served
  with a 200 → **likely false positive**; otherwise **unconfirmed**. The verdict
  is advisory (badged green/red in the UI, dossier, and report; it never
  silently drops a result). Ordering catches the "user X not found" case that
  echoes the handle.
- **Unified confidence** (`recon/confidence.py`) — one source of truth for
  account confidence (engine agreement + enrichment + verification + how the
  handle was derived) and the correlation weights, so the identity graph,
  dossier, and report agree. Verified accounts read green in the graph, flagged
  ones red.

### Responsible use

Same rules as v2, plus: monitoring runs unattended re-scans of public data —
only watch subjects you are authorized to investigate, keep intervals modest,
and honor the dossier's responsible-use footer (no stalking, harassment, or
employment/credit/housing decisions).
