<!-- Read-only audit produced 2026-09-06 against commit 32c061f. Line numbers refer to that commit. -->
# sherlock-web — Operations / Observability / Infrastructure review

Target: `/Users/emmanuel/Desktop/Projects/sherlock-web` @ `32c061f` (working tree == main; only `.superdesign/` untracked).
Mode: read-only. Commands run: `./venv/bin/python -m pytest -q --durations=10` (x3, once with `-W always`, once with `-rs`), `./venv/bin/python -m pip list/show`, `git log --since=60.days --stat`, `git tag`, `git check-ignore`, read-only SQLite (`file:history.db?mode=ro`), `lsof -iTCP:8420`, `ps`, `stat`. No server started, no network.
Environment facts: Python 3.12.2; fastapi 0.141.1 / starlette 1.6.0 / uvicorn 0.52.1 / httpx 0.28.1 / sherlock-project 0.16.0 / maigret 0.6.4 / scrapling 0.4.14 / patchright 1.62.1; patchright Chromium present (`~/Library/Caches/ms-playwright/chromium-1234`). A dev server **is** listening on :8420 (PID 42881, started 02:26:45, `venv/bin/uvicorn app:app --host 127.0.0.1 --port 8420`) — not started by this review.

Legend: PRESENT / PARTIAL / ABSENT. Every claim cites `path:line` or a command above. `UNVERIFIED` marks inference.

---

## 1. Runtime & deployment — PARTIAL

| Item | Status | Evidence |
|---|---|---|
| Launcher | PRESENT | `run.sh:3` `set -euo pipefail`; `:7-10` creates `venv/`; `:19` `PORT` default 8420; `:21` `exec uvicorn app:app --host 127.0.0.1 --port $PORT` — no `--reload`, no `--workers` (single worker, correct: state is in-process), no `--log-config`, no `--timeout-graceful-shutdown`. |
| Dependency refresh | PARTIAL (bug) | `run.sh:13` reinstalls only if `import fastapi, uvicorn, sherlock_project` fails → a dep added later to `requirements.txt` (`phonenumbers`, `psycopg`, `ignorant` were added in later commits: `git log --stat` shows `requirements.txt` touched in 6260b19, d1589b2, 3051024) is never installed into an existing venv. |
| Python pin | PRESENT | `.python-version:1` = 3.12; `ci.yml:21` 3.12; `ruff.toml:8` py312. |
| Pinning | PARTIAL | `requirements.txt:1-3,10` floors only (`fastapi>=0.110`, `uvicorn>=0.29`, `sherlock-project>=0.16.0`, `psycopg[binary]>=3.1`); `:4-9` exact pins. No lockfile (`ls`: no `requirements.lock`/`pyproject.toml`). Installed fastapi 0.141.1 vs floor 0.110 — CI and local can silently diverge. |
| Optional stealth deps | PRESENT but install docs inconsistent | `requirements-stealth.txt:14` `scrapling[fetchers]>=0.4.14,<0.5`; `:8` says `./venv/bin/scrapling install`; code says `./venv/bin/patchright install chromium` (`recon/stealthweb.py:244-245`); commit `bf46fec` body item 2 states the `scrapling install` browser is the *wrong* Chromium (patchright ships its own). `README.md:173` still says `scrapling install`. `run.sh` never installs the stealth extra or the browser (by design, but undocumented in run.sh). |
| Env config | PRESENT, partly undocumented | Env vars read (grep): `PORT` (run.sh:19), `DATABASE_URL` (dbconn.py:27), `APP_PASSWORD` (app.py:117), `GODSEYE_URL` (app.py:1497), `PROXY_LIST` (router.py:490), `RECON_STEALTH` (stealthweb.py:66), `RECON_VERIFY_BUDGET` (enrich.py:30), `RECON_STEALTH_BUDGET` (enrich.py:35), `RECON_DETECTOR_BROWSER_BUDGET` (detectors.py:44), `RECON_WMN_STEALTH_BUDGET` (whatsmyname.py:43), `PHONE_DEFAULT_REGION` (phone_pivot.py:33); launcher: `GODSEYE_PORT`, `OPENSKY_AUTH_MODE` (scripts/godseye.sh:20,41). README documents only `PORT`, `DATABASE_URL`, `APP_PASSWORD`, `PROXY_LIST`, `RECON_STEALTH`, `RECON_STEALTH_BUDGET`, `GODSEYE_*` (in docs/GODSEYE.md:42-44). |
| Deployment manifest | PARTIAL | Only `railway.json:1-13` (Nixpacks; start `uvicorn ... --host 0.0.0.0`; `healthcheckPath: /api/sites`; `ON_FAILURE` ×5). No Dockerfile / Procfile / compose / systemd (`ls`). `/api/sites` is an in-memory list (`app.py:267-272`) — the health check never touches the DB. |
| First-run behaviour | PARTIAL (hidden network dependency) | DB auto-created at import (`app.py:202` → `_init_db` `:155-199`). **Startup requires internet**: `app.py:146` `SitesInformation()` with no args → sherlock defaults `data_file_path` to `MANIFEST_URL` (`sherlock_project/sites.py:118-122`, `:11`), does `requests.get(...)` with **no timeout** (`sites.py:129-132`; `grep timeout sites.py` → none) and a second fetch of `EXCLUSIONS_URL` (`sites.py:167-169`). Offline → `FileNotFoundError` at import; unreachable GitHub → indefinite hang. The bundled `sherlock_project/resources/data.json` exists in the venv (ls) but is not used. Consequence: the scan-enabled site count (README:243 "433 of 481") floats with upstream master. |
| scripts/ | PRESENT | Only `scripts/godseye.sh` (`:22-46`: clone once, `PUPPETEER_SKIP_DOWNLOAD=1 npm install`, copy `.env.example`, `npm run dev`). |
| .gitignore | PARTIAL | `.gitignore:1-16` covers `venv/`, `__pycache__/`, `.pytest_cache/`, `history.db{,-wal,-shm}`, android build, `*.apk`, `.DS_Store`, `.claude/`, `godseye/`. Not covered: `.superdesign/` (untracked per `git status`), `.ruff_cache/` (relies on ruff's self-written `.ruff_cache/.gitignore` = `*`, verified by `cat`). |
| Versioning | ABSENT | `git tag` → 0 tags; no `__version__`/version string in `app.py` or `static/manifest.webmanifest` (grep); `FastAPI(title="sherlock-web")` `app.py:109` has no version. |

## 2. CI/CD — PARTIAL

- `.github/workflows/ci.yml:3-6` push→main + PR; `:8-10` concurrency cancel-in-progress; job `test` (`:13-50`): setup-python 3.12 w/ pip cache (`:19-23`), `pip install -r requirements-dev.txt` (`:28`), `ruff check .` (`:31`), `pytest -q` (`:34`), boot smoke `/api/sites` + `/` = 200 (`:36-50`). Job `postgres` (`:52-97`): postgres:16 service, boot, `POST /api/investigate`, asserts the row persists via a fresh `dbconn.connect()` (`:92-97`). Good.
- `.github/workflows/android-apk.yml:3-9` path-filtered APK build; `:11-12` `permissions: contents: read`.
- ABSENT: pre-commit config, dependabot, CODEOWNERS (`ls`), `pytest.ini`/`pyproject.toml` (`ls`), `node --check static/js/app.js` in CI (memory note says validate locally), coverage, release/tag workflow, CHANGELOG. `docs/specs/06-ci.md` W1–W4 (network marker, auth smoke, audit verifier, branch protection) all still unshipped (no `pytest.ini`; ci.yml unchanged since d1589b2 per `git log --stat`). Branch protection: UNVERIFIED (needs GitHub API).
- **Likely CI break (UNVERIFIED — could not query Actions):** CI installs `requirements-dev.txt` only (`ci.yml:28`), which does not include `requirements-stealth.txt`, and scrapling is not a transitive dep (`pip show scrapling` → `Required-by:` empty). `tests/test_enrich.py:30-35` asserts `_extract_scrapling(...) is not None` and `:52-58` asserts `og_description` (a Scrapling-only field — regex path matches only `og:*`, `recon/enrich.py:42-44`). Both must fail wherever scrapling is absent. Either CI is red since PR #40/#43, or those tests were never run in CI.

## 3. Data lifecycle — PARTIAL

- Schema (SQLite, verified via `sqlite_master`): `runs`, `investigations` (`app.py:155-199`), `watchlist`, `watch_alerts` (`recon/monitor.py:43-70`), `site_health` PK(site,engine), `proxy_health` PK(proxy) (`recon/router.py:228-255`). Indexes: only PK autoindexes; none on `runs.investigation_id` (queried `app.py:1197-1201`), `investigations(inputs,status)` (queried `app.py:1139-1145`), `watch_alerts.watch_id`. Harmless at 67/53 rows.
- Migrations: ad-hoc `PRAGMA table_info(runs)` + `ALTER` (`app.py:175-185`), SQLite-only (`if not dbconn.IS_POSTGRES`). `PRAGMA user_version` = 0 (read). No migration path exists for Postgres schema changes; no versioning of schema.
- Connection settings: `dbconn.py:85-91` WAL, `busy_timeout` 5000 ms, `synchronous=NORMAL`; a new connection per operation, no pool. Postgres adapter `dbconn.py:45-73`, naive `?`→`%s` (`:36-42`).
- WAL is on (`pragma journal_mode` → wal). Nothing ever checkpoints explicitly (grep `wal_checkpoint` → none); current `history.db-wal` = 972 KB vs db 2.18 MB. A naive `cp history.db` loses that content. No backup procedure anywhere (README/docs grep). `migrate_to_postgres.py` is an import tool, not a backup (`:1-11`).
- Growth: every investigation summary is stored **twice** — `investigations.summary` (`app.py:1079` → `_set_investigation` `:946-959`) and again as `runs.results` (`app.py:1088-1090`, `save_run(..., summary, kind="investigation")`). Read-only SQL: `sum(length(summary))` = 664,619 B over 53 rows (avg 15.5 KB, max 154,385 B); `sum(length(results))` = 762,293 B over 67 runs (same max 154,385). 25 days of use → ~3.1 MB incl. WAL. No retention/deletion (only `DELETE` statements are watch deletes, `app.py:1408-1411`); `/api/history` shows the newest 50 (`app.py:230`), older rows are kept but unreachable from the UI. `freelist_count` 0; no VACUUM.
- `site_health`: 2,165 rows (maigret 1,097 / whatsmyname 649 / sherlock 419), window capped at 50 (`router.py:149,298`) → bounded (~108 K obs max). Flushed once per run in one transaction (`router.py:355-377`, `:638-653`).
- Concurrent writers: request handlers (sync defs run in Starlette's threadpool), sherlock worker threads (`save_run` from thread `app.py:407`), monitor task (`monitor.py:241-263`), router flush. WAL + busy_timeout makes this safe; no `database is locked` handling beyond the timeout.
- Atomicity nit: `_set_investigation(done)` and `save_run` are separate transactions (`app.py:1079` vs `:1088`); a crash between leaves a `done` investigation with no `runs` row.
- Postgres on Railway: `dbconn.py:6-8` and README:44-47 correctly explain ephemeral disk; CI covers persistence (`ci.yml:92-97`).

## 4. Logging — PARTIAL

- Root config: `app.py:31` `logging.basicConfig(level=logging.INFO)` → default `%(levelname)s:%(name)s:%(message)s` — **no timestamps**, no pid, no request/investigation id. uvicorn keeps its own `uvicorn.error`/`uvicorn.access` handlers (access log on; `run.sh:21` passes no log flags). Destination: stdout/stderr only.
- Logger names: `app` (`app.py:76,398,1266,1284`), `recon.<module>` per module (`recon/*.py`, grep). Free-text messages; no structured fields.
- Levels: run-level events INFO (`router.py:555,578`; `monitor.py:124,264,273`; `enrich.py:463,499`); engine/callback failures `.exception` (`pipeline.py:127,348,405`; `monitor.py:106,145,282,284`); **individual fetch failures are DEBUG** and therefore invisible at the configured INFO: `detectors.py:158`, `stealthweb.py:178,197,275,291`, `geo.py:255,296`, `breach.py:114`, `timeline.py:191,194`.
- **Failed investigations are not logged at all**: `app.py:1093-1095` catches the exception, sets `status='failed'` and emits an SSE `fatal` — no `logger.exception`, and the message is not persisted. Same for deep recon (`app.py:822-823`) and quick search (`app.py:418-421`).
- Correlation to an investigation id: ABSENT. `run_pipeline` does not receive the id (`pipeline.py:138-153`), so no pipeline/enrich/router/stealth log line can carry it; only `app.py:1266-1267,1284-1285` (breach/footprint) log an `inv_id`.
- Third-party noise (verified in venv):
  - `httpx` logs **every request at INFO** (`httpx/_client.py:117`, `:1026`, `:1741` `'HTTP Request: ...'`). Callers via `safeweb.async_client`: WhatsMyName (649 sites/handle — `whatsmyname.py:184-201`; offline count 649), enrichment (≤120 + one control probe per host — `enrich.py:30,380-401`), holehe and ignorant (both httpx: `holehe/core.py`, `ignorant/core.py`), adapters/detectors/gravatar/geo/breach/brokers/timeline → roughly 800+ INFO lines for a single-handle investigation.
  - `scrapling` installs its **own StreamHandler at INFO** on logger `scrapling` with a different format and leaves `propagate=True` (`scrapling/core/utils/_utils.py:25-36`) → every scrapling line is printed twice. `log.error("No Cloudflare challenge found.")` (`scrapling/engines/_browsers/_stealth.py:116,391`) fires whenever `solve_cloudflare=True` and no CF challenge is present. `bf46fec` made the solver opt-in (`enrich.py:370-372`, `detectors.py:117-119`), but `has_challenge_markers` also matches DataDome/PerimeterX/DDoS-Guard (`stealthweb.py:88-104`) → the ERROR still fires on those hosts.
  - maigret: our `logging.getLogger("maigret")` is passed in (`engines.py:148`); maigret logs mostly DEBUG, plus webgate INFO/WARNING (`maigret/checking.py:493,504`) and an ERROR with traceback at `:326`. Its own `basicConfig` is CLI-only (`maigret/maigret.py:571-580` inside `main()`), so it does not clobber ours.
  - sherlock: `QueryNotify` base does not print; prints live only in `QueryNotifyPrint` (`sherlock_project/notify.py:158-270`), which is not used.
- Request logging: uvicorn access lines only; an SSE stream logs one line at open, nothing at close/cancel.

## 5. Health & metrics — PARTIAL

PRESENT:
- `GET /api/health/sources` (`app.py:279-283` → `router.sources_summary` `:668-724`): per (site, engine) `failure_rate` over ≤50 obs, `dominant_error`, `consecutive_failures`, `circuit` open/half-open/closed + `cooldown_remaining_s`, `ewma_latency_ms`; aggregate `sites_tracked`, `circuits_open`, `observations`, `overall_failure_rate`; `available:false` when the store failed (`:715`). UI: Health tab (`static/index.html:453-461`, `static/js/app.js:611-654`).
- `site_health` write path: `RunRouter.observe` for sherlock/maigret/whatsmyname (`pipeline.py:69-71,312-315,371-373`; `app.py:319-321`; `monitor.py:93-95`), classified by `router.classify` (`router.py:101-142`, 9 classes). Observed class distribution in the live DB (9,078 windowed obs): detector_stale 821, timeout 750, http_403_waf 624, conn_reset 250, unknown 245, tls 94, http_429 23, http_5xx 23, dns 17.
- `proxy_health` (`router.py:427-471`) — 0 rows (no `PROXY_LIST`).
- SSE `done`: quick search `{"runs", error_breakdown, degraded_sources}` (`app.py:424`, `router.breakdown` `:655-660`); investigation adds verification buckets found/leads/flagged/indeterminate/not_examined/hits (`pipeline.py:679-697`). Front end renders it (`app.js:588-606,1986-2007`). `skipped_degraded` and `retry` events (`router.py:575-585`; `pipeline.py:121,341,398`).
- `GET /api/godseye/status` TCP probe (`app.py:1500-1516`).

Metric-by-metric:

| Metric | Status | Where / gap |
|---|---|---|
| Search success rate (per run / over time) | PARTIAL | Bucket counts exist only in the SSE `done` event (`pipeline.py:678-684`); not persisted, no aggregate. Derivable post hoc by re-bucketing stored rows' `verification.status`. |
| Retrieval success per source | PARTIAL | `site_health` for the 3 engines only. Nothing for enrichment fetches, adapters, detectors, holehe, ignorant, gravatar, geo, breach, brokers (no `observe`/record calls in those modules — grep). Signals-engine `BLOCKED`/`ABSENT` results are discarded before anyone sees them (`detectors.py:178-179`; `adapters.discover` keeps EXISTS only). |
| Latency per source | PARTIAL (sherlock only) | `ewma_latency_ms` populated for sherlock (413/419 rows); **0/1,097 maigret and 0/649 whatsmyname rows** (read-only SQL). WMN never sets `WmnResult.query_time` (`whatsmyname.py:61` default only; no assignment); maigret result has no `query_time` (`pipeline.py:314` `getattr(..., None)`). No histogram anywhere; no timing of enrichment/adapter/detector fetches (grep `monotonic|perf_counter` in `recon/`, `app.py` → none). |
| HTTP failure classes | PARTIAL | Per-site windows (persisted) + per-run `error_breakdown` (SSE only). Enrichment/verification failures are free text in `verification.signals` (`verify.py:232-242`). |
| 429s | PARTIAL | Class `http_429` in the above; not tracked for enrichment/adapters. |
| Cache hits | ABSENT | `enrich.control_cache` (`enrich.py:346`), `geo._place_cache/_ip_cache` (`geo.py:59-60`), `breach._cache` (`breach.py:48`) — none counted or exposed. |
| Fallback (stealth tier) frequency | PARTIAL | `stealth_used` counted per run but **only logged at INFO** (`enrich.py:351,363,374,498-501`) — confirmed. Per-row `fetch_via` persisted only when a tier rescued (`enrich.py:462`). Failed escalations, detector/WMN tier use (WMN `"stealth-recovered"` context is dropped because `classify` returns `None` for success, `router.py:597-602`), and the tier-3 dead flag (`_session_dead`, one WARNING `stealthweb.py:242-247,285-289`) are not recorded anywhere queryable. |
| Verification outcome distribution | PARTIAL | Per row persisted (`verification.status/score/signals`, `enrich.py:410,427,476`); run totals SSE-only; no cross-run aggregate. |
| Result confidence distribution | PARTIAL | `account_confidence(row)` computed on demand (`pipeline.py:637`, graph); derivable from stored rows; not aggregated. |
| Run duration | ABSENT | Not recorded. `runs.ts` − `investigations.created_at` approximates it but `created_at` is POST time, not stream start (`app.py:1004-1010` vs `:1053`). |
| Retries | PARTIAL | `router.retries_done` counted (`router.py:539`; `pipeline.py:118,338,395`) but **not included** in `breakdown()` (`router.py:655-660`); visible only as individual SSE `retry` events. |
| Engine crashes (`engine_error`) | ABSENT post hoc | SSE toast only (`pipeline.py:101,330,388,433`; `app.js:1940-1943`). |
| Process health (DB probe, version, uptime, in-flight runs, optional deps, stealth state) | ABSENT | No such endpoint; Railway probes `/api/sites` (static). |

## 6. Failure visibility — what an operator can reconstruct afterwards (PARTIAL)

For a `failed`/`interrupted` investigation, from `history.db` + stdout:

| Question | Answerable? | Evidence |
|---|---|---|
| What did we try? | PARTIAL | `investigations.inputs` and `summary.candidates` persisted. Site sets actually scanned (post circuit filter), engines that ran, budgets used: SSE `meta` only (`pipeline.py:525-532`). |
| Which source failed? | PARTIAL | Per-site engine failures: only in `site_health` windows aggregated across runs (each obs has `ts` but no run id/username) — time-window correlation is the best available. Enrichment: per-row `verification.signals` text for examined rows. `engine_error`: SSE only. Signals engine BLOCKED: discarded. |
| Why? | PARTIAL | Class per site in windows; enrichment free text ("blocked: HTTP 403", "no HTML retrieved", `verify.py:235-242`); most fetch exceptions logged at DEBUG (§4). For a `fatal`, **nothing**: `status='failed'` carries no message and nothing is logged (`app.py:1093-1095`). |
| What fallback was tried? | PARTIAL | `fetch_via` per row only on success (`enrich.py:462`); attempts, retries, skipped sites not persisted. |
| Did the fallback work? | PARTIAL | Only the success case (`fetch_via`). |
| Confidence of what was found? | PRESENT | `verification` per row persisted; `account_confidence` deterministic from the row. |

Live evidence of the gap: 7 of 53 investigations are `status='running'` (ids 11, 14, 42, 51, 52, 53 with `summary IS NULL`; **54 has a saved summary and a completed `runs` row 68 at 02:20:56 yet reads `running`**), plus 4 orphan `pending` rows (5, 6, 7, 49). No row explains why.

## 7. Process resilience — PARTIAL

- Lifespan (`app.py:84-106`): cancels the monitor task and closes the stealth session. It does **not** mark in-flight investigations, cancel coordinator tasks, or join sherlock threads (all `daemon=True`: `app.py:459-464,661-665`; `pipeline.py:281-286`).
- Stuck `running` — mechanisms verified in code:
  1. `investigate_stream` sets `running` **unconditionally** on every GET, even for a `done` investigation, and re-runs the whole pipeline (`app.py:1046-1053,1068`). Explains id 54 (summary from the first run, status from a later re-stream).
  2. Client disconnect → `coord_task.cancel()` (`app.py:1116-1118`); `CancelledError` is a `BaseException`, not caught by `except Exception` (`app.py:1093`) → status stays `running` forever; `router.finish()` is also skipped (`pipeline.py:674` is not in a `finally`) so the run's observations are lost.
  3. Process kill mid-run → same; no startup sweep (the only writers of `status` are `app.py:1053,1079,1094`).
  4. Front end: `invEs.onerror` (`static/js/app.js:2008-2010`) never calls `close()`, so a dropped connection (server restart, keepalive failure) makes `EventSource` auto-reconnect → a silent full re-run of the same id. Stop/done/fatal paths do close (`app.js:1806,1976,2005`).
- Timeouts: per-site 1–120 s (`app.py:433,985`); enrichment 10 s (`enrich.py:32`); tier-2 15 s / tier-3 45 s (`stealthweb.py:74-75`); adapters/detectors 12 s (`adapters.py:41`, `detectors.py:33`). No whole-run deadline. Monitor: `run_watch` has no timeout and watches run sequentially (`monitor.py:277-282`; `asyncio.to_thread` without `wait_for` `:130-132`) → one hung light scan stalls every watch.
- Concurrency: **no cap** on simultaneous investigations/searches (no semaphore/counter in `app.py`). Per investigation: sherlock 20 workers per call (`sherlock_project/sherlock.py:243-249`) × 1 base + 3 name shards (`pipeline.py:46,568-569`); maigret `max_connections` default 100 (`maigret/checking.py:1149`) × 3 (`pipeline.py:47,570-572`); WMN 20 (`whatsmyname.py:38`) × 3; enrichment 5 (`enrich.py:31`); avatar hashing 5 (`correlate.py:455`). Two concurrent full investigations ≈ 600+ outbound connections.
- Memory: module-level caches are unbounded but small-keyed (`geo.py:59-60`, `breach.py:48`); `_MAIGRET_DB`, WMN cache, `SITE_DATA_ALL` load once. Cancelled runs leave daemon threads posting callbacks into dead closures until sherlock finishes (wasteful, not leaky).
- Startup: network-dependent with no timeout (§1).
- Multi-worker safety: not safe (`asyncio.Queue`, monitor task, `_session` are per-process) — single worker is a requirement, currently only implicit in `run.sh:21`.

## 8. Documentation accuracy — PARTIAL (stale statements)

README (`README.md`):
- `:76-77` "installs requirements.txt (FastAPI, uvicorn, sherlock-project)" — omits maigret/holehe/ignorant/httpx/pillow/phonenumbers/psycopg (`requirements.txt:4-10`).
- `:113-115` retries "jittered 5–15s delay, sequentially" — code: 2–5 s, one batched re-scan (`router.py:160-161`; `pipeline.py:109-125`; `app.py:380-396`).
- `:159` "impersonate='chrome'" — code rotates 4 fingerprints (`stealthweb.py:80,186`).
- `:173` and `requirements-stealth.txt:8` "`scrapling install`" — code/commit say `patchright install chromium` (`stealthweb.py:244-245`; `bf46fec`).
- `:289` enrichment "max 40/run" — `MAX_ENRICH_PER_RUN` = 120 (`enrich.py:30`); `RECON_VERIFY_BUDGET` undocumented.
- `:272` WhatsMyName "~685 categorized sites" — 649 usable (offline count via `whatsmyname.all_sites()`).
- `:385` `POST /api/investigate` body omits `domain`, `location`, `thorough` (`app.py:976-986`).
- `:230-231` "installable PWA (manifest + service worker)" — `static/sw.js:1-13` is a kill-switch that unregisters itself; `index.html:583-584` unregisters on load.
- `:243` "433 of 481 sites" — depends on a live upstream fetch at startup (§1), not a fixed number.
- Missing entirely: God's Eye workspace (no README mention; `docs/GODSEYE.md` exists), `/api/investigate/{id}/breach` and `/footprint` (`app.py:1253-1287`), the signals engine (`recon/adapters.py`, `recon/detectors.py`), env knobs listed in §1, the startup network requirement, backup/retention, the `running`-status caveat, single-worker requirement.
- Accurate: circuit-breaker constants (`:94-101` ↔ `router.py:149-155`), monitor tick/interval (`:376` ↔ `monitor.py:29-31`), name-scan fan-out (`:349-350` ↔ `pipeline.py:46-47`), Postgres/CI story (`:36-59` ↔ `ci.yml:52-97`), "tests need no network" (`:28-29`; verified: no test imports `app`, guard tests use IP literals `tests/test_safeweb.py:38-55`, `tests/test_stealthweb.py:111-128`).
- `docs/GODSEYE.md` matches `scripts/godseye.sh` and `app.py:1497-1516` (nit: tab label "[GEO] God's Eye" vs script text "[GODSEYE] tab", `godseye.sh:44`).
- `docs/specs/01-06`: 01 shipped (d1589b2); 06 partially (its own status line); 02 auth, 03 audit log, 04 Stripe, 05 job queue not implemented (grep `audit|stripe|owner_user|jobs` in `app.py` → none) — still labelled P0.
- `CLAUDE.md`: ABSENT in repo (`ls`); only user-level memory notes exist. The dev-workflow memory says "184 passing" — now 351.

## 9. Test suite health — PRESENT (with one environment coupling)

- `pytest -q --durations=10`: **351 passed, 1 skipped, 16 warnings in 1.2–1.3 s** (3 runs). Slowest 0.52 s (`tests/test_engines.py:33-41`, loads the maigret DB).
- Skips: `tests/test_stealthweb.py:96` (`skipif scrapling installed`) — the mirror `:90` runs here; both branches are only covered across environments. `tests/test_engines.py:34-35` skips if maigret missing (not here).
- Warnings: all 16 are one `DeprecationWarning` from lxml (`lxml/html/__init__.py:1891`, `strip_cdata`) raised by scrapling's `Selector`, triggered in `test_detectors` (2) and `test_enrich` (14) (`pytest -W always | sort | uniq -c`). Not repo code; disappears where scrapling is absent; silenceable with `filterwarnings` in a `pytest.ini` (none exists).
- Network: none (no test imports `app`; SSRF guard tests use literals). Time: `test_router.py:128-182` injects `now=`; no sleeps/`datetime.now`. Deterministic.
- Environment coupling: `tests/test_enrich.py:30-35,52-58` hard-require scrapling (§2). No `importorskip`, no marker.
- No coverage tooling; no markers config.

---

## 10. Prioritized operational gaps

| # | Gap | Impact | Smallest safe fix | Effort |
|---|---|---|---|---|
| 1 | Failed investigations leave no reason anywhere (`app.py:1093-1095`, `:822-823`, `:418-421`) | Post-mortem impossible; `failed` rows are mute | Add `logging.getLogger("app").exception("investigation %d failed", inv_id)` and persist the message (e.g. `summary={"error": "..."}` via `_set_investigation`) | S |
| 2 | `running` never recovers; re-GET of `/stream` re-runs a done investigation; client auto-reconnects (`app.py:1046-1053,1093,1116-1118`; `pipeline.py:674`; `app.js:2008-2010`) | 7/53 rows stuck; duplicate scans and network load after any restart/blip; lost `site_health` observations | (a) `except BaseException` + `finally` → mark `cancelled`/`failed`; wrap pipeline body so `router.finish()` runs in `finally`; (b) lifespan startup: `UPDATE investigations SET status='interrupted' WHERE status='running'`; (c) return 409 if `status='done'` on `/stream` (or replay from summary); (d) `invEs.onerror`: `close()` when `readyState===CLOSED` and never auto-reconnect | S–M |
| 3 | Boot requires GitHub with no timeout (`app.py:146` → `sites.py:118-122,129-132,167-169`) | Offline/degraded network = app won't start or hangs; site list floats | Pass the bundled `sherlock_project/resources/data.json` path (exists in venv) to `SitesInformation`, or fetch with a timeout and fall back to the bundled file; log which source was used | S |
| 4 | CI dependency drift: scrapling-only tests vs `requirements-dev.txt` (`ci.yml:28`; `tests/test_enrich.py:30-35,52-58`) | CI likely red or non-representative (UNVERIFIED) | Either `-r requirements-stealth.txt` in `requirements-dev.txt`, or `pytest.importorskip("scrapling")` in those two tests | S |
| 5 | Log noise/format: httpx INFO per request (~800+/run), scrapling duplicate handler + spurious "No Cloudflare challenge found" ERROR, no timestamps (`app.py:31`; `httpx/_client.py:1026,1741`; `scrapling/core/utils/_utils.py:25-36`) | Real warnings drown; lines can't be ordered across restarts | In `app.py` after `basicConfig`: `format="%(asctime)s %(levelname)s %(name)s: %(message)s"`; `getLogger("httpx").setLevel(WARNING)`; `getLogger("scrapling").propagate=False` (keep its handler) or `.handlers.clear()`; only pass `solve_cloudflare=True` when a *Cloudflare* marker matched | S |
| 6 | No per-run diagnostics persisted (§5/§6): `router.breakdown()`, `retries_done`, degraded list, `stealth_used`, `engine_error`s, duration all die with the SSE stream (`pipeline.py:658-673,679-697`; `enrich.py:498-501`) | Six questions unanswerable post hoc | Add `summary["run"]` (see §11) populated at `pipeline.py:658`; include `retries_done` in `router.breakdown()` | S–M |
| 7 | Latency missing for maigret and WMN (`whatsmyname.py:61` never set; `pipeline.py:314`) | Health tab EWMA blank for 1,746/2,165 sources | Time `_get_capped` in `whatsmyname._check_site` and set `query_time`; for maigret, time the callback interval or accept the gap | S |
| 8 | Signals-engine outcomes never observed (`detectors.py:178-179`; `adapters.discover`) | Adapter/detector blocks invisible to circuit breaker and Health tab | In `signals_worker` (`pipeline.py:413-442`) call `router.observe("signals", site, status, signal)` for every result, not just EXISTS | S |
| 9 | `run.sh:13` reinstall heuristic misses new deps | Silent `ImportError`-driven degradation (`*_available()` returns False) after pulling | Stamp `venv/.requirements.sha256` and reinstall when `requirements.txt` hash changes | S |
| 10 | No process-level health endpoint; Railway probes a static list (`railway.json:8`; `app.py:267-272`) | Can't tell DB broken / stealth dead / deps missing / runs in flight | Add `GET /api/health` returning `{db_ok (SELECT 1), version/commit (env GIT_SHA or `git rev-parse` at boot), uptime_s, in_flight, stuck_running, deps:{maigret,holehe,ignorant,scrapling,browser_ok}, stealth_tier3_dead}`; point `railway.json` at it | S–M |
| 11 | Unbounded concurrency; monitor has no per-watch timeout (`app.py` no semaphore; `monitor.py:277-282`) | Self-DoS on outbound connections; one hung watch stalls all | `asyncio.Semaphore(2)` around `run_pipeline` in `investigate_stream` (emit a `queued` event); `asyncio.wait_for(run_watch(...), 900)` | S |
| 12 | Summary stored twice; no retention/backup/checkpoint (`app.py:1079,1088-1090`) | DB doubles growth; naive copies lose WAL | For `kind="investigation"` store a slim `results` (counts + `investigation_id`) or `NULL`; document `sqlite3 history.db ".backup out.db"`; `PRAGMA wal_checkpoint(TRUNCATE)` in lifespan shutdown | S |
| 13 | No schema versioning (`user_version`=0; SQLite-only ALTERs `app.py:175-185`) | Next column addition breaks Postgres silently | `PRAGMA user_version` (SQLite) / `schema_version` table (both), ordered migration list in `_init_db` | M |
| 14 | README/requirements-stealth staleness (§8) | Operators run the wrong install command, mis-tune budgets | Fix the 9 listed lines; add env-var table, startup-network note, single-worker note, backup note | S–M |
| 15 | No version/tag/changelog; no dependabot; `.superdesign/` unignored | Can't correlate a DB/log with a code state | Tag releases or expose commit in `/api/health`; add `.superdesign/` to `.gitignore` (or commit it) | S |
| 16 | Cancelled runs leave daemon sherlock threads running (`pipeline.py:281-286`) | Wasted bandwidth after Stop; can't be interrupted inside `sherlock()` | Check a `cancelled` flag between usernames in `_sherlock_worker`; document the residual | M (low priority) |

## 11. Proposed minimal observability model (local single-user tool; no Prometheus)

Principle: **persist per-run facts in the DB (post-hoc), keep counters in-process (exposed by `/api/health`), use logs for process events with `inv_id=` on every line, keep SSE as the live view.** All additive.

**A. Per-run diagnostics → DB.** Add `summary["run"]` (built at `pipeline.py:658`, written by the existing `_set_investigation`) and two columns on `investigations`: `started_at`, `finished_at` (or keep them inside the blob), plus `error TEXT` for the `fatal` path. Contents, all bounded:
- `planned`: `{sherlock, maigret, whatsmyname, signals, candidate_sites}` site counts (already computed for `meta`), `budgets: {verify, stealth_browser, detector_browser, wmn_stealth}`.
- `skipped_degraded`: the `router.degraded` list (site, engine, until).
- `errors_by_class`: `router.error_counts`; `errors_by_engine_class`: extend `observe` to a `Counter[(engine, class)]`.
- `failed_checks`: up to 300 `{engine, site, class, context[:80]}` — the per-site failures that today vanish; cap keeps the blob small.
- `retries`: `{attempted: router.retries_done, recovered: n}` (recovered = retried sites whose second observation was ok — computable in `drain_transient` callers).
- `engine_errors`: list of `{engine, message}` (from `_engine_lifecycle`).
- `signals`: `{adapter/detector name: exists|absent|blocked}` per handle (currently discarded).
- `stealth`: `{tls_attempts, tls_ok, browser_attempts, browser_ok, browser_dead: bool}` (from `escalate()` + `_session_dead`), plus detector/WMN counters.
- `fetch_status_hist`: `{"200": n, "403": n, "404": n, "429": n, "5xx": n, "none": n}` from `_fetch_page`.
- `verification_counts`: `bucket_counts(all_rows)` (already computed for `done`).
- `timings_s`: `{scan, variants, candidates, enrich, correlate, total}` via `time.monotonic()` at phase boundaries.
Also: `router.breakdown()` gains `retries_done`; `finish()` runs in `finally`.

**B. Source-level.** Keep `site_health` as the per-source rolling store (already right-sized). Fill latency for WMN (set `query_time`) and record `signals` observations. Add a `response` event hook in `safeweb.async_client` that increments an in-process `Counter[(host, status_class)]` and an EWMA per host — zero changes in callers; expose via `/api/health` (`hosts_top_failing`).

**C. Process-level `/api/health`** (in-process counters, reset on restart): `uptime_s`, `commit`, `db_ok`, `db_bytes`, `wal_bytes`, `investigations: {in_flight, done, failed, interrupted, pending}`, `deps: {...available}`, `stealth: {enabled, tier3_dead, browser_installed}`, `monitor: {last_tick_at, watches_due, last_error}`, `httpx: {requests, by_status_class}`, `cache_hits: {control, geo, breach}`.

**D. Logging.** Root format with `asctime`; `httpx`→WARNING; `scrapling` de-duplicated; a `logging.LoggerAdapter`/`contextvars` `inv_id` injected in `investigate_stream` so every `recon.*` line carries `inv=<id>`; exactly one INFO line at run start (`inv=54 start usernames=[...] planned=...`) and one at end (`inv=54 done 128.4s found=3 leads=9 flagged=6 errors={...} retries=12 stealth=tls:4/7 browser:1/2`); `exception` on every `fatal`; WARNING once per run when tier-3 is dead or a circuit trips.

**E. SSE.** Unchanged, plus `elapsed_s` and `retries` on `done` (already has the rest).

Six-question check after A–D: *tried* → `run.planned` + `inputs`; *which source failed* → `run.failed_checks`, `run.engine_errors`, `run.signals`, per-row `verification`; *why* → class + context per failure, `investigations.error`, exception in log with `inv=`; *fallback* → `run.stealth`, `run.retries`, per-row `fetch_via`; *worked?* → `*_ok` counters + `fetch_via`; *confidence* → per-row `verification` (unchanged). Everything answerable from `history.db` alone; logs become corroboration, not the primary record.

## 12. UNVERIFIED

- Actual GitHub Actions status for recent commits (network required); whether branch protection exists.
- The exact trigger that re-streamed investigation 54 (mechanism verified in code; the client action is not observable from the DB).
- `SitesInformation` keyword names for a local file / exclusions toggle (usage at `sites.py:118,167` implies `data_file_path`, `honor_exclusions`; signature line not captured).
- Whether maigret exposes any per-site timing usable for latency.
