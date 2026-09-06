<!-- Read-only audit produced 2026-09-06 against commit 32c061f. Line numbers refer to that commit. -->
# sherlock-web — technical-debt inventory

Repo: `/Users/emmanuel/Desktop/Projects/sherlock-web` @ `32c061f` (working tree == main).
Method: read-only static review of `app.py`, `dbconn.py`, `recon/*`, `static/*`, `tests/*`; offline tooling only.

## 0. Baseline verified offline

| Check | Result |
|---|---|
| `./venv/bin/python -m pytest -q` | 351 passed, 1 skipped (`tests/test_stealthweb.py:96`, skips *because* scrapling is installed), 16 `DeprecationWarning` from lxml via scrapling, 1.4 s, no network |
| `./venv/bin/python -m ruff check .` (`ruff.toml` select = `E9,F`) | clean |
| `ruff --select E,W,I,B,UP,SIM,C4` (not enforced) | 218 findings: UP045 ×153, E501 ×14, I001 ×13, E402 ×11, B905 ×3, B023 ×1 — 181 auto-fixable |
| `pip check` | no broken requirements |
| `pip-audit` | **not installed → CVE status of every dependency is UNVERIFIED** |
| `node --check static/js/app.js` | OK |
| Sizes | `app.py` 1533 LOC · `recon/` 8 128 LOC (30 modules) · `static/js/app.js` 4457 · `static/css/app.css` 10 168 · `static/index.html` 596 · `tests/` 3 093 (28 files) |

---

## 1. Prioritised inventory

### P0

#### D1 — Legacy v2 "deep recon" pipeline duplicated inside `app.py`, no caller
- **Problem**: `/api/recon/stream` re-implements the investigation pipeline (`app.py:558-852`, 295 lines, largest def in the file) with its own `_ReconSherlockNotify`/`_recon_sherlock_worker` (`app.py:509-556`) that mirror `recon/pipeline.py:52-103`, its own `coordinator` (`app.py:726-826`) mirroring `run_pipeline`, and its own `ERROR_STATUSES` (`app.py:288` vs `recon/pipeline.py:43`). It lacks the router (`RunRouter`), WhatsMyName, signals, phone/domain/broker pivots and `subject_name` verification that the real pipeline has — it is a frozen older copy.
- **Evidence**: frontend references no `recon/stream`, `recon/report`, `/api/domain`, `/api/brokers` (`grep` of `static/js/app.js` API strings — only `/api/investigate*`, `/api/watchlist*`, `/api/alerts*`, `/api/history*`, `/api/sites`, `/api/search/stream`, `/api/health/sources`, `/api/godseye/status`). Only `static/js/app.js:4422-4423` reads *stored* `kind == "recon"` history rows. README still documents it as a live API (`README.md:259-310, 408`).
- **Impact**: 350 lines of parallel scan logic must be kept behaviourally in sync; stale constant `min(40, …)` at `app.py:784` vs `MAX_ENRICH_PER_RUN=120` (`recon/enrich.py:30`) already shows drift.
- **Risk if unfixed**: bug fixes land in one copy (e.g. correlation-honesty rules went through `recon/*`, not here); attack surface stays exposed for an unused SSE route.
- **Root cause**: v3 investigations added beside v2 instead of replacing it ("`/api/recon/stream` and the classic endpoints are unchanged", `README.md:408`).
- **Cost to fix**: M (delete `app.py:509-892` block for the stream; keep `/api/recon/report/{id}` only if old `kind="recon"` history rows must still render — or route it through `render_report` from `/api/history`; update README §v2).
- **Cost of not fixing**: every pipeline change is a two-place change; reviewers must reason about two coordinators.
- **Recommendation**: remove `/api/recon/stream` and `recon_stream_unavailable` (`app.py:1459`); keep `render_report` reachable for historical rows via the history endpoint. Prefer deletion over extracting a shared abstraction.
- **Priority**: P0

#### D2 — Two graph stacks shipped and loaded on every page
- **Problem**: the inline Cytoscape graph (`renderGraph`, `static/js/app.js:2439-2655`, 217 lines) and the sigma.js WebGL case graph (`cgRender`, `app.js:3220-3341`) coexist. Five features are implemented twice: ego view (`app.js:2779` vs `3907`), timeline scrubber (`2176` vs `3925`), changes-only filter (`2846` vs `3988`), PNG export (`2240` vs `3996`), GraphML export (`2905`/`2982` vs `4018`/`4067`). `app.js:3028-3030` admits Cytoscape "remains for the fallback path".
- **Evidence**: `static/index.html:567-575` loads cytoscape.min.js (374 KB) + layout-base (148 KB) + cose-base (119 KB) + cytoscape-fcose (57 KB) + cytoscape-navigator (29 KB) **and** graphology (74 KB) + sigma (97 KB). `static/vendor/graphology-library.min.js` (168 KB) is listed in `static/vendor/README-webgl.md` but is **not referenced by any `<script>` tag or JS** — dead vendored file. `app.js` has 53 `cy.`/`cytoscape` references vs 10 sigma references.
- **Impact**: ~730 KB of JS for a fallback; 5 duplicated feature paths; `#graphPanel` (`index.html:278-296`) plus its CSS still shipped.
- **Risk if unfixed**: the two renderers diverge (they already do: only `cgRender` has tiers/hulls/inspector); bug reports ambiguous about which graph.
- **Root cause**: in-flight sigma migration (memory: "Increments 0–3 done + 4 in progress") kept the old panel as a safety net.
- **Cost to fix**: M (delete `renderGraph` + `#graphPanel` + 5 duplicate feature blocks + 5 vendor files + README fallback sentence at `README.md:411-412`); S to delete `graphology-library.min.js` today.
- **Cost of not fixing**: every graph feature ships twice or ships inconsistently.
- **Recommendation**: finish Increment 4, then remove the Cytoscape path outright; delete `graphology-library.min.js` now.
- **Priority**: P0 (dead 168 KB file: quick win; full removal after Increment 4)

#### D3 — Investigation left in `status='running'` forever on client disconnect
- **Problem**: `investigate_stream` marks the row `running` (`app.py:1052`) and only `coordinator`'s `except Exception` (`app.py:1093-1095`) sets `failed`. Client disconnect → `event_gen` `except asyncio.CancelledError: coord_task.cancel()` (`app.py:1116-1117`); `CancelledError` is a `BaseException` so the `except Exception` never runs and no status is written.
- **Evidence**: `app.py:1093-1099`, `app.py:1116-1118`. `docs/specs/05-job-queue.md:12,44` describes the problem (with stale line numbers) but nothing in code handles it.
- **Impact**: `investigations.status` becomes unreliable; `investigate_graph` baseline query filters on `status = 'done'` (`app.py:1141`) so a re-run of an interrupted case silently loses its diff baseline; UI shows a case as running indefinitely.
- **Risk if unfixed**: data-integrity drift accumulates in prod; the planned job queue (spec 05) will inherit bad rows.
- **Root cause**: run executes inside the request handler; cancellation path not covered by a `finally`.
- **Cost to fix**: S (in `coordinator`, `except asyncio.CancelledError: _set_investigation(inv_id, "cancelled"); raise`, or a `finally` that writes a terminal status if none written).
- **Cost of not fixing**: manual DB clean-ups; misleading history.
- **Recommendation**: add the cancel branch + a test that cancels the task and asserts the stored status.
- **Priority**: P0

#### D4 — No HTTP-layer tests at all; three large modules untested
- **Problem**: `app.py` (30 routes, 1533 LOC) has zero tests — no `TestClient`, no SSE parsing (`grep TestClient tests/` → none). `recon/pipeline.py` (698 LOC, `run_pipeline` 562 lines), `recon/dossier.py` (624), `recon/report.py` (213) have no test file.
- **Evidence**: coverage matrix §2. CI only curls `/` and `/api/sites` and `POST /api/investigate` (`.github/workflows/ci.yml:33-52, 90-99`).
- **Impact**: every error-shape, validation and persistence bug in §D10 is invisible to CI; pipeline event contract (`emit(...)` payload keys consumed by `app.js`) has no guard.
- **Risk if unfixed**: regressions in the most user-visible code ship silently; refactors from D1/D9/D10 cannot be done safely.
- **Root cause**: tests were written for pure functions ("stdlib-fast" policy) and never extended to the boundary.
- **Cost to fix**: M (a `tests/test_app.py` with `fastapi.testclient.TestClient(app)` against a `tmp_path` SQLite; needs `DB_PATH` injectable — today it is a module constant at `app.py:83` and `_init_db()` runs at import `app.py:202`; a fake `run_pipeline` via monkeypatch; dossier/report rendered from a fixture summary and asserted for escaping + section presence).
- **Cost of not fixing**: manual verification per PR; D1/D9/D10/D12 refactors stall.
- **Recommendation**: make `DB_PATH`/`_init_db` overridable (env `SHERLOCK_DB_PATH`), add route tests for the 404/409/400 paths, an SSE test for `search_stream` with a stubbed `sherlock`, and golden-HTML tests for `render_dossier`/`render_report`.
- **Priority**: P0

#### D5 — Failures swallowed: `gather(return_exceptions=True)` with discarded results, `fatal` events not logged
- **Problem**: five `asyncio.gather(..., return_exceptions=True)` calls drop exceptions without inspection: `recon/enrich.py:497` (whole enrichment fan-out), `recon/whatsmyname.py:201`, `recon/correlate.py:482-483`, `recon/adapters.py:307-308`, `recon/detectors.py:247-248`. Coordinator failures are emitted to the browser but never logged server-side: `app.py:822-823` and `app.py:1093-1095` have no `logger.exception`. `run_pipeline` engine errors (`recon/pipeline.py:100-101, 329-331, 387-389, 432-434`) go only to `emit("engine_error")`. Bare `pass` swallows at `app.py:101-106`, `recon/correlate.py:479-480`, `recon/geo.py:288-289`, `recon/enrich.py:202-203`.
- **Evidence**: 104 broad `except Exception`/`except:` across `app.py` (19) and `recon/` (85); see per-file counts in §5.
- **Impact**: a `work()` crash in enrichment loses that row's verdict *and* its `not_examined` marker (row stays with no `verification`, which `verdict_bucket` maps to `not_examined` only by accident, `recon/confidence.py:88`); production incidents have no stack traces.
- **Risk if unfixed**: "run finished with 0 leads" is indistinguishable from "enrichment crashed".
- **Root cause**: "never raises" contract implemented as blanket swallowing instead of log-and-degrade.
- **Cost to fix**: S per site (capture `results = await gather(...)`, log `isinstance(r, Exception)`; add `logger.exception` before each `emit("fatal")`).
- **Cost of not fixing**: debugging field runs by reproduction only.
- **Recommendation**: keep the never-raise contract, add logging; treat `return_exceptions=True` without inspection as a lint failure (ruff has no rule; add a grep to CI or a code comment convention).
- **Priority**: P0

### P1

#### D6 — Same HTML/text helpers and phrase lists in several modules
- **Problem / evidence**:
  - `_visible_text` (`recon/verify.py:109-115`) and `visible_text` (`recon/stealthweb.py:118-124`) are byte-identical; so are `_SCRIPT_STYLE_RE/_TAG_RE/_WS_RE` (`verify.py:45-47` vs `stealthweb.py:106-108`); `_TAG_RE` again at `recon/enrich.py:50`.
  - Challenge-marker list: `verify._CHALLENGE` (`verify.py:80-86`, 15 phrases) == `stealthweb._CHALLENGE_MARKERS` (`stealthweb.py:88-104`, same 15 in different order); overlapping subsets in `brokers._WAF_MARKERS` (`recon/brokers.py:61-62`), `router.classify` (`recon/router.py:127-131`: "cloudflare", "captcha", "just a moment") and `correlate._BOILERPLATE_PHRASES` (`recon/correlate.py:139`: "before you continue to", "just a moment").
  - Streamed capped GET implemented four times: `enrich._fetch_page` (`enrich.py:225-247`), `detectors._fetch` (`detectors.py:137-159`), `whatsmyname._get_capped` (`whatsmyname.py:119-130`), `brokers._get_capped` (`brokers.py:152-162`); `safeweb.fetch_capped` (`recon/safeweb.py:125-145`) exists but returns bytes only (no status), so nobody who needs the status can use it.
  - `average_hash` / `average_hash16` differ by one integer (`recon/correlate.py:150-181`).
  - `holehe_scan` (`recon/email_pivot.py:109-163`) and `ignorant_scan` (`recon/phone_accounts.py:85-147`) are the same sequential-module loop.
  - `_e()` HTML-escape helper in `recon/report.py:13` and `recon/dossier.py:18`.
  - Honest UA string in four variants: `adapters.py:43`, `detectors.py:35-36`, `geo.py:45-46`, `breach.py:41-42`.
  - `EXISTS/ABSENT/BLOCKED` in `adapters.py:45-47` and `detectors.py:38-40`; `discover()` bodies (`adapters.py:277-309`, `detectors.py:224-249`) identical modulo registry.
  - Retry-transient block written three times in `recon/pipeline.py` (`106-127`, `332-349`, `390-407`).
- **Impact**: the challenge list was extended in one place only once already (order differs → someone edited them separately); a fix to the capped-GET content-type check (`enrich.py:234` checks `text/html|application/xhtml`, `detectors.py:145` checks `"html" or "text"`) applies to one copy.
- **Risk**: verify and stealthweb disagree on what counts as a challenge page → a page escalates (stealthweb says challenge) but verify then labels the tier-3 result "unconfirmed" or vice-versa.
- **Root cause**: modules grown independently under a "no cross-module coupling" instinct; no `recon/htmltext.py`.
- **Cost**: S–M. Move `visible_text`, the regexes and `CHALLENGE_MARKERS` into one module (stealthweb already exports public names — have verify import them); add `status` to `safeweb.fetch_capped` and delete the four copies; parametrise `average_hash(size=8)`.
- **Cost of not fixing**: divergent detection semantics across the ladder and the verifier.
- **Priority**: P1

#### D7 — Enrichment-field precedence copied 11× with *inconsistent* semantics
- **Problem**: `jsonld_name or og_title [or title]` appears in `recon/graph.py:72`, `recon/report.py:70`, `recon/dossier.py:159` (all **include** raw `title`) vs `recon/exposure.py:128`, `recon/correlate.py:367`, `recon/detectors.py:170` (**exclude** `title`, with `exposure.py:124-126` documenting *why*: "a bare page `<title>` is site boilerplate, not a person's name"). Avatar precedence `jsonld_image or og_image` in `graph.py:67`, `correlate.py:447`, `exposure.py:133`, `report.py:67`, `detectors.py:173`. The "all account rows" concatenation `accounts + variants + name_accounts` is written in `app.py:1086`, `app.py:1154-1158`, `recon/graph.py:80-83`, `recon/geo.py:84-87`, `recon/connections.py:82-84`, `recon/exposure.py:89-95, 156-159`, `recon/dossier.py:86, 322`.
- **Impact**: the graph node `display_name` (`graph.py:159`) and the dossier account table can show a `<title>` such as "carmen_pop - Streamer Overview & Stats · TwitchTracker" as the person's name — exactly the false-attribution class the correlation-honesty rules (`correlate.py:15-23`) forbid.
- **Risk**: report and graph name an unrelated third party; the fix in `exposure.py` never propagated.
- **Root cause**: no row-accessor module; each renderer re-derives fields.
- **Cost**: S (a `recon/rows.py` with `all_account_rows(summary)`, `display_name(row)`, `avatar(row)`, `bio(row)`; switch the 11 sites).
- **Cost of not fixing**: correctness rule enforced in 3 of 6 consumers.
- **Recommendation**: one accessor module; make `display_name` exclude `title` everywhere (matches the documented rule).
- **Priority**: P1

#### D8 — Timeline re-fetches GitHub for data the adapter already stored
- **Problem**: `recon/timeline.py:151-194` (`account_creation_dates`) calls `https://api.github.com/users/{login}` per GitHub row (≤15/call, `timeline.py:44`) on every `/timeline` and `/report` request (`app.py:1236, 1327`). The GitHub adapter already recorded `temporal.created_at` on the row during enrichment (`recon/adapters.py:157-171`, stored at `recon/enrich.py:443`), and `recon/graph.py:75-77` reads it from `row["temporal"]`.
- **Evidence**: two `api.github.com` fetch sites: `adapters.py:159`, `timeline.py:181`. Adapter note: "Unauthenticated limit is 60 requests/hour per source IP — enrichment only, never a scan-wide sweep" (`adapters.py:170`).
- **Impact**: each dossier open spends up to 15 of the 60 hourly unauthenticated GitHub calls; rate-limited responses silently drop the milestone (`timeline.py:190-192`).
- **Risk**: adapter checks during a live investigation fail with 403 after a few report opens.
- **Root cause**: timeline predates adapters (dates 12 Aug vs 24 Aug in `ls -la recon/`).
- **Cost**: S (read `row.get("temporal", {}).get("created_at")` first; fall back to fetch only for rows without it, or drop the fetch).
- **Priority**: P1

#### D9 — Investigation summary persisted twice; JSON-blob equality used as a key
- **Problem**: `investigate_stream` writes the summary to `investigations.summary` (`app.py:1079`) **and** again to `runs.results` via `save_run(..., summary, kind="investigation")` (`app.py:1088-1090`). Baseline for run-diff is found by `WHERE inputs = ?` with `json.dumps(inv["inputs"])` (`app.py:1139-1145`) — byte-equality of serialised JSON (key order, whitespace, `usernames` mutation at `app.py:1000-1002`).
- **Evidence**: `history.db` 2.1 MB + 0.97 MB WAL after light local use. All persisted structures are schemaless TEXT: `runs.results`, `investigations.inputs/summary`, `watchlist.inputs/last_signature`, `watch_alerts.data`, `site_health.window` (`app.py:157-201`, `recon/monitor.py:43-70`, `recon/router.py:228-255`). No `schema_version` field in `summary`; consumers defend with `.get()` everywhere (e.g. `recon/graph.py:93-94`, `exposure.py:155-163`).
- **Impact**: storage doubles per investigation; `WHERE inputs = ?` cannot use an index on Postgres (TEXT compare) and breaks the moment `inputs` gains a key (e.g. `location` added later → old rows never match). Postgres path stores JSON as TEXT rather than JSONB (`dbconn.py` has no type mapping).
- **Risk**: silent loss of run-diff; unbounded row growth; migrations impossible without a version field.
- **Root cause**: history table predates investigations; run-diff bolted on via string compare.
- **Cost**: M (store only `investigation_id` in `runs` for kind=investigation and join; add `summary["schema"] = N`; compute a stable `inputs_hash` column for baseline lookup).
- **Cost of not fixing**: every schema evolution is a guess; DB bloat on Railway Postgres.
- **Priority**: P1

#### D10 — Inconsistent error shapes and unvalidated bodies that 500
- **Problem**: four error shapes coexist: JSON `{"error": ...}` (25 sites in `app.py`, e.g. `:248, :914, :1017`), `text/plain` `Response("not found")` (`app.py:861, 1318, 1320`), FastAPI's `{"detail": [...]}` for `Query` validation (any `?timeout=abc`), and SSE `event: fatal` inside an HTTP 200 (`app.py:441-444, 572-582, 1048-1051`). No `HTTPException` anywhere (`grep -c HTTPException app.py` → 0). Global 404 returns `{"error","path"}` (`app.py:1529`).
- **Unvalidated inputs** (→ 500): `create_watch` does `body.get(...)` without an `isinstance(body, dict)` check (`app.py:1362`; `create_investigation` does check at `:967`); `int(body.get("interval_hours") or …)` raises on `"abc"` (`app.py:1378-1380`); `[int(i) for i in ids]` in `mark_alerts_seen` (`app.py:1447`); `get_run` `json.loads(row[5])` unguarded (`app.py:255`).
- **Impact**: clients cannot rely on one error contract; a malformed watch body produces a 500 with a stack trace (no auth gate by default).
- **Root cause**: handlers written ad hoc, no shared `err(status, msg)` helper; Pydantic models unused although FastAPI is the framework.
- **Cost**: S–M (Pydantic request models for `POST /api/investigate`, `POST /api/watchlist`, `POST /api/alerts/mark_seen`; one `_not_found()` helper; make `/report` endpoints return JSON errors like the rest).
- **Priority**: P1

#### D11 — CSS: redesign layered over legacy by specificity, large dead surface
- **Problem**: `static/css/app.css` (10 168 lines) contains the "LEDGER — integrated redesign (swarm of 37 agents…)" block (`app.css:1435-1441`) pasted on top of the original stylesheet: "PASTE NOTE: this block is written to win wherever it is pasted… deliberately one step more specific than its legacy twin… Deleting the legacy rules…" (`app.css:1895-1898`), "Kill the legacy blue 34px grid" (`app.css:5522`), legacy aliases kept (`app.css:1456-1457, 1481, 1486, 1510`). Four `:root` blocks (`app.css:11, 1447, 1566, 9094`); `.shell > .topbar` and `#controls` each redefined 8×, `.shell` 7×, `.sidebar` 6× (1737 rules / 1265 unique selectors); 35 `!important`; 93 `@media` blocks.
- **Dead classes**: 149 of 436 class selectors appear in neither `index.html` nor `app.js` (prefix-confirmed absent: `sh-*` source-health board, `w-*`/`wl-*`/`watch-group` watchlist, `a-panel/a-head`, `vk-*`, `tb-*`/`topbar-*`, `broker-*`, `cav-*`, `gt-*`, `sec-*`, `skel-*`, `sc-*`, `bstat*`, `cb-*`, `btn-key`, `btn-quiet`, `skip-link`, `mono-input`, `subdomain-*`, `phone-error/prose/stamp-cell`, `is-hot/is-inv/is-notice/is-caveat`, `consistent/conflicting/insufficient`, …). `sitePickerBtnLabel` id in HTML is referenced nowhere.
- **Impact**: any new rule must out-specify two generations of selectors; cascade order is load-bearing and undocumented outside comments.
- **Root cause**: additive redesign without removing what it replaced.
- **Cost**: L to consolidate; S to delete the 149 dead classes and the unreferenced id.
- **Cost of not fixing**: every UI change is trial-and-error against 10k lines.
- **Recommendation**: delete dead selectors first (mechanical, verifiable by the same grep), then collapse to one `:root`, then remove "legacy twin" rules the redesign explicitly overrides.
- **Priority**: P1 (dead-class deletion S; consolidation L)

#### D12 — Configuration: import-time env reads, magic numbers, duplicated defaults
- **Problem**: env is read at import in 8 places (`app.py:117, 1497`; `dbconn.py:27`; `recon/enrich.py:30, 35`; `recon/detectors.py:44`; `recon/whatsmyname.py:43`; `recon/phone_pivot.py:33-34`) so tests cannot vary them without `importlib.reload`; `RECON_STEALTH` alone is read per call (`stealthweb.py:65-66`). No single place lists knobs (README documents some; `docs/GODSEYE.md:43-44` others). Magic numbers: SSE keepalive `timeout=15` ×3 (`app.py:480, 833, 1106`); enrichment `CONCURRENCY=5`, `TIMEOUT_S=10` (`enrich.py:31-32`); `WMN_CONCURRENCY=20` (`whatsmyname.py:38`); `MAX_AVATARS=30` (`correlate.py:74`); `DEFAULT_MAIGRET_LIMIT=1200` (`engines.py:106`); `TICK_SECONDS=60`, `MAX_WATCHES_PER_TICK=5` (`monitor.py:29-33`). God's Eye default URL duplicated in `app.py:1497` and `static/index.html:538, 542` (JS overwrites at runtime, `app.js:550-551`, but the HTML default must still match). Import-time side effects: `logging.basicConfig` (`app.py:31`), `SitesInformation()` load (`app.py:146-148`), `_init_db()` (`app.py:202`) — `migrate_to_postgres.py:53` depends on that side effect ("importing runs `_init_db()`").
- **Impact**: D4's test harness is blocked by `DB_PATH` + `_init_db()` at import; operators must read source to know knobs.
- **Root cause**: organic growth; no `recon/config.py`.
- **Cost**: S (one `settings` dict read lazily; document all `RECON_*`/`PHONE_*`/`GODSEYE_*`/`PROXY_LIST`/`APP_PASSWORD`/`DATABASE_URL` in README).
- **Priority**: P1

#### D13 — Dependency hygiene: mixed pinning, no lockfile, unverifiable CVE status, CI cache key
- **Problem**: `requirements.txt` mixes `==` (maigret, holehe, ignorant, httpx, pillow, phonenumbers) with `>=` (fastapi, uvicorn, sherlock-project, psycopg) — the framework floats while leaf libs are frozen; no hash-pinned lock; `pip-audit` absent so nothing can be asserted about CVEs offline. `phonenumbers==8.13.55` is a metadata library that releases roughly weekly (carrier/geo data ages). `sherlock-project>=0.16.0` pulls `pandas`, `openpyxl`, `stem`; `maigret==0.6.4` pulls `Flask`, `reportlab`, `XMind`, `pyvis`, `networkx 2.8.8` (Required-by: maigret, pyvis) — ~120 transitive packages for a FastAPI app. CI `cache-dependency-path: requirements-dev.txt` (`ci.yml:20, 76`) but `requirements-dev.txt` only `-r requirements.txt` → cache key never changes when `requirements.txt` changes. CI never installs `requirements-stealth.txt`, so the stealth ladder's real import path is only exercised locally (the one skipped test).
- **Impact**: non-reproducible installs across dev/CI/Railway; stale caches in CI.
- **Cost**: S (pin with `pip-compile`/`uv pip compile` to a lock; add `pip-audit` to `requirements-dev.txt` and a CI step; fix `cache-dependency-path` to both files).
- **Priority**: P1

### P2

#### D14 — Coupling: private cross-module imports, upward dependency on `dbconn`, lazy imports
- `recon/adapters.py:341` imports `_identity_matches` from `recon.verify`; `recon/detectors.py:164` imports `_extract` from `recon.enrich`; `recon/geo.py:285` calls `safeweb._is_public_ip`; `app.py:373` calls `notify._emit`; tests import privates (`tests/test_enrich.py:8`, `tests/test_engines.py:4`). Make them public (drop the underscore) — they are de-facto API.
- `recon/router.py:51` and `recon/monitor.py:20-21` import the root-level `dbconn` — the package depends on the application layer. Move `dbconn.py` to `recon/db.py` or pass connections in.
- `app.py` imports most of `recon` at module top (`app.py:55-77`) but four routes import inside the body (`app.py:909, 923, 1262, 1280`) with no stated reason (unlike the deliberate lazy imports of maigret/holehe). Pick one style.
- The `RECON_AVAILABLE` try/except (`app.py:53-80`) guards imports of *local* modules whose only heavy deps are already lazy; if it ever triggers, 25 routes vanish with one WARNING. Either drop the guard or fail loudly.
- **Cost**: S. **Priority**: P2

#### D15 — Naming inconsistencies
- Eight normalisation helpers: `engines.normalize_site` (`engines.py:40-42`), `verify._norm` (`verify.py:101`), `correlate._norm_handle` (`correlate.py:203`) — all `re.sub("[^a-z0-9]","",lower)`; `graph._norm_handle` (`graph.py:171-172`, *different*: lstrip `@` + lower only); `connections._clean` (`connections.py:39`); `correlate._norm_name/_norm_url` (`correlate.py:199, 284`); `enrich._clean` (`enrich.py:53`, HTML clean — same name, different meaning). `graph` node ids `acct:{site}:{username}` use the raw site label (`graph.py:139`) while `monitor.compute_signature` keys use `normalize_site` (`monitor.py:159`).
- Seven status vocabularies: Sherlock `QueryStatus`; WhatsMyName `claimed/available/unknown` (`whatsmyname.py:47-49`); adapters/detectors `exists/absent/blocked`; verify `confirmed/unconfirmed/likely_false_positive/indeterminate/not_examined`; brokers `listed/not_found/blocked/manual/unknown` (`brokers.py:55-59`); buckets `found/lead/flagged/indeterminate/not_examined` (`confidence.py:68-90`); tiers `confirmed/strong/weak/refuted` (`confidence.py:119-128`). The verify→bucket→tier layering is documented and deliberate (see §6); the adapters/detectors/brokers trio is not.
- Timestamps: `"%Y-%m-%d %H:%M:%S"` literal in 12 places (`app.py`, `monitor.py:208`, `router.py:212`, `timeline.py:40`), naive **local** time (`time.strftime`, `time.mktime`) — Railway (UTC) vs laptop differ; DST-ambiguous once a year.
- Product name: `sherlock-web` (`app.py:110`), "Sherlock Web … 400+ sites, powered by Sherlock" (`static/manifest.webmanifest:2-4`), "Signals Ops" (`static/404.html:6`, CSS tokens `app.css:7`), "LEDGER" (`app.css:1436`).
- `runs.kind` values `sherlock|recon|investigation` (`app.py:206, 812, 1089`).
- **Cost**: S each. **Priority**: P2

#### D16 — Dead code
| Item | Evidence | Note |
|---|---|---|
| `adapters.check_account` | `recon/adapters.py:269-274`; 0 refs in src/tests/js | delete |
| `adapters.covered_sites`, `detectors.covered_sites` | `adapters.py:265-266`, `detectors.py:220-221`; 0 refs | delete or expose via `/api/health/sources` |
| `domain_pivot.reverse_dns` | `recon/domain_pivot.py:180-188`; 0 refs | delete |
| `router.select_retries` | `recon/router.py:193-195`; tests only (`RunRouter.drain_transient` reimplements the cap) | delete + its tests |
| `correlate.bio_similarity` | `recon/correlate.py:233-238`; tests only — superseded by `_jaccard` over `clean_bio_tokens` (`correlate.py:426-430, 559`) | delete + tests |
| `phone_pivot.phone_footprint` | `recon/phone_pivot.py:138-144`, docstring: "Used by tests" | delete; test `phone_intel` directly |
| `static/vendor/graphology-library.min.js` | 168 KB, no `<script>`/JS reference | delete |
| Cytoscape stack | see D2 | after Increment 4 |
| `sitePickerBtnLabel` | `static/index.html`, no JS/CSS reference | delete |
| 149 CSS classes | see D11 | delete |
| `docs/specs/01-06` | "Status: proposed" for Postgres although `dbconn.py` shipped; cites stale lines (`app.py:66`, `:98-119`, `:938`, `:482`) | mark 01 shipped, re-anchor or drop line refs |
| `.superdesign/` | untracked, not in `.gitignore` | ignore or commit |

#### D17 — `run_pipeline` is a 562-line function with 12 closures
- `recon/pipeline.py:138-698`: workers (`maigret_worker`, `whatsmyname_worker`, `signals_worker`, `email_worker`, `domain_worker`, `broker_worker`, `phone_accounts_worker`) and handlers are closures over ~10 mutable locals; `router` is referenced by closures defined before it is assigned (`pipeline.py:284, 312` use `router` created at `:502`). Untestable in isolation (D4). Same shape in `app.py:558-852`. `build_graph` (309 lines, `graph.py:86-393`) and `render_dossier` (318, `dossier.py:308`) are the next largest.
- **Cost**: M (a `RunState` dataclass + module-level worker functions taking it). **Priority**: P2

#### D18 — Observability gaps
- No request/run id in logs; `logging.basicConfig(INFO)` at import (`app.py:31`); `logging.getLogger("app")` ad hoc (`app.py:80, 391, 1266, 1284`); no `/healthz` (Railway healthcheck hits `/api/sites`, `railway.json:8`, which loads nothing DB-related); no phase timings (only `emit("phase", {"phase": "enriching"})`, `pipeline.py:625`); stealth ladder success is `logger.info` only (`enrich.py:463, 499-501`) and never persisted per row beyond `fetch_via` (`enrich.py:462`). See D5 for missing exception logs.
- **Cost**: S (structured `extra={"inv": inv_id}`, a `/healthz` doing `SELECT 1`, timing around each pipeline phase). **Priority**: P2

#### D19 — SSE plumbing duplicated three times
- `event_gen` loop with keepalive/disconnect check: `app.py:466-494`, `829-846`, `1100-1118`. Username splitting `re.split(r"[,\n]+", …)`: `app.py:438, 568, 973, 1365`. `{"error": "not found"}` 404 literal ×11.
- **Cost**: S (`sse_response(queue, request, on_cancel)` helper; `parse_usernames()`). **Priority**: P2

### P3

#### D20 — Lint breadth
- `ruff.toml:6-8` admits the rule set is minimal; widening to `E,W,I,B,UP,SIM,C4` yields 218 findings, 181 auto-fixable (UP045 ×153 `Optional[X]`→`X | None`, I001 ×13). `B023` (closure over loop variable) ×1 and `B905` ×3 are the only ones with behavioural potential. **Cost**: S (`ruff --fix`, then enable `I`, `B`). **Priority**: P3

#### D21 — External font dependency
- `static/index.html:12-14` loads Inter/JetBrains Mono from Google Fonts while every other asset is vendored (`static/vendor/README-webgl.md`); offline/air-gapped use falls back silently; a third-party request per page view for an OSINT tool. **Cost**: S (vendor the two woff2 files or drop to system fonts). **Priority**: P3

#### D22 — `android/` + `android-apk/` in the main repo
- 13 tracked files and a dedicated workflow (`.github/workflows/android-apk.yml`) for a WebView wrapper with a placeholder `SERVER_URL`; unrelated to the Python/JS surface, lengthens every clone. **Cost**: S (separate repo or subdir doc). **Priority**: P3

---

## 2. Test coverage matrix

Public = top-level `def`/`class` without leading underscore. "Untested" = name absent from every `tests/*.py`.

| Module | LOC | Covered by | Public | Untested public | Untested failure paths worth a test |
|---|---|---|---|---|---|
| `app.py` | 1533 | **none** (CI curl of `/`, `/api/sites`, `POST /api/investigate` only) | 14 + 16 routes under `if RECON_AVAILABLE` | all: `lifespan`, `basic_auth_gate`, `save_run`, `get_history`, `get_run`, `get_sites`, `get_health_sources`, `QueueNotify`, `search_stream`, `web_manifest`, `service_worker`, `godseye_status`, `not_found`, every `/api/investigate*`, `/api/watchlist*`, `/api/alerts*`, `/api/recon*`, `/api/domain`, `/api/brokers` | 404/409 shapes; `create_watch` non-dict body / non-int interval (500); `mark_alerts_seen` non-int id (500); Basic-auth wrong password; disconnect → status stuck `running` (D3); baseline lookup after `inputs` schema change |
| `dbconn.py` | 102 | `test_dbconn.py` | 2 | — | Postgres branch (`_PgConnection`, `RETURNING id`) untested locally — CI job covers boot + one insert only |
| `recon/adapters.py` | 350 | `test_policy_adapters.py`, `test_enrich.py` | 6 | `covered_sites`, `check_account` (dead) | `Adapter.check` non-JSON 200; `exists_when` raising |
| `recon/breach.py` | 178 | `test_breach.py` | 3 | — | — |
| `recon/brokers.py` | 228 | `test_brokers.py`, `test_phone_pivot.py` | 6 | `broker_exposure` | `_check` WAF marker → BLOCKED; `MAX_CHECKS` cap |
| `recon/confidence.py` | 128 | `test_confidence.py`, `test_policy_adapters.py` | 4 | — | — |
| `recon/connections.py` | 145 | `test_connections.py` | 2 | — | — |
| `recon/correlate.py` | 657 | `test_correlate.py` | 16 | `average_hash16` | `_download_avatars` failure path swallowed (`:479`) |
| `recon/detectors.py` | 249 | `test_detectors.py` | 4 | `covered_sites` (dead) | tier-3 budget exhaustion; `classify` with `present=()` |
| `recon/domain_pivot.py` | 216 | `test_domain_pivot.py` | 7 | `reverse_dns` (dead), `domain_intel` | RDAP non-200; crt.sh non-JSON |
| `recon/dossier.py` | 624 | **none** | 1 | `render_dossier` | HTML escaping of subject/display names; empty summary; `timeline=None` |
| `recon/email_pivot.py` | 163 | `test_email_recovery.py` | 5 | `gravatar_lookup`, `holehe_available`, `holehe_scan` | module timeout → `exists: None` entry; `only=` filter |
| `recon/engines.py` | 163 | `test_engines.py` | 8 | `maigret_site_names`, `maigret_variant_sites`, `maigret_scan`, `sherlock_variant_site_data` | `maigret_all_sites` fallback when `ranked_sites_dict` raises |
| `recon/enrich.py` | 502 | `test_enrich.py` | 2 | — | `work()` raising inside `gather` (row left without verdict, D5); budget `skipped` marking; `control_for` cache per host |
| `recon/exposure.py` | 298 | `test_exposure.py` | 3 | — | — |
| `recon/geo.py` | 358 | `test_geo.py` | 6 | — | Nominatim rate-limit lock; `MAX_PLACES` overflow note |
| `recon/graph.py` | 393 | `test_graph.py`, `test_email_recovery.py` | 2 | `category_for` | `gone:` ghost nodes with baseline; correlation link endpoint parsing when URL contains `)` |
| `recon/monitor.py` | 285 | `test_monitor.py` | 6 | `light_scan`, `run_watch`, `monitor_loop` | baseline-silent first run; `last_run_at` stamped before scan; unparseable `last_run_at` |
| `recon/names.py` | 128 | `test_names.py` | 1 | — | — |
| `recon/permutations.py` | 75 | `test_permutations.py` | 1 | — | — |
| `recon/phone_accounts.py` | 147 | `test_phone_accounts.py` | 2 | `ignorant_available` | — |
| `recon/phone_pivot.py` | 222 | `test_phone_pivot.py` | 4 | `phonenumbers_available`, `footprint_links` (indirectly via `phone_footprint`) | `PHONE_DEFAULT_REGION` override (import-time, D12) |
| `recon/pipeline.py` | 698 | **none** | 1 | `run_pipeline` | every emit payload contract; router filtering; variants phase; `email` invalid → skipped; engine_error path |
| `recon/policy.py` | 85 | `test_detectors.py`, `test_policy_adapters.py` | 3 | — | — |
| `recon/report.py` | 213 | **none** | 1 | `render_report` | escaping; plain-sherlock run shape from `app.py:869-891` |
| `recon/router.py` | 724 | `test_router.py` | 12 | `retry_delay` | `RunRouter.finish` proxy-health write; store disables itself on `sqlite3.Error` |
| `recon/safeweb.py` | 145 | `test_safeweb.py`, `test_stealthweb.py` | 4 | `fetch_capped` | `max_bytes` overflow → None |
| `recon/stealthweb.py` | 306 | `test_stealthweb.py`, `test_enrich.py` | 8 | `visible_text` (dup of verify) | `_session_dead` latch after launch failure |
| `recon/timeline.py` | 195 | `test_timeline.py` | 5 | `account_creation_dates` (network) | rate-limited 403 body |
| `recon/validate.py` | 24 | `test_validate.py` | 1 | — | — |
| `recon/verify.py` | 323 | `test_verify.py` | 1 | — | — |
| `recon/whatsmyname.py` | 201 | `test_whatsmyname.py` | 6 | `WmnResult`, `whatsmyname_scan` | stealth retry budget; `on_result` raising |
| `migrate_to_postgres.py` | 85 | none | 1 | `main` | — (one-shot script) |

Network-touching tests use `monkeypatch`/mocks (9 files) — good; nothing hits the network.

---

## 3. Dependency table

Installed versions from `pip list` in `./venv`. "Latest" cannot be checked offline → **UNVERIFIED**; CVE status **UNVERIFIED** (no `pip-audit`).

| Requirement (file) | Pin | Installed | Used by | Notes |
|---|---|---|---|---|
| `fastapi>=0.110` | floating | 0.141.1 | `app.py:33-35` | Framework floats while leaves are frozen; Pydantic models unused (D10) |
| `uvicorn>=0.29` | floating | 0.52.1 | `run.sh:21`, `railway.json:7`, CI | — |
| `sherlock-project>=0.16.0` | floating | 0.16.0 | `app.py:41-44`, `recon/pipeline.py:21-23`, `recon/monitor.py:84-86` | pulls pandas/openpyxl/stem; docstring pins API to 0.16.0 (`app.py:7`) while range allows breaking majors |
| `maigret==0.6.4` | pinned | 0.6.4 | `recon/engines.py:69-153` (lazy) | pulls Flask, reportlab, XMind, pyvis, `networkx 2.8.8` (old major); `MaigretDatabase().load_from_path(pkg.__path__[0] + "/resources/data.json")` (`engines.py:86-88`) depends on package layout |
| `holehe==1.61` | pinned | 1.61 | `recon/email_pivot.py:95-106` (lazy) | relies on private `holehe.core.get_functions/import_submodules` |
| `ignorant==1.2` | pinned | 1.2 | `recon/phone_accounts.py:35-67` (lazy) | same private-API reliance, with explicit fallback list (`:57-61`) |
| `httpx==0.28.1` | pinned | 0.28.1 | `recon/safeweb.py`, `enrich.py`, all pivots | shared by holehe/ignorant — pin coupling |
| `pillow==12.3.0` | pinned | 12.3.0 | `recon/correlate.py:153, 171` (lazy) | only for 8×8/16×16 average hash |
| `phonenumbers==8.13.55` | pinned | 8.13.55 | `recon/phone_pivot.py`, `recon/phone_accounts.py:74` | metadata lib, weekly releases → pinned data ages |
| `psycopg[binary]>=3.1` | floating | 3.3.4 | `dbconn.py:80-81` (lazy) | — |
| `pytest>=8.0` (dev) | floating | 9.1.1 | tests | — |
| `ruff>=0.6` (dev) | floating | 0.16.2 | CI lint | — |
| `scrapling[fetchers]>=0.4.14,<0.5` (stealth) | range | 0.4.14 | `recon/stealthweb.py:52`, `recon/enrich.py:132` | brings patchright 1.62.1 + playwright 1.62.0; lxml `strip_cdata` DeprecationWarning ×16 in tests originates here; not installed in CI |
| *(transitive)* `lxml 6.1.1`, `curl_cffi 0.16.0`, `requests 2.34.2`, `urllib3 2.7.0`, `aiohttp 3.14.3`, `Jinja2 3.1.6`, `Werkzeug 3.1.8`, `certifi 2026.7.22` | — | — | via maigret/scrapling/sherlock | CVE status UNVERIFIED |
| Vendored JS | — | sigma 2.4.0, graphology 0.25.4, graphology-library 0.8.0 (**unused**), leaflet 1.9.4, cytoscape (version undocumented in README-webgl.md), fcose/cose-base/layout-base/navigator (undocumented) | `static/index.html:567-578` | Cytoscape family missing from the vendor README; 5 of 11 files belong to the fallback stack (D2) |
| Vendored data | — | `recon/data/wmn-data.json` 255 KB (CC BY-SA), `data_brokers.json` 7 KB | `whatsmyname.py:34`, `graph.py:38`, `brokers.py:48` | no refresh date recorded in-file |
| External at runtime | — | Google Fonts (`index.html:12-14`), OSM tiles (`app.js:395`), Nominatim/ipwho.is (`geo.py:48-49`), Cavalier (`breach.py:40`), Cloudflare DoH/RDAP/crt.sh (`domain_pivot.py:29-31`) | — | all documented in module docstrings |

---

## 4. Quick wins (S cost, P0/P1)

1. Delete `static/vendor/graphology-library.min.js` (168 KB, never loaded) — D2/D16.
2. Add `except asyncio.CancelledError: _set_investigation(inv_id, "cancelled"); raise` in `app.py:1093` coordinator — D3.
3. `logger.exception(...)` before `emit("fatal", …)` at `app.py:823` and `app.py:1095`; inspect `gather` results at `recon/enrich.py:497`, `whatsmyname.py:201`, `correlate.py:482` — D5.
4. `recon/timeline.py:account_creation_dates`: read `row["temporal"]["created_at"]` first, fetch only when absent — D8.
5. Make `verify._visible_text`/`_CHALLENGE` import from `stealthweb` (or the reverse); delete one copy — D6.
6. Replace `graph.py:72`, `report.py:70`, `dossier.py:159` name precedence with the `exposure.py:128` rule (drop `title`) — D7.
7. `isinstance(body, dict)` + try/except `ValueError` in `create_watch` (`app.py:1357-1391`) and `mark_alerts_seen` (`app.py:1447`) — D10.
8. Delete dead functions: `check_account`, both `covered_sites`, `reverse_dns`, `select_retries`, `bio_similarity`, `phone_footprint` (+ their tests) — D16.
9. Fix CI `cache-dependency-path` to `requirements*.txt`; add `pip-audit` to `requirements-dev.txt` and a CI step — D13.
10. Delete the 149 unreferenced CSS classes and `sitePickerBtnLabel` — D11.
11. Remove `app.py:784` `min(40, …)` (stale) — or remove the whole `/api/recon/stream` route (D1, M).

---

## 5. Broad-except census (context for D5)

`except Exception`/bare `except` per file: `app.py` 19 · `recon/enrich.py` 14 · `phone_accounts.py` 8 · `stealthweb.py` 7 · `pipeline.py` 7 · `correlate.py` 6 · `monitor.py` 5 · `geo.py` 5 · `email_pivot.py` 5 · `adapters.py` 5 · `whatsmyname.py` 4 · `engines.py` 3 · `domain_pivot.py` 3 · `detectors.py` 3 · others ≤2 (total 104). Most are the deliberate "never raises" contract with logging (keep); the ones without any log or marker are listed in D5.

---

## 6. Do not touch (looks like debt, is deliberate — rationale is in the code)

| Item | Where | Why it stays |
|---|---|---|
| `DENIED_HOSTS` hard-coded list and `not_examined` verdict | `recon/policy.py:29-42, 76-85` | Each entry cites a robots.txt observation; "we did not look" must never render as "no account" — accuracy rule, not config |
| `blocked ≠ absent` triple outcome in adapters/detectors/verify | `adapters.py:10-12`, `detectors.py:15-16`, `verify.py:15-18, 33` | Core honesty invariant; do not collapse the vocabularies' *semantics* even if the constants are unified (D15) |
| `_SOFT_404`, `_REMOVED`, `_CONSENT_WALL` phrase lists and their scoping to title/heading/top-400 chars | `verify.py:59-95, 118-134, 249-261` | Each rule cites a real false positive it fixed (`verify.py:22-33`) |
| Correlation rules 1–6 (placeholder avatars, template stripping, same-site hard evidence, 16×16 corroboration, URL dedupe) and the `ignored:` provenance trail | `correlate.py:7-42, 490-572` | Replay-evidenced (memory: run-50/54); the `ignored` list is a feature |
| Denied hosts not counted against the enrichment budget | `enrich.py:321-331` | Documented from a real run (28 rows ate a third of the budget) |
| Template-field stripping *after* verification | `enrich.py:480-486` | Verification needs the raw title for its control comparison |
| Buffered `RunRouter.observe` + single flush in `finish()` | `router.py:543-549, 638-653` | Avoids per-observation SQLite writes from worker threads |
| Router: 429/WAF never retried in-run | `router.py:87-89` | Circuit breaker owns those across runs |
| Kill-switch service worker (no fetch handler) and its `/sw.js` no-cache route | `static/sw.js:1-13`, `app.py:1483-1490` | Purges old workers that caused stale-UI bugs; `index.html` also unregisters |
| `RunRouter` degrading to a no-op when the DB is unavailable | `router.py:258-270, 542` | Scans must not fail because health memory failed |
| Lazy imports of maigret/holehe/ignorant/phonenumbers/scrapling | `engines.py:69, 83`, `email_pivot.py:95`, `phone_accounts.py:35`, `phone_pivot.py:64, 159`, `stealthweb.py:51-58` | Optional heavy deps; app must boot without them (`recon/__init__.py:18-21`) |
| Honest, identifiable `USER_AGENT` for adapters/detectors/geo/breach vs browser UA for generic enrichment | `adapters.py:42-43`, `safeweb.py:36-39` | Policy split (public APIs get an honest agent) — unify the *string*, keep the split |
| Nominatim 1 req/s lock and per-case caps | `geo.py:52-57, 236-252` | Usage-policy compliance |
| Cavalier: passwords/logins/IPs dropped before leaving the function | `breach.py:51-69` | Deliberate data minimisation |
| SSE `event: fatal` inside HTTP 200 for stream endpoints | `app.py:441-444, 1048-1051` | EventSource cannot read non-200 bodies; only the *pre-stream* validation errors could become 400 |
| `dbconn._translate` `?`→`%s` string replace | `dbconn.py:36-42` | Documented assumption (no literal `?`/`%` in SQL); revisit only if JSON-in-SQL literals appear |
| `_control_url` / `CONTROL_HANDLE` known-nonexistent probe | `enrich.py:37-39, 250-256` | Strongest soft-404 signal available |
| Name-derived candidates never fanned to adapters/detectors | `adapters.py:284-285`, `detectors.py:227`, `pipeline.py:418-420` | Bounded API cost + avoids guessing about other people |
