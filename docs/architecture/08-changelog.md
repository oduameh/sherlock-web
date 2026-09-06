# Implementation changelog, risks, next steps

Maintained per increment (see `02-target-architecture.md` §10). Each entry records what
changed, how it was verified (tests, replay, live run), and the independent review outcome.

## Baseline — 2026-09-06, `32c061f`
* Tests: 351 passed, 1 skipped, ~1.3 s, no network.
* Known stuck investigations: 7 rows `running`, 4 orphan `pending`.
* Six audits produced (`docs/audit/2026-09-06/`); eleven defects verified directly (target §1.3).

## Increments

### D (part 1) — ops hygiene · PR #47 · 2026-09-06
`run.sh` reinstalls when `requirements.txt` changes (hash stamp) instead of only when three
core imports are missing; CI's pip cache key now tracks `requirements*.txt`, installs the
stealth extra the parser tests need, runs `node --check`, and reports `pip-audit`
(advisory until the lockfile lands); `pytest.ini` silences two third-party deprecation
warnings; `.gitignore` covers `.superdesign/`, `.ruff_cache/`.
Verification: suite green (351), `bash -n`, YAML parse. Review: not separately reviewed
(config-only); covered by the later program review.

### F — frontend dead code and URL hygiene · PR #48 · 2026-09-06
The Cytoscape identity-graph workbench had no caller. Removed ~987 lines of JS, the
`#graphPanel` subtree, three CSS blocks and seven vendor files (~897 KB, including a
bundle that was never loaded). `esc()` escapes quotes; every remote or subject-controlled
`href` / `img.src` / `background-image` goes through an http(s) allow-list on the client
and in the HTML report and dossier (non-http(s) values render as text). Vendor provenance
recorded with sha256.
Verification: `node --check`; all 113 element ids resolve; zero references to removed
ids/classes; suite green (+8 tests, mutation-checked); headless-Chromium pixel diff vs
baseline across 8 views: 0 differing pixels on the case graph, footprint, watchlist and
God's Eye; zero console/page errors; no horizontal overflow.
Review: approved with three should-fixes (report `<img src>` gating, DROP-portal link,
brokers-section test) — all landed before merge.

### C — policy completeness · PR #49 + hotfix #50 · 2026-09-06
The deny list was enforced only by our own fetchers. Now: plan-time filtering of all six
engine site sets (policy first, then circuits) with one additive `skipped_policy` event
and honest per-site reasons; a distinct WhatsMyName `policy` status that is neither
observed nor reported as an error; holehe/ignorant skip modules targeting denied hosts;
avatar downloads refuse denied URLs; images above 4 M pixels are rejected before decode;
the access policy is checked inside `safeweb._guard` on every request and redirect hop.
Deny list corrected from robots.txt observed 2026-09-06: `cdninstagram.com`, `fbcdn.net`,
`pinimg.com`, `redditmedia.com` added (`Disallow: /`); `twimg.com` removed
(`pbs.twimg.com` allows all). Written rule: a scraper mirror is not an alternative source
for a denied platform.
Verification: suite green (404 after #50); the reviewer enumerated every planned set
offline — no denied-host template survives; Sherlock 5, Maigret 9, WMN 8 removed.
Review: approved with two should-fixes, landed. **Process defect**: #49 was merged with
two failing assertions because a multi-step script continued past an aborted patch step;
fixed in #50 and prevented by `scripts/gate.sh` (#51).

### A — investigation lifecycle · PR #53 · 2026-09-06
State machine `pending → running → done | failed | cancelled | interrupted`: an atomic claim
moves pending→running; any non-pending stream answers 409 (a GET used to re-run finished
cases and a disconnect stranded them — 7 of 53 rows); `cancelled` on disconnect
(`CancelledError` used to slip past `except Exception`); `failed` with the reason persisted
in `investigations.error` and logged; `started_at`/`finished_at`; startup sweep of stale
`running` and 24 h-old `pending` rows; at most two concurrent runs with a `queued` event;
`done` held until the summary is on disk. A cancelled run now cancels every engine/pivot
task it spawned and flushes routing observations on any exit (live: 2 log lines after a
cancel instead of 543+). Boot no longer needs the internet: the Sherlock list is a cached
live copy refreshed weekly with a 5 s timeout, validated by loading before caching, atomic,
falling back to the stale cache then the bundled file (vendored exclusions snapshot). The
EventSource never auto-reconnects. `SHERLOCK_DB_PATH` makes the database injectable; first
HTTP-layer tests.
Verification: gate green (423 at merge); live on the real database (7 + 4 rows repaired,
cancel path, 409 guard, site list `433 sites from cache source (48 excluded)`).
Review: two independent reviews (initial: six should-fixes; re-review: one blocker on the
loader — a wrong-shape payload cached with a fresh mtime would have broken boot for a week
— and four should-fixes); all landed before merge.

### B — verification correctness · PR #56 + hotfix #57 · 2026-09-06
`recon/htmltext.py` is the single home for HTML→text and the challenge / consent / soft-404
markers (they had diverged between `verify.py` and `stealthweb.py`); every pattern is linear
and bounded (hostile pages that stalled the event loop for 20 s now cost ≤ 40 ms). V1: a
not-found page echoing the handle in its title was `confirmed 72` — a headline soft-404
regex runs before handle corroboration, control similarity is computed after masking both
handles, and handle-anchored forms ("Torvalds does not use Launchpad") are refuted per
headline part. V2: unlisted WAF pages (Akamai, Imperva) are `indeterminate` and escalate;
a page identical to the control that carries no profile metadata and does not name the
handle is a block page, not a refutation. V7: 429/503 never trigger the stealth ladder;
per-host backoff (`Retry-After`, minimum 5 s); later rows on that host are `indeterminate`
with `reason: rate_limited` without a fetch. A failed control probe is `control_probe:
"failed"` and never cached. Posture: the browser tier never solves Cloudflare challenges
(Scrapling's solver clicked Turnstile) nor sends a forged Google referer; downloads
disabled; cookies cleared on host change. Owner decision: a person's name written next to
the handle that is clearly someone else makes the row an unconfirmed lead; boilerplate
around the handle yields no opinion.
Verification: gate green (524 at #57); every hostile-input shape from the audit and both
reviews timed under 0.5 s.
Review: first review do-not-merge-as-is (1 blocker: the heading window had been cut and
re-opened V1; 6 should-fixes); re-review merge-after-fixes (1 blocker in the new
display-name rule, 2 should-fixes) — all landed with the reviewers' probes as tests.
**Process defect**: #56 merged red (a missing test import; the gate's failure was masked
by a shell pipeline) — fixed in #57; the gate is now run unpiped with its exit code
enforced.

### H1 — HTTP-layer hardening · PR #54 · 2026-09-06
Cross-site protection for the unauthenticated local API: Host allow-list
(`APP_ALLOWED_HOSTS`), `Sec-Fetch-Site`/`Origin` (host **and** port) guard on every
`/api/*` request that is not a pure database read, JSON-only POSTs (415), 64 KiB body cap
(413, also for chunked bodies), 20 usernames and 500 alert ids per request, typed bodies
(400 naming the field, never a 500). Security headers on every response and a CSP on
every HTML document (`script-src 'self'`; the one inline script became a file).
`/api/health` (registered unconditionally, reachable behind the password gate with
liveness-only fields) and Railway's health check uses it. `DELETE /api/investigate/{id}`
(cascades; 409 while running) and `DELETE /api/history/{id}`; the database is created
0600. The legacy v2 `/api/recon/stream` (344 lines, no caller, no routing, no policy) is
removed. Quick scan and site picker are policy-filtered. SSRF guard requires `is_global`
and unwraps 6to4 / IPv4-mapped / Teredo addresses. Quieter, timestamped logging.
Verification: gate green (439+); headless Chromium: zero console errors (no CSP
violations); live curl probes on the merged server: 403 / 200 / 400 / 415 / 404 as
specified.
Review: merge-after-fixes with curl probes (pivot GETs unprotected, Origin port ignored,
quick-scan cap missing, health unreachable behind the gate, chunked bodies, DELETE of a
running case) — all landed with the probes as tests; the fix also uncovered that a bare
IPv6 entry in the allow-list parsed to "" and matched the userinfo Host trick.

### E — observability · PR #60 · 2026-09-06
After a run, `history.db` alone answers what was tried, which source failed, why, which
retries ran and recovered, and how confident the result is: `summary["run"]` (bounded,
schema 1) holds planned site counts and budgets, `skipped_policy`, `skipped_degraded`,
errors by class and by engine×class, up to 120 failed checks with class and context,
retries attempted/recovered, engine errors, signals-engine outcomes, verification counts,
per-phase timings, and an honest `not_recorded` list (stealth-ladder attempts, WMN stealth
retries, detector browser escalations, budget consumption, fetch status histogram — still
to come with G2). The signals engine is observed by the circuit breaker (a walled detector
is now `blocked`, not `absent`); WhatsMyName latency is measured (0 of 649 rows had it);
every log line during a run carries `inv=<id>`; `done` carries `elapsed_s`/`retries`; the
UI shows `skipped_policy`.
Verification: gate green; live on the merged server: run id on router/engine/plan lines;
a completed run's summary carries `run` (checked after the merge).
Review: merge-after-fixes (1 rebase blocker — keep H1's email-free log line; 7 should-fixes)
— all landed.

### I — data layer · PR #59 · 2026-09-06
`dbschema.py`: an append-only migration list tracked in a `schema_version` table
(primary key) on SQLite and Postgres, mirrored to `PRAGMA user_version`; v1 baseline
including the columns older files gained through inline ALTERs, v2 indexes for the
queries the app runs; the monitor creates its own `watch_alerts` index on every boot so a
first boot without the recon package can never skip it. The investigation summary is
stored once: the history row written on completion holds a pointer and
`/api/history/{id}` resolves it by join (older full rows untouched). The legacy report
route redirects investigation rows to the dossier (it 500'd before). WAL checkpoint on
shutdown off the event loop with its result logged; README documents `.backup` and the
versioning rule.
Verification: reviewer probed a copy of the real database (67 runs, 56 investigations,
2 177 site_health rows): identical row counts, `[1, 2]`, four indexes used by `EXPLAIN`,
`integrity_check` ok, second run a no-op; live: the real database migrated at boot.
Review: merge-after-fixes (3 should-fixes, 2 nits) — all landed.

### G1 — retrieval intelligence (modules) · PR #62 · 2026-09-06
`recon/retrieval.py`: one outcome vocabulary (`ok | absent | blocked | transport | policy |
ssrf`) and one `fetch()` facade — policy check (no DNS, no request), SSRF guard (a DNS failure
there is `transport`, not `ssrf`; skipped when the client is already guarded), per-host backoff
(no request while it runs), one capped streamed GET, `classify()` (404/410 absent; 401/403/429/5xx
and every non-decisive status blocked with the status; a 2xx with a challenge marker, consent
wall, `cf-mitigated` header or a login URL blocked; GitHub's 403 + `X-RateLimit-Remaining: 0`
and 403 + `Retry-After` are rate limits), a backoff from `Retry-After` on 429/503 (default 60 s,
clamped 5 s–1 h), an injected ladder at most once and only for `blocked`/`transport` — never a
rate limit — and `RetrievalStats`. Never raises. `recon/cache.py` TTLCache with no API for
caching a failure; `recon/sources.py` registry of the 17 sources we call directly with
in-process health; `recon/rows.py` accessors (`display_name` never the raw `<title>`, D7/V10)
used by graph, report, dossier, exposure, geo, connections.
Verification: 672 passed; reviewer's 36-row `classify` grid and the `fetch` order probes (policy
→ no DNS; private IP → `ssrf` with no request; backoff shares the key across `www.`/`:443`;
ladder once, never on 429/503).
Review: merge-after-fixes (1 blocker: monitor still emitted `account_gone` on a rate limit —
fixed by computing `checked` from the engine's HTTP status; 6 should-fixes) — all landed.

### H2 — OPSEC and third-party hygiene · PR #63 · 2026-09-06
`GET /api/avatar?u=` relays profile thumbnails so the analyst's browser never contacts the
subject's host: http(s) on ports 80/443 only, no credentials, policy-denied hosts refused, the
SSRF guard on every redirect hop (≤ 3), identity encoding (compressed body refused — a gzip bomb
inflated 71 KB → 257 MiB), a 2 MiB streamed cap, raster images only, a 10 s wall-clock deadline,
8 concurrent upstream streams, a bounded LRU cache, `nosniff` + a sandbox CSP on the response,
and the cross-site guard. CSP `img-src` is self + OpenStreetMap tiles; the God's Eye iframe is
sandboxed (no microphone); Inter and JetBrains Mono are self-hosted (OFL, sha256 recorded) so
a page view makes no Google Fonts request; README has a "Data sent to third parties" table.
`recon/policy`: a trailing-dot host (`instagram.com.`) no longer bypasses the deny list.
Verification: gate green; loopback/CGNAT/metadata/IPv4-mapped/octal/decimal literals all 403;
redirect hops to loopback 403; cross-site/`Origin: null` 403; 12 parallel requests → 8 upstream;
headless Chromium: 0 console errors, 0 third-party requests.
Review: merge-after-fixes (5 should-fixes: gzip bomb, total deadline, iframe sandbox, trailing-dot
bypass, ports/userinfo) — all landed.

### D3 — hash-pinned dependency locks · PR #64 · 2026-09-06
`requirements.lock` (101 pins, hash-pinned) and `requirements-ci.lock` (143 pins, hash-pinned)
generated by `pip-compile --generate-hashes`. `scripts/lockcheck.py` detects drift between
`requirements*.txt` and the locks. `run.sh` prefers `requirements.lock` with `--require-hashes`;
CI installs only from the lock with `--require-hashes`; `pip-audit` is now blocking (no
`continue-on-error`). Gate includes lockcheck.
Verification: macOS dry-run and CI ubuntu both pass hash verification; `pip-audit` 0 findings.

### Railway hotfix · PR #65 · 2026-09-06
The HTTP-hardening increment's Host allow-list defaulted to loopback. Railway probes
`/api/health` with `Host: healthcheck.railway.app`, which got 400 — every deploy from #54 to #64
was marked failed. Fix: `/api/health` is now exempt from the Host check; `_platform_hosts()` reads
`RAILWAY_PUBLIC_DOMAIN`/`RAILWAY_PRIVATE_DOMAIN` from the environment plus
`RAILWAY_HEALTHCHECK_HOST`. Deployment confirmed success.

### H3 — report thumbnails · PR #66 · 2026-09-06
Saved reports embed server-made PNG thumbnail `data:` URIs instead of linking remote avatar URLs
(V11). `recon/thumbnail.py`: `Image.open(formats=("PNG","JPEG","GIF","WEBP"))` (ICO bomb guard),
4 MP pixel cap, 56 px thumbnails. `_avatar_thumbnails()` fetches through the avatar cache and
concurrency gate with a 12 s budget. `_avatar_gate` uses per-loop `WeakKeyDictionary` (matches
the investigation semaphore). `recon_report` DB read and render moved to `asyncio.to_thread`.
`assert_public_url` now blocks non-standard ports and embedded credentials on every redirect hop.
Verification: gate green (823 tests); report HTML contains only `data:image/png;base64,` srcs,
no remote avatar URLs.
Review: merge-after-fixes (1 blocker: ICO bomb; 5 should-fixes: pixel cap, per-loop semaphore,
exception logging, async DB read, redirect port/userinfo) — all landed.

### G2 — retrieval wiring · PR #67 · 2026-09-06
Every outbound request in the recon pipeline now goes through `retrieval.fetch`: adapters,
detectors, whatsmyname, enrichment, domain pivot, email pivot, brokers, exposure, correlation,
timeline, dossier, and monitor. `recon/ladder.py`: `escalate_shell()` decides when to spend a
browser fetch on a JS-rendered page. Direct-source registry exposed at `/api/health/sources` as
additive `direct_sources`. `recon/rows.py` `all_account_rows()` replaces scattered summary
concatenation. Shared `conftest.py` fixtures: `public_dns` and `mock_client`.
Verification: gate green (887 tests); rebase conflict (H2/H3 appended test sections) resolved;
USER_AGENT import moved from adapters to sources.

### Gate script · PR #51 · 2026-09-06
`./scripts/gate.sh` runs ruff, lockcheck, `node --check` and the suite, failing fast; merges are
gated on it.

## Remaining risks
- **DNS rebinding**: the SSRF guard resolves before the request; httpx re-resolves at connect
  time. A determined attacker with DNS control could bypass the guard. Accepted for a public-data
  OSINT tool that only fetches well-known public sites.
- **Railway installs from `requirements.txt`**: Railway's Nixpack builder does not support
  `--require-hashes`. The lock is verified in CI; Railway's install path is documented but
  unverified at deploy time.
- **Stealth tier lifecycle**: the Patchright browser session can silently die, leaving tier-3
  fetches returning None. The session is rebuilt on failure, but a cascade of WAF blocks can
  exhaust the browser budget before the session restarts.
- **SQLite under concurrent writes**: WAL mode and the `_db_lock` serialize writes, but a heavily
  loaded deployment could see write contention. Postgres is supported but not deployed.

## Remaining technical debt
- `app.py` is ~2100 lines; the investigation pipeline, avatar proxy, and report rendering should
  be extracted into separate modules.
- The `not_recorded` list in run diagnostics (stealth-ladder attempts, WMN stealth retries,
  detector browser escalations, budget consumption, fetch status histogram) is still incomplete.
- The `recon/enrich.py` enrichment functions still carry their own HTTP clients in some paths
  rather than using the G2 `retrieval.fetch` facade for all requests.
- No rate-limit budget tracking at the investigation level — individual hosts back off, but the
  total rate-limit exposure across an investigation is not capped.

## Recommended next steps
- Extract the investigation pipeline from `app.py` into `recon/investigation.py`.
- Add the remaining `not_recorded` metrics to the run diagnostics.
- Deploy Postgres on Railway for multi-instance durability.
- Add a per-investigation rate-limit budget that pauses scanning when too many hosts are backing off.
- Implement investigation-level caching so re-running the same subject reuses recent results.
