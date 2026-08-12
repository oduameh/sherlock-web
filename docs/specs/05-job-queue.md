# Spec 05 — Postgres-backed job queue; decouple investigations from SSE

**Issue:** [#5 [Infra] Background job queue: decouple investigations from SSE](https://github.com/oduameh/sherlock-web/issues/5)
**Status:** proposed · **Priority:** P0 · **Depends on:** spec 01 (engine/`SKIP LOCKED`), spec 02 (`users`, owner ids), spec 04 (per-plan concurrency caps)

## Problem statement

Investigation execution happens **inside the SSE request handler**:
`GET /api/investigate/{id}/stream` (`app.py:938`) creates the coordinator task
that calls `run_pipeline` (`app.py:964`), and `GET /api/recon/stream`
(`app.py:482`) does the same for deep recon. If the client disconnects, the
`asyncio.CancelledError` path cancels the coordinator (`app.py:1003-1005`) and
the work is lost mid-run. There is no retry, no concurrency control (20
browser tabs = 20 concurrent full scans in one process), and no restart
survival. The watchlist monitor is a separate ad-hoc `asyncio.sleep` loop
(`recon/monitor.py:253`) with the same restart-fragility (mitigated only by
its `last_run_at` stamp).

## Goals

- DB-backed job table; in-process asyncio worker tasks; **no Redis**.
- `POST /api/investigate` enqueues and returns immediately; the SSE stream
  becomes a *tailer* of job progress with disconnect/reconnect replay.
- Jobs survive client disconnect and process restart.
- Global + per-user/per-plan concurrency caps.
- The watchlist monitor becomes scheduled jobs instead of its own loop.
- Graceful drain on SIGTERM (Railway redeploys).

## Non-goals

- No multi-process/multi-replica worker fleet (the claim protocol is written
  to be safe for it later, but v1 ships one process).
- No priority queues beyond a simple `priority` column (FIFO within priority).
- No changes to the classic `/api/search/stream` (`app.py:354`) or
  `/api/recon/stream` (`app.py:482`) endpoints — they stay live-only SSE as
  today. Only the **investigations** pipeline moves to the queue (it's the
  long-running, persistable one). Recon-stream migration is a follow-up.
- No cron-expression scheduling; watch intervals stay integer hours.

## Current state (what we're replacing)

- `POST /api/investigate` (`app.py:860`) only inserts a row
  (`status='pending'`) and returns `{"investigation_id": id}` — execution is
  deferred to the GET stream, which sets `status='running'` (`app.py:949`),
  runs `run_pipeline(...)` with an `emit(event, payload)` callback feeding an
  `asyncio.Queue` (`app.py:959-985`), persists via `save_run(...,
  kind='investigation', investigation_id=...)` (`app.py:975`), and emits
  terminal events.
- SSE event vocabulary of the investigation stream (must be preserved
  byte-for-byte for the existing frontend): `meta_run` (first event,
  `{investigation_id}`), then pipeline events from `recon/pipeline.py`:
  `meta`, `candidates`, `phone_intel`, `engine_start`, `engine_done`,
  `engine_error`, `found`, `merged`, `error`, `progress`, `variants_planned`,
  `phase`, `enriched`, `correlation`, `email`, `email_done`, `done`, then
  `saved` (`{history_id, investigation_id}`, `app.py:978`) or `fatal`
  (`{message}`). Keepalives are `: keepalive` comment lines every 15s.
- Watchlist scheduling: `monitor_loop` (`recon/monitor.py:253`) wakes every
  `TICK_SECONDS=60`, runs up to `MAX_WATCHES_PER_TICK=5` due watches inline.
  Due-ness is computed from `last_run_at + interval_hours` in `_due_watches`
  (`recon/monitor.py:194`). Started from the app lifespan (`app.py:76-78`).
- Shutdown today: lifespan cancels the monitor task; in-flight investigations
  die with the process.

## Decision

**Postgres-backed queue, in-process asyncio workers.** Rationale: Railway
Postgres already exists after spec 01; a broker (Redis) would add a paid
service and a second failure domain for a workload of tens of jobs/day. The
queue semantics needed (claim, retry, delay) are a well-understood
`SELECT ... FOR UPDATE SKIP LOCKED` pattern.

### Schema (Alembic revision `0005_jobs`)

```sql
CREATE TABLE jobs (
    id SERIAL PRIMARY KEY,
    type TEXT NOT NULL,                  -- 'investigation' | 'watch_scan'
    payload_json TEXT NOT NULL,          -- investigation: {investigation_id}
                                         -- watch_scan:    {watch_id}
    status TEXT NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued','running','done','failed')),
    priority INTEGER NOT NULL DEFAULT 0, -- higher first; watch_scan = -10
    run_after TEXT NOT NULL,             -- UTC ISO-8601; claimable when <= now
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    error TEXT,
    owner_user_id INTEGER REFERENCES users(id),  -- NULL in legacy mode
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT
);
-- Partial index: the claim query's hot path.
CREATE INDEX idx_jobs_claim ON jobs(priority DESC, id)
    WHERE status = 'queued';
CREATE INDEX idx_jobs_owner_running ON jobs(owner_user_id)
    WHERE status = 'running';

CREATE TABLE job_events (
    id SERIAL PRIMARY KEY,
    job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    investigation_id INTEGER,            -- denormalized for stream lookup
    seq INTEGER NOT NULL,                -- per-investigation monotonic, from 1
    ts TEXT NOT NULL,
    event TEXT NOT NULL,                 -- 'found', 'progress', ... (existing vocabulary)
    payload_json TEXT NOT NULL,
    UNIQUE (investigation_id, seq)
);
CREATE INDEX idx_job_events_stream ON job_events(investigation_id, seq);
```

## Enqueue path

`POST /api/investigate` (`app.py:860`) changes from "insert investigation,
return" to:

1. Validate inputs (unchanged) + spec-04 quota check (unchanged).
2. Insert `investigations(status='queued')` — **new status value**; the
   current set is `pending|running|done|failed` (`app.py:169`,
   `app.py:949/970/981`). `pending` is kept for rows created before this
   spec; `queued` means a live job exists.
3. Insert `jobs(type='investigation',
   payload_json={"investigation_id": id, "inputs": inputs, "nsfw": false},
   owner_user_id=current_user.id)`.
4. Response becomes `{"investigation_id": 17, "job_id": 55}` — additive
   change, old clients still work (they ignore `job_id` and open the stream).

`POST /api/investigate/{id}/rerun` (`app.py:916`) does the same for its clone.

The pipeline inputs are snapshotted into `payload_json` at enqueue time so
editing races can't change what runs.

## Worker pool

New module `jobs.py`, started from the app lifespan (replacing the direct
`monitor_loop` start at `app.py:76-78`):

- `N_WORKERS = 4` asyncio tasks (`worker(i)`), each looping: claim → run →
  finalize.
- **Claim (Postgres):**

```sql
UPDATE jobs SET status='running', started_at=:now, attempts=attempts+1
WHERE id = (
    SELECT id FROM jobs
    WHERE status='queued' AND run_after <= :now
    ORDER BY priority DESC, id
    FOR UPDATE SKIP LOCKED
    LIMIT 1
)
RETURNING *;
```

- **Claim (SQLite dev fallback):** SQLite has no `SKIP LOCKED`; with a single
  in-process worker pool the race is internal, so: open `BEGIN IMMEDIATE`
  (SQLAlchemy: `connection.execution_options(isolation_level="IMMEDIATE")` —
  this replaces the spec-01 WAL busy-timeout dance for the claim), `SELECT`
  the next claimable id, `UPDATE` it, commit. Two claims in the same process
  serialize on the write lock; correctness over parallelism (SQLite is dev
  only).
- **Per-user cap** is enforced *at claim time*: after picking a candidate
  investigation job, count its owner's running investigation jobs; if
  `>= plan_limits(owner).concurrent_jobs` (spec 04: solo 1, team 3, free 1,
  self-host unlimited-ish 4), defer the job (`run_after = now + 30s`) instead
  of running it, and pick again. The global cap is simply `N_WORKERS`.
- **Handlers:**
  - `investigation`: reconstruct the `emit` callback to (a) append to
    `job_events` (seq = `COUNT(*)+1` for that investigation, inside the same
    transaction as liveness updates), and (b) publish to the in-memory bus
    (below). Set investigation `running` at start, `done`+summary and
    `save_run(..., kind='investigation', investigation_id=...)` on success —
    exactly the persistence logic currently inline at `app.py:949-979`, moved
    into the worker. Writes the spec-03 `investigate.execute` audit row at
    claim time.
  - `watch_scan`: call the existing `recon.monitor.run_watch(db, watch,
    sher_light)` logic refactored to take a `watch_id` and re-read the row
    (today it receives a dict from `_due_watches`). `light_scan`,
    `compute_signature`, `diff_signatures` are reused unchanged.

## Scheduler: monitor loop becomes an enqueuer

`recon/monitor.py:monitor_loop` is replaced by a light scheduler task (kept in
`jobs.py`, still every `TICK_SECONDS=60`):

```python
due = _due_watches(conn)  # unchanged query/logic
for w in due:
    enqueue_if_absent(type='watch_scan',
                      payload={'watch_id': w['id']},
                      priority=-10,
                      owner_user_id=w['user_id'])
```

`enqueue_if_absent` = `INSERT ... WHERE NOT EXISTS (SELECT 1 FROM jobs WHERE
type='watch_scan' AND payload_json->>'watch_id' = :wid AND status IN
('queued','running'))` (SQLite: compare `payload_json` text, payloads are
canonical). This preserves today's dedupe-by-`last_run_at` behavior —
`run_watch` still stamps `last_run_at` up front (`recon/monitor.py:224`) —
while gaining retries and concurrency control. `MAX_WATCHES_PER_TICK=5`
becomes "enqueue at most 5 per tick"; actual parallelism comes from free
workers and the per-user cap.

## SSE tailing + resume protocol

`GET /api/investigate/{id}/stream` (`app.py:938`) no longer executes anything.
Ownership checks unchanged (spec 02). Protocol:

1. Immediately yield the existing `event: meta_run` with
   `{investigation_id, status, job_id}` (added fields are additive).
2. **Replay:** read `Last-Event-ID` header (SSE standard; browsers send it
   automatically on `EventSource` reconnect). Default 0. Yield every
   `job_events` row for this investigation with `seq > last_event_id`, in
   order, as:

```
id: <seq>
event: <event>
data: <payload_json>

```

3. **Live tail:** subscribe an `asyncio.Queue` to the in-memory bus
   (`_BUSES: dict[int, set[asyncio.Queue]]` keyed by investigation id,
   module-level in `jobs.py`). Forward events as they arrive, same `id:`
   framing. On each forwarded batch, re-check `jobs.status`; terminal states
   end the stream after the final stored event (`saved` or `fatal`, the
   existing terminal vocabulary) is delivered.
4. **Queued state:** if the job hasn't started, the client receives (new,
   additive) `event: queued` with `{position: n}` every 15s in place of a
   bare keepalive comment; keepalive comments stay for running jobs.
5. A job with no attached clients runs to completion regardless — that is the
   entire point. A reconnecting client replays from `job_events` and sees a
   finished investigation instantly. `job_events` rows are deleted when the
   investigation is deleted (no investigation-delete endpoint exists yet;
   retention: rows for terminal jobs older than 30 days are swept by a daily
   reaper pass — same sweep that reaps stuck jobs, below).
6. Race between replay and subscribe: subscribe **first**, then replay with
   `seq > last_event_id`, then drain the queue skipping `seq <= last replayed
   seq` (queue events carry their seq). Duplicates are impossible; gaps are
   impossible because the worker appends to `job_events` before publishing.

## Retry, failure, reaping

- Handler raises → `attempts < max_attempts`: status back to `queued`,
  `run_after = now + 30s * 2^(attempts-1)` (30s, 60s, 120s), `error` recorded.
  Otherwise: `status='failed'`, `finished_at`, and for investigation jobs the
  investigation is set `failed` with the reason stored into
  `investigations.summary = {"error": "..."}` so `GET /api/investigate/{id}`
  shows why (frontend already renders `status`).
- Transient vs permanent: exceptions are all treated as transient in v1
  except `ValueError`/`ValidationError` from payload decoding (permanent
  immediately). Network flakiness inside sherlock/maigret is already absorbed
  per-site by the engines; what reaches the handler is a real crash.
- **Stuck-job reaper:** every scheduler tick, `UPDATE jobs SET
  status='failed', error='reaped: running > 30min', finished_at=now WHERE
  status='running' AND started_at < now - 30 minutes`. Investigation rows
  orphaned by a reaped job are set `failed` with the same reason. This is the
  restart-recovery path: a job `running` when the process dies is reaped
  within ~30min of the next boot. (Improvement path: lease heartbeats;
  documented, not built.)
- **Restart semantics (issue acceptance criterion):** on boot, `queued` jobs
  resume automatically; a job that was `running` at crash is reaped to
  `failed` with reason `reaped` — we deliberately do not auto-resume
  half-finished scans because the pipeline is not checkpointed. The user
  clicks rerun (`POST /rerun` exists for exactly this, `app.py:916`).

## Graceful shutdown (SIGTERM)

Railway sends SIGTERM on redeploy, then SIGKILL after a grace period (~30s
default; we target 25s). The lifespan shutdown sequence:

1. Stop the scheduler tick and stop workers from claiming (module-level
   `_draining` flag; claim loop checks it first).
2. Wait up to 25s for running jobs to finish
   (`asyncio.wait(gather(*worker_tasks), timeout=25)`).
3. Survivors: `UPDATE jobs SET status='queued', started_at=NULL WHERE
   status='running' AND id IN (...)` (requeue; `attempts` is **not**
   incremented for drains — the job didn't fail) and set their investigations
   back to `queued`.
4. uvicorn exits. New release boots, claims the requeued jobs. Net effect of a
   mid-job redeploy: that job restarts from scratch once — acceptable at this
   pipeline length, and infinitely better than silent data loss.

## Error behavior

- Enqueue when DB down → 500 (unchanged from today's insert failure mode).
- Stream for a `failed` job → replays stored events then
  `event: fatal` `{message}` (same payload shape as today's crash path,
  `app.py:982`).
- Stream for unknown/foreign id → existing `event: fatal` "investigation not
  found" (`app.py:944`), unchanged.
- Job payload undecodable → permanent failure as above; never crashes the
  worker loop (handler exceptions are caught per job).

## Migration / rollout plan

1. Revision `0005_jobs` + `jobs.py` + stream rewrite land together; the
   `monitor_loop` lifespan start (`app.py:76-78`) is replaced by
   `start_workers()` + scheduler in the same PR (keeping both would double-run
   watches).
2. Deploy is safe with in-flight work: any investigation `running` under the
   old code dies with the old release (same as today); new rows all queue.
3. Verify on staging: kill browser mid-run → job completes → reopen stream →
   full replay; redeploy mid-run → job requeued and completes on the new
   release; 20-way load test.

## Testing plan

- `tests/test_jobs.py` (SQLite fallback path):
  - claim is FIFO within priority, honors `run_after`, and double-claim is
    impossible (two concurrent claims → distinct jobs);
  - investigation job end-to-end with a **stubbed `run_pipeline`** (monkeypatch
    `jobs.run_pipeline` to emit 3 events + summary): investigation goes
    `queued→running→done`, `runs` row written with `kind='investigation'`,
    `job_events` has seq 1..3;
  - retry: handler raising once → job requeued with backoff, `attempts=1`;
    raising always → `failed` after `max_attempts`, investigation `failed`
    with reason;
  - reaper: artificially aged `started_at` → failed with `reaped`;
  - per-user cap: owner at cap → job deferred, not run;
  - drain: set `_draining`, assert no new claims.
- `tests/test_stream_replay.py`: seed `job_events`, attach stream with and
  without `Last-Event-ID`, assert replay framing (`id:` lines) and that no
  seq is delivered twice across a reconnect.
- Watch scheduler: due watch → exactly one `watch_scan` job enqueued across
  two ticks (dedupe), disabled watch → none.
- **Load test** `scripts/load_test.py` (issue acceptance criterion): fires 20
  concurrent `POST /api/investigate` + stream attach against a target URL,
  asserts all complete (status `done`/`failed`, never 5xx) and wall time.
  Uses `httpx.AsyncClient`; marked `@pytest.mark.network` so spec-06 CI
  deselects it; meant for manual runs against staging:
  `python scripts/load_test.py --base https://staging... --cookie ...`.
- Existing `tests/test_monitor.py` keeps passing: it tests
  `compute_signature`/`diff_signatures` only, which are untouched.

## Open questions

- Lease-based liveness (worker heartbeats + `LOCKED ... SKIP` re-claim after
  lease expiry) instead of the 30-min reaper? More machinery; revisit if
  reaped-then-rerun duplicates become a real annoyance.
- Should watch_scan jobs count against the per-user concurrency cap? v1: no
  (they're short light scans), documented so a future change is a conscious
  one.
- Priority inversion: user-facing investigation (priority 0) always beats
  watch scans (-10) — do we need an "urgent" +10 tier for a "run now" button?
  Trivial later; not in v1.
- Job payload size: `inputs` snapshots are small JSON; if recon-stream ever
  moves onto the queue, payload shape needs a second type — noted for that
  follow-up spec.
