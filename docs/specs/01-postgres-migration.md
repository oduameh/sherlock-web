# Spec 01 — Postgres migration

**Issue:** [#1 [Platform] Migrate persistence to Postgres](https://github.com/oduameh/sherlock-web/issues/1)
**Status:** proposed · **Priority:** P0 · **Blocks:** specs 02–05 (all add tables through Alembic)

## Problem statement

The app persists everything to `history.db`, a SQLite file on the local disk
(`app.py:66`, `DB_PATH = BASE_DIR / "history.db"`). On Railway the filesystem is
ephemeral: every redeploy wipes all investigations, watchlists, alerts, and run
history. Data must live in a managed Postgres instance instead, without breaking
the zero-config local-dev story.

## Goals

- `DATABASE_URL` env var selects the database; unset → `sqlite:///history.db`
  (current local behavior, byte-for-byte compatible).
- All existing tables represented in Alembic migrations; new tables from specs
  02–05 land as numbered follow-on revisions.
- `dbconn.py` becomes the single SQLAlchemy engine/connection factory; every
  raw `sqlite3` call site migrates to SQLAlchemy Core.
- One-shot, idempotent importer `scripts/migrate_sqlite_to_pg.py`.
- Railway Postgres add-on setup documented as a one-time ops step.

## Non-goals

- No ORM models / session-per-request refactor. We use SQLAlchemy 2.x **Core**
  (`Table`, `text()`, `Connection`) because the codebase is written in
  positional raw SQL and Core is the smallest honest translation layer.
- No read replicas, connection poolers, or PgBouncer (Railway's single Postgres
  is fine at current scale).
- No change to any endpoint behavior or response shape.

## Current state

- `dbconn.py` — the whole module is one function:
  `connect(path) -> sqlite3.Connection` which sets `PRAGMA journal_mode=WAL`,
  `PRAGMA busy_timeout=5000`, `PRAGMA synchronous=NORMAL` (`dbconn.py:22`).
- Schema is created at import time by `_init_db()` (`app.py:136-177`), which
  `CREATE TABLE IF NOT EXISTS` two tables and does two ad-hoc `ALTER TABLE`
  migrations (`kind`, `investigation_id` on `runs`), then delegates to
  `recon.monitor.init_tables(conn)` (`recon/monitor.py:42`) for two more.

### Existing tables (ground truth, from the code)

```sql
-- app.py:139  (_init_db)
CREATE TABLE runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,                -- time.strftime("%Y-%m-%d %H:%M:%S"), server-local
    username TEXT NOT NULL,          -- subject label; for recon/investigation runs it is a joined label
    found INTEGER NOT NULL,
    total INTEGER NOT NULL,
    results TEXT NOT NULL,           -- JSON
    kind TEXT NOT NULL DEFAULT 'sherlock',  -- 'sherlock' | 'recon' | 'investigation'  (app.py:154)
    investigation_id INTEGER         -- nullable backlink (app.py:159)
);

-- app.py:163
CREATE TABLE investigations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    inputs TEXT NOT NULL,            -- JSON: {name, usernames, email, phone, variants, timeout}
    summary TEXT,                    -- JSON, NULL until the run finishes
    status TEXT NOT NULL DEFAULT 'pending'  -- pending | running | done | failed
);

-- recon/monitor.py:43 (init_tables)
CREATE TABLE watchlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    label TEXT NOT NULL,
    inputs TEXT NOT NULL,            -- JSON
    interval_hours INTEGER NOT NULL, -- >= recon.monitor.MIN_INTERVAL_HOURS (6)
    last_run_at TEXT,
    last_signature TEXT,             -- JSON signature from compute_signature()
    enabled INTEGER NOT NULL DEFAULT 1
);

-- recon/monitor.py:58
CREATE TABLE watch_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    watch_id INTEGER NOT NULL,       -- soft FK to watchlist.id (no FK clause today; app deletes manually, app.py:1105)
    created_at TEXT NOT NULL,
    kind TEXT NOT NULL,              -- new_account | account_gone | new_holehe_hit | holehe_hit_gone
    message TEXT NOT NULL,
    data TEXT,                       -- JSON
    seen INTEGER NOT NULL DEFAULT 0
);
```

### Raw sqlite3 call-site inventory (must all migrate)

`app.py` (14 sites):
`_init_db` (137), `save_run` (183), `get_history` (202), `get_run` (216),
`recon_report` (780), `_get_investigation` (830), `_set_investigation` (846),
`create_investigation` (900), `rerun_investigation` (928),
`investigate_graph`/`investigate_report` (via `_get_investigation`),
`list_watchlist` (1037), `create_watch` (1077), `toggle_watch` (1091),
`delete_watch` (1103), `list_alerts` (1123), `mark_alerts_seen` (1139).

`recon/monitor.py` (3 functions, 6 statements):
`init_tables` (42), `_due_watches` (195), `run_watch` (223 stamp, 234 alerts+signature).

Known migration hazards in these sites:

- `cur.lastrowid` (`save_run`, `create_investigation`, `rerun_investigation`,
  `create_watch`) — Postgres has no `lastrowid`; use Core
  `insert(...).returning(table.c.id)` (works on SQLite too via SQLAlchemy).
- `?` paramstyle and f-string `IN (?,?,...)` (`mark_alerts_seen`,
  `app.py:1141`) — replace with SQLAlchemy `bindparam(expanding=True)` or Core
  `.in_()`.
- `PRAGMA` statements in `dbconn.connect` — SQLite-only; guard by dialect.
- Boolean-as-int columns (`enabled`, `seen`) — keep as `SMALLINT`/`INTEGER`
  for now to avoid touching response code (`bool(r[6])` in `list_watchlist`).
  A boolean cleanup is explicitly out of scope.
- Timestamps are naive local-time strings. See "Timestamps" below.

## Decision

**SQLAlchemy 2.x Core + Alembic.** `DATABASE_URL` env var; default
`sqlite:///history.db`. New dependencies (add to `requirements.txt`):

```
sqlalchemy>=2.0
alembic>=1.13
psycopg[binary]>=3.1   # Postgres driver; psycopg3, not psycopg2
```

## New `dbconn.py` contract

```python
# dbconn.py (rewritten)
DATABASE_URL = os.environ.get("DATABASE_URL") or f"sqlite:///{BASE_DIR / 'history.db'}"

def get_engine() -> sqlalchemy.Engine          # module-level singleton, lazy
def connect() -> ContextManager[Connection]     # engine.begin(); the ONLY way app code talks to the DB
def is_postgres() -> bool
def run_migrations() -> None                    # alembic upgrade head, programmatic
```

- `connect()` yields a `Connection` inside `engine.begin()` (auto-commit on
  exit, rollback on exception). It is a drop-in replacement for the current
  `with db_connect(DB_PATH) as conn:` pattern — call sites change the import
  and the argument list, not the control flow.
- Callers currently pass `DB_PATH`; after migration `connect()` takes **no
  arguments** — every call site drops the path parameter.
- For SQLite URLs the engine sets `check_same_thread=False` (scan threads call
  `save_run` from worker threads, `app.py:334`) and applies the three existing
  PRAGMAs via a `connect` event listener. WAL/busy-timeout behavior is
  preserved exactly.
- `run_migrations()` is called once at startup **only when the URL is SQLite**
  (keeps local dev zero-config). On Railway, migrations run as a deploy step
  (see Rollout).

## Alembic layout and revision plan

```
alembic.ini                 # script_location=alembic; env.py overrides sqlalchemy.url from DATABASE_URL
alembic/env.py              # reads DATABASE_URL via dbconn, target_metadata = dbconn.metadata
alembic/versions/
  0001_initial.py           # spec 01 — the four existing tables
  0002_users_sessions.py    # spec 02 — users, sessions, user_id columns + backfill
  0003_audit_log.py         # spec 03 — audit_log
  0004_billing.py           # spec 04 — user entitlement columns, usage_events
  0005_jobs.py              # spec 05 — jobs, job_events
```

`dbconn.py` owns a single `sqlalchemy.MetaData` with Core `Table` definitions
for every table (added spec by spec); Alembic autogenerate is **not** used —
revisions are handwritten to match the tables exactly, because the existing
schema is small and the `ALTER TABLE` history must collapse into one clean
initial revision.

Revision `0001_initial` DDL (Postgres dialect shown; Alembic ops are
dialect-agnostic, `sa.Text()`, `sa.Integer()` etc.):

```sql
CREATE TABLE investigations (
    id SERIAL PRIMARY KEY,
    created_at TEXT NOT NULL,
    inputs TEXT NOT NULL,
    summary TEXT,
    status TEXT NOT NULL DEFAULT 'pending'
);
CREATE TABLE runs (
    id SERIAL PRIMARY KEY,
    ts TEXT NOT NULL,
    username TEXT NOT NULL,
    found INTEGER NOT NULL,
    total INTEGER NOT NULL,
    results TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'sherlock',
    investigation_id INTEGER REFERENCES investigations(id)
);
CREATE TABLE watchlist (
    id SERIAL PRIMARY KEY,
    created_at TEXT NOT NULL,
    label TEXT NOT NULL,
    inputs TEXT NOT NULL,
    interval_hours INTEGER NOT NULL,
    last_run_at TEXT,
    last_signature TEXT,
    enabled INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE watch_alerts (
    id SERIAL PRIMARY KEY,
    watch_id INTEGER NOT NULL REFERENCES watchlist(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    kind TEXT NOT NULL,
    message TEXT NOT NULL,
    data TEXT,
    seen INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_runs_investigation ON runs(investigation_id);
CREATE INDEX idx_watch_alerts_watch ON watch_alerts(watch_id);
CREATE INDEX idx_watch_alerts_seen ON watch_alerts(seen);
```

Notes:

- The initial revision *adds* the `watch_alerts.watch_id` FK and the two
  obvious indexes that the raw schema lacks. This is safe because on a fresh
  SQLite dev DB the same DDL applies, and the importer (below) inserts in FK
  order. `delete_watch` (`app.py:1102`) may then drop its manual
  `DELETE FROM watch_alerts` — optional cleanup, behavior identical.
- Timestamps stay `TEXT` in this migration (see below).

### Timestamps

All existing rows store `time.strftime("%Y-%m-%d %H:%M:%S")` (server-local; on
Railway containers this is effectively UTC). Decision: **keep TEXT timestamps
in revision 0001** to make the SQLite↔Postgres byte comparison trivial, and
switch writers to UTC ISO-8601 (`datetime.now(timezone.utc).isoformat()`)
behind the same helper `_now()` used everywhere today
(`recon/monitor.py:190`, `app.py:188`). A later (non-P0) revision may convert
to `TIMESTAMPTZ`. `_due_watches` parses with `time.strptime(...)`
(`recon/monitor.py:206`) — it must learn `datetime.fromisoformat` and treat
naive values as UTC. Both formats must parse during the transition window.

## `scripts/migrate_sqlite_to_pg.py`

One-shot importer: existing `history.db` → the Postgres at `DATABASE_URL`.

```
python scripts/migrate_sqlite_to_pg.py [--sqlite history.db] [--dry-run]
```

- Requires `DATABASE_URL` to point at Postgres; refuses to run against SQLite.
- Runs `alembic upgrade head` first (or asserts `alembic_version == head`).
- Insert order respects FKs: `investigations` → `runs` → `watchlist` →
  `watch_alerts`.
- Idempotent: every batch is `INSERT ... ON CONFLICT (id) DO NOTHING` (Core
  `postgresql.insert(...).on_conflict_do_nothing()`), so re-running after a
  partial failure is safe. Explicit `id` values are inserted to preserve all
  cross-references (`runs.investigation_id`, `watch_alerts.watch_id`,
  `investigation_id` in URLs).
- After each table, `SELECT setval(pg_get_serial_sequence('<t>','id'),
  COALESCE(MAX(id),1))` so future inserts don't collide.
- Prints a per-table `{inserted, skipped}` summary; exits non-zero on any
  error. `--dry-run` counts rows only.
- Verification: row counts per table printed at the end and compared against
  the source; the operator eyeballs them before cutover.

## Error behavior

- `DATABASE_URL` set but unreachable at startup: `run_migrations()` raises,
  the app fails fast on boot (Railway marks the deploy unhealthy and keeps the
  old release). We deliberately do **not** fall back to SQLite silently — that
  would recreate the data-loss bug.
- Importer on missing/locked SQLite file: clear error, exit 2.

## Rollout plan

1. Merge the refactor. With `DATABASE_URL` unset the app is byte-identical in
   behavior (SQLite, WAL, same tables, same endpoints). Zero risk deploy.
2. One-time Railway setup (document in README):
   - Railway project → **New → Database → PostgreSQL**.
   - In the sherlock-web service → **Variables** → add
     `DATABASE_URL` = `${{Postgres.DATABASE_URL}}` (Railway variable reference;
     the add-on injects host/user/password).
   - Add a pre-deploy command so migrations run before the new release starts:
     `railway.json` → `deploy.preDeployCommand: "alembic upgrade head"`.
3. Run the importer once (Railway shell or locally with `DATABASE_URL` pointed
   at the Railway proxy): `python scripts/migrate_sqlite_to_pg.py`.
4. Redeploy. Verify `/api/history`, `/api/watchlist`, `/api/alerts` show old
   data; redeploy again and confirm persistence (issue acceptance criterion).
5. Local dev: nothing to do — `run.sh` still boots against `history.db`.

## Testing plan

- **pytest stays on SQLite.** `conftest.py` already puts the repo root on
  `sys.path`; add a fixture that points `DATABASE_URL` at a `tmp_path` SQLite
  file before importing `app`. The whole existing `tests/` suite must pass
  unchanged (it only imports `recon.*` pure functions today, so this is cheap).
- New unit tests: `tests/test_dbconn.py` — `connect()` round-trip on SQLite;
  migration head creates all four tables; `_now()`/`fromisoformat` round-trip
  for both timestamp formats.
- **Local Postgres testing:** add `docker-compose.yml` with a `postgres:16`
  service (port 5432, `POSTGRES_PASSWORD=postgres`). Documented command:
  `DATABASE_URL=postgresql+psycopg://postgres:postgres@localhost:5432/sherlock pytest tests/test_dbconn.py`.
- Importer test: build a fixture SQLite DB with rows in all four tables, run
  the importer against the compose Postgres twice, assert identical counts and
  no error on the second run (idempotency).
- Optional CI matrix (not required for this issue): a GitHub Actions job with a
  `postgres:16` service container running `pytest -m postgres`. Deferred to
  spec 06's follow-ups; flagged here so nobody thinks it was forgotten.

## Open questions

- Do we want `TIMESTAMPTZ` + real booleans in a fast-follow migration once
  cutover is proven? (Recommended yes, not P0.)
- Should `preDeployCommand` also run a `pg_dump`-to-S3 backup step before
  `alembic upgrade head` once we have real customer data? (Ops decision.)
- Multi-instance Railway replicas: WAL-era assumptions (one writer process)
  currently hold; horizontal scaling needs the job queue's `SKIP LOCKED`
  claiming (spec 05) before we ever set `replicas > 1`.
