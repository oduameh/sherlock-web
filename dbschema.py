"""Versioned schema migrations for history.db (SQLite) and Postgres.

Before this module the schema evolved by ad-hoc, SQLite-only ``ALTER TABLE``
guards at import time; Postgres deployments were assumed fresh and had no
upgrade path, and nothing recorded which shape a database was in
(``docs/audit/2026-09-06/ops-observability.md`` §3).

Every migration is idempotent and runs inside the caller's connection; the
current version is kept in a ``schema_version`` table on both backends (and
mirrored into ``PRAGMA user_version`` on SQLite for tools that read it).
Add a migration by appending to :data:`MIGRATIONS`; never edit an old one.
"""

from __future__ import annotations

import logging
from typing import Callable

import dbconn

logger = logging.getLogger("dbschema")


def _ensure_column(conn, table: str, column: str, decl: str) -> None:
    """Add ``column`` to ``table`` if missing, on SQLite (PRAGMA) and Postgres
    (ADD COLUMN IF NOT EXISTS). Idempotent."""
    if dbconn.IS_POSTGRES:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {decl}")
        return
    cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]
    if column not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")


def _m1_baseline(conn) -> None:
    """The tables as they existed on 2026-09-06, including the columns that
    older SQLite files gained through inline ALTERs (kind, investigation_id,
    started_at, finished_at, error)."""
    conn.execute(f"""
        CREATE TABLE IF NOT EXISTS runs (
            id {dbconn.PK},
            ts TEXT NOT NULL,
            username TEXT NOT NULL,
            found INTEGER NOT NULL,
            total INTEGER NOT NULL,
            results TEXT NOT NULL,
            kind TEXT NOT NULL DEFAULT 'sherlock',
            investigation_id INTEGER
        )""")
    _ensure_column(conn, "runs", "kind", "TEXT NOT NULL DEFAULT 'sherlock'")
    _ensure_column(conn, "runs", "investigation_id", "INTEGER")
    conn.execute(f"""
        CREATE TABLE IF NOT EXISTS investigations (
            id {dbconn.PK},
            created_at TEXT NOT NULL,
            inputs TEXT NOT NULL,
            summary TEXT,
            status TEXT NOT NULL DEFAULT 'pending',
            started_at TEXT,
            finished_at TEXT,
            error TEXT
        )""")
    for col in ("started_at", "finished_at", "error"):
        _ensure_column(conn, "investigations", col, "TEXT")


def _m2_indexes(conn) -> None:
    """Indexes for the queries the app actually runs: history rows by
    investigation (cascade delete, timeline), investigations by status
    (health, sweep, baseline lookup), alerts by watch."""
    conn.execute("CREATE INDEX IF NOT EXISTS idx_runs_investigation ON runs (investigation_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_runs_kind_id ON runs (kind, id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_investigations_status ON investigations (status)")
    # watch_alerts belongs to recon.monitor.init_tables, which creates its own
    # index on every boot; a versioned migration cannot, because a boot
    # without the recon package would record the version and never retry.


# (version, description, function). Append only.
MIGRATIONS: list[tuple[int, str, Callable]] = [
    (1, "baseline tables and legacy columns", _m1_baseline),
    (2, "indexes for history/status/alerts lookups", _m2_indexes),
]
SCHEMA_VERSION = MIGRATIONS[-1][0]


def current_version(conn) -> int:
    conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY)")
    row = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
    return int(row[0]) if row and row[0] is not None else 0


def migrate(conn, *, extra_tables: Callable | None = None) -> int:
    """Bring the database to :data:`SCHEMA_VERSION`. ``extra_tables`` (the
    monitor/router table creators) runs before the index migration so their
    tables can be indexed. Returns the resulting version."""
    have = current_version(conn)
    for version, desc, fn in MIGRATIONS:
        if version <= have:
            continue
        fn(conn)
        conn.execute("INSERT INTO schema_version (version) VALUES (?)", (version,))   # PK: no duplicates
        logger.info("schema migrated to v%d: %s", version, desc)
        have = version
    if extra_tables is not None:      # monitor/router tables: idempotent, every boot
        extra_tables(conn)
    if not dbconn.IS_POSTGRES:
        conn.execute(f"PRAGMA user_version = {int(have)}")
    return have
