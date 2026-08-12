#!/usr/bin/env python3
"""One-shot import of an existing SQLite ``history.db`` into Postgres.

Usage:
    DATABASE_URL=postgres://user:pass@host/db ./venv/bin/python migrate_to_postgres.py [sqlite_path]

Creates the Postgres schema (by importing ``app``), copies every row from the
SQLite database preserving ids, and resets the id sequences so new inserts don't
collide. Safe to run against a fresh Postgres; existing rows are skipped
(``ON CONFLICT DO NOTHING``).
"""

from __future__ import annotations

import os
import sqlite3
import sys

import dbconn

# table -> ordered columns. `site_health.window` is a Postgres keyword, so it is
# quoted on the Postgres side.
TABLES = {
    "runs": ["id", "ts", "username", "found", "total", "results", "kind",
             "investigation_id"],
    "investigations": ["id", "created_at", "inputs", "summary", "status"],
    "watchlist": ["id", "created_at", "label", "inputs", "interval_hours",
                  "last_run_at", "last_signature", "enabled"],
    "watch_alerts": ["id", "watch_id", "created_at", "kind", "message", "data",
                     "seen"],
    "site_health": ["site", "engine", "window", "ewma_latency_ms",
                    "consecutive_failures", "circuit_open_until",
                    "cooldown_seconds", "updated_at"],
    "proxy_health": ["proxy", "uses", "failures", "banned_until", "updated_at"],
}
SERIAL_TABLES = ["runs", "investigations", "watchlist", "watch_alerts"]


def _pg_col(c: str) -> str:
    return '"window"' if c == "window" else c


def main() -> int:
    if not dbconn.IS_POSTGRES:
        print("Set DATABASE_URL to a postgres:// URL first.", file=sys.stderr)
        return 2
    src_path = sys.argv[1] if len(sys.argv) > 1 else "history.db"
    if not os.path.exists(src_path):
        print(f"{src_path} not found.", file=sys.stderr)
        return 2

    import app  # noqa: F401 — importing runs _init_db(), creating the PG schema

    src = sqlite3.connect(src_path)
    src.row_factory = sqlite3.Row
    total = 0
    with dbconn.connect() as pg:
        for table, cols in TABLES.items():
            try:
                rows = src.execute(f"SELECT {', '.join(cols)} FROM {table}").fetchall()
            except sqlite3.OperationalError:
                print(f"{table}: (not in source, skipped)")
                continue
            pg_cols = ", ".join(_pg_col(c) for c in cols)
            placeholders = ", ".join("?" for _ in cols)
            for r in rows:
                pg.execute(
                    f"INSERT INTO {table} ({pg_cols}) VALUES ({placeholders})"
                    " ON CONFLICT DO NOTHING",
                    tuple(r[c] for c in cols),
                )
            print(f"{table}: {len(rows)} rows")
            total += len(rows)
        for table in SERIAL_TABLES:
            pg.execute(
                f"SELECT setval(pg_get_serial_sequence('{table}', 'id'),"
                f" COALESCE((SELECT MAX(id) FROM {table}), 1))"
            )
    src.close()
    print(f"done — {total} rows imported")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
