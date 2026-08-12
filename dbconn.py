"""Database connection factory — SQLite (default) or Postgres.

The backend is chosen by the ``DATABASE_URL`` environment variable: a
``postgres://`` / ``postgresql://`` URL selects Postgres; anything else (unset)
selects SQLite with zero configuration for local development.

Railway's disk is ephemeral, so SQLite there loses every investigation,
watchlist and alert on each redeploy — Postgres is what makes casework survive.

All application SQL is written once in the SQLite idiom (``?`` placeholders,
``AUTOINCREMENT`` primary keys, ``INSERT`` + ``lastrowid``). This module hides
the two dialects behind a small surface so the call sites stay backend-agnostic:

* :data:`PK` — the primary-key column type for ``CREATE TABLE``.
* :func:`connect` — returns a connection whose ``.execute(sql, params)`` accepts
  ``?`` placeholders and whose ``with`` block commits on success.
* :func:`insert_returning_id` — ``INSERT`` a row and get its new id (``lastrowid``
  on SQLite, ``RETURNING id`` on Postgres).
"""

from __future__ import annotations

import os
import sqlite3
from typing import Any

DATABASE_URL = os.environ.get("DATABASE_URL") or ""
IS_POSTGRES = DATABASE_URL.startswith(("postgres://", "postgresql://"))

BUSY_TIMEOUT_MS = 5000

# Primary-key column type used in every CREATE TABLE.
PK = "BIGSERIAL PRIMARY KEY" if IS_POSTGRES else "INTEGER PRIMARY KEY AUTOINCREMENT"


def _translate(sql: str) -> str:
    """Rewrite SQLite ``?`` placeholders to Postgres ``%s``.

    The app's SQL contains no literal ``?`` or ``%`` outside placeholders, so a
    plain substitution is safe.
    """
    return sql.replace("?", "%s")


class _PgConnection:
    """Adapts a psycopg (v3) connection to the sqlite3 usage in this app:
    ``.execute()``/``.executemany()`` on the connection return a cursor and take
    ``?`` placeholders; the context manager commits on success, rolls back on
    error, and closes."""

    def __init__(self, conn):
        self._conn = conn

    def execute(self, sql: str, params: Any = ()):
        cur = self._conn.cursor()
        cur.execute(_translate(sql), params or None)
        return cur

    def executemany(self, sql: str, seq):
        cur = self._conn.cursor()
        cur.executemany(_translate(sql), seq)
        return cur

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            self._conn.commit()
        else:
            self._conn.rollback()
        self._conn.close()
        return False


def connect(sqlite_path: "str | os.PathLike | None" = None):
    """Open a connection to the configured backend.

    ``sqlite_path`` is used for SQLite and ignored for Postgres.
    """
    if IS_POSTGRES:
        import psycopg
        return _PgConnection(psycopg.connect(DATABASE_URL))

    conn = sqlite3.connect(sqlite_path, timeout=BUSY_TIMEOUT_MS / 1000)
    # WAL + a busy timeout let the background monitor and live scans write
    # concurrently without "database is locked".
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def insert_returning_id(conn, sql: str, params: Any = ()) -> int:
    """Run an ``INSERT`` and return the new row's id.

    SQLite reports it via ``lastrowid``; Postgres needs ``RETURNING id`` (every
    id column in this app's schema is named ``id``).
    """
    if IS_POSTGRES:
        return conn.execute(sql + " RETURNING id", params).fetchone()[0]
    return conn.execute(sql, params).lastrowid
