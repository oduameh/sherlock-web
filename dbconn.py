"""Shared SQLite connection factory.

Every connection in the app goes through :func:`connect`, which enables WAL
journaling and a busy timeout. Without this, the background watchlist monitor
(which writes alert rows on its own tick) and live scans / history saves open
independent connections and race each other into ``sqlite3.OperationalError:
database is locked`` on any busy deployment.

WAL mode is a persistent property of the database file (set once, it sticks);
the busy timeout and synchronous level are per-connection and are (cheaply)
re-applied on each connect.
"""

from __future__ import annotations

import os
import sqlite3

BUSY_TIMEOUT_MS = 5000


def connect(path: str | os.PathLike) -> sqlite3.Connection:
    """Open a SQLite connection tuned for concurrent readers/writers."""
    conn = sqlite3.connect(path, timeout=BUSY_TIMEOUT_MS / 1000)
    # WAL lets readers proceed while a writer holds the lock; the busy timeout
    # makes a blocked writer wait instead of failing immediately.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn
