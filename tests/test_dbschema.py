"""Versioned migrations: fresh databases, legacy upgrades, idempotency."""

import sqlite3

import dbschema
from dbconn import connect as db_connect


def _indexes(conn, table):
    return {r[1] for r in conn.execute(f"PRAGMA index_list({table})")}


def test_fresh_database_reaches_current_version_with_indexes(tmp_path):
    path = tmp_path / "fresh.db"
    with db_connect(path) as conn:
        assert dbschema.migrate(conn) == dbschema.SCHEMA_VERSION
        assert dbschema.current_version(conn) == dbschema.SCHEMA_VERSION
        assert conn.execute("PRAGMA user_version").fetchone()[0] == dbschema.SCHEMA_VERSION
        assert "idx_runs_investigation" in _indexes(conn, "runs")
        assert "idx_investigations_status" in _indexes(conn, "investigations")
        cols = {r[1] for r in conn.execute("PRAGMA table_info(investigations)")}
        assert {"started_at", "finished_at", "error"} <= cols


def test_legacy_database_is_upgraded_in_place(tmp_path):
    """A history.db from before the lifecycle columns and before any version
    tracking must upgrade without losing rows."""
    path = tmp_path / "legacy.db"
    raw = sqlite3.connect(path)
    raw.execute("CREATE TABLE runs (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,"
                " username TEXT NOT NULL, found INTEGER NOT NULL, total INTEGER NOT NULL,"
                " results TEXT NOT NULL)")
    raw.execute("CREATE TABLE investigations (id INTEGER PRIMARY KEY AUTOINCREMENT,"
                " created_at TEXT NOT NULL, inputs TEXT NOT NULL, summary TEXT,"
                " status TEXT NOT NULL DEFAULT 'pending')")
    raw.execute("INSERT INTO runs (ts, username, found, total, results) VALUES ('t','u',1,2,'[]')")
    raw.commit(); raw.close()
    with db_connect(path) as conn:
        assert dbschema.current_version(conn) == 0
        assert dbschema.migrate(conn) == dbschema.SCHEMA_VERSION
        cols = {r[1] for r in conn.execute("PRAGMA table_info(runs)")}
        assert {"kind", "investigation_id"} <= cols
        assert conn.execute("SELECT kind FROM runs").fetchone()[0] == "sherlock"
        assert "idx_runs_investigation" in _indexes(conn, "runs")


def test_migrate_is_idempotent(tmp_path):
    path = tmp_path / "twice.db"
    with db_connect(path) as conn:
        dbschema.migrate(conn)
        dbschema.migrate(conn)
        rows = conn.execute("SELECT version FROM schema_version ORDER BY version").fetchall()
    assert [r[0] for r in rows] == [m[0] for m in dbschema.MIGRATIONS]


def test_migrations_are_append_only_and_monotonic():
    versions = [m[0] for m in dbschema.MIGRATIONS]
    assert versions == sorted(versions) and len(set(versions)) == len(versions)
    assert versions[0] == 1 and versions[-1] == dbschema.SCHEMA_VERSION
