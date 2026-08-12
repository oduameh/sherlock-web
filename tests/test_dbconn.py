import dbconn


def test_translate_placeholders():
    assert dbconn._translate("WHERE a = ? AND b = ?") == "WHERE a = %s AND b = %s"
    assert dbconn._translate("no placeholders here") == "no placeholders here"


def test_backend_constants_are_consistent():
    assert isinstance(dbconn.IS_POSTGRES, bool)
    if dbconn.IS_POSTGRES:
        assert dbconn.PK == "BIGSERIAL PRIMARY KEY"
    else:
        assert dbconn.PK == "INTEGER PRIMARY KEY AUTOINCREMENT"


def test_connect_and_insert_returning_id_sqlite(tmp_path):
    # Exercises the SQLite path of the abstraction end to end.
    db = tmp_path / "t.db"
    with dbconn.connect(db) as conn:
        conn.execute(f"CREATE TABLE t (id {dbconn.PK}, v TEXT)")
    with dbconn.connect(db) as conn:
        rid1 = dbconn.insert_returning_id(conn, "INSERT INTO t (v) VALUES (?)", ("a",))
        rid2 = dbconn.insert_returning_id(conn, "INSERT INTO t (v) VALUES (?)", ("b",))
    assert rid1 == 1 and rid2 == 2
    with dbconn.connect(db) as conn:
        rows = conn.execute("SELECT id, v FROM t ORDER BY id").fetchall()
    assert [tuple(r) for r in rows] == [(1, "a"), (2, "b")]
