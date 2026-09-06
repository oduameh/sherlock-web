"""HTTP-layer tests for the investigation lifecycle.

The first tests of app.py itself. They use FastAPI's TestClient against a
temporary SQLite database (see conftest.py) and a stubbed pipeline — no
network. They pin the state machine documented in
docs/architecture/02-target-architecture.md §4:

    pending → running → done | failed | cancelled | interrupted

and the rule that a GET on /stream can never start a second run.
"""

import asyncio
import os
import json
import logging

import pytest
from fastapi.testclient import TestClient

import app as appmod
from dbconn import connect as db_connect
from dbconn import insert_returning_id


def _events(body: str):
    """Parse an SSE body into [(event, payload_dict_or_None)]."""
    out = []
    for block in body.split("\n\n"):
        event, data = None, None
        for line in block.splitlines():
            if line.startswith("event: "):
                event = line[7:]
            elif line.startswith("data: "):
                data = json.loads(line[6:])
        if event:
            out.append((event, data))
    return out


def _row(inv_id):
    with db_connect(appmod.DB_PATH) as conn:
        r = conn.execute(
            "SELECT status, summary, started_at, finished_at, error"
            " FROM investigations WHERE id = ?", (inv_id,)).fetchone()
    return {"status": r[0], "summary": r[1], "started_at": r[2],
            "finished_at": r[3], "error": r[4]}


def _runs_for(inv_id):
    with db_connect(appmod.DB_PATH) as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM runs WHERE investigation_id = ?",
            (inv_id,)).fetchone()[0]


SUMMARY = {"accounts": [], "variants": [], "name_accounts": [],
           "email": {"gravatar": None, "holehe": []}, "correlation": []}


async def _fake_pipeline_ok(**kw):
    kw["emit"]("meta", {"usernames": kw["usernames"]})
    kw["emit"]("done", {"found": 0, "leads": 0})
    return dict(SUMMARY)


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(appmod, "run_pipeline", _fake_pipeline_ok)
    with TestClient(appmod.app) as c:
        yield c


# --- boot -------------------------------------------------------------------

def test_app_boots_offline_from_the_bundled_site_list():
    """Startup used to download Sherlock's site list from GitHub with no
    timeout; offline the app could not import at all."""
    assert appmod.SITES_SOURCE == "bundled"
    assert len(appmod.SITE_DATA_ALL) > 300


# --- validation shapes --------------------------------------------------------

def test_create_investigation_error_shapes(client):
    r = client.post("/api/investigate", content=b"not json",
                    headers={"content-type": "application/json"})
    assert r.status_code == 400 and "error" in r.json()
    r = client.post("/api/investigate", json={})
    assert r.status_code == 400 and "error" in r.json()
    r = client.post("/api/investigate", json={"usernames": "alice"})
    assert r.status_code == 200 and isinstance(r.json()["investigation_id"], int)


def test_stream_of_unknown_investigation_is_json_404(client):
    r = client.get("/api/investigate/999999/stream")
    assert r.status_code == 404 and r.json() == {"error": "not found"}


# --- pending → running → done ------------------------------------------------

def test_stream_runs_a_pending_investigation_to_done(client):
    iid = client.post("/api/investigate", json={"usernames": "alice"}).json()["investigation_id"]
    assert _row(iid)["status"] == "pending"
    with client.stream("GET", f"/api/investigate/{iid}/stream") as r:
        assert r.status_code == 200
        body = "".join(r.iter_text())
    names = [e for e, _ in _events(body)]
    assert names[0] == "meta_run"
    assert "done" in names and "saved" in names
    row = _row(iid)
    assert row["status"] == "done"
    assert row["summary"] and row["started_at"] and row["finished_at"]
    assert row["error"] is None
    assert _runs_for(iid) == 1


def test_stream_never_reruns_a_non_pending_investigation(client):
    """The defect: a GET on /stream re-ran a finished case and a disconnect
    stranded it in `running` (7 of 53 rows in one database)."""
    iid = client.post("/api/investigate", json={"usernames": "alice"}).json()["investigation_id"]
    with client.stream("GET", f"/api/investigate/{iid}/stream") as r:
        "".join(r.iter_text())
    before = _row(iid)
    r = client.get(f"/api/investigate/{iid}/stream")
    assert r.status_code == 409
    assert r.json()["status"] == "done" and "error" in r.json()
    assert _row(iid) == before, "a refused stream must not touch the row"
    assert _runs_for(iid) == 1, "no second run was recorded"
    # Same for a row that is currently running elsewhere.
    iid2 = client.post("/api/investigate", json={"usernames": "bob"}).json()["investigation_id"]
    assert appmod._claim_investigation(iid2) is True
    assert appmod._claim_investigation(iid2) is False       # atomic, once only
    r = client.get(f"/api/investigate/{iid2}/stream")
    assert r.status_code == 409 and r.json()["status"] == "running"


# --- failed ---------------------------------------------------------------------

def test_failed_run_persists_the_reason_and_logs_it(monkeypatch, caplog):
    async def boom(**kw):
        raise RuntimeError("engine exploded")
    monkeypatch.setattr(appmod, "run_pipeline", boom)
    with TestClient(appmod.app) as client:
        iid = client.post("/api/investigate", json={"usernames": "alice"}).json()["investigation_id"]
        with caplog.at_level(logging.ERROR, logger="app"):
            with client.stream("GET", f"/api/investigate/{iid}/stream") as r:
                body = "".join(r.iter_text())
    evs = dict(_events(body))
    assert "fatal" in evs and "engine exploded" in evs["fatal"]["message"]
    row = _row(iid)
    assert row["status"] == "failed"
    assert row["error"] == "RuntimeError: engine exploded"
    assert row["finished_at"]
    assert any("failed" in rec.getMessage() and rec.exc_info for rec in caplog.records), \
        "the failure must be logged server-side with a traceback"
    assert _runs_for(iid) == 0


# --- cancelled ------------------------------------------------------------------

def test_client_disconnect_marks_the_investigation_cancelled(monkeypatch):
    """CancelledError is a BaseException: the old `except Exception` never saw
    it, so the row stayed `running` forever."""
    async def slow(**kw):
        await asyncio.sleep(30)
        return dict(SUMMARY)
    monkeypatch.setattr(appmod, "run_pipeline", slow)

    async def scenario():
        with db_connect(appmod.DB_PATH) as conn:
            iid = insert_returning_id(conn,
                "INSERT INTO investigations (created_at, inputs, status)"
                " VALUES (?,?,'pending')",
                ("2026-01-01 00:00:00", json.dumps({
                    "name": "", "usernames": ["alice"], "email": "", "phone": "",
                    "domain": "", "location": "", "variants": False,
                    "thorough": False, "timeout": 5})))
        assert appmod._claim_investigation(iid)
        inputs = appmod._get_investigation(iid)["inputs"]
        events = []
        task = asyncio.create_task(appmod.run_investigation(
            iid, inputs, {}, lambda e, p: events.append(e), asyncio.get_running_loop()))
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        return iid

    iid = asyncio.run(scenario())
    row = _row(iid)
    assert row["status"] == "cancelled"
    assert "disconnected" in row["error"]
    assert row["finished_at"]


# --- interrupted (startup sweep) -----------------------------------------------------

def test_startup_sweep_marks_stale_running_rows_interrupted():
    with db_connect(appmod.DB_PATH) as conn:
        iid = insert_returning_id(conn,
            "INSERT INTO investigations (created_at, inputs, status)"
            " VALUES (?,?,'running')",
            ("2026-01-01 00:00:00", json.dumps({"usernames": ["x"]})))
        zombie = insert_returning_id(conn,
            "INSERT INTO investigations (created_at, inputs, status)"
            " VALUES (?,?,'pending')",
            ("2026-01-01 00:00:00", json.dumps({"usernames": ["y"]})))
        fresh = insert_returning_id(conn,
            "INSERT INTO investigations (created_at, inputs, status)"
            " VALUES (?,?,'pending')",
            (appmod._now(), json.dumps({"usernames": ["z"]})))
    assert appmod.sweep_stuck_investigations() >= 2
    row = _row(iid)
    assert row["status"] == "interrupted"
    assert "restarted" in row["error"] and row["finished_at"]
    assert _row(zombie)["status"] == "interrupted"          # pending for months
    assert _row(fresh)["status"] == "pending"               # just created: kept
    assert appmod.sweep_stuck_investigations() == 0         # idempotent


# --- concurrency -------------------------------------------------------------------

def test_queued_event_when_the_concurrency_limit_is_reached(monkeypatch):
    monkeypatch.setattr(appmod, "run_pipeline", _fake_pipeline_ok)

    async def scenario():
        with db_connect(appmod.DB_PATH) as conn:
            iid = insert_returning_id(conn,
                "INSERT INTO investigations (created_at, inputs, status)"
                " VALUES (?,?,'pending')",
                ("2026-01-01 00:00:00", json.dumps({
                    "name": "", "usernames": ["alice"], "email": "", "phone": "",
                    "domain": "", "location": "", "variants": False,
                    "thorough": False, "timeout": 5})))
        assert appmod._claim_investigation(iid)
        inputs = appmod._get_investigation(iid)["inputs"]
        sem = appmod._investigation_semaphore()
        await sem.acquire()                       # someone else is running
        events = []
        task = asyncio.create_task(appmod.run_investigation(
            iid, inputs, {}, lambda e, p: events.append((e, p)), asyncio.get_running_loop()))
        await asyncio.sleep(0.05)
        assert events and events[0][0] == "queued"
        assert events[0][1]["max_concurrent"] == appmod.MAX_CONCURRENT_INVESTIGATIONS
        sem.release()
        await task
        return iid, events

    iid, events = asyncio.run(scenario())
    assert _row(iid)["status"] == "done"
    assert [e for e, _ in events][-1] == "saved"


# --- site list loader --------------------------------------------------------------

def test_site_list_auto_mode_falls_back_to_bundled_without_network(tmp_path, caplog):
    def no_network(url):
        raise OSError("network unreachable")
    with caplog.at_level(logging.WARNING, logger="app"):
        sites, label = appmod._load_sherlock_sites("auto", cache_dir=tmp_path, fetch=no_network)
    assert label == "bundled" and len(sites) > 300
    assert any("refresh failed" in r.getMessage() for r in caplog.records)
    assert not (tmp_path / "sherlock-data.json").exists()


def test_site_list_auto_mode_caches_a_fetched_list_and_reuses_it(tmp_path):
    from pathlib import Path
    import sherlock_project
    bundled = Path(sherlock_project.__file__).parent / "resources" / "data.json"
    payload = bundled.read_text()
    calls = []

    def fake_fetch(url):
        calls.append(url)
        return payload if url.endswith(".json") else "GitHub\nFakeSiteToExclude\n"
    sites, label = appmod._load_sherlock_sites("auto", cache_dir=tmp_path, fetch=fake_fetch)
    assert label == "remote-cached" and len(calls) == 2
    assert (tmp_path / "sherlock-data.json").exists()
    assert "GitHub" not in {s.name for s in sites}          # live exclusions applied
    calls2 = []

    def recording_fetch(url):
        calls2.append(url)
        raise AssertionError("must not be called")
    sites2, label2 = appmod._load_sherlock_sites("auto", cache_dir=tmp_path, fetch=recording_fetch)
    assert calls2 == [], "a fresh cache must not trigger a fetch"
    assert label2 == "cache" and len(sites2) == len(sites)


def test_site_list_rejects_a_corrupt_remote_payload(tmp_path):
    sites, label = appmod._load_sherlock_sites("auto", cache_dir=tmp_path,
                                               fetch=lambda url: "<html>not json")
    assert label == "bundled" and not (tmp_path / "sherlock-data.json").exists()


def test_bundled_mode_applies_the_vendored_exclusions():
    excl = appmod._read_exclusions(appmod._VENDORED_EXCLUSIONS)
    assert excl, "recon/data/sherlock-exclusions.txt must not be empty"
    assert not (excl & set(appmod.SITE_DATA_ALL)), "excluded sites must not be scanned"


def test_site_list_rejects_wrong_shape_json_and_never_caches_it(tmp_path):
    """Valid JSON of the wrong shape used to be cached with a fresh mtime and
    then crash SitesInformation at every boot for a week (re-review blocker)."""
    for payload in ("[]", '"str"', '{"Foo": {}}', '{"$schema": "s"}'):
        sites, label = appmod._load_sherlock_sites("auto", cache_dir=tmp_path,
                                                   fetch=lambda url, p=payload: p)
        assert label == "bundled" and len(sites) > 300, payload
        assert not (tmp_path / "sherlock-data.json").exists(), payload


def test_site_list_deletes_an_unreadable_cache_and_boots(tmp_path):
    (tmp_path / "sherlock-data.json").write_text("{corrupt")
    sites, label = appmod._load_sherlock_sites(
        "auto", cache_dir=tmp_path, fetch=lambda url: (_ for _ in ()).throw(OSError("offline")))
    assert label == "bundled" and len(sites) > 300
    assert not (tmp_path / "sherlock-data.json").exists()


def test_site_list_uses_a_fetched_list_even_when_the_cache_is_unwritable(tmp_path):
    from pathlib import Path
    import sherlock_project
    payload = (Path(sherlock_project.__file__).parent / "resources" / "data.json").read_text()
    unwritable = tmp_path / "file-not-dir"
    unwritable.write_text("x")                      # mkdir(cache_dir) will fail
    sites, label = appmod._load_sherlock_sites(
        "auto", cache_dir=unwritable, fetch=lambda url: payload if url.endswith(".json") else "")
    assert label == "remote" and len(sites) > 300


def test_done_is_only_sent_after_the_summary_is_written(monkeypatch):
    """A failed `done` write must surface as `fatal`, not leave a row that the
    client saw finish but the database still calls running."""
    async def pipeline(**kw):
        kw["emit"]("done", {"found": 1})
        return dict(SUMMARY)
    monkeypatch.setattr(appmod, "run_pipeline", pipeline)
    real_set = appmod._set_investigation

    def failing_set(inv_id, status, summary=None, **kw):
        if status == "done":
            raise RuntimeError("disk full")
        return real_set(inv_id, status, summary, **kw)
    monkeypatch.setattr(appmod, "_set_investigation", failing_set)

    async def scenario():
        with db_connect(appmod.DB_PATH) as conn:
            iid = insert_returning_id(conn,
                "INSERT INTO investigations (created_at, inputs, status)"
                " VALUES (?,?,'pending')",
                ("2026-01-01 00:00:00", json.dumps({
                    "name": "", "usernames": ["alice"], "email": "", "phone": "",
                    "domain": "", "location": "", "variants": False,
                    "thorough": False, "timeout": 5})))
        assert appmod._claim_investigation(iid)
        events = []
        await appmod.run_investigation(iid, appmod._get_investigation(iid)["inputs"], {},
                                       lambda e, p: events.append(e), asyncio.get_running_loop())
        return iid, events

    iid, events = asyncio.run(scenario())
    assert "done" not in events and "fatal" in events
    assert _row(iid)["status"] == "failed" and "disk full" in _row(iid)["error"]


# --- HTTP-layer hardening (increment H1) -------------------------------------------

def _pending(client):
    return client.post("/api/investigate", json={"usernames": "alice"}).json()["investigation_id"]


def test_cross_site_post_is_refused_and_writes_nothing(client):
    before = client.get("/api/watchlist").json()
    r = client.post("/api/watchlist", json={"inputs": {"usernames": "eve"}},
                    headers={"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"})
    assert r.status_code == 403 and "cross-site" in r.json()["error"]
    assert client.get("/api/watchlist").json() == before
    # A foreign Origin alone (older browsers without Sec-Fetch-Site) is enough.
    r = client.post("/api/investigate", json={"usernames": "eve"},
                    headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
    # The console's own origin and header-less local tools are fine.
    r = client.post("/api/investigate", json={"usernames": "alice"},
                    headers={"Origin": "http://testserver", "Sec-Fetch-Site": "same-origin"})
    assert r.status_code == 200


def test_scan_starting_get_is_protected_like_a_write(client):
    iid = _pending(client)
    r = client.get(f"/api/investigate/{iid}/stream", headers={"Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 403
    assert _row(iid)["status"] == "pending", "a refused request must not claim the row"
    r = client.get("/api/search/stream?usernames=alice", headers={"Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 403


def test_foreign_host_header_is_refused(client):
    r = client.get("/api/history", headers={"Host": "evil.example"})
    assert r.status_code == 400 and "Host" in r.json()["error"]


def test_json_endpoints_require_json_content_type(client):
    r = client.post("/api/investigate", content=b'{"usernames":"alice"}',
                    headers={"content-type": "text/plain"})
    assert r.status_code == 415


def test_request_limits(client):
    r = client.post("/api/investigate", json={"usernames": ",".join(f"u{i}" for i in range(21))})
    assert r.status_code == 400 and "at most" in r.json()["error"]
    r = client.post("/api/investigate", content=b"x" * (70 * 1024),
                    headers={"content-type": "application/json"})
    assert r.status_code == 413
    r = client.post("/api/alerts/mark_seen", json={"ids": list(range(501))})
    assert r.status_code == 400


def test_malformed_bodies_are_400_not_500(client):
    assert client.post("/api/investigate", json={"usernames": "alice", "timeout": "abc"}).status_code == 400
    assert client.post("/api/watchlist", json={"inputs": []}).status_code == 400
    assert client.post("/api/watchlist", json={"inputs": {"usernames": "a"}, "interval_hours": "x"}).status_code == 400
    assert client.post("/api/alerts/mark_seen", json={"ids": ["x"]}).status_code == 400
    assert client.post("/api/alerts/mark_seen", content=b"", headers={"content-type": "application/json"}).status_code == 200


def test_security_headers_and_csp_on_html(client):
    r = client.get("/")
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["Referrer-Policy"] == "no-referrer"
    csp = r.headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert "unsafe-inline" not in csp.split("style-src")[0]      # no inline scripts
    assert "Content-Security-Policy" not in client.get("/api/history").headers
    # The one former inline script now loads from a file the CSP allows.
    assert client.get("/static/js/sw-cleanup.js").status_code == 200
    assert "<script>" not in client.get("/").text


def test_health_endpoint(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["db_ok"] is True and body["backend"] == "sqlite"
    for key in ("commit", "uptime_s", "investigations", "deps", "stealth", "sites", "max_concurrent"):
        assert key in body, key
    assert body["sites"]["source"] == "bundled" and body["sites"]["sherlock"] > 300


def test_delete_investigation_cascades_to_history(client):
    iid = _pending(client)
    with client.stream("GET", f"/api/investigate/{iid}/stream") as r:
        "".join(r.iter_text())
    assert _runs_for(iid) == 1
    r = client.delete(f"/api/investigate/{iid}")
    assert r.status_code == 200 and r.json() == {"deleted": iid}
    assert client.get(f"/api/investigate/{iid}").status_code == 404
    assert _runs_for(iid) == 0
    assert client.delete(f"/api/investigate/{iid}").status_code == 404
    assert client.delete("/api/history/999999").status_code == 404


def test_legacy_recon_stream_is_gone_but_reports_remain(client):
    assert client.get("/api/recon/stream?usernames=alice").status_code == 404
    assert client.get("/api/recon/report/999999").status_code == 404   # route exists


def test_site_picker_has_no_denied_hosts(client):
    from recon import engines, policy
    names = {s["name"] for s in client.get("/api/sites").json()}
    for name in names:
        info = appmod.SITE_DATA_ALL[name]
        assert policy.denied_site_reason(engines.sherlock_url_templates(info)) is None, name


def test_database_file_is_private():
    import stat
    mode = stat.S_IMODE(os.stat(appmod.DB_PATH).st_mode)
    assert mode & 0o077 == 0, oct(mode)
