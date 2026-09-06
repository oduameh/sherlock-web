"""HTTP-layer tests for the investigation lifecycle.

The first tests of app.py itself. They use FastAPI's TestClient against a
temporary SQLite database (see conftest.py) and a stubbed pipeline — no
network. They pin the state machine documented in
docs/architecture/02-target-architecture.md §4:

    pending → running → done | failed | cancelled | interrupted

and the rule that a GET on /stream can never start a second run.
"""

import asyncio
import json
import logging

import pytest
from fastapi.testclient import TestClient

import app as appmod
from dbconn import connect as db_connect


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
            iid = conn.execute(
                "INSERT INTO investigations (created_at, inputs, status)"
                " VALUES (?,?,'pending')",
                ("2026-01-01 00:00:00", json.dumps({
                    "name": "", "usernames": ["alice"], "email": "", "phone": "",
                    "domain": "", "location": "", "variants": False,
                    "thorough": False, "timeout": 5}))).lastrowid
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
        iid = conn.execute(
            "INSERT INTO investigations (created_at, inputs, status)"
            " VALUES (?,?,'running')",
            ("2026-01-01 00:00:00", json.dumps({"usernames": ["x"]}))).lastrowid
    assert appmod.sweep_stuck_investigations() >= 1
    row = _row(iid)
    assert row["status"] == "interrupted"
    assert "restarted" in row["error"] and row["finished_at"]
    # Idempotent: nothing left to sweep for this row.
    assert _row(iid)["status"] == "interrupted"


# --- concurrency -------------------------------------------------------------------

def test_queued_event_when_the_concurrency_limit_is_reached(monkeypatch):
    monkeypatch.setattr(appmod, "run_pipeline", _fake_pipeline_ok)

    async def scenario():
        with db_connect(appmod.DB_PATH) as conn:
            iid = conn.execute(
                "INSERT INTO investigations (created_at, inputs, status)"
                " VALUES (?,?,'pending')",
                ("2026-01-01 00:00:00", json.dumps({
                    "name": "", "usernames": ["alice"], "email": "", "phone": "",
                    "domain": "", "location": "", "variants": False,
                    "thorough": False, "timeout": 5}))).lastrowid
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
