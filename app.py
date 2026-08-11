"""sherlock-web: a FastAPI wrapper around the Sherlock OSINT library.

Serves a single-page frontend (static/index.html) and streams username
search results over Server-Sent Events. Completed runs are persisted to
SQLite (history.db) so past results can be reloaded.

Sherlock library API used (sherlock-project 0.16.0):
    from sherlock_project.sherlock import sherlock
        sherlock(username, site_data, query_notify, timeout=...) -> dict
    from sherlock_project.sites import SitesInformation
        iterable of SiteInformation objects (name, information, is_nsfw, ...)
    from sherlock_project.notify import QueryNotify
        subclass and override update(result) for per-site callbacks
    from sherlock_project.result import QueryStatus
        CLAIMED = found; UNKNOWN/WAF/ILLEGAL = error-ish; AVAILABLE = not found
"""

import asyncio
import base64
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from pathlib import Path

from fastapi import FastAPI, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from sherlock_project.notify import QueryNotify
from sherlock_project.result import QueryStatus
from sherlock_project.sherlock import sherlock
from sherlock_project.sites import SitesInformation

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "history.db"
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="sherlock-web")

# ---------------------------------------------------------------------------
# Optional access gate (Railway deployments etc.)
# ---------------------------------------------------------------------------

# If APP_PASSWORD is set, every route (including / and the SSE stream) requires
# HTTP Basic auth with that password (any username). Unset = fully open.
APP_PASSWORD = os.environ.get("APP_PASSWORD") or None


@app.middleware("http")
async def basic_auth_gate(request: Request, call_next):
    if APP_PASSWORD is not None:
        authorized = False
        auth = request.headers.get("authorization", "")
        if auth.startswith("Basic "):
            try:
                decoded = base64.b64decode(auth[6:], validate=True).decode("utf-8")
                _, _, password = decoded.partition(":")
                authorized = secrets.compare_digest(password, APP_PASSWORD)
            except Exception:
                authorized = False
        if not authorized:
            return Response(
                "Unauthorized",
                status_code=401,
                headers={"WWW-Authenticate": 'Basic realm="sherlock-web"'},
            )
    return await call_next(request)

# ---------------------------------------------------------------------------
# Site data (loaded once at startup)
# ---------------------------------------------------------------------------

# SitesInformation() honors Sherlock's built-in exclusions (dead sites etc.).
# SiteInformation.information is the raw per-site dict sherlock() expects.
_ALL_SITES = list(SitesInformation())
SITE_DATA_ALL = {s.name: s.information for s in _ALL_SITES}
NSFW_NAMES = {s.name for s in _ALL_SITES if s.is_nsfw}


# ---------------------------------------------------------------------------
# SQLite history
# ---------------------------------------------------------------------------

def _init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                username TEXT NOT NULL,
                found INTEGER NOT NULL,
                total INTEGER NOT NULL,
                results TEXT NOT NULL
            )
            """
        )


_init_db()


def save_run(username: str, found: int, total: int, results: list[dict]) -> None:
    """Persist one completed per-username run. Called from the scan thread."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO runs (ts, username, found, total, results) VALUES (?,?,?,?,?)",
            (
                time.strftime("%Y-%m-%d %H:%M:%S"),
                username,
                found,
                total,
                json.dumps(results),
            ),
        )


@app.get("/api/history")
def get_history() -> list[dict]:
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT id, ts, username, found, total FROM runs ORDER BY id DESC LIMIT 50"
        ).fetchall()
    return [
        {"id": r[0], "ts": r[1], "username": r[2], "found": r[3], "total": r[4]}
        for r in rows
    ]


@app.get("/api/history/{run_id}")
def get_run(run_id: int) -> JSONResponse:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT id, ts, username, found, total, results FROM runs WHERE id = ?",
            (run_id,),
        ).fetchone()
    if row is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse(
        {
            "id": row[0],
            "ts": row[1],
            "username": row[2],
            "found": row[3],
            "total": row[4],
            "results": json.loads(row[5]),
        }
    )


# ---------------------------------------------------------------------------
# Site list
# ---------------------------------------------------------------------------

@app.get("/api/sites")
def get_sites() -> list[dict]:
    return [
        {"name": name, "nsfw": name in NSFW_NAMES}
        for name in sorted(SITE_DATA_ALL, key=str.lower)
    ]


# ---------------------------------------------------------------------------
# Streaming search (SSE)
# ---------------------------------------------------------------------------

# Statuses that mean "checked, but something went wrong" (rate limit, WAF, ...).
ERROR_STATUSES = {QueryStatus.UNKNOWN, QueryStatus.WAF, QueryStatus.ILLEGAL}


class QueueNotify(QueryNotify):
    """QueryNotify that forwards every per-site result into an asyncio.Queue.

    Sherlock's scan is synchronous and runs in a worker thread; the SSE
    response lives on the asyncio event loop, so we hop across with
    loop.call_soon_threadsafe.
    """

    def __init__(self, username: str, queue: asyncio.Queue, loop: asyncio.AbstractEventLoop):
        super().__init__()
        self.username = username
        self.queue = queue
        self.loop = loop

    def _emit(self, event: str, payload: dict) -> None:
        payload["username"] = self.username
        self.loop.call_soon_threadsafe(
            self.queue.put_nowait, (event, payload)
        )

    def update(self, result) -> None:  # called once per site, from scan thread
        status = result.status
        if status == QueryStatus.CLAIMED:
            self._emit(
                "found",
                {
                    "site": result.site_name,
                    "url": result.site_url_user,
                    "query_time": result.query_time,
                },
            )
        elif status in ERROR_STATUSES:
            self._emit(
                "error",
                {
                    "site": result.site_name,
                    "status": str(status.value),
                    "context": result.context or "",
                },
            )
        # AVAILABLE = not found: not emitted as a row, only counted in progress.


def _run_scan(usernames: list[str], site_data: dict, timeout: int,
              queue: asyncio.Queue, loop: asyncio.AbstractEventLoop) -> None:
    """Worker-thread entry point: scans usernames sequentially."""
    total = len(site_data)
    summary = []
    try:
        for username in usernames:
            loop.call_soon_threadsafe(
                queue.put_nowait,
                ("user_start", {"username": username, "total": total}),
            )
            notify = QueueNotify(username, queue, loop)
            checked = 0

            # Wrap update() to also count progress per completed site check.
            orig_update = notify.update

            def counting_update(result, _orig=orig_update):
                nonlocal checked
                checked += 1
                _orig(result)
                notify._emit("progress", {"checked": checked, "total": total})

            notify.update = counting_update

            results_raw = sherlock(username, site_data, notify, timeout=timeout)

            found_rows = []
            for site_name, info in results_raw.items():
                r = info["status"]
                if r.status == QueryStatus.CLAIMED:
                    found_rows.append({"site": site_name, "url": r.site_url_user})

            save_run(username, len(found_rows), total, found_rows)
            summary.append(
                {"username": username, "found": len(found_rows), "total": total}
            )
            loop.call_soon_threadsafe(
                queue.put_nowait,
                (
                    "user_done",
                    {"username": username, "found": len(found_rows), "total": total},
                ),
            )
    except Exception as exc:  # surface unexpected scan failures to the client
        loop.call_soon_threadsafe(
            queue.put_nowait, ("fatal", {"message": f"{type(exc).__name__}: {exc}"})
        )
    finally:
        loop.call_soon_threadsafe(queue.put_nowait, ("done", {"runs": summary}))
        loop.call_soon_threadsafe(queue.put_nowait, None)  # sentinel


@app.get("/api/search/stream")
async def search_stream(
    request: Request,
    usernames: str = Query(...),
    timeout: int = Query(10, ge=1, le=120),
    nsfw: bool = Query(False),
    sites: str = Query(""),
) -> StreamingResponse:
    # Accept comma- and/or newline-separated usernames.
    names = [u.strip() for u in re.split(r"[,\n]+", usernames) if u.strip()]
    if not names:
        return StreamingResponse(
            iter(['event: fatal\ndata: {"message": "no usernames given"}\n\n']),
            media_type="text/event-stream",
        )

    # Build the site subset; empty selection = all sites. Case-insensitive.
    selected = {s.strip().lower() for s in sites.split(",") if s.strip()}
    site_data = {}
    for name, info in SITE_DATA_ALL.items():
        if selected and name.lower() not in selected:
            continue
        if not nsfw and name in NSFW_NAMES:
            continue
        site_data[name] = info

    queue: asyncio.Queue = asyncio.Queue()
    loop = asyncio.get_running_loop()

    # Kick off the synchronous Sherlock scan in a daemon thread.
    thread = threading.Thread(
        target=_run_scan,
        args=(names, site_data, timeout, queue, loop),
        daemon=True,
    )
    thread.start()

    async def event_gen():
        # Announce what is about to happen.
        meta = {
            "usernames": names,
            "sites_total": len(site_data),
            "timeout": timeout,
            "nsfw": nsfw,
        }
        yield f"event: meta\ndata: {json.dumps(meta)}\n\n"
        try:
            while True:
                # Wait for the next event, but wake up periodically so we can
                # notice client disconnects and stop the stream.
                try:
                    item = await asyncio.wait_for(queue.get(), timeout=15)
                except asyncio.TimeoutError:
                    if await request.is_disconnected():
                        break
                    yield ": keepalive\n\n"
                    continue
                if item is None:  # sentinel: scan finished
                    break
                event, payload = item
                yield f"event: {event}\ndata: {json.dumps(payload)}\n\n"
        except asyncio.CancelledError:
            # Client aborted (Stop button / closed tab). The daemon scan
            # thread finishes on its own; its queue writes are harmless.
            raise

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ---------------------------------------------------------------------------
# Frontend
# ---------------------------------------------------------------------------

@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


# PWA assets. sw.js is served from the root so its service-worker scope is "/".
@app.get("/manifest.webmanifest")
def web_manifest() -> FileResponse:
    return FileResponse(
        STATIC_DIR / "manifest.webmanifest", media_type="application/manifest+json"
    )


@app.get("/sw.js")
def service_worker() -> FileResponse:
    return FileResponse(
        STATIC_DIR / "sw.js",
        media_type="text/javascript",
        headers={"Service-Worker-Allowed": "/", "Cache-Control": "no-cache"},
    )


# Icons and any other static assets.
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
