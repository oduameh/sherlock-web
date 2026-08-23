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
import logging
import os
import re
import secrets
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path

logging.basicConfig(level=logging.INFO)

from fastapi import FastAPI, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

import dbconn
from dbconn import connect as db_connect
from dbconn import insert_returning_id

# Adaptive routing (recon.router) is stdlib-only — safe to import even when
# the optional recon dependencies (maigret, holehe) are missing.
from recon import router as recon_router

from sherlock_project.notify import QueryNotify
from sherlock_project.result import QueryStatus
from sherlock_project.sherlock import sherlock
from sherlock_project.sites import SitesInformation

# recon package: heavy deps (maigret, holehe) are lazily imported inside it,
# but guard the import anyway so the classic app always boots.
try:
    from recon import engines as recon_engines
    from recon import monitor as recon_monitor
    from recon.connections import find_connections, subject_identifiers
    from recon.correlate import correlate as recon_correlate
    from recon.dossier import render_dossier
    from recon.email_pivot import gravatar_lookup, holehe_available, holehe_scan
    from recon.enrich import enrich_profiles
    from recon.exposure import exposure_summary
    from recon.graph import build_graph
    from recon.permutations import generate_variants
    from recon.pipeline import run_pipeline
    from recon.report import render_report
    from recon.timeline import (
        account_creation_dates,
        account_events,
        build_timeline,
    )
    from recon.validate import is_probably_email

    RECON_AVAILABLE = True
except Exception as _recon_exc:  # pragma: no cover
    import logging as _logging

    _logging.getLogger("app").warning("recon package unavailable: %s", _recon_exc)
    RECON_AVAILABLE = False

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "history.db"
STATIC_DIR = BASE_DIR / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start (and cleanly stop) the background watchlist monitor."""
    monitor_task = None
    if RECON_AVAILABLE:
        sher_light = recon_engines.sherlock_variant_site_data(SITE_DATA_ALL)
        monitor_task = asyncio.create_task(
            recon_monitor.monitor_loop(DB_PATH, sher_light)
        )
    try:
        yield
    finally:
        if monitor_task is not None:
            monitor_task.cancel()
            try:
                await monitor_task
            except asyncio.CancelledError:
                pass
        try:
            from recon import stealthweb
            await stealthweb.aclose()
        except Exception:
            pass


app = FastAPI(title="sherlock-web", lifespan=lifespan)

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
    with db_connect(DB_PATH) as conn:
        conn.execute(
            f"""
            CREATE TABLE IF NOT EXISTS runs (
                id {dbconn.PK},
                ts TEXT NOT NULL,
                username TEXT NOT NULL,
                found INTEGER NOT NULL,
                total INTEGER NOT NULL,
                results TEXT NOT NULL,
                kind TEXT NOT NULL DEFAULT 'sherlock',
                investigation_id INTEGER
            )
            """
        )
        # Migration for pre-existing SQLite databases created before the `kind`
        # / `investigation_id` columns existed. A fresh database (SQLite or
        # Postgres) already has them from the CREATE above, so this is
        # SQLite-only (PRAGMA table_info is SQLite-specific).
        if not dbconn.IS_POSTGRES:
            cols = [r[1] for r in conn.execute("PRAGMA table_info(runs)")]
            if "kind" not in cols:
                conn.execute(
                    "ALTER TABLE runs ADD COLUMN kind TEXT NOT NULL"
                    " DEFAULT 'sherlock'"
                )
            if "investigation_id" not in cols:
                conn.execute(
                    "ALTER TABLE runs ADD COLUMN investigation_id INTEGER"
                )
        conn.execute(
            f"""
            CREATE TABLE IF NOT EXISTS investigations (
                id {dbconn.PK},
                created_at TEXT NOT NULL,
                inputs TEXT NOT NULL,
                summary TEXT,
                status TEXT NOT NULL DEFAULT 'pending'
            )
            """
        )
        if RECON_AVAILABLE:
            recon_monitor.init_tables(conn)
        recon_router.init_tables(conn)


_init_db()


def save_run(username: str, found: int, total: int, results,
             kind: str = "sherlock", investigation_id: int = None) -> int:
    """Persist one completed per-username run. Called from the scan thread."""
    with db_connect(DB_PATH) as conn:
        return insert_returning_id(
            conn,
            "INSERT INTO runs (ts, username, found, total, results, kind,"
            " investigation_id) VALUES (?,?,?,?,?,?,?)",
            (
                time.strftime("%Y-%m-%d %H:%M:%S"),
                username,
                found,
                total,
                json.dumps(results),
                kind,
                investigation_id,
            ),
        )


@app.get("/api/history")
def get_history() -> list[dict]:
    with db_connect(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT id, ts, username, found, total, kind, investigation_id"
            " FROM runs ORDER BY id DESC LIMIT 50"
        ).fetchall()
    return [
        {"id": r[0], "ts": r[1], "username": r[2], "found": r[3], "total": r[4],
         "kind": r[5], "investigation_id": r[6]}
        for r in rows
    ]


@app.get("/api/history/{run_id}")
def get_run(run_id: int) -> JSONResponse:
    with db_connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT id, ts, username, found, total, results, kind,"
            " investigation_id FROM runs WHERE id = ?",
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
            "kind": row[6],
            "investigation_id": row[7],
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
# Source health (adaptive routing)
# ---------------------------------------------------------------------------

@app.get("/api/health/sources")
def get_health_sources() -> JSONResponse:
    """Per-site reliability summary (failure rate, dominant error class,
    circuit state, EWMA latency), worst-first, plus aggregate stats."""
    return JSONResponse(recon_router.sources_summary(DB_PATH))


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

    def __init__(self, username: str, queue: asyncio.Queue, loop: asyncio.AbstractEventLoop,
                 router: "recon_router.RunRouter | None" = None):
        super().__init__()
        self.username = username
        self.queue = queue
        self.loop = loop
        self.router = router

    def _emit(self, event: str, payload: dict) -> None:
        payload["username"] = self.username
        self.loop.call_soon_threadsafe(
            self.queue.put_nowait, (event, payload)
        )

    def update(self, result) -> None:  # called once per site, from scan thread
        status = result.status
        if self.router is not None:
            self.router.observe("sherlock", result.site_name,
                                str(status.value), result.context or "",
                                result.query_time, username=self.username)
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
    # Adaptive routing: drop open-circuit sites, observe every result, retry
    # transient failures once. Disabled (no-op) if the DB is unavailable.
    def _emit_ts(event: str, payload: dict) -> None:
        loop.call_soon_threadsafe(queue.put_nowait, (event, payload))

    router = recon_router.RunRouter(DB_PATH, emit=_emit_ts)
    site_data = router.filter_sites(site_data, "sherlock")
    router.announce_skipped()

    total = len(site_data)
    summary = []
    try:
        for username in usernames:
            loop.call_soon_threadsafe(
                queue.put_nowait,
                ("user_start", {"username": username, "total": total}),
            )
            notify = QueueNotify(username, queue, loop, router)
            checked = 0

            # Wrap update() to also count progress per completed site check.
            orig_update = notify.update

            def counting_update(result, _orig=orig_update):
                nonlocal checked
                checked += 1
                _orig(result)
                notify._emit("progress", {"checked": checked, "total": total})

            notify.update = counting_update

            results_raw = sherlock(username, site_data, notify,
                                   timeout=timeout, proxy=router.proxy)

            # Smart retries: re-check this pass's transient failures ONCE, all
            # together in a single concurrent re-scan after one short delay.
            # (Doing them one-at-a-time with a sleep each stacked up to minutes
            # of delay on a full run.) 429/WAF-class failures are left to the
            # circuit breaker across runs.
            retry_recs = router.drain_transient("sherlock", username)
            retry_sites = {rec["site"]: site_data[rec["site"]]
                           for rec in retry_recs if rec["site"] in site_data}
            if retry_sites:
                router.retries_done += len(retry_sites)
                for rec in retry_recs:
                    if rec["site"] in retry_sites:
                        _emit_ts("retry", rec)
                time.sleep(recon_router.retry_delay())
                try:
                    sherlock(username, retry_sites, notify,
                             timeout=timeout, proxy=router.proxy)
                except Exception:
                    logging.getLogger("app").exception(
                        "retry batch failed for %s", username)

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
        router.finish()
        done_payload = {"runs": summary, **router.breakdown()}
        loop.call_soon_threadsafe(queue.put_nowait, ("done", done_payload))
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
# Deep recon (SSE): Sherlock + Maigret + variants + email pivot + enrichment
# + correlation. Everything here is best-effort and degrades gracefully.
# ---------------------------------------------------------------------------

if RECON_AVAILABLE:

    class _ReconSherlockNotify(QueryNotify):
        """Forwards Sherlock per-site results to the recon coordinator."""

        def __init__(self, scanned_name, variant_of, emit_threadsafe):
            super().__init__()
            self.scanned_name = scanned_name
            self.variant_of = variant_of
            self.emit = emit_threadsafe
            self.checked = 0
            self.total = 0

        def update(self, result) -> None:
            self.checked += 1
            status = result.status
            if status == QueryStatus.CLAIMED:
                self.emit(
                    "found", "sherlock", self.scanned_name, result.site_name,
                    result.site_url_user, result.query_time, self.variant_of,
                )
            elif status in ERROR_STATUSES:
                self.emit(
                    "error", "sherlock", self.scanned_name, result.site_name,
                    str(status.value), result.context or "", self.variant_of,
                )
            self.emit(
                "progress", "sherlock", self.scanned_name,
                self.checked, self.total, self.variant_of,
            )

    def _recon_sherlock_worker(items, site_data, timeout, emit_threadsafe,
                               loop, done_event):
        """Thread entry: scan (username, variant_of) pairs sequentially."""
        try:
            for scanned_name, variant_of in items:
                notify = _ReconSherlockNotify(scanned_name, variant_of,
                                              emit_threadsafe)
                notify.total = len(site_data)
                emit_threadsafe("engine_start", "sherlock", scanned_name,
                                len(site_data), variant_of)
                sherlock(scanned_name, site_data, notify, timeout=timeout)
                emit_threadsafe("engine_done", "sherlock", scanned_name,
                                variant_of)
        except Exception as exc:
            emit_threadsafe("engine_error", "sherlock",
                            f"{type(exc).__name__}: {exc}")
        finally:
            loop.call_soon_threadsafe(done_event.set)

    @app.get("/api/recon/stream")
    async def recon_stream(
        request: Request,
        usernames: str = Query(""),
        email: str = Query(""),
        variants: bool = Query(False),
        timeout: int = Query(10, ge=1, le=120),
        nsfw: bool = Query(False),
        sites: str = Query(""),
    ) -> StreamingResponse:
        email = email.strip()
        names = [u.strip() for u in re.split(r"[,\n]+", usernames) if u.strip()]
        if email and not is_probably_email(email):
            return StreamingResponse(
                iter([f'event: fatal\ndata: {json.dumps({"message": f"invalid email: {email}"})}\n\n']),
                media_type="text/event-stream",
            )
        if not names and email:
            names = [email.split("@", 1)[0]]
        if not names and not email:
            return StreamingResponse(
                iter(['event: fatal\ndata: {"message": "give a username or an email"}\n\n']),
                media_type="text/event-stream",
            )

        queue: asyncio.Queue = asyncio.Queue()
        loop = asyncio.get_running_loop()

        # --- shared run state (mutated on the event loop only) -----------
        rows: dict[tuple[str, str], dict] = {}
        accounts: list[dict] = []
        variant_rows: list[dict] = []
        email_state: dict = {"gravatar": None, "holehe": []}

        def emit(event: str, payload: dict) -> None:
            queue.put_nowait((event, payload))

        def handle_found(engine, scanned_name, site, url, query_time,
                         variant_of):
            key = (scanned_name, recon_engines.normalize_site(site))
            row = rows.get(key)
            if row is not None:
                if engine not in row["engines"]:
                    row["engines"].append(engine)
                    emit("merged", {
                        "username": scanned_name, "site": row["site"],
                        "engines": row["engines"], "variant_of": variant_of,
                    })
                return
            row = {
                "username": scanned_name, "site": site, "url": url,
                "engines": [engine], "variant_of": variant_of,
                "query_time": query_time,
            }
            rows[key] = row
            (variant_rows if variant_of else accounts).append(row)
            emit("found", dict(row))

        def handle_error(engine, scanned_name, site, status, context,
                         variant_of):
            emit("error", {
                "engine": engine, "username": scanned_name, "site": site,
                "status": status, "context": context, "variant_of": variant_of,
            })

        def handle_progress(engine, scanned_name, checked, total, variant_of):
            emit("progress", {
                "engine": engine, "username": scanned_name,
                "checked": checked, "total": total, "variant_of": variant_of,
            })

        def emit_threadsafe(kind, *args):
            """Route worker-thread callbacks onto the event loop."""
            handler = {
                "found": handle_found,
                "error": handle_error,
                "progress": handle_progress,
            }.get(kind)
            if handler is not None:
                loop.call_soon_threadsafe(handler, *args)
            else:
                loop.call_soon_threadsafe(
                    _engine_lifecycle, kind, *args
                )

        def _engine_lifecycle(kind, engine, *args):
            if kind == "engine_start":
                scanned_name, total, variant_of = args
                emit("engine_start", {
                    "engine": engine, "username": scanned_name,
                    "total": total, "variant_of": variant_of,
                })
            elif kind == "engine_done":
                scanned_name, variant_of = args
                emit("engine_done", {
                    "engine": engine, "username": scanned_name,
                    "variant_of": variant_of,
                })
            elif kind == "engine_error":
                emit("engine_error", {"engine": engine, "message": args[0]})

        # --- engine workers ----------------------------------------------
        def start_sherlock(items, site_data):
            done = asyncio.Event()
            threading.Thread(
                target=_recon_sherlock_worker,
                args=(items, site_data, timeout, emit_threadsafe, loop, done),
                daemon=True,
            ).start()
            return done

        async def maigret_worker(items, site_dict):
            if not recon_engines.maigret_available():
                _engine_lifecycle("engine_error", "maigret",
                                  "maigret package not installed")
                return
            from maigret.result import MaigretCheckStatus

            total = len(site_dict)
            for scanned_name, variant_of in items:
                _engine_lifecycle("engine_start", "maigret", scanned_name,
                                  total, variant_of)
                checked = 0

                def on_result(result, _name=scanned_name, _vo=variant_of):
                    nonlocal checked
                    checked += 1
                    st = result.status  # MaigretCheckStatus enum
                    if st == MaigretCheckStatus.CLAIMED:
                        handle_found("maigret", _name, result.site_name,
                                     result.site_url_user, None, _vo)
                    elif st in (MaigretCheckStatus.UNKNOWN,
                                MaigretCheckStatus.ILLEGAL):
                        handle_error("maigret", _name, result.site_name,
                                     str(st.value),
                                     result.context or "", _vo)
                    handle_progress("maigret", _name, checked, total, _vo)

                try:
                    await recon_engines.maigret_scan(
                        scanned_name, site_dict, timeout, on_result
                    )
                except Exception as exc:
                    _engine_lifecycle("engine_error", "maigret",
                                      f"{type(exc).__name__}: {exc}")
                _engine_lifecycle("engine_done", "maigret", scanned_name,
                                  variant_of)

        async def email_worker(addr):
            grav = await gravatar_lookup(addr)
            email_state["gravatar"] = grav
            emit("email", {
                "source": "gravatar", "email": addr, "found": bool(grav),
                "profile": grav,
            })
            if holehe_available():
                def on_holehe(entry):
                    email_state["holehe"].append(entry)
                    emit("email", {"source": "holehe", "email": addr, **entry})

                await holehe_scan(addr, on_holehe)
            else:
                emit("email", {"source": "holehe", "email": addr,
                               "error": "holehe not installed"})
            hits = sum(1 for h in email_state["holehe"] if h.get("exists"))
            emit("email_done", {"email": addr, "holehe_hits": hits,
                                "gravatar": bool(grav)})

        # --- coordinator ---------------------------------------------------
        async def coordinator():
            params = {"usernames": names, "email": email,
                      "variants": variants, "timeout": timeout, "nsfw": nsfw}
            try:
                # Site subsets.
                selected = {s.strip().lower() for s in sites.split(",")
                            if s.strip()}
                sher_data = {
                    n: i for n, i in SITE_DATA_ALL.items()
                    if (not selected or n.lower() in selected)
                    and (nsfw or n not in NSFW_NAMES)
                }
                mai_sites = (
                    {n: s for n, s in recon_engines.maigret_all_sites().items()
                     if not selected or n.lower() in selected}
                    if recon_engines.maigret_available() else {}
                )
                emit("meta", {
                    **params, "sherlock_sites": len(sher_data),
                    "maigret_sites": len(mai_sites),
                })

                base_items = [(n, None) for n in names]
                sher_done = start_sherlock(base_items, sher_data)
                mai_task = asyncio.create_task(maigret_worker(base_items,
                                                              mai_sites))
                email_task = (asyncio.create_task(email_worker(email))
                              if email else None)
                await sher_done.wait()
                await mai_task

                # Variants phase (reduced high-value site list).
                if variants:
                    sher_reduced = recon_engines.sherlock_variant_site_data(
                        sher_data)
                    mai_reduced = (
                        recon_engines.maigret_variant_sites()
                        if recon_engines.maigret_available() else {}
                    )
                    if selected:  # honor an explicit site selection
                        sher_reduced = {n: i for n, i in sher_reduced.items()
                                        if n.lower() in selected}
                        mai_reduced = {n: s for n, s in mai_reduced.items()
                                       if n.lower() in selected}
                    for base in names:
                        vs = generate_variants(base)
                        emit("variants_planned", {"base": base, "variants": vs,
                                                  "sites": len(sher_reduced)})
                        if not vs:
                            continue
                        v_items = [(v, base) for v in vs]
                        v_done = start_sherlock(v_items, sher_reduced)
                        await maigret_worker(v_items, mai_reduced)
                        await v_done.wait()

                # Enrichment phase.
                all_rows = accounts + variant_rows
                emit("phase", {"phase": "enriching",
                               "targets": min(40, len(all_rows))})
                def on_enriched(row, data):
                    emit("enriched", {
                        "username": row["username"], "site": row["site"],
                        "url": row["url"], "variant_of": row["variant_of"],
                        "enrichment": data,
                        "verification": row.get("verification"),
                    })
                await enrich_profiles(all_rows, on_enriched)

                # Correlation phase.
                clusters = await recon_correlate(all_rows)
                emit("correlation", {"clusters": clusters})

                # Wait for the email pivot before persisting.
                if email_task is not None:
                    await email_task

                # Persist + finish.
                subject = ", ".join(names) if names else email
                total_checked = len(sher_data) + len(mai_sites)
                results = {
                    "params": params,
                    "accounts": accounts,
                    "variants": variant_rows,
                    "email": email_state,
                    "correlation": clusters,
                }
                run_id = save_run(subject, len(accounts), total_checked,
                                  results, kind="recon")
                emit("done", {
                    "history_id": run_id,
                    "found": len(accounts),
                    "variant_hits": len(variant_rows),
                    "clusters": len(clusters),
                    "email_hits": sum(
                        1 for h in email_state["holehe"] if h.get("exists")),
                })
            except Exception as exc:
                emit("fatal", {"message": f"{type(exc).__name__}: {exc}"})
            finally:
                queue.put_nowait(None)  # sentinel

        coord_task = asyncio.create_task(coordinator())

        async def event_gen():
            try:
                while True:
                    try:
                        item = await asyncio.wait_for(queue.get(), timeout=15)
                    except asyncio.TimeoutError:
                        if await request.is_disconnected():
                            break
                        yield ": keepalive\n\n"
                        continue
                    if item is None:
                        break
                    event, payload = item
                    yield f"event: {event}\ndata: {json.dumps(payload)}\n\n"
            except asyncio.CancelledError:
                coord_task.cancel()
                raise

        return StreamingResponse(
            event_gen(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.get("/api/recon/report/{run_id}")
    def recon_report(run_id: int) -> Response:
        with db_connect(DB_PATH) as conn:
            row = conn.execute(
                "SELECT ts, username, results, kind FROM runs WHERE id = ?",
                (run_id,),
            ).fetchone()
        if row is None:
            return Response("not found", status_code=404)
        ts, username, results_json, kind = row
        results = json.loads(results_json)
        if kind == "recon":
            run = {
                "subject": username,
                "ts": ts,
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "params": results.get("params") or {},
                "results": results,
            }
        else:  # plain sherlock run: render a minimal report
            run = {
                "subject": username,
                "ts": ts,
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "params": {"usernames": [username]},
                "results": {
                    "accounts": [
                        {"username": username, "site": r.get("site"),
                         "url": r.get("url"), "engines": ["sherlock"]}
                        for r in results
                    ],
                    "variants": [], "email": {}, "correlation": [],
                },
            }
        return Response(render_report(run), media_type="text/html")

    # -----------------------------------------------------------------------
    # v3: Investigations — unified pipeline, graph, dossier, monitoring
    # -----------------------------------------------------------------------

    def _subject_label(inputs: dict) -> str:
        bits = []
        if inputs.get("name"):
            bits.append(inputs["name"])
        bits.extend(inputs.get("usernames") or [])
        if inputs.get("email"):
            bits.append(inputs["email"])
        if inputs.get("phone"):
            bits.append(inputs["phone"])
        if inputs.get("domain"):
            bits.append(inputs["domain"])
        return ", ".join(bits)

    @app.get("/api/domain")
    async def domain_lookup(domain: str = Query(...)) -> JSONResponse:
        """Standalone domain/DNS/RDAP/subdomain pivot (public data, no keys)."""
        from recon.domain_pivot import domain_intel, looks_like_domain

        domain = domain.strip().lower()
        if not looks_like_domain(domain):
            return JSONResponse(
                {"error": f"'{domain}' is not a valid domain"}, status_code=400)
        return JSONResponse(await domain_intel(domain))

    @app.get("/api/brokers")
    async def broker_lookup(name: str = Query(...),
                            location: str = Query("")) -> JSONResponse:
        """Data-broker exposure for a person: which brokers likely hold their
        data, each with a direct opt-out link. Best-effort presence checks on
        the auto-checkable minority; the rest link straight to opt-out."""
        from recon.brokers import broker_exposure

        name = name.strip()
        if not name:
            return JSONResponse({"error": "a name is required"}, status_code=400)
        return JSONResponse(await broker_exposure(name, location.strip()))

    def _get_investigation(inv_id: int):
        with db_connect(DB_PATH) as conn:
            row = conn.execute(
                "SELECT id, created_at, inputs, summary, status"
                " FROM investigations WHERE id = ?",
                (inv_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "id": row[0], "created_at": row[1],
            "inputs": json.loads(row[2]),
            "summary": json.loads(row[3]) if row[3] else None,
            "status": row[4],
        }

    def _set_investigation(inv_id: int, status: str,
                           summary: dict | None = None) -> None:
        with db_connect(DB_PATH) as conn:
            if summary is not None:
                conn.execute(
                    "UPDATE investigations SET status = ?, summary = ?"
                    " WHERE id = ?",
                    (status, json.dumps(summary), inv_id),
                )
            else:
                conn.execute(
                    "UPDATE investigations SET status = ? WHERE id = ?",
                    (status, inv_id),
                )

    @app.post("/api/investigate")
    async def create_investigation(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid JSON body"}, status_code=400)
        if not isinstance(body, dict):
            return JSONResponse({"error": "JSON object expected"},
                                status_code=400)

        raw_users = body.get("usernames") or []
        if isinstance(raw_users, str):
            raw_users = re.split(r"[,\n]+", raw_users)
        usernames = [u.strip() for u in raw_users if str(u).strip()]

        inputs = {
            "name": str(body.get("name") or "").strip(),
            "usernames": usernames,
            "email": str(body.get("email") or "").strip(),
            "phone": str(body.get("phone") or "").strip(),
            "domain": str(body.get("domain") or "").strip().lower(),
            "location": str(body.get("location") or "").strip(),
            "variants": bool(body.get("variants")),
            "thorough": bool(body.get("thorough")),
            "timeout": max(1, min(120, int(body.get("timeout") or 10))),
        }
        if not (inputs["name"] or usernames or inputs["email"]
                or inputs["phone"] or inputs["domain"]):
            return JSONResponse(
                {"error": "provide at least one of: name, usernames, email,"
                          " phone, domain"},
                status_code=400,
            )
        if inputs["email"] and not is_probably_email(inputs["email"]):
            return JSONResponse(
                {"error": f"'{inputs['email']}' is not a valid email address"},
                status_code=400,
            )
        # Parity with deep recon: an email-only investigation also scans the
        # local part as a username.
        if not usernames and inputs["email"] and not inputs["name"]:
            usernames = [inputs["email"].split("@", 1)[0]]
            inputs["usernames"] = usernames
        with db_connect(DB_PATH) as conn:
            inv_id = insert_returning_id(
                conn,
                "INSERT INTO investigations (created_at, inputs, status)"
                " VALUES (?,?, 'pending')",
                (time.strftime("%Y-%m-%d %H:%M:%S"), json.dumps(inputs)),
            )
        return JSONResponse({"investigation_id": inv_id})

    @app.get("/api/investigate/{inv_id}")
    def get_investigation(inv_id: int) -> JSONResponse:
        inv = _get_investigation(inv_id)
        if inv is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        return JSONResponse(inv)

    @app.post("/api/investigate/{inv_id}/rerun")
    def rerun_investigation(inv_id: int) -> JSONResponse:
        """Clone an investigation's inputs into a fresh, unrun investigation.

        Each run stays a distinct history entry, so a subject becomes a living
        case file you can re-scan over time and diff by eye. The caller streams
        the returned id like any new investigation.
        """
        src = _get_investigation(inv_id)
        if src is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        inputs = src["inputs"]
        with db_connect(DB_PATH) as conn:
            new_id = insert_returning_id(
                conn,
                "INSERT INTO investigations (created_at, inputs, status)"
                " VALUES (?,?, 'pending')",
                (time.strftime("%Y-%m-%d %H:%M:%S"), json.dumps(inputs)),
            )
        return JSONResponse({"investigation_id": new_id, "inputs": inputs,
                             "rerun_of": inv_id})

    @app.get("/api/investigate/{inv_id}/stream")
    async def investigate_stream(request: Request, inv_id: int,
                                 nsfw: bool = Query(False)
                                 ) -> StreamingResponse:
        inv = _get_investigation(inv_id)
        if inv is None:
            return StreamingResponse(
                iter(['event: fatal\ndata: {"message": "investigation not found"}\n\n']),
                media_type="text/event-stream",
            )
        inputs = inv["inputs"]
        _set_investigation(inv_id, "running")

        queue: asyncio.Queue = asyncio.Queue()
        loop = asyncio.get_running_loop()

        sher_data = {
            n: i for n, i in SITE_DATA_ALL.items()
            if nsfw or n not in NSFW_NAMES
        }

        async def coordinator():
            def emit(event: str, payload: dict) -> None:
                queue.put_nowait((event, payload))

            try:
                summary = await run_pipeline(
                    name=inputs["name"], usernames=inputs["usernames"],
                    email=inputs["email"], phone=inputs["phone"],
                    domain=inputs.get("domain", ""),
                    location=inputs.get("location", ""),
                    variants=inputs["variants"],
                    thorough=inputs.get("thorough", False),
                    timeout=inputs["timeout"],
                    sher_data=sher_data, emit=emit, loop=loop,
                    db_path=DB_PATH,
                )
                _set_investigation(inv_id, "done", summary)
                subject = _subject_label(inputs)
                # Persist the honest headline: verification-confirmed accounts
                # only, not the raw union of every speculative "handle exists"
                # hit (which lumped base + variants + 24 name guesses together).
                from recon.confidence import bucket_counts
                all_rows = (summary["accounts"] + summary["variants"]
                            + summary["name_accounts"])
                n_found = bucket_counts(all_rows)["found"]
                run_id = save_run(subject, n_found, len(all_rows), summary,
                                  kind="investigation",
                                  investigation_id=inv_id)
                emit("saved", {"history_id": run_id,
                               "investigation_id": inv_id})
            except Exception as exc:
                _set_investigation(inv_id, "failed")
                emit("fatal", {"message": f"{type(exc).__name__}: {exc}"})
            finally:
                queue.put_nowait(None)  # sentinel

        coord_task = asyncio.create_task(coordinator())

        async def event_gen():
            yield f"event: meta_run\ndata: {json.dumps({'investigation_id': inv_id})}\n\n"
            try:
                while True:
                    try:
                        item = await asyncio.wait_for(queue.get(), timeout=15)
                    except asyncio.TimeoutError:
                        if await request.is_disconnected():
                            break
                        yield ": keepalive\n\n"
                        continue
                    if item is None:
                        break
                    event, payload = item
                    yield f"event: {event}\ndata: {json.dumps(payload)}\n\n"
            except asyncio.CancelledError:
                coord_task.cancel()
                raise

        return StreamingResponse(
            event_gen(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.get("/api/investigate/{inv_id}/graph")
    def investigate_graph(inv_id: int) -> JSONResponse:
        inv = _get_investigation(inv_id)
        if inv is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        if not inv["summary"]:
            return JSONResponse({"error": "investigation has not run yet"},
                                status_code=409)
        return JSONResponse(build_graph(inv["summary"]))

    # --- investigation intelligence: exposure / timeline / connections -------

    def _summary_rows(summary: dict) -> list[dict]:
        summary = summary or {}
        return ((summary.get("accounts") or [])
                + (summary.get("variants") or [])
                + (summary.get("name_accounts") or []))

    def _all_investigation_idents() -> list[dict]:
        """Load every stored investigation as {id, label, ident} for linking."""
        with db_connect(DB_PATH) as conn:
            rows = conn.execute(
                "SELECT id, inputs, summary FROM investigations"
            ).fetchall()
        out = []
        for rid, inputs_json, summary_json in rows:
            inputs = json.loads(inputs_json) if inputs_json else {}
            summary = json.loads(summary_json) if summary_json else {}
            out.append({
                "id": rid,
                "label": _subject_label(inputs),
                "ident": subject_identifiers(inputs, summary),
            })
        return out

    def _investigation_connections(inv: dict,
                                   others: list[dict] | None = None
                                   ) -> list[dict]:
        target_ident = subject_identifiers(inv["inputs"], inv["summary"] or {})
        if others is None:
            others = _all_investigation_idents()
        return find_connections(inv["id"], target_ident, others)

    async def _investigation_timeline(inv: dict) -> list[dict]:
        """Assemble the subject timeline (opened, scans, alerts, account ages)."""
        inputs = inv["inputs"]
        summary = inv["summary"] or {}
        events: list[dict] = [{
            "date": inv["created_at"], "kind": "opened",
            "title": "Investigation opened",
            "detail": _subject_label(inputs) or None,
        }]

        # Scan runs linked to this investigation.
        with db_connect(DB_PATH) as conn:
            run_rows = conn.execute(
                "SELECT ts, found, total FROM runs WHERE investigation_id = ?"
                " ORDER BY id",
                (inv["id"],),
            ).fetchall()
            watch_rows = conn.execute(
                "SELECT id, label, inputs FROM watchlist"
            ).fetchall()
            alert_rows = conn.execute(
                "SELECT watch_id, created_at, message FROM watch_alerts"
                " ORDER BY id"
            ).fetchall()
        for ts, found, total in run_rows:
            events.append({
                "date": ts, "kind": "scan", "title": "Scan run",
                "detail": f"{found} account(s) found across {total} site(s)",
            })

        # Watchlist alerts from watches that share a handle/email with this
        # subject (public-signature overlap, not a hard link).
        target_ident = subject_identifiers(inputs, summary)
        matched_watches = {}
        for wid, label, w_inputs_json in watch_rows:
            w_ident = subject_identifiers(
                json.loads(w_inputs_json) if w_inputs_json else {}, {})
            if (target_ident["handles"] & w_ident["handles"]
                    or target_ident["emails"] & w_ident["emails"]):
                matched_watches[wid] = label
        for wid, created_at, message in alert_rows:
            if wid in matched_watches:
                events.append({
                    "date": created_at, "kind": "alert", "title": message,
                    "detail": f"watch: {matched_watches[wid]}",
                })

        # Public account-creation dates (GitHub API, best-effort, no key).
        rows = _summary_rows(summary)
        try:
            dates = await account_creation_dates(rows)
        except Exception:
            dates = {}
        events.extend(account_events(rows, dates))

        return build_timeline(events)

    @app.get("/api/investigate/{inv_id}/exposure")
    def investigate_exposure(inv_id: int) -> JSONResponse:
        inv = _get_investigation(inv_id)
        if inv is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        return JSONResponse({
            "investigation_id": inv_id,
            "status": inv["status"],
            "exposure": exposure_summary(inv["summary"] or {}),
        })

    @app.get("/api/investigate/{inv_id}/timeline")
    async def investigate_timeline(inv_id: int) -> JSONResponse:
        inv = _get_investigation(inv_id)
        if inv is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        timeline = await _investigation_timeline(inv)
        return JSONResponse({
            "investigation_id": inv_id,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "timeline": timeline,
        })

    @app.get("/api/investigate/{inv_id}/connections")
    def investigate_connections(inv_id: int) -> JSONResponse:
        inv = _get_investigation(inv_id)
        if inv is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        others = _all_investigation_idents()
        connections = _investigation_connections(inv, others)
        return JSONResponse({
            "investigation_id": inv_id,
            "checked": max(0, len(others) - 1),
            "connections": connections,
        })

    @app.get("/api/investigate/{inv_id}/report")
    async def investigate_report(inv_id: int) -> Response:
        inv = _get_investigation(inv_id)
        if inv is None:
            return Response("not found", status_code=404)
        if not inv["summary"]:
            return Response("investigation has not run yet", status_code=409)
        # Enrich the dossier with the timeline + cross-case connections.
        try:
            timeline = await _investigation_timeline(inv)
        except Exception:
            timeline = None
        try:
            connections = _investigation_connections(inv)
        except Exception:
            connections = None
        return Response(
            render_dossier(inv, inv["summary"], timeline=timeline,
                           connections=connections),
            media_type="text/html",
        )

    # --- watchlist + alerts ---------------------------------------------------

    @app.get("/api/watchlist")
    def list_watchlist() -> list[dict]:
        with db_connect(DB_PATH) as conn:
            rows = conn.execute(
                "SELECT id, created_at, label, inputs, interval_hours,"
                " last_run_at, enabled FROM watchlist ORDER BY id DESC"
            ).fetchall()
            counts = dict(conn.execute(
                "SELECT watch_id, COUNT(*) FROM watch_alerts GROUP BY watch_id"
            ).fetchall())
        return [
            {"id": r[0], "created_at": r[1], "label": r[2],
             "inputs": json.loads(r[3]), "interval_hours": r[4],
             "last_run_at": r[5], "enabled": bool(r[6]),
             "alerts": counts.get(r[0], 0)}
            for r in rows
        ]

    @app.post("/api/watchlist")
    async def create_watch(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid JSON body"}, status_code=400)
        inputs = body.get("inputs") or {}
        if isinstance(inputs.get("usernames"), str):
            inputs["usernames"] = [
                u.strip() for u in re.split(r"[,\n]+", inputs["usernames"])
                if u.strip()
            ]
        if not (inputs.get("usernames") or inputs.get("email")
                or inputs.get("name")):
            return JSONResponse(
                {"error": "watch needs usernames, email, or name"},
                status_code=400,
            )
        label = str(body.get("label") or "").strip() or (
            ", ".join(inputs.get("usernames") or [])
            or inputs.get("email") or inputs.get("name"))
        interval = max(recon_monitor.MIN_INTERVAL_HOURS,
                       int(body.get("interval_hours")
                           or recon_monitor.DEFAULT_INTERVAL_HOURS))
        with db_connect(DB_PATH) as conn:
            watch_id = insert_returning_id(
                conn,
                "INSERT INTO watchlist"
                " (created_at, label, inputs, interval_hours, enabled)"
                " VALUES (?,?,?,?,1)",
                (time.strftime("%Y-%m-%d %H:%M:%S"), label,
                 json.dumps(inputs), interval),
            )
        return JSONResponse({"watch_id": watch_id, "label": label,
                             "interval_hours": interval})

    @app.post("/api/watchlist/{watch_id}/toggle")
    def toggle_watch(watch_id: int) -> JSONResponse:
        with db_connect(DB_PATH) as conn:
            row = conn.execute(
                "SELECT enabled FROM watchlist WHERE id = ?", (watch_id,)
            ).fetchone()
            if row is None:
                return JSONResponse({"error": "not found"}, status_code=404)
            new_state = 0 if row[0] else 1
            conn.execute("UPDATE watchlist SET enabled = ? WHERE id = ?",
                         (new_state, watch_id))
        return JSONResponse({"id": watch_id, "enabled": bool(new_state)})

    @app.delete("/api/watchlist/{watch_id}")
    def delete_watch(watch_id: int) -> JSONResponse:
        with db_connect(DB_PATH) as conn:
            conn.execute("DELETE FROM watch_alerts WHERE watch_id = ?",
                         (watch_id,))
            cur = conn.execute("DELETE FROM watchlist WHERE id = ?",
                               (watch_id,))
        if cur.rowcount == 0:
            return JSONResponse({"error": "not found"}, status_code=404)
        return JSONResponse({"deleted": watch_id})

    @app.get("/api/alerts")
    def list_alerts(unseen: bool = Query(False)) -> list[dict]:
        sql = (
            "SELECT a.id, a.watch_id, a.created_at, a.kind, a.message,"
            " a.data, a.seen, w.label FROM watch_alerts a"
            " LEFT JOIN watchlist w ON w.id = a.watch_id"
        )
        if unseen:
            sql += " WHERE a.seen = 0"
        sql += " ORDER BY a.id DESC LIMIT 100"
        with db_connect(DB_PATH) as conn:
            rows = conn.execute(sql).fetchall()
        return [
            {"id": r[0], "watch_id": r[1], "created_at": r[2], "kind": r[3],
             "message": r[4], "data": json.loads(r[5]) if r[5] else None,
             "seen": bool(r[6]), "watch_label": r[7]}
            for r in rows
        ]

    @app.post("/api/alerts/mark_seen")
    async def mark_alerts_seen(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except Exception:
            body = {}
        ids = (body or {}).get("ids") or []
        with db_connect(DB_PATH) as conn:
            if ids:
                conn.execute(
                    f"UPDATE watch_alerts SET seen = 1 WHERE id IN"
                    f" ({','.join('?' for _ in ids)})",
                    [int(i) for i in ids],
                )
            else:
                conn.execute("UPDATE watch_alerts SET seen = 1 WHERE seen = 0")
        return JSONResponse({"ok": True})

    # The background watchlist monitor is started from the app lifespan handler
    # (see ``lifespan`` above), which also cancels it cleanly on shutdown.

else:

    @app.get("/api/recon/stream")
    async def recon_stream_unavailable() -> StreamingResponse:
        return StreamingResponse(
            iter(['event: fatal\ndata: {"message": "recon package unavailable"}\n\n']),
            media_type="text/event-stream",
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
