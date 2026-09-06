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
import socket
import logging
import os
import re
import secrets
import threading
import time
import weakref
from contextlib import asynccontextmanager
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
# httpx logs every request at INFO (~800 lines per investigation); Scrapling
# installs a second handler that duplicated every line.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("scrapling").propagate = False


class _InvestigationIdFilter(logging.Filter):
    """Prefix every line logged while a pipeline runs with `inv=<id>`, so
    router/enrichment/detector lines can be tied to a case. The pipeline's
    own lines carry the prefix already."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            from recon.pipeline import INV_ID
            inv = INV_ID.get(None)
        except Exception:
            inv = None
        if inv is not None and record.name != "recon.pipeline" \
                and not str(record.msg).startswith("inv="):
            record.msg = f"inv={inv} {record.msg}"
        return True


for _h in logging.getLogger().handlers:
    _h.addFilter(_InvestigationIdFilter())
# Files this process creates (the SQLite database and its WAL, caches, logs)
# hold subject data; keep them private to this user.
os.umask(0o077)

from fastapi import FastAPI, Query, Request
from fastapi.responses import (
    FileResponse,
    JSONResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)
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
    from recon.dossier import render_dossier
    from recon.email_pivot import holehe_available
    from recon.exposure import exposure_summary
    from recon.graph import build_graph
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
# SHERLOCK_DB_PATH lets tests and multi-instance setups point at their own
# SQLite file (ignored when DATABASE_URL selects Postgres).
DB_PATH = Path(os.environ.get("SHERLOCK_DB_PATH") or (BASE_DIR / "history.db"))
STATIC_DIR = BASE_DIR / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start (and cleanly stop) the background watchlist monitor."""
    monitor_task = None
    try:
        sweep_stuck_investigations()
    except Exception:
        logging.getLogger("app").exception("startup sweep failed")
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
        if not dbconn.IS_POSTGRES:
            # Fold the write-ahead log back into the main file so a plain copy
            # of history.db is complete (the WAL held ~1 MB of unmerged data).
            # Off the event loop: it can wait up to the busy timeout.
            def _checkpoint():
                with db_connect(DB_PATH) as conn:
                    return conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            try:
                busy, log_pages, done = await asyncio.to_thread(_checkpoint)
                if busy:
                    logging.getLogger("app").warning(
                        "WAL checkpoint could not complete (busy); %d pages remain", log_pages)
                else:
                    logging.getLogger("app").info("WAL checkpoint: %d pages folded", done)
            except Exception:
                logging.getLogger("app").warning("WAL checkpoint failed", exc_info=True)


app = FastAPI(title="sherlock-web", lifespan=lifespan)

# ---------------------------------------------------------------------------
# Request protection for a local, unauthenticated API
# ---------------------------------------------------------------------------
# The console runs unauthenticated on loopback. Without these checks any web
# page the analyst visits — or, with the headless tier, any page the tool
# itself renders — could POST to it (create investigations, plant recurring
# watches, delete them) and DNS rebinding could read every stored case. See
# docs/audit/2026-09-06/security.md F-1, F-8, F-10, F-13.

APP_STARTED_AT = time.time()


def _app_commit() -> str:
    sha = os.environ.get("GIT_SHA") or os.environ.get("RAILWAY_GIT_COMMIT_SHA")
    if sha:
        return sha[:12]
    try:
        head = (BASE_DIR / ".git" / "HEAD").read_text().strip()
        if head.startswith("ref: "):
            return (BASE_DIR / ".git" / head[5:]).read_text().strip()[:12]
        return head[:12]
    except OSError:
        return "unknown"


APP_COMMIT = _app_commit()
MAX_USERNAMES_PER_REQUEST = 20
MAX_BODY_BYTES = 64 * 1024
MAX_ALERT_IDS = 500
_JSON_POST_PATHS = ("/api/investigate", "/api/watchlist", "/api/alerts/mark_seen")


def _raw_host(request: Request) -> str:
    """The Host header as the browser sent it (lower-cased, no userinfo
    tricks): `evil.example@localhost` must not parse as `localhost`."""
    host = request.headers.get("host", "").strip().lower()
    if "@" in host or "/" in host or " " in host:
        return ""
    return host


def _host_only(netloc: str) -> str:
    """Hostname without port; IPv6 brackets removed. A bare IPv6 address
    (`::1`, no brackets, no port) is returned whole — splitting it at the
    first colon produced "", which then matched the empty host that the
    userinfo trick (`evil.example@localhost`) reduces to."""
    netloc = netloc.strip().lower()
    if netloc.startswith("["):
        return netloc[1:netloc.find("]")] if "]" in netloc else ""
    if netloc.count(":") > 1:
        return netloc
    return netloc.split(":", 1)[0]


def _allowed_hosts() -> set:
    raw = os.environ.get("APP_ALLOWED_HOSTS")
    if raw is None:
        # A deployment (password gate configured) serves on a public hostname we
        # cannot know; a local run is loopback only.
        return {"*"} if os.environ.get("APP_PASSWORD") else {"localhost", "127.0.0.1", "::1"}
    return {_host_only(h) for h in raw.split(",") if h.strip()} - {""}


ALLOWED_HOSTS = _allowed_hosts()
if "*" in ALLOWED_HOSTS:
    logging.getLogger("app").warning(
        "APP_ALLOWED_HOSTS is open (*): set it to the public hostname of this deployment")


# GETs that only read the database. Everything else under /api/ either writes
# or starts network activity toward third parties (scans, pivots, reports that
# re-query GitHub/Nominatim/Cavalier) and gets the cross-site guard. An
# allow-list, not a deny-list: a new endpoint is protected by default.
_PURE_READ_RE = re.compile(
    r"^/api/(?:history(?:/\d+)?|sites|health(?:/sources)?|watchlist|alerts|godseye/status"
    r"|investigate/\d+(?:/graph|/exposure|/connections)?)$")


def _is_pure_read(method: str, path: str) -> bool:
    return method == "GET" and bool(_PURE_READ_RE.match(path))


def _cross_site_reason(request: Request) -> str | None:
    """Why this /api request must be refused as cross-site, or None."""
    site = request.headers.get("sec-fetch-site", "").lower()
    if site in ("cross-site", "same-site"):
        return f"Sec-Fetch-Site is {site}"
    origin = request.headers.get("origin")
    if origin and origin != "null":
        try:
            from urllib.parse import urlsplit
            onetloc = (urlsplit(origin).netloc or "").lower()
        except Exception:
            onetloc = ""
        # Host and port must both match: a page served from localhost:4173
        # (God's Eye) is not this console on localhost:8420.
        if not onetloc or onetloc != _raw_host(request):
            return f"Origin {origin} is not this console"
    elif origin == "null":
        return "opaque Origin"
    return None


@app.middleware("http")
async def request_protection(request: Request, call_next):
    path = request.url.path
    # 1. Host header allow-list (DNS rebinding sends a foreign Host to our port).
    host = _host_only(_raw_host(request))
    if "*" not in ALLOWED_HOSTS and (not host or host not in ALLOWED_HOSTS):
        return JSONResponse({"error": "unexpected Host header"}, status_code=400)
    if path.startswith("/api/"):
        # 2. No cross-site writes, scan starts or third-party pivots.
        if not _is_pure_read(request.method, path):
            why = _cross_site_reason(request)
            if why:
                return JSONResponse({"error": f"cross-site request refused ({why})"},
                                    status_code=403)
        # 3. Bounded bodies, JSON only where JSON is expected.
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > MAX_BODY_BYTES:
            return JSONResponse({"error": "request body too large"}, status_code=413)
        if request.method == "POST" and any(path.startswith(p) for p in _JSON_POST_PATHS) \
                and length and length != "0":
            ctype = request.headers.get("content-type", "").split(";")[0].strip().lower()
            if ctype != "application/json":
                return JSONResponse({"error": "Content-Type must be application/json"},
                                    status_code=415)
    response = await call_next(request)
    # 4. Security headers; a CSP on every HTML document we serve.
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-Frame-Options", "DENY")
    ctype = response.headers.get("content-type", "")
    if ctype.startswith("text/html"):
        response.headers.setdefault("Content-Security-Policy", _content_security_policy())
    return response


def _content_security_policy() -> str:
    frame_src = "'none'"
    try:
        from urllib.parse import urlsplit
        g = urlsplit(GODSEYE_URL)
        if g.scheme and g.netloc:
            frame_src = f"{g.scheme}://{g.netloc}"
    except Exception:
        pass
    return ("default-src 'self'; script-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com data:; "
            "img-src * data: blob:; connect-src 'self'; "
            f"frame-src {frame_src}; frame-ancestors 'none'; base-uri 'self'; "
            "form-action 'self'; object-src 'none'")


# ---------------------------------------------------------------------------
# Optional access gate (Railway deployments etc.)
# ---------------------------------------------------------------------------

# If APP_PASSWORD is set, every route (including / and the SSE stream) requires
# HTTP Basic auth with that password (any username). Unset = fully open.
APP_PASSWORD = os.environ.get("APP_PASSWORD") or None


def _is_authorized(request: Request) -> bool:
    if APP_PASSWORD is None:
        return True
    auth = request.headers.get("authorization", "")
    if auth.startswith("Basic "):
        try:
            decoded = base64.b64decode(auth[6:], validate=True).decode("utf-8")
            _, _, password = decoded.partition(":")
            return secrets.compare_digest(password, APP_PASSWORD)
        except Exception:
            return False
    return False


@app.middleware("http")
async def basic_auth_gate(request: Request, call_next):
    # /api/health stays reachable for the platform health check (it answers
    # with liveness only when unauthenticated).
    if APP_PASSWORD is not None and request.url.path != "/api/health":
        authorized = _is_authorized(request)
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

# Sherlock's site list. The library's default downloads data.json and an
# exclusions list from GitHub at import time with no timeout, so the app could
# not start offline and hung on a slow network. Loader modes
# (SHERLOCK_SITES_SOURCE):
#   auto (default)  a cached copy of the live list, refreshed at most every
#                   SHERLOCK_SITES_MAX_AGE_H hours with a 5 s timeout; on any
#                   failure the stale cache, then the data.json bundled with the
#                   installed package. Never blocks boot for more than the timeout.
#   bundled         the installed package's data.json only (deterministic; tests).
#   remote          the library's own live download (untimed) — kept for parity.
# Exclusions (dead / false-positive-prone sites) come from the live list when it
# was fetched, else from the vendored snapshot recon/data/sherlock-exclusions.txt.
_SITES_CACHE_DIR = BASE_DIR / "recon" / "data" / "cache"
_VENDORED_EXCLUSIONS = BASE_DIR / "recon" / "data" / "sherlock-exclusions.txt"
_SITES_FETCH_TIMEOUT_S = 5.0
_SITES_MIN_COUNT = 200          # a real Sherlock list has ~400 entries


def _sites_max_age_s() -> float:
    try:
        return float(os.environ.get("SHERLOCK_SITES_MAX_AGE_H") or "168") * 3600
    except ValueError:
        return 168 * 3600


def _read_exclusions(path: Path) -> set:
    try:
        return {ln.strip().lower() for ln in path.read_text().splitlines()
                if ln.strip() and not ln.startswith("#")}
    except OSError:
        return set()


def _fetch_text_with_timeout(url: str) -> str:
    import httpx
    r = httpx.get(url, timeout=_SITES_FETCH_TIMEOUT_S, follow_redirects=True)
    r.raise_for_status()
    return r.text


def _sites_from_json_text(text: str) -> list:
    """Parse a Sherlock data.json payload into site objects, or raise.

    Validates the *shape* before anything is cached: valid JSON of the wrong
    shape (a list, a string, a dict of non-sites) used to pass a bare
    ``json.loads`` guard, get cached with a fresh mtime, and then make every
    boot for a week fail inside ``SitesInformation``.
    """
    import tempfile
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("site list is not a JSON object")
    entries = {k: v for k, v in data.items() if k != "$schema"}
    if len(entries) < _SITES_MIN_COUNT or not all(
            isinstance(v, dict) and isinstance(v.get("url"), str) for v in entries.values()):
        raise ValueError(f"site list has the wrong shape ({len(entries)} entries)")
    # SitesInformation insists on a path ending in .json; load from a temp file
    # so a bad payload can never poison the cache.
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        fh.write(text)
        tmp = fh.name
    try:
        # honor_exclusions=False: the library would fetch the list remotely.
        return list(SitesInformation(data_file_path=tmp, honor_exclusions=False))
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _load_sherlock_sites(source: str | None = None, cache_dir: Path | None = None,
                         fetch=None, now: float | None = None):
    """Return ``(sites, label)`` per the modes documented above.

    ``auto``: a cached copy of the live list, refreshed with a timeout when
    older than SHERLOCK_SITES_MAX_AGE_H; on any failure the stale cache, then
    the bundled copy. Every payload is validated by actually loading it before
    it is cached; the cache is written atomically; a cache that fails to load
    is deleted and never blocks boot. A fetched list is used even when the
    cache directory cannot be written. Parameters exist so tests can exercise
    every path without the network.
    """
    source = (source or os.environ.get("SHERLOCK_SITES_SOURCE") or "auto").strip().lower()
    log = logging.getLogger("app")
    import sherlock_project
    bundled = Path(sherlock_project.__file__).resolve().parent / "resources" / "data.json"
    vendored_excl = _read_exclusions(_VENDORED_EXCLUSIONS)

    def load_bundled():
        return _sites_from_json_text(bundled.read_text()), vendored_excl, "bundled"

    if source == "remote":
        return list(SitesInformation()), "remote"
    if source == "bundled":
        sites, excl, label = load_bundled()
    else:
        from sherlock_project.sites import EXCLUSIONS_URL, MANIFEST_URL
        cache_dir = cache_dir or _SITES_CACHE_DIR
        data_file = cache_dir / "sherlock-data.json"
        excl_file = cache_dir / "sherlock-exclusions.txt"
        now = time.time() if now is None else now
        sites = excl = None
        label = "cache"
        age = (now - data_file.stat().st_mtime) if data_file.exists() else None
        fresh = age is not None and 0 <= age < _sites_max_age_s()
        if not fresh:
            fetch = fetch or _fetch_text_with_timeout
            try:
                text = fetch(MANIFEST_URL)
                sites = _sites_from_json_text(text)          # validated before caching
                label = "remote"
                excl_text = None
                try:
                    excl_text = fetch(EXCLUSIONS_URL)
                except Exception as exc:                     # exclusions are best-effort
                    log.info("sherlock exclusions refresh failed (%s)", exc)
                try:
                    cache_dir.mkdir(parents=True, exist_ok=True)
                    tmp = data_file.with_suffix(".json.tmp")
                    tmp.write_text(text)
                    os.replace(tmp, data_file)                # atomic: never a torn file
                    if excl_text is not None:
                        excl_file.write_text(excl_text)
                    label = "remote-cached"
                except OSError as exc:
                    log.warning("sherlock site list fetched but not cached (%s)", exc)
                excl = ({ln.strip().lower() for ln in excl_text.splitlines()
                         if ln.strip() and not ln.startswith("#")}
                        if excl_text else vendored_excl)
            except Exception as exc:
                log.warning("sherlock site list refresh failed (%s); using %s", exc,
                            "the stale cache" if data_file.exists() else "the bundled copy")
        if sites is None and data_file.exists():
            try:
                sites = _sites_from_json_text(data_file.read_text())
                excl = _read_exclusions(excl_file) or vendored_excl
                label = "cache"
            except Exception as exc:
                log.warning("cached sherlock site list unreadable (%s); deleting it", exc)
                try:
                    data_file.unlink()
                except OSError:
                    pass
                sites = None
        if sites is None:
            sites, excl, label = load_bundled()
    before = len(sites)
    sites = [st for st in sites if st.name.lower() not in excl]
    log.info("sherlock site list: %d sites from %s source (%d excluded)",
             len(sites), label, before - len(sites))
    return sites, label


_ALL_SITES, SITES_SOURCE = _load_sherlock_sites()
SITE_DATA_ALL = {s.name: s.information for s in _ALL_SITES}
if RECON_AVAILABLE:
    # robots-denied hosts are never scanned by any path — including the classic
    # quick scan and the site picker (the pipeline filters again with reasons).
    from recon import policy as _policy
    SITE_DATA_ALL, _DENIED_SHERLOCK_SITES = _policy.filter_site_mapping(
        SITE_DATA_ALL, recon_engines.sherlock_url_templates)
    if _DENIED_SHERLOCK_SITES:
        logging.getLogger("app").info(
            "sherlock sites on robots-denied hosts excluded everywhere: %s",
            ", ".join(_DENIED_SHERLOCK_SITES))
NSFW_NAMES = {s.name for s in _ALL_SITES if s.is_nsfw}


# ---------------------------------------------------------------------------
# SQLite history
# ---------------------------------------------------------------------------

def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def sweep_stuck_investigations() -> int:
    """Mark investigations left in ``running`` by a previous process as
    ``interrupted``. Runs once at startup. Before this, a restart mid-run left
    rows in ``running`` forever (7 of 53 rows in one database) and every
    downstream endpoint answered 409 for them."""
    stale = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - 86400))
    with db_connect(DB_PATH) as conn:
        cur = conn.execute(
            "UPDATE investigations SET status = 'interrupted', finished_at = ?,"
            " error = COALESCE(error, 'process restarted while the"
            " investigation was running') WHERE status = 'running'",
            (_now(),),
        )
        n = cur.rowcount or 0
        # A row created but never streamed within a day is not going to be.
        cur = conn.execute(
            "UPDATE investigations SET status = 'interrupted', finished_at = ?,"
            " error = 'never streamed within 24 hours of creation'"
            " WHERE status = 'pending' AND created_at < ?",
            (_now(), stale),
        )
        n += cur.rowcount or 0
    if n:
        logging.getLogger("app").warning(
            "marked %d investigation(s) interrupted (stale running/pending rows)", n)
    return n


def _init_db() -> None:
    """Create or upgrade the schema through the versioned migration list
    (dbschema.MIGRATIONS). The monitor and router tables are created first so
    the index migration can see them."""
    import dbschema

    def extra(conn):
        if RECON_AVAILABLE:
            recon_monitor.init_tables(conn)
        recon_router.init_tables(conn)

    with db_connect(DB_PATH) as conn:
        version = dbschema.migrate(conn, extra_tables=extra)
    logging.getLogger("app").info("database schema v%d (%s)", version,
                                  "postgres" if dbconn.IS_POSTGRES else DB_PATH)


_init_db()
if not dbconn.IS_POSTGRES:
    try:
        os.chmod(DB_PATH, 0o600)
    except OSError:
        pass


def _resolve_run_results(results_json: str, kind: str, investigation_id):
    """A history row's results. Investigation rows written after 2026-09-06
    hold only a pointer (`{"investigation_id": n, "slim": true}`); the summary
    is read from the investigations table so the API shape is unchanged.
    Older rows that still carry the full summary are returned as they are."""
    try:
        results = json.loads(results_json)
    except Exception:
        return {}
    if kind == "investigation" and isinstance(results, dict) and results.get("slim"):
        with db_connect(DB_PATH) as conn:
            row = conn.execute("SELECT summary FROM investigations WHERE id = ?",
                               (investigation_id,)).fetchone()
        if row and row[0]:
            try:
                return json.loads(row[0])
            except Exception:
                return {}
        return {}
    return results


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
            "results": _resolve_run_results(row[5], row[6], row[7]),
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
    if len(names) > MAX_USERNAMES_PER_REQUEST:
        return JSONResponse(
            {"error": f"at most {MAX_USERNAMES_PER_REQUEST} usernames per scan"},
            status_code=400)

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

    from pydantic import BaseModel, Field, ValidationError

    class InvestigateBody(BaseModel):
        name: str = ""
        usernames: str | list[str] = Field(default_factory=list)
        email: str = ""
        phone: str = ""
        domain: str = ""
        location: str = ""
        variants: bool = False
        thorough: bool = False
        timeout: int = 10

    class WatchInputs(BaseModel):
        usernames: str | list[str] = Field(default_factory=list)
        email: str = ""
        name: str = ""

    class WatchBody(BaseModel):
        inputs: WatchInputs = Field(default_factory=WatchInputs)
        label: str = ""
        interval_hours: int | None = None

    class MarkSeenBody(BaseModel):
        ids: list[int] = Field(default_factory=list)

    def _split_usernames(raw) -> list[str]:
        if isinstance(raw, str):
            raw = re.split(r"[,\n]+", raw)
        return [str(u).strip() for u in raw if str(u).strip()]

    async def _parse_body(request: Request, model, allow_empty: bool = False):
        """(model instance, None) or (None, 400 JSON). Malformed bodies used
        to raise inside the handler and answer 500 with a stack trace."""
        try:
            raw = await request.body()
        except Exception:
            return None, JSONResponse({"error": "unreadable body"}, status_code=400)
        # Chunked uploads carry no Content-Length, so the middleware could not
        # size or type them; enforce both here as well.
        if len(raw) > MAX_BODY_BYTES:
            return None, JSONResponse({"error": "request body too large"}, status_code=413)
        if raw.strip():
            ctype = request.headers.get("content-type", "").split(";")[0].strip().lower()
            if ctype != "application/json":
                return None, JSONResponse({"error": "Content-Type must be application/json"},
                                          status_code=415)
        try:
            data = json.loads(raw) if raw.strip() else ({} if allow_empty else None)
        except Exception:
            return None, JSONResponse({"error": "invalid JSON body"}, status_code=400)
        if data is None or not isinstance(data, dict):
            return None, JSONResponse({"error": "JSON object expected"}, status_code=400)
        try:
            return model.model_validate(data), None
        except ValidationError as exc:
            first = exc.errors()[0] if exc.errors() else {}
            loc = ".".join(str(x) for x in first.get("loc", ())) or "body"
            return None, JSONResponse(
                {"error": f"invalid field {loc}: {first.get('msg', 'invalid')}"},
                status_code=400)

    @app.delete("/api/investigate/{inv_id}")
    def delete_investigation(inv_id: int) -> JSONResponse:
        """Remove a case and its history rows (subject data retention, F-5)."""
        with db_connect(DB_PATH) as conn:
            row = conn.execute("SELECT id, status FROM investigations WHERE id = ?",
                               (inv_id,)).fetchone()
            if row is None:
                return JSONResponse({"error": "not found"}, status_code=404)
            if row[1] == "running":
                # The pipeline would keep running and re-create an orphan
                # history row; stop the stream first (it cancels the run).
                return JSONResponse({"error": "investigation is running; stop it first",
                                     "status": "running"}, status_code=409)
            conn.execute("DELETE FROM runs WHERE investigation_id = ?", (inv_id,))
            conn.execute("DELETE FROM investigations WHERE id = ?", (inv_id,))
        return JSONResponse({"deleted": inv_id})

    @app.delete("/api/history/{run_id}")
    def delete_history_run(run_id: int) -> JSONResponse:
        with db_connect(DB_PATH) as conn:
            row = conn.execute("SELECT id FROM runs WHERE id = ?", (run_id,)).fetchone()
            if row is None:
                return JSONResponse({"error": "not found"}, status_code=404)
            conn.execute("DELETE FROM runs WHERE id = ?", (run_id,))
        return JSONResponse({"deleted": run_id})

    # The v2 "/api/recon/stream" endpoint — a 350-line frozen copy of the
    # investigation pipeline with no frontend caller, no adaptive routing and no
    # policy filtering — was removed on 2026-09-06 (target architecture §3).
    # /api/recon/report/{run_id} stays so stored kind="recon" history rows
    # still render.

    @app.get("/api/recon/report/{run_id}")
    def recon_report(run_id: int) -> Response:
        with db_connect(DB_PATH) as conn:
            row = conn.execute(
                "SELECT ts, username, results, kind, investigation_id FROM runs WHERE id = ?",
                (run_id,),
            ).fetchone()
        if row is None:
            return Response("not found", status_code=404)
        ts, username, results_json, kind, inv_id = row
        if kind == "investigation":
            # The v2 renderer never understood investigation summaries (it
            # 500'd on them); the dossier is the report for these rows.
            if inv_id is None:
                return JSONResponse({"error": "not found"}, status_code=404)
            return RedirectResponse(url=f"/api/investigate/{inv_id}/report", status_code=307)
        results = _resolve_run_results(results_json, kind, inv_id)
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

    # Investigation lifecycle: pending → running → done | failed | cancelled |
    # interrupted. Terminal states carry finished_at and (except done) an error
    # message, so a stored case can always say what happened to it.
    TERMINAL_STATUSES = ("done", "failed", "cancelled", "interrupted")

    def _set_investigation(inv_id: int, status: str,
                           summary: dict | None = None, *,
                           error: str | None = None) -> None:
        sets, params = ["status = ?"], [status]
        if summary is not None:
            sets.append("summary = ?")
            params.append(json.dumps(summary))
        if error is not None:
            sets.append("error = ?")
            params.append(error[:2000])
        if status in TERMINAL_STATUSES:
            sets.append("finished_at = ?")
            params.append(_now())
        params.append(inv_id)
        with db_connect(DB_PATH) as conn:
            conn.execute(
                f"UPDATE investigations SET {', '.join(sets)} WHERE id = ?",
                tuple(params),
            )

    def _claim_investigation(inv_id: int) -> bool:
        """Atomically move ``pending`` → ``running``. False when the row is in
        any other state, so two streams (or a browser reconnect) can never start
        the same investigation twice."""
        with db_connect(DB_PATH) as conn:
            cur = conn.execute(
                "UPDATE investigations SET status = 'running', started_at = ?"
                " WHERE id = ? AND status = 'pending'",
                (_now(), inv_id),
            )
            return bool(cur.rowcount)

    # At most this many investigations run concurrently; further streams wait
    # and announce it. Two full runs already open ~600 outbound connections.
    MAX_CONCURRENT_INVESTIGATIONS = max(1, int(
        os.environ.get("RECON_MAX_CONCURRENT_INVESTIGATIONS") or "2"))
    _inv_semaphores: "weakref.WeakKeyDictionary" = weakref.WeakKeyDictionary()

    def _investigation_semaphore() -> asyncio.Semaphore:
        # One semaphore per event loop, keyed by the loop object itself: an
        # id(loop) key was reused by later loops in tests and raised
        # "bound to a different event loop" on a contended acquire.
        loop = asyncio.get_running_loop()
        sem = _inv_semaphores.get(loop)
        if sem is None:
            sem = asyncio.Semaphore(MAX_CONCURRENT_INVESTIGATIONS)
            _inv_semaphores[loop] = sem
        return sem

    def _set_status_safely(inv_id: int, status: str, **kw) -> bool:
        """A terminal-status write must never turn into a different failure:
        a DB error here used to replace the CancelledError (row left `running`)
        or skip the `fatal` event. Logged, never raised."""
        try:
            _set_investigation(inv_id, status, **kw)
            return True
        except Exception:
            logging.getLogger("app").exception(
                "inv=%d could not record status %s", inv_id, status)
            return False

    async def run_investigation(inv_id: int, inputs: dict, sher_data: dict,
                                emit, loop) -> None:
        """Run one claimed investigation to a terminal state.

        Every exit path writes a terminal status: ``done`` with the summary;
        ``failed`` with the exception, which is also logged (before this the
        browser got the message and the server kept nothing); ``cancelled``
        when the client disconnected (``CancelledError`` is a ``BaseException``
        and used to slip past ``except Exception``, stranding the row in
        ``running``).
        """
        log = logging.getLogger("app")
        sem = _investigation_semaphore()
        if sem.locked():
            emit("queued", {"max_concurrent": MAX_CONCURRENT_INVESTIGATIONS})
        started = time.monotonic()
        # The pipeline emits `done` itself and the browser closes the stream on
        # it. Hold that event until the summary is safely on disk, so a failed
        # write can still surface as `fatal` instead of a row left `running`.
        held: dict = {}

        def emit_gated(event: str, payload: dict) -> None:
            if event == "done":
                held["done"] = payload
                return
            emit(event, payload)

        try:
            async with sem:
                log.info("inv=%d start usernames=%s name=%r email=%s",
                         inv_id, inputs.get("usernames"), inputs.get("name"),
                         "yes" if inputs.get("email") else "no")
                summary = await run_pipeline(
                    name=inputs["name"], usernames=inputs["usernames"],
                    email=inputs["email"], phone=inputs["phone"],
                    domain=inputs.get("domain", ""),
                    location=inputs.get("location", ""),
                    variants=inputs["variants"],
                    thorough=inputs.get("thorough", False),
                    timeout=inputs["timeout"],
                    sher_data=sher_data, emit=emit_gated, loop=loop,
                    db_path=DB_PATH, investigation_id=inv_id,
                )
            _set_investigation(inv_id, "done", summary)     # may raise → failed
            if "done" in held:
                emit("done", held["done"])
            from recon.confidence import bucket_counts
            all_rows = (summary["accounts"] + summary["variants"]
                        + summary["name_accounts"])
            n_found = bucket_counts(all_rows)["found"]
            log.info("inv=%d done in %.1fs found=%d rows=%d", inv_id,
                     time.monotonic() - started, n_found, len(all_rows))
            try:
                # Persist the honest headline: verification-confirmed accounts
                # only, not the raw union of every speculative "handle exists"
                # hit. A failure here must not relabel a finished run. The
                # summary itself lives once, in investigations.summary — the
                # history row only points at it (it used to be stored twice).
                run_id = save_run(_subject_label(inputs), n_found, len(all_rows),
                                  {"investigation_id": inv_id, "slim": True},
                                  kind="investigation", investigation_id=inv_id)
                emit("saved", {"history_id": run_id, "investigation_id": inv_id})
            except Exception:
                log.exception("inv=%d finished but its history row failed", inv_id)
        except asyncio.CancelledError:
            _set_status_safely(inv_id, "cancelled",
                               error="client disconnected before the run finished")
            log.info("inv=%d cancelled after %.1fs (client disconnected)",
                     inv_id, time.monotonic() - started)
            raise
        except Exception as exc:
            log.exception("inv=%d failed after %.1fs", inv_id,
                          time.monotonic() - started)
            _set_status_safely(inv_id, "failed",
                               error=f"{type(exc).__name__}: {exc}")
            emit("fatal", {"message": f"{type(exc).__name__}: {exc}"})

    @app.post("/api/investigate")
    async def create_investigation(request: Request) -> JSONResponse:
        body, err = await _parse_body(request, InvestigateBody)
        if err is not None:
            return err
        usernames = _split_usernames(body.usernames)
        if len(usernames) > MAX_USERNAMES_PER_REQUEST:
            return JSONResponse(
                {"error": f"at most {MAX_USERNAMES_PER_REQUEST} usernames per investigation"},
                status_code=400)

        inputs = {
            "name": body.name.strip(),
            "usernames": usernames,
            "email": body.email.strip(),
            "phone": body.phone.strip(),
            "domain": body.domain.strip().lower(),
            "location": body.location.strip(),
            "variants": bool(body.variants),
            "thorough": bool(body.thorough),
            "timeout": max(1, min(120, int(body.timeout))),
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
                                 nsfw: bool = Query(False)):
        inv = _get_investigation(inv_id)
        if inv is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        # A GET must never start a second run: only a pending investigation
        # can be streamed. Before this, reopening a finished case's stream (or a
        # browser auto-reconnect) re-ran the whole pipeline and a disconnect
        # left it stuck in `running`.
        if not _claim_investigation(inv_id):
            current = _get_investigation(inv_id)
            status = current["status"] if current else "unknown"
            return JSONResponse(
                {"error": f"investigation is {status}; only a pending"
                          " investigation can be streamed",
                 "status": status},
                status_code=409,
            )
        inputs = inv["inputs"]

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
                await run_investigation(inv_id, inputs, sher_data, emit, loop)
            finally:
                queue.put_nowait(None)  # sentinel

        async def event_gen():
            # Created here, not before the response starts: a generator the
            # server never begins runs no `finally`, and a coordinator created
            # outside it would have run unattended.
            coord_task = asyncio.create_task(coordinator())
            try:
                yield f"event: meta_run\ndata: {json.dumps({'investigation_id': inv_id})}\n\n"
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
            finally:
                # Every way out of the generator — disconnect detected on the
                # keepalive path, CancelledError, GeneratorExit from the server
                # — stops the run. A no-op once the coordinator has finished.
                coord_task.cancel()

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
        # Run diff: the most recent earlier DONE investigation with identical
        # inputs becomes the baseline, so re-scans surface new/gone accounts.
        baseline = None
        try:
            with db_connect(DB_PATH) as conn:
                row = conn.execute(
                    "SELECT summary FROM investigations"
                    " WHERE inputs = ? AND id < ? AND status = 'done'"
                    "   AND summary IS NOT NULL"
                    " ORDER BY id DESC LIMIT 1",
                    (json.dumps(inv["inputs"]), inv_id),
                ).fetchone()
            if row and row[0]:
                baseline = json.loads(row[0])
        except Exception:
            baseline = None
        return JSONResponse(build_graph(inv["summary"], baseline=baseline))

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

    @app.get("/api/investigate/{inv_id}/breach")
    async def investigate_breach(inv_id: int) -> JSONResponse:
        """Infostealer exposure for the subject's identifiers (never secrets)."""
        inv = _get_investigation(inv_id)
        if inv is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        if not inv["summary"]:
            return JSONResponse({"error": "investigation has not run yet"},
                                status_code=409)
        from recon.breach import breach_exposure
        try:
            data = await breach_exposure(inv["summary"])
        except Exception:
            logging.getLogger("app").exception(
                "breach exposure failed for %s", inv_id)
            data = {"checked": False, "results": [], "compromised_count": 0}
        return JSONResponse({"investigation_id": inv_id, **data})

    @app.get("/api/investigate/{inv_id}/footprint")
    async def investigate_footprint(inv_id: int) -> JSONResponse:
        """Geographic footprint: every location claim resolved to map points."""
        inv = _get_investigation(inv_id)
        if inv is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        if not inv["summary"]:
            return JSONResponse({"error": "investigation has not run yet"},
                                status_code=409)
        from recon.geo import build_footprint
        try:
            data = await build_footprint(inv["summary"])
        except Exception:
            logging.getLogger("app").exception(
                "footprint build failed for %s", inv_id)
            data = {"points": [], "unresolved": [], "stats": {}}
        return JSONResponse({"investigation_id": inv_id, **data})

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
        body, err = await _parse_body(request, WatchBody)
        if err is not None:
            return err
        usernames = _split_usernames(body.inputs.usernames)
        if len(usernames) > MAX_USERNAMES_PER_REQUEST:
            return JSONResponse(
                {"error": f"at most {MAX_USERNAMES_PER_REQUEST} usernames per watch"},
                status_code=400)
        inputs = {"usernames": usernames, "email": body.inputs.email.strip(),
                  "name": body.inputs.name.strip()}
        if not (usernames or inputs["email"] or inputs["name"]):
            return JSONResponse(
                {"error": "watch needs usernames, email, or name"},
                status_code=400,
            )
        label = body.label.strip() or (
            ", ".join(usernames) or inputs["email"] or inputs["name"])
        interval = min(24 * 365, max(recon_monitor.MIN_INTERVAL_HOURS,
                                     int(body.interval_hours or recon_monitor.DEFAULT_INTERVAL_HOURS)))
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
        body, err = await _parse_body(request, MarkSeenBody, allow_empty=True)
        if err is not None:
            return err
        ids = list(body.ids or [])
        if len(ids) > MAX_ALERT_IDS:
            return JSONResponse({"error": f"at most {MAX_ALERT_IDS} ids"}, status_code=400)
        with db_connect(DB_PATH) as conn:
            if ids:
                conn.execute(
                    f"UPDATE watch_alerts SET seen = 1 WHERE id IN"
                    f" ({','.join('?' for _ in ids)})",
                    ids,
                )
            else:
                conn.execute("UPDATE watch_alerts SET seen = 1 WHERE seen = 0")
        return JSONResponse({"ok": True})

    # The background watchlist monitor is started from the app lifespan handler
    # (see ``lifespan`` above), which also cancels it cleanly on shutdown.

# ---------------------------------------------------------------------------
# Process health (always registered, never behind the password gate)
# ---------------------------------------------------------------------------

@app.get("/api/health")
def health(request: Request) -> JSONResponse:
    """Process health for operators and the platform health check: is the
    database reachable, which optional engines are present, is the stealth
    browser alive, how many investigations are in flight."""
    db_ok = True
    counts: dict = {}
    try:
        with db_connect(DB_PATH) as conn:
            conn.execute("SELECT 1").fetchone()
            for status, n in conn.execute(
                    "SELECT status, COUNT(*) FROM investigations GROUP BY status"):
                counts[status] = n
    except Exception:
        db_ok = False
    try:
        from recon import stealthweb
        stealth = {"enabled": stealthweb.enabled(),
                   "tier3_dead": bool(getattr(stealthweb, "_session_dead", False))}
    except Exception:
        stealth = {"enabled": False, "tier3_dead": None}
    deps: dict = {"recon": RECON_AVAILABLE}
    if RECON_AVAILABLE:
        deps["maigret"] = recon_engines.maigret_available()
        deps["holehe"] = holehe_available()
        try:
            from recon.phone_accounts import ignorant_available
            deps["ignorant"] = ignorant_available()
        except Exception:
            deps["ignorant"] = False
    body = {
        "ok": db_ok,
        "db_ok": db_ok,
        "backend": "postgres" if dbconn.IS_POSTGRES else "sqlite",
        "commit": APP_COMMIT,
        "uptime_s": int(time.time() - APP_STARTED_AT),
        "investigations": counts,
        "in_flight": counts.get("running", 0),
        "max_concurrent": globals().get("MAX_CONCURRENT_INVESTIGATIONS"),
        "deps": deps,
        "stealth": stealth,
        "sites": {"sherlock": len(SITE_DATA_ALL), "source": SITES_SOURCE},
    }
    if APP_PASSWORD is not None and not _is_authorized(request):
        # A platform health check must work without credentials, but an
        # unauthenticated caller learns only liveness.
        body = {"ok": db_ok, "db_ok": db_ok, "uptime_s": body["uptime_s"]}
    return JSONResponse(body, status_code=200 if db_ok else 503)


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


# --- God's Eye View geospatial workspace ---------------------------------
# The full app (github.com/bilawalsidhu/gods-eye-view, MIT) runs as its own
# service — a Vite/Node server proxying ~15 live geospatial feeds — and the
# frontend's [GODSEYE] tab embeds it. We only report whether that server is up
# so the tab can show the globe or setup instructions. Keys stay in that app.
GODSEYE_URL = os.environ.get("GODSEYE_URL", "http://localhost:4173").rstrip("/")


def _godseye_reachable(url: str) -> bool:
    """A cheap TCP connect check — no HTTP fetch, no data leaves this machine."""
    try:
        from urllib.parse import urlparse
        p = urlparse(url)
        host = p.hostname or "localhost"
        port = p.port or (443 if p.scheme == "https" else 80)
        with socket.create_connection((host, port), timeout=1.0):
            return True
    except Exception:
        return False


@app.get("/api/godseye/status")
def godseye_status() -> JSONResponse:
    return JSONResponse({"url": GODSEYE_URL,
                         "reachable": _godseye_reachable(GODSEYE_URL)})


# Custom 404: a styled page for browser navigation, JSON for API/programmatic
# clients (so API consumers still get machine-readable errors).
@app.exception_handler(404)
async def not_found(request: Request, exc):
    path = request.url.path
    accept = request.headers.get("accept", "")
    wants_html = "text/html" in accept and not path.startswith("/api/")
    if wants_html:
        return FileResponse(STATIC_DIR / "404.html", status_code=404,
                            media_type="text/html")
    return JSONResponse({"error": "not found", "path": path}, status_code=404)


# Icons and any other static assets.
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
