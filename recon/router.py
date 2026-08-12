"""Adaptive routing: error taxonomy, per-site health memory, circuit breaker,
smart retries, and an optional proxy pool.

Motivation: on datacenter deployments (Railway etc.) a large share of site
checks fail — WAF blocks and 429s from IP reputation, transient connect/DNS
timeouts, and stale site detectors. Without routing, every run blindly retries
dead sites and the failures surface as undifferentiated "error" rows.

Design:

* :func:`classify` maps (status, context, exception text) to a stable error
  class. Pure and unit-testable.
* :class:`SiteHealthStore` persists a sliding window of the last
  ``WINDOW_SIZE`` observations per (site, engine) in the ``site_health``
  table, plus EWMA latency, consecutive-failure count and circuit state.
* Circuit breaker: a site trips open after ``TRIP_CONSECUTIVE_FAILURES``
  straight failures, or when its failure rate over the last
  ``TRIP_RATE_WINDOW`` observations exceeds ``TRIP_FAILURE_RATE`` (with at
  least ``TRIP_RATE_MIN_OBS`` observations). Open sites are excluded from
  scans for ``BASE_COOLDOWN_S``, doubling on each re-trip up to
  ``MAX_COOLDOWN_S``. After the cooldown the site is half-open: it is scanned
  once — success closes the circuit (cooldown resets), failure re-trips it
  with the doubled cooldown.
* Smart retries: results classed as transient (``TRANSIENT_CLASSES``) are
  retried once per run after a jittered delay, capped at ``RETRY_CAP`` per
  run. 429/WAF-class failures are deliberately NOT retried in-run — the
  circuit breaker handles those across runs.
* Optional proxy pool (``PROXY_LIST`` env, off by default): one proxy is
  picked per run (round-robin, skipping banned ones), passed to sherlock's
  and maigret's ``proxy=`` params, and tracked in ``proxy_health``. Proxies
  whose failure rate exceeds ``PROXY_BAN_RATE`` over ``PROXY_BAN_MIN_USES``
  uses are benched for ``PROXY_RECHECK_S``.

Everything degrades gracefully: if the database is unavailable the store
disables itself (one warning) and scans run exactly as before.
"""

from __future__ import annotations

import json
import logging
import os
import random
import re
import sqlite3
import threading
import time
from collections import Counter
from typing import Callable, Optional

from dbconn import connect as db_connect

logger = logging.getLogger("recon.router")

# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------

TIMEOUT = "timeout"
DNS = "dns"
TLS = "tls"
CONN_RESET = "conn_reset"
HTTP_429 = "http_429"
HTTP_403_WAF = "http_403_waf"
HTTP_5XX = "http_5xx"
DETECTOR_STALE = "detector_stale"
UNKNOWN = "unknown"

ERROR_CLASSES = [
    TIMEOUT, DNS, TLS, CONN_RESET, HTTP_429, HTTP_403_WAF, HTTP_5XX,
    DETECTOR_STALE, UNKNOWN,
]

# Short human labels for the UI / README.
CLASS_LABELS = {
    TIMEOUT: "timeout",
    DNS: "DNS failure",
    TLS: "TLS error",
    CONN_RESET: "connection reset",
    HTTP_429: "rate-limited",
    HTTP_403_WAF: "WAF-blocked",
    HTTP_5XX: "server error (5xx)",
    DETECTOR_STALE: "stale detector",
    UNKNOWN: "unknown",
}

# Transient classes are worth one in-run retry; everything else is left to
# the circuit breaker (retrying a 429 or WAF block immediately is pointless).
TRANSIENT_CLASSES = frozenset({TIMEOUT, CONN_RESET, HTTP_5XX, DNS})

_SUCCESS_STATUSES = {"claimed", "available"}

_DNS_RE = re.compile(
    r"name resolution|getaddrinfo|nodename nor servname|no such host|\bdns\b"
    r"|name or service not known"
)
_TLS_RE = re.compile(r"\bssl\b|\btls\b|certificate")
_5XX_RE = re.compile(r"\b5\d\d\b")


def classify(status: str, context: str = "", exception: str = "") -> Optional[str]:
    """Map (status, context, exception text) to an error class.

    ``status`` is the engine's status value (sherlock ``QueryStatus.value`` or
    maigret ``MaigretCheckStatus.value``: Claimed/Available/Unknown/Illegal/
    WAF). Returns ``None`` for successful checks. Pure function.
    """
    s = (status or "").strip().lower()
    if s in _SUCCESS_STATUSES:
        return None
    if s == "waf":
        return HTTP_403_WAF
    # ILLEGAL means the username can't exist on the site or the detector's
    # match rules no longer parse the response — a stale detector either way.
    if s == "illegal":
        return DETECTOR_STALE

    text = f"{context or ''} {exception or ''}".lower()
    if "timeout" in text or "timed out" in text:
        return TIMEOUT
    if _DNS_RE.search(text):
        return DNS
    if _TLS_RE.search(text):
        return TLS
    if "429" in text or "too many requests" in text or "rate limit" in text:
        return HTTP_429
    if (
        "403" in text or "forbidden" in text or "cloudflare" in text
        or "captcha" in text or "access denied" in text or "waf" in text
        or "just a moment" in text
    ):
        return HTTP_403_WAF
    if _5XX_RE.search(text) or "server error" in text or "bad gateway" in text:
        return HTTP_5XX
    if (
        "reset" in text or "error connecting" in text or "connect" in text
        or "proxy error" in text or "network" in text
    ):
        return CONN_RESET
    if "regex" in text or "parsing" in text or "illegal" in text:
        return DETECTOR_STALE
    return UNKNOWN


# ---------------------------------------------------------------------------
# Circuit-breaker tuning (pure helpers)
# ---------------------------------------------------------------------------

WINDOW_SIZE = 50               # observations kept per (site, engine)
TRIP_CONSECUTIVE_FAILURES = 5
TRIP_FAILURE_RATE = 0.60       # over the last TRIP_RATE_WINDOW observations
TRIP_RATE_WINDOW = 20
TRIP_RATE_MIN_OBS = 10
BASE_COOLDOWN_S = 15 * 60      # 15 min
MAX_COOLDOWN_S = 4 * 3600      # 4 h

RETRY_CAP = 40                 # total in-run retries across all sites
RETRY_DELAY_MIN_S = 5.0
RETRY_DELAY_MAX_S = 15.0

PROXY_BAN_RATE = 0.70
PROXY_BAN_MIN_USES = 10
PROXY_RECHECK_S = 30 * 60


def should_trip(consecutive_failures: int, window: list[dict]) -> bool:
    """True when the circuit should open for this failure history."""
    if consecutive_failures >= TRIP_CONSECUTIVE_FAILURES:
        return True
    recent = window[-TRIP_RATE_WINDOW:]
    if len(recent) >= TRIP_RATE_MIN_OBS:
        fails = sum(1 for o in recent if not o.get("ok"))
        if fails / len(recent) > TRIP_FAILURE_RATE:
            return True
    return False


def next_cooldown(current_s: int) -> int:
    """Cooldown for the *next* trip: doubles, capped at MAX_COOLDOWN_S."""
    return min(current_s * 2, MAX_COOLDOWN_S)


def partition_sites(site_names, open_circuits: dict[str, str]):
    """Split site names into (kept, skipped) given {site: open_until} circuits."""
    kept, skipped = [], []
    for name in site_names:
        (skipped if name in open_circuits else kept).append(name)
    return kept, skipped


def select_retries(records: list[dict], cap: int = RETRY_CAP) -> list[dict]:
    """Pick transient-class failure records to retry, capped per run."""
    return [r for r in records if r.get("class") in TRANSIENT_CLASSES][:cap]


def proxy_should_ban(uses: int, failures: int) -> bool:
    """Ban a proxy whose failure rate exceeds the threshold over enough uses."""
    return uses >= PROXY_BAN_MIN_USES and failures / uses > PROXY_BAN_RATE


def retry_delay() -> float:
    """Jittered delay before a retry attempt."""
    return random.uniform(RETRY_DELAY_MIN_S, RETRY_DELAY_MAX_S)


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

_TS_FMT = "%Y-%m-%d %H:%M:%S"


def _fmt(ts: float) -> str:
    return time.strftime(_TS_FMT, time.localtime(ts))


def _parse(s: Optional[str]) -> Optional[float]:
    if not s:
        return None
    try:
        return time.mktime(time.strptime(s, _TS_FMT))
    except Exception:
        return None


def init_tables(conn: sqlite3.Connection) -> None:
    """Create routing tables. Called from the app's startup migration."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS site_health (
            site TEXT NOT NULL,
            engine TEXT NOT NULL,
            window TEXT NOT NULL DEFAULT '[]',
            ewma_latency_ms REAL,
            consecutive_failures INTEGER NOT NULL DEFAULT 0,
            circuit_open_until TEXT,
            cooldown_seconds INTEGER NOT NULL DEFAULT 900,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (site, engine)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS proxy_health (
            proxy TEXT PRIMARY KEY,
            uses INTEGER NOT NULL DEFAULT 0,
            failures INTEGER NOT NULL DEFAULT 0,
            banned_until TEXT,
            updated_at TEXT NOT NULL
        )
        """
    )


class SiteHealthStore:
    """SQLite-backed per-site health memory. Every operation is guarded: on
    the first database error the store disables itself and routing silently
    steps aside (scans continue unrouted)."""

    def __init__(self, db_path):
        self.db_path = db_path
        self.available = True

    def _guard(self, exc: Exception) -> None:
        if self.available:
            logger.warning("site health store unavailable, routing disabled: %s", exc)
        self.available = False

    # -- writes ------------------------------------------------------------

    def record(self, site: str, engine: str, ok: bool,
               err_class: Optional[str] = None,
               latency_ms: Optional[float] = None,
               now: Optional[float] = None) -> None:
        """Record one observation and update circuit state for (site, engine)."""
        if not self.available:
            return
        now = time.time() if now is None else now
        try:
            with db_connect(self.db_path) as conn:
                row = conn.execute(
                    "SELECT window, ewma_latency_ms, consecutive_failures,"
                    " circuit_open_until, cooldown_seconds"
                    " FROM site_health WHERE site = ? AND engine = ?",
                    (site, engine),
                ).fetchone()
                if row:
                    window = json.loads(row[0])
                    ewma = row[1]
                    consec = row[2]
                    open_until = row[3]
                    cooldown = row[4]
                else:
                    window, ewma, consec, open_until = [], None, 0, None
                    cooldown = BASE_COOLDOWN_S

                window.append({"ok": 1 if ok else 0, "class": err_class,
                               "ts": now})
                window = window[-WINDOW_SIZE:]
                if latency_ms is not None:
                    ewma = (latency_ms if ewma is None
                            else 0.3 * latency_ms + 0.7 * ewma)

                if ok:
                    # Success closes the circuit (incl. the half-open probe)
                    # and resets the cooldown ladder.
                    consec = 0
                    open_until = None
                    cooldown = BASE_COOLDOWN_S
                else:
                    consec += 1
                    open_ts = _parse(open_until)
                    currently_open = open_ts is not None and open_ts > now
                    # Only trip when closed or half-open; failures recorded
                    # while open don't stack more cooldown doublings.
                    if not currently_open and should_trip(consec, window):
                        open_until = _fmt(now + cooldown)
                        cooldown = next_cooldown(cooldown)

                conn.execute(
                    "INSERT INTO site_health (site, engine, window,"
                    " ewma_latency_ms, consecutive_failures,"
                    " circuit_open_until, cooldown_seconds, updated_at)"
                    " VALUES (?,?,?,?,?,?,?,?)"
                    " ON CONFLICT(site, engine) DO UPDATE SET"
                    " window = excluded.window,"
                    " ewma_latency_ms = excluded.ewma_latency_ms,"
                    " consecutive_failures = excluded.consecutive_failures,"
                    " circuit_open_until = excluded.circuit_open_until,"
                    " cooldown_seconds = excluded.cooldown_seconds,"
                    " updated_at = excluded.updated_at",
                    (site, engine, json.dumps(window), ewma, consec,
                     open_until, cooldown, _fmt(now)),
                )
        except (sqlite3.Error, OSError) as exc:
            self._guard(exc)

    # -- reads -------------------------------------------------------------

    def open_circuits(self, engine: Optional[str] = None,
                      now: Optional[float] = None) -> dict[str, str]:
        """{site: circuit_open_until} for circuits still open right now."""
        if not self.available:
            return {}
        now = time.time() if now is None else now
        try:
            with db_connect(self.db_path) as conn:
                sql = ("SELECT site, circuit_open_until FROM site_health"
                       " WHERE circuit_open_until IS NOT NULL")
                args: tuple = ()
                if engine:
                    sql += " AND engine = ?"
                    args = (engine,)
                rows = conn.execute(sql, args).fetchall()
        except (sqlite3.Error, OSError) as exc:
            self._guard(exc)
            return {}
        return {site: until for site, until in rows
                if (_parse(until) or 0) > now}

    def all_rows(self) -> list[dict]:
        if not self.available:
            return []
        try:
            with db_connect(self.db_path) as conn:
                rows = conn.execute(
                    "SELECT site, engine, window, ewma_latency_ms,"
                    " consecutive_failures, circuit_open_until,"
                    " cooldown_seconds, updated_at FROM site_health"
                ).fetchall()
        except (sqlite3.Error, OSError) as exc:
            self._guard(exc)
            return []
        out = []
        for r in rows:
            out.append({
                "site": r[0], "engine": r[1], "window": json.loads(r[2]),
                "ewma_latency_ms": r[3], "consecutive_failures": r[4],
                "circuit_open_until": r[5], "cooldown_seconds": r[6],
                "updated_at": r[7],
            })
        return out

    # -- proxy health --------------------------------------------------------

    def record_proxy(self, proxy: str, ok: bool,
                     now: Optional[float] = None) -> None:
        if not self.available:
            return
        now = time.time() if now is None else now
        try:
            with db_connect(self.db_path) as conn:
                row = conn.execute(
                    "SELECT uses, failures FROM proxy_health WHERE proxy = ?",
                    (proxy,),
                ).fetchone()
                uses, failures = (row[0], row[1]) if row else (0, 0)
                uses += 1
                failures += 0 if ok else 1
                banned_until = None
                if proxy_should_ban(uses, failures):
                    banned_until = _fmt(now + PROXY_RECHECK_S)
                    logger.warning("proxy %s banned for %ds (%d/%d failed)",
                                   proxy, PROXY_RECHECK_S, failures, uses)
                conn.execute(
                    "INSERT INTO proxy_health (proxy, uses, failures,"
                    " banned_until, updated_at) VALUES (?,?,?,?,?)"
                    " ON CONFLICT(proxy) DO UPDATE SET"
                    " uses = excluded.uses, failures = excluded.failures,"
                    " banned_until = excluded.banned_until,"
                    " updated_at = excluded.updated_at",
                    (proxy, uses, failures, banned_until, _fmt(now)),
                )
        except (sqlite3.Error, OSError) as exc:
            self._guard(exc)

    def banned_proxies(self, now: Optional[float] = None) -> set[str]:
        if not self.available:
            return set()
        now = time.time() if now is None else now
        try:
            with db_connect(self.db_path) as conn:
                rows = conn.execute(
                    "SELECT proxy, banned_until FROM proxy_health"
                    " WHERE banned_until IS NOT NULL"
                ).fetchall()
        except (sqlite3.Error, OSError) as exc:
            self._guard(exc)
            return set()
        return {p for p, until in rows if (_parse(until) or 0) > now}


# ---------------------------------------------------------------------------
# Proxy pool (optional; PROXY_LIST env, comma-separated http/socks5 URLs)
# ---------------------------------------------------------------------------


class ProxyPool:
    """Round-robin proxy picker with health-based banning.

    One proxy is picked per run (rotation happens at run granularity, not
    per request — per-request rotation would need engine internals). A proxy
    banned for excessive failures becomes eligible again after
    ``PROXY_RECHECK_S`` so a recovered proxy is re-tried automatically.
    """

    def __init__(self, urls: Optional[list[str]] = None):
        if urls is None:
            raw = os.environ.get("PROXY_LIST") or ""
            urls = [u.strip() for u in raw.split(",") if u.strip()]
        self.urls = list(urls)
        self._lock = threading.Lock()
        self._idx = 0

    @property
    def configured(self) -> bool:
        return bool(self.urls)

    def pick(self, store: Optional[SiteHealthStore] = None) -> Optional[str]:
        """Next proxy in rotation, skipping currently-banned ones."""
        if not self.urls:
            return None
        banned = store.banned_proxies() if store is not None else set()
        with self._lock:
            for _ in range(len(self.urls)):
                proxy = self.urls[self._idx % len(self.urls)]
                self._idx += 1
                if proxy not in banned:
                    return proxy
        logger.warning("all %d proxies are currently banned; running direct",
                       len(self.urls))
        return None


# ---------------------------------------------------------------------------
# Per-run router
# ---------------------------------------------------------------------------

Emit = Callable[[str, dict], None]


class RunRouter:
    """Coordinates routing for one scan run.

    ``emit`` (optional) is the run's SSE emitter — used for the
    ``skipped_degraded`` announcement. When the store is unavailable every
    method becomes a cheap no-op and the run proceeds unrouted.
    """

    def __init__(self, db_path=None, emit: Optional[Emit] = None,
                 proxy_pool: Optional[ProxyPool] = None):
        self.store = SiteHealthStore(db_path) if db_path else None
        self.emit = emit
        self.error_counts: Counter = Counter()
        self.degraded: list[dict] = []
        self._degraded_keys: set = set()
        self._transient: list[dict] = []
        self.retries_done = 0
        self.observations = 0
        self.error_observations = 0
        self.disabled = self.store is None or not self.store.available
        self.proxy: Optional[str] = None
        pool = proxy_pool if proxy_pool is not None else ProxyPool()
        if not self.disabled and pool.configured:
            self.proxy = pool.pick(self.store)
            if self.proxy:
                logger.info("run routing via proxy %s", self.proxy)

    # -- pre-scan: circuit filtering ----------------------------------------

    def filter_sites(self, site_data: dict, engine: str) -> dict:
        """Drop open-circuit sites from an engine's site dict."""
        if self.disabled or not site_data:
            return site_data
        open_c = self.store.open_circuits(engine)
        if not open_c:
            return site_data
        kept_names, skipped = partition_sites(site_data.keys(), open_c)
        for name in skipped:
            key = (name, engine)
            if key not in self._degraded_keys:
                self._degraded_keys.add(key)
                self.degraded.append({"site": name, "engine": engine,
                                      "until": open_c[name]})
        return {n: site_data[n] for n in kept_names}

    def announce_skipped(self) -> None:
        """Emit the (never silent) skipped_degraded event, if any."""
        if self.degraded:
            logger.info("skipping %d degraded source(s): %s",
                        len(self.degraded),
                        ", ".join(d["site"] for d in self.degraded))
            if self.emit:
                self.emit("skipped_degraded", {
                    "count": len(self.degraded),
                    "sites": self.degraded,
                })

    # -- during-scan: observation ---------------------------------------------

    def observe(self, engine: str, site: str, status: str,
                context: str = "", query_time: Optional[float] = None,
                username: Optional[str] = None) -> None:
        """Record one per-site check result (called for EVERY status)."""
        err_class = classify(status, context)
        self.observations += 1
        if err_class is not None:
            self.error_observations += 1
            self.error_counts[err_class] += 1
            if err_class in TRANSIENT_CLASSES:
                self._transient.append({
                    "engine": engine, "site": site, "username": username,
                    "class": err_class,
                })
        if self.disabled:
            return
        self.store.record(
            site, engine, ok=err_class is None, err_class=err_class,
            latency_ms=query_time * 1000 if query_time else None,
        )

    # -- post-pass: smart retries ----------------------------------------------

    def drain_transient(self, engine: str,
                        username: Optional[str]) -> list[dict]:
        """Pop this pass's retryable failures (transient only, cap enforced).

        Entries left in the queue (over cap or from a retry's own failure) are
        discarded so each failed check is retried at most once per run.
        """
        picked, rest = [], []
        for rec in self._transient:
            if (rec["engine"] == engine and rec["username"] == username
                    and self.retries_done + len(picked) < RETRY_CAP):
                picked.append(rec)
            else:
                rest.append(rec)
        self._transient = rest
        return picked

    # -- end of run -------------------------------------------------------------

    def finish(self) -> None:
        """Record proxy health for the run (majority-error pass = failure)."""
        if self.proxy and not self.disabled and self.observations:
            ok = self.error_observations / self.observations <= 0.5
            self.store.record_proxy(self.proxy, ok)

    def breakdown(self) -> dict:
        """Additive fields for the run's final done/summary payload."""
        return {
            "error_breakdown": dict(self.error_counts),
            "degraded_sources": len(self.degraded),
        }


# ---------------------------------------------------------------------------
# /api/health/sources payload
# ---------------------------------------------------------------------------


def sources_summary(db_path, now: Optional[float] = None) -> dict:
    """Per-site reliability summary, worst-first, plus run-level aggregates."""
    now = time.time() if now is None else now
    store = SiteHealthStore(db_path)
    rows = store.all_rows()
    sites = []
    total_obs = 0
    total_fail = 0
    circuits_open = 0
    for r in rows:
        window = r["window"]
        n = len(window)
        fails = sum(1 for o in window if not o.get("ok"))
        classes = Counter(o.get("class") for o in window
                          if o.get("class"))
        open_ts = _parse(r["circuit_open_until"])
        if open_ts is not None and open_ts > now:
            circuit = "open"
            circuits_open += 1
            cooldown_remaining = int(open_ts - now)
        elif open_ts is not None:
            circuit = "half-open"
            cooldown_remaining = 0
        else:
            circuit = "closed"
            cooldown_remaining = 0
        total_obs += n
        total_fail += fails
        sites.append({
            "site": r["site"],
            "engine": r["engine"],
            "observations": n,
            "failure_rate": round(fails / n, 3) if n else 0.0,
            "dominant_error": classes.most_common(1)[0][0] if classes else None,
            "consecutive_failures": r["consecutive_failures"],
            "circuit": circuit,
            "circuit_open_until": r["circuit_open_until"],
            "cooldown_remaining_s": cooldown_remaining,
            "ewma_latency_ms": (round(r["ewma_latency_ms"], 1)
                                if r["ewma_latency_ms"] is not None else None),
            "updated_at": r["updated_at"],
        })
    # Worst first: open circuits, then half-open, then by failure rate.
    rank = {"open": 0, "half-open": 1, "closed": 2}
    sites.sort(key=lambda s: (rank[s["circuit"]], -s["failure_rate"],
                              -s["observations"]))
    return {
        "available": store.available,
        "sites": sites,
        "aggregate": {
            "sites_tracked": len(sites),
            "circuits_open": circuits_open,
            "observations": total_obs,
            "overall_failure_rate": (round(total_fail / total_obs, 3)
                                     if total_obs else 0.0),
        },
    }
