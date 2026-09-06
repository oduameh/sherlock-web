"""Subject timeline: reconstruct a chronology for an investigation.

Combines dated events from several sources into one sorted list:

* the investigation being opened,
* each scan run recorded against it (history rows),
* watchlist alert events (new/gone accounts, new registrations),
* account **creation dates** where a platform exposes them publicly. The
  adapters already store ``temporal.created_at`` on a row during enrichment
  (GitHub, Bluesky, dev.to, Docker Hub, Keybase, Vimeo, mastodon.social), and
  that is read first. Only a GitHub row *without* it is looked up on the
  public user API (``api.github.com/users/{login}``, no key) — through a
  process-wide TTL cache, so a login is fetched once per six hours instead of
  on every ``/timeline`` and ``/report`` open (tech-debt D8, defect 10: each
  dossier open used to spend up to 15 of GitHub's 60 hourly calls).

The assembly, parsing, and account-event helpers are pure and unit-tested; the
GitHub lookup goes through :func:`recon.retrieval.fetch` (policy- and
SSRF-guarded, capped, never raises). A rate limit or transport failure is
never cached; a 404 is cached as a definitive absence.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime
from typing import Callable, Optional
from urllib.parse import quote, urlparse

from recon import adapters, retrieval, sources
from recon.cache import TTLCache
from recon.engines import normalize_site
from recon.rows import created_at as row_created_at
from recon.safeweb import async_client

logger = logging.getLogger("recon.timeline")

# Path segments that are never a GitHub username.
_GITHUB_RESERVED = {
    "", "orgs", "sponsors", "features", "about", "pricing", "marketplace",
    "explore", "topics", "collections", "trending", "events", "login",
    "join", "settings", "notifications", "search", "apps",
}

_TS_FORMATS = (
    "%Y-%m-%dT%H:%M:%S",       # ISO 8601 (GitHub created_at, Z stripped)
    "%Y-%m-%d %H:%M:%S",       # our stored history/alert format
    "%Y-%m-%d",                # bare date
)

_MAX_GITHUB_LOOKUPS = 15

# Positive answers and definitive absences, six hours; failures never (D8).
GITHUB_TTL_S = 6 * 3600
_github_cache = TTLCache(maxsize=512, ttl_s=GITHUB_TTL_S)
_GITHUB_HEADERS = {"Accept": "application/vnd.github+json",
                   "User-Agent": sources.USER_AGENT}


def clear_cache() -> None:
    """Forget every cached GitHub answer (tests)."""
    _github_cache.clear()


def github_login_from_url(url: Optional[str]) -> Optional[str]:
    """Extract a GitHub username from a profile URL, or ``None``.

    ``https://github.com/torvalds`` -> ``"torvalds"``. Rejects reserved paths
    (``/orgs/...``) and non-github hosts.
    """
    if not url:
        return None
    try:
        parsed = urlparse(url if "//" in url else "https://" + url)
    except ValueError:
        return None
    host = (parsed.netloc or "").lower()
    if host not in ("github.com", "www.github.com"):
        return None
    parts = [p for p in (parsed.path or "").split("/") if p]
    if not parts:
        return None
    login = parts[0]
    if login.lower() in _GITHUB_RESERVED:
        return None
    return login


def parse_ts(raw: Optional[str]) -> Optional[datetime]:
    """Parse the timestamp formats this app produces into a ``datetime``.

    Tolerates a trailing ``Z`` / ``+00:00`` offset. Returns ``None`` for empty
    or unrecognised input (such events sort last, undated).
    """
    if not raw:
        return None
    s = str(raw).strip()
    if s.endswith("Z"):
        s = s[:-1]
    # Drop a trailing UTC offset like +00:00 (naive comparison is fine here).
    if len(s) >= 6 and s[-6] in "+-" and s[-3] == ":":
        s = s[:-6]
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def build_timeline(events: list[dict]) -> list[dict]:
    """Sort + de-duplicate raw events into an ascending timeline.

    Each event is ``{"date": <str|None>, "kind": str, "title": str,
    "detail"?: str}``. Output events gain a ``dated`` boolean; dated events are
    sorted chronologically first, undated ones (unparseable/missing date) come
    last in stable input order. Exact ``(date, kind, title)`` duplicates are
    collapsed.
    """
    seen: set[tuple] = set()
    dated: list[tuple[datetime, dict]] = []
    undated: list[dict] = []
    for i, ev in enumerate(events or []):
        key = (ev.get("date"), ev.get("kind"), ev.get("title"))
        if key in seen:
            continue
        seen.add(key)
        norm = {
            "date": ev.get("date"),
            "kind": ev.get("kind"),
            "title": ev.get("title"),
            "detail": ev.get("detail"),
        }
        dt = parse_ts(ev.get("date"))
        if dt is None:
            norm["dated"] = False
            undated.append(norm)
        else:
            norm["dated"] = True
            # Include original index to keep sort stable for equal timestamps.
            dated.append((dt, i, norm))
    dated.sort(key=lambda t: (t[0], t[1]))
    return [d[2] for d in dated] + undated


def account_events(rows: list[dict],
                   creation_dates: dict[str, str]) -> list[dict]:
    """Turn ``{profile_url: created_at}`` into account-creation timeline events.

    ``rows`` are account rows (so we can attach the platform + handle); only
    rows whose URL has a known creation date contribute.
    """
    out: list[dict] = []
    for row in rows or []:
        url = row.get("url")
        created = creation_dates.get(url) if url else None
        if not created:
            continue
        site = row.get("site") or "account"
        out.append({
            "date": created,
            "kind": "account_created",
            "title": f"{site} account created",
            "detail": f"{row.get('username') or ''} — {url}".strip(" —"),
        })
    return out


async def account_creation_dates(
    rows: list[dict], *,
    client_factory: Callable[..., object] = async_client,
    max_lookups: int = _MAX_GITHUB_LOOKUPS,
    cache: Optional[TTLCache] = None,
) -> dict[str, str]:
    """Best-effort ``{profile_url: created_at}`` for account rows.

    Rule (D8 / defect 10): a row's own ``temporal.created_at`` — stored by the
    adapter during enrichment — is used as-is and costs nothing. Only a GitHub
    row without it is looked up, through the module cache (positive 6 h,
    404 cached as absent, blocked/transport never cached), at most
    ``max_lookups`` *fetches* per call. Never raises. ``client_factory`` and
    ``cache`` are injectable for tests.
    """
    cache = _github_cache if cache is None else cache
    dates: dict[str, str] = {}
    targets: list[tuple[str, str]] = []  # (url, github_login) still to fetch
    for row in rows or []:
        url = row.get("url")
        if not url:
            continue
        stored = row_created_at(row)
        if stored:
            dates[url] = stored
            continue
        if normalize_site(row.get("site") or "") != "github":
            continue
        login = github_login_from_url(url)
        if not login:
            continue
        hit, cached = cache.get(login.lower())
        if hit:
            if cached:
                dates[url] = cached
            continue
        # The adapter cache (recon.adapters) may already hold this login from
        # the run's discovery or enrichment — one GitHub source, one budget:
        # an EXISTS answer carries created_at, an ABSENT one is definitive.
        shared = adapters.cached_result("github", login)
        if shared is not None:
            created = (shared.get("temporal") or {}).get("created_at")
            if created:
                dates[url] = str(created)
            continue
        targets.append((url, login))

    if not targets:
        return dates

    fetched = 0
    try:
        async with client_factory(timeout=8.0) as client:
            for url, login in targets:
                if fetched >= max_lookups:
                    break
                key = login.lower()
                hit, cached = cache.get(key)     # filled by an earlier target?
                if hit:
                    if cached:
                        dates[url] = cached
                    continue
                fetched += 1
                t0 = time.monotonic()
                res = await retrieval.fetch(
                    f"https://api.github.com/users/{quote(login, safe='')}",
                    client=client, kind="json", headers=_GITHUB_HEADERS,
                    max_bytes=256 * 1024)
                latency_ms = (time.monotonic() - t0) * 1000
                if res.outcome == retrieval.OK and isinstance(res.data, dict):
                    created = res.data.get("created_at")
                    if created:
                        cache.set(key, str(created))
                        dates[url] = str(created)
                    else:
                        cache.set_absent(key)   # the user exists; no date exposed
                    sources.record("github", True, latency_ms)
                elif res.outcome == retrieval.ABSENT:
                    cache.set_absent(key)       # no such user: definitive
                    sources.record("github", True, latency_ms)
                else:
                    # blocked (incl. rate limit) / transport / policy / ssrf:
                    # not an answer, so nothing is cached and the next call
                    # asks again.
                    sources.record("github", False, latency_ms, res.reason)
                    logger.debug("github lookup for %s: %s (%s)", login,
                                 res.outcome, res.reason)
    except Exception:
        logger.debug("github enrichment client failed", exc_info=True)
    return dates
