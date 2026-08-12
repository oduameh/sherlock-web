"""Subject timeline: reconstruct a chronology for an investigation.

Combines dated events from several sources into one sorted list:

* the investigation being opened,
* each scan run recorded against it (history rows),
* watchlist alert events (new/gone accounts, new registrations),
* account **creation dates** where a platform exposes them publicly — GitHub's
  public user API (``api.github.com/users/{login}``) returns ``created_at`` with
  no key, so a confirmed GitHub account contributes a real "account created"
  milestone.

The assembly, parsing, and account-event helpers are pure and unit-tested; the
GitHub enrichment is a best-effort async fetch through :mod:`recon.safeweb`
(SSRF-guarded, no key) that never raises.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Callable, Optional
from urllib.parse import urlparse

from recon.engines import normalize_site
from recon.safeweb import async_client, fetch_capped

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
) -> dict[str, str]:
    """Best-effort ``{profile_url: created_at}`` from public platform APIs.

    Currently GitHub (public, no key). Never raises; on any error a lookup is
    simply skipped. ``client_factory`` is injectable for testing.
    """
    targets: list[tuple[str, str]] = []  # (url, github_login)
    for row in rows or []:
        url = row.get("url")
        if not url or normalize_site(row.get("site") or "") != "github":
            continue
        login = github_login_from_url(url)
        if login:
            targets.append((url, login))
        if len(targets) >= max_lookups:
            break

    if not targets:
        return {}

    dates: dict[str, str] = {}
    try:
        async with client_factory(timeout=8.0) as client:
            for url, login in targets:
                try:
                    body = await fetch_capped(
                        client, f"https://api.github.com/users/{login}",
                        256 * 1024,
                    )
                    if not body:
                        continue
                    data = json.loads(body)
                    created = data.get("created_at")
                    if created:
                        dates[url] = created
                except Exception:
                    logger.debug("github lookup failed for %s", login,
                                 exc_info=True)
    except Exception:
        logger.debug("github enrichment client failed", exc_info=True)
    return dates
