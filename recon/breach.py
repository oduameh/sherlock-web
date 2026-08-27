"""Infostealer exposure — has this identity been on a compromised machine?

Every other pivot asks *where the subject is present*. This one asks a
defensive question the tool could not answer before: **has an identifier
belonging to this subject appeared in infostealer malware logs?** A hit means a
computer the subject used was infected and its saved credentials harvested —
materially different from "this account exists", and often the single most
actionable fact in an exposure assessment.

Source: Hudson Rock's free **Cavalier** OSINT endpoints
(``cavalier.hudsonrock.com/api/json/v2/osint-tools/...``). Public, key-less,
and ``robots.txt`` permits the path (only ``/tokenaccess`` is disallowed).
Supported identifiers are **email**, **username**, and **domain** — there is no
phone endpoint.

**What we deliberately keep, and what we drop.** The free tier already returns
credentials masked (``top_passwords`` like ``C****************``). We go
further and never surface them at all: this module keeps only the *exposure
shape* — that a compromise happened, when, on what machine/OS, and how many
services were affected. Passwords, logins, and partial IPs are dropped before
the data ever leaves this function. The finding an analyst needs is "this
identity was compromised on 2026-08-20, 1,396 user services affected"; the
harvested secrets are neither needed nor ours to redistribute.

Best-effort and never raises: an unreachable service yields ``checked: False``
rather than a false "clean" verdict, because "we could not check" and "nothing
found" are different answers.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

from recon import safeweb

logger = logging.getLogger("recon.breach")

BASE_URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"
USER_AGENT = ("sherlock-web/1.0 (OSINT exposure check; "
              "+https://github.com/oduameh/sherlock-web)")
TIMEOUT_S = 20
# Politeness cap: a subject has a handful of identifiers worth checking, and
# this is a free community service.
MAX_USERNAMES = 5

_cache: dict[tuple, Optional[dict]] = {}


def _summarize_stealer(entry: Any) -> Optional[dict]:
    """Keep only the exposure shape of one infection record.

    Explicitly drops ``top_passwords``/``top_logins`` (even masked) and the
    partially-masked IP — we report *that* a compromise happened, never the
    harvested secrets.
    """
    if not isinstance(entry, dict):
        return None
    out = {
        "date_compromised": entry.get("date_compromised"),
        "computer_name": entry.get("computer_name"),
        "operating_system": entry.get("operating_system"),
        "malware_path": entry.get("malware_path"),
        "antiviruses": entry.get("antiviruses") or [],
        "user_services": entry.get("total_user_services"),
        "corporate_services": entry.get("total_corporate_services"),
    }
    return {k: v for k, v in out.items() if v not in (None, "", [])} or None


def summarize_response(data: Any) -> dict:
    """Cavalier payload → our compact exposure record (pure function)."""
    if not isinstance(data, dict):
        return {"compromised": False, "infections": 0, "stealers": []}
    raw = data.get("stealers")
    stealers = []
    if isinstance(raw, list):
        for entry in raw:
            summary = _summarize_stealer(entry)
            if summary:
                stealers.append(summary)
    dates = sorted(s["date_compromised"] for s in stealers
                   if s.get("date_compromised"))
    return {
        "compromised": bool(stealers),
        "infections": len(stealers),
        "first_compromise": dates[0] if dates else None,
        "last_compromise": dates[-1] if dates else None,
        "stealers": stealers,
    }


async def _lookup(kind: str, value: str) -> Optional[dict]:
    """One Cavalier lookup. None when the service could not be reached."""
    key = (kind, value.strip().lower())
    if key in _cache:
        return _cache[key]
    endpoint = {"email": "search-by-email?email={}",
                "username": "search-by-username?username={}",
                "domain": "search-by-domain?domain={}"}.get(kind)
    if not endpoint or not value:
        return None
    from urllib.parse import quote
    url = f"{BASE_URL}/{endpoint.format(quote(value, safe=''))}"
    try:
        async with safeweb.async_client(timeout=TIMEOUT_S) as client:
            resp = await client.get(url, headers={"User-Agent": USER_AGENT})
        if resp.status_code >= 400:
            _cache[key] = None
            return None
        data = resp.json()
    except Exception as exc:
        logger.debug("cavalier lookup failed for %s %r: %s", kind, value, exc)
        _cache[key] = None
        return None
    out = summarize_response(data)
    out["identifier"] = value
    out["kind"] = kind
    _cache[key] = out
    return out


def collect_identifiers(summary: dict) -> list[tuple]:
    """The identifiers worth checking, as ``(kind, value)`` (pure function).

    The subject's email and domain, plus the handles they actually searched —
    never the speculative name-derived candidates, which are guesses about
    other people.
    """
    summary = summary or {}
    params = summary.get("params") or {}
    out: list[tuple] = []
    seen: set[tuple] = set()

    def add(kind: str, value: Any) -> None:
        if not isinstance(value, str):
            return
        v = value.strip()
        if not v:
            return
        key = (kind, v.lower())
        if key in seen:
            return
        seen.add(key)
        out.append((kind, v))

    add("email", params.get("email"))
    add("domain", params.get("domain"))
    for handle in (params.get("usernames") or [])[:MAX_USERNAMES]:
        add("username", handle)
    return out


async def breach_exposure(summary: dict) -> dict:
    """Check every subject identifier for infostealer exposure.

    Returns ``{checked, results, compromised_count, identifiers_checked}``.
    ``checked`` is False when the service could not be reached at all, so a
    lookup failure never reads as "clean". Never raises.
    """
    identifiers = collect_identifiers(summary)
    if not identifiers:
        return {"checked": False, "results": [], "compromised_count": 0,
                "identifiers_checked": 0,
                "note": "no email, domain, or username to check"}

    found = await asyncio.gather(
        *(_lookup(kind, value) for kind, value in identifiers),
        return_exceptions=True)
    results = [r for r in found if isinstance(r, dict)]
    return {
        "checked": bool(results),
        "identifiers_checked": len(results),
        "compromised_count": sum(1 for r in results if r.get("compromised")),
        "results": results,
        "source": "Hudson Rock Cavalier (free OSINT tier)",
    }
