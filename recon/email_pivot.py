"""Email pivot: Gravatar profile lookup + holehe registered-account checks.

Public data only: Gravatar's public JSON profile API and holehe's checks
against public register/password-reset endpoints. holehe is imported lazily;
if it is missing the gravatar lookup still works.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from typing import Any, Callable, Optional

import httpx

logger = logging.getLogger("recon.email_pivot")

BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# Rate-sensitivity knobs: holehe-style checks run sequentially.
HOLEHE_DELAY_S = 0.4
HOLEHE_MODULE_TIMEOUT_S = 15


async def gravatar_lookup(email: str) -> Optional[dict]:
    """Fetch the public Gravatar profile for an email. None if no profile."""
    digest = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()
    url = f"https://www.gravatar.com/{digest}.json"
    try:
        async with httpx.AsyncClient(
            timeout=10, headers={"User-Agent": BROWSER_UA}, follow_redirects=True
        ) as client:
            resp = await client.get(url)
        if resp.status_code != 200:
            return None
        entries = resp.json().get("entry") or []
        if not entries:
            return None
        e = entries[0]
        accounts = [
            {
                "name": a.get("name"),
                "domain": a.get("domain"),
                "url": a.get("url"),
                "username": a.get("username"),
            }
            for a in e.get("accounts", [])
        ]
        return {
            "hash": digest,
            "display_name": e.get("displayName"),
            "full_name": (e.get("name") or {}).get("formatted"),
            "profile_url": e.get("profileUrl"),
            "avatar_url": e.get("thumbnailUrl"),
            "about": e.get("aboutMe"),
            "location": e.get("currentLocation"),
            "accounts": accounts,
        }
    except Exception:
        logger.exception("gravatar lookup failed")
        return None


def holehe_available() -> bool:
    try:
        import holehe  # noqa: F401
        return True
    except Exception:
        return False


def _holehe_functions() -> list:
    """All holehe check functions (lazy import; raises if unavailable)."""
    from holehe.core import get_functions, import_submodules

    modules = import_submodules("holehe.modules")
    return get_functions(modules)


async def holehe_scan(email: str, on_result: Callable[[dict], None],
                      only: Optional[set[str]] = None,
                      delay: float = HOLEHE_DELAY_S) -> list[dict]:
    """Run holehe modules sequentially (rate-friendly), streaming results.

    Each result dict: {site, domain, exists, rate_limit, error?, others?}.
    Calls ``on_result`` per completed module. Never raises. ``only`` (a set of
    normalized site names) restricts the run to a subset — used by the
    watchlist monitor's light scans.
    """
    results: list[dict] = []
    try:
        functions = _holehe_functions()
    except Exception:
        logger.exception("holehe import failed")
        on_result({"site": "holehe", "error": "holehe unavailable"})
        return results
    if only is not None:
        functions = [fn for fn in functions if fn.__name__.lower() in only]

    async with httpx.AsyncClient(
        timeout=HOLEHE_MODULE_TIMEOUT_S,
        headers={"User-Agent": BROWSER_UA},
        follow_redirects=True,
    ) as client:
        for fn in functions:
            site = fn.__name__
            out: list = []
            entry: dict
            try:
                await asyncio.wait_for(
                    fn(email, client, out), timeout=HOLEHE_MODULE_TIMEOUT_S
                )
                if out:
                    r = out[0]
                    entry = {
                        "site": r.get("name", site),
                        "domain": r.get("domain"),
                        "exists": bool(r.get("exists")),
                        "rate_limit": bool(r.get("rateLimit")),
                        "email_recovery": r.get("emailrecovery"),
                        "phone_number": r.get("phoneNumber"),
                        "others": r.get("others"),
                    }
                else:
                    entry = {"site": site, "exists": False, "rate_limit": False}
            except Exception as exc:
                entry = {
                    "site": site,
                    "exists": None,
                    "error": f"{type(exc).__name__}",
                }
            results.append(entry)
            try:
                on_result(entry)
            except Exception:
                logger.exception("holehe on_result callback failed")
            await asyncio.sleep(delay)
    return results
