"""Email pivot: Gravatar profile lookup + holehe registered-account checks.

Public data only: Gravatar's public JSON profile API and holehe's checks
against public register/password-reset endpoints. holehe is imported lazily;
if it is missing the gravatar lookup still works.

Honesty rules (G2):

* :func:`gravatar_profile` distinguishes **"no profile"** (a 404, or an empty
  entry list) from **"could not check"** (a 429, a 5xx, a transport failure).
  Until G2 a rate limit rendered as "No public Gravatar profile" (retrieval
  audit §2). The call goes through :func:`recon.retrieval.fetch` and is
  recorded against ``gravatar_json`` in the source registry.
* :func:`holehe_tally` counts what holehe actually **answered**: an entry is
  checked only when ``exists`` is True/False and it is neither rate-limited
  nor errored. "No exposure found" may only be said when the checks ran
  (audit defect 6); the dossier and the exposure summary read this tally.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import time
from typing import Callable, NamedTuple, Optional

from recon import policy, retrieval, safeweb, sources

logger = logging.getLogger("recon.email_pivot")

# Rate-sensitivity knobs: holehe-style checks run sequentially.
HOLEHE_DELAY_S = 0.4
HOLEHE_MODULE_TIMEOUT_S = 15


def _digits(s: Optional[str]) -> str:
    return re.sub(r"\D", "", s or "")


def masked_recovery_matches_phone(masked: Optional[str],
                                  subject_e164: Optional[str]) -> bool:
    """True when a holehe masked recovery phone's visible digits match the
    subject's number.

    Password-reset flows reveal ~the last 2-4 digits of the account's recovery
    phone (e.g. ``"•••-•••-2671"``). We require the last 3-4 visible digits to
    equal the subject's last digits — enough to be a meaningful trail, strict
    enough to avoid coincidental 2-digit collisions.
    """
    vis = _digits(masked)
    subj = _digits(subject_e164)
    if len(vis) < 3 or len(subj) < 3:
        return False
    n = min(len(vis), 4)
    return vis[-n:] == subj[-n:]


def annotate_recovery(entry: dict, subject_e164: Optional[str]) -> dict:
    """Flag a holehe entry whose masked recovery phone corroborates the subject
    phone — a real phone↔email↔account trail. Mutates and returns the entry."""
    if entry.get("phone_number") and masked_recovery_matches_phone(
            entry.get("phone_number"), subject_e164):
        entry["corroborates_phone"] = True
    return entry


class GravatarResult(NamedTuple):
    """``profile`` is the public profile (None when there is none);
    ``error`` is set — and ``profile`` None — when the lookup could not be
    made ("could not check: rate limited (HTTP 429)"). Both None means the
    source answered and there is no profile."""
    profile: Optional[dict]
    error: Optional[str] = None


def _profile_from_entry(digest: str, e: dict) -> dict:
    accounts = [
        {
            "name": a.get("name"),
            "domain": a.get("domain"),
            "url": a.get("url"),
            "username": a.get("username"),
        }
        for a in (e.get("accounts") or [])
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


async def gravatar_profile(email: str, *,
                           retrieval_stats: Optional[retrieval.RetrievalStats] = None
                           ) -> GravatarResult:
    """Look up the public Gravatar profile for ``email``. Never raises.

    ``absent`` (404) or an empty entry list → no profile; ``ok`` → the
    profile; ``blocked``/``transport``/``policy``/``ssrf`` → ``error`` with
    retrieval's reason — a "could not check", distinct from "no profile".
    """
    digest = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()
    url = f"https://www.gravatar.com/{digest}.json"
    t0 = time.monotonic()
    try:
        async with safeweb.async_client(timeout=10) as client:
            res = await retrieval.fetch(url, client=client, kind="json",
                                        stats=retrieval_stats)
    except Exception as exc:   # the client itself could not be opened
        res = retrieval.FetchResult(retrieval.TRANSPORT,
                                    f"no response ({type(exc).__name__})",
                                    None, None, type(exc).__name__, final_url=url)
    latency_ms = (time.monotonic() - t0) * 1000
    if res.outcome == retrieval.ABSENT:
        sources.record("gravatar_json", True, latency_ms)
        return GravatarResult(None)
    if res.outcome != retrieval.OK:
        sources.record("gravatar_json", False, latency_ms, res.reason)
        logger.info("gravatar could not be checked: %s", res.reason)
        return GravatarResult(None, f"could not check: {res.reason}")
    sources.record("gravatar_json", True, latency_ms)
    data = res.data if isinstance(res.data, dict) else {}
    entries = data.get("entry") or []
    if not entries or not isinstance(entries[0], dict):
        return GravatarResult(None)
    try:
        return GravatarResult(_profile_from_entry(digest, entries[0]))
    except Exception:
        logger.exception("gravatar profile parse failed")
        return GravatarResult(None, "could not check: unexpected profile shape")


async def gravatar_lookup(email: str) -> Optional[dict]:
    """Profile-or-None view of :func:`gravatar_profile` (kept for callers that
    only want the profile; the pipeline uses the full result)."""
    return (await gravatar_profile(email)).profile


# --- holehe honesty ----------------------------------------------------------

def holehe_entry_checked(entry: dict) -> bool:
    """True when a holehe entry is a decisive answer (exists True/False) and
    not a rate limit or an error — the only case that may later say "gone"
    (watchlist, defect 5) or "no exposure" (dossier, defect 6)."""
    if not isinstance(entry, dict):
        return False
    return (entry.get("exists") is not None and not entry.get("rate_limit")
            and not entry.get("error"))


def holehe_tally(entries: Optional[list]) -> dict:
    """Counts over a holehe result list (pure): ``total`` modules that ran,
    ``checked_ok`` decisive answers, ``hits`` positives, ``rate_limited`` and
    ``errors``, and ``undetermined`` — True when nothing was found **and**
    fewer than half the modules answered, i.e. "no exposure found" would be
    a claim the checks cannot support (audit defect 6)."""
    rows = [e for e in (entries or []) if isinstance(e, dict)]
    total = len(rows)
    checked_ok = sum(1 for e in rows if holehe_entry_checked(e))
    hits = sum(1 for e in rows if e.get("exists"))
    rate_limited = sum(1 for e in rows if e.get("rate_limit"))
    errors = sum(1 for e in rows if e.get("error"))
    return {
        "total": total,
        "checked_ok": checked_ok,
        "hits": hits,
        "rate_limited": rate_limited,
        "errors": errors,
        "undetermined": bool(total) and hits == 0 and checked_ok < 0.5 * total,
    }


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
    # Access policy: holehe ships instagram/twitter/pinterest/flickr modules
    # that post to robots-denied hosts, and every one ran on every email
    # pivot (security F-2). Skipped modules emit nothing — they were not
    # checked, and a missing row must never read as "not registered".
    functions, skipped = policy.partition_check_functions(functions)
    if skipped:
        logger.debug("holehe: %d module(s) skipped by access policy: %s",
                     len(skipped), ", ".join(skipped))

    async with safeweb.async_client(timeout=HOLEHE_MODULE_TIMEOUT_S) as client:
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
