"""WhatsMyName: a third username-search engine.

Runs alongside Sherlock and Maigret over the community-maintained WhatsMyName
dataset (~700 categorized sites). Detection is the WhatsMyName scheme: an
account is *claimed* when the response status equals the site's ``e_code`` and
its ``e_string`` appears in the body; a known "missing" code/string marks it
*available*; anything else is *unknown* (treated as an error by the router).
A site on a robots-denied host is never requested and yields *policy* — not a
vote, not an error (see :data:`POLICY`).

The value of a third engine is less raw coverage (Maigret already spans ~3200
sites) than an **independent vote** — a site confirmed by three engines is a
much stronger signal than one — plus a **category** per site (social / coding /
gaming …) that enriches found accounts.

Data: ``recon/data/wmn-data.json``, vendored from the WhatsMyName project
(https://github.com/WebBreacher/WhatsMyName), (C) Micah Hoffman & contributors,
licensed CC BY-SA 4.0. All fetches go through the SSRF-guarded ``recon.safeweb``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from recon import policy, safeweb, stealthweb
from recon.engines import HIGH_VALUE_SITES, normalize_site

logger = logging.getLogger("recon.whatsmyname")

_DATA_PATH = Path(__file__).resolve().parent / "data" / "wmn-data.json"
_NSFW_CAT = "xx nsfw xx"

MAX_BODY_BYTES = 512 * 1024
WMN_CONCURRENCY = 20

# High-value sites (normalized) eligible for a stealth retry on UNKNOWN.
_HV_NORM = {normalize_site(n) for n in HIGH_VALUE_SITES}
# Per-scan cap on tier-2 stealth retries — bounds cost even on a full fan-out.
_STEALTH_RETRY_BUDGET = int(os.environ.get("RECON_WMN_STEALTH_BUDGET") or "10")

# Status strings mirror the other engines' vocabulary so the router's classifier
# and the pipeline's merge logic treat all three the same way.
CLAIMED = "claimed"
AVAILABLE = "available"
UNKNOWN = "unknown"
# The site's host is robots-denied: never fetched, so this is neither a vote
# nor an error. Until 2026-09-06 denied sites came back UNKNOWN with a
# "policy:" context, which the pipeline emitted as an error row and the router
# recorded as a failure in site_health — eight fake failures per run tripping
# circuits for sites we never touched (audit defect 8). POLICY results must
# not be observed or reported as errors.
POLICY = "policy"

_SITES_CACHE: Optional[list[dict]] = None


@dataclass
class WmnResult:
    status: str
    site_name: str
    site_url_user: str
    category: Optional[str] = None
    context: str = ""
    query_time: Optional[float] = None


def load_sites() -> list[dict]:
    """Load the vendored WhatsMyName site definitions once (cached)."""
    global _SITES_CACHE
    if _SITES_CACHE is not None:
        return _SITES_CACHE
    try:
        data = json.loads(_DATA_PATH.read_text(encoding="utf-8"))
        # Keep only URL-substitution (GET) sites; a minority use POST bodies /
        # GraphQL (no ``{account}`` in the URL), which this GET-only scanner
        # can't check correctly.
        _SITES_CACHE = [s for s in (data.get("sites") or [])
                        if "{account}" in (s.get("uri_check") or "")]
    except Exception:
        logger.exception("failed to load WhatsMyName data")
        _SITES_CACHE = []
    logger.info("WhatsMyName DB loaded: %d usable sites", len(_SITES_CACHE))
    return _SITES_CACHE


def _is_nsfw(site: dict) -> bool:
    return (site.get("cat") or "").strip().lower() == _NSFW_CAT


def all_sites(nsfw: bool = False) -> list[dict]:
    """Every site (optionally including NSFW)."""
    sites = load_sites()
    return sites if nsfw else [s for s in sites if not _is_nsfw(s)]


def url_templates(site: dict) -> list[str]:
    """The URL a WhatsMyName check fetches: ``uri_check`` (``{account}``
    template). ``uri_pretty`` is display-only and never requested."""
    t = site.get("uri_check")
    return [t] if isinstance(t, str) and t else []


def variant_sites(policy_filtered: bool = True) -> list[dict]:
    """The curated high-value subset, for variant / name-candidate scans.

    Policy-filtered by default; ``policy_filtered=False`` is for
    :func:`recon.plan.plan_site_sets`, which filters and reports itself.
    """
    wanted = {normalize_site(n) for n in HIGH_VALUE_SITES}
    picked = [s for s in all_sites() if normalize_site(s.get("name", "")) in wanted]
    if not policy_filtered:
        return picked
    return [s for s in picked
            if policy.denied_site_reason(url_templates(s)) is None]


def classify_response(site: dict, status_code: int, body: str) -> str:
    """Map an HTTP response to CLAIMED / AVAILABLE / UNKNOWN (pure function).

    POLICY is never produced here: a denied site has no response to classify,
    because :func:`_check_site` refuses it before any request.
    """
    e_code = site.get("e_code")
    e_string = site.get("e_string") or ""
    m_code = site.get("m_code")
    m_string = site.get("m_string") or ""

    # Claimed: the found-code matches and the found-string is present (or the
    # site defines no found-string, in which case the code alone decides).
    if status_code == e_code and (not e_string or e_string in body):
        return CLAIMED
    # Explicit "missing" markers.
    if status_code == m_code or (m_string and m_string in body):
        return AVAILABLE
    # Matched the found-code but not the found-string: almost always a soft-404.
    if status_code == e_code:
        return AVAILABLE
    return UNKNOWN


async def _get_capped(client, url: str) -> tuple[Optional[int], str]:
    """GET streaming at most MAX_BODY_BYTES. Returns (status_code, body_text)."""
    async with client.stream("GET", url) as resp:
        chunks: list[bytes] = []
        size = 0
        async for chunk in resp.aiter_bytes(16384):
            chunks.append(chunk)
            size += len(chunk)
            if size >= MAX_BODY_BYTES:
                break
        body = b"".join(chunks).decode(resp.encoding or "utf-8", errors="replace")
        return resp.status_code, body


async def _check_site(client, site: dict, username: str,
                      stealth_retry: bool = False,
                      budget: Optional[dict] = None) -> WmnResult:
    template = site.get("uri_check") or ""
    url = template.replace("{account}", username)
    name = site.get("name", "?")
    cat = site.get("cat")
    # Robots-disallowed host — never fetch it, and never let the stealth retry
    # touch it. A distinct POLICY status (not UNKNOWN): the pipeline neither
    # observes it nor emits it as an error. Plan-time filtering removes such
    # sites before a scan, so this is the last line of defence for direct
    # callers.
    reason = policy.denied_reason(url)
    if reason:
        return WmnResult(POLICY, name, url, cat, f"policy: {reason}")
    # ``query_time`` is the plain request's wall time (success or failure),
    # like Sherlock's. It feeds the router's EWMA latency per site — until
    # 2026-09-06 it was never set, so 0 of 649 WhatsMyName site_health rows
    # had a latency (audit ops-observability §5 / §10 gap 7).
    t0 = time.monotonic()
    try:
        status_code, body = await _get_capped(client, url)
        elapsed = time.monotonic() - t0
        status = classify_response(site, status_code, body)
        # A blocked/ambiguous response on a HIGH-VALUE site is often a WAF/JS
        # interstitial. Spend one budgeted tier-2 stealth fetch (TLS-impersonated,
        # still SSRF-guarded, never tier-3) to try to recover the vote. Gated so
        # it never fans out across the ~700-site dataset.
        if (status == UNKNOWN and stealth_retry and budget is not None
                and budget.get("left", 0) > 0
                and normalize_site(name) in _HV_NORM
                and stealthweb.enabled()):
            budget["left"] -= 1
            try:
                st2, body2 = await stealthweb.fetch_tls(url)
            except Exception:
                st2, body2 = None, None
            if st2 is not None and body2:
                status2 = classify_response(site, st2, body2)
                if status2 != UNKNOWN:
                    return WmnResult(status2, name, url, cat, "stealth-recovered",
                                     query_time=elapsed)
        context = "" if status != UNKNOWN else f"HTTP {status_code}"
        return WmnResult(status, name, url, cat, context, query_time=elapsed)
    except Exception as exc:
        return WmnResult(UNKNOWN, name, url, cat, f"{type(exc).__name__}: {exc}",
                         query_time=time.monotonic() - t0)


async def whatsmyname_scan(username: str, sites: list[dict], timeout: int,
                           on_result: Callable[[WmnResult], None],
                           proxy: Optional[str] = None,
                           stealth_retry: bool = False) -> None:
    """Scan ``username`` across ``sites``, calling ``on_result`` per site.

    Bounded concurrency, all through the SSRF-guarded client. Never raises;
    a failed site check yields an UNKNOWN result. A robots-denied host is never
    requested and yields a POLICY result (callers must not count it as an
    error). With ``stealth_retry`` and the ladder enabled, an UNKNOWN on a
    high-value site gets one budgeted tier-2 stealth retry.
    """
    if not sites:
        return
    sem = asyncio.Semaphore(WMN_CONCURRENCY)
    budget = {"left": _STEALTH_RETRY_BUDGET} if stealth_retry else None
    client_kwargs: dict[str, Any] = {"timeout": float(timeout)}
    if proxy:
        client_kwargs["proxy"] = proxy

    async with safeweb.async_client(**client_kwargs) as client:
        async def one(site: dict) -> None:
            async with sem:
                result = await _check_site(client, site, username,
                                           stealth_retry=stealth_retry,
                                           budget=budget)
            try:
                on_result(result)
            except Exception:
                logger.exception("whatsmyname on_result callback failed")

        await asyncio.gather(*(one(s) for s in sites), return_exceptions=True)
