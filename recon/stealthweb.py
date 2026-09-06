"""Optional stealth fetch ladder — Scrapling-backed tiers behind plain httpx.

Enrichment and verification fetch profile pages with a plain ``httpx`` client
(:mod:`recon.safeweb`). That client is fast and SSRF-hardened, but it is also
exactly what modern anti-bot stacks fingerprint and block: a non-browser TLS
handshake, a static User-Agent, no JS. On blocked sites enrichment returns an
empty shell or a challenge page, verification degrades to "indeterminate", and
the run loses leads it actually found.

This module adds two escalation tiers *behind* the plain client, using
`Scrapling <https://github.com/D4Vinci/Scrapling>`_ as an **optional**
dependency:

* **Tier 2** (:func:`fetch_tls`) — one-shot request with browser TLS-fingerprint
  impersonation (curl-cffi under the hood). Cheap (~one normal request), fixes
  TLS/JA3-class blocks. No browser involved.
* **Tier 3** (:func:`fetch_browser`) — a shared headless stealth-browser session
  that *renders* JS-driven pages on permitted hosts (single-page-app profiles
  whose plain HTML is an empty shell). Expensive (seconds per page), so callers
  budget it explicitly per run.

**What tier 3 is not** (owner decision, security audit F-7): it never solves
challenges. Scrapling's ``solve_cloudflare`` clicks Cloudflare's Turnstile box
and its default ``google_search=True`` sends a forged Google ``Referer``; both
contradict the project's "no CAPTCHA bypass / honest client" posture. The
session is built with ``solve_cloudflare=False`` and ``google_search=False``,
:func:`fetch_browser` has no way to switch the solver on, and a challenge page
seen through any tier is a **blocked** outcome — the row stays
``indeterminate``. Rendering a page is not defeating a protection; clicking a
CAPTCHA is.

Browser hygiene (F-12): downloads are disabled (``accept_downloads=False`` via
Playwright's context options), tier-3 fetches are serialised, and the
persistent context's cookies are cleared whenever the target host changes so
one site cannot observe the sequence of other sites in the investigation.
Residual: Scrapling launches a persistent context over a temporary profile
directory, and Playwright exposes no context-level "clear storage" — DOM
storage written by one host survives within the process until
:func:`aclose`. Documented, not hidden.

Rate limits are not escalated: a 429/503 from the plain client means "back
off", and answering it with two more disguised requests is exactly what a
rate-limited host is asking us not to do (:func:`should_escalate`).

Everything degrades gracefully: if ``scrapling[fetchers]`` is not installed,
or ``RECON_STEALTH=off``, both tiers are inert no-ops and behaviour is exactly
as before. If the browsers are missing (``scrapling install`` was never run),
tier 3 disables itself after its first failed launch instead of retrying on
every page. The session is created lazily inside the running event loop and
closed from the app's lifespan shutdown handler (:func:`aclose`).

SSRF: these tiers bypass httpx, so they bypass the httpx request hook too.
Every URL is therefore pre-validated with :func:`recon.safeweb.assert_public_url`
before it reaches curl-cffi or a browser. Residual caveat (documented in
safeweb): redirect hops are followed inside curl-cffi/the browser where our
hook cannot see them — the same accepted rebinding risk as the httpx path.

The page-class helpers (:func:`visible_text`, :func:`has_challenge_markers`,
:func:`looks_like_shell`) live in :mod:`recon.htmltext` and are re-exported
here so existing callers keep working; the marker list is the one shared list.

Environment knobs:

* ``RECON_STEALTH``       ``auto`` (default: use tiers when importable) | ``off``
* nothing to configure for tier 2; tier 3 additionally needs the browsers
  installed once via ``scrapling install``
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Optional
from urllib.parse import urlparse

from recon.htmltext import (
    CHALLENGE_MARKERS,
    MIN_VISIBLE_CHARS,
    has_challenge_markers,
    looks_like_shell,
    visible_text,
)

__all__ = [
    "CHALLENGE_MARKERS", "MIN_VISIBLE_CHARS", "RATE_LIMIT_STATUSES",
    "visible_text", "has_challenge_markers", "looks_like_shell",
    "should_escalate", "enabled", "fetch_tls", "fetch_browser", "aclose",
]

logger = logging.getLogger("recon.stealthweb")

try:  # optional dependency — absence must never break the app
    from scrapling.fetchers import AsyncFetcher, AsyncStealthySession

    _IMPORTABLE = True
except Exception:  # pragma: no cover - exercised only without the extra
    AsyncFetcher = None
    AsyncStealthySession = None
    _IMPORTABLE = False

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def _mode() -> str:
    return (os.environ.get("RECON_STEALTH") or "auto").strip().lower()


def enabled() -> bool:
    """True when the ladder may be used (dependency present, not switched off)."""
    return _IMPORTABLE and _mode() != "off"


_TIER2_TIMEOUT_S = 15.0
_TIER3_TIMEOUT_S = 45.0
_MAX_HTML_BYTES = 512 * 1024

# Rotate the TLS/JA3 fingerprint per request so a WAF can't pin us to one
# Chrome fingerprint. All four are valid curl_cffi aliases (resolve to latest).
_TLS_IMPERSONATE = ["chrome", "firefox", "safari", "edge"]

# Statuses that mean "you are sending too much" — never answered with more
# requests. Enrichment records a per-host backoff for them instead.
RATE_LIMIT_STATUSES = frozenset({429, 503})


# ---------------------------------------------------------------------------
# Escalation decision (pure function — unit-tested, no network)
# ---------------------------------------------------------------------------

# Statuses that mean "blocked" (not "absent"): worth one better-disguised try.
# 404/410 are deliberately absent — absence is already decisive. 429/503 are
# excluded too: a rate limit is answered by backing off, not by a stealthier
# retry (retrieval audit V7 — one 429 used to trigger three more requests).


def should_escalate(status: Optional[int], html: Optional[str]) -> bool:
    """True when the plain-client result looks blocked/empty enough that a
    stealthier fetch could still turn it into real content.

    ``status is None`` means transport failure (TLS reset, timeout) — common
    against WAF-fronted hosts from datacenter IPs, and sometimes fixed purely
    by impersonating a browser handshake, so it escalates once.

    A 429/503 never escalates, whatever the body says: the host asked us to
    slow down, and a challenge-looking 429 body is still a rate limit.
    """
    if status in RATE_LIMIT_STATUSES:
        return False
    if status is not None and status >= 400 and status not in (404, 410):
        return True
    if has_challenge_markers(html):
        return True
    if status == 200 and html is not None and looks_like_shell(html):
        return True
    if status is None and html is None:
        return True
    return False


# ---------------------------------------------------------------------------
# Tier 2 — TLS-impersonated HTTP (no browser)
# ---------------------------------------------------------------------------


async def fetch_tls(url: str, timeout: float = _TIER2_TIMEOUT_S,
                    ) -> tuple[Optional[int], Optional[str]]:
    """GET ``url`` with a browser-like TLS fingerprint. Returns the same
    ``(status, html)`` shape as the plain client's fetcher; ``(None, None)``
    on any failure. Never raises."""
    if not enabled():
        return None, None
    from recon import safeweb

    try:
        await safeweb.assert_public_url(url)
    except Exception as exc:
        logger.debug("stealth tier-2 blocked by SSRF guard for %s: %s", url, exc)
        return None, None
    try:
        resp = await asyncio.wait_for(
            AsyncFetcher.get(
                url,
                # A list rotates the JA3/TLS fingerprint per request (Scrapling
                # picks one at random) so a WAF can't pin us to one fingerprint.
                impersonate=_TLS_IMPERSONATE,
                stealthy_headers=True,
                # "safe" follows redirects but refuses hops resolving to
                # internal/private IPs — defence in depth for the redirect-SSRF
                # residual (assert_public_url above stays the primary gate).
                follow_redirects="safe",
                timeout=timeout,
            ),
            timeout=timeout + 5.0,
        )
    except Exception as exc:
        logger.debug("stealth tier-2 fetch failed for %s: %s", url, exc)
        return None, None
    status = getattr(resp, "status", None)
    html = getattr(resp, "html_content", None) or ""
    return status, html[:_MAX_HTML_BYTES] or None


# ---------------------------------------------------------------------------
# Tier 3 — shared stealth-browser session (rendering only, never solving)
# ---------------------------------------------------------------------------

_session: Optional[AsyncStealthySession] = None
_session_lock: Optional[asyncio.Lock] = None
_session_dead = False
# Tier-3 fetches are serialised so the cookie hygiene below is deterministic
# (clearing cookies while another host's page is mid-load would break it).
_fetch_lock: Optional[asyncio.Lock] = None
_last_host: Optional[str] = None

# Constructor options for the shared session. Kept as a dict so the posture
# is inspectable and testable without launching a browser.
SESSION_OPTIONS = {
    "max_pages": 2,
    "headless": True,
    # F-7: never solve Cloudflare Turnstile/interstitials — a challenge page
    # is a blocked outcome, and never send Scrapling's forged Google referer.
    "solve_cloudflare": False,
    "google_search": False,
    # We only ever read the HTML for identity fields, so drop
    # images/media/fonts and ad/tracker domains — big latency and bandwidth
    # cut per browser page, no effect on results.
    "disable_resources": True,
    "block_ads": True,
    "timeout": int(_TIER3_TIMEOUT_S * 1000),
    # F-12: Playwright context option (Scrapling merges ``additional_args``
    # into the persistent-context options) — no stray files on disk.
    "additional_args": {"accept_downloads": False},
}


async def _get_session():
    global _session, _session_lock, _session_dead
    if _session_dead:
        return None
    if _session_lock is None:
        _session_lock = asyncio.Lock()
    async with _session_lock:
        if _session_dead:
            return None
        if _session is None:
            try:
                session = AsyncStealthySession(**SESSION_OPTIONS)
                # The constructor only records options — it does NOT launch the
                # browser. Without start() every fetch raises "Context manager
                # has been closed" and tier 3 silently returns nothing, so this
                # await is what actually makes the stealth browser exist.
                await session.start()
                _session = session
            except Exception as exc:
                logger.warning(
                    "stealth browser unavailable (%s) — tier 3 disabled "
                    "(install the browser with: ./venv/bin/patchright install "
                    "chromium)", exc
                )
                _session_dead = True
                return None
        return _session


async def _clear_cookies_if_host_changed(session, url: str) -> None:
    """F-12: wipe the persistent context's cookies when the target host differs
    from the previous tier-3 target, so site A's cookies never travel to site B.
    Best-effort — a failure here must never fail the fetch."""
    global _last_host
    host = (urlparse(url).hostname or "").lower()
    if host and host != _last_host and _last_host is not None:
        ctx = getattr(session, "context", None)
        clear = getattr(ctx, "clear_cookies", None)
        if clear is not None:
            try:
                await clear()
            except Exception:
                logger.debug("stealth tier-3 cookie clear failed", exc_info=True)
    if host:
        _last_host = host


async def fetch_browser(url: str, timeout: float = _TIER3_TIMEOUT_S,
                        ) -> tuple[Optional[int], Optional[str]]:
    """Render ``url`` in the shared headless stealth browser. Same
    ``(status, html)`` contract; ``(None, None)`` on any failure. Never raises.

    Rendering only: there is deliberately no way to enable Scrapling's
    challenge solver from here (F-7). If the rendered page is itself a
    challenge/WAF page the caller's :func:`should_escalate` check rejects it
    and the row stays ``indeterminate`` — blocked, not absent.
    """
    global _session_dead, _fetch_lock

    if not enabled():
        return None, None
    session = await _get_session()
    if session is None:
        return None, None
    from recon import safeweb

    try:
        await safeweb.assert_public_url(url)
    except Exception as exc:
        logger.debug("stealth tier-3 blocked by SSRF guard for %s: %s", url, exc)
        return None, None
    if _fetch_lock is None:
        _fetch_lock = asyncio.Lock()
    try:
        async with _fetch_lock:
            await _clear_cookies_if_host_changed(session, url)
            resp = await asyncio.wait_for(
                session.fetch(url, solve_cloudflare=False, google_search=False),
                timeout=timeout,
            )
    except Exception as exc:
        msg = str(exc).lower()
        if any(hint in msg for hint in ("executable", "not installed",
                                        "failed to launch", "browser")):
            logger.warning(
                "stealth browser launch failed (%s) — tier 3 disabled for "
                "this process (install browsers with: scrapling install)", exc
            )
            _session_dead = True
        else:
            logger.debug("stealth tier-3 fetch failed for %s: %s", url, exc)
        return None, None
    status = getattr(resp, "status", None)
    html = getattr(resp, "html_content", None) or ""
    return status, html[:_MAX_HTML_BYTES] or None


async def aclose() -> None:
    """Shut the shared browser session down (called from app lifespan)."""
    global _session, _last_host
    if _session is not None:
        try:
            await _session.close()
        except Exception:
            logger.debug("stealth session close failed", exc_info=True)
        _session = None
    _last_host = None
