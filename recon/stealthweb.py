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
  with Cloudflare-challenge solving. Expensive (seconds per page), so callers
  budget it explicitly per run.

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

Environment knobs:

* ``RECON_STEALTH``       ``auto`` (default: use tiers when importable) | ``off``
* nothing to configure for tier 2; tier 3 additionally needs the browsers
  installed once via ``scrapling install``
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from typing import Optional

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


# ---------------------------------------------------------------------------
# Escalation decision (pure functions — unit-tested, no network)
# ---------------------------------------------------------------------------

# Phrases that identify an anti-bot interstitial rather than a real page.
_CHALLENGE_MARKERS = (
    "just a moment",
    "attention required",
    "checking your browser",
    "verify you are a human",
    "verifying you are human",
    "one more step",
    "enable javascript and cookies",
    "ddos protection by",
    "ddos-guard",
    "cf-challenge",
    "challenge-platform",
    "datadome",
    "perimeterx",
    "px-captcha",
    "captcha-delivery",
)

_SCRIPT_STYLE_RE = re.compile(r"<(script|style)\b[^>]*>.*?</\1>", re.I | re.S)
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")

# A page whose entire visible text is shorter than this is a JS-app shell or a
# bare interstitial — there is nothing to extract or verify from it.
_MIN_VISIBLE_CHARS = 80

# Statuses that mean "blocked" (not "absent"): worth one better-disguised try.
# 404/410 are deliberately absent — absence is already decisive.


def visible_text(html: Optional[str], limit: int = 4000) -> str:
    """Strip script/style bodies and tags → collapse whitespace → lowercase."""
    if not html:
        return ""
    chunk = html[: limit * 6]
    chunk = _SCRIPT_STYLE_RE.sub(" ", chunk)
    return _WS_RE.sub(" ", _TAG_RE.sub(" ", chunk)).strip().lower()[:limit]


def has_challenge_markers(html: Optional[str]) -> bool:
    """True when the page smells like an anti-bot interstitial."""
    if not html:
        return False
    low = html[:20000].lower()
    return any(marker in low for marker in _CHALLENGE_MARKERS)


def looks_like_shell(html: Optional[str]) -> bool:
    """True for an empty JS-app shell / boilerplate page with no real text."""
    if not html:
        return False
    return len(visible_text(html)) < _MIN_VISIBLE_CHARS


def should_escalate(status: Optional[int], html: Optional[str]) -> bool:
    """True when the plain-client result looks blocked/empty enough that a
    stealthier fetch could still turn it into real content.

    ``status is None`` means transport failure (TLS reset, timeout) — common
    against WAF-fronted hosts from datacenter IPs, and sometimes fixed purely
    by impersonating a browser handshake, so it escalates once.
    """
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
# Tier 3 — shared stealth-browser session (Cloudflare solving)
# ---------------------------------------------------------------------------

_session: Optional[AsyncStealthySession] = None
_session_lock: Optional[asyncio.Lock] = None
_session_dead = False


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
                _session = AsyncStealthySession(
                    max_pages=2,
                    headless=True,
                    solve_cloudflare=True,
                    # We only ever read the HTML for identity fields, so drop
                    # images/media/fonts and ad/tracker domains — big latency
                    # and bandwidth cut per browser page, no effect on results.
                    disable_resources=True,
                    block_ads=True,
                    timeout=int(_TIER3_TIMEOUT_S * 1000),
                )
            except Exception as exc:
                logger.warning(
                    "stealth browser unavailable (%s) — tier 3 disabled "
                    "(install browsers with: scrapling install)", exc
                )
                _session_dead = True
                return None
        return _session


async def fetch_browser(url: str, timeout: float = _TIER3_TIMEOUT_S,
                        ) -> tuple[Optional[int], Optional[str]]:
    """Fetch ``url`` through the shared headless stealth browser, solving
    Cloudflare challenges. Same ``(status, html)`` contract; ``(None, None)``
    on any failure. Never raises."""
    global _session_dead

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
    try:
        resp = await asyncio.wait_for(
            session.fetch(url, solve_cloudflare=True), timeout=timeout
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
    global _session
    if _session is not None:
        try:
            await _session.close()
        except Exception:
            logger.debug("stealth session close failed", exc_info=True)
        _session = None
