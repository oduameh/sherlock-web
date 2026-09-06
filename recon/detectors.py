"""Content-based existence detectors — the second half of our own discovery
engine, for high-value platforms that have **no clean public API** but whose
robots.txt **permits** the profile path.

Where :mod:`recon.adapters` reads a JSON API, a detector fetches the public
profile HTML and decides existence from **content markers** — a token that
appears only on a real profile, or a "not found" marker — instead of the
fragile status-only guess the third-party engines rely on. The page comes
through :func:`recon.retrieval.fetch` (G2): the access policy, the SSRF guard,
the per-host backoff, the outcome vocabulary and the stealth ladder
(:class:`recon.ladder.StealthLadder`, TLS-impersonated then a rendering-only
browser, **never** a CAPTCHA bypass and **never** a robots-denied host) are
the shared ones, and every check is recorded against the source registry
(:func:`recon.sources.record`).

Outcome precedence (audit §2 item 7 — a challenge page without the
``present`` marker used to be ABSENT): retrieval's verdict first —
``blocked``/``transport``/``policy``/``ssrf`` is BLOCKED with the reason before
any marker logic, ``absent`` is ABSENT — and only an ``ok`` page is read for
markers. The browser budget is **per sweep** (an argument, no module global:
concurrent runs used to reset each other's budget — audit §6 "also noted").

Same rules as adapters, enforced by review:
  * Public + unauthenticated only; robots.txt must permit the path.
  * Denied hosts (:mod:`recon.policy`) are never fetched — the result is
    ``blocked``, distinct from ``absent``.
  * Every marker below was verified against a known-real and a known-fake
    handle (2026-08-24).
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Optional

from recon import policy, retrieval, safeweb, sources
from recon.engines import normalize_site
from recon.htmltext import has_challenge_markers, has_consent_wall
from recon.ladder import StealthLadder
from recon.retrieval import FetchResult
from recon.rows import avatar as row_avatar, bio as row_bio, display_name as row_display_name

logger = logging.getLogger("recon.detectors")

TIMEOUT_S = 12
MAX_BODY_BYTES = 512 * 1024

EXISTS = "exists"
ABSENT = "absent"
BLOCKED = "blocked"

# Per-sweep cap on tier-3 (headless browser) escalations — each costs seconds.
# One StealthLadder(BROWSER_BUDGET) per :func:`discover` call carries it.
BROWSER_BUDGET = int(os.environ.get("RECON_DETECTOR_BROWSER_BUDGET") or "3")

_UNREADABLE = (retrieval.BLOCKED, retrieval.TRANSPORT, retrieval.POLICY, retrieval.SSRF)


class HtmlDetector:
    """A declarative content-based profile check for one platform.

    ``present`` markers appear only on a real profile; ``absent`` markers appear
    on the not-found page. Existence is decided by markers first, status second.
    ``source`` is the registry name in :mod:`recon.sources` the check is
    recorded against.
    """

    def __init__(self, name: str, sites: tuple, url: str,
                 present: tuple = (), absent: tuple = (),
                 absent_status: tuple = (404, 410),
                 stealth: bool = True, note: str = "",
                 source: Optional[str] = None):
        self.name = name
        self.sites = {normalize_site(s) for s in sites}
        self.url = url
        self.present = tuple(present)
        self.absent = tuple(absent)
        self.absent_status = absent_status
        self.stealth = stealth
        self.note = note
        self.source = source or normalize_site(name)

    def handles(self, site: str) -> bool:
        return normalize_site(site or "") in self.sites

    def profile_url(self, username: str) -> str:
        return self.url.format(username=username)

    def classify(self, status: Optional[int], html: Optional[str]) -> str:
        """Pure marker/status → EXISTS / ABSENT / BLOCKED."""
        if status is None:
            return BLOCKED
        if status in self.absent_status:
            return ABSENT
        if status >= 400:
            return BLOCKED
        low = (html or "").lower()
        if any(m.lower() in low for m in self.present):
            return EXISTS
        # A 200 that is an anti-bot interstitial or a consent wall is a wall,
        # not an answer: without this a walled detector reported ABSENT and
        # the circuit breaker recorded it as healthy. (Bare JS shells are left
        # to the escalation ladder in check(), which runs before classify.)
        if html and (has_challenge_markers(html) or has_consent_wall(html)):
            return BLOCKED
        if any(m.lower() in low for m in self.absent):
            return ABSENT
        # A real profile always carries a present-marker, so a 200 without one
        # is a soft-404 — absent, not a false "exists".
        if self.present:
            return ABSENT
        return BLOCKED

    def outcome(self, res: FetchResult) -> tuple[str, Optional[str]]:
        """``(verdict, reason)`` — retrieval's outcome first, markers second.

        ``blocked``/``transport``/``policy``/``ssrf`` ⇒ BLOCKED with
        :attr:`FetchResult.reason` (a rate limit, a challenge page, a consent
        wall, a login redirect, an exception class); ``absent`` ⇒ ABSENT;
        ``ok`` ⇒ :meth:`classify` on the page. Pure.
        """
        if res.outcome in _UNREADABLE:
            return BLOCKED, res.reason
        if res.outcome == retrieval.ABSENT:
            return ABSENT, None
        return self.classify(res.status, res.html), None

    async def check(self, username: str, *,
                    host_state: Optional[retrieval.HostState] = None,
                    retrieval_stats: Optional[retrieval.RetrievalStats] = None,
                    ladder: Optional[StealthLadder] = None) -> dict:
        """Run the detector. Never raises; returns an adapter-shaped result.

        ``host_state`` / ``retrieval_stats`` are the run's shared retrieval
        state; ``ladder`` the sweep's budgeted stealth ladder (a private one
        is created for a lone call). The check is recorded against
        ``self.source`` in the registry — ``ok`` when the source answered
        (EXISTS or ABSENT), a failure with the reason when it was BLOCKED; a
        policy refusal is not recorded because nothing was fetched.
        """
        url = self.profile_url(username)
        out: dict = {"detector": self.name, "source_url": url}
        reason = policy.denied_reason(url)
        if reason:
            out.update(status=BLOCKED, signal=f"policy: {reason}")
            return out

        if self.stealth and ladder is None:
            ladder = StealthLadder(BROWSER_BUDGET)
        use = ladder.for_fetch() if (self.stealth and ladder is not None) else None
        t0 = time.monotonic()
        try:
            async with safeweb.async_client(timeout=TIMEOUT_S) as client:
                res = await retrieval.fetch(
                    url, client=client, kind="html", host_state=host_state,
                    stats=retrieval_stats, ladder=use,
                    headers={"User-Agent": sources.USER_AGENT},
                    max_bytes=MAX_BODY_BYTES)
        except Exception as exc:   # the client itself could not be opened
            logger.debug("detector fetch failed for %s: %s", url, exc)
            res = FetchResult(retrieval.TRANSPORT, f"no response ({type(exc).__name__})",
                              None, None, type(exc).__name__, final_url=url)
        # A 2xx JS shell is ``ok`` to retrieval. A single-page profile renders
        # one to a plain client and `classify` would call the live account
        # ABSENT — a false negative — so it is rendered (budget-capped, never
        # a challenge solver) before any verdict.
        res = await retrieval.escalate_shell(res, url, ladder=use,
                                             host_state=host_state,
                                             stats=retrieval_stats)
        latency_ms = (time.monotonic() - t0) * 1000

        verdict, why = self.outcome(res)
        out["http_status"] = res.status
        out["status"] = verdict
        if verdict == EXISTS:
            out["signal"] = f"{self.name} profile page confirms this account exists"
            out["identity"] = _identity_from_html(res.html, url)
            out["temporal"] = {}
        elif verdict == ABSENT:
            out["signal"] = f"{self.name}: no such profile"
        else:
            why = why or res.reason
            out["signal"] = f"{self.name}: blocked ({why}) — cannot determine"
        sources.record(self.source, verdict != BLOCKED, latency_ms,
                       why if verdict == BLOCKED else None)
        return out


def _identity_from_html(html: Optional[str], url: str) -> dict:
    """Reuse the enrichment extractor for name/avatar/bio from the profile,
    read back through :mod:`recon.rows` so the precedence (JSON-LD before
    Open Graph, never the raw title) is the one every consumer shares."""
    from recon.enrich import _extract
    try:
        data = _extract(html or "", url)
    except Exception:
        return {}
    row = {"enrichment": data}
    ident: dict = {}
    for key, value in (("display_name", row_display_name(row)),
                       ("avatar", row_avatar(row)), ("bio", row_bio(row))):
        if value:
            ident[key] = value
    return ident


# --- the registry ----------------------------------------------------------
DETECTORS: list[HtmlDetector] = [
    HtmlDetector(
        "Telegram", ("Telegram", "t.me"),
        "https://t.me/{username}",
        present=("tgme_page_title",),
        absent_status=(404,),
        source="telegram",
        note="Real users render a tgme_page_title block; a nonexistent handle "
             "returns a bare 'Telegram: Contact @handle' page without it. t.me "
             "serves no robots.txt (allow-all). Verified 2026-08-24.",
    ),
    HtmlDetector(
        "Steam", ("Steam", "steamcommunity"),
        "https://steamcommunity.com/id/{username}",
        present=("g_rgProfileData",),
        absent=("specified profile could not be found", "error_ctn"),
        source="steam_community",
        note="Vanity /id/ profile. Real profiles embed g_rgProfileData; the "
             "not-found page shows 'could not be found'. robots permits /id/ "
             "(/trade,/actions,/email,... are disallowed). Verified 2026-08-24.",
    ),
    HtmlDetector(
        "Gravatar", ("Gravatar",),
        "https://gravatar.com/{username}",
        present=("og:image",),
        absent_status=(404,),
        source="gravatar_html",
        note="Username profile HTML (NOT the .json, which robots disallows); "
             "404 for a missing user. Verified 2026-08-24.",
    ),
]


def detector_for(site: str) -> Optional[HtmlDetector]:
    for d in DETECTORS:
        if d.handles(site):
            return d
    return None


def covered_sites() -> list:
    return sorted({s for d in DETECTORS for s in d.sites})


async def discover(username: str, stats: Optional[dict] = None, *,
                   host_state: Optional[retrieval.HostState] = None,
                   retrieval_stats: Optional[retrieval.RetrievalStats] = None,
                   ladder: Optional[StealthLadder] = None) -> list:
    """Run every content detector for ``username`` concurrently. Returns
    ``{site, url, identity, temporal, source_url}`` for EXISTS results only.
    Never raises. Bounded to a real handle — never fanned across candidates.

    ``stats``, when given, receives every detector's outcome —
    ``{name: {kind, status, signal, http_status}}`` — including ABSENT and
    BLOCKED, which the return value omits (they were discarded before anyone
    could observe them: audit ops-observability gap 8). Return shape unchanged.

    ``ladder`` is the sweep's browser budget (``BROWSER_BUDGET`` tier-3
    fetches); a fresh one is made per call when none is given, so no sweep
    can spend or reset another's.
    """
    if not username:
        return []
    if ladder is None:
        ladder = StealthLadder(BROWSER_BUDGET)   # fresh budget per sweep

    async def _one(d: HtmlDetector) -> Optional[dict]:
        try:
            res = await d.check(username, host_state=host_state,
                                retrieval_stats=retrieval_stats, ladder=ladder)
        except Exception as exc:
            if stats is not None:
                stats[d.name] = {
                    "kind": "detector", "status": BLOCKED,
                    "signal": f"discover failed ({type(exc).__name__})",
                    "http_status": None,
                }
            return None
        if stats is not None:
            stats[d.name] = {
                "kind": "detector", "status": res.get("status"),
                "signal": res.get("signal"),
                "http_status": res.get("http_status"),
            }
        if res.get("status") != EXISTS:
            return None
        return {
            "site": d.name,
            "url": d.profile_url(username),
            "identity": res.get("identity") or {},
            "temporal": res.get("temporal") or {},
            "source_url": res.get("source_url"),
        }

    results = await asyncio.gather(*(_one(d) for d in DETECTORS),
                                   return_exceptions=True)
    return [r for r in results if isinstance(r, dict)]
