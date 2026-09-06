"""The stealth ladder as an injectable object for :func:`recon.retrieval.fetch`.

Increment G1 made :mod:`recon.retrieval` the only place that decides *how* a
page is fetched, but kept it free of :mod:`recon.stealthweb` so the layer is
testable without a browser: the ladder is an injected
``async (url) -> (status, html, via)``. Until G2 enrichment and the detectors
each carried their own copy of that ladder — tier 2 (TLS-impersonated
request) then tier 3 (headless render) behind a browser budget — with two
different budget scopes (per run in enrichment, a *module global* in the
detectors that any concurrent sweep reset: audit §6 "also noted"). This is
the one implementation; the caller decides the budget's scope by choosing
when to construct it (one per run for enrichment, one per sweep for a
detector fan-out).

Rules (unchanged from the enrichment copy, now enforced in one place):

* Tier 2 first; tier 3 only while budget lasts and only when tier 2 was still
  walled or an empty JS shell.
* Rendering only — there is no way to enable a challenge solver (F-7).
* A 429/503 from any tier is returned as a bare status with no HTML so the
  façade backs the host off (V7) — never a further request.
* "Rescued" means a tier produced a page that no longer looks walled or empty
  (:func:`recon.stealthweb.should_escalate` says no); that ends the ladder
  and is what the per-tier ``*_ok`` counters count. Without a rescue the last
  tier's answer is still returned for re-classification whenever it carries
  evidence — a page (a wall names its WAF, a rendered shell may carry a
  detector's marker in its markup) or a decisive/blocking status (≥ 400) —
  and ``(None, None, via)`` only when a tier returned a bare 2xx with no
  body, so the façade keeps the plain result. Whether a still-walled or
  still-empty page is adopted is then the classification's call, exactly as
  for the plain fetch.
* Every attempt and rescue is counted per tier: the counters are what
  ``summary["run"]["retrieval"]["stealth"]`` persists (architecture §6).
"""

from __future__ import annotations

from typing import Optional

from recon import stealthweb
from recon.retrieval import RATE_LIMIT_STATUSES

__all__ = ["StealthLadder", "TIER2", "TIER3"]

TIER2 = "scrapling_tls"
TIER3 = "scrapling_browser"


class StealthLadder:
    """Tier 2 → tier 3 within ``browser_budget`` tier-3 fetches. Never raises."""

    def __init__(self, browser_budget: int) -> None:
        self.browser_budget = max(0, int(browser_budget))
        self.browser_left = self.browser_budget
        self.tls_attempts = 0
        self.tls_ok = 0
        self.browser_attempts = 0
        self.browser_ok = 0
        self.rate_limited = 0

    @property
    def enabled(self) -> bool:
        """Whether the stealth tiers may be used right now (dependency present,
        not switched off). Checked at call time so a runtime toggle is honoured."""
        return stealthweb.enabled()

    def for_fetch(self) -> Optional["StealthLadder"]:
        """``self`` when the ladder may run, else None — the value to pass as
        :func:`recon.retrieval.fetch`'s ``ladder=``."""
        return self if self.enabled else None

    async def __call__(self, url: str) -> tuple[Optional[int], Optional[str], str]:
        if not self.enabled:
            return None, None, "off"
        self.tls_attempts += 1
        t2_status, t2_html = await stealthweb.fetch_tls(url)
        if t2_status in RATE_LIMIT_STATUSES:
            self.rate_limited += 1
            return t2_status, None, TIER2
        # A rescue is a *page* that no longer looks walled or empty; a bare
        # status with no body passes should_escalate's checks and is not one
        # (the enrichment copy counted it as a TLS rescue).
        if t2_html and not stealthweb.should_escalate(t2_status, t2_html):
            self.tls_ok += 1
            return t2_status, t2_html, TIER2
        fallback: tuple[Optional[int], Optional[str], str] = (t2_status, t2_html, TIER2)
        if self.browser_left > 0:
            self.browser_left -= 1
            self.browser_attempts += 1
            t3_status, t3_html = await stealthweb.fetch_browser(url)
            if t3_status in RATE_LIMIT_STATUSES:
                self.rate_limited += 1
                return t3_status, None, TIER3
            if t3_html and not stealthweb.should_escalate(t3_status, t3_html):
                self.browser_ok += 1
                return t3_status, t3_html, TIER3
            if t3_status is not None:
                fallback = (t3_status, t3_html, TIER3)
        status, html, via = fallback
        if status is None:
            return None, None, via
        # A page (even a wall or a rendered shell) or a 4xx/5xx is evidence
        # for re-classification: a browser-seen 404 is absence, any status
        # beats a transport failure, a wall names its WAF. A bare 2xx with
        # no body is not — the plain result's reason is the better one.
        if html or status >= 400:
            return status, html, via
        return None, None, via

    def snapshot(self) -> dict:
        return {
            "tls_attempts": self.tls_attempts,
            "tls_ok": self.tls_ok,
            "browser_attempts": self.browser_attempts,
            "browser_ok": self.browser_ok,
            "browser_budget": self.browser_budget,
            "browser_budget_left": self.browser_left,
            "rate_limited": self.rate_limited,
        }
