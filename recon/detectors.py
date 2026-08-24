"""Content-based existence detectors — the second half of our own discovery
engine, for high-value platforms that have **no clean public API** but whose
robots.txt **permits** the profile path.

Where :mod:`recon.adapters` reads a JSON API, a detector fetches the public
profile HTML and decides existence from **content markers** — a token that
appears only on a real profile, or a "not found" marker — instead of the
fragile status-only guess the third-party engines rely on. When an honest plain
fetch is anti-bot-walled, it escalates through the same stealth ladder as
enrichment (:mod:`recon.stealthweb`): TLS-impersonated, **never** a CAPTCHA
bypass and **never** a robots-denied host.

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
from typing import Optional

from recon import policy, safeweb, stealthweb
from recon.engines import normalize_site

logger = logging.getLogger("recon.detectors")

TIMEOUT_S = 12
MAX_BODY_BYTES = 512 * 1024
USER_AGENT = ("sherlock-web/1.0 (OSINT account verification; "
              "+https://github.com/oduameh/sherlock-web)")

EXISTS = "exists"
ABSENT = "absent"
BLOCKED = "blocked"


class HtmlDetector:
    """A declarative content-based profile check for one platform.

    ``present`` markers appear only on a real profile; ``absent`` markers appear
    on the not-found page. Existence is decided by markers first, status second.
    """

    def __init__(self, name: str, sites: tuple, url: str,
                 present: tuple = (), absent: tuple = (),
                 absent_status: tuple = (404, 410),
                 stealth: bool = True, note: str = ""):
        self.name = name
        self.sites = {normalize_site(s) for s in sites}
        self.url = url
        self.present = tuple(present)
        self.absent = tuple(absent)
        self.absent_status = absent_status
        self.stealth = stealth
        self.note = note

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
        if any(m.lower() in low for m in self.absent):
            return ABSENT
        # A real profile always carries a present-marker, so a 200 without one
        # is a soft-404 — absent, not a false "exists".
        if self.present:
            return ABSENT
        return BLOCKED

    async def check(self, username: str) -> dict:
        """Run the detector. Never raises; returns an adapter-shaped result."""
        url = self.profile_url(username)
        out: dict = {"detector": self.name, "source_url": url}
        reason = policy.denied_reason(url)
        if reason:
            out.update(status=BLOCKED, signal=f"policy: {reason}")
            return out

        status, html = await _fetch(url)
        # Anti-bot wall on an honest fetch → escalate via the stealth ladder
        # (still SSRF-guarded, still robots-permitted; never a denied host).
        if (self.stealth and stealthweb.enabled()
                and stealthweb.should_escalate(status, html)):
            st2, html2 = await stealthweb.fetch_tls(url)
            if st2 is not None:
                status, html = st2, html2

        verdict = self.classify(status, html)
        out["http_status"] = status
        out["status"] = verdict
        if verdict == EXISTS:
            out["signal"] = f"{self.name} profile page confirms this account exists"
            out["identity"] = _identity_from_html(html, url)
            out["temporal"] = {}
        elif verdict == ABSENT:
            out["signal"] = f"{self.name}: no such profile"
        else:
            out["signal"] = f"{self.name}: blocked — cannot determine"
        return out


async def _fetch(url: str) -> tuple:
    """Plain capped HTML GET. Returns ``(status, html)`` or ``(None, None)``."""
    try:
        async with safeweb.async_client(timeout=TIMEOUT_S) as client:
            async with client.stream(
                    "GET", url, headers={"User-Agent": USER_AGENT}) as resp:
                status = resp.status_code
                ct = (resp.headers.get("content-type") or "").lower()
                if "html" not in ct and "text" not in ct:
                    return status, None
                chunks: list = []
                size = 0
                async for chunk in resp.aiter_bytes(16384):
                    chunks.append(chunk)
                    size += len(chunk)
                    if size >= MAX_BODY_BYTES:
                        break
                body = b"".join(chunks).decode(
                    resp.encoding or "utf-8", errors="replace")
                return status, body
    except Exception as exc:
        logger.debug("detector fetch failed for %s: %s", url, exc)
        return None, None


def _identity_from_html(html: Optional[str], url: str) -> dict:
    """Reuse the enrichment extractor for name/avatar/bio from the profile."""
    from recon.enrich import _extract
    try:
        data = _extract(html or "", url)
    except Exception:
        return {}
    ident: dict = {}
    name = data.get("jsonld_name") or data.get("og_title")
    if name:
        ident["display_name"] = name
    avatar = data.get("jsonld_image") or data.get("og_image")
    if avatar:
        ident["avatar"] = avatar
    bio = data.get("jsonld_description") or data.get("og_description")
    if bio:
        ident["bio"] = bio
    return ident


# --- the registry ----------------------------------------------------------
DETECTORS: list[HtmlDetector] = [
    HtmlDetector(
        "Telegram", ("Telegram", "t.me"),
        "https://t.me/{username}",
        present=("tgme_page_title",),
        absent_status=(404,),
        note="Real users render a tgme_page_title block; a nonexistent handle "
             "returns a bare 'Telegram: Contact @handle' page without it. t.me "
             "serves no robots.txt (allow-all). Verified 2026-08-24.",
    ),
    HtmlDetector(
        "Steam", ("Steam", "steamcommunity"),
        "https://steamcommunity.com/id/{username}",
        present=("g_rgProfileData",),
        absent=("specified profile could not be found", "error_ctn"),
        note="Vanity /id/ profile. Real profiles embed g_rgProfileData; the "
             "not-found page shows 'could not be found'. robots permits /id/ "
             "(/trade,/actions,/email,... are disallowed). Verified 2026-08-24.",
    ),
    HtmlDetector(
        "Gravatar", ("Gravatar",),
        "https://gravatar.com/{username}",
        present=("og:image",),
        absent_status=(404,),
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


async def discover(username: str) -> list:
    """Run every content detector for ``username`` concurrently. Returns
    ``{site, url, identity, temporal, source_url}`` for EXISTS results only.
    Never raises. Bounded to a real handle — never fanned across candidates."""
    if not username:
        return []

    async def _one(d: HtmlDetector) -> Optional[dict]:
        try:
            res = await d.check(username)
        except Exception:
            return None
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
