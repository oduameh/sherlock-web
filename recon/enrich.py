"""Best-effort public profile enrichment.

Fetches each found profile page (public HTML only) and extracts <title>,
Open Graph tags, and JSON-LD Person fields. Regex-based parsing wrapped in
try/except everywhere: weird HTML must never crash a run. Responses are
streamed and capped so memory stays bounded.
"""

from __future__ import annotations

import asyncio
import html as _html
import json
import logging
import os
import re
from typing import Any, Callable, Optional
from urllib.parse import urlparse

import httpx

from recon import adapters, policy, safeweb, stealthweb
from recon.verify import verify_username

logger = logging.getLogger("recon.enrich")

MAX_BODY_BYTES = 512 * 1024  # stop reading after 512 KB
MAX_ENRICH_PER_RUN = 80
CONCURRENCY = 5
TIMEOUT_S = 10

# Per-run cap on tier-3 (headless browser) fetches — each one costs seconds.
STEALTH_BROWSER_BUDGET = int(os.environ.get("RECON_STEALTH_BUDGET") or "8")

# A handle that will not exist anywhere. Fetching a site at this handle gives a
# "known-negative" page to compare each real hit against (soft-404 detection).
CONTROL_HANDLE = "qzx9no7such8user2wj"

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_META_OG_RE = re.compile(
    r'<meta[^>]+(?:property|name)=["\'](og:[a-z_]+)["\'][^>]*>', re.I
)
_CONTENT_ATTR_RE = re.compile(r'content=["\'](.*?)["\']', re.I | re.S)
_JSONLD_RE = re.compile(
    r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
    re.I | re.S,
)
_TAG_RE = re.compile(r"<[^>]+>")


def _clean(text: Optional[str]) -> Optional[str]:
    if not text:
        return None
    text = _TAG_RE.sub(" ", text)
    text = _html.unescape(text)   # decode &amp; &#233; &quot; — was silently kept
    return re.sub(r"\s+", " ", text).strip() or None


def _clean_url(url: Optional[str]) -> Optional[str]:
    """Image/URL fields: decode entities but keep the URL intact (no tag strip)."""
    if not url:
        return None
    return _html.unescape(url).strip() or None


def _person_fields(obj: Any, data: dict) -> None:
    """Recursively pull name/description/image from JSON-LD Person/ProfilePage."""
    if isinstance(obj, list):
        for item in obj:
            _person_fields(item, data)
        return
    if not isinstance(obj, dict):
        return
    types = obj.get("@type")
    if isinstance(types, str):
        types = [types]
    if types and any(str(t).lower() in ("person", "profilepage") for t in types):
        if obj.get("name") and not data.get("jsonld_name"):
            data["jsonld_name"] = _clean(str(obj["name"]))
        if obj.get("description") and not data.get("jsonld_description"):
            data["jsonld_description"] = _clean(str(obj["description"]))
        img = obj.get("image")
        if isinstance(img, dict):
            img = img.get("url")
        if isinstance(img, list) and img:
            img = img[0].get("url") if isinstance(img[0], dict) else img[0]
        if img and not data.get("jsonld_image"):
            data["jsonld_image"] = _clean_url(str(img))
    for v in obj.values():
        if isinstance(v, (dict, list)):
            _person_fields(v, data)


def _extract_regex(html_text: str) -> dict:
    """Pure-stdlib fallback extractor (used when Scrapling is unavailable)."""
    data: dict[str, Any] = {}
    m = _TITLE_RE.search(html_text)
    if m:
        data["title"] = _clean(m.group(1))
    for tag_m in _META_OG_RE.finditer(html_text):
        prop = tag_m.group(1).lower()
        c = _CONTENT_ATTR_RE.search(tag_m.group(0))
        if not c:
            continue
        if prop == "og:title":
            data["og_title"] = _clean(c.group(1))
        elif prop == "og:description":
            data["og_description"] = _clean(c.group(1))
        elif prop == "og:image":
            data["og_image"] = _clean_url(c.group(1))
    for m in _JSONLD_RE.finditer(html_text):
        try:
            parsed = json.loads(m.group(1).strip())
        except Exception:
            continue
        _person_fields(parsed, data)
    return data


_SELECTOR = None
_selector_tried = False


def _get_selector():
    """Lazy, optional Scrapling parser (lxml-backed). None if not installed."""
    global _SELECTOR, _selector_tried
    if not _selector_tried:
        _selector_tried = True
        try:
            from scrapling import Selector
            _SELECTOR = Selector
        except Exception:
            _SELECTOR = None
    return _SELECTOR


def _extract_scrapling(html_text: str, url: str) -> Optional[dict]:
    """Scrapling/lxml extraction — tolerant of malformed HTML, decodes entities,
    and reaches fields the regex path never captured (``<meta name=description>``,
    Twitter cards). Returns None if Scrapling is unavailable or the parse fails."""
    Selector = _get_selector()
    if Selector is None:
        return None
    try:
        sel = Selector(html_text, url=url or "")
    except Exception:
        return None

    def one(query: str, clean: bool = True) -> Optional[str]:
        try:
            res = sel.css(query)
            val = res.get() if res is not None else None
        except Exception:
            return None
        if not val:
            return None
        return _clean(val) if clean else _clean_url(val)

    data: dict[str, Any] = {}
    title = one("title::text")
    if title:
        data["title"] = title
    ogt = (one('meta[property="og:title"]::attr(content)')
           or one('meta[name="og:title"]::attr(content)'))
    if ogt:
        data["og_title"] = ogt
    ogd = (one('meta[property="og:description"]::attr(content)')
           or one('meta[name="og:description"]::attr(content)'))
    if ogd:
        data["og_description"] = ogd
    ogi = (one('meta[property="og:image"]::attr(content)', clean=False)
           or one('meta[name="og:image"]::attr(content)', clean=False))
    if ogi:
        data["og_image"] = ogi
    # Fallbacks the old regex extractor missed entirely.
    if not data.get("og_title"):
        data["og_title"] = one('meta[name="twitter:title"]::attr(content)')
    if not data.get("og_description"):
        data["og_description"] = (
            one('meta[name="description"]::attr(content)')
            or one('meta[name="twitter:description"]::attr(content)'))
    if not data.get("og_image"):
        data["og_image"] = (
            one('meta[name="twitter:image"]::attr(content)', clean=False)
            or one('meta[property="twitter:image"]::attr(content)', clean=False))
    # JSON-LD via Scrapling's one-call JSON parse, with a text->json fallback.
    try:
        for script in sel.css('script[type="application/ld+json"]'):
            parsed = None
            try:
                parsed = script.json()
            except Exception:
                try:
                    raw = script.text
                    parsed = json.loads(str(raw)) if raw else None
                except Exception:
                    parsed = None
            if parsed is not None:
                _person_fields(parsed, data)
    except Exception:
        pass
    return {k: v for k, v in data.items() if v}


def _extract(html: str, url: str = "") -> dict:
    """Extract identity fields from a profile page. Prefers Scrapling's lxml
    parser (resilient, entity-decoding); falls back to regex when Scrapling is
    absent, and backfills any gap with the regex path either way."""
    data = None
    try:
        data = _extract_scrapling(html, url)
    except Exception:
        data = None
    if not data:
        return _extract_regex(html)
    rx = _extract_regex(html)
    for k, v in rx.items():
        if v and not data.get(k):
            data[k] = v
    return data


async def _fetch_page(client: httpx.AsyncClient,
                      url: str) -> tuple[Optional[int], Optional[str]]:
    """GET a page (≤ MAX_BODY_BYTES). Returns (status_code, html). ``html`` is
    None for a non-HTML response or a read error; ``status_code`` is None only
    when the request itself failed (DNS/timeout/etc.)."""
    try:
        async with client.stream("GET", url) as resp:
            status = resp.status_code
            ctype = resp.headers.get("content-type", "")
            if "text/html" not in ctype and "application/xhtml" not in ctype:
                return status, None
            chunks: list[bytes] = []
            size = 0
            async for chunk in resp.aiter_bytes(16384):
                chunks.append(chunk)
                size += len(chunk)
                if size >= MAX_BODY_BYTES:
                    break
            html = b"".join(chunks).decode(resp.encoding or "utf-8",
                                           errors="replace")
            return status, html
    except Exception:
        return None, None


def _control_url(url: Optional[str], username: Optional[str]) -> Optional[str]:
    """Build the same profile URL for a known-nonexistent handle, by swapping
    the last occurrence of the username. None if the handle isn't in the URL."""
    if not url or not username or username not in url:
        return None
    idx = url.rfind(username)
    return url[:idx] + CONTROL_HANDLE + url[idx + len(username):]


# Verify the results most likely to be false positives first: base handles are
# few and usually real; name-derived candidates are the noisy set that most
# needs a verdict; variants last.
_SOURCE_ORDER = {"base": 0, "name": 1, "variant": 2}


def _verify_priority(row: dict) -> tuple:
    # Adapter-covered rows first: they are cheap, authoritative, and yield
    # identity + dates, so they are the best possible use of the budget.
    has_adapter = adapters.adapter_for(row.get("site") or "") is not None
    return (0 if has_adapter else 1,
            _SOURCE_ORDER.get(row.get("source"), 3),
            -len(row.get("engines") or []))


async def enrich_profiles(rows: list[dict],
                          on_enriched: Callable[[dict, dict], Any],
                          limit: int = MAX_ENRICH_PER_RUN,
                          subject_name: Optional[str] = None) -> int:
    """Enrich + verify up to ``limit`` found-profile rows (mutates in place).

    Each fetched row gets ``row["enrichment"]`` (extracted metadata) and an
    advisory ``row["verification"]`` verdict (see :mod:`recon.verify`) — which
    now includes a **control-probe soft-404 check** (a cached fetch of a
    known-nonexistent handle per site) and, when ``subject_name`` is given, a
    profile-name attribution check. The noisiest rows (name-derived candidates)
    are verified first. ``on_enriched(row, data)`` is called once per row that
    receives a verdict — including hard-404s and soft-404s (so the UI can label
    them). Returns the number of profiles processed.
    """
    seen_urls: set[str] = set()
    targets: list[dict] = []
    skipped: list[dict] = []
    for row in sorted(rows, key=_verify_priority):
        url = row.get("url")
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        if len(targets) < limit:
            targets.append(row)
        else:
            skipped.append(row)
    # Anything we never fetched must say so explicitly. An unexamined row is not
    # a weak finding — it is no finding at all, and it must never be presented
    # alongside verified ones as though someone had checked it.
    for row in skipped:
        row.setdefault("verification", {
            "status": "not_examined",
            "score": 0,
            "signals": ["not fetched — verification budget exhausted"],
            "reason": "budget_exhausted",
        })

    sem = asyncio.Semaphore(CONCURRENCY)
    count = 0
    # One control fetch per site host, shared across every hit on that site.
    control_cache: dict[str, tuple] = {}
    control_locks: dict[str, asyncio.Lock] = {}
    # Per-run budget for tier-3 (headless browser) fetches; decremented inline
    # (single event loop, no await between read and write → no lost updates).
    browser_budget = {"left": max(0, STEALTH_BROWSER_BUDGET)}
    stealth_used = {"tls": 0, "browser": 0}

    async def escalate(url: str) -> tuple[Optional[int], Optional[str], str]:
        """Stealth ladder behind a failed/blocked plain fetch: tier-2
        (TLS-impersonated request) first, then tier-3 (headless browser with
        challenge solving) while budget lasts. Returns ``(status, html, via)``
        — the best evidence found: full content from whichever tier produced
        a usable page, else just the tier's decisive status (e.g. a real 404
        seen through a browser fingerprint), else ``(None, None, ...)`` to
        keep the plain result untouched."""
        t2_status, t2_html = await stealthweb.fetch_tls(url)
        if not stealthweb.should_escalate(t2_status, t2_html):
            stealth_used["tls"] += 1
            return t2_status, t2_html, "scrapling_tls"
        fallback_status = t2_status
        if browser_budget["left"] > 0:
            browser_budget["left"] -= 1
            t3_status, t3_html = await stealthweb.fetch_browser(url)
            if t3_html and not stealthweb.should_escalate(t3_status, t3_html):
                stealth_used["browser"] += 1
                return t3_status, t3_html, "scrapling_browser"
            if t3_status is not None:
                fallback_status = t3_status
        return fallback_status, None, "httpx"

    async with safeweb.async_client(timeout=TIMEOUT_S) as client:

        async def control_for(url: str, username: str) -> tuple:
            """(status, html, extracted) for a known-nonexistent handle on this
            site, fetched once per host. ({}, None, None) if not applicable."""
            curl = _control_url(url, username)
            if not curl:
                return None, None, None
            host = urlparse(url).netloc
            lock = control_locks.setdefault(host, asyncio.Lock())
            async with lock:
                if host not in control_cache:
                    async with sem:
                        c_status, c_html = await _fetch_page(client, curl)
                    c_data = {}
                    if c_html:
                        try:
                            c_data = _extract(c_html)
                        except Exception:
                            c_data = {}
                    control_cache[host] = (c_status, c_html, c_data)
            return control_cache[host]

        async def work(row: dict) -> None:
            nonlocal count
            # 1. Access policy: some hosts disallow all automated access. We do
            #    not fetch them, and we say so — "we did not look" is honest;
            #    inferring absence from a login wall is not.
            reason = policy.denied_reason(row.get("url") or "")
            if reason:
                row["verification"] = policy.not_examined_verdict(reason)
                count += 1
                try:
                    res = on_enriched(row, {})
                    if asyncio.iscoroutine(res):
                        await res
                except Exception:
                    logger.exception("on_enriched callback failed")
                return

            # 2. Per-site adapter: an authoritative public API beats scraping a
            #    page and guessing. It also yields identity + creation/activity
            #    dates the generic path cannot see.
            adapter = adapters.adapter_for(row.get("site") or "")
            if adapter is not None:
                async with sem:
                    result = await adapter.check(row.get("username") or "")
                row["verification"] = adapters.to_verification(
                    result, subject_name=subject_name)
                ident = result.get("identity") or {}
                temporal = result.get("temporal") or {}
                data = {}
                if ident.get("display_name"):
                    data["jsonld_name"] = ident["display_name"]
                if ident.get("avatar"):
                    data["jsonld_image"] = ident["avatar"]
                if ident.get("bio"):
                    data["jsonld_description"] = ident["bio"]
                if data:
                    row["enrichment"] = data
                if ident:
                    row["platform_identity"] = ident
                if temporal:
                    row["temporal"] = temporal
                row["evidence_source"] = result.get("source_url")
                count += 1
                try:
                    res = on_enriched(row, data)
                    if asyncio.iscoroutine(res):
                        await res
                except Exception:
                    logger.exception("on_enriched callback failed")
                return

            async with sem:
                status, html = await _fetch_page(client, row["url"])
            # Stealth ladder: only when the plain fetch looks blocked or
            # empty, and never for decisive absences (404/410).
            if stealthweb.enabled() and stealthweb.should_escalate(status, html):
                esc_status, esc_html, esc_via = await escalate(row["url"])
                if esc_html is not None:
                    status, html = esc_status, esc_html
                    row["fetch_via"] = esc_via
                    logger.info("stealth fetch rescued %s via %s",
                                row["url"], esc_via)
                elif esc_status is not None and not (status or 0) >= 400:
                    # No content, but a tier answered decisively — upgrade
                    # only the status evidence (e.g. a browser-seen 404).
                    status = esc_status
            c_status, c_html, c_data = await control_for(
                row["url"], row.get("username"))
            try:
                data = _extract(html, row.get("url") or "") if html else {}
            except Exception:
                logger.exception("enrichment parse failed for %s", row["url"])
                data = {}
            row["verification"] = verify_username(
                row.get("username"), row.get("url"), html, data,
                status=status, control_html=c_html, control_extracted=c_data,
                subject_name=subject_name)
            if data:
                row["enrichment"] = data
            count += 1
            try:
                res = on_enriched(row, data)
                if asyncio.iscoroutine(res):
                    await res
            except Exception:
                logger.exception("on_enriched callback failed")

        await asyncio.gather(*(work(r) for r in targets), return_exceptions=True)
    if stealth_used["tls"] or stealth_used["browser"]:
        logger.info("stealth ladder rescued %d profile(s) via TLS impersonation, "
                    "%d via headless browser",
                    stealth_used["tls"], stealth_used["browser"])
    return count
