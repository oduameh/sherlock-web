"""Best-effort public profile enrichment.

Fetches each found profile page (public HTML only) and extracts <title>,
Open Graph tags, and JSON-LD Person fields. Regex-based parsing wrapped in
try/except everywhere: weird HTML must never crash a run. Responses are
streamed and capped so memory stays bounded, and every parser is linear in the
input (security audit F-3 — the old ``<title>(.*?)</title>`` took >20 s on a
280 KB page a subject could serve us).

Retrieval rules (retrieval audit V7 and traces a/c):

* **A rate limit is answered by backing off, never by more requests.** A
  429/503 from the plain client used to trigger the stealth ladder (two more
  requests to the same host within seconds) and then the control probe (a
  fourth), and every other row on that host repeated the pattern. Now the
  first 429/503 records a per-host backoff (``Retry-After`` if present, else
  60 s); the row is ``indeterminate`` with ``reason: rate_limited``; later rows
  on that host are given the same verdict *without fetching*; the ladder never
  runs for it. Fetches to one host are serialised so "later" is well-defined.
* **A failed control probe is reported as failed, not cached as "no control".**
  Only a control fetch that produced a page (2xx with HTML) or a decisive
  absence (404/410) is cached per host; a transport failure, non-HTML body or
  blocking status is retried once later in the run and otherwise surfaces as
  ``control_probe: "failed"`` on the verdict.
* **The exception class survives.** ``ConnectTimeout``/``ReadError``/… is put in
  the verdict signal ("no HTML retrieved (ConnectTimeout)") so a stored case
  can say why nothing was retrieved.
"""

from __future__ import annotations

import asyncio
import email.utils
import html as _html
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Callable, NamedTuple, Optional
from urllib.parse import urlparse

import httpx

from recon import adapters, policy, safeweb, stealthweb
from recon.htmltext import (
    META_CONTENT_RE,
    META_KEY_RE,
    TAG_RE,
    TITLE_RE,
    WS_RE,
    iter_jsonld_blocks,
    iter_tags,
)
from recon.stealthweb import RATE_LIMIT_STATUSES
from recon.verify import CONTROL_HANDLE, verify_username

__all__ = ["CONTROL_HANDLE", "FetchResult", "enrich_profiles",
           "strip_template_fields", "rate_limited_verdict"]

logger = logging.getLogger("recon.enrich")

MAX_BODY_BYTES = 512 * 1024  # stop reading after 512 KB
# Verification budget: how many distinct profile URLs get fetched+verified per
# run. Policy-denied hosts are resolved without a fetch and do not count.
MAX_ENRICH_PER_RUN = int(os.environ.get("RECON_VERIFY_BUDGET") or "120")
CONCURRENCY = 5
TIMEOUT_S = 10

# Per-run cap on tier-3 (headless browser) fetches — each one costs seconds.
STEALTH_BROWSER_BUDGET = int(os.environ.get("RECON_STEALTH_BUDGET") or "8")

# Per-host backoff after a 429/503: the ``Retry-After`` header when present
# (clamped), else this default. Per run — nothing persists across runs yet.
DEFAULT_BACKOFF_S = 60.0
MAX_BACKOFF_S = 3600.0

# A control probe that fails is retried at most once more in the same run.
CONTROL_MAX_ATTEMPTS = 2

# Statuses that prove the control handle is absent — a decisive, cacheable
# control result even though there is no page to compare against.
_DECISIVE_ABSENT = frozenset({404, 410})


def _clean(text: Optional[str]) -> Optional[str]:
    if not text:
        return None
    text = TAG_RE.sub(" ", text)
    text = _html.unescape(text)   # decode &amp; &#233; &quot; — was silently kept
    return WS_RE.sub(" ", text).strip() or None


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


def _attr(match) -> Optional[str]:
    """First non-None group of a two-alternative (double/single quote) attribute match."""
    if not match:
        return None
    return match.group(1) if match.group(1) is not None else match.group(2)


def _extract_regex(html_text: str) -> dict:
    """Pure-stdlib fallback extractor (used when Scrapling is unavailable).

    Linear in the input: the title pattern is bounded, ``<meta>`` tags and
    JSON-LD blocks are located with ``str.find`` (F-3) and only the text of one
    tag at a time meets a regex.
    """
    data: dict[str, Any] = {}
    m = TITLE_RE.search(html_text)
    if m:
        data["title"] = _clean(m.group(1))
    for tag in iter_tags(html_text, "meta"):
        prop = (_attr(META_KEY_RE.search(tag)) or "").lower()
        if not prop.startswith("og:"):
            continue
        content = _attr(META_CONTENT_RE.search(tag))
        if content is None:
            continue
        if prop == "og:title":
            data["og_title"] = _clean(content)
        elif prop == "og:description":
            data["og_description"] = _clean(content)
        elif prop == "og:image":
            data["og_image"] = _clean_url(content)
    for block in iter_jsonld_blocks(html_text):
        try:
            parsed = json.loads(block.strip())
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


# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------

class FetchResult(NamedTuple):
    """Outcome of one capped GET.

    ``status`` is None only when the request itself failed (then ``error`` is
    the exception class name, e.g. ``ConnectTimeout``); ``html`` is None for a
    non-HTML response or a read error; ``retry_after`` is the parsed
    ``Retry-After`` in seconds when the status was 429/503 and the header was
    present.
    """
    status: Optional[int]
    html: Optional[str]
    error: Optional[str] = None
    retry_after: Optional[float] = None


MIN_BACKOFF_S = 5.0     # a Retry-After of 0 or a past date still means "back off"


def _parse_retry_after(value: Optional[str]) -> Optional[float]:
    """``Retry-After`` → seconds (clamped to ``MAX_BACKOFF_S``), or None when
    absent/unparseable. Accepts delta-seconds and HTTP-dates."""
    if not value:
        return None
    v = value.strip()
    if v.isdigit():
        secs = float(v)
    else:
        try:
            dt = email.utils.parsedate_to_datetime(v)
        except Exception:
            return None
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        secs = (dt - datetime.now(timezone.utc)).total_seconds()
    return min(max(secs, MIN_BACKOFF_S), MAX_BACKOFF_S)


async def _fetch_page_ex(client: httpx.AsyncClient, url: str) -> FetchResult:
    """GET a page (≤ MAX_BODY_BYTES) and report *why* when nothing came back."""
    try:
        async with client.stream("GET", url) as resp:
            status = resp.status_code
            retry_after = None
            if status in RATE_LIMIT_STATUSES:
                retry_after = _parse_retry_after(resp.headers.get("retry-after"))
            ctype = resp.headers.get("content-type", "")
            if "text/html" not in ctype and "application/xhtml" not in ctype:
                return FetchResult(status, None, None, retry_after)
            chunks: list[bytes] = []
            size = 0
            async for chunk in resp.aiter_bytes(16384):
                chunks.append(chunk)
                size += len(chunk)
                if size >= MAX_BODY_BYTES:
                    break
            html = b"".join(chunks).decode(resp.encoding or "utf-8",
                                           errors="replace")
            return FetchResult(status, html, None, retry_after)
    except Exception as exc:
        return FetchResult(None, None, type(exc).__name__)


async def _fetch_page(client: httpx.AsyncClient,
                      url: str) -> tuple[Optional[int], Optional[str]]:
    """Two-tuple ``(status_code, html)`` view of :func:`_fetch_page_ex`."""
    res = await _fetch_page_ex(client, url)
    return res.status, res.html


def _control_url(url: Optional[str], username: Optional[str]) -> Optional[str]:
    """Build the same profile URL for a known-nonexistent handle, by swapping
    the last occurrence of the username. None if the handle isn't in the URL."""
    if not url or not username or username not in url:
        return None
    idx = url.rfind(username)
    return url[:idx] + CONTROL_HANDLE + url[idx + len(username):]


def _host(url: Optional[str]) -> str:
    """Backoff/lock key: hostname without a leading ``www.`` or default port,
    so ``www.x.com`` and ``x.com`` share one backoff (review nit)."""
    host = (urlparse(url or "").hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


def rate_limited_verdict(status: int, fetched: bool = True) -> dict:
    """The verdict a rate-limited row carries. Blocked, never absent: the host
    told us to slow down, which says nothing about whether the account exists.

    ``fetched=False`` marks a row that was *not* requested because an earlier
    request to the same host was already rate-limited this run — the same
    status/score/reason, with an extra signal saying so.
    """
    signals = [f"rate limited / unavailable (HTTP {status}) — not retried this run"]
    if not fetched:
        signals.append("not fetched: an earlier request to this host was rate "
                       "limited and the host is backing off")
    return {"status": "indeterminate", "score": 30, "signals": signals,
            "reason": "rate_limited"}


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


# Metadata fields a site may stamp identically on every page, profile or not.
_TEMPLATE_CANDIDATES = ("og_image", "og_title", "og_description",
                        "jsonld_name", "jsonld_description", "jsonld_image",
                        "title")


def strip_template_fields(data: dict, control: dict) -> dict:
    """Drop every field whose value is identical on the control page (a fetch
    of a known-nonexistent handle on the same site): such a value describes
    the site, never the person. Pure; returns a new dict with the names of
    the dropped fields under ``template_fields`` (omitted when none)."""
    out = {k: v for k, v in data.items()}
    dropped = []
    for key in _TEMPLATE_CANDIDATES:
        v = out.get(key)
        if v and control.get(key) and str(v).strip() == str(control[key]).strip():
            out.pop(key)
            dropped.append(key)
    if dropped:
        out["template_fields"] = dropped
    return out


async def enrich_profiles(rows: list[dict],
                          on_enriched: Callable[[dict, dict], Any],
                          limit: int = MAX_ENRICH_PER_RUN,
                          subject_name: Optional[str] = None,
                          stats: Optional[dict] = None) -> int:
    """Enrich + verify up to ``limit`` found-profile rows (mutates in place).

    Each fetched row gets ``row["enrichment"]`` (extracted metadata) and an
    advisory ``row["verification"]`` verdict (see :mod:`recon.verify`) — which
    includes a **control-probe soft-404 check** (a cached fetch of a
    known-nonexistent handle per site) and, when ``subject_name`` is given, a
    profile-name attribution check. The noisiest rows (name-derived candidates)
    are verified first. ``on_enriched(row, data)`` is called once per row that
    receives a verdict — including hard-404s, soft-404s and rate-limited rows
    (so the UI can label them). Returns the number of profiles processed.

    ``stats``, when given, is filled with the run's retrieval counters
    (``stealth_tls``, ``stealth_browser``, ``rate_limited_hosts``,
    ``rate_limited_rows``, ``backoff_s`` per host, ``control_failed_hosts``)
    for the pipeline diagnostics to persist.
    """
    seen_urls: set[str] = set()
    targets: list[dict] = []
    skipped: list[dict] = []
    budgeted = 0
    for row in sorted(rows, key=_verify_priority):
        url = row.get("url")
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        # Denied hosts are answered from policy without a fetch — they cost
        # nothing, so they must not consume the budget that real fetches need.
        # (Before this, 28 Instagram/Pinterest/Twitter rows in one run ate a
        # third of the budget and 105 fetchable rows went unexamined.)
        if policy.denied_reason(url):
            targets.append(row)
        elif budgeted < limit:
            targets.append(row)
            budgeted += 1
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
    # Control probe per site host, shared across every hit on that site. Only
    # a control that produced a page (or a decisive 404/410) is cached; a
    # failure is retried once and otherwise reported as failed.
    control_cache: dict[str, tuple] = {}
    control_attempts: dict[str, int] = {}
    control_locks: dict[str, asyncio.Lock] = {}
    control_failed_hosts: set[str] = set()
    # One fetch at a time per host, so a 429 on the first row is seen before
    # the second row on that host is requested.
    host_locks: dict[str, asyncio.Lock] = {}
    # host → (monotonic deadline, status that caused it)
    host_backoff: dict[str, tuple[float, int]] = {}
    backoff_seconds: dict[str, float] = {}
    rate_limited = {"rows": 0}
    # Per-run budget for tier-3 (headless browser) fetches; decremented inline
    # (single event loop, no await between read and write → no lost updates).
    browser_budget = {"left": max(0, STEALTH_BROWSER_BUDGET)}
    stealth_used = {"tls": 0, "browser": 0}

    def record_backoff(host: str, status: int, retry_after: Optional[float]) -> None:
        secs = DEFAULT_BACKOFF_S if retry_after is None else retry_after
        deadline = time.monotonic() + secs
        prev = host_backoff.get(host)
        if prev is None or deadline > prev[0]:
            host_backoff[host] = (deadline, status)
            backoff_seconds[host] = secs
        logger.info("rate limited by %s (HTTP %d) — backing off %.0fs, no more "
                    "requests to it this run", host, status, secs)

    def active_backoff(host: str) -> Optional[int]:
        entry = host_backoff.get(host)
        if entry is None:
            return None
        deadline, status = entry
        if time.monotonic() < deadline:
            return status
        return None

    async def escalate(url: str) -> tuple[Optional[int], Optional[str], str]:
        """Stealth ladder behind a failed/blocked plain fetch: tier-2
        (TLS-impersonated request) first, then tier-3 (headless browser,
        rendering only — never challenge solving) while budget lasts. Returns
        ``(status, html, via)`` — the best evidence found: full content from
        whichever tier produced a usable page, else just the tier's decisive
        status (e.g. a real 404 seen through a browser fingerprint), else
        ``(None, None, ...)`` to keep the plain result untouched. A 429/503
        from any tier is returned as-is with no HTML so the caller backs off."""
        t2_status, t2_html = await stealthweb.fetch_tls(url)
        if t2_status in RATE_LIMIT_STATUSES:
            return t2_status, None, "scrapling_tls"
        if not stealthweb.should_escalate(t2_status, t2_html):
            stealth_used["tls"] += 1
            return t2_status, t2_html, "scrapling_tls"
        fallback_status = t2_status
        if browser_budget["left"] > 0:
            browser_budget["left"] -= 1
            t3_status, t3_html = await stealthweb.fetch_browser(url)
            if t3_status in RATE_LIMIT_STATUSES:
                return t3_status, None, "scrapling_browser"
            if t3_html and not stealthweb.should_escalate(t3_status, t3_html):
                stealth_used["browser"] += 1
                return t3_status, t3_html, "scrapling_browser"
            if t3_status is not None:
                fallback_status = t3_status
        return fallback_status, None, "httpx"

    async with safeweb.async_client(timeout=TIMEOUT_S) as client:

        async def control_for(url: str, username: str
                              ) -> tuple[Optional[int], Optional[str],
                                         Optional[dict], bool]:
            """``(status, html, extracted, failed)`` for a known-nonexistent
            handle on this site. ``(None, None, None, False)`` when no control
            URL can be built; ``failed=True`` when a control was wanted but no
            usable result exists (fetch failed twice, or the host is backing
            off after a rate limit)."""
            curl = _control_url(url, username)
            if not curl:
                return None, None, None, False
            host = _host(url)
            lock = control_locks.setdefault(host, asyncio.Lock())
            async with lock:
                cached = control_cache.get(host)
                if cached is not None:
                    return cached[0], cached[1], cached[2], False
                if active_backoff(host) is not None:
                    return None, None, None, True
                if control_attempts.get(host, 0) >= CONTROL_MAX_ATTEMPTS:
                    return None, None, None, True
                control_attempts[host] = control_attempts.get(host, 0) + 1
                async with sem:
                    res = await _fetch_page_ex(client, curl)
                if res.status in RATE_LIMIT_STATUSES:
                    record_backoff(host, res.status, res.retry_after)
                    control_failed_hosts.add(host)
                    return None, None, None, True
                if res.status in _DECISIVE_ABSENT:
                    # The site 404s unknown handles: decisive, and there is no
                    # page to compare against — cache it, it is not a failure.
                    control_cache[host] = (res.status, None, {})
                    return res.status, None, {}, False
                if res.status is not None and 200 <= res.status < 400 and res.html:
                    try:
                        c_data = _extract(res.html)
                    except Exception:
                        c_data = {}
                    control_cache[host] = (res.status, res.html, c_data)
                    return res.status, res.html, c_data, False
                # Transport failure, non-HTML body, other 4xx/5xx: not cached,
                # so the next row on this host retries once.
                control_failed_hosts.add(host)
                logger.debug("control probe failed for %s (status=%s error=%s)",
                             host, res.status, res.error)
                return res.status, None, None, True

        async def finish(row: dict, data: dict) -> None:
            nonlocal count
            count += 1
            try:
                res = on_enriched(row, data)
                if asyncio.iscoroutine(res):
                    await res
            except Exception:
                logger.exception("on_enriched callback failed")

        async def work(row: dict) -> None:
            url = row.get("url") or ""
            # 1. Access policy: some hosts disallow all automated access. We do
            #    not fetch them, and we say so — "we did not look" is honest;
            #    inferring absence from a login wall is not.
            reason = policy.denied_reason(url)
            if reason:
                row["verification"] = policy.not_examined_verdict(reason)
                await finish(row, {})
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
                await finish(row, data)
                return

            # 3. Plain fetch, one row at a time per host.
            host = _host(url)
            hlock = host_locks.setdefault(host, asyncio.Lock())
            fetch_error: Optional[str] = None
            async with hlock:
                limited = active_backoff(host)
                if limited is not None:
                    row["verification"] = rate_limited_verdict(limited, fetched=False)
                    rate_limited["rows"] += 1
                    await finish(row, {})
                    return
                async with sem:
                    res = await _fetch_page_ex(client, url)
                status, html, fetch_error = res.status, res.html, res.error
                if status in RATE_LIMIT_STATUSES:
                    # V7: back off; no ladder, no control probe, no retry.
                    record_backoff(host, status, res.retry_after)
                    row["verification"] = rate_limited_verdict(status)
                    rate_limited["rows"] += 1
                    await finish(row, {})
                    return
                # Stealth ladder: only when the plain fetch looks blocked or
                # empty, and never for decisive absences (404/410) or rate
                # limits (handled above; should_escalate refuses them too).
                if stealthweb.enabled() and stealthweb.should_escalate(status, html):
                    esc_status, esc_html, esc_via = await escalate(url)
                    if esc_status in RATE_LIMIT_STATUSES:
                        record_backoff(host, esc_status, None)
                        row["verification"] = rate_limited_verdict(esc_status)
                        rate_limited["rows"] += 1
                        await finish(row, {})
                        return
                    if esc_html is not None:
                        status, html = esc_status, esc_html
                        row["fetch_via"] = esc_via
                        logger.info("stealth fetch rescued %s via %s", url, esc_via)
                    elif esc_status is not None and (
                            status is None or esc_status in _DECISIVE_ABSENT):
                        # No content, but a tier answered decisively — adopt
                        # the status evidence: a browser-seen 404 is absence
                        # even when the plain client was blocked, and any
                        # status beats a transport failure.
                        status = esc_status
            c_status, c_html, c_data, c_failed = await control_for(
                url, row.get("username"))
            try:
                data = _extract(html, url) if html else {}
            except Exception:
                logger.exception("enrichment parse failed for %s", url)
                data = {}
            row["verification"] = verify_username(
                row.get("username"), url, html, data,
                status=status, control_html=c_html, control_extracted=c_data,
                subject_name=subject_name, control_failed=c_failed,
                fetch_error=fetch_error)
            # Template fields: metadata that is byte-identical on the page of
            # a handle that does not exist is the site's, not the person's
            # (a site logo as og:image, "Patreon" as og:title). Stripped only
            # AFTER verification, which needs the raw title for its own
            # control comparison; recorded so the UI can say what was dropped.
            if data and c_data:
                data = strip_template_fields(data, c_data)
            if data:
                row["enrichment"] = data
            await finish(row, data)

        await asyncio.gather(*(work(r) for r in targets), return_exceptions=True)
    if stealth_used["tls"] or stealth_used["browser"] or rate_limited["rows"]:
        logger.info("enrichment: stealth ladder rescued %d profile(s) via TLS "
                    "impersonation, %d via headless browser; rate-limited: %d "
                    "host(s), %d row(s) not retried",
                    stealth_used["tls"], stealth_used["browser"],
                    len(host_backoff), rate_limited["rows"])
    if stats is not None:
        stats.update({
            "stealth_tls": stealth_used["tls"],
            "stealth_browser": stealth_used["browser"],
            "rate_limited_hosts": len(host_backoff),
            "rate_limited_rows": rate_limited["rows"],
            "backoff_s": dict(backoff_seconds),
            "control_failed_hosts": sorted(control_failed_hosts),
        })
    return count
