"""Best-effort public profile enrichment.

Fetches each found profile page (public HTML only) and extracts <title>,
Open Graph tags, and JSON-LD Person fields. Regex-based parsing wrapped in
try/except everywhere: weird HTML must never crash a run. Responses are
streamed and capped so memory stays bounded, and every parser is linear in the
input (security audit F-3 — the old ``<title>(.*?)</title>`` took >20 s on a
280 KB page a subject could serve us).

Retrieval (Increment G2): every page goes through :func:`recon.retrieval.fetch`
— the access policy, the SSRF guard, the per-host backoff, the outcome
vocabulary and the stealth ladder all live there. What this module keeps is
the *enrichment* policy on top of it (retrieval audit V7 and traces a/c):

* **A rate limit is answered by backing off, never by more requests.** The
  first 429/503 on a host records a per-host backoff (``Retry-After`` if
  present, else 60 s) in the run's :class:`recon.retrieval.HostState`; the
  row is ``indeterminate`` with ``reason: rate_limited``; later rows on that
  host get the same verdict *without fetching*; the ladder never runs for it.
  Fetches to one host are serialised so "later" is well-defined.
* **A failed control probe is reported as failed, not cached as "no control".**
  Only a control fetch whose outcome is ``ok`` with HTML or ``absent`` is
  cached per host; anything else is retried once later in the run and
  otherwise surfaces as ``control_probe: "failed"`` on the verdict.
* **The retrieval reason survives verbatim.** A blocked or unreachable row's
  first signal is :attr:`recon.retrieval.FetchResult.reason` — "no response
  (ConnectTimeout)", 'challenge page ("just a moment")', "login redirect
  (/login)" — so a stored case can say why nothing could be read.
"""

from __future__ import annotations

import asyncio
import html as _html
import json
import logging
import os
from typing import Any, Callable, Optional

from recon import adapters, policy, retrieval, safeweb
from recon.htmltext import (
    META_CONTENT_RE,
    META_KEY_RE,
    TAG_RE,
    TITLE_RE,
    WS_RE,
    challenge_marker,
    consent_wall_marker,
    iter_jsonld_blocks,
    iter_tags,
)
from recon.ladder import StealthLadder
from recon.retrieval import ABSENT, BLOCKED, OK, SSRF, TRANSPORT, FetchResult
from recon.verify import CONTROL_HANDLE, verify_username

__all__ = ["CONTROL_HANDLE", "blocked_verdict", "enrich_profiles",
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

# A control probe that fails is retried at most once more in the same run.
CONTROL_MAX_ATTEMPTS = 2


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
# Verdicts for rows that could not be read
# ---------------------------------------------------------------------------

def _control_url(url: Optional[str], username: Optional[str]) -> Optional[str]:
    """Build the same profile URL for a known-nonexistent handle, by swapping
    the last occurrence of the username. None if the handle isn't in the URL."""
    if not url or not username or username not in url:
        return None
    idx = url.rfind(username)
    return url[:idx] + CONTROL_HANDLE + url[idx + len(username):]


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


def blocked_verdict(res: FetchResult, control_probe: Optional[str] = None) -> dict:
    """The verdict a row carries when retrieval could not read the page and
    the page itself cannot say why (G2; audit defect 7 asked for the *why*).

    ``blocked`` / ``transport`` → ``indeterminate`` with
    :attr:`recon.retrieval.FetchResult.reason` verbatim as the first signal
    ("blocked: HTTP 403 (cf-mitigated: challenge)", "blocked: login redirect
    (/login)", "no response (ConnectTimeout)"). Blocked is never absent.
    ``ssrf`` → ``not_examined``: the URL failed the public-address guard and
    was dropped, so there is no evidence either way. ``reason`` names the
    outcome so a stored case can be filtered by it (additive).
    """
    if res.outcome == SSRF:
        return {"status": "not_examined", "score": 0,
                "signals": [f"not fetched — {res.reason}"], "reason": "ssrf"}
    text = res.reason if res.outcome == TRANSPORT else f"blocked: {res.reason}"
    v = {"status": "indeterminate", "score": 30,
         "signals": [f"{text} — cannot determine existence"],
         "reason": res.outcome}
    if control_probe is not None:
        v["control_probe"] = control_probe
    return v


def _walled_body(res: FetchResult) -> bool:
    """A 2xx page retrieval called ``blocked`` because of what the *body* says
    (challenge phrase, consent wall). Those rows still go through
    :func:`recon.verify.verify_username`, which applies the same markers with
    its weak-phrase exception ("Access Denied" is an album when the page names
    the handle). A block seen only in the headers or the final URL (login
    redirect, ``cf-mitigated``) is decided here — the body cannot show it."""
    return (res.outcome == BLOCKED and res.status is not None and res.status < 300
            and bool(res.html)
            and (challenge_marker(res.html, raw_tokens=False) is not None
                 or consent_wall_marker(res.html) is not None))


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
                          stats: Optional[dict] = None, *,
                          host_state: Optional[retrieval.HostState] = None,
                          retrieval_stats: Optional[retrieval.RetrievalStats] = None,
                          ladder: Optional[StealthLadder] = None) -> int:
    """Enrich + verify up to ``limit`` found-profile rows (mutates in place).

    Each fetched row gets ``row["enrichment"]`` (extracted metadata) and an
    advisory ``row["verification"]`` verdict (see :mod:`recon.verify`) — which
    includes a **control-probe soft-404 check** (a cached fetch of a
    known-nonexistent handle per site) and, when ``subject_name`` is given, a
    profile-name attribution check. The noisiest rows (name-derived candidates)
    are verified first. ``on_enriched(row, data)`` is called once per row that
    receives a verdict — including hard-404s, soft-404s and rate-limited rows
    (so the UI can label them). Returns the number of profiles processed.

    ``host_state`` / ``retrieval_stats`` / ``ladder`` are the run's shared
    retrieval state — one :class:`recon.retrieval.HostState`, one
    :class:`recon.retrieval.RetrievalStats` and one
    :class:`recon.ladder.StealthLadder` per run, created by the pipeline so a
    host backed off during discovery stays backed off here. Each defaults to a
    fresh private instance for direct callers.

    ``stats``, when given, is filled with the run's enrichment counters
    (``stealth_tls``, ``stealth_browser``, ``rate_limited_hosts``,
    ``rate_limited_rows``, ``backoff_s`` per host, ``control_failed_hosts``,
    the verification budget's use, and the ladder's ``stealth`` snapshot)
    for the pipeline diagnostics to persist.
    """
    hs = host_state if host_state is not None else retrieval.HostState()
    rstats = (retrieval_stats if retrieval_stats is not None
              else retrieval.RetrievalStats())
    if ladder is None:
        ladder = StealthLadder(STEALTH_BROWSER_BUDGET)
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
    # a control whose outcome is ok-with-HTML or absent is cached; a failure
    # is retried once and otherwise reported as failed.
    control_cache: dict[str, tuple] = {}
    control_attempts: dict[str, int] = {}
    control_locks: dict[str, asyncio.Lock] = {}
    control_failed_hosts: set[str] = set()
    # One fetch at a time per host, so a 429 on the first row is seen before
    # the second row on that host is requested.
    host_locks: dict[str, asyncio.Lock] = {}
    # host → backoff seconds recorded on its first rate limit this run
    # (reporting only; the backoff itself lives in ``hs``).
    backoff_seconds: dict[str, float] = {}
    rate_limited = {"rows": 0}
    tls_ok0, browser_ok0 = ladder.tls_ok, ladder.browser_ok

    def note_rate_limit(host: str, res: FetchResult) -> None:
        if host in backoff_seconds:
            return
        backoff_seconds[host] = res.retry_after or retrieval.DEFAULT_BACKOFF_S
        logger.info("rate limited by %s (HTTP %s) — backing off %.0fs, no more "
                    "requests to it this run", host, res.status,
                    backoff_seconds[host])

    async with safeweb.async_client(timeout=TIMEOUT_S) as client:

        async def fetch(url: str, *, with_ladder: bool) -> FetchResult:
            async with sem:
                return await retrieval.fetch(
                    url, client=client, kind="html", host_state=hs, stats=rstats,
                    ladder=ladder.for_fetch() if with_ladder else None,
                    max_bytes=MAX_BODY_BYTES)

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
            host = retrieval.host_key(url)
            lock = control_locks.setdefault(host, asyncio.Lock())
            async with lock:
                cached = control_cache.get(host)
                if cached is not None:
                    return cached[0], cached[1], cached[2], False
                if hs.active_backoff(host) is not None:
                    return None, None, None, True
                if control_attempts.get(host, 0) >= CONTROL_MAX_ATTEMPTS:
                    return None, None, None, True
                control_attempts[host] = control_attempts.get(host, 0) + 1
                res = await fetch(curl, with_ladder=False)
                if res.rate_limited:
                    note_rate_limit(host, res)
                    control_failed_hosts.add(host)
                    return None, None, None, True
                if res.outcome == ABSENT:
                    # The site 404s unknown handles: decisive, and there is no
                    # page to compare against — cache it, it is not a failure.
                    control_cache[host] = (res.status, None, {})
                    return res.status, None, {}, False
                if res.outcome == OK and res.html:
                    try:
                        c_data = _extract(res.html)
                    except Exception:
                        c_data = {}
                    control_cache[host] = (res.status, res.html, c_data)
                    return res.status, res.html, c_data, False
                # Transport failure, non-HTML body, blocked (a wall on the
                # control is not a control): not cached, so the next row on
                # this host retries once.
                control_failed_hosts.add(host)
                logger.debug("control probe failed for %s: %s", host, res.reason)
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
            #    dates the generic path cannot see. Served from the adapter
            #    cache when discovery already asked this run (GitHub once per
            #    handle per run — defect 10).
            adapter = adapters.adapter_for(row.get("site") or "")
            if adapter is not None:
                async with sem:
                    result = await adapter.check(row.get("username") or "",
                                                 host_state=hs,
                                                 retrieval_stats=rstats)
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

            # 3. Plain fetch, one row at a time per host. retrieval.fetch
            #    applies the backoff (no request while the host is backing
            #    off), records a new one on a 429/503, and runs the ladder
            #    once for a block — never for a rate limit.
            host = retrieval.host_key(url)
            hlock = host_locks.setdefault(host, asyncio.Lock())
            async with hlock:
                was_backing_off = hs.active_backoff(host) is not None
                res = await fetch(url, with_ladder=True)
                if not res.rate_limited:
                    # A 2xx JS shell is ``ok`` to retrieval; rendering it is
                    # our decision (a live single-page profile is an empty
                    # shell to a plain client).
                    res = await retrieval.escalate_shell(
                        res, url, ladder=ladder.for_fetch(), host_state=hs,
                        stats=rstats)
                if res.rate_limited:
                    # V7: back off; no ladder, no control probe, no retry.
                    note_rate_limit(host, res)
                    row["verification"] = rate_limited_verdict(
                        res.status or 429, fetched=not was_backing_off)
                    rate_limited["rows"] += 1
                    await finish(row, {})
                    return
                if (res.via != "httpx" and res.outcome == OK and res.html
                        and not res.is_shell):
                    row["fetch_via"] = res.via
                    logger.info("stealth fetch rescued %s via %s", url, res.via)
            c_status, c_html, c_data, c_failed = await control_for(
                url, row.get("username"))
            # A page we can read (ok), a decisive absence (verify turns a
            # 404/410 into likely_false_positive) or a 2xx wall the body
            # itself shows: verify decides. Anything else is decided here from
            # retrieval's reason.
            readable = res.outcome in (OK, ABSENT) or _walled_body(res)
            data: dict = {}
            if readable and res.html:
                try:
                    data = _extract(res.html, url)
                except Exception:
                    logger.exception("enrichment parse failed for %s", url)
                    data = {}
            if readable:
                row["verification"] = verify_username(
                    row.get("username"), url, res.html, data,
                    status=res.status, control_html=c_html,
                    control_extracted=c_data, subject_name=subject_name,
                    control_failed=c_failed)
            else:
                probe = "ran" if c_html is not None else ("failed" if c_failed else None)
                row["verification"] = blocked_verdict(res, control_probe=probe)
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
    tls_ok = ladder.tls_ok - tls_ok0
    browser_ok = ladder.browser_ok - browser_ok0
    if tls_ok or browser_ok or rate_limited["rows"]:
        logger.info("enrichment: stealth ladder rescued %d profile(s) via TLS "
                    "impersonation, %d via headless browser; rate-limited: %d "
                    "host(s), %d row(s) not retried",
                    tls_ok, browser_ok, len(backoff_seconds), rate_limited["rows"])
    if stats is not None:
        stats.update({
            "stealth_tls": tls_ok,
            "stealth_browser": browser_ok,
            "rate_limited_hosts": len(backoff_seconds),
            "rate_limited_rows": rate_limited["rows"],
            "backoff_s": dict(backoff_seconds),
            "control_failed_hosts": sorted(control_failed_hosts),
            "verify_budget": limit,
            "verify_budget_used": budgeted,
            "verify_budget_skipped": len(skipped),
            "stealth": ladder.snapshot(),
        })
    return count
