"""Best-effort public profile enrichment.

Fetches each found profile page (public HTML only) and extracts <title>,
Open Graph tags, and JSON-LD Person fields. Regex-based parsing wrapped in
try/except everywhere: weird HTML must never crash a run. Responses are
streamed and capped so memory stays bounded.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any, Callable, Optional
from urllib.parse import urlparse

import httpx

from recon import safeweb
from recon.verify import verify_username

logger = logging.getLogger("recon.enrich")

MAX_BODY_BYTES = 512 * 1024  # stop reading after 512 KB
MAX_ENRICH_PER_RUN = 80
CONCURRENCY = 5
TIMEOUT_S = 10

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
    return re.sub(r"\s+", " ", text).strip() or None


def _extract(html: str) -> dict:
    data: dict[str, Any] = {}

    m = _TITLE_RE.search(html)
    if m:
        data["title"] = _clean(m.group(1))

    for tag_m in _META_OG_RE.finditer(html):
        prop = tag_m.group(1).lower()
        c = _CONTENT_ATTR_RE.search(tag_m.group(0))
        if not c:
            continue
        val = _clean(c.group(1))
        if prop == "og:title":
            data["og_title"] = val
        elif prop == "og:description":
            data["og_description"] = val
        elif prop == "og:image":
            data["og_image"] = c.group(1).strip()

    def person_fields(obj: Any) -> None:
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
            if img and not data.get("jsonld_image"):
                data["jsonld_image"] = str(img)
        for v in obj.values():
            if isinstance(v, (dict, list)):
                person_fields(v) if isinstance(v, dict) else [
                    person_fields(i) for i in v
                ]

    for m in _JSONLD_RE.finditer(html):
        try:
            parsed = json.loads(m.group(1).strip())
            if isinstance(parsed, list):
                for item in parsed:
                    person_fields(item)
            else:
                person_fields(parsed)
        except Exception:
            continue

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
    return (_SOURCE_ORDER.get(row.get("source"), 3),
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
            async with sem:
                status, html = await _fetch_page(client, row["url"])
            c_status, c_html, c_data = await control_for(
                row["url"], row.get("username"))
            try:
                data = _extract(html) if html else {}
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
    return count
