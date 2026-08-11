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

import httpx

logger = logging.getLogger("recon.enrich")

BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

MAX_BODY_BYTES = 512 * 1024  # stop reading after 512 KB
MAX_ENRICH_PER_RUN = 40
CONCURRENCY = 5
TIMEOUT_S = 10

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


async def _fetch_limited(client: httpx.AsyncClient, url: str) -> Optional[str]:
    """GET a page, reading at most MAX_BODY_BYTES, then close."""
    try:
        async with client.stream("GET", url) as resp:
            if resp.status_code >= 400:
                return None
            ctype = resp.headers.get("content-type", "")
            if "text/html" not in ctype and "application/xhtml" not in ctype:
                return None
            chunks: list[bytes] = []
            size = 0
            async for chunk in resp.aiter_bytes(16384):
                chunks.append(chunk)
                size += len(chunk)
                if size >= MAX_BODY_BYTES:
                    break
            return b"".join(chunks).decode(resp.encoding or "utf-8", errors="replace")
    except Exception:
        return None


async def enrich_one(client: httpx.AsyncClient, url: str) -> dict:
    html = await _fetch_limited(client, url)
    if not html:
        return {}
    try:
        return _extract(html)
    except Exception:
        logger.exception("enrichment parse failed for %s", url)
        return {}


async def enrich_profiles(rows: list[dict],
                          on_enriched: Callable[[dict, dict], Any],
                          limit: int = MAX_ENRICH_PER_RUN) -> int:
    """Enrich up to ``limit`` found-profile rows (mutates rows in place).

    ``rows`` items need a ``url`` key; enrichment output is stored under
    ``row["enrichment"]``. ``on_enriched(row, data)`` is awaited/called per
    completed profile. Returns the number of profiles enriched.
    """
    seen_urls: set[str] = set()
    targets: list[dict] = []
    for row in rows:
        url = row.get("url")
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        targets.append(row)
        if len(targets) >= limit:
            break

    sem = asyncio.Semaphore(CONCURRENCY)
    count = 0

    async with httpx.AsyncClient(
        timeout=TIMEOUT_S,
        headers={"User-Agent": BROWSER_UA},
        follow_redirects=True,
    ) as client:

        async def work(row: dict) -> None:
            nonlocal count
            async with sem:
                data = await enrich_one(client, row["url"])
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
