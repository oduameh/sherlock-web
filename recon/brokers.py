"""Data-broker exposure — the "reduce my footprint" mirror of the pivots.

Instead of "where does this handle have accounts", it answers "which data
brokers / people-search sites expose this person" and, crucially, gives the
direct **opt-out link** for each (the remediation path — what services like
Incogni automate).

Reality check: most brokers sit behind CAPTCHA/Cloudflare and block automation,
which is exactly why data-removal is a paid service and not a scraper. So this
is primarily a curated exposure + opt-out map (works from a name alone), with
**best-effort** automated presence checks on the minority of brokers that have
predictable, checkable search URLs — and WAF/challenge responses are reported
honestly as "blocked", never as a false "not found". The check runs through
:func:`recon.retrieval.fetch` (G2): a WAF page, rate limit, login redirect or
transport failure is ``blocked`` by the shared classification; only a real
page is read for the broker's match string.

Residual (audit §6 "also noted"): a 200 page that carries neither the match
string nor a wall marker reads as ``not_found`` — marker rot on a broker's
markup is indistinguishable from "not listed" without a control probe.

For comprehensive *free* removal, California residents can file one request via
the official DROP portal (https://consumer.drop.privacy.ca.gov), covering 500+
registered brokers. All fetches go through the SSRF-guarded ``recon.safeweb``.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Optional
from urllib.parse import quote

from recon import retrieval, safeweb
from recon.htmltext import visible_text

logger = logging.getLogger("recon.brokers")

# Reverse-phone deep links for the people-search brokers that support them.
# These are the closest legal thing to a "reverse lookup": the number pre-filled
# on the broker's own search page (the analyst clicks through; we never scrape).
# Reverse-phone is a US/North-American-plan feature, so it is gated on region.
# Tokens: {phone}=national digits, {dashed}=xxx-xxx-xxxx, {e164}, {e164_digits}.
_REVERSE_PHONE_TEMPLATES: dict[str, str] = {
    "TruePeopleSearch": "https://www.truepeoplesearch.com/resultphone?phoneno={phone}",
    "FastPeopleSearch": "https://www.fastpeoplesearch.com/{dashed}",
    "ThatsThem": "https://thatsthem.com/phone/{dashed}",
    "Whitepages": "https://www.whitepages.com/phone/{e164}",
    "Spokeo": "https://www.spokeo.com/{dashed}",
    "USPhonebook": "https://www.usphonebook.com/{dashed}",
    "Radaris": "https://radaris.com/p/reverse-phone/?ph={phone}",
}

_DATA_PATH = Path(__file__).resolve().parent / "data" / "data_brokers.json"
DROP_PORTAL = "https://consumer.drop.privacy.ca.gov"

TIMEOUT_S = 12
MAX_CHECKS = 12          # bound the automated checks per run
MAX_BODY_BYTES = 256 * 1024

LISTED = "listed"        # found a profile for this person
NOT_FOUND = "not_found"  # searched, nothing listed
BLOCKED = "blocked"      # WAF / CAPTCHA / rate limit — can't tell (check manually)
MANUAL = "manual"        # not auto-checkable; use the opt-out link directly
UNKNOWN = "unknown"

# Wall phrases the shared marker list (recon.htmltext) does not carry yet,
# looked for in the visible text of a page retrieval called ``ok``: a CAPTCHA
# gate served as a 200 must be BLOCKED, not "not listed". A residual until
# htmltext grows them; everything else ("just a moment", "access denied",
# "attention required", "enable javascript and cookies", …) is classified
# once, in retrieval.
_EXTRA_WALL_PHRASES = ("captcha", "are you human")

_CACHE: Optional[list[dict]] = None


def load_brokers() -> list[dict]:
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    try:
        _CACHE = json.loads(_DATA_PATH.read_text(encoding="utf-8"))["brokers"]
    except Exception:
        logger.exception("failed to load broker registry")
        _CACHE = []
    return _CACHE


def name_parts(name: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    parts = [p for p in (name or "").strip().split() if p]
    if not parts:
        return None, None
    return parts[0], parts[-1]


def parse_location(location: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """'Austin, TX' -> ('Austin', 'TX'). Tolerant of missing pieces."""
    if not location:
        return None, None
    loc = location.strip()
    if "," in loc:
        city, _, state = loc.partition(",")
        return city.strip() or None, state.strip() or None
    return loc or None, None


def build_search_url(broker: dict, first, last, name, city, state) -> Optional[str]:
    """Fill a broker's search-URL template, or None if a needed field is absent."""
    url = broker.get("search_url")
    if not url:
        return None
    reps = {"{first}": first, "{last}": last, "{name}": name,
            "{city}": city, "{state}": state}
    for token, value in reps.items():
        if token in url:
            if not value:
                return None
            url = url.replace(token, quote(str(value)))
    return url


def reverse_phone_links(e164: Optional[str],
                        region: Optional[str] = None) -> list[dict]:
    """Direct reverse-phone search links for the people-search brokers that
    support them, reusing the registry's opt-out metadata. Offline (pure link
    building) — the number is where a person's name/address actually lives, so
    we point at those brokers rather than scraping them.

    Reverse-phone lookup is a North-American-plan feature; for non-US numbers we
    return nothing (the footprint search dorks still apply). Never raises.
    """
    if not e164:
        return []
    digits = re.sub(r"\D", "", e164)
    if not digits:
        return []
    # National significant number (drop the US country code) for {phone}/{dashed}.
    nsn = digits[1:] if len(digits) == 11 and digits.startswith("1") else digits
    if region and region != "US":
        return []
    if len(nsn) != 10:  # reverse-phone templates below assume a 10-digit NANP number
        return []
    dashed = f"{nsn[0:3]}-{nsn[3:6]}-{nsn[6:]}"
    by_name = {b["name"]: b for b in load_brokers()}
    out: list[dict] = []
    for name, tmpl in _REVERSE_PHONE_TEMPLATES.items():
        b = by_name.get(name, {})
        url = (tmpl.replace("{phone}", nsn)
                   .replace("{dashed}", dashed)
                   .replace("{e164}", quote(e164))
                   .replace("{e164_digits}", digits))
        out.append({
            "name": name,
            "category": b.get("category") or "people-search",
            "owner": b.get("owner"),
            "optout_url": b.get("optout_url"),
            "search_url": url,
        })
    return out


def classify_page(res: retrieval.FetchResult, match: str) -> str:
    """One broker presence verdict from a :class:`recon.retrieval.FetchResult`
    (pure): ``absent`` → NOT_FOUND; anything not ``ok`` (a WAF page, rate
    limit, login redirect, transport failure, policy refusal) → BLOCKED; a
    real page → LISTED when the broker's match string is present, else
    NOT_FOUND (the residual above)."""
    if res.outcome == retrieval.ABSENT:
        return NOT_FOUND
    if res.outcome != retrieval.OK:
        return BLOCKED
    body = res.html or ""
    top = visible_text(body, limit=2000).lower()
    if any(p in top for p in _EXTRA_WALL_PHRASES):
        return BLOCKED
    if match and match in body:
        return LISTED
    return NOT_FOUND


async def _check(client, url: str, match: str, *,
                 stats: Optional[retrieval.RetrievalStats] = None) -> str:
    res = await retrieval.fetch(url, client=client, kind="text", stats=stats,
                                max_bytes=MAX_BODY_BYTES)
    return classify_page(res, match)


async def broker_exposure(name: str, location: Optional[str] = None, *,
                          do_checks: bool = True,
                          retrieval_stats: Optional[retrieval.RetrievalStats] = None
                          ) -> dict:
    """Map a person's data-broker exposure. Never raises.

    Every broker contributes an opt-out link (the remediation value); the
    minority that are auto-checkable get a best-effort presence status.
    """
    name = (name or "").strip()
    first, last = name_parts(name)
    city, state = parse_location(location)
    brokers = load_brokers()

    results: list[dict] = []
    checkable: list[tuple[dict, dict, str]] = []
    for b in brokers:
        search = build_search_url(b, first, last, name, city, state)
        entry = {
            "name": b["name"], "category": b.get("category"),
            "owner": b.get("owner"), "optout_url": b.get("optout_url"),
            "search_url": search, "status": MANUAL,
        }
        if do_checks and b.get("checkable") and search:
            checkable.append((entry, b, search))
        results.append(entry)

    if checkable:
        async with safeweb.async_client(timeout=TIMEOUT_S) as client:
            for entry, b, search in checkable[:MAX_CHECKS]:
                entry["status"] = await _check(client, search, b.get("match") or "",
                                               stats=retrieval_stats)

    def _count(status):
        return sum(1 for e in results if e["status"] == status)

    return {
        "name": name, "city": city, "state": state,
        "drop_portal": DROP_PORTAL,
        "brokers": results,
        "summary": {
            "total": len(results),
            "auto_checked": _count(LISTED) + _count(NOT_FOUND) + _count(BLOCKED),
            "listed": _count(LISTED),
            "blocked": _count(BLOCKED),
            "manual": _count(MANUAL),
        },
    }
