"""Subject footprint — where an identity claims and appears to be.

The other pivots answer *which accounts are the subject's*; this one answers
**where they sit in the world**, which is a different investigative question:

* **Corroboration** — a profile that says "Redmond", a phone in the same metro
  and infrastructure in the same country is a consistent story.
* **Contradiction** — profiles claiming cities on three continents is a persona
  signal (or evidence the accounts are simply different people). The spread is
  the finding, so :func:`footprint_stats` reports it explicitly.

Five sources, all already produced by the pipeline:

===================  ==========================================================
``subject``          the location the investigator supplied (the *claim*)
``profile``          per-platform ``location`` from adapters/enrichment
``gravatar``         the email pivot's Gravatar ``location``
``phone``            the phone pivot's derived city/region
``infra``            A-record IPs from the domain pivot (server location, which
                     is the *host's* geography — never the person's)
===================  ==========================================================

Resolution uses free, key-less public services with an honest User-Agent:
OpenStreetMap **Nominatim** for place names (rate-limited to 1 request/second
per their usage policy) and **ipwho.is** for IP geolocation. Results are cached
in-process so re-opening a case re-queries nothing. Only public place strings
and public IPs are ever sent; nothing about the subject's identity leaves here.

Everything network-facing is best-effort and never raises: an unresolvable
place is reported in ``unresolved`` rather than dropped silently, because
"we couldn't place this" is different from "there was nothing here".
"""

from __future__ import annotations

import asyncio
import logging
import math
from typing import Any, Optional

from recon import safeweb

logger = logging.getLogger("recon.geo")

USER_AGENT = ("sherlock-web/1.0 (OSINT footprint mapping; "
              "+https://github.com/oduameh/sherlock-web)")

NOMINATIM_URL = "https://nominatim.openstreetmap.org/search"
IPWHO_URL = "https://ipwho.is/{ip}"

TIMEOUT_S = 12
# Nominatim's usage policy: at most one request per second from a client.
_NOMINATIM_MIN_INTERVAL_S = 1.05
# Politeness caps per investigation — a footprint is a handful of places, and
# an unbounded sweep would abuse a free community service.
MAX_PLACES = 25
MAX_IPS = 8

_place_cache: dict[str, Optional[dict]] = {}
_ip_cache: dict[str, Optional[dict]] = {}
_nominatim_lock: Optional[asyncio.Lock] = None
_last_nominatim_at = 0.0


# --- pure: collecting geographic claims from a summary ---------------------

def _clean_place(value: Any) -> Optional[str]:
    """A usable place string, or None. Rejects junk that would geocode wrongly."""
    if not isinstance(value, str):
        return None
    text = " ".join(value.split()).strip(" ,;|")
    if len(text) < 2 or len(text) > 120:
        return None
    # A bare URL/handle/email is not a place.
    lowered = text.lower()
    if any(tok in lowered for tok in ("http://", "https://", "@", "www.")):
        return None
    # Require at least one letter — "12345" alone is not a place we can trust.
    if not any(ch.isalpha() for ch in text):
        return None
    return text


def _rows(summary: dict) -> list[dict]:
    return ((summary.get("accounts") or [])
            + (summary.get("variants") or [])
            + (summary.get("name_accounts") or []))


def collect_places(summary: dict) -> list[dict]:
    """Every geographic claim in ``summary``, de-duplicated (pure function).

    Each item: ``{kind, place|ip, label, site}`` where ``kind`` is one of
    ``subject`` / ``profile`` / ``gravatar`` / ``phone`` / ``infra``.
    """
    summary = summary or {}
    params = summary.get("params") or {}
    out: list[dict] = []
    seen: set[tuple] = set()

    def add(kind: str, *, place: Optional[str] = None, ip: Optional[str] = None,
            label: str = "", site: Optional[str] = None) -> None:
        key = (kind, (place or ip or "").lower(), site or "")
        if not (place or ip) or key in seen:
            return
        seen.add(key)
        item: dict[str, Any] = {"kind": kind, "label": label or place or ip}
        if place:
            item["place"] = place
        if ip:
            item["ip"] = ip
        if site:
            item["site"] = site
        out.append(item)

    # 1. What the investigator claimed.
    claimed = _clean_place(params.get("location"))
    if claimed:
        add("subject", place=claimed, label=claimed)

    # 2. Per-platform profile locations (adapter identity first, then enrichment).
    for row in _rows(summary):
        ident = row.get("platform_identity") or {}
        place = _clean_place(ident.get("location"))
        if place:
            add("profile", place=place, label=place, site=row.get("site"))

    # 3. Gravatar's self-reported location.
    grav = ((summary.get("email") or {}).get("gravatar") or {})
    gplace = _clean_place(grav.get("location"))
    if gplace:
        add("gravatar", place=gplace, label=gplace, site="Gravatar")

    # 4. Phone geography (city/region if known, else the country).
    phone = summary.get("phone") or {}
    if phone.get("valid"):
        pplace = _clean_place(phone.get("location")) or _clean_place(phone.get("country"))
        if pplace:
            add("phone", place=pplace, label=pplace, site="phone")

    # 5. Domain infrastructure — where the servers are, not the person.
    domain = summary.get("domain") or {}
    dom_name = domain.get("domain")
    if domain and not domain.get("error"):
        for ip in (domain.get("dns") or {}).get("A") or []:
            add("infra", ip=ip, label=ip, site=dom_name)
    return out


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in kilometres."""
    r = 6371.0088
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = (math.sin(dp / 2) ** 2
         + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2)
    return 2 * r * math.asin(min(1.0, math.sqrt(a)))


# Person-attributable kinds. Server geography says where a host is, not where
# its owner lives, so ``infra`` never drives the consistency verdict.
_PERSON_KINDS = ("subject", "profile", "gravatar", "phone")

# A metro area is ~100 km across; beyond ~500 km is a different region, and
# beyond ~2000 km is effectively a different part of the world.
_SAME_METRO_KM = 100.0
_SAME_REGION_KM = 500.0


def footprint_stats(points: list[dict]) -> dict:
    """Spread of resolved points — the actual finding, not just dots.

    Returns counts, the countries seen, the widest distance between two
    person-attributable points, and a plain-language ``assessment``.
    """
    points = points or []
    person = [p for p in points
              if p.get("kind") in _PERSON_KINDS
              and p.get("lat") is not None and p.get("lon") is not None]
    countries = sorted({p["country"] for p in points
                        if p.get("country")})
    person_countries = sorted({p["country"] for p in person if p.get("country")})

    max_km = 0.0
    for i in range(len(person)):
        for j in range(i + 1, len(person)):
            d = haversine_km(person[i]["lat"], person[i]["lon"],
                             person[j]["lat"], person[j]["lon"])
            if d > max_km:
                max_km = d

    if len(person) < 2:
        assessment = ("Only one person-linked location — not enough to compare."
                      if person else "No person-linked location resolved.")
        consistency = "insufficient"
    elif max_km <= _SAME_METRO_KM:
        assessment = "All person-linked locations sit in one metro area."
        consistency = "consistent"
    elif max_km <= _SAME_REGION_KM:
        assessment = "Person-linked locations sit in the same region."
        consistency = "consistent"
    elif len(person_countries) > 1:
        assessment = (f"Person-linked locations span {len(person_countries)} "
                      f"countries ({', '.join(person_countries)}) — "
                      "possible persona, relocation, or different people.")
        consistency = "conflicting"
    else:
        assessment = ("Person-linked locations are far apart within one "
                      "country — possible relocation or stale profile data.")
        consistency = "mixed"

    return {
        "resolved": len(points),
        "person_points": len(person),
        "countries": countries,
        "person_countries": person_countries,
        "max_spread_km": round(max_km, 1),
        "consistency": consistency,
        "assessment": assessment,
    }


# --- network: resolution (best-effort, cached, rate-limited) ---------------

async def geocode_place(place: str) -> Optional[dict]:
    """Place name → ``{lat, lon, display, country}``. None if unresolvable.

    Honours Nominatim's 1 request/second policy and caches every answer
    (including misses) so a re-opened case issues no new traffic.
    """
    global _nominatim_lock, _last_nominatim_at
    key = place.strip().lower()
    if key in _place_cache:
        return _place_cache[key]
    if _nominatim_lock is None:
        _nominatim_lock = asyncio.Lock()
    try:
        async with _nominatim_lock:
            loop = asyncio.get_running_loop()
            wait = _NOMINATIM_MIN_INTERVAL_S - (loop.time() - _last_nominatim_at)
            if wait > 0:
                await asyncio.sleep(wait)
            async with safeweb.async_client(timeout=TIMEOUT_S) as client:
                resp = await client.get(
                    NOMINATIM_URL,
                    params={"q": place, "format": "jsonv2", "limit": 1,
                            "addressdetails": 1},
                    headers={"User-Agent": USER_AGENT,
                             "Accept-Language": "en"},
                )
            _last_nominatim_at = loop.time()
        data = resp.json()
    except Exception as exc:
        logger.debug("geocode failed for %r: %s", place, exc)
        _place_cache[key] = None
        return None
    if not isinstance(data, list) or not data:
        _place_cache[key] = None
        return None
    hit = data[0]
    try:
        out = {
            "lat": float(hit["lat"]),
            "lon": float(hit["lon"]),
            "display": hit.get("display_name") or place,
            "country": (hit.get("address") or {}).get("country"),
        }
    except Exception:
        _place_cache[key] = None
        return None
    _place_cache[key] = out
    return out


async def geolocate_ip(ip: str) -> Optional[dict]:
    """Public IP → ``{lat, lon, display, country, org}``. None if unresolvable.

    Private/reserved addresses are never sent to a third party.
    """
    key = ip.strip()
    if key in _ip_cache:
        return _ip_cache[key]
    try:
        if not safeweb._is_public_ip(key):
            _ip_cache[key] = None
            return None
    except Exception:
        pass
    try:
        async with safeweb.async_client(timeout=TIMEOUT_S) as client:
            resp = await client.get(IPWHO_URL.format(ip=key),
                                    headers={"User-Agent": USER_AGENT})
        data = resp.json()
    except Exception as exc:
        logger.debug("ip geolocation failed for %s: %s", key, exc)
        _ip_cache[key] = None
        return None
    if not isinstance(data, dict) or not data.get("success"):
        _ip_cache[key] = None
        return None
    try:
        city = data.get("city")
        country = data.get("country")
        out = {
            "lat": float(data["latitude"]),
            "lon": float(data["longitude"]),
            "display": ", ".join(p for p in (city, country) if p) or key,
            "country": country,
            "org": ((data.get("connection") or {}).get("org")
                    or (data.get("connection") or {}).get("isp")),
        }
    except Exception:
        _ip_cache[key] = None
        return None
    _ip_cache[key] = out
    return out


async def build_footprint(summary: dict) -> dict:
    """Resolve every geographic claim in ``summary`` into map points.

    Returns ``{points, unresolved, stats}``. Never raises.
    """
    claims = collect_places(summary)
    places = [c for c in claims if c.get("place")][:MAX_PLACES]
    ips = [c for c in claims if c.get("ip")][:MAX_IPS]

    # Place lookups are serialised by the Nominatim rate limit; IP lookups are
    # a different service and can run concurrently with them.
    async def _all_places() -> list:
        return [await geocode_place(c["place"]) for c in places]

    async def _all_ips() -> list:
        return list(await asyncio.gather(
            *(geolocate_ip(c["ip"]) for c in ips), return_exceptions=True))

    place_hits, ip_hits = await asyncio.gather(_all_places(), _all_ips())

    points: list[dict] = []
    unresolved: list[dict] = []
    for claim, hit in zip(places, place_hits):
        if isinstance(hit, dict):
            points.append({**claim, **hit})
        else:
            unresolved.append({**claim, "reason": "could not geocode"})
    for claim, hit in zip(ips, ip_hits):
        if isinstance(hit, dict):
            points.append({**claim, **hit})
        else:
            unresolved.append({**claim, "reason": "could not geolocate IP"})

    dropped = len(claims) - len(places) - len(ips)
    if dropped > 0:
        unresolved.append({"kind": "note", "label": f"{dropped} further "
                           "location(s) not resolved (per-case lookup cap)"})
    return {"points": points, "unresolved": unresolved,
            "stats": footprint_stats(points)}
