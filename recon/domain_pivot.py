"""Domain / IP / DNS infrastructure pivot.

Public data only, zero API keys. Every network call rides
:func:`recon.retrieval.fetch` on ``recon.safeweb`` (the SSRF-guarded client),
so DNS is resolved over DNS-over-HTTPS rather than raw UDP:

* DNS records (A / AAAA / MX / NS / TXT) via Cloudflare DoH JSON,
* registration data (registrar, key dates, nameservers, status) via RDAP
  (``rdap.org`` bootstraps to the authoritative server),
* subdomains via crt.sh public Certificate Transparency logs,
* reverse DNS (IP -> PTR) via DoH.

Parsing is split into pure functions (``parse_doh``, ``parse_rdap``,
``parse_crtsh``) so they can be unit-tested from fixtures without a network.
Every fetch is best-effort and never raises — but a source that did not
answer is **reported**, not silently emptied (G2; audit §6 "also noted": a
crt.sh 503 used to read as "0 subdomains"): :func:`domain_intel` carries an
``errors`` list (``{source, query, reason}`` per failed call) and
``subdomain_count`` is ``None`` when crt.sh could not be read. Each call is
recorded against the source registry (:func:`recon.sources.record`).
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any, Optional
from urllib.parse import quote, urlencode

from recon import retrieval, safeweb, sources

logger = logging.getLogger("recon.domain_pivot")

DOH_URL = "https://cloudflare-dns.com/dns-query"
RDAP_URL = "https://rdap.org/domain/"
CRTSH_URL = "https://crt.sh/"

TIMEOUT_S = 12
MAX_SUBDOMAINS = 100
MAX_TXT = 20

# DNS record type -> numeric code (DoH `type` param).
_RTYPES = {"A": 1, "AAAA": 28, "MX": 15, "NS": 2, "TXT": 16, "PTR": 12}

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def looks_like_domain(value: Optional[str]) -> bool:
    """True for a bare registrable domain / hostname (not an email or URL)."""
    value = (value or "").strip().rstrip(".")
    if not value or "@" in value or "/" in value or " " in value:
        return False
    return bool(_DOMAIN_RE.match(value)) and "." in value


def domain_from_email(email: Optional[str]) -> Optional[str]:
    """The domain part of an email, or None."""
    email = (email or "").strip().lower()
    if "@" not in email:
        return None
    dom = email.split("@", 1)[1].strip().rstrip(".")
    return dom if looks_like_domain(dom) else None


# ---------------------------------------------------------------------------
# Pure parsers (unit-testable from fixtures)
# ---------------------------------------------------------------------------

def parse_doh(payload: dict, record_type: str) -> list[str]:
    """Extract answer values for one record type from a DoH JSON response."""
    want = _RTYPES.get(record_type)
    out: list[str] = []
    for ans in (payload or {}).get("Answer") or []:
        if want is not None and ans.get("type") != want:
            continue
        data = (ans.get("data") or "").strip()
        if not data:
            continue
        if record_type in ("NS", "PTR", "MX"):
            data = data.rstrip(".")
        if record_type == "TXT":
            data = data.strip('"')
        out.append(data)
    return out


def parse_rdap(payload: dict) -> dict:
    """Pull registrar, key dates, nameservers and status from RDAP JSON."""
    payload = payload or {}
    events = {}
    for ev in payload.get("events") or []:
        action = ev.get("eventAction")
        if action and ev.get("eventDate"):
            events[action] = ev["eventDate"]

    registrar = None
    for ent in payload.get("entities") or []:
        roles = ent.get("roles") or []
        if "registrar" in roles:
            vcard = ent.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) > 1:
                for field in vcard[1]:
                    if isinstance(field, list) and field and field[0] == "fn":
                        registrar = field[-1]
                        break
            registrar = registrar or ent.get("handle")
            break

    nameservers = []
    for ns in payload.get("nameservers") or []:
        name = ns.get("ldhName")
        if name:
            nameservers.append(name.rstrip(".").lower())

    return {
        "registrar": registrar,
        "registered": events.get("registration"),
        "expires": events.get("expiration"),
        "updated": events.get("last changed") or events.get("last update of RDAP database"),
        "nameservers": nameservers,
        "status": payload.get("status") or [],
    }


def parse_crtsh(entries: list, base_domain: str) -> list[str]:
    """Dedupe subdomains of ``base_domain`` from crt.sh JSON entries."""
    base = base_domain.lower().rstrip(".")
    seen: set[str] = set()
    for entry in entries or []:
        raw = (entry.get("name_value") or "") if isinstance(entry, dict) else ""
        for name in raw.split("\n"):
            name = name.strip().lower().rstrip(".")
            if name.startswith("*."):
                name = name[2:]
            if not name or name == base:
                continue
            if name == base or name.endswith("." + base):
                seen.add(name)
    return sorted(seen)[:MAX_SUBDOMAINS]


# ---------------------------------------------------------------------------
# Async fetchers
# ---------------------------------------------------------------------------

async def _fetch_json(client, source: str, url: str, *, label: str,
                      headers: Optional[dict] = None,
                      stats: Optional[retrieval.RetrievalStats] = None,
                      errors: Optional[list] = None) -> tuple[Any, Optional[str]]:
    """``(data, error)`` for one JSON source through :func:`retrieval.fetch`.

    ``ok`` → the parsed body; ``absent`` (404/410 — RDAP for an unregistered
    name) → ``(None, None)``; anything else → ``(None, reason)`` and an entry
    in ``errors`` so the caller can say the source did not answer instead of
    reporting an empty result. Recorded against ``source`` in the registry.
    """
    t0 = time.monotonic()
    res = await retrieval.fetch(url, client=client, kind="json", headers=headers,
                                stats=stats)
    latency_ms = (time.monotonic() - t0) * 1000
    if res.outcome == retrieval.OK:
        sources.record(source, True, latency_ms)
        return res.data, None
    if res.outcome == retrieval.ABSENT:
        sources.record(source, True, latency_ms)
        return None, None
    sources.record(source, False, latency_ms, res.reason)
    if errors is not None:
        errors.append({"source": source, "query": label, "reason": res.reason})
    logger.debug("%s did not answer for %s: %s", source, label, res.reason)
    return None, res.reason


async def _doh_query(client, name: str, record_type: str, *,
                     stats: Optional[retrieval.RetrievalStats] = None,
                     errors: Optional[list] = None) -> list[str]:
    url = DOH_URL + "?" + urlencode({"name": name, "type": record_type})
    data, _err = await _fetch_json(client, "cloudflare_doh", url,
                                   label=f"{record_type} {name}",
                                   headers={"Accept": "application/dns-json"},
                                   stats=stats, errors=errors)
    return parse_doh(data, record_type) if isinstance(data, dict) else []


async def _rdap(client, domain: str, *,
                stats: Optional[retrieval.RetrievalStats] = None,
                errors: Optional[list] = None) -> dict:
    data, _err = await _fetch_json(client, "rdap", RDAP_URL + quote(domain, safe=""),
                                   label=domain, stats=stats, errors=errors)
    return parse_rdap(data) if isinstance(data, dict) else {}


async def _subdomains(client, domain: str, *,
                      stats: Optional[retrieval.RetrievalStats] = None,
                      errors: Optional[list] = None) -> Optional[list[str]]:
    """Subdomains from crt.sh, or **None** when crt.sh did not answer — a 503
    from the CT search is "unavailable", never "0 subdomains"."""
    url = CRTSH_URL + "?" + urlencode({"q": "%." + domain, "output": "json"})
    data, err = await _fetch_json(client, "crtsh", url, label=domain,
                                  stats=stats, errors=errors)
    if err is not None:
        return None
    return parse_crtsh(data, domain) if isinstance(data, list) else []


async def reverse_dns(ip: str) -> Optional[str]:
    """PTR lookup for an IPv4 address, via DoH. None if unavailable."""
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    ptr_name = ".".join(reversed(parts)) + ".in-addr.arpa"
    async with safeweb.async_client(timeout=TIMEOUT_S) as client:
        ptrs = await _doh_query(client, ptr_name, "PTR")
    return ptrs[0] if ptrs else None


async def domain_intel(domain: str, *,
                       retrieval_stats: Optional[retrieval.RetrievalStats] = None
                       ) -> dict:
    """Gather DNS + RDAP + subdomain intel for a domain. Never raises.

    Additive keys (G2): ``errors`` — one ``{source, query, reason}`` per call
    whose outcome was neither ``ok`` nor ``absent`` (empty when every source
    answered) — and ``subdomain_count`` is ``None`` rather than ``0`` when
    crt.sh could not be read.
    """
    domain = (domain or "").strip().lower().rstrip(".")
    if not looks_like_domain(domain):
        return {"domain": domain, "error": "not a valid domain"}

    errors: list[dict] = []
    async with safeweb.async_client(timeout=TIMEOUT_S) as client:
        a, aaaa, mx, ns, txt, rdap_data, subs = await asyncio.gather(
            _doh_query(client, domain, "A", stats=retrieval_stats, errors=errors),
            _doh_query(client, domain, "AAAA", stats=retrieval_stats, errors=errors),
            _doh_query(client, domain, "MX", stats=retrieval_stats, errors=errors),
            _doh_query(client, domain, "NS", stats=retrieval_stats, errors=errors),
            _doh_query(client, domain, "TXT", stats=retrieval_stats, errors=errors),
            _rdap(client, domain, stats=retrieval_stats, errors=errors),
            _subdomains(client, domain, stats=retrieval_stats, errors=errors),
        )

    return {
        "domain": domain,
        "dns": {
            "A": a, "AAAA": aaaa, "MX": mx, "NS": ns, "TXT": txt[:MAX_TXT],
        },
        "rdap": rdap_data,
        "subdomains": subs or [],
        "subdomain_count": None if subs is None else len(subs),
        "errors": errors,
    }
