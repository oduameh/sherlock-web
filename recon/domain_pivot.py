"""Domain / IP / DNS infrastructure pivot.

Public data only, zero API keys. Every network call rides ``recon.safeweb``
(the SSRF-guarded client), so DNS is resolved over DNS-over-HTTPS rather than
raw UDP:

* DNS records (A / AAAA / MX / NS / TXT) via Cloudflare DoH JSON,
* registration data (registrar, key dates, nameservers, status) via RDAP
  (``rdap.org`` bootstraps to the authoritative server),
* subdomains via crt.sh public Certificate Transparency logs,
* reverse DNS (IP -> PTR) via DoH.

Parsing is split into pure functions (``parse_doh``, ``parse_rdap``,
``parse_crtsh``) so they can be unit-tested from fixtures without a network.
Every fetch is best-effort: a failing source degrades to empty, never raises.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Optional

from recon import safeweb

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

async def _doh_query(client, name: str, record_type: str) -> list[str]:
    try:
        resp = await client.get(
            DOH_URL,
            params={"name": name, "type": record_type},
            headers={"Accept": "application/dns-json"},
        )
        if resp.status_code != 200:
            return []
        return parse_doh(resp.json(), record_type)
    except Exception:
        return []


async def _rdap(client, domain: str) -> dict:
    try:
        resp = await client.get(RDAP_URL + domain)
        if resp.status_code != 200:
            return {}
        return parse_rdap(resp.json())
    except Exception:
        return {}


async def _subdomains(client, domain: str) -> list[str]:
    try:
        resp = await client.get(
            CRTSH_URL, params={"q": "%." + domain, "output": "json"}
        )
        if resp.status_code != 200:
            return []
        return parse_crtsh(resp.json(), domain)
    except Exception:
        return []


async def reverse_dns(ip: str) -> Optional[str]:
    """PTR lookup for an IPv4 address, via DoH. None if unavailable."""
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    ptr_name = ".".join(reversed(parts)) + ".in-addr.arpa"
    async with safeweb.async_client(timeout=TIMEOUT_S) as client:
        ptrs = await _doh_query(client, ptr_name, "PTR")
    return ptrs[0] if ptrs else None


async def domain_intel(domain: str) -> dict:
    """Gather DNS + RDAP + subdomain intel for a domain. Never raises."""
    domain = (domain or "").strip().lower().rstrip(".")
    if not looks_like_domain(domain):
        return {"domain": domain, "error": "not a valid domain"}

    async with safeweb.async_client(timeout=TIMEOUT_S) as client:
        a, aaaa, mx, ns, txt, rdap_data, subs = await asyncio.gather(
            _doh_query(client, domain, "A"),
            _doh_query(client, domain, "AAAA"),
            _doh_query(client, domain, "MX"),
            _doh_query(client, domain, "NS"),
            _doh_query(client, domain, "TXT"),
            _rdap(client, domain),
            _subdomains(client, domain),
        )

    return {
        "domain": domain,
        "dns": {
            "A": a, "AAAA": aaaa, "MX": mx, "NS": ns, "TXT": txt[:MAX_TXT],
        },
        "rdap": rdap_data,
        "subdomains": subs,
        "subdomain_count": len(subs),
    }
