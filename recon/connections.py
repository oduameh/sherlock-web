"""Cross-investigation link analysis.

Answers the analyst question *"where else has this identity turned up?"* by
comparing one investigation's identifiers against every other stored
investigation and reporting the overlaps: a shared email, phone, domain,
platform account, registered service, or reused handle.

All pure functions over already-loaded investigation records — no network, no
DB — so the endpoint layer just has to fetch the rows and hand them over.
"""

from __future__ import annotations

from typing import Any

from recon.engines import normalize_site

# Per-signal contribution to a connection's strength (0-100, capped).
_WEIGHTS = {
    "emails": 40,
    "phones": 40,
    "domains": 30,
    "accounts": 15,
    "registrations": 10,
    "handles": 5,
}

# Human-readable singular labels for the summary line.
_LABELS = {
    "emails": "email",
    "phones": "phone",
    "domains": "domain",
    "accounts": "account",
    "registrations": "registration",
    "handles": "handle",
}


def _clean(value: Any) -> str:
    return str(value or "").strip().lower()


def subject_identifiers(inputs: dict, summary: dict) -> dict[str, set[str]]:
    """Collect the comparable identifiers for one investigation.

    Draws from both the ``inputs`` (available before a run) and the ``summary``
    (available after), so a pending investigation still contributes its clues.
    Returns a dict of identifier-type -> set of normalized strings.
    """
    inputs = inputs or {}
    summary = summary or {}
    params = summary.get("params") or {}

    ident: dict[str, set[str]] = {
        "emails": set(), "phones": set(), "domains": set(),
        "accounts": set(), "registrations": set(), "handles": set(),
    }

    for email in (inputs.get("email"), params.get("email")):
        if email:
            ident["emails"].add(_clean(email))

    # Phone: prefer the normalized E.164 from phone intel, fall back to raw.
    phone_intel = summary.get("phone") or {}
    for phone in (phone_intel.get("e164"), inputs.get("phone"),
                  params.get("phone")):
        if phone:
            ident["phones"].add(_clean(phone).replace(" ", ""))

    domain_state = summary.get("domain") or {}
    for domain in (inputs.get("domain"), params.get("domain"),
                   domain_state.get("domain")):
        if domain:
            ident["domains"].add(_clean(domain))

    # Handles: input usernames + every discovered account username.
    for handle in (inputs.get("usernames") or []) + (params.get("usernames")
                                                      or []):
        if handle:
            ident["handles"].add(_clean(handle))

    all_rows = ((summary.get("accounts") or [])
                + (summary.get("variants") or [])
                + (summary.get("name_accounts") or []))
    for row in all_rows:
        site = normalize_site(row.get("site") or "")
        handle = _clean(row.get("username"))
        if handle:
            ident["handles"].add(handle)
        if site and handle:
            ident["accounts"].add(f"{site}|{handle}")

    for hit in (summary.get("email") or {}).get("holehe") or []:
        if hit.get("exists") and hit.get("site"):
            ident["registrations"].add(normalize_site(hit["site"]))

    return ident


def find_connections(target_id: int, target_ident: dict[str, set[str]],
                     others: list[dict]) -> list[dict]:
    """Find other investigations sharing identifiers with the target.

    ``others`` is a list of ``{"id", "label", "ident"}`` where ``ident`` is a
    :func:`subject_identifiers` result. Returns a list of connection dicts
    (JSON-friendly: shared values are sorted lists) ranked by strength.
    """
    connections: list[dict] = []
    for other in others or []:
        if other.get("id") == target_id:
            continue
        other_ident = other.get("ident") or {}
        shared: dict[str, list[str]] = {}
        strength = 0
        for key, weight in _WEIGHTS.items():
            common = target_ident.get(key, set()) & other_ident.get(key, set())
            if common:
                shared[key] = sorted(common)
                strength += weight * len(common)
        if not shared:
            continue
        connections.append({
            "investigation_id": other.get("id"),
            "label": other.get("label"),
            "strength": min(100, strength),
            "shared": shared,
            "summary": _summarize(shared),
        })
    connections.sort(key=lambda c: (-c["strength"], c["investigation_id"] or 0))
    return connections


def _summarize(shared: dict[str, list[str]]) -> str:
    """One-line human summary of what two investigations share."""
    bits: list[str] = []
    # Strong, specific signals first.
    for key in ("emails", "phones", "domains"):
        for value in shared.get(key, []):
            bits.append(f"{_LABELS[key]} {value}")
    for key in ("accounts", "registrations", "handles"):
        n = len(shared.get(key, []))
        if n:
            label = _LABELS[key]
            bits.append(f"{n} shared {label}" + ("s" if n != 1 else ""))
    return "shares " + ", ".join(bits) if bits else "shares identifiers"
