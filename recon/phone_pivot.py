"""Phone number intelligence: offline parsing via the phonenumbers library,
plus offline lead generation (format variants + OSINT footprint links).

The parsing half is purely offline: validity, E.164 normalization,
country/region, carrier, line type (where the metadata has it), and timezones.
On top of that we generate — still offline, pure string building — a set of
``formats`` (E.164/national/digits/dashed) and ``footprint`` links (search-engine
dorks, spam/reputation lookups, a WhatsApp presence link). These are *leads* the
analyst opens, not scraped facts: no free/legal API returns a person's identity
from a number, so we point at where those leads live instead of pretending to.

Live account-existence checks (which platforms a number is registered on) live
in :mod:`recon.phone_accounts`; reverse-lookup people-search links live in
:mod:`recon.brokers`. phonenumbers is imported lazily; if it is missing,
``phone_intel`` returns an "unavailable" result instead of raising.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Optional
from urllib.parse import quote

logger = logging.getLogger("recon.phone_pivot")

# A bare national number ("415-555-2671") has no country code, so phonenumbers
# can't resolve it without a region. This app is US-centric (US placeholder, US
# people-search brokers), so we assume this region for numbers typed without a
# leading "+". Override with PHONE_DEFAULT_REGION; an explicit "+<country code>"
# always takes precedence.
DEFAULT_REGION = (os.environ.get("PHONE_DEFAULT_REGION", "US").strip().upper()
                  or "US")

# Friendly messages for phonenumbers.NumberParseException.error_type.
_PARSE_ERRORS = {
    0: ("couldn't read the country — prefix with + and the country code, "
        "e.g. +1 415 555 2671"),
    1: "that doesn't look like a phone number",
    2: "too short after the international dialing prefix",
    3: "too short to be a valid number",
    4: "too long to be a valid number",
}

_TYPE_NAMES = {
    0: "fixed_line",
    1: "mobile",
    2: "fixed_line_or_mobile",
    3: "toll_free",
    4: "premium_rate",
    5: "shared_cost",
    6: "voip",
    7: "personal_number",
    8: "pager",
    9: "uan",
    10: "voicemail",
    -1: "unknown",
}


def phonenumbers_available() -> bool:
    try:
        import phonenumbers  # noqa: F401
        return True
    except Exception:
        return False


def _number_formats(num, phonenumbers) -> dict[str, str]:
    """Build the copy-friendly format variants used by the UI and footprint
    links. ``num`` is a parsed phonenumbers PhoneNumber."""
    e164 = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
    national = phonenumbers.format_number(
        num, phonenumbers.PhoneNumberFormat.NATIONAL)
    nsn = phonenumbers.national_significant_number(num)  # digits, no CC
    e164_digits = re.sub(r"\D", "", e164)               # digits incl. CC
    dashed = (f"{nsn[0:3]}-{nsn[3:6]}-{nsn[6:]}"        # US-style grouping
              if len(nsn) == 10 else national)
    return {
        "e164": e164,
        "international": phonenumbers.format_number(
            num, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        "national": national,
        "national_digits": nsn,
        "e164_digits": e164_digits,
        "dashed": dashed,
    }


def footprint_links(fmts: dict[str, str], country_code: int) -> list[dict]:
    """OSINT footprint leads for a number: search-engine dorks, spam/reputation
    lookups, and a WhatsApp presence link. Pure string building — no network,
    always available. Each entry: ``{kind, label, url}``.

    These are leads to open manually, not extracted facts. Spam/reputation
    sites are North-American-plan (country code 1) only; search dorks and the
    WhatsApp link are universal.
    """
    e164 = fmts["e164"]
    national = fmts["national"]
    e164_digits = fmts["e164_digits"]

    def google(q: str) -> str:
        return "https://www.google.com/search?q=" + quote(q)

    links: list[dict] = [
        {"kind": "search", "label": "Google — exact number",
         "url": google(f'"{e164}"')},
        {"kind": "search", "label": "Google — national format",
         "url": google(f'"{national}"')},
        {"kind": "search", "label": "Google — social profiles",
         "url": google(f'"{e164}" (site:facebook.com OR site:twitter.com '
                       f'OR site:instagram.com OR site:linkedin.com)')},
        {"kind": "search", "label": "Google — pastes & leaks",
         "url": google(f'"{e164}" (site:pastebin.com OR site:ghostbin.com '
                       f'OR site:throwbin.io)')},
        {"kind": "search", "label": "Google — documents",
         "url": google(f'"{e164}" (filetype:pdf OR filetype:xlsx '
                       f'OR filetype:csv)')},
        {"kind": "search", "label": "Bing",
         "url": "https://www.bing.com/search?q=" + quote(f'"{e164}"')},
        {"kind": "search", "label": "DuckDuckGo",
         "url": "https://duckduckgo.com/?q=" + quote(f'"{e164}"')},
        {"kind": "messaging", "label": "WhatsApp — opens a chat if registered",
         "url": "https://wa.me/" + e164_digits},
    ]
    if country_code == 1:  # North American Numbering Plan spam databases
        links.append({
            "kind": "reputation", "label": "800notes — spam/scam reports",
            "url": "https://800notes.com/Phone.aspx/" + quote(e164_digits)})
        links.append({
            "kind": "reputation", "label": "Google — reported spam/scam",
            "url": google(f'"{national}" (scam OR spam OR robocall)')})
    return links


def phone_footprint(raw: str, country_hint: Optional[str] = None) -> dict:
    """Convenience: parse ``raw`` and return just ``{formats, footprint}`` (or
    an ``error``). Used by tests and any caller that only wants the leads."""
    res = phone_intel(raw, country_hint)
    if res.get("error"):
        return {"error": res["error"]}
    return {"formats": res.get("formats"), "footprint": res.get("footprint")}


def phone_intel(raw: str, country_hint: Optional[str] = None) -> dict[str, Any]:
    """Parse a phone number into structured intel. Never raises.

    ``raw`` may be E.164 ("+14155552671") or a national format combined with
    a two-letter ``country_hint`` ("US", "GB", ...).
    """
    raw = (raw or "").strip()
    if not raw:
        return {"input": raw, "error": "empty phone number"}
    if not phonenumbers_available():
        return {"input": raw, "error": "phonenumbers package not installed"}

    import phonenumbers
    from phonenumbers import carrier as pn_carrier
    from phonenumbers import geocoder as pn_geocoder
    from phonenumbers import timezone as pn_timezone

    hint = (country_hint or "").strip().upper() or None
    # For a bare national number (no "+", no explicit hint), assume the default
    # region so common formats like "415-555-2671" parse instead of erroring.
    assumed_region = None
    if hint is None and not raw.lstrip().startswith("+"):
        hint = DEFAULT_REGION
        assumed_region = DEFAULT_REGION
    try:
        num = phonenumbers.parse(raw, hint)
    except phonenumbers.NumberParseException as exc:
        msg = _PARSE_ERRORS.get(getattr(exc, "error_type", -1),
                                "couldn't parse this number")
        return {"input": raw, "error": msg}

    valid = phonenumbers.is_valid_number(num)
    possible = phonenumbers.is_possible_number(num)
    region = phonenumbers.region_code_for_number(num)
    line_type = _TYPE_NAMES.get(
        phonenumbers.number_type(num), "unknown"
    )

    result: dict[str, Any] = {
        "input": raw,
        "valid": valid,
        "possible": possible,
        "e164": phonenumbers.format_number(
            num, phonenumbers.PhoneNumberFormat.E164
        ),
        "international": phonenumbers.format_number(
            num, phonenumbers.PhoneNumberFormat.INTERNATIONAL
        ),
        "national": phonenumbers.format_number(
            num, phonenumbers.PhoneNumberFormat.NATIONAL
        ),
        "country_code": num.country_code,
        "region": region,
        "country": pn_geocoder.country_name_for_number(num, "en") or None,
        "location": pn_geocoder.description_for_number(num, "en") or None,
        "carrier": pn_carrier.name_for_number(num, "en") or None,
        "line_type": line_type,
        "timezones": list(pn_timezone.time_zones_for_number(num)),
    }
    # Offline lead generation: copy-friendly format variants + OSINT footprint
    # links (search dorks, spam DBs, WhatsApp presence). Always attached for a
    # parseable number — these are leads, not scraped facts.
    fmts = _number_formats(num, phonenumbers)
    result["formats"] = fmts
    result["footprint"] = footprint_links(fmts, num.country_code)
    if assumed_region:
        # Transparency: we guessed the country for a number typed without "+".
        result["assumed_region"] = assumed_region
    # Fictional/range note: phonenumbers marks reserved-for-fiction ranges
    # (e.g. US 555-01xx, UK 7700 900xxx) as possible-but-invalid; surface that.
    if not valid and possible:
        result["note"] = (
            "number is possible but not valid — likely an unassigned or "
            "reserved (e.g. fictional) range"
        )
    return result
