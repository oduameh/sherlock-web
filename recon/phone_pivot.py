"""Phone number intelligence: offline parsing via the phonenumbers library.

Purely offline: validity, E.164 normalization, country/region, carrier,
line type (where the metadata has it), and timezones. No WhatsApp/Telegram
presence checks — those need APIs we don't have, and guessing would be
noise. phonenumbers is imported lazily; if it is missing, ``phone_intel``
returns an "unavailable" result instead of raising.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

logger = logging.getLogger("recon.phone_pivot")

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
    try:
        num = phonenumbers.parse(raw, hint)
    except phonenumbers.NumberParseException as exc:
        return {"input": raw, "error": f"unparseable: {exc.error_type}"}

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
    # Fictional/range note: phonenumbers marks reserved-for-fiction ranges
    # (e.g. US 555-01xx, UK 7700 900xxx) as possible-but-invalid; surface that.
    if not valid and possible:
        result["note"] = (
            "number is possible but not valid — likely an unassigned or "
            "reserved (e.g. fictional) range"
        )
    return result
