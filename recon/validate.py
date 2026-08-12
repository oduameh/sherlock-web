"""Small input validators shared across endpoints and the pipeline.

Deliberately pragmatic, not RFC-exhaustive: the goal is to reject obvious
garbage before we spend a rate-limited holehe run or draw a misleading "email"
node, not to certify deliverability.
"""

from __future__ import annotations

import re

# One @, a non-empty local part, and a dotted domain with a >=2-char TLD.
_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,}$"
)


def is_probably_email(value: str) -> bool:
    """True if ``value`` looks like a real email address."""
    value = (value or "").strip()
    if not value or len(value) > 254 or ".." in value:
        return False
    return bool(_EMAIL_RE.match(value))
