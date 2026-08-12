"""Profile verification — cut username-search false positives.

Sherlock and Maigret report a "claimed" account from an HTTP signal (status
code, redirect, error string). Some sites return 200 for *any* path, so a hit
can be a false positive. This module cross-checks the fetched profile page:

* if the scanned username actually appears in the page's title / Open Graph /
  JSON-LD / body, the hit is **corroborated**;
* if the page instead reads like a soft-404 ("user not found" served with a
  200), it is flagged as a **likely false positive**;
* otherwise it stays **unconfirmed** (fetched, but nothing decisive).

The verdict is advisory — it feeds the account confidence score and the UI
badge, and never silently drops a result. Ordering matters: a soft-404 that
echoes the requested handle ("user octocat not found") must be caught before
the body-echo check, or it would falsely confirm.
"""

from __future__ import annotations

import re
from typing import Optional

_NON_ALNUM = re.compile(r"[^a-z0-9]+")

# Specific phrases that, on a 200 response, strongly indicate the profile is
# absent. Kept specific (no bare "not found") to avoid flagging real bios.
_SOFT_404 = (
    "user not found", "page not found", "profile not found",
    "account not found", "page doesn't exist", "page does not exist",
    "user does not exist", "this account doesn", "account suspended",
    "account has been suspended", "no longer available",
    "nothing to see here", "404 not found", "sorry, this page",
    "couldn't find this account", "this page isn't available",
)

# Fields extracted by recon.enrich, most-authoritative first.
_STRUCTURED_KEYS = ("title", "og_title", "og_description",
                    "jsonld_name", "jsonld_description")


def _norm(s: Optional[str]) -> str:
    return _NON_ALNUM.sub("", (s or "").lower())


def verify_username(username: Optional[str], url: Optional[str],
                    html: Optional[str], extracted: Optional[dict] = None) -> dict:
    """Return an advisory verdict for one fetched profile page.

    ``{"status": "confirmed"|"unconfirmed"|"likely_false_positive",
       "score": int, "signals": [str, ...]}``
    """
    extracted = extracted or {}
    uname = _norm(username)
    if not uname or not html:
        return {"status": "unconfirmed", "score": 40, "signals": []}

    signals: list[str] = []

    # 1. Structured metadata is the strongest positive signal — a real profile
    #    almost always echoes the handle/name in its title or OG/JSON-LD.
    structured = " ".join(str(extracted.get(k) or "") for k in _STRUCTURED_KEYS)
    if uname in _norm(structured):
        return {"status": "confirmed", "score": 90,
                "signals": ["username appears in page title/metadata"]}

    # 2. Soft-404 detection — checked BEFORE the body-echo test so a "user X
    #    not found" page doesn't falsely confirm on its own echoed handle.
    hay = (extracted.get("title") or "").lower() + " " + html[:2500].lower()
    for phrase in _SOFT_404:
        if phrase in hay:
            return {"status": "likely_false_positive", "score": 10,
                    "signals": [f"page reads like a soft-404 (\"{phrase}\")"]}

    # 3. Body echo — weaker, but a handle appearing in the page body is still
    #    corroboration once a soft-404 has been ruled out.
    if uname in _norm(html[:200000]):
        signals.append("username appears in page body")
        return {"status": "confirmed", "score": 70, "signals": signals}

    return {"status": "unconfirmed", "score": 40,
            "signals": ["page fetched; username not found on it"]}
