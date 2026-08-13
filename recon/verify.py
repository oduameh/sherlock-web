"""Profile verification — the accuracy gate that cuts username-search false
positives and, where possible, attributes a profile to the actual subject.

Sherlock/Maigret report a "claimed" account from a thin HTTP signal (status
code, redirect, error string). Many sites return 200 for *any* path, so a raw
hit is often a false positive. This module turns a fetched page (plus an
optional fetch of a known-nonexistent handle on the same site, and the subject's
real name) into an advisory verdict:

* ``likely_false_positive`` — a hard error, a soft-404 phrase, a page that looks
  the same as a known-nonexistent handle (the site serves a page for everyone),
  or a structured profile name that clearly isn't the subject.
* ``confirmed`` — the page is genuinely about this handle (handle in the
  title/metadata) or the profile's name matches the subject.
* ``unconfirmed`` — fetched, real page, but nothing decisive (a lead).

Crucially it does **not** confirm merely because the handle appears somewhere in
the raw HTML: the page was fetched at ``/<handle>``, so the handle is in its own
canonical URL / breadcrumb even on error pages. Confirmation comes only from
extracted/structured content or a subject-name match.

The verdict is advisory — it feeds the confidence score and the UI label, and
never silently drops a result. ``identity_match`` is included when a subject
name was supplied (True/False/None = matched / clearly-different / unknown).
"""

from __future__ import annotations

import difflib
import re
from typing import Optional

_NON_ALNUM = re.compile(r"[^a-z0-9]+")
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")

# Two pages this similar (visible text) are treated as the same template — i.e.
# the "hit" page is the site's not-found/placeholder page.
_CONTROL_SIM_THRESHOLD = 0.90

# Specific phrases that, on a 200 response, indicate the profile is absent.
_SOFT_404 = (
    "user not found", "page not found", "profile not found",
    "account not found", "page doesn't exist", "page does not exist",
    "user does not exist", "this account doesn", "account suspended",
    "account has been suspended", "no longer available",
    "nothing to see here", "404 not found", "sorry, this page",
    "couldn't find this account", "this page isn't available",
    "doesn't exist", "isn't available", "not be found", "no users found",
)

# Extracted fields (recon.enrich), most-authoritative first.
_STRUCTURED_KEYS = ("title", "og_title", "og_description",
                    "jsonld_name", "jsonld_description")
# Fields that plausibly carry a person's real name.
_NAME_KEYS = ("jsonld_name", "og_title", "title", "og_description",
              "jsonld_description")


def _norm(s: Optional[str]) -> str:
    return _NON_ALNUM.sub("", (s or "").lower())


def _tokens(s: Optional[str]) -> list[str]:
    return [t for t in _NON_ALNUM.split((s or "").lower()) if t]


def _visible_text(html: Optional[str], limit: int = 4000) -> str:
    """Strip tags → collapse whitespace → lowercase, capped. Used for soft-404
    phrase scanning and control-page similarity (raw HTML is too noisy)."""
    if not html:
        return ""
    text = _WS_RE.sub(" ", _TAG_RE.sub(" ", html[: limit * 4])).strip().lower()
    return text[:limit]


def _similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a, b).quick_ratio()


def _identity_matches(subject_name: str, extracted: dict) -> Optional[bool]:
    """Does the profile's exposed identity match the subject's name?

    True  — a name field contains both the subject's first and last name.
    False — a *structured* person name (jsonld_name) is present but shares
            neither the first nor the last name (a different person).
    None  — no usable name exposed, can't attribute.
    """
    toks = [t for t in _tokens(subject_name) if len(t) >= 2]
    if len(toks) < 2:
        return None
    first, last = toks[0], toks[-1]
    for key in _NAME_KEYS:
        nt = set(_tokens(extracted.get(key)))
        if first in nt and last in nt:
            return True
    jn = extracted.get("jsonld_name")
    if jn:
        nt = set(_tokens(jn))
        if first not in nt and last not in nt:
            return False
    return None


def _verdict(status: str, score: int, signals: list,
             identity_match: Optional[bool] = None) -> dict:
    v = {"status": status, "score": score, "signals": signals}
    if identity_match is not None:
        v["identity_match"] = identity_match
    return v


def verify_username(username: Optional[str], url: Optional[str],
                    html: Optional[str], extracted: Optional[dict] = None,
                    *, status: Optional[int] = None,
                    control_html: Optional[str] = None,
                    control_extracted: Optional[dict] = None,
                    subject_name: Optional[str] = None) -> dict:
    """Advisory verdict for one fetched profile page. Never raises.

    ``{"status": "confirmed"|"unconfirmed"|"likely_false_positive",
       "score": int, "signals": [...], "identity_match"?: bool}``
    """
    extracted = extracted or {}
    uname = _norm(username)

    # 0. Hard error / no usable page → the claim doesn't hold up.
    if status is not None and status >= 400:
        return _verdict("likely_false_positive", 8,
                        [f"page returned HTTP {status}"])
    if not html:
        return _verdict("unconfirmed", 30, ["no HTML page fetched"])

    text = _visible_text(html)
    hay = (extracted.get("title") or "").lower() + " " + text

    # 1. Soft-404 by phrase (visible text, not raw markup, not English-only URL).
    for phrase in _SOFT_404:
        if phrase in hay:
            return _verdict("likely_false_positive", 10,
                            [f'soft-404 phrase: "{phrase}"'])

    # 2. Soft-404 by control probe — the strongest FP signal. If a fetch of a
    #    known-nonexistent handle on this site looks ~identical, the site serves
    #    a page for everyone, so this "hit" is a false positive.
    if control_html is not None:
        sim = _similarity(text, _visible_text(control_html))
        t = _norm(extracted.get("title"))
        ct = _norm((control_extracted or {}).get("title"))
        if sim >= _CONTROL_SIM_THRESHOLD or (t and t == ct):
            return _verdict("likely_false_positive", 10,
                            [f"page matches a known-nonexistent handle "
                             f"(soft-404, {int(sim * 100)}% similar)"])

    signals: list = []
    out_status, score = "unconfirmed", 45  # real page, nothing decisive yet

    # 3. Handle in STRUCTURED metadata — the page is about this handle (not just
    #    its own URL). Substring in extracted title/OG/JSON-LD only.
    structured = _norm(" ".join(str(extracted.get(k) or "")
                                for k in _STRUCTURED_KEYS))
    if uname and uname in structured:
        signals.append("handle appears in page title/metadata")
        out_status, score = "confirmed", 75

    # 4. Subject attribution — does the profile's name match the real subject?
    identity_match = None
    if subject_name:
        identity_match = _identity_matches(subject_name, extracted)
        if identity_match is True:
            signals.append("profile name matches the subject")
            out_status, score = "confirmed", max(score, 85)
        elif identity_match is False:
            # The page exposes a real name that isn't the subject — this handle
            # exists but belongs to someone else.
            return _verdict("likely_false_positive", 20,
                            ["profile name does not match the subject"],
                            identity_match=False)

    if out_status == "unconfirmed" and not signals:
        signals.append("page fetched; nothing tied it to the subject")
    return _verdict(out_status, score, signals, identity_match=identity_match)
