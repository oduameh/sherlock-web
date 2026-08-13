"""Profile verification — the accuracy gate that decides whether a raw engine
"claimed" is really the subject's account.

Sherlock/Maigret report a hit from a thin HTTP signal (status code, redirect,
error string), and many sites return 200 for *any* path. This module turns a
fetched page — plus an optional fetch of a known-nonexistent handle on the same
site, and the subject's real name — into an advisory verdict:

* ``confirmed``            the page is genuinely about this handle (handle
                           appears as a token in the page's own title/metadata)
                           or the profile's structured name matches the subject.
* ``likely_false_positive`` a hard 404/410, a soft-404 phrase in the page's own
                           heading, or a page indistinguishable from a
                           known-nonexistent handle on the same site.
* ``indeterminate``        we were blocked and genuinely cannot tell (401/403/
                           407/429/5xx, transport failure, non-HTML). NOT the
                           same as "does not exist" — a login-walled platform
                           must never be reported as an absent account.
* ``unconfirmed``          a real page was fetched, nothing tied it to the
                           subject. A lead, not a finding.

Design rules learned the hard way (each one is a real bug this file has had):

1. Never confirm from raw HTML containing the handle — the page is fetched at
   ``/<handle>``, so the handle is in its own canonical URL even on error pages.
2. Never attribute identity from free-text (descriptions, page titles): a fan
   page or a news article mentioning "John Smith" is not John Smith's account.
   Attribution uses the *structured* profile name, and requires the subject's
   name parts adjacent and in order.
3. A different display name is weak *negative* evidence, not proof of a wrong
   person — plenty of real accounts show a nickname or the handle itself. It
   downgrades to ``unconfirmed``; it must never hard-flag.
4. "Blocked" is not "absent". Keep them separate verdicts.

Verdicts are advisory: they drive the confidence score and the UI label, and
never silently drop a result.
"""

from __future__ import annotations

import re
from typing import Optional

_NON_ALNUM = re.compile(r"[^a-z0-9]+")
_SCRIPT_STYLE_RE = re.compile(r"<(script|style)\b[^>]*>.*?</\1>", re.I | re.S)
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")
_TITLE_TAG_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_HEADING_RE = re.compile(r"<h[12][^>]*>(.*?)</h[12]>", re.I | re.S)

# Two pages whose visible text overlaps this much are the same template — i.e.
# the "hit" is the site's placeholder/not-found page.
_CONTROL_SIM_THRESHOLD = 0.90

# A handle shorter than this collides with ordinary words far too often to be
# treated as corroboration on its own.
_MIN_HANDLE_FOR_CONFIRM = 5

# Phrases that, in a page's OWN title/heading, mean the profile is absent.
# Deliberately specific: bare fragments like "doesn't exist" match real bios.
_SOFT_404 = (
    "user not found", "page not found", "profile not found",
    "account not found", "page doesn't exist", "page does not exist",
    "user does not exist", "no longer exists", "404 not found",
    "sorry, this page", "couldn't find this account",
    "this page isn't available", "nothing to see here",
    "no users found", "user unavailable",
)

# Phrases meaning the account existed but is gone — evidentially interesting,
# so it stays a lead rather than being dismissed as a false positive.
_REMOVED = (
    "account suspended", "account has been suspended", "this account doesn",
    "no longer available", "account deactivated", "account terminated",
)

# HTTP statuses that genuinely prove absence vs. merely block us.
_ABSENT_STATUS = {404, 410}


def _norm(s: Optional[str]) -> str:
    return _NON_ALNUM.sub("", (s or "").lower())


def _tokens(s: Optional[str]) -> list[str]:
    return [t for t in _NON_ALNUM.split((s or "").lower()) if t]


def _visible_text(html: Optional[str], limit: int = 4000) -> str:
    """Strip script/style bodies and tags → collapse whitespace → lowercase."""
    if not html:
        return ""
    chunk = html[: limit * 6]
    chunk = _SCRIPT_STYLE_RE.sub(" ", chunk)
    return _WS_RE.sub(" ", _TAG_RE.sub(" ", chunk)).strip().lower()[:limit]


def _page_headline(html: Optional[str], extracted: dict) -> str:
    """The page's title, headings and the top of its main content — where a site
    actually states "not found".

    Scoping soft-404 matching here (rather than the whole body) stops a phrase
    buried in someone's bio, a comment thread or a boilerplate footer from
    condemning a real profile, while still catching a 200-with-"User not found"
    page whose title is generic.
    """
    parts = [str(extracted.get("title") or ""), str(extracted.get("og_title") or "")]
    if html:
        m = _TITLE_TAG_RE.search(html)
        if m:
            parts.append(m.group(1))
        parts.extend(_HEADING_RE.findall(html[:200000])[:3])
    text = " ".join(_TAG_RE.sub(" ", p) for p in parts)
    return _WS_RE.sub(" ", text).strip().lower()


def _shingles(text: str, n: int = 4) -> set:
    toks = text.split()
    if len(toks) < n:
        return {text} if text else set()
    return {" ".join(toks[i:i + n]) for i in range(len(toks) - n + 1)}


def _similarity(a: str, b: str) -> float:
    """Token-shingle Jaccard over the whole visible body. More robust than a
    character-ratio: insensitive to reordering and to per-request noise."""
    sa, sb = _shingles(a), _shingles(b)
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / float(len(sa | sb))


def _handle_in_metadata(uname_raw: str, extracted: dict) -> bool:
    """Does the handle appear as a *token* in the page's own title/metadata?

    Requires a word/@/slash boundary on the unnormalised text, so "bob" does not
    match "Bobby's Blog", and requires a handle long enough to be meaningful.
    """
    if not uname_raw or len(uname_raw) < _MIN_HANDLE_FOR_CONFIRM:
        return False
    hay = " ".join(str(extracted.get(k) or "")
                   for k in ("title", "og_title", "jsonld_name"))
    if not hay:
        return False
    # Separators inside the handle are optional in the page's rendering
    # ("john.smith" often appears as "johnsmith"), but the handle must still sit
    # on a token boundary — so "bob" never matches inside "Bobby's Blog".
    body = "[^a-z0-9]?".join(re.escape(ch) for ch in _norm(uname_raw))
    if not body:
        return False
    pat = re.compile(r"(?:^|[^a-z0-9])" + body + r"(?:$|[^a-z0-9])")
    return bool(pat.search(hay.lower()))


def _identity_matches(subject_name: str, extracted: dict) -> Optional[bool]:
    """Does the profile's *structured* identity match the subject's name?

    True  — the structured profile name contains the subject's first and last
            name adjacent and in order (e.g. "John Smith", "John Q Smith").
    False — a structured profile name is present and is clearly someone else.
    None  — no usable structured name, so no attribution either way.

    Only ``jsonld_name`` / ``og_title`` are consulted. Free-text descriptions
    are excluded on purpose: a page that merely *mentions* the subject is not
    the subject's account.
    """
    toks = [t for t in _tokens(subject_name) if len(t) >= 2]
    if len(toks) < 2:
        return None
    first, last = toks[0], toks[-1]
    # first ... last, in order, with at most two words between (middle names).
    pat = re.compile(r"\b" + re.escape(first) + r"\b(?:\s+\S+){0,2}\s+\b"
                     + re.escape(last) + r"\b")
    candidates = [extracted.get("jsonld_name"), extracted.get("og_title")]
    seen_structured = False
    for value in candidates:
        if not value:
            continue
        low = str(value).lower()
        if pat.search(low):
            return True
        if extracted.get("jsonld_name") and value is extracted.get("jsonld_name"):
            seen_structured = True
    return False if seen_structured else None


def _verdict(status: str, score: int, signals: list,
             identity_match: Optional[bool] = None,
             control_probe: Optional[str] = None) -> dict:
    v = {"status": status, "score": score, "signals": signals}
    if identity_match is not None:
        v["identity_match"] = identity_match
    if control_probe is not None:
        v["control_probe"] = control_probe
    return v


def verify_username(username: Optional[str], url: Optional[str],
                    html: Optional[str], extracted: Optional[dict] = None,
                    *, status: Optional[int] = None,
                    control_html: Optional[str] = None,
                    control_extracted: Optional[dict] = None,
                    subject_name: Optional[str] = None) -> dict:
    """Advisory verdict for one fetched profile page. Never raises."""
    extracted = extracted or {}
    uname_raw = (username or "").strip()
    probe = ("ran" if control_html is not None
             else ("not_applicable" if html else None))

    # 0. Transport / status. Absence and blockage are different claims.
    if status is not None and status in _ABSENT_STATUS:
        return _verdict("likely_false_positive", 8,
                        [f"page returned HTTP {status} (absent)"],
                        control_probe=probe)
    if status is not None and status >= 400:
        return _verdict("indeterminate", 30,
                        [f"blocked: HTTP {status} — cannot determine existence"],
                        control_probe=probe)
    if not html:
        return _verdict("indeterminate", 30,
                        ["no HTML retrieved — cannot determine existence"],
                        control_probe=probe)

    text = _visible_text(html)
    headline = _page_headline(html, extracted)

    # 1. Subject attribution first: a structured name match vetoes a stray
    #    soft-404 phrase (real profiles do say "this post is no longer
    #    available"), and it is the strongest evidence available.
    identity_match = _identity_matches(subject_name, extracted) if subject_name else None
    if identity_match is True:
        return _verdict("confirmed", 90,
                        ["profile name matches the subject"],
                        identity_match=True, control_probe=probe)

    # 2. Removed/suspended: the account existed. Keep it as a lead, not a
    #    dismissal — an investigator wants to know an account was taken down.
    for phrase in _REMOVED:
        if phrase in headline:
            return _verdict("unconfirmed", 40,
                            [f'account appears removed/suspended ("{phrase}") '
                             f"— it likely existed"],
                            identity_match=identity_match, control_probe=probe)

    # 3. Soft-404 stated in the page's OWN title/heading — decisive.
    for phrase in _SOFT_404:
        if phrase in headline:
            return _verdict("likely_false_positive", 10,
                            [f'page heading reads as not-found ("{phrase}")'],
                            identity_match=identity_match, control_probe=probe)

    # 4. Soft-404 by control probe — the strongest FP signal: if a fetch of a
    #    known-nonexistent handle on this site looks the same, the site serves a
    #    page for everyone.
    if control_html is not None:
        sim = _similarity(text, _visible_text(control_html))
        t = _norm(extracted.get("title"))
        ct = _norm((control_extracted or {}).get("title"))
        if sim >= _CONTROL_SIM_THRESHOLD or (t and t == ct):
            return _verdict("likely_false_positive", 10,
                            [f"page is indistinguishable from a known-nonexistent "
                             f"handle on this site ({int(sim * 100)}% overlap)"],
                            identity_match=identity_match, control_probe=probe)

    # 5. Handle corroboration — the page's own title/metadata names this handle.
    #    Checked BEFORE the weaker body-text scan below, so a genuine profile
    #    whose bio merely contains an unlucky phrase is not condemned by it.
    if _handle_in_metadata(uname_raw, extracted):
        return _verdict("confirmed", 72,
                        ["handle appears in the page's title/metadata"],
                        identity_match=identity_match, control_probe=probe)

    # 6. Soft-404 stated at the top of the main content, with no corroborating
    #    handle in the metadata — e.g. a generic title over "User not found".
    top = _visible_text(html, limit=400)
    for phrase in _SOFT_404:
        if phrase in top:
            return _verdict("likely_false_positive", 12,
                            [f'page content reads as not-found ("{phrase}")'],
                            identity_match=identity_match, control_probe=probe)

    # 7. Real page, nothing decisive. A different display name is weak negative
    #    evidence (nicknames, handles-as-names are common) — never a hard flag.
    signals = ["page fetched; nothing tied it to the subject"]
    if identity_match is False:
        signals = ["page shows a different display name — may be another person"]
    return _verdict("unconfirmed", 38 if identity_match is False else 45,
                    signals, identity_match=identity_match, control_probe=probe)
