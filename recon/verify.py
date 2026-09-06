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
                           407/429/5xx, transport failure, non-HTML, challenge
                           page, consent wall, block page). NOT the same as
                           "does not exist" — a login-walled platform must never
                           be reported as an absent account.
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
5. A not-found page that echoes the handle is still a not-found page.
   ``Profile johnsmith77 not found | ExampleSite`` used to verify as
   ``confirmed 72``: no fixed soft-404 phrase matched (the handle splits
   "profile … not found"), the control page differed only by the handle so the
   4-gram overlap fell under 0.90, and the handle-in-title rule then fired.
   The fix is two-fold and both parts run *before* handle corroboration: a
   headline regex (:data:`recon.htmltext.SOFT_404_RE`) and a control
   comparison computed after masking both handles with one placeholder.
6. A page identical to the control page that carries no profile metadata is a
   block page, not a refutation. Akamai's "Access Denied … Reference #" is
   served identically for the real and the control handle; calling that
   ``likely_false_positive`` reports a block as "refuted".
7. When the control probe *failed* (rate limit, timeout, 5xx) the verdict says
   so (``control_probe: "failed"``) instead of pretending no control applied,
   and a verdict reached without the comparison carries a note.

Verdicts are advisory: they drive the confidence score and the UI label, and
never silently drop a result.
"""

from __future__ import annotations

import re
from typing import Optional

from recon.htmltext import (
    SOFT_404_PHRASES,
    SOFT_404_RE,
    WEAK_CHALLENGE_PHRASES,
    soft_404_pattern,
    challenge_marker,
    consent_wall_marker,
    page_headline,
    visible_text,
)

_NON_ALNUM = re.compile(r"[^a-z0-9]+")

# A handle that will not exist anywhere. Fetching a site at this handle gives a
# "known-negative" page to compare each real hit against (soft-404 detection).
# Defined here (not in enrich) so the verifier can mask it without a circular
# import; :mod:`recon.enrich` re-exports it.
CONTROL_HANDLE = "qzx9no7such8user2wj"

# Two pages whose visible text overlaps this much are the same template — i.e.
# the "hit" is the site's placeholder/not-found page.
_CONTROL_SIM_THRESHOLD = 0.90

# A handle shorter than this collides with ordinary words far too often to be
# treated as corroboration on its own.
_MIN_HANDLE_FOR_CONFIRM = 5

# Handles shorter than this are not masked before the control comparison: a
# 2-letter handle occurs inside ordinary words and masking it would mangle the
# text on both sides unequally.
_MIN_HANDLE_FOR_MASK = 3

# What both handles become before the control comparison. Alphanumeric so it
# survives :func:`_norm` identically on both sides.
_HANDLE_PLACEHOLDER = " hxhandlexh "

# A block page's title is short ("Access Denied", "Pardon Our Interruption").
# A title longer than this is treated as page-specific content.
_MAX_BLOCK_TITLE_WORDS = 4

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


def _mask_handles(text: Optional[str], handles: tuple[str, ...]) -> str:
    """Replace every handle (as typed and separator-stripped, longest first)
    with one placeholder token, on lowercase text.

    Rule 5 above: the control comparison must ask "is this the same template?",
    and a template that echoes the handle differs from the control page *only*
    by the handle. Masking both handles on both sides makes such pages identical
    again, so the 0.90 threshold and the titles-equal check cannot be defeated
    by handle echo.
    """
    out = (text or "").lower()
    forms: set[str] = set()
    for h in handles:
        h = (h or "").strip().lower()
        if len(h) >= _MIN_HANDLE_FOR_MASK:
            forms.add(h)
            n = _norm(h)
            if len(n) >= _MIN_HANDLE_FOR_MASK:
                forms.add(n)
    for form in sorted(forms, key=len, reverse=True):
        out = out.replace(form, _HANDLE_PLACEHOLDER)
    return out


def _has_profile_metadata(extracted: dict) -> bool:
    """Does the page carry anything that looks like *profile* metadata?

    Rule 6: og:title / og:image / a JSON-LD name, or a title longer than four
    words. Block pages have none of these — a WAF renders "Access Denied" with
    no Open Graph tags — whereas a soft-404 factory almost always stamps the
    site's own og tags on every page (which is what makes it a false positive
    rather than a block).
    """
    if extracted.get("og_title") or extracted.get("og_image") \
            or extracted.get("jsonld_name"):
        return True
    # str.split, not the ASCII tokenizer: a Japanese or Cyrillic title used to
    # count as zero words and every non-Latin profile became a "block page".
    return len(str(extracted.get("title") or "").split()) > _MAX_BLOCK_TITLE_WORDS


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


def _display_name_conflicts(subject_name: str, extracted: dict, handle: str) -> bool:
    """True when the page's structured/og display name, minus the handle and
    the site's boilerplate, shares no name token (nor a nickname prefix) with
    the subject. Both sides must have a real token left, else no opinion."""
    raw = extracted.get("jsonld_name") or extracted.get("og_title") or ""
    hn = _norm(handle)
    name_toks = {t for t in _tokens(raw) if len(t) >= 2 and t != hn and hn not in t}
    subj_toks = {t for t in _tokens(subject_name) if len(t) >= 2}
    if not name_toks or not subj_toks:
        return False
    for x in name_toks:
        for y in subj_toks:
            if x == y or x.startswith(y) or y.startswith(x):
                return False
    return True


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


_CONTROL_FAILED_NOTE = ("control probe failed — the soft-404 comparison could "
                        "not be run for this site")


def _verdict(status: str, score: int, signals: list,
             identity_match: Optional[bool] = None,
             control_probe: Optional[str] = None) -> dict:
    v = {"status": status, "score": score, "signals": list(signals)}
    if identity_match is not None:
        v["identity_match"] = identity_match
    if control_probe is not None:
        v["control_probe"] = control_probe
    # Rule 7: a positive or open verdict reached without the control comparison
    # must say so — the audit's worst case was a "confirmed 72" whose control
    # fetch had been rate-limited, with nothing in the verdict revealing it.
    if control_probe == "failed" and status in ("confirmed", "unconfirmed"):
        v["signals"].append(_CONTROL_FAILED_NOTE)
    return v


def verify_username(username: Optional[str], url: Optional[str],
                    html: Optional[str], extracted: Optional[dict] = None,
                    *, status: Optional[int] = None,
                    control_html: Optional[str] = None,
                    control_extracted: Optional[dict] = None,
                    subject_name: Optional[str] = None,
                    control_failed: bool = False,
                    fetch_error: Optional[str] = None,
                    control_handle: str = CONTROL_HANDLE) -> dict:
    """Advisory verdict for one fetched profile page. Never raises.

    ``control_failed`` — the control fetch was attempted but produced no page
    (transport failure or a blocking status); recorded as
    ``control_probe: "failed"`` rather than the misleading ``"not_applicable"``.
    ``fetch_error`` — exception class name when the page fetch itself failed,
    surfaced in the signal so a stored case can say *why* nothing was retrieved.
    ``control_handle`` — the known-nonexistent handle the control page was
    fetched for; masked alongside ``username`` before the control comparison.
    """
    extracted = extracted or {}
    uname_raw = (username or "").strip()
    if control_html is not None:
        probe: Optional[str] = "ran"
    elif control_failed:
        probe = "failed"
    else:
        probe = "not_applicable" if html else None

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
        if fetch_error:
            why = f" ({fetch_error})"
        elif status is not None:
            why = f" (HTTP {status}, non-HTML response)"
        else:
            why = ""
        return _verdict("indeterminate", 30,
                        [f"no HTML retrieved{why} — cannot determine existence"],
                        control_probe=probe)

    text = visible_text(html)
    headline = page_headline(html, extracted)

    # 0.5. Anti-bot interstitial / WAF block page: we received *a* page, but it
    #      is not the profile — neither confirm nor condemn. Scoped to the
    #      headline and top of content (shared rule in recon.htmltext); raw
    #      vendor tokens are deliberately NOT consulted here (rule: a DataDome
    #      script tag on a legitimate page is not a block page).
    marker = challenge_marker(html, extracted, raw_tokens=False)
    if marker in WEAK_CHALLENGE_PHRASES and _handle_in_metadata(uname_raw, extracted):
        marker = None      # "Access Denied" is an album here; the page names the handle
    if marker:
        return _verdict("indeterminate", 30,
                        [f'anti-bot challenge page ("{marker}") — '
                         f"cannot determine existence"],
                        control_probe=probe)
    wall = consent_wall_marker(html, extracted)
    if wall:
        return _verdict("indeterminate", 30,
                        [f'consent/cookie wall ("{wall}") — '
                         f"cannot determine existence"],
                        control_probe=probe)

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

    # 3. Soft-404 stated in the page's OWN title/heading — decisive. Fixed
    #    phrases first, then the subject…predicate regex that catches a handle
    #    echoed between them ("Profile johnsmith77 not found") — rule 5. Both
    #    run BEFORE handle corroboration, which is what used to confirm them.
    for phrase in SOFT_404_PHRASES:
        if phrase in headline:
            return _verdict("likely_false_positive", 10,
                            [f'page heading reads as not-found ("{phrase}")'],
                            identity_match=identity_match, control_probe=probe)
    m = SOFT_404_RE.search(headline) or (
        soft_404_pattern(uname_raw).search(headline) if uname_raw else None)
    if m:
        return _verdict("likely_false_positive", 10,
                        [f'page heading reads as not-found ("{m.group(0)}")'],
                        identity_match=identity_match, control_probe=probe)

    # 4. Soft-404 by control probe — the strongest FP signal: if a fetch of a
    #    known-nonexistent handle on this site looks the same, the site serves a
    #    page for everyone. Compared after masking BOTH handles (rule 5), and
    #    only a page with profile metadata is called a false positive — an
    #    identical, metadata-free page is a block page (rule 6).
    if control_html is not None:
        handles = (uname_raw, control_handle)
        sim = _similarity(_mask_handles(text, handles),
                          _mask_handles(visible_text(control_html), handles))
        t = _norm(_mask_handles(extracted.get("title"), handles))
        ct = _norm(_mask_handles((control_extracted or {}).get("title"), handles))
        if sim >= _CONTROL_SIM_THRESHOLD or (t and t == ct):
            # A WAF block page never names the handle; a soft-404 factory that
            # echoes it is a refutation, whatever its metadata (review S4).
            if (not _has_profile_metadata(extracted)
                    and not _handle_in_metadata(uname_raw, extracted)):
                return _verdict("indeterminate", 30,
                                ["identical to the control page and carries no "
                                 "profile metadata — likely a block page"],
                                identity_match=identity_match,
                                control_probe=probe)
            return _verdict("likely_false_positive", 10,
                            [f"page is indistinguishable from a known-nonexistent "
                             f"handle on this site ({int(sim * 100)}% overlap)"],
                            identity_match=identity_match, control_probe=probe)

    # 5. Handle corroboration — the page's own title/metadata names this handle.
    #    Checked BEFORE the weaker body-text scan below, so a genuine profile
    #    whose bio merely contains an unlucky phrase is not condemned by it.
    if _handle_in_metadata(uname_raw, extracted):
        # Owner decision (2026-09-06): when the handle is the ONLY evidence and
        # the page's display name — with the handle stripped — is clearly not
        # the subject, this is a lead, not a confirmation (rule 3: a different
        # name is weak negative evidence). "torvalds (Hemant)" with subject
        # "Linus Torvalds" is Hemant's account, not Linus's.
        if subject_name and _display_name_conflicts(subject_name, extracted, uname_raw):
            return _verdict("unconfirmed", 38,
                            ["handle appears in the page's title, but the display "
                             "name is someone else — may be another person"],
                            identity_match=False, control_probe=probe)
        return _verdict("confirmed", 72,
                        ["handle appears in the page's title/metadata"],
                        identity_match=identity_match, control_probe=probe)

    # 6. Soft-404 stated at the top of the main content, with no corroborating
    #    handle in the metadata — e.g. a generic title over "User not found".
    top = text[:400]
    for phrase in SOFT_404_PHRASES:
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
