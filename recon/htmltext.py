"""Shared HTML-to-text helpers and page-class marker lists.

This is the *single* home for the pieces that :mod:`recon.verify` (the verdict)
and :mod:`recon.stealthweb` (the escalation decision) used to each keep a copy
of. The copies had already drifted (the challenge lists were the same phrases
in a different order — someone had edited them separately), and the class of
bug that produces is nasty: the ladder escalates a page because stealthweb
calls it a challenge, then verify reads the same page as a real profile.
Every consumer now asks the same functions the same question.

Three kinds of thing live here, all pure and network-free:

* **HTML → text** — :func:`visible_text`, :func:`page_headline`,
  :func:`heading_texts`, :func:`strip_script_style`, :func:`iter_tags`,
  :func:`iter_jsonld_blocks`, and the regexes behind them. Every pattern here
  is linear and length-capped. The previous ``<title[^>]*>(.*?)</title>`` and
  ``<h[12][^>]*>(.*?)</h[12]>`` took more than 20 s on ``"<title>" * 40000``
  (280 KB — well inside the 512 KB body cap) and ran synchronously in the event
  loop, freezing every SSE stream (security audit F-3). A profile page is
  content the *subject* controls, so hostile markup is a realistic input.
* **Marker lists** — :data:`CHALLENGE_MARKERS`, :data:`CONSENT_WALL_MARKERS`,
  :data:`SOFT_404_PHRASES`, :data:`SOFT_404_RE`. Extending the challenge list
  with the WAF families that used to slip through (Akamai "Access Denied …
  Reference #", Imperva "Pardon Our Interruption / Incapsula incident", AWS WAF,
  Kasada, "Request unsuccessful", "Request blocked") is what turns those pages
  from "likely false positive" / "unconfirmed lead" into "blocked" (V2).
* **Classifiers** — :func:`challenge_marker` / :func:`has_challenge_markers`,
  :func:`consent_wall_marker` / :func:`has_consent_wall`,
  :func:`looks_like_shell`.

Scoping rule for markers: human-readable phrases ("access denied", "just a
moment", "request blocked" …) are matched only in the page's *own* headline
(title, ``og:title``, first ``<h1>``/``<h2>``) and the first 400 characters of
visible text, so a bio that jokes about captchas or a comment thread cannot
turn a real profile into a block page. Vendor tokens that only ever appear in
anti-bot machinery (``cf-challenge``, ``datadome``, ``px-captcha`` …) may
additionally be matched in the first 20 KB of raw HTML, but only by the
escalation decision — a legitimate page fronted by DataDome/PerimeterX carries
their script tag on every page, so that raw match must never decide a verdict.

Invariant carried by everything here: **blocked ≠ absent**. A challenge page,
a consent wall and a rate limit are all "we could not look", never "no account".
"""

from __future__ import annotations

import re
from typing import Iterator, Optional

# ---------------------------------------------------------------------------
# Regexes — every one linear and length-capped (F-3)
# ---------------------------------------------------------------------------

# A tag: ``<`` then up to 4000 non-angle characters (possessive, so no
# backtracking) then ``>``. The old ``<[^>]+>`` was quadratic on ``"<" * N``.
TAG_RE = re.compile(r"<[^<>]{0,4000}+>")
WS_RE = re.compile(r"\s+")

# ``<title>`` text: the tag itself is bounded (``[^<>]{0,200}``) and the text is
# ``[^<]{0,4000}`` — RCDATA cannot contain a tag, so stopping at the first ``<``
# loses nothing real. Replaces ``<title[^>]*>(.*?)</title>`` (re.S), which was
# super-linear on unterminated titles.
TITLE_RE = re.compile(r"<title\b[^<>]{0,200}+>([^<]{0,4000})", re.I)

# Opening ``<h1>``/``<h2>`` tag only; the heading text is sliced out with
# :func:`heading_texts` so nested markup (``<h1><span>Not found</span></h1>``)
# still yields its text — a plain ``([^<]{0,2000})`` capture would return ""
# for the nested form and lose the very phrase the soft-404 rule looks for.
HEADING_OPEN_RE = re.compile(r"<h[12]\b[^<>]{0,500}+>", re.I)
_HEADING_CLOSE_RE = re.compile(r"</h[12]\b", re.I)
HEADING_TEXT_CAP = 2000

# Attribute extraction runs only on a single tag's text (≤ ``TAG_TEXT_CAP``
# chars, produced by :func:`iter_tags`), so these bounded patterns are cheap.
META_KEY_RE = re.compile(
    r"""\b(?:property|name)\s*=\s*(?:"([^"]{0,200})"|'([^']{0,200})')""", re.I)
META_CONTENT_RE = re.compile(
    r"""\bcontent\s*=\s*(?:"([^"]{0,4000})"|'([^']{0,4000})')""", re.I)
TAG_TEXT_CAP = 4000

# Page-headline scan window: the title and first headings live in the first
# few KB; scanning further only costs time on hostile input.
HEADLINE_SCAN_LIMIT = 512 * 1024   # == the fetch body cap: a heading behind 70 KB of
                                   # inline script must still be seen (review blocker)
VISIBLE_TEXT_RAW_LIMIT = 128 * 1024

# JSON-LD extraction caps (per block / per page).
JSONLD_BLOCK_CAP = 200_000
JSONLD_MAX_BLOCKS = 20

# A page whose entire visible text is shorter than this is a JS-app shell or a
# bare interstitial — there is nothing to extract or verify from it.
MIN_VISIBLE_CHARS = 80

# Generic phrases are checked only in the headline and the top of the visible
# text, never deeper (a bio must not be able to trigger them).
MARKER_TOP_CHARS = 400
# Vendor tokens may be looked for in this much raw HTML (escalation only).
MARKER_RAW_LIMIT = 20_000


# ---------------------------------------------------------------------------
# Marker lists
# ---------------------------------------------------------------------------

# Human-readable anti-bot / WAF phrases. Matched in the page's own headline and
# first 400 visible characters only.
CHALLENGE_PHRASES: tuple[str, ...] = (
    # Cloudflare and the generic interstitials that copy its wording
    "just a moment", "attention required", "checking your browser",
    "verifying you are human", "verify you are a human", "one more step",
    "enable javascript and cookies", "ddos protection by",
    # WAF families that used to slip through (V2): Akamai, Imperva, AWS WAF,
    # Kasada, F5/generic "request blocked" pages
    "access denied", "reference #", "pardon our interruption",
    "incapsula incident", "request unsuccessful", "client challenge",
    "request blocked",
)

# Tokens that only occur inside anti-bot machinery (script paths, element ids,
# cookie names). Safe to look for in raw HTML *for escalation*; not for a
# verdict — sites fronted by DataDome/PerimeterX/Cloudflare's JS detections
# carry these script tags on every legitimate page too.
CHALLENGE_VENDOR_TOKENS: tuple[str, ...] = (
    "cf-challenge", "challenge-platform", "ddos-guard", "datadome",
    "perimeterx", "px-captcha", "captcha-delivery", "awswaf", "kasada",
)

# The one shared list (union of the former verify._CHALLENGE and
# stealthweb._CHALLENGE_MARKERS, plus the WAF families above).
CHALLENGE_MARKERS: tuple[str, ...] = CHALLENGE_PHRASES + CHALLENGE_VENDOR_TOKENS

# Consent / cookie walls: a real page was served, but it is the platform's
# GDPR interstitial, not the profile. Google-family sites ("Before you continue
# to YouTube") do this for every logged-out datacenter request. Same class of
# outcome as a challenge page — blockage, never absence and never a lead.
CONSENT_WALL_MARKERS: tuple[str, ...] = (
    "before you continue to", "consent.google", "consent.youtube",
    "we use cookies to continue", "accept all cookies to continue",
)

# Phrases that, in a page's OWN title/heading, mean the profile is absent.
# Deliberately specific: bare fragments like "doesn't exist" match real bios.
SOFT_404_PHRASES: tuple[str, ...] = (
    "user not found", "page not found", "profile not found",
    "account not found", "page doesn't exist", "page does not exist",
    "user does not exist", "no longer exists", "404 not found",
    "sorry, this page", "couldn't find this account",
    "this page isn't available", "nothing to see here",
    "no users found", "user unavailable",
)

# Soft-404 stated *around* the handle: "Profile johnsmith77 not found",
# "The user @jsmith does not exist", "This page couldn't be found". The fixed
# phrases above require adjacency, so a site that echoes the handle between
# the subject word and the predicate slipped past them — and then the handle
# in the title *confirmed* the account (V1). Subject word, ≤ 40 characters of
# anything, predicate; word-bounded so "user experience not found elsewhere"
# in a bio does not count (and bios are never scanned by this anyway — it is
# applied to the headline only).
SOFT_404_RE = re.compile(
    r"\b(?:profile|user|page|account|member)\b.{0,40}?\b"
    r"(?:not found|does ?not exist|doesn['’]t exist|could ?not be found|"
    r"couldn['’]t be found|no longer exists)\b",
    re.I | re.S,
)

# Predicates a not-found page uses when it names the handle itself:
# "Torvalds does not use Launchpad", "torvalds is not on Mastodon",
# "torvalds hasn't joined Keybase yet". None of them appears in a real profile
# title, so anchoring on the handle is safe (review should-fix 3).
_SOFT_404_PREDICATES = (
    r"not found|does ?not exist|doesn['’]t exist|could ?not be found|"
    r"couldn['’]t be found|no longer exists|does ?not use|doesn['’]t use|"
    r"is ?not on|isn['’]t on|has ?not joined|hasn['’]t joined"
)


def soft_404_pattern(handle: str) -> re.Pattern:
    """A per-call soft-404 regex with the handle as an extra subject word."""
    subject = r"profile|user|page|account|member"
    if handle and len(handle) >= 3:
        subject += "|" + re.escape(handle)
    return re.compile(r"\b(?:" + subject + r")\b.{0,40}?\b(?:" + _SOFT_404_PREDICATES + r")\b",
                      re.I | re.S)


# Generic phrases that also occur on legitimate pages (an album called
# "Access Denied"). They may decide a verdict only when nothing on the page
# names the handle — a WAF block page never does (review should-fix 6).
WEAK_CHALLENGE_PHRASES: tuple[str, ...] = (
    "access denied", "reference #", "request blocked", "request unsuccessful",
)


# ---------------------------------------------------------------------------
# HTML → text
# ---------------------------------------------------------------------------

_SCRIPT_STYLE_OPEN_RE = re.compile(r"<(script|style)(?=[\s>/])", re.I)


def strip_script_style(html: str) -> str:
    """Remove ``<script>``/``<style>`` elements including their bodies.

    Linear: one regex finds the next real open tag (the lookahead rejects
    ``<scripts>``-style junk without a Python loop over every look-alike), and
    ``str.find`` jumps to its closing tag. The previous helper rescanned for
    both names on every call, so M terminated elements followed by N
    look-alikes cost M×N iterations (0.9 s per row in the event loop on
    24 KB of hostile markup — review should-fix). An unterminated element
    swallows the rest of the document, exactly as a browser does.
    """
    if not html:
        return ""
    out: list[str] = []
    i, n, low = 0, len(html), html.lower()
    while i < n:
        m = _SCRIPT_STYLE_OPEN_RE.search(html, i)
        if not m:
            out.append(html[i:])
            break
        out.append(html[i:m.start()])
        out.append(" ")
        k = low.find("</" + m.group(1).lower(), m.end())
        if k < 0:
            break
        end = low.find(">", k)
        i = n if end < 0 else end + 1
    return "".join(out)


def visible_text(html: Optional[str], limit: int = 4000) -> str:
    """Strip script/style bodies and tags → collapse whitespace → lowercase.

    Works on the first ``limit * 6`` characters of the document and returns at
    most ``limit`` characters of text, so it is bounded on any input.
    """
    if not html:
        return ""
    chunk = strip_script_style(html[:VISIBLE_TEXT_RAW_LIMIT])
    return WS_RE.sub(" ", TAG_RE.sub(" ", chunk)).strip().lower()[:limit]


def heading_texts(html: Optional[str], limit: int = 3,
                  cap: int = HEADING_TEXT_CAP) -> list[str]:
    """Text of the first ``limit`` ``<h1>``/``<h2>`` elements, tags stripped.

    Linear: the opening tag is located with a bounded regex and the text is a
    ``cap``-character slice cut at the first ``</h1>``/``</h2>``.
    """
    if not html:
        return []
    out: list[str] = []
    for m in HEADING_OPEN_RE.finditer(html):
        seg = html[m.end(): m.end() + cap]
        close = _HEADING_CLOSE_RE.search(seg)
        if close:
            seg = seg[: close.start()]
        out.append(TAG_RE.sub(" ", seg))
        if len(out) >= limit:
            break
    return out


def page_title(html: Optional[str], scan_limit: int = HEADLINE_SCAN_LIMIT
               ) -> Optional[str]:
    """Raw ``<title>`` text from the first ``scan_limit`` characters, or None."""
    if not html:
        return None
    m = TITLE_RE.search(html[:scan_limit])
    return m.group(1) if m else None


def page_headline(html: Optional[str], extracted: Optional[dict],
                  scan_limit: int = HEADLINE_SCAN_LIMIT) -> str:
    """The page's title, headings and extracted title/og:title — where a site
    actually states "not found" or "access denied" — as one lowercase string.

    Scoping soft-404 and challenge matching here (rather than the whole body)
    stops a phrase buried in someone's bio, a comment thread or a boilerplate
    footer from condemning a real profile, while still catching a
    200-with-"User not found" page whose title is generic. Scans at most
    ``scan_limit`` (64 KB) of HTML.
    """
    extracted = extracted or {}
    parts = [str(extracted.get("title") or ""), str(extracted.get("og_title") or "")]
    if html:
        head = html[:scan_limit]
        title = page_title(head, scan_limit)
        if title:
            parts.append(title)
        parts.extend(heading_texts(head, limit=3))
    text = " ".join(TAG_RE.sub(" ", p) for p in parts)
    return WS_RE.sub(" ", text).strip().lower()


def iter_tags(html: Optional[str], name: str, cap: int = TAG_TEXT_CAP
              ) -> Iterator[str]:
    """Yield the text of every ``<name …>`` tag (the tag itself, ``<`` to ``>``).

    ``str.find``-based and bounded: a tag with no ``>`` inside ``cap``
    characters is skipped, so hostile ``"<meta " * N`` input is linear.
    """
    if not html:
        return
    low = html.lower()
    needle = "<" + name.lower()
    pos = 0
    n = len(html)
    while pos < n:
        j = low.find(needle, pos)
        if j < 0:
            return
        nxt = j + len(needle)
        if nxt < n and low[nxt] not in " \t\r\n>/":
            pos = nxt
            continue
        end = low.find(">", nxt, nxt + cap)
        if end < 0:
            pos = nxt
            continue
        yield html[j:end + 1]
        pos = end + 1


def iter_jsonld_blocks(html: Optional[str], block_cap: int = JSONLD_BLOCK_CAP,
                       max_blocks: int = JSONLD_MAX_BLOCKS) -> Iterator[str]:
    """Yield the raw text of each ``<script type="application/ld+json">`` block.

    ``str.find``-based scanning (linear) instead of the former
    ``<script[^>]+type=…>(.*?)</script>`` regex, which took ~10 s on 280 KB of
    unterminated ld+json. At most ``max_blocks`` blocks of at most
    ``block_cap`` characters each; an unterminated block is dropped.
    """
    if not html:
        return
    low = html.lower()
    pos = 0
    n = len(html)
    yielded = 0
    while pos < n and yielded < max_blocks:
        j = low.find("<script", pos)
        if j < 0:
            return
        open_end = low.find(">", j, j + TAG_TEXT_CAP)
        if open_end < 0:
            pos = j + 7
            continue
        open_tag = low[j:open_end + 1]
        pos = open_end + 1
        if "ld+json" not in open_tag:
            continue
        close = low.find("</script", pos, pos + block_cap + 9)
        if close < 0:
            return
        yield html[pos:close]
        yielded += 1
        pos = close + 9


# ---------------------------------------------------------------------------
# Page-class classifiers
# ---------------------------------------------------------------------------

def _scoped_text(html: Optional[str], extracted: Optional[dict]) -> str:
    """Headline plus the first 400 characters of visible text — the only
    region where generic block/consent phrases are allowed to decide."""
    return (page_headline(html, extracted) + " "
            + visible_text(html)[:MARKER_TOP_CHARS])


def challenge_marker(html: Optional[str], extracted: Optional[dict] = None,
                     *, raw_tokens: bool = True) -> Optional[str]:
    """The anti-bot marker this page carries, or None.

    Every marker in :data:`CHALLENGE_MARKERS` is checked against the headline
    and the top 400 visible characters. With ``raw_tokens`` (the escalation
    decision's setting) the vendor tokens are additionally looked for in the
    first 20 KB of raw HTML. Verification passes ``raw_tokens=False``: a
    DataDome/PerimeterX script tag on a legitimate page must never turn a real
    profile into a block page, whereas spending one stealth fetch on it is an
    acceptable cost.
    """
    if not html:
        return None
    scoped = _scoped_text(html, extracted)
    for marker in CHALLENGE_MARKERS:
        if marker in scoped:
            return marker
    if raw_tokens:
        raw = html[:MARKER_RAW_LIMIT].lower()
        for token in CHALLENGE_VENDOR_TOKENS:
            if token in raw:
                return token
    return None


def has_challenge_markers(html: Optional[str]) -> bool:
    """True when the page smells like an anti-bot interstitial (escalation
    setting: scoped phrases plus raw vendor tokens)."""
    return challenge_marker(html) is not None


def consent_wall_marker(html: Optional[str], extracted: Optional[dict] = None
                        ) -> Optional[str]:
    """The consent/cookie-wall phrase in the page's headline or top text, or None."""
    if not html:
        return None
    scoped = _scoped_text(html, extracted)
    for marker in CONSENT_WALL_MARKERS:
        if marker in scoped:
            return marker
    return None


def has_consent_wall(html: Optional[str]) -> bool:
    """True when the page is a GDPR consent interstitial, not the profile."""
    return consent_wall_marker(html) is not None


def looks_like_shell(html: Optional[str]) -> bool:
    """True for an empty JS-app shell / boilerplate page with no real text."""
    if not html:
        return False
    return len(visible_text(html)) < MIN_VISIBLE_CHARS
