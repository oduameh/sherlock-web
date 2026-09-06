"""Cross-account correlation: avatar hashes, name similarity, bio overlap.

Clusters enriched profiles that look like the same person and assigns a
confidence score (avatar 50 / name 30 / bio 20). Heuristic only — correlation
false positives are expected and confidence is advisory.

Design rules learned from real runs (each one was a live false bond):

1. **A placeholder avatar is not an avatar.** Two accounts that both show the
   site's default image (Twitch's ``user-default-pictures``, Telegram's logo
   for photo-less users, Tumblr's ``default_avatar`` shapes) hash identically
   and used to bond strangers at 97%. Placeholders are recognised by URL
   pattern *and* by frequency: one image on several different accounts of a
   site is the site's default, whatever its URL.
2. **A site template is not a bio, and a page title is never a display name.**
   Every platform stamps a template into ``og:description`` ("X is on
   Snapchat!", "Listen to X | SoundCloud is an audio platform…"), so two
   handles on one site share most of their "bio" words by construction. Bios
   are compared after stripping the site's template (learned per run from the
   site's own rows, seeded with known phrases), the site name and the handle.
   The raw ``<title>`` ("carmen_pop - Streamer Overview & Stats · TwitchTracker")
   is never used as a name — only structured ``jsonld_name`` / ``og:title``,
   and a "name" that is just the handle carries no independent information.
3. **Same-site pairs need hard evidence.** Two accounts on the same platform
   with similar names are not evidence of one person — in a name-derived run
   the handles were generated from the same name in the first place. A
   same-site bond requires a genuine (non-placeholder) avatar match; text
   signals are recorded as ignored so the analyst can see why there is no bond.
4. **Only real profile pages correlate.** A 404, a soft-404, a challenge page
   ("Just a moment...") or an unfetched row has enrichment that describes the
   site, not a person; those rows do not participate.
5. **A site's logo is not the user's avatar.** Many sites put their own logo,
   banner or social card in ``og:image`` (``9gag-og.png``, ``ifttt-banner``,
   ``logo-preview.png``). Six such images bonded six unrelated sites at hash
   distance 4. Site-asset URLs are placeholders; images too plain to identify
   a person (a heavily skewed 8x8 hash) are placeholders; and an 8x8 match
   must be corroborated at 16x16, where a reused photo still matches but two
   different generic images no longer do.
6. **A profile is not two profiles.** Engines label one site several ways
   ("Drive2" / "DRIVE2.RU"); the same URL modulo scheme, ``www.`` and a
   trailing slash is one account and never bonds with itself.
"""

from __future__ import annotations

import asyncio
import difflib
import io
import logging
import math
import re
import warnings
from collections import Counter, defaultdict
from typing import Optional
from urllib.parse import urlparse

from recon import policy, safeweb
from recon.confidence import (
    AVATAR_WEIGHT,
    BIO_WEIGHT,
    CORRELATION_LINK_MIN,
    NAME_WEIGHT,
)

logger = logging.getLogger("recon.correlate")

AVATAR_HAMMING_MAX = 5       # <= this on an 8x8 average hash = "same avatar"
AVATAR16_HAMMING_MAX = 24    # ... corroborated at 16x16 (256 bits) when available
GENERIC_HASH_MIN_BITS = 20   # an 8x8 hash with this many set bits or fewer (or
GENERIC_HASH_MAX_BITS = 44   # this many or more) is a near-uniform image, not a face
NAME_SIM_MIN = 0.75          # difflib ratio threshold
NAME_CONFLICT_PENALTY = 20   # two unrelated display names deflate a cross-site bond
BIO_JACCARD_MIN = 0.30       # token-overlap threshold (bios >= 5 words)
BIO_MIN_TOKENS = 5
MAX_AVATARS = 30             # unique avatar URLs downloaded per run
AVATAR_TIMEOUT_S = 8
AVATAR_MAX_BYTES = 5 * 1024 * 1024
# Decoded-size cap (security F-4). The byte cap bounds the *file*, not the
# decoded bitmap: a 12000x12000 blank PNG is ~18 KB on the wire and ~144 MB
# (mode "L") once decoded, x5 concurrent downloads. Pillow's own bomb check
# only warns below ~179 M pixels. A profile avatar is never 2000x2000.
AVATAR_MAX_PIXELS = 4_000_000

# Frequency rules for "this image is the site's default, not a person's face".
PLACEHOLDER_HASH_MIN_ROWS = 3        # one hash on >= this many rows anywhere
PLACEHOLDER_SAME_SITE_MIN_ROWS = 2   # ... or on >= this many handles of one site
TEMPLATE_MIN_ROWS = 3                # learn a site's bio template from >= 3 rows
TEMPLATE_MIN_SHARE = 0.6             # a token in >= 60% of the site's bios

_WORD_RE = re.compile(r"[a-z0-9]+")
_NON_ALNUM = re.compile(r"[^a-z0-9]+")

# Verification statuses whose enrichment describes the site, not a profile.
_NON_PROFILE_STATUSES = {"likely_false_positive", "indeterminate", "not_examined"}

# Known default/placeholder avatar URL fragments (all verified on live pages).
# Deliberately conservative — the frequency rules below catch the unknown ones.
_PLACEHOLDER_AVATAR_RE = re.compile(
    r"(user-default-pictures"          # Twitch
    r"|/default_avatar/"               # Tumblr shapes (cone_closed_200.png ...)
    r"|/img/t_logo"                    # Telegram logo shown for photo-less users
    r"|default_profile_images"         # Twitter
    r"|/avatar_default_"               # Reddit
    r"|/embed/avatars/"                # Discord
    r"|/missing\.png"                  # Mastodon
    r"|gravatar\.com/avatar/0{32}"     # Gravatar "no such hash"
    r"|fef49e7fa7e1997310d705b2a6158ff8dc1cdfeb"  # Steam default
    r"|/default_avatar_"               # SoundCloud
    r"|[/_-]no[-_]?avatar[/_.-]"
    r"|[/_-]placeholder[/_.-]"
    # --- site assets served as og:image (the site's logo, not the user) ---
    r"|[/_-]og[-_.](?:png|jpe?g|webp|image)"   # 9gag-og.png, og-image.png
    r"|opengraph|social[-_]?(?:card|share|preview)|share[-_]?image"
    r"|logo|banner|[-_]preview\.(?:png|jpe?g|webp)"
    r"|/static/images/|/builds/assets/"
    r"|discourse-cdn\.com/.*/letter/)",      # Discourse letter avatars ("T")
    re.I,
)

# Template phrases platforms stamp into titles/descriptions. Removed as
# substrings (lowercase) from names and bios before comparison. Seeds the
# per-run learned template for sites with too few rows to learn from.
_BOILERPLATE_PHRASES = (
    # Snapchat
    "snapchat stories, spotlight and lenses", "is on snapchat", "on snapchat",
    # SoundCloud
    "soundcloud is an audio platform that lets you listen to what you love "
    "and share the sounds you create", "listen to songs, albums, playlists "
    "for free on soundcloud",
    # Telegram
    "telegram: contact", "telegram: view", "you can contact",
    "you can view and join", "right away",
    # Linktree
    "linktree. make your link do more", "| linktree",
    # Tumblr
    "and get more of the good stuff by joining tumblr today. dive in!",
    "on tumblr", "untitled",
    # TwitchTracker
    "streamer overview & stats", "twitchtracker", "overview of",
    "activities, statistics, played games and past streams",
    # Patreon
    "patreon is empowering a new generation of creators",
    "support and engage with artists and creators",
    # misc
    "on codepen", "itch.io", "before you continue to", "just a moment",
    "make your day", "official",
)

# Connector words that are left dangling once a template is removed
# ("Carmen Pop on" ← "Carmen Pop on Snapchat"). Stripped from name edges only.
_EDGE_WORDS = {"on", "at", "in", "by", "the", "a", "an", "of", "from", "to",
               "profile", "page", "stream", "listen", "follow", "view",
               "contact", "and", "or", "|", "-", "·", ":", "•"}


def _open_avatar(image_bytes: bytes):
    """Open an avatar for hashing, refusing decompression bombs (F-4).

    ``Image.open`` reads only the header, so the dimensions are known before
    any pixel is decoded; ``.convert`` is what allocates the full bitmap.
    Returns None when ``width * height`` exceeds :data:`AVATAR_MAX_PIXELS`,
    and Pillow's ``DecompressionBombWarning`` (raised for >89 M pixels) is
    turned into an error so the caller's ``except`` returns None as well.
    """
    from PIL import Image

    with warnings.catch_warnings():
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        img = Image.open(io.BytesIO(image_bytes))
    if img.width * img.height > AVATAR_MAX_PIXELS:
        return None
    return img


def _average_hash_n(image_bytes: bytes, n: int) -> Optional[int]:
    try:
        img = _open_avatar(image_bytes)
        if img is None:
            return None
        img = img.convert("L").resize((n, n))
        pixels = list(img.tobytes())  # n*n grayscale bytes, one per pixel
        avg = sum(pixels) / len(pixels)
        bits = 0
        for p in pixels:
            bits = (bits << 1) | (1 if p >= avg else 0)
        return bits
    except Exception:
        return None


def average_hash(image_bytes: bytes) -> Optional[int]:
    """8x8 average hash as a 64-bit int. None if the image can't be read or
    would decode to more than :data:`AVATAR_MAX_PIXELS` pixels."""
    return _average_hash_n(image_bytes, 8)


def average_hash16(image_bytes: bytes) -> Optional[int]:
    """16x16 average hash as a 256-bit int — the corroboration hash. A photo
    reused across sites still matches here; two different generic images that
    happen to agree at 8x8 no longer do. Same size cap as :func:`average_hash`."""
    return _average_hash_n(image_bytes, 16)


def hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def is_generic_hash(h: Optional[int]) -> bool:
    """True when an 8x8 hash is too plain to identify a person: a logo on a
    flat background or a letter avatar sets very few (or nearly all) bits.
    Measured on live runs: real face photos 28-40 set bits; site logos,
    banners and letter avatars 10-20."""
    if h is None:
        return False
    pop = bin(h).count("1")
    return pop <= GENERIC_HASH_MIN_BITS or pop >= GENERIC_HASH_MAX_BITS


def _norm_name(s: Optional[str]) -> str:
    return re.sub(r"\s+", " ", (s or "").strip().lower())


def _norm_handle(s: Optional[str]) -> str:
    return _NON_ALNUM.sub("", (s or "").lower())


def names_conflict(a: str, b: str) -> bool:
    """True when two *real* display names share no name token at all (nor a
    nickname prefix: "rob" ~ "robert"). Character similarity is useless here —
    "carmen pariamo" vs "casey poplaski" scores 0.50 on shared letters."""
    ta = {t for t in _WORD_RE.findall((a or "").lower()) if len(t) >= 2}
    tb = {t for t in _WORD_RE.findall((b or "").lower()) if len(t) >= 2}
    if not ta or not tb:
        return False
    for x in ta:
        for y in tb:
            if x == y or x.startswith(y) or y.startswith(x):
                return False
    return True


def name_similarity(a: str, b: str) -> float:
    a, b = _norm_name(a), _norm_name(b)
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a, b).ratio()


def _tokens(s: Optional[str]) -> set[str]:
    return set(_WORD_RE.findall((s or "").lower()))


def bio_similarity(a: Optional[str], b: Optional[str]) -> float:
    ta, tb = _tokens(a), _tokens(b)
    if len(ta) < BIO_MIN_TOKENS or len(tb) < BIO_MIN_TOKENS:
        return 0.0
    union = ta | tb
    return len(ta & tb) / len(union) if union else 0.0


# ---------------------------------------------------------------------------
# Placeholder avatars (rule 1)
# ---------------------------------------------------------------------------

def is_placeholder_avatar(url: Optional[str]) -> bool:
    """True when the avatar URL is a known site default/placeholder image."""
    if not url:
        return False
    return bool(_PLACEHOLDER_AVATAR_RE.search(url))


def placeholder_hashes(rows: list[dict]) -> set[int]:
    """Avatar hashes that are a site default rather than a person's picture.

    * near-uniform images (see :func:`is_generic_hash`);
    * one hash on >= :data:`PLACEHOLDER_HASH_MIN_ROWS` rows anywhere;
    * one hash on >= :data:`PLACEHOLDER_SAME_SITE_MIN_ROWS` *different* handles
      of the same site — a real avatar URL is unique per user, a default is not;
    * the hash of any row whose avatar URL matches a known placeholder pattern.
    """
    out: set[int] = set()
    counts: Counter = Counter()
    per_site: dict[tuple, set] = defaultdict(set)
    for r in rows:
        h = r.get("avatar_hash")
        if h is None:
            continue
        if is_generic_hash(h):            # covers all-0 / all-1 too
            out.add(h)
        if is_placeholder_avatar(_avatar_url(r)):
            out.add(h)
        counts[h] += 1
        per_site[(_site_key(r), h)].add(_norm_handle(r.get("username")))
    out.update(h for h, n in counts.items() if n >= PLACEHOLDER_HASH_MIN_ROWS)
    out.update(h for (_, h), handles in per_site.items()
               if len(handles) >= PLACEHOLDER_SAME_SITE_MIN_ROWS)
    return out


# ---------------------------------------------------------------------------
# Names and bios without the site's template (rule 2)
# ---------------------------------------------------------------------------

def _norm_url(url: Optional[str]) -> str:
    """Scheme-, ``www.``- and trailing-slash-insensitive URL identity."""
    u = (url or "").strip().lower()
    u = re.sub(r"^https?://", "", u)
    u = re.sub(r"^www\.", "", u)
    return u.rstrip("/")


def _host(row: dict) -> str:
    try:
        host = urlparse(row.get("url") or "").netloc.lower()
    except Exception:
        return ""
    return host[4:] if host.startswith("www.") else host


def same_account(a: dict, b: dict) -> bool:
    """One profile listed twice (two engine labels for one site)."""
    if _norm_url(a.get("url")) == _norm_url(b.get("url")):
        return True
    return (bool(_host(a)) and _host(a) == _host(b)
            and _norm_handle(a.get("username")) == _norm_handle(b.get("username")))


def _site_key(row: dict) -> str:
    """Normalised site identity: the ``site`` label, else the URL host."""
    site = _norm_handle(row.get("site"))
    if site:
        return site
    try:
        return _norm_handle(urlparse(row.get("url") or "").netloc)
    except Exception:
        return ""


def _site_words(row: dict) -> set[str]:
    """Words that name the platform itself (site label + URL host parts)."""
    words = set(_WORD_RE.findall((row.get("site") or "").lower()))
    words.add(_site_key(row))
    try:
        host = urlparse(row.get("url") or "").netloc.lower()
    except Exception:
        host = ""
    for part in host.split("."):
        if part and part not in ("www", "com", "net", "org", "io", "me", "co"):
            words.add(part)
    return {w for w in words if w}


def _strip_phrases(text: str, phrases=_BOILERPLATE_PHRASES) -> str:
    low = text.lower()
    for p in phrases:
        if p in low:
            low = low.replace(p, " ")
    return low


def _strip_handle(text: str, handle: str) -> str:
    """Remove the handle (with optional separators / leading @) from text."""
    h = _norm_handle(handle)
    if len(h) < 2:
        return text
    body = "[^a-z0-9]?".join(re.escape(ch) for ch in h)
    # Lookarounds keep the match on a token boundary: handle "carmenp" must not
    # eat the "Carmen P" out of "Carmen Pacheco".
    text = re.sub(r"(?<!\w)@" + body + r"(?!\w)", " ", text, flags=re.I)
    # A bare handle is removed only when a separator glues it to a template
    # ("cpop - Streamer Overview", "cpop | Linktree") — never out of the middle
    # of a real name ("Alice Example" for handle alice keeps its "Alice").
    sep = r"[-|·:()\[\]•]"
    text = re.sub(r"(^|" + sep + r")\s*" + body + r"(?!\w)\s*(?=" + sep + r"|$)",
                  r"\1 ", text, flags=re.I)
    return text


def clean_display_name(row: dict) -> str:
    """The person's display name with the site's template removed, or "".

    Uses only structured fields (``jsonld_name``, ``og_title``) — never the raw
    page ``<title>``. Returns "" when nothing person-specific is left or when
    the "name" is merely the handle again.
    """
    enr = row.get("enrichment") or {}
    raw = enr.get("jsonld_name") or enr.get("og_title") or ""
    if not raw:
        return ""
    handle = row.get("username") or ""
    if _norm_handle(raw) == _norm_handle(handle):
        return ""                              # handle-as-name: no new information
    text = _strip_phrases(raw)
    text = _strip_handle(text, handle)
    site_words = _site_words(row)
    words = [w for w in re.split(r"\s+", text) if w]
    words = [w for w in words
             if _NON_ALNUM.sub("", w) not in site_words]
    # Trim dangling connectors/punctuation left at the edges by the removals.
    while words and (_NON_ALNUM.sub("", words[0]) in _EDGE_WORDS
                     or not _NON_ALNUM.sub("", words[0])):
        words.pop(0)
    while words and (_NON_ALNUM.sub("", words[-1]) in _EDGE_WORDS
                     or not _NON_ALNUM.sub("", words[-1])):
        words.pop()
    name = " ".join(w.strip("()[]|-·:@,") for w in words).strip()
    name = re.sub(r"\s+", " ", name)
    if len(_norm_handle(name)) < 2 or _norm_handle(name) == _norm_handle(handle):
        return ""
    return name


def _raw_bio(row: dict) -> str:
    enr = row.get("enrichment") or {}
    return enr.get("jsonld_description") or enr.get("og_description") or ""


def site_template_tokens(site_rows: list[dict]) -> set[str]:
    """Bio tokens that are the site's template, learned from the site's own
    rows: any token present in >= :data:`TEMPLATE_MIN_SHARE` of at least
    :data:`TEMPLATE_MIN_ROWS` bios. With fewer rows nothing is learned (the
    static seed phrases still apply)."""
    bios = [_tokens(_raw_bio(r)) for r in site_rows if _raw_bio(r)]
    if len(bios) < TEMPLATE_MIN_ROWS:
        return set()
    need = max(TEMPLATE_MIN_ROWS, math.ceil(TEMPLATE_MIN_SHARE * len(bios)))
    counts: Counter = Counter()
    for toks in bios:
        counts.update(toks)
    return {t for t, n in counts.items() if n >= need}


def clean_bio_tokens(row: dict, template: set[str] = frozenset()) -> set[str]:
    """Bio vocabulary minus the site's template, the site's name and the
    handle. Empty set when nothing person-specific is left."""
    raw = _raw_bio(row)
    if not raw:
        return set()
    text = _strip_phrases(raw)
    text = _strip_handle(text, row.get("username") or "")
    toks = _tokens(text) - template - _site_words(row)
    toks -= _tokens(row.get("username"))
    return toks


def _jaccard(a: set, b: set) -> float:
    if len(a) < BIO_MIN_TOKENS or len(b) < BIO_MIN_TOKENS:
        return 0.0
    union = a | b
    return len(a & b) / len(union) if union else 0.0


# ---------------------------------------------------------------------------
# Participation (rule 4)
# ---------------------------------------------------------------------------

def participates(row: dict) -> bool:
    """Only real, fetched profile pages take part in correlation."""
    if not (row.get("enrichment") or row.get("avatar_hash") is not None):
        return False
    status = (row.get("verification") or {}).get("status")
    return status not in _NON_PROFILE_STATUSES


def _avatar_url(row: dict) -> Optional[str]:
    enr = row.get("enrichment") or {}
    return enr.get("jsonld_image") or enr.get("og_image")


async def _download_avatars(rows: list[dict]) -> None:
    """Attach ``avatar_hash`` to rows that have an avatar URL (in place).

    Known placeholders are not fetched; rows sharing one URL share one fetch.
    Avatars hosted on a robots-denied host (``og:image`` on ``pbs.twimg.com``
    is common) are never requested (security F-2): the access policy applies
    to every fetch path, not only profile pages.
    """
    sem = asyncio.Semaphore(5)
    by_url: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        url = _avatar_url(r)
        if not url or r.get("avatar_hash") is not None:
            continue
        if is_placeholder_avatar(url):
            continue
        if policy.denied_reason(url):
            logger.debug("avatar not fetched (access policy): %s", url)
            continue
        by_url[url].append(r)
    targets = list(by_url.items())[:MAX_AVATARS]
    if not targets:
        return
    async with safeweb.async_client(timeout=AVATAR_TIMEOUT_S) as client:

        async def one(url: str, group: list[dict]) -> None:
            try:
                async with sem:
                    content = await safeweb.fetch_capped(
                        client, url, AVATAR_MAX_BYTES)
                if content:
                    h = average_hash(content)
                    h16 = average_hash16(content)
                    if h is not None:
                        for row in group:
                            row["avatar_hash"] = h
                            if h16 is not None:
                                row["avatar_hash16"] = h16
            except Exception:
                pass

        await asyncio.gather(*(one(u, g) for u, g in targets),
                             return_exceptions=True)


# ---------------------------------------------------------------------------
# Pairwise scoring
# ---------------------------------------------------------------------------

def score_pair(a: dict, b: dict, *, placeholders: set[int] = frozenset(),
               templates: Optional[dict] = None) -> dict:
    """Score one pair. Returns ``{score, rationale, signals}`` where
    ``signals`` is the structured evidence breakdown (``avatar_distance``,
    ``name_sim``, ``bio_overlap``) plus an ``ignored`` list naming every
    signal that was present but deliberately not counted, so the analyst can
    see the reasoning rather than just its result."""
    templates = templates or {}
    score = 0
    reasons: list[str] = []
    signals: dict = {}
    ignored: list[str] = []
    same_site = _site_key(a) == _site_key(b) and _site_key(a) != ""

    if same_account(a, b):
        return {"score": 0, "rationale": "",
                "signals": {"ignored": ["same profile listed under two site "
                                        "names — one account, not a bond"]}}

    ha, hb = a.get("avatar_hash"), b.get("avatar_hash")
    if ha is not None and hb is not None:
        d = hamming(ha, hb)
        if d <= AVATAR_HAMMING_MAX:
            h16a, h16b = a.get("avatar_hash16"), b.get("avatar_hash16")
            d16 = (hamming(h16a, h16b)
                   if h16a is not None and h16b is not None else None)
            if ha in placeholders or hb in placeholders:
                ignored.append("avatars match but the image is the site's "
                               "default placeholder or logo, not a person")
            elif d16 is not None and d16 > AVATAR16_HAMMING_MAX:
                ignored.append("avatars resemble each other only at low "
                               "resolution — two different generic images, "
                               "not one reused photo")
            else:
                score += AVATAR_WEIGHT
                reasons.append(f"avatars match (hash distance {d})")
                signals["avatar_distance"] = d
                if d16 is not None:
                    signals["avatar_distance16"] = d16

    na, nb = clean_display_name(a), clean_display_name(b)
    nsim = name_similarity(na, nb) if na and nb else 0.0
    conflict = bool(na and nb) and names_conflict(na, nb)
    if conflict:
        # Two genuine, different display names: weak negative evidence (people
        # use nicknames), never a hard flag — except on the same site, where
        # the only positive evidence possible was an avatar match, and a
        # different name means a different person behind a similar picture.
        signals["name_conflict"] = round(nsim, 2)
        if same_site:
            score = 0
            reasons = []
            signals.pop("avatar_distance", None)
            ignored.append(f"avatars match but the display names differ "
                           f'("{na}" vs "{nb}") — likely two people')
        else:
            score = max(0, score - NAME_CONFLICT_PENALTY)
            reasons.append(f'display names differ ("{na}" vs "{nb}")')
    if nsim >= NAME_SIM_MIN:
        if same_site:
            ignored.append("display names similar, but two accounts on the "
                           "same site are not evidence of one person")
        else:
            score += round(NAME_WEIGHT * nsim)
            reasons.append(f"display names {nsim:.0%} similar")
            signals["name_sim"] = round(nsim, 2)

    ta = clean_bio_tokens(a, templates.get(_site_key(a), set()))
    tb = clean_bio_tokens(b, templates.get(_site_key(b), set()))
    bsim = _jaccard(ta, tb)
    if bsim >= BIO_JACCARD_MIN:
        if same_site:
            ignored.append("bios overlap, but same-site bios share the "
                           "platform's template")
        else:
            score += round(BIO_WEIGHT * min(1.0, bsim / BIO_JACCARD_MIN))
            reasons.append(f"bios share {bsim:.0%} of words")
            signals["bio_overlap"] = round(bsim, 2)

    if ignored:
        signals["ignored"] = ignored
    return {"score": min(100, score), "rationale": "; ".join(reasons),
            "signals": signals}


async def correlate(rows: list[dict]) -> list[dict]:
    """Cluster found-profile rows. Returns clusters with confidence 0-100.

    Only real, fetched profile rows with enrichment participate. Each cluster:
      {members: [{username, site, url}], confidence, links: [{a, b, score,
      rationale, signals}]}
    """
    candidates = [r for r in rows if participates(r)]
    if len(candidates) < 2:
        return []

    await _download_avatars(candidates)
    candidates = [r for r in candidates if r.get("enrichment")]
    if len(candidates) < 2:
        return []

    # One profile, one row: engines label a site several ways and the same
    # URL (modulo scheme / www. / trailing slash) must not bond with itself.
    unique: dict[str, dict] = {}
    for r in candidates:
        unique.setdefault(_norm_url(r.get("url")), r)
    candidates = list(unique.values())
    if len(candidates) < 2:
        return []

    placeholders = placeholder_hashes(candidates)
    by_site: dict[str, list[dict]] = defaultdict(list)
    for r in candidates:
        by_site[_site_key(r)].append(r)
    templates = {s: site_template_tokens(rs) for s, rs in by_site.items()}

    # Union-find over pairwise links.
    parent = list(range(len(candidates)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i: int, j: int) -> None:
        parent[find(i)] = find(j)

    def label(r: dict) -> str:
        return f'{r.get("site")} ({r.get("url")})'

    links: list[dict] = []
    for i in range(len(candidates)):
        for j in range(i + 1, len(candidates)):
            a, b = candidates[i], candidates[j]
            res = score_pair(a, b, placeholders=placeholders, templates=templates)
            if res["score"] >= CORRELATION_LINK_MIN:  # below this, too speculative
                links.append({"a": label(a), "b": label(b), **res})
                union(i, j)

    groups: dict[int, list[int]] = {}
    for i in range(len(candidates)):
        groups.setdefault(find(i), []).append(i)

    clusters = []
    for idxs in groups.values():
        if len(idxs) < 2:
            continue
        members = [
            {
                "username": candidates[i].get("username"),
                "site": candidates[i].get("site"),
                "url": candidates[i].get("url"),
            }
            for i in idxs
        ]
        # Attribute links by exact endpoint label — a prefix match on the site
        # name used to leak every same-site link into every cluster on that site.
        labels = {label(candidates[i]) for i in idxs}
        member_links = [l for l in links if l["a"] in labels and l["b"] in labels]
        confidence = max((l["score"] for l in member_links), default=0)
        clusters.append({
            "members": members,
            "confidence": confidence,
            "links": member_links,
        })
    clusters.sort(key=lambda c: c["confidence"], reverse=True)
    return clusters
