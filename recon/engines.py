"""Scan engine wrappers: Sherlock (sync, thread) and Maigret (async).

Everything maigret-related is imported lazily so the app boots fine when the
package is missing. Site-name matching across engines is done on a normalized
form (lowercase, alphanumerics only) so "GitHub"/"github" merge.
"""

from __future__ import annotations

import logging
import re
import threading
from typing import Any, Callable, Optional

from recon import policy

logger = logging.getLogger("recon.engines")

# ---------------------------------------------------------------------------
# Curated high-value site list used for variant scans.
# Each entry: canonical tag -> aliases to try (normalized matching).
#
# Robots-denied platforms are deliberately absent: Twitter/X, Instagram,
# Reddit, Pinterest, Facebook and Flickr were listed here until 2026-09-06 and
# so were scanned on every variant / name-candidate pass by all three engines,
# contradicting recon.policy ("denied hosts are never fetched"). The
# authoritative rule is the URL filter applied at plan time; this list is kept
# clean so the curated subset never *asks* for a denied host, and
# tests/test_engines.py asserts no member matches policy.denied_name_reason.
# HackerNews stays: Sherlock checks it on news.ycombinator.com (permitted);
# the Maigret/WhatsMyName entries that probe the denied Firebase API are
# removed by their URLs.
# ---------------------------------------------------------------------------

HIGH_VALUE_SITES = [
    "GitHub", "TikTok", "YouTube",
    "mastodon.social", "Bluesky", "Medium", "DEV Community", "Keybase",
    "GitLab", "Twitch", "Steam", "Spotify", "LinkedIn",
    "Snapchat", "Telegram", "tumblr", "Behance",
    "Dribbble", "ProductHunt", "HackerNews", "WordPress", "Vimeo",
    "SoundCloud", "Patreon", "Linktree", "About.me", "Gravatar",
    "Itch.io", "Codepen", "npm", "PyPi", "Kaggle", "Strava",
]

# Extra aliases for names that differ between engines' databases.
_ALIASES = {
    "linktree": ["linktr.ee"],
    "dev community": ["dev.to"],
    "steam": ["steam community (user)"],
}


def normalize_site(name: str) -> str:
    """Normalization key used to dedupe sites across engines."""
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _match_names(available: list[str], wanted: list[str]) -> list[str]:
    """Return the subset of `available` matching the wanted canonical names."""
    by_norm = {normalize_site(n): n for n in available}
    picked: list[str] = []
    for w in wanted:
        candidates = [w] + _ALIASES.get(w.lower(), [])
        for c in candidates:
            hit = by_norm.get(normalize_site(c))
            if hit and hit not in picked:
                picked.append(hit)
                break
    return picked


# ---------------------------------------------------------------------------
# Maigret (optional, async)
# ---------------------------------------------------------------------------

_MAIGRET_DB = None
_MAIGRET_LOCK = threading.Lock()


def maigret_available() -> bool:
    try:
        import maigret  # noqa: F401
        return True
    except Exception:
        return False


def load_maigret_db():
    """Load maigret's bundled site database once (lazy, thread-safe)."""
    global _MAIGRET_DB
    if _MAIGRET_DB is not None:
        return _MAIGRET_DB
    with _MAIGRET_LOCK:
        if _MAIGRET_DB is not None:
            return _MAIGRET_DB
        import maigret as pkg
        from maigret.sites import MaigretDatabase

        _MAIGRET_DB = MaigretDatabase().load_from_path(
            pkg.__path__[0] + "/resources/data.json"
        )
        logger.info("maigret DB loaded: %d sites", len(_MAIGRET_DB.sites))
        return _MAIGRET_DB


def maigret_site_names() -> list[str]:
    return [s.name for s in load_maigret_db().sites]


def maigret_url_templates(site: Any) -> list[str]:
    """Every URL a Maigret site check may fetch, with ``{urlMain}`` /
    ``{urlSubpath}`` resolved (Maigret 0.6.4 ``checking.py`` formats ``url``
    and ``url_probe`` with exactly those two plus ``{username}``).

    ``url`` is the profile page, ``url_probe`` the URL actually requested when
    present (HackerNews probes the denied Firebase API behind a permitted
    profile URL), ``url_main`` the platform itself. Any of them on a denied
    host denies the site.
    """
    url_main = getattr(site, "url_main", "") or ""
    subpath = getattr(site, "url_subpath", "") or ""
    out: list[str] = []
    for attr in ("url", "url_probe", "url_main"):
        t = getattr(site, attr, None)
        if isinstance(t, str) and t:
            out.append(policy.fill_template(t, url_main=url_main,
                                            url_subpath=subpath))
    return out


def maigret_variant_sites(policy_filtered: bool = True) -> dict[str, Any]:
    """The curated high-value subset of the maigret DB, for variant scans.

    Policy-filtered by default (defence in depth for callers outside the
    pipeline). ``policy_filtered=False`` returns the raw subset for
    :func:`recon.plan.plan_site_sets`, which filters *and reports* the denied
    sites itself — it is the only caller that should pass it.
    """
    db = load_maigret_db()
    wanted = set(_match_names(maigret_site_names(), HIGH_VALUE_SITES))
    picked = {s.name: s for s in db.sites if s.name in wanted}
    if not policy_filtered:
        return picked
    kept, _denied = policy.filter_site_mapping(picked, maigret_url_templates)
    return kept


# Default cap on the base username scan (top N by rank). A "thorough" run
# passes limit=None to scan maigret's entire database (~3200 sites).
DEFAULT_MAIGRET_LIMIT = 1200


def maigret_all_sites(limit: Optional[int] = DEFAULT_MAIGRET_LIMIT
                      ) -> dict[str, Any]:
    """Top ``limit`` sites by rank, or the whole database when ``limit`` is None."""
    db = load_maigret_db()
    top = len(db.sites) if limit is None else limit
    try:
        return db.ranked_sites_dict(top=top)
    except Exception:
        return {s.name: s for s in db.sites[:top]}


class _MaigretNotify:
    """Bridges maigret's query_notify protocol to plain callbacks."""

    def __init__(self, on_result: Callable[[Any], None]):
        self._on_result = on_result

    def start(self, username: str, id_type: str) -> None:  # noqa: ARG002
        pass

    def update(self, result, is_similar: bool = False) -> None:  # noqa: ARG002
        try:
            self._on_result(result)
        except Exception:
            logger.exception("maigret notify callback failed")

    def finish(self) -> None:
        pass


async def maigret_scan(username: str, site_dict: dict[str, Any], timeout: int,
                       on_result: Callable[[Any], None],
                       proxy: Optional[str] = None) -> dict:
    """Run one maigret scan. Returns the raw results dict."""
    from maigret.maigret import maigret as maigret_search

    return await maigret_search(
        username,
        site_dict,
        logging.getLogger("maigret"),
        query_notify=_MaigretNotify(on_result),
        timeout=timeout,
        no_progressbar=True,
        proxy=proxy,
    )


# ---------------------------------------------------------------------------
# Sherlock helpers (site subsetting; the scan itself lives in app.py threads)
# ---------------------------------------------------------------------------

def sherlock_url_templates(info: dict) -> list[str]:
    """Every URL a Sherlock site check may fetch: ``url`` (the ``{}`` template
    Sherlock formats with the handle), ``urlProbe`` when the check hits a
    different endpoint, and ``urlMain`` (the platform itself)."""
    return [info[k] for k in ("url", "urlProbe", "urlMain")
            if isinstance(info.get(k), str) and info[k]]


def sherlock_variant_site_data(site_data_all: dict[str, dict],
                               policy_filtered: bool = True) -> dict[str, dict]:
    """The curated high-value subset of Sherlock's site data.

    Policy-filtered by default (defence in depth: app.py's classic stream and
    the watchlist monitor call this directly). ``policy_filtered=False`` is
    for :func:`recon.plan.plan_site_sets`, which filters and reports itself.
    """
    picked = _match_names(list(site_data_all), HIGH_VALUE_SITES)
    subset = {n: site_data_all[n] for n in picked}
    if not policy_filtered:
        return subset
    kept, _denied = policy.filter_site_mapping(subset, sherlock_url_templates)
    return kept
