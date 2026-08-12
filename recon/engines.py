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

logger = logging.getLogger("recon.engines")

# ---------------------------------------------------------------------------
# Curated high-value site list used for variant scans.
# Each entry: canonical tag -> aliases to try (normalized matching).
# ---------------------------------------------------------------------------

HIGH_VALUE_SITES = [
    "GitHub", "Twitter", "Instagram", "TikTok", "YouTube", "Reddit",
    "mastodon.social", "Bluesky", "Medium", "DEV Community", "Keybase",
    "GitLab", "Twitch", "Steam", "Spotify", "Pinterest", "LinkedIn",
    "Facebook", "Snapchat", "Telegram", "tumblr", "Flickr", "Behance",
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


def maigret_variant_sites() -> dict[str, Any]:
    """The curated high-value subset of the maigret DB, for variant scans."""
    db = load_maigret_db()
    wanted = set(_match_names(maigret_site_names(), HIGH_VALUE_SITES))
    return {s.name: s for s in db.sites if s.name in wanted}


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

def sherlock_variant_site_data(site_data_all: dict[str, dict]) -> dict[str, dict]:
    """The curated high-value subset of Sherlock's site data."""
    picked = _match_names(list(site_data_all), HIGH_VALUE_SITES)
    return {n: site_data_all[n] for n in picked}
