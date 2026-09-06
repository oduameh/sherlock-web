"""The single accessor for account-row fields.

Tech-debt D7 (V10): the precedence ``jsonld_name or og_title [or title]`` was
copied eleven times with two different semantics. Three renderers (graph,
report, dossier) *included* the raw page ``<title>``, so a node or a dossier
row could name the subject "carmen_pop - Streamer Overview & Stats ·
TwitchTracker" — a site's boilerplate presented as a person's name, exactly
the false attribution the correlation rules (``recon/correlate.py`` rule 1)
forbid. The other consumers excluded it. Now every consumer asks here, and
:func:`display_name` never reads ``title``.

Every function is pure, total (a missing key or a ``None`` row yields
``None`` / ``[]``) and reads, in order of authority:

1. ``platform_identity`` — structured fields an adapter or detector took from
   the platform's own API/markup (canonical handle, real name, avatar, bio);
2. ``enrichment`` JSON-LD (``jsonld_*``) — the page's own structured data;
3. ``enrichment`` Open Graph (``og_*``) — what the page tells link previews.

The raw ``<title>`` and free text are never a name.
"""

from __future__ import annotations

from typing import Any, Optional

__all__ = ["ROW_LISTS", "all_account_rows", "avatar", "bio", "created_at",
           "display_name", "enrichment", "handle", "platform_identity"]

# The three lists an investigation summary keeps account rows in, in the
# order every consumer used to concatenate them by hand.
ROW_LISTS: tuple[str, ...] = ("accounts", "variants", "name_accounts")


def all_account_rows(summary: Optional[dict]) -> list[dict]:
    """Every account row in a summary: base handles, then username variants,
    then name-derived candidates. Order is stable; missing lists are empty."""
    if not isinstance(summary, dict):
        return []
    out: list[dict] = []
    for key in ROW_LISTS:
        rows = summary.get(key) or []
        out.extend(r for r in rows if isinstance(r, dict))
    return out


def _text(value: Any) -> Optional[str]:
    """A non-empty stripped string, else None."""
    if isinstance(value, str):
        s = value.strip()
        return s or None
    return None


def enrichment(row: Optional[dict]) -> dict:
    """The row's page-extracted fields (``{}`` when none)."""
    enr = row.get("enrichment") if isinstance(row, dict) else None
    return enr if isinstance(enr, dict) else {}


def platform_identity(row: Optional[dict]) -> dict:
    """The row's adapter/detector identity block (``{}`` when none)."""
    ident = row.get("platform_identity") if isinstance(row, dict) else None
    return ident if isinstance(ident, dict) else {}


def display_name(row: Optional[dict]) -> Optional[str]:
    """The person's name as the *platform* states it, or None.

    ``platform_identity.display_name`` → ``jsonld_name`` → ``og_title``.
    Never ``title``: a bare page ``<title>`` is site boilerplate ("… ·
    TwitchTracker"), not a person's name (D7 / V10).
    """
    ident = platform_identity(row)
    enr = enrichment(row)
    return (_text(ident.get("display_name"))
            or _text(enr.get("jsonld_name"))
            or _text(enr.get("og_title")))


def avatar(row: Optional[dict]) -> Optional[str]:
    """Avatar URL: ``platform_identity.avatar`` → ``jsonld_image`` → ``og_image``."""
    ident = platform_identity(row)
    enr = enrichment(row)
    return (_text(ident.get("avatar"))
            or _text(enr.get("jsonld_image"))
            or _text(enr.get("og_image")))


def bio(row: Optional[dict]) -> Optional[str]:
    """Bio / description: ``platform_identity.bio`` → ``jsonld_description``
    → ``og_description``."""
    ident = platform_identity(row)
    enr = enrichment(row)
    return (_text(ident.get("bio"))
            or _text(enr.get("jsonld_description"))
            or _text(enr.get("og_description")))


def handle(row: Optional[dict]) -> Optional[str]:
    """The handle as the platform spells it (``canonical_handle``), else the
    handle we searched for (``username``)."""
    ident = platform_identity(row)
    searched = row.get("username") if isinstance(row, dict) else None
    return _text(ident.get("canonical_handle")) or _text(searched)


def created_at(row: Optional[dict]) -> Optional[str]:
    """Account creation timestamp an adapter reported (``temporal.created_at``),
    or None. The only source of an account's age we have without a fetch —
    :mod:`recon.timeline` reads it before asking any API (D8)."""
    if not isinstance(row, dict):
        return None
    temporal = row.get("temporal")
    if not isinstance(temporal, dict):
        return None
    return _text(temporal.get("created_at"))
