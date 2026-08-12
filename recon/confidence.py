"""Single source of truth for confidence scoring.

Before this module, account confidence lived in ``graph.py`` while the
correlation weights lived in ``correlate.py`` and the dossier scored things a
third way — so the graph, dossier, and report could disagree. Both scores now
come from here:

* :func:`account_confidence` — 0-100 belief that a discovered account belongs
  to the subject, from engine agreement, enrichment, page verification, and how
  the handle was derived.
* the correlation link weights (avatar / name / bio) used by
  :mod:`recon.correlate`.
"""

from __future__ import annotations

# --- correlation signal weights (used by recon.correlate) ------------------
AVATAR_WEIGHT = 50            # same avatar (perceptual hash) — strongest signal
NAME_WEIGHT = 30             # similar display name
BIO_WEIGHT = 20             # overlapping bio vocabulary
CORRELATION_LINK_MIN = 40    # below this a pairwise link is too weak to report

# --- account confidence components -----------------------------------------
_BASE = 45
_TWO_ENGINE_BONUS = 25       # two independent engines both claim the account
_IDENTITY_BONUS = 15         # a real page with a name/avatar was parsed
_VERIFY_BONUS = {
    "confirmed": 20,             # scanned username corroborated on the page
    "unconfirmed": -5,           # page fetched but username not seen
    "likely_false_positive": -40,  # page looks like a soft-404
}
_SOURCE_PENALTY = {
    "name": -15,                 # name-derived candidate, speculative
    "variant": -8,               # handle variant, weaker than the base handle
}


def _has_identity(row: dict) -> bool:
    enr = row.get("enrichment") or {}
    return bool(
        enr.get("jsonld_name") or enr.get("og_title") or enr.get("title")
        or enr.get("jsonld_image") or enr.get("og_image")
    )


def account_confidence(row: dict) -> int:
    """0-100 confidence that ``row`` is really the subject's account."""
    score = _BASE
    if len(row.get("engines") or []) >= 2:
        score += _TWO_ENGINE_BONUS
    if _has_identity(row):
        score += _IDENTITY_BONUS
    status = (row.get("verification") or {}).get("status")
    score += _VERIFY_BONUS.get(status, 0)
    score += _SOURCE_PENALTY.get(row.get("source"), 0)
    return max(5, min(100, score))
