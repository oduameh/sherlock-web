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
# A bare "this handle exists" hit is weak on its own: the belief that it's the
# *subject's* account has to be earned by verification and identity signals, not
# assumed. So the base is low and verification is the dominant lever.
_BASE = 30
_TWO_ENGINE_BONUS = 15       # engine agreement raises *existence* certainty
_IDENTITY_BONUS = 15         # a real page with a name/avatar was parsed
_VERIFY_BONUS = {
    "confirmed": 45,             # page is genuinely about this handle/subject
    "unconfirmed": -8,           # page fetched, nothing tied it to the subject
    "likely_false_positive": -60,  # 404/410, soft-404, or site serves all handles
    "indeterminate": -10,        # blocked (403/429/5xx) — existence unknown
    "not_examined": -12,         # never fetched (budget//skip) — not evidence
    None: -12,                   # no verdict recorded → treat as not examined
}
_ATTRIBUTION_BONUS = 20      # profile's name matched the subject (verify.py)
_SOURCE_PENALTY = {
    "name": -12,                 # name-derived candidate, speculative
    "variant": -6,               # handle variant, weaker than the base handle
}


def _has_identity(row: dict) -> bool:
    # Only a real name or avatar counts — a bare <title> (which every page,
    # including error pages, has) is not identity evidence.
    enr = row.get("enrichment") or {}
    return bool(enr.get("jsonld_name") or enr.get("jsonld_image")
                or enr.get("og_image"))


def account_confidence(row: dict) -> int:
    """0-100 confidence that ``row`` is really the subject's account."""
    score = _BASE
    if len(row.get("engines") or []) >= 2:
        score += _TWO_ENGINE_BONUS
    if _has_identity(row):
        score += _IDENTITY_BONUS
    verification = row.get("verification") or {}
    score += _VERIFY_BONUS.get(verification.get("status"), 0)
    if verification.get("identity_match") is True:
        score += _ATTRIBUTION_BONUS
    score += _SOURCE_PENALTY.get(row.get("source"), 0)
    return max(5, min(100, score))


def verdict_bucket(row: dict) -> str:
    """Coarse honesty bucket for headline counts (single source of truth):

    * ``"found"``         verification confirmed it's the subject's account.
    * ``"flagged"``       likely false positive (404/soft-404/serves-everyone).
    * ``"indeterminate"`` we were blocked and genuinely cannot tell.
    * ``"not_examined"``  never fetched — carries no evidential weight at all.
    * ``"lead"``          fetched, real page, nothing tied it to the subject.

    A raw engine "claimed" is only ever a lead until verification promotes it.
    Critically, "blocked" and "never looked" are kept out of ``lead`` so they can
    never be presented as though someone checked and found something.
    """
    status = (row.get("verification") or {}).get("status")
    if status == "confirmed":
        return "found"
    if status == "likely_false_positive":
        return "flagged"
    if status == "indeterminate":
        return "indeterminate"
    if status == "not_examined" or not status:
        return "not_examined"
    return "lead"


def bucket_counts(rows) -> dict:
    """Counts per :func:`verdict_bucket` over an iterable of rows."""
    counts = {"found": 0, "lead": 0, "flagged": 0,
              "indeterminate": 0, "not_examined": 0}
    for row in rows:
        counts[verdict_bucket(row)] += 1
    return counts
