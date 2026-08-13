"""Exposure analytics: turn an investigation summary into an analyst-grade
digital-footprint breakdown.

This is the single source of truth for the digital-footprint score (previously
inline in :mod:`recon.dossier`, which now imports :func:`footprint_score` from
here so the dossier, the ``/api/investigate/{id}/exposure`` endpoint, and any
future consumer agree).

Everything here is a pure function over the stored summary dict — no network,
no DB — so it is cheap to call and easy to test.
"""

from __future__ import annotations

from typing import Any

from recon.confidence import account_confidence, bucket_counts, verdict_bucket
from recon.engines import normalize_site


# ---------------------------------------------------------------------------
# Platform categorisation (curated, heuristic). Keyed by normalized site name.
# ---------------------------------------------------------------------------

_CATEGORY_SITES: dict[str, list[str]] = {
    "development": [
        "GitHub", "GitLab", "Bitbucket", "Codepen", "npm", "PyPi", "Kaggle",
        "Docker Hub", "Replit", "HackerNews", "DEV Community", "Keybase",
        "Stack Overflow", "LeetCode", "Codewars", "Exercism",
    ],
    "social": [
        "Twitter", "X", "Instagram", "Facebook", "TikTok", "Snapchat",
        "Bluesky", "mastodon.social", "Threads", "VK", "Reddit", "tumblr",
        "Linktree", "About.me", "Gravatar", "Telegram",
    ],
    "professional": [
        "LinkedIn", "AngelList", "ProductHunt", "Xing", "Strava",
    ],
    "creative": [
        "Behance", "Dribbble", "Flickr", "Deviantart", "ArtStation",
        "Pinterest", "500px",
    ],
    "media": [
        "YouTube", "Twitch", "Spotify", "SoundCloud", "Vimeo", "Patreon",
        "Bandcamp", "Mixcloud",
    ],
    "writing": [
        "Medium", "WordPress", "Substack", "Blogger", "Ghost",
    ],
    "gaming": [
        "Steam", "Itch.io", "Xbox Gamertag", "Chess.com", "Lichess",
        "Roblox", "osu!",
    ],
    "commerce": [
        "Etsy", "eBay", "Gumroad", "Ko-fi",
    ],
}

# Normalized-name -> category, precomputed once.
_SITE_CATEGORY: dict[str, str] = {
    normalize_site(site): category
    for category, sites in _CATEGORY_SITES.items()
    for site in sites
}


def categorize_site(site: str) -> str:
    """Best-effort platform category for a site name (``"other"`` default)."""
    return _SITE_CATEGORY.get(normalize_site(site or ""), "other")


# ---------------------------------------------------------------------------
# Footprint score (canonical home; re-exported by recon.dossier).
# ---------------------------------------------------------------------------

def footprint_score(summary: dict) -> dict:
    """Digital-footprint score 0-100, weighted by verification so speculation
    can't inflate it. Documented heuristic:

      confirmed accounts    6 pts each, capped at 42  (verification-confirmed)
      unconfirmed leads     1 pt each,  capped at 8   (fetched, not confirmed)
      email registrations   5 pts each, capped at 25  (holehe positives)
      gravatar profile      10 pts flat
      valid phone number    10 pts flat
      phone registrations   5 pts each, capped at 15  (ignorant positives)

    Likely-false-positive rows contribute nothing.
    """
    accounts = summary.get("accounts") or []
    variants = summary.get("variants") or []
    name_rows = summary.get("name_accounts") or []
    email = summary.get("email") or {}
    phone = summary.get("phone") or {}

    b = bucket_counts(accounts + variants + name_rows)
    confirmed, leads = b["found"], b["lead"]
    holehe_hits = sum(1 for h in (email.get("holehe") or []) if h.get("exists"))
    phone_regs = sum(1 for a in (phone.get("accounts") or []) if a.get("exists"))
    parts = {
        f"confirmed accounts ({confirmed} × 6, cap 42)": min(42, confirmed * 6),
        f"unconfirmed leads ({leads} × 1, cap 8)": min(8, leads),
        f"email registrations ({holehe_hits} × 5, cap 25)": min(25, holehe_hits * 5),
        "gravatar profile present": 10 if email.get("gravatar") else 0,
        "valid phone number": 10 if phone.get("valid") else 0,
        f"phone registrations ({phone_regs} × 5, cap 15)": min(15, phone_regs * 5),
    }
    return {"score": min(100, sum(parts.values())), "parts": parts}


# ---------------------------------------------------------------------------
# Exposure summary
# ---------------------------------------------------------------------------

def _score_band(score: int) -> str:
    if score < 20:
        return "minimal"
    if score < 45:
        return "moderate"
    if score < 70:
        return "significant"
    return "extensive"


def _display_name(row: dict) -> str | None:
    # A bare page <title> is site boilerplate, not a person's name — including
    # it is how an unrelated page's title became "the subject's real name".
    enr = row.get("enrichment") or {}
    return enr.get("jsonld_name") or enr.get("og_title")


def _has_avatar(row: dict) -> bool:
    enr = row.get("enrichment") or {}
    return bool(enr.get("jsonld_image") or enr.get("og_image"))


def exposure_summary(summary: dict) -> dict[str, Any]:
    """Structured exposure/footprint breakdown for an investigation summary.

    Pure function; safe to call on a summary that is missing or empty (returns
    a zeroed, well-formed structure). Fields:

    ``score`` / ``score_parts`` / ``band``
        the footprint score, its components, and a qualitative band.
    ``counts``
        headline tallies (accounts, platforms, verified, registrations, …).
    ``categories``
        account count per platform category, worst-first.
    ``identity_signals``
        booleans + display names that reveal a real-world identity.
    ``top_accounts``
        the highest-confidence accounts, capped at 8.
    ``factors``
        human-readable exposure statements for the report.
    """
    summary = summary or {}
    accounts = summary.get("accounts") or []
    variants = summary.get("variants") or []
    name_rows = summary.get("name_accounts") or []
    all_rows = accounts + variants + name_rows
    email = summary.get("email") or {}
    phone = summary.get("phone") or {}
    domain = summary.get("domain") or {}
    clusters = summary.get("correlation") or []

    score = footprint_score(summary)
    band = _score_band(score["score"])

    platforms = {r.get("site") for r in all_rows if r.get("site")}
    verified = sum(
        1 for r in all_rows
        if (r.get("verification") or {}).get("status") == "confirmed"
    )
    flagged = sum(
        1 for r in all_rows
        if (r.get("verification") or {}).get("status") == "likely_false_positive"
    )
    holehe_hits = sum(1 for h in (email.get("holehe") or []) if h.get("exists"))
    phone_regs = sum(1 for a in (phone.get("accounts") or []) if a.get("exists"))
    high_conf_links = sum(1 for c in clusters if (c.get("confidence") or 0) >= 60)

    # Category breakdown (worst-first by count, then name for stability).
    cat_counts: dict[str, int] = {}
    for r in all_rows:
        cat = categorize_site(r.get("site") or "")
        cat_counts[cat] = cat_counts.get(cat, 0) + 1
    categories = dict(
        sorted(cat_counts.items(), key=lambda kv: (-kv[1], kv[0]))
    )

    # Identity signals. Names are collected ONLY from verification-confirmed
    # rows: attributing a rejected row's display name to the subject is how an
    # innocent third party ends up named in a report.
    confirmed_rows = [r for r in all_rows if verdict_bucket(r) == "found"]
    display_names = []
    seen_names: set[str] = set()
    for r in confirmed_rows:
        name = _display_name(r)
        if name and name.lower() not in seen_names:
            seen_names.add(name.lower())
            display_names.append(name)
    identity_signals = {
        "has_real_name": bool(display_names),
        "has_avatar": any(_has_avatar(r) for r in confirmed_rows),
        "gravatar": bool(email.get("gravatar")),
        "phone_valid": bool(phone.get("valid")),
        "has_domain": bool(domain.get("domain") and not domain.get("error")),
        "display_names": display_names[:5],
    }

    # Top accounts by confidence.
    ranked = sorted(
        all_rows,
        key=lambda r: (account_confidence(r), len(r.get("engines") or [])),
        reverse=True,
    )
    top_accounts = [
        {
            "site": r.get("site"),
            "username": r.get("username"),
            "url": r.get("url"),
            "confidence": account_confidence(r),
            "category": categorize_site(r.get("site") or ""),
            "verification": (r.get("verification") or {}).get("status"),
        }
        for r in ranked[:8]
    ]

    counts = {
        "accounts": len(all_rows),
        "base_accounts": len(accounts),
        "variant_accounts": len(variants),
        "name_accounts": len(name_rows),
        "platforms": len(platforms),
        "categories": len(categories),
        "verified": verified,
        "flagged": flagged,
        "email_registrations": holehe_hits,
        "phone_registrations": phone_regs,
        "correlation_clusters": len(clusters),
        "high_confidence_links": high_conf_links,
    }

    factors = _factors(counts, identity_signals, phone, domain, band)

    return {
        "score": score["score"],
        "score_parts": score["parts"],
        "band": band,
        "counts": counts,
        "categories": categories,
        "identity_signals": identity_signals,
        "top_accounts": top_accounts,
        "factors": factors,
    }


def _factors(counts: dict, identity: dict, phone: dict, domain: dict,
             band: str) -> list[str]:
    """Human-readable exposure statements, most notable first."""
    out: list[str] = []
    if counts["accounts"]:
        out.append(
            f"{counts['accounts']} account(s) across {counts['platforms']} "
            f"platform(s) in {counts['categories']} category(ies)"
        )
    if counts["verified"]:
        out.append(f"{counts['verified']} account(s) page-verified")
    if counts["email_registrations"]:
        out.append(
            f"email registered on {counts['email_registrations']} checked "
            f"service(s)"
        )
    if identity["gravatar"]:
        out.append("public Gravatar profile present")
    if identity["has_real_name"]:
        out.append(
            "real-world name exposed: "
            + ", ".join(identity["display_names"][:3])
        )
    if identity["phone_valid"]:
        loc = phone.get("country") or phone.get("region")
        out.append("valid phone number" + (f" ({loc})" if loc else ""))
    if counts.get("phone_registrations"):
        out.append(
            f"phone registered on {counts['phone_registrations']} checked "
            f"platform(s)"
        )
    if identity["has_domain"]:
        out.append(f"owns/associated domain {domain.get('domain')}")
    if counts["high_confidence_links"]:
        out.append(
            f"{counts['high_confidence_links']} high-confidence cross-account "
            f"link(s)"
        )
    if not out:
        out.append("no public exposure detected from the supplied inputs")
    out.append(f"overall exposure: {band}")
    return out
