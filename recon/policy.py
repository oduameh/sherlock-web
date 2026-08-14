"""Access policy — hosts we must not automatically request.

Some large platforms serve ``User-agent: * / Disallow: /``. Checking a handle
there is not just a compliance problem; it is an *accuracy* problem, because the
only responses we can get are login walls and challenge pages. Two failure modes
follow, and both have been observed in this tool:

* the site returns 200 for a real handle **and** for a nonexistent one
  (Facebook and Instagram ship exactly that rule pair in the vendored
  WhatsMyName data), so every check is a false positive; or
* the site returns 403/404 to us and the tool reports "does not exist" about a
  person who does exist — a confidently wrong statement about a named human.

So denied hosts are never fetched, and the row is marked ``not_examined`` with
the reason. That is an honest answer: *we did not look*. It must never be
rendered as "no account found", and it carries no evidential weight.

Each entry records the robots.txt observation that justifies it, so the list is
auditable and can be re-checked. Verified 2026-08-14 against the live
robots.txt of each host.
"""

from __future__ import annotations

from urllib.parse import urlparse

# host suffix -> human-readable reason (shown to the analyst and stored in the
# verification verdict, so a report can explain the gap).
DENIED_HOSTS: dict[str, str] = {
    "reddit.com": "reddit.com robots.txt disallows all automated access (User-agent: * / Disallow: /)",
    "redd.it": "reddit.com robots.txt disallows all automated access",
    "x.com": "x.com robots.txt disallows all automated access (Disallow: /)",
    "twitter.com": "twitter.com robots.txt disallows all automated access",
    "twimg.com": "X/Twitter infrastructure — robots.txt disallows automated access",
    "facebook.com": "facebook.com robots.txt disallows automated collection without written permission",
    "instagram.com": "instagram.com robots.txt disallows all automated access (Disallow: /)",
    "threads.com": "threads.com robots.txt disallows all automated access",
    "threads.net": "threads.net robots.txt disallows all automated access",
    "pinterest.com": "pinterest.com robots.txt allowlists named crawlers then Disallow: / for everyone else",
    "flickr.com": "flickr.com robots.txt allowlists named crawlers then Disallow: / for everyone else",
    "hacker-news.firebaseio.com": "the Hacker News Firebase API serves Disallow: /",
}

# Hosts a *parameter* may legitimately mention without the request going there.
# e.g. the Wayback availability API is queried ON archive.org ABOUT an
# instagram.com URL — that request is to archive.org and is allowed.
_ALLOWED_QUERY_HOSTS = ("archive.org", "web.archive.org")


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def denied_reason(url: str) -> str | None:
    """Reason this URL must not be fetched, or None if it is allowed.

    Matches on the *request* host only — never on a host that merely appears
    inside a query parameter.
    """
    host = _host(url)
    if not host:
        return None
    if any(host == a or host.endswith("." + a) for a in _ALLOWED_QUERY_HOSTS):
        return None
    for denied, reason in DENIED_HOSTS.items():
        if host == denied or host.endswith("." + denied):
            return reason
    return None


def is_denied(url: str) -> bool:
    return denied_reason(url) is not None


def not_examined_verdict(reason: str) -> dict:
    """The verdict a denied row carries. Deliberately not a finding either way."""
    return {
        "status": "not_examined",
        "score": 0,
        "signals": [f"not checked — {reason}"],
        "reason": "access_policy",
    }
