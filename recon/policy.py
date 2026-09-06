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

import re
from typing import Any, Callable, Iterable
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


# ---------------------------------------------------------------------------
# Engine site templates
#
# The promise above ("denied hosts are never fetched") used to hold only for
# our own fetchers: Sherlock, Maigret and WhatsMyName were handed their full
# site lists and scanned Instagram/Reddit/X/Flickr/Threads on every run
# (audit 2026-09-06, retrieval-reliability §6 defect 8; security F-2). These
# helpers let the plan filter an engine's site *templates* — URLs with a
# username placeholder — before any engine runs.
# ---------------------------------------------------------------------------

# A neutral handle substituted for the placeholder so the template parses as a
# URL. Only the host matters here; the handle never leaves this module.
_PROBE_HANDLE = "probe"
# Sherlock uses ``{}``, Maigret ``{username}`` (plus ``{urlMain}``/``{urlSubpath}``,
# resolved by the caller or here), WhatsMyName ``{account}``. Any other
# ``{...}`` is treated as a handle position too, so an unknown placeholder can
# never hide the request host from the check.
_PLACEHOLDER_RE = re.compile(r"\{[^{}]*\}")


def fill_template(url_template: str, *, url_main: str = "",
                  url_subpath: str = "") -> str:
    """Resolve an engine URL template into a concrete probe URL.

    Substitutes ``{urlMain}``/``{urlSubpath}`` with the given values and every
    remaining placeholder (``{}``, ``{username}``, ``{account}``, …) with a
    neutral handle. A scheme-less template (a few Maigret entries) is given
    ``https://`` so its host can still be read. Pure.
    """
    t = (url_template or "").replace("{urlMain}", url_main or "")
    t = t.replace("{urlSubpath}", url_subpath or "")
    t = _PLACEHOLDER_RE.sub(_PROBE_HANDLE, t).strip()
    if t and "://" not in t:
        t = "https://" + t.lstrip("/")
    return t


def denied_template_reason(url_template: str, *, url_main: str = "",
                           url_subpath: str = "") -> str | None:
    """Reason an engine site template must not be scanned, or None."""
    filled = fill_template(url_template, url_main=url_main,
                           url_subpath=url_subpath)
    return denied_reason(filled) if filled else None


def is_denied_template(url_template: str, *, url_main: str = "",
                       url_subpath: str = "") -> bool:
    """True when the template's request host is robots-denied.

    Understands the engines' placeholders (``{}``, ``{username}``,
    ``{account}``) by substituting a probe handle before reading the host.
    """
    return denied_template_reason(url_template, url_main=url_main,
                                  url_subpath=url_subpath) is not None


def filter_site_mapping(mapping: dict, url_of: Callable[[Any], Any]
                        ) -> tuple[dict, list[str]]:
    """Split a dict of engine sites into ``(kept, denied_names)``.

    ``url_of(value)`` returns the URL template for a site value — or an
    iterable of templates when the engine fetches more than one URL per site
    (Maigret's ``url_probe``, Sherlock's ``urlProbe``). A site is denied when
    *any* of its templates targets a denied host: Maigret's HackerNews entry
    shows a permitted profile URL but probes the denied Firebase API, and the
    probe is what gets fetched. Order is preserved. Pure.
    """
    kept: dict = {}
    denied: list[str] = []
    for name, value in mapping.items():
        if denied_site_reason(url_of(value)) is None:
            kept[name] = value
        else:
            denied.append(name)
    return kept, denied


def denied_site_reason(templates: Any) -> str | None:
    """Reason for the first denied template among ``templates`` (a str or an
    iterable of str), or None when every template is permitted."""
    if isinstance(templates, str):
        templates = (templates,)
    for t in templates or ():
        if not t:
            continue
        reason = denied_template_reason(t)
        if reason:
            return reason
    return None


# ---------------------------------------------------------------------------
# Names and third-party check modules (holehe / ignorant, curated site lists)
#
# holehe and ignorant name every check function after the platform
# (``instagram``, ``twitter``, ``pinterest``, ``flickr``) and keep the domain
# only as a local constant (``domain = "instagram.com"``), so there is no URL
# to hand to :func:`denied_reason`. Both modules were called on every
# email/phone pivot (security F-2). The label table below is *derived* from
# DENIED_HOSTS — never hand-typed — so adding a host denies its module too.
# ---------------------------------------------------------------------------


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


def denied_labels() -> dict[str, str]:
    """``{normalized label: reason}`` for every denied host.

    The label is the one left of the public suffix (``instagram`` for
    ``instagram.com``, ``firebaseio`` for ``hacker-news.firebaseio.com``) —
    the word a module or curated list would use for the platform. Using the
    registrable label rather than the leftmost one keeps Sherlock's
    ``HackerNews`` (news.ycombinator.com, permitted) out of the denied set
    while its Firebase API entries are still caught by their URLs.
    """
    out: dict[str, str] = {}
    for host, reason in DENIED_HOSTS.items():
        parts = host.split(".")
        label = parts[-2] if len(parts) >= 2 else parts[0]
        out.setdefault(_norm(label), reason)
    return out


def denied_name_reason(name: str) -> str | None:
    """Reason a bare platform name (``"Instagram"``, ``"twitter"``) denotes a
    denied host, or None. Case- and punctuation-insensitive."""
    return denied_labels().get(_norm(name))


_HOSTNAME_RE = re.compile(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+")


def _string_constants(code) -> list[str]:
    """Every str constant reachable from a code object (nested code included)."""
    out: list[str] = []
    for c in getattr(code, "co_consts", ()) or ():
        if isinstance(c, str):
            out.append(c)
        elif hasattr(c, "co_consts"):
            out.extend(_string_constants(c))
    return out


def denied_module_reason(name: str, constants: Iterable[str] = ()
                         ) -> str | None:
    """Reason a third-party check module targets a denied host, or None.

    Denied when its ``name`` is a denied host's label (holehe's ``instagram``
    ↔ ``instagram.com``) or when any of its string ``constants`` is a URL or
    bare hostname on a denied host (the module's ``domain = "…"`` and the
    endpoints it posts to). Pure.
    """
    reason = denied_name_reason(name)
    if reason:
        return reason
    for s in constants:
        if not isinstance(s, str) or len(s) > 2048:
            continue
        if "://" in s:
            reason = denied_reason(s)
        elif _HOSTNAME_RE.fullmatch(s.strip().lower()):
            reason = denied_reason("https://" + s.strip())
        else:
            continue
        if reason:
            return reason
    return None


def function_denied_reason(fn: Any) -> str | None:
    """:func:`denied_module_reason` for a holehe/ignorant check function,
    reading its ``__name__`` and the string constants of its code."""
    name = getattr(fn, "__name__", "") or ""
    consts = _string_constants(getattr(fn, "__code__", None))
    return denied_module_reason(name, consts)


def partition_check_functions(functions: Iterable[Any]
                              ) -> tuple[list, list[str]]:
    """Split check functions into ``(kept, skipped_names)`` by access policy.

    Skipped modules were *not checked*: callers must emit nothing for them
    (a missing row is not "no account") and may log the names at DEBUG.
    """
    kept: list = []
    skipped: list[str] = []
    for fn in functions:
        if function_denied_reason(fn):
            skipped.append(getattr(fn, "__name__", repr(fn)))
        else:
            kept.append(fn)
    return kept, skipped
