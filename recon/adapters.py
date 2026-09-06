"""Per-site adapters — authoritative public checks for platforms worth doing
properly, instead of the generic "GET /<username> and guess from the status".

The generic probe is weak or actively wrong on big platforms: single-page apps
return 200 for every path (so every hit is a false positive), login walls return
403 (which a status-only rule reads as "absent"), and nothing structured is
extracted. Each adapter here instead uses the platform's own **public,
unauthenticated** surface, which buys three things the generic path cannot:

1. a *definitive* exists / absent / blocked answer, with blocked kept distinct
   from absent so we never claim a person has no account when we were simply
   refused;
2. **structured identity** (canonical handle, immutable id, real name, avatar)
   which feeds subject attribution in :mod:`recon.verify` — far stronger than
   "the handle appeared in the page title";
3. **temporal signal** — account creation and last-activity dates. The tool has
   never had this, and in a time-critical case "last active yesterday" vs
   "dormant since 2019" is often the single most decisive fact.

Retrieval (G2): the call goes through :func:`recon.retrieval.fetch` with
``kind="json"`` — ``absent`` ⇒ ABSENT, ``ok`` + JSON ⇒ ``exists_when``, and
``blocked``/``transport``/``policy``/``ssrf`` ⇒ BLOCKED with retrieval's
reason (a GitHub 403 with ``X-RateLimit-Remaining: 0`` now reads "rate
limited", audit defect 10). Answers are cached per ``(source, handle)`` for
six hours — EXISTS and ABSENT only, never BLOCKED (:mod:`recon.cache`'s rule)
— and the cache is shared by discovery, enrichment's re-check and the
timeline, so GitHub's 60/h budget is spent once per handle per run. Every
call is recorded against the source registry (:func:`recon.sources.record`).

Rules for adding an adapter (all of these are enforced by review, not code):
  * Public and unauthenticated only. No tokens, cookies, or logged-in sessions.
  * No evasion: no browser-impersonating User-Agent, no CAPTCHA/challenge
    bypass, no proxy rotation. If a platform blocks an honest client, the
    correct outcome is ``blocked`` — see :mod:`recon.policy`.
  * The host's robots.txt must permit the path. Hosts that disallow everything
    live in ``recon.policy.DENIED_HOSTS`` and get no adapter.
  * Every rule below was empirically checked against a known-real and a
    known-nonexistent handle (2026-08-14).
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Optional

from recon import retrieval, safeweb, sources
from recon.cache import TTLCache
from recon.engines import normalize_site
from recon.retrieval import FetchResult

logger = logging.getLogger("recon.adapters")

TIMEOUT_S = 12
MAX_BODY_BYTES = 256 * 1024
CACHE_TTL_S = 6 * 3600

EXISTS = "exists"
ABSENT = "absent"
BLOCKED = "blocked"

# Process-wide answer cache: (source name, handle) → the EXISTS/ABSENT result
# dict. A BLOCKED answer is never stored — there is no API for it.
_CACHE = TTLCache(maxsize=2048, ttl_s=CACHE_TTL_S)


def cache_key(source: str, username: str) -> tuple[str, str]:
    """The shared key: the registry source name (``"github"``) and the handle
    lower-cased, so the timeline and the adapters look up the same entry."""
    return (source, (username or "").strip().lower())


def cached_result(source: str, username: str) -> Optional[dict]:
    """The cached EXISTS/ABSENT result for ``(source, handle)``, or None."""
    hit, value = _CACHE.get(cache_key(source, username))
    return dict(value) if hit and isinstance(value, dict) else None


def clear_cache() -> None:
    """Forget every cached adapter answer (tests)."""
    _CACHE.clear()


def cache_stats() -> dict:
    return _CACHE.stats()


def _dig(obj: Any, path: str) -> Any:
    """Fetch a dotted path from nested dicts/lists ('a.b.0.c'). None if absent."""
    cur = obj
    for part in path.split("."):
        if isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
        if cur is None:
            return None
    return cur


class Adapter:
    """A declarative public-API check for one platform.

    ``url`` is a template taking ``{username}``. ``exists_when`` receives the
    decoded JSON and returns True when the account provably exists. ``identity``
    and ``temporal`` map output keys to dotted JSON paths. ``source`` is the
    registry name in :mod:`recon.sources` the check is recorded and cached
    under.
    """

    def __init__(self, name: str, sites: tuple, url: str,
                 exists_when: Callable[[Any], bool],
                 identity: Optional[dict] = None,
                 temporal: Optional[dict] = None,
                 absent_status: tuple = (404,),
                 headers: Optional[dict] = None,
                 profile: str = "",
                 note: str = "",
                 source: Optional[str] = None):
        self.name = name
        self.sites = {normalize_site(s) for s in sites}
        self.url = url
        self.exists_when = exists_when
        self.identity = identity or {}
        self.temporal = temporal or {}
        self.absent_status = absent_status
        self.headers = headers or {}
        # Human profile URL template (for discovery). Falls back to the API URL.
        self.profile = profile
        self.note = note
        self.source = source or normalize_site(name)

    def profile_url(self, username: str) -> str:
        try:
            return (self.profile or self.url).format(username=username)
        except Exception:
            return self.url.format(username=username)

    def handles(self, site: str) -> bool:
        return normalize_site(site or "") in self.sites

    def outcome(self, res: FetchResult) -> dict:
        """Map one :class:`recon.retrieval.FetchResult` to the result fields
        (``status``, ``signal``, and ``identity``/``temporal`` on EXISTS). Pure.

        Order: a status in ``absent_status`` (Bluesky answers 400 for an
        unknown actor) or an ``absent`` outcome ⇒ ABSENT; any outcome other
        than ``ok`` ⇒ BLOCKED with retrieval's reason ("rate limited (HTTP
        403, X-RateLimit-Remaining: 0)", "non-JSON response (HTTP 200)", "no
        response (ConnectTimeout)"); ``ok`` ⇒ ``exists_when`` on the JSON.
        """
        out: dict[str, Any] = {"http_status": res.status}
        if (res.status is not None and res.status in self.absent_status) \
                or res.outcome == retrieval.ABSENT:
            out.update(status=ABSENT,
                       signal=f"{self.name} API returned HTTP {res.status}")
            return out
        if res.outcome != retrieval.OK:
            out.update(status=BLOCKED,
                       signal=f"blocked: {res.reason} — cannot determine")
            return out
        data = res.data
        try:
            exists = bool(self.exists_when(data))
        except Exception:
            exists = False
        if not exists:
            out.update(status=ABSENT,
                       signal=f"{self.name} API returned no matching account")
            return out
        out["status"] = EXISTS
        out["signal"] = f"{self.name} public API confirms this account exists"
        ident = {k: _dig(data, p) for k, p in self.identity.items()}
        temp = {k: _dig(data, p) for k, p in self.temporal.items()}
        out["identity"] = {k: v for k, v in ident.items() if v not in (None, "")}
        out["temporal"] = {k: v for k, v in temp.items() if v not in (None, "")}
        return out

    async def check(self, username: str, *,
                    host_state: Optional[retrieval.HostState] = None,
                    retrieval_stats: Optional[retrieval.RetrievalStats] = None,
                    use_cache: bool = True) -> dict:
        """Run the check. Never raises; returns a result dict.

        Served from the answer cache when this ``(source, handle)`` was
        answered EXISTS/ABSENT within ``CACHE_TTL_S`` (the copy carries
        ``cached: True``); a BLOCKED answer is never cached, so the next
        caller asks again. ``host_state`` / ``retrieval_stats`` are the run's
        shared retrieval state.
        """
        url = self.url.format(username=username)
        out: dict[str, Any] = {"adapter": self.name, "source_url": url}
        key = cache_key(self.source, username)
        if use_cache:
            hit, cached = _CACHE.get(key)
            if hit and isinstance(cached, dict):
                served = dict(cached)
                served["cached"] = True
                return served
        headers = {"User-Agent": sources.USER_AGENT, **self.headers}
        t0 = time.monotonic()
        try:
            async with safeweb.async_client(timeout=TIMEOUT_S) as client:
                res = await retrieval.fetch(
                    url, client=client, kind="json", host_state=host_state,
                    stats=retrieval_stats, headers=headers,
                    max_bytes=MAX_BODY_BYTES)
        except Exception as exc:   # the client itself could not be opened
            res = FetchResult(retrieval.TRANSPORT, f"no response ({type(exc).__name__})",
                              None, None, type(exc).__name__, final_url=url)
        latency_ms = (time.monotonic() - t0) * 1000
        out.update(self.outcome(res))
        ok = out["status"] != BLOCKED
        sources.record(self.source, ok, latency_ms, None if ok else res.reason)
        if ok and use_cache:
            _CACHE.set(key, dict(out))
        return out


# --- the registry ----------------------------------------------------------
# Only platforms whose public endpoint was empirically verified to discriminate
# a real handle from a nonexistent one, and whose robots.txt permits the path.

ADAPTERS: list[Adapter] = [
    Adapter(
        "GitHub", ("GitHub",),
        "https://api.github.com/users/{username}",
        exists_when=lambda d: isinstance(d, dict) and bool(d.get("id")) and bool(d.get("login")),
        identity={"canonical_handle": "login", "account_id": "id",
                  "display_name": "name", "avatar": "avatar_url", "bio": "bio",
                  "location": "location", "company": "company",
                  "blog": "blog", "twitter": "twitter_username",
                  "account_type": "type", "followers": "followers",
                  "public_repos": "public_repos"},
        temporal={"created_at": "created_at", "last_profile_update": "updated_at"},
        headers={"Accept": "application/vnd.github+json"},
        profile="https://github.com/{username}",
        source="github",
        note="Unauthenticated limit is 60 requests/hour per source IP — enrichment only, never a scan-wide sweep.",
    ),
    Adapter(
        "Bluesky", ("Bluesky", "bsky"),
        "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={username}",
        exists_when=lambda d: isinstance(d, dict) and bool(d.get("did")),
        identity={"canonical_handle": "handle", "account_id": "did",
                  "display_name": "displayName", "avatar": "avatar",
                  "bio": "description", "followers": "followersCount",
                  "posts": "postsCount"},
        temporal={"created_at": "createdAt", "indexed_at": "indexedAt"},
        absent_status=(400, 404),
        profile="https://bsky.app/profile/{username}",
        source="bluesky",
        note="Bluesky returns 400 InvalidRequest for an unresolvable actor.",
    ),
    Adapter(
        "DEV Community", ("DEV Community", "dev.to", "devto"),
        "https://dev.to/api/users/by_username?url={username}",
        exists_when=lambda d: isinstance(d, dict) and bool(d.get("id")),
        identity={"canonical_handle": "username", "account_id": "id",
                  "display_name": "name", "avatar": "profile_image",
                  "bio": "summary", "location": "location",
                  "github": "github_username", "website": "website_url"},
        temporal={"created_at": "joined_at"},
        profile="https://dev.to/{username}",
        source="devto",
        note="Documented public Forem API.",
    ),
    Adapter(
        "Docker Hub", ("Docker Hub", "dockerhub"),
        "https://hub.docker.com/v2/users/{username}/",
        exists_when=lambda d: isinstance(d, dict) and bool(d.get("id") or d.get("username")),
        identity={"canonical_handle": "username", "account_id": "id",
                  "display_name": "full_name", "avatar": "gravatar_url",
                  "location": "location", "company": "company"},
        temporal={"created_at": "date_joined"},
        profile="https://hub.docker.com/u/{username}",
        source="dockerhub",
    ),
    Adapter(
        "Keybase", ("Keybase",),
        "https://keybase.io/_/api/1.0/user/lookup.json?usernames={username}",
        # Keybase answers 200 with status.code != 0 when the user is unknown.
        exists_when=lambda d: (_dig(d, "status.code") == 0
                               and bool(_dig(d, "them.0.id"))),
        identity={"canonical_handle": "them.0.basics.username",
                  "account_id": "them.0.id",
                  "display_name": "them.0.profile.full_name",
                  "bio": "them.0.profile.bio",
                  "location": "them.0.profile.location"},
        temporal={"created_at": "them.0.basics.ctime"},
        profile="https://keybase.io/{username}",
        source="keybase",
        note="Proof chain (them.0.proofs_summary) carries self-declared, "
             "cryptographically-signed cross-platform links.",
    ),
    Adapter(
        "Vimeo", ("Vimeo",),
        "https://vimeo.com/api/v2/{username}/info.json",
        exists_when=lambda d: isinstance(d, dict) and bool(d.get("id")),
        identity={"canonical_handle": "profile_url", "account_id": "id",
                  "display_name": "display_name", "avatar": "portrait_huge",
                  "bio": "bio", "location": "location"},
        temporal={"created_at": "created_on"},
        profile="https://vimeo.com/{username}",
        source="vimeo",
        note="Use the API, not the HTML page: vimeo.com/staff returns 410 while "
             "the API proves the account is live.",
    ),
    Adapter(
        "mastodon.social", ("mastodon.social", "Mastodon"),
        "https://mastodon.social/api/v1/accounts/lookup?acct={username}",
        exists_when=lambda d: isinstance(d, dict) and bool(d.get("id")),
        identity={"canonical_handle": "acct", "account_id": "id",
                  "display_name": "display_name", "avatar": "avatar",
                  "bio": "note", "url": "url",
                  "followers": "followers_count", "posts": "statuses_count"},
        temporal={"created_at": "created_at", "last_active": "last_status_at"},
        profile="https://mastodon.social/@{username}",
        source="mastodon_social",
        note="Public account lookup on the flagship instance; robots.txt permits "
             "/api/v1/accounts/lookup (only /media_proxy/ and /interact/ are "
             "disallowed). Verified real vs fake 2026-08-24. Other instances "
             "are separate hosts and are NOT covered by this adapter.",
    ),
]
# Deliberately NOT registered until each is verified end-to-end the same way:
# Tumblr (public read API returns JSONP, not JSON — needs an unwrap step),
# Steam (XML), Roblox (POST), Medium/Substack/Blogger (RSS/Atom, not JSON).
# Hacker News' Firebase API is excluded permanently: it serves Disallow: /.


def adapter_for(site: str) -> Optional[Adapter]:
    """The adapter that owns this site name, if any."""
    for a in ADAPTERS:
        if a.handles(site):
            return a
    return None


def covered_sites() -> list[str]:
    return sorted({s for a in ADAPTERS for s in a.sites})


async def check_account(site: str, username: str, *,
                        host_state: Optional[retrieval.HostState] = None,
                        retrieval_stats: Optional[retrieval.RetrievalStats] = None
                        ) -> Optional[dict]:
    """Run the adapter for ``site`` if one exists. None when unsupported."""
    a = adapter_for(site)
    if a is None or not username:
        return None
    return await a.check(username, host_state=host_state,
                         retrieval_stats=retrieval_stats)


async def discover(username: str, stats: Optional[dict] = None, *,
                   host_state: Optional[retrieval.HostState] = None,
                   retrieval_stats: Optional[retrieval.RetrievalStats] = None
                   ) -> list[dict]:
    """DISCOVERY: query every adapter's public API for ``username`` directly,
    independent of the third-party engines. Each hit is a definitive API answer
    — far higher signal than a page guess — carrying identity + dates. Returns a
    list of ``{site, url, identity, temporal, source_url}`` for EXISTS results
    only. Never raises; failures and absences are simply omitted.

    ``stats``, when given, receives every adapter's outcome —
    ``{name: {kind, status, signal, http_status}}`` — including the ABSENT and
    BLOCKED answers the return value omits, so the caller can observe them. A
    blocked adapter used to be invisible to the circuit breaker and the Health
    tab (audit ops-observability gap 8). The return shape is unchanged.

    This is bounded to a real handle (never fan it across name candidates): it
    is at most ``len(ADAPTERS)`` public-API calls, one per platform — fewer
    when the answer cache already holds them.
    """
    import asyncio

    if not username:
        return []

    async def _one(a: Adapter) -> Optional[dict]:
        try:
            res = await a.check(username, host_state=host_state,
                                retrieval_stats=retrieval_stats)
        except Exception as exc:
            if stats is not None:
                stats[a.name] = {
                    "kind": "adapter", "status": BLOCKED,
                    "signal": f"discover failed ({type(exc).__name__})",
                    "http_status": None,
                }
            return None
        if stats is not None:
            stats[a.name] = {
                "kind": "adapter", "status": res.get("status"),
                "signal": res.get("signal"),
                "http_status": res.get("http_status"),
            }
        if res.get("status") != EXISTS:
            return None
        return {
            "site": a.name,
            "url": a.profile_url(username),
            "identity": res.get("identity") or {},
            "temporal": res.get("temporal") or {},
            "source_url": res.get("source_url"),
        }

    results = await asyncio.gather(*(_one(a) for a in ADAPTERS),
                                   return_exceptions=True)
    return [r for r in results if isinstance(r, dict)]


# --- mapping adapter results onto verification verdicts --------------------

def to_verification(result: dict, subject_name: Optional[str] = None) -> dict:
    """Translate an adapter result into a :mod:`recon.verify`-shaped verdict.

    An adapter answer is authoritative in a way a page heuristic never is, so
    ``exists`` confirms outright. If the platform also exposes a real name and
    it matches the subject, that is recorded as identity attribution.
    """
    status = result.get("status")
    src = result.get("adapter") or "adapter"
    if status == ABSENT:
        return {"status": "likely_false_positive", "score": 6,
                "signals": [result.get("signal") or f"{src}: account not found"],
                "source": "adapter"}
    if status == BLOCKED:
        return {"status": "indeterminate", "score": 30,
                "signals": [result.get("signal") or f"{src}: blocked"],
                "source": "adapter"}
    if status != EXISTS:
        return {"status": "not_examined", "score": 0,
                "signals": [f"{src}: no result"], "source": "adapter"}

    signals = [result.get("signal") or f"{src}: account exists"]
    verdict: dict[str, Any] = {"status": "confirmed", "score": 88,
                               "signals": signals, "source": "adapter"}
    ident = result.get("identity") or {}
    display = ident.get("display_name")
    if subject_name and display:
        from recon.verify import _identity_matches
        match = _identity_matches(subject_name, {"jsonld_name": str(display)})
        if match is True:
            verdict["identity_match"] = True
            verdict["score"] = 95
            signals.append("platform-reported name matches the subject")
        elif match is False:
            verdict["identity_match"] = False
            signals.append("platform-reported name differs from the subject")
    return verdict
