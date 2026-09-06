"""The registry of sources *we* call directly, with their runtime health.

Retrieval audit §5 ("Source registry: PARTIAL — four separate registries with
different schemas"): the adapters, the detectors, the pivots (Nominatim,
ipwho.is, Cavalier, DoH, RDAP, crt.sh, Gravatar) and the timeline each knew
their own host, timeout and rate limit privately, and nothing tracked whether a
source was answering. This module is the one table of static facts and one
in-process health ledger for them. The third-party engines' site lists
(Sherlock, Maigret, WhatsMyName) stay external data — they are filtered by
:mod:`recon.policy` at plan time and tracked per site by :mod:`recon.router`.

Static facts per :class:`Source`:

``mechanism``   ``api`` (documented JSON API) · ``structured`` (a JSON/XML
                endpoint that is not a documented API) · ``html`` (public page
                read with content markers) · ``browser`` (needs rendering).
``authority``   1–5, the ranking the target architecture makes explicit:
                official API (5) > structured endpoint (4) > public HTML with
                content markers (3) > status-only engine hit (2) > browser
                rendered guess (1).
``rate_limit``  the published or observed limit, as text for the analyst.
``fallback``    the registered source to try when this one is blocked, or
                None (a pivot with one provider degrades to "unavailable with
                a reason", never to "no result").

Runtime health (:func:`record`, :func:`health`, :func:`summary`) keeps the
last 50 observations per source in memory: failure rate, last success time,
EWMA latency and the dominant failure reason. :func:`summary` is shaped for an
additive merge into ``/api/health/sources`` (the router's per-site list stays
as it is; this is a second list keyed by source name).

Pure, in-process, no I/O.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from typing import Callable, Deque, Optional

__all__ = ["MECHANISMS", "SOURCES", "Source", "SourceHealth", "get", "for_host",
           "health", "names", "record", "reset", "summary"]

MECHANISMS: tuple[str, ...] = ("api", "structured", "html", "browser")

# The honest, identifiable agent every direct source call should carry. Never
# a browser impersonation: if a source blocks an honest client the outcome is
# ``blocked``, not a disguise (recon.adapters / recon.policy rules).
USER_AGENT = ("sherlock-web/1.0 (OSINT account verification; "
              "+https://github.com/oduameh/sherlock-web)")

# GitHub's unauthenticated budget is shared by every caller of api.github.com:
# adapter discovery, enrichment and the timeline. One source, one note.
_GITHUB_NOTE = ("Unauthenticated limit 60 requests/hour per source IP, shared by "
                "discovery, enrichment and the timeline (D8): call once per "
                "handle per run and cache the answer. X-RateLimit-Remaining: 0 "
                "on a 403 means rate limited, not forbidden.")


@dataclass(frozen=True)
class Source:
    name: str
    host: str
    mechanism: str
    authority: int
    rate_limit: str
    timeout_s: float
    freshness_ttl_s: int
    fallback: Optional[str] = None
    notes: str = ""

    def __post_init__(self) -> None:
        if self.mechanism not in MECHANISMS:
            raise ValueError(f"{self.name}: unknown mechanism {self.mechanism!r}")
        if not 1 <= int(self.authority) <= 5:
            raise ValueError(f"{self.name}: authority must be 1..5")


_H6 = 6 * 3600
_D1 = 24 * 3600

_ENTRIES: tuple[Source, ...] = (
    # --- adapters: official / documented JSON APIs (authority 5) ---------------
    Source("github", "api.github.com", "api", 5, "60/h unauthenticated (shared)",
           12, _H6, None, _GITHUB_NOTE),
    Source("bluesky", "public.api.bsky.app", "api", 5, "unpublished; generous",
           12, _H6, None, "AT Protocol public appview; 400 InvalidRequest = no such actor."),
    Source("devto", "dev.to", "api", 5, "unpublished", 12, _H6, None,
           "Documented Forem API (/api/users/by_username)."),
    Source("dockerhub", "hub.docker.com", "api", 5, "unpublished", 12, _H6, None,
           "/v2/users/{name}/ — 404 for unknown users."),
    Source("keybase", "keybase.io", "api", 5, "unpublished", 12, _H6, None,
           "user/lookup.json answers 200 with status.code != 0 for unknown users."),
    Source("vimeo", "vimeo.com", "api", 5, "unpublished (v2 simple API)", 12, _H6, None,
           "Use the API, not the HTML page: vimeo.com/staff is 410 while the API is live."),
    Source("mastodon_social", "mastodon.social", "api", 5,
           "300 requests / 5 min per IP (Mastodon default)", 12, _H6, None,
           "Flagship instance only; other instances are separate hosts."),
    # --- detectors: public HTML with content markers (authority 3) --------------
    Source("telegram", "t.me", "html", 3, "unpublished", 12, _H6, None,
           "Public profile page; existence from content markers."),
    Source("steam_community", "steamcommunity.com", "html", 3, "unpublished", 12, _H6,
           None, "Public profile page (/id/{name}); XML endpoint not yet verified."),
    Source("gravatar_html", "gravatar.com", "html", 3, "unpublished", 12, _H6,
           "gravatar_json", "Profile page by username; markers verified 2026-08-24."),
    # --- structured endpoints (authority 4) --------------------------------------
    Source("gravatar_json", "www.gravatar.com", "structured", 4, "unpublished", 10, _H6,
           None, "Profile JSON keyed by the email's MD5; 404 = no profile."),
    Source("crtsh", "crt.sh", "structured", 4, "unpublished; slow, frequent 5xx",
           12, _D1, None, "Certificate-transparency search; 503 must read as "
           "'unavailable', never as '0 subdomains'."),
    Source("rdap", "rdap.org", "api", 4, "unpublished (bootstrap redirector)", 12, _D1,
           None, "RDAP bootstrap; redirects to the registry's RDAP server."),
    Source("cloudflare_doh", "cloudflare-dns.com", "api", 4, "unpublished; generous",
           12, 3600, None, "DNS over HTTPS (application/dns-json)."),
    # --- pivots: geo / breach (authority 4 / 3) -----------------------------------
    Source("nominatim", "nominatim.openstreetmap.org", "api", 4,
           "1 request/second per client (usage policy)", 12, _D1, None,
           "Honest User-Agent required; serialised by a lock in recon.geo."),
    Source("ipwhois", "ipwho.is", "api", 3, "10,000/month free tier", 12, _H6, None,
           "Approximate IP geolocation; server geography, never the person's."),
    Source("hudson_rock_cavalier", "cavalier.hudsonrock.com", "api", 4,
           "unpublished free tier; 429 observed", 20, _H6, None,
           "Infostealer exposure; credentials stripped before the data leaves "
           "recon.breach. A 429/5xx is 'could not check', never 'clean'."),
)

SOURCES: dict[str, Source] = {s.name: s for s in _ENTRIES}


def names() -> list[str]:
    return list(SOURCES)


def get(name: str) -> Optional[Source]:
    return SOURCES.get(name)


def for_host(host: str) -> list[Source]:
    """Sources registered on ``host`` (exact, case-insensitive; a leading
    ``www.`` is ignored on both sides)."""
    h = (host or "").strip().lower()
    if h.startswith("www."):
        h = h[4:]
    out = []
    for s in SOURCES.values():
        sh = s.host.lower()
        if sh.startswith("www."):
            sh = sh[4:]
        if sh == h:
            out.append(s)
    return out


# ---------------------------------------------------------------------------
# Runtime health
# ---------------------------------------------------------------------------

_WINDOW = 50
_EWMA_ALPHA = 0.3


def _iso_utc(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


class SourceHealth:
    """Rolling health per source: the last ``window`` observations.

    ``record(name, ok, latency_ms, reason)`` is the only write. It never
    raises — an unknown ``name`` is tracked too (with ``host`` unknown in the
    summary) so a new caller cannot break health reporting by forgetting to
    register first.
    """

    def __init__(self, window: int = _WINDOW, *,
                 clock: Callable[[], float] = time.time) -> None:
        self.window = int(window)
        self._clock = clock
        self._obs: dict[str, Deque[tuple[float, bool, float, Optional[str]]]] = {}
        self._ewma: dict[str, float] = {}
        self._last_ok: dict[str, float] = {}
        self._last_fail: dict[str, float] = {}

    def record(self, name: str, ok: bool, latency_ms: Optional[float] = None,
               reason: Optional[str] = None) -> None:
        if not name:
            return
        try:
            now = float(self._clock())
            lat = float(latency_ms) if latency_ms is not None else None
        except Exception:
            return
        q = self._obs.get(name)
        if q is None:
            q = self._obs[name] = deque(maxlen=self.window)
        q.append((now, bool(ok), lat if lat is not None else -1.0,
                  (str(reason)[:120] if reason else None)))
        if lat is not None and lat >= 0:
            prev = self._ewma.get(name)
            self._ewma[name] = lat if prev is None else (
                _EWMA_ALPHA * lat + (1 - _EWMA_ALPHA) * prev)
        if ok:
            self._last_ok[name] = now
        else:
            self._last_fail[name] = now

    def health(self, name: str) -> dict:
        q = self._obs.get(name) or ()
        n = len(q)
        failures = sum(1 for _, ok, _, _ in q if not ok)
        reasons: dict[str, int] = {}
        for _, ok, _, reason in q:
            if not ok and reason:
                reasons[reason] = reasons.get(reason, 0) + 1
        dominant = max(reasons.items(), key=lambda kv: (kv[1], kv[0]))[0] if reasons else None
        ewma = self._ewma.get(name)
        return {
            "name": name,
            "observations": n,
            "failures": failures,
            "failure_rate": round(failures / n, 3) if n else 0.0,
            "last_ok_at": _iso_utc(self._last_ok[name]) if name in self._last_ok else None,
            "last_failure_at": (_iso_utc(self._last_fail[name])
                                if name in self._last_fail else None),
            "ewma_latency_ms": round(ewma, 1) if ewma is not None else None,
            "dominant_reason": dominant,
        }

    def summary(self) -> list[dict]:
        """One row per registered source (plus any unregistered name that was
        recorded), worst failure rate first, then by name. Additive shape:
        ``{name, host, mechanism, authority, observations, failure_rate,
        last_ok_at, ewma_latency_ms, dominant_reason, ...}``."""
        rows = []
        for name in list(SOURCES) + [n for n in self._obs if n not in SOURCES]:
            src = SOURCES.get(name)
            h = self.health(name)
            rows.append({
                "name": name,
                "host": src.host if src else None,
                "mechanism": src.mechanism if src else None,
                "authority": src.authority if src else None,
                "rate_limit": src.rate_limit if src else None,
                "fallback": src.fallback if src else None,
                **{k: v for k, v in h.items() if k != "name"},
            })
        rows.sort(key=lambda r: (-r["failure_rate"], -r["observations"], r["name"]))
        return rows

    def reset(self) -> None:
        self._obs.clear()
        self._ewma.clear()
        self._last_ok.clear()
        self._last_fail.clear()


HEALTH = SourceHealth()


def record(name: str, ok: bool, latency_ms: Optional[float] = None,
           reason: Optional[str] = None) -> None:
    """Record one observation against the process-wide ledger. Never raises."""
    try:
        HEALTH.record(name, ok, latency_ms, reason)
    except Exception:   # pragma: no cover - health must never break a fetch
        pass


def health(name: str) -> dict:
    return HEALTH.health(name)


def summary() -> list[dict]:
    return HEALTH.summary()


def reset() -> None:
    HEALTH.reset()
