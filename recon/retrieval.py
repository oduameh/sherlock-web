"""One outcome vocabulary and one fetch façade for every page we retrieve.

Retrieval audit §2: the same real-world event ("the host answered 429") had
five labels across the code — ``Available`` (Sherlock), ``blocked`` (adapter),
``indeterminate`` (verification), ``None`` = "no profile" (Gravatar), ``None``
cached forever (breach) — and only one of them reached the circuit breaker.
Target architecture §5 replaces them with **one** vocabulary:

=============  ==========================================================
``ok``         a real page / JSON was retrieved (2xx with content)
``absent``     decisive absence: 404, 410
``blocked``    the source refused or walled us: 401/403/429/5xx, any other
               non-decisive status, a challenge page or consent wall on a
               2xx, a redirect that landed on a login page
``transport``  no response: DNS, TLS, timeout, connection reset — with the
               exception class in the reason
``policy``     robots-denied host — never fetched, never counted as an error
``ssrf``       the URL failed the public-address guard — dropped
=============  ==========================================================

Invariant: **blocked ≠ absent**. A status we cannot read as "no such page" is
"we could not look", never "no account".

:func:`classify` is the pure part; :func:`fetch` is the façade that checks the
access policy, the SSRF guard and the per-host backoff *before* any request,
performs one capped GET through the caller's ``httpx`` client, classifies,
records a backoff on a rate limit (``Retry-After`` or 60 s), runs an injected
stealth ladder at most once — and never for a rate limit — and counts
everything. It never raises.

This module imports neither :mod:`recon.stealthweb` nor :mod:`recon.enrich`:
the ladder is an injected ``async (url) -> (status, html, via)`` so the
retrieval layer stays testable without a browser (the wiring is Increment G2).
"""

from __future__ import annotations

import email.utils
import json
import logging
import socket
import time
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, NamedTuple, Optional
from urllib.parse import urlparse

import httpx

from recon import policy, safeweb
from recon.htmltext import challenge_marker, consent_wall_marker, looks_like_shell

__all__ = [
    "ABSENT", "BLOCKED", "OK", "OUTCOMES", "POLICY", "SSRF", "TRANSPORT",
    "Classification", "FetchResult", "HostState", "RetrievalStats",
    "classify", "fetch", "host_key", "is_login_url", "is_rate_limit",
    "parse_retry_after",
]

logger = logging.getLogger("recon.retrieval")

OK = "ok"
ABSENT = "absent"
BLOCKED = "blocked"
TRANSPORT = "transport"
POLICY = "policy"
SSRF = "ssrf"
OUTCOMES: tuple[str, ...] = (OK, ABSENT, BLOCKED, TRANSPORT, POLICY, SSRF)

# Statuses that prove the page is absent — the only decisive negatives.
ABSENT_STATUSES = frozenset({404, 410})
# Statuses that mean "slow down": backed off, never escalated (V7).
RATE_LIMIT_STATUSES = frozenset({429, 503})

DEFAULT_BACKOFF_S = 60.0
MIN_BACKOFF_S = 5.0        # a Retry-After of 0 or a past date still means "back off"
MAX_BACKOFF_S = 3600.0
DEFAULT_MAX_BYTES = 512 * 1024
_CHUNK = 16384

# Path segments that mean "you were sent to log in". Matched segment-wise so a
# handle such as ``login_master`` never triggers it.
LOGIN_SEGMENTS = frozenset({
    "login", "log-in", "log_in", "signin", "sign-in", "sign_in",
    "session", "sessions", "sso", "authenticate",
})

_HTML_TYPES = ("text/html", "application/xhtml")
_JSON_TYPES = ("application/json", "text/json", "+json")
_TEXT_TYPES = ("text/",)


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

def host_key(url_or_host: Optional[str]) -> str:
    """Normalised host for per-host state: lowercase, without a leading
    ``www.`` and without a default port (``:80``/``:443``). A bare host is
    accepted as well as a URL. ``""`` when nothing usable is present."""
    s = (url_or_host or "").strip()
    if not s:
        return ""
    if "://" not in s:
        s = "//" + s
    try:
        parts = urlparse(s)
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        return ""
    if not host:
        return ""
    if host.startswith("www."):
        host = host[4:]
    if port and port not in (80, 443):
        host = f"{host}:{port}"
    return host


def is_login_url(url: Optional[str]) -> bool:
    """True when ``url``'s path has a segment that names a login page."""
    if not url:
        return False
    try:
        path = urlparse(url).path or ""
    except ValueError:
        return False
    return any(seg.lower() in LOGIN_SEGMENTS for seg in path.split("/") if seg)


def is_rate_limit(status: Optional[int], headers: Optional[dict] = None) -> bool:
    """429 and 503 are rate limits; so is a 403 whose ``X-RateLimit-Remaining``
    is ``0`` (GitHub's unauthenticated budget — audit defect 10 asked for it to
    be distinguishable from a real 403)."""
    if status in RATE_LIMIT_STATUSES:
        return True
    if status == 403 and headers:
        remaining = _header(headers, "x-ratelimit-remaining")
        if remaining is not None and remaining.strip() == "0":
            return True
    return False


def parse_retry_after(value: Optional[str], *,
                      now: Optional[datetime] = None) -> Optional[float]:
    """``Retry-After`` → seconds in ``[MIN_BACKOFF_S, MAX_BACKOFF_S]``, or None
    when absent or unparseable. Accepts delta-seconds and HTTP-dates."""
    if not value:
        return None
    v = str(value).strip()
    if not v:
        return None
    if v.isdigit():
        secs = float(v)
    else:
        try:
            dt = email.utils.parsedate_to_datetime(v)
        except Exception:
            return None
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        ref = now or datetime.now(timezone.utc)
        secs = (dt - ref).total_seconds()
    return min(max(secs, MIN_BACKOFF_S), MAX_BACKOFF_S)


def _header(headers: Optional[Any], name: str) -> Optional[str]:
    """Case-insensitive header lookup over a dict or ``httpx.Headers``."""
    if not headers:
        return None
    try:
        v = headers.get(name)
        if v is None:
            v = headers.get(name.title())
        if v is None and hasattr(headers, "items"):
            low = name.lower()
            for k, val in headers.items():
                if str(k).lower() == low:
                    v = val
                    break
    except Exception:
        return None
    return None if v is None else str(v)


class Classification(NamedTuple):
    outcome: str
    reason: str


def classify(status: Optional[int], html: Optional[str],
             headers: Optional[dict] = None, *, url: str = "",
             requested_url: Optional[str] = None, error: Optional[str] = None,
             kind: str = "html", body_ok: bool = True) -> Classification:
    """Map one response to the outcome vocabulary (pure).

    Rules, in order:

    * ``status is None`` → ``transport`` with the exception class (``error``).
    * 404 / 410 → ``absent``.
    * a rate limit (:func:`is_rate_limit`) → ``blocked`` "rate limited …".
    * any other status ≥ 400 (401, 403, 5xx, and every non-decisive 4xx) →
      ``blocked`` with the status; a challenge marker or ``cf-mitigated``
      header is appended so the reason says *what kind* of block.
    * a 3xx that was not followed → ``blocked`` (an unresolved redirect is
      not a page).
    * 2xx: a final URL on a login page (when it differs from
      ``requested_url``) → ``blocked`` "login redirect"; a ``cf-mitigated:
      challenge`` header, a challenge marker or a consent wall in the body →
      ``blocked``; otherwise ``ok``. For ``kind="json"`` a body that is not
      JSON (``body_ok=False``) is ``blocked`` "non-JSON response" — the usual
      shape of a login page served on an API URL.

    A JS shell (2xx with almost no visible text) is ``ok`` here: whether to
    render it is the caller's decision (:attr:`FetchResult.is_shell`).
    Markers are matched with ``raw_tokens=False`` — a DataDome/PerimeterX
    script tag on a legitimate page must not turn it into a block.
    """
    if status is None:
        return Classification(TRANSPORT, f"no response ({error or 'unknown error'})")
    if status in ABSENT_STATUSES:
        return Classification(ABSENT, f"HTTP {status}")
    cf = _header(headers, "cf-mitigated")
    if is_rate_limit(status, headers):
        reason = f"rate limited (HTTP {status}"
        if status == 403:
            reason += ", X-RateLimit-Remaining: 0"
        ra = _header(headers, "retry-after")
        if ra:
            reason += f", Retry-After {ra.strip()}"
        return Classification(BLOCKED, reason + ")")
    if status >= 400:
        reason = f"HTTP {status}"
        if cf:
            reason += f" (cf-mitigated: {cf.strip()})"
        marker = challenge_marker(html, raw_tokens=False) if html else None
        if marker:
            reason += f', challenge page ("{marker}")'
        return Classification(BLOCKED, reason)
    if status >= 300:
        return Classification(BLOCKED, f"unfollowed redirect (HTTP {status})")
    # 2xx
    if url and is_login_url(url) and (requested_url is None
                                      or url.rstrip("/") != requested_url.rstrip("/")):
        try:
            path = urlparse(url).path
        except ValueError:
            path = url
        return Classification(BLOCKED, f"login redirect ({path})")
    if cf and cf.strip().lower() == "challenge":
        return Classification(BLOCKED, "challenge (cf-mitigated: challenge)")
    if html:
        marker = challenge_marker(html, raw_tokens=False)
        if marker:
            return Classification(BLOCKED, f'challenge page ("{marker}")')
        wall = consent_wall_marker(html)
        if wall:
            return Classification(BLOCKED, f'consent wall ("{wall}")')
    if kind == "json" and not body_ok:
        return Classification(BLOCKED, f"non-JSON response (HTTP {status})")
    return Classification(OK, f"HTTP {status}")


# ---------------------------------------------------------------------------
# Per-host state and counters
# ---------------------------------------------------------------------------

class HostState:
    """In-process memory per host: backoff deadline, consecutive blocks, last
    status. Keys are normalised with :func:`host_key` (``www.`` and default
    ports stripped), so ``www.example.com`` and ``example.com:443`` share one
    entry. Clock injectable for tests."""

    def __init__(self, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._backoff_until: dict[str, float] = {}
        self._backoff_status: dict[str, Optional[int]] = {}
        self._blocks: dict[str, int] = {}
        self._last_status: dict[str, Optional[int]] = {}
        self._last_outcome: dict[str, str] = {}

    def backoff(self, host: str, seconds: float, *, status: Optional[int] = None
                ) -> float:
        """Back ``host`` off for ``seconds`` (clamped to ``MAX_BACKOFF_S``).
        Never shortens an existing longer backoff. Returns the deadline."""
        key = host_key(host)
        secs = min(max(float(seconds), 0.0), MAX_BACKOFF_S)
        deadline = self._clock() + secs
        if deadline > self._backoff_until.get(key, 0.0):
            self._backoff_until[key] = deadline
            self._backoff_status[key] = status
        return self._backoff_until[key]

    def active_backoff(self, host: str) -> Optional[float]:
        """Seconds of backoff left for ``host``, or None when it may be fetched."""
        key = host_key(host)
        until = self._backoff_until.get(key)
        if until is None:
            return None
        left = until - self._clock()
        if left <= 0:
            self._backoff_until.pop(key, None)
            self._backoff_status.pop(key, None)
            return None
        return left

    def record(self, host: str, outcome: str, status: Optional[int]) -> None:
        """Note one outcome for ``host``: ``blocked``/``transport`` extend the
        consecutive-block count, ``ok``/``absent`` reset it."""
        key = host_key(host)
        if not key:
            return
        if outcome in (BLOCKED, TRANSPORT):
            self._blocks[key] = self._blocks.get(key, 0) + 1
        elif outcome in (OK, ABSENT):
            self._blocks[key] = 0
        self._last_status[key] = status
        self._last_outcome[key] = outcome

    def consecutive_blocks(self, host: str) -> int:
        return self._blocks.get(host_key(host), 0)

    def last_status(self, host: str) -> Optional[int]:
        return self._last_status.get(host_key(host))

    def last_outcome(self, host: str) -> Optional[str]:
        return self._last_outcome.get(host_key(host))

    def snapshot(self) -> dict:
        now = self._clock()
        hosts = set(self._blocks) | set(self._last_status) | set(self._backoff_until)
        out = {}
        for h in sorted(hosts):
            left = self._backoff_until.get(h, 0.0) - now
            out[h] = {
                "backoff_s_left": round(left, 1) if left > 0 else 0,
                "backoff_status": self._backoff_status.get(h) if left > 0 else None,
                "consecutive_blocks": self._blocks.get(h, 0),
                "last_status": self._last_status.get(h),
                "last_outcome": self._last_outcome.get(h),
            }
        return out


_MAX_TRACKED_HOSTS = 1000


class RetrievalStats:
    """Counters: attempts by outcome, by status class, by host
    (attempts/blocked), plus skips (policy/ssrf/backoff) and ladder use."""

    def __init__(self) -> None:
        self.attempts = 0
        self.requests = 0
        self.by_outcome: dict[str, int] = {o: 0 for o in OUTCOMES}
        self.by_status_class: dict[str, int] = {}
        self.by_host: dict[str, dict[str, int]] = {}
        self.skipped: dict[str, int] = {"policy": 0, "ssrf": 0, "backoff": 0}
        self.ladder_runs = 0
        self.ladder_rescued = 0

    def record(self, outcome: str, status: Optional[int], host: str, *,
               requested: bool = True, skipped: Optional[str] = None) -> None:
        self.attempts += 1
        if requested:
            self.requests += 1
        self.by_outcome[outcome] = self.by_outcome.get(outcome, 0) + 1
        if status is not None:
            cls = f"{status // 100}xx"
            self.by_status_class[cls] = self.by_status_class.get(cls, 0) + 1
        elif outcome == TRANSPORT:
            self.by_status_class["none"] = self.by_status_class.get("none", 0) + 1
        if skipped:
            self.skipped[skipped] = self.skipped.get(skipped, 0) + 1
        key = host_key(host) or "?"
        entry = self.by_host.get(key)
        if entry is None:
            if len(self.by_host) >= _MAX_TRACKED_HOSTS:
                key = "_other"
                entry = self.by_host.get(key)
            if entry is None:
                entry = self.by_host[key] = {"attempts": 0, "blocked": 0}
        entry["attempts"] += 1
        if outcome in (BLOCKED, TRANSPORT):
            entry["blocked"] += 1

    def snapshot(self) -> dict:
        worst = sorted(self.by_host.items(),
                       key=lambda kv: (-kv[1]["blocked"], -kv[1]["attempts"], kv[0]))
        return {
            "attempts": self.attempts,
            "requests": self.requests,
            "by_outcome": dict(self.by_outcome),
            "by_status_class": dict(sorted(self.by_status_class.items())),
            "by_host": {h: dict(v) for h, v in worst},
            "skipped": dict(self.skipped),
            "ladder": {"runs": self.ladder_runs, "rescued": self.ladder_rescued},
        }


# ---------------------------------------------------------------------------
# The façade
# ---------------------------------------------------------------------------

class FetchResult(NamedTuple):
    """Outcome of one :func:`fetch`.

    ``status`` is None only for ``transport``/``policy``/``ssrf`` (no
    response); ``html`` is the decoded text body for ``kind`` ``html``/``json``
    (None when the response was not of that type, or nothing was read);
    ``error`` is the exception class of a transport failure; ``via`` names the
    tier that produced the adopted result (``httpx`` or the ladder's label);
    ``retry_after`` is the parsed header on a rate limit; ``is_shell`` is
    :func:`recon.htmltext.looks_like_shell` on a 2xx body (or an empty body);
    ``data`` is the parsed JSON for ``kind="json"``; ``content`` the raw bytes
    for ``kind="bytes"``.
    """
    outcome: str
    reason: str
    status: Optional[int]
    html: Optional[str]
    error: Optional[str] = None
    via: str = "httpx"
    retry_after: Optional[float] = None
    is_shell: bool = False
    data: Any = None
    content: Optional[bytes] = None
    final_url: Optional[str] = None
    content_type: str = ""
    truncated: bool = False
    rate_limited: bool = False

    @property
    def ok(self) -> bool:
        return self.outcome == OK


Ladder = Callable[[str], Awaitable[tuple[Optional[int], Optional[str], str]]]


def _wants(kind: str, ctype: str) -> bool:
    ct = (ctype or "").lower()
    if kind == "html":
        return any(t in ct for t in _HTML_TYPES)
    if kind == "json":
        return any(t in ct for t in _JSON_TYPES) or not ct
    if kind == "text":
        return any(t in ct for t in _TEXT_TYPES + _JSON_TYPES + ("xml",)) or not ct
    return True   # bytes: anything


async def _read_capped(resp: httpx.Response, max_bytes: int) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    size = 0
    truncated = False
    async for chunk in resp.aiter_bytes(_CHUNK):
        chunks.append(chunk)
        size += len(chunk)
        if size >= max_bytes:
            truncated = size > max_bytes
            break
    body = b"".join(chunks)
    if len(body) > max_bytes:
        body = body[:max_bytes]
        truncated = True
    return body, truncated


def _blocked_exception_result(exc: safeweb.BlockedRequestError, url: str
                              ) -> FetchResult:
    """A guard refusal raised *during* the request (a redirect hop): map it to
    ``policy``, ``transport`` (DNS) or ``ssrf`` by cause, not by message alone."""
    msg = str(exc)
    if isinstance(exc.__cause__, socket.gaierror):
        return FetchResult(TRANSPORT, f"no response (DNS resolution failed: {msg})",
                           None, None, "gaierror", final_url=url)
    if msg.startswith("access policy"):
        return FetchResult(POLICY, msg, None, None, "BlockedRequestError",
                           final_url=url)
    return FetchResult(SSRF, msg, None, None, "BlockedRequestError", final_url=url)


async def fetch(url: str, *, client: httpx.AsyncClient, kind: str = "html",
                host_state: Optional[HostState] = None,
                stats: Optional[RetrievalStats] = None,
                ladder: Optional[Ladder] = None,
                max_bytes: int = DEFAULT_MAX_BYTES,
                headers: Optional[dict] = None) -> FetchResult:
    """GET ``url`` once, honestly, and say what happened. Never raises.

    Order of checks — each one earlier stops the later ones:

    1. :func:`recon.policy.denied_reason` → ``policy`` (no request, no DNS).
    2. :func:`recon.safeweb.assert_public_url` → ``ssrf``; a DNS failure at
       the guard is ``transport``, not ``ssrf``.
    3. ``host_state.active_backoff`` → ``blocked`` "rate limited — backing
       off" (no request).
    4. One streamed GET capped at ``max_bytes`` through ``client`` (which
       should be a :func:`recon.safeweb.async_client`, whose request hook
       re-checks every redirect hop). Any exception → ``transport`` with
       the class name; a guard refusal on a hop → ``policy``/``ssrf``.
    5. :func:`classify`. A rate limit records ``host_state.backoff`` from
       ``Retry-After`` (default 60 s) and is **never** escalated.
    6. When ``ladder`` is given and the outcome is ``blocked`` for any reason
       other than a rate limit, it runs exactly once; a status from it is
       re-classified and adopted with its ``via`` label. A ladder that raises
       leaves the plain result in place.

    ``kind``: ``html`` (only HTML bodies are decoded), ``json`` (decoded and
    parsed into ``data``; a non-JSON 2xx is ``blocked``), ``text`` (any
    text-like body) or ``bytes`` (raw ``content``, e.g. an avatar).
    """
    hs = host_state
    st = stats
    host = host_key(url)

    reason = policy.denied_reason(url)
    if reason:
        if st:
            st.record(POLICY, None, host, requested=False, skipped="policy")
        return FetchResult(POLICY, f"access policy: {reason}", None, None,
                           final_url=url)

    try:
        await safeweb.assert_public_url(url)
    except safeweb.BlockedRequestError as exc:
        res = _blocked_exception_result(exc, url)
        if st:
            st.record(res.outcome, None, host, requested=False,
                      skipped="ssrf" if res.outcome == SSRF else None)
        return res
    except Exception as exc:   # a broken resolver must not take the run down
        if st:
            st.record(TRANSPORT, None, host, requested=False)
        return FetchResult(TRANSPORT, f"no response ({type(exc).__name__})", None,
                           None, type(exc).__name__, final_url=url)

    if hs is not None:
        left = hs.active_backoff(host)
        if left is not None:
            if st:
                st.record(BLOCKED, None, host, requested=False, skipped="backoff")
            return FetchResult(
                BLOCKED, f"rate limited — backing off ({int(left) + 1} s left)",
                hs.last_status(host), None, retry_after=left, final_url=url,
                rate_limited=True)

    result = await _get_once(url, client=client, kind=kind, max_bytes=max_bytes,
                             headers=headers)

    if result.rate_limited and hs is not None:
        hs.backoff(host, result.retry_after or DEFAULT_BACKOFF_S,
                   status=result.status)

    if ladder is not None and result.outcome == BLOCKED and not result.rate_limited:
        if st:
            st.ladder_runs += 1
        try:
            l_status, l_html, l_via = await ladder(url)
        except Exception as exc:
            logger.debug("ladder failed for %s: %s", url, exc)
            result = result._replace(
                reason=f"{result.reason}; ladder failed ({type(exc).__name__})")
        else:
            if l_status is not None:
                result = _classify_ladder(url, kind, l_status, l_html,
                                          l_via or "ladder")
                if st and result.outcome in (OK, ABSENT):
                    st.ladder_rescued += 1
                if result.rate_limited and hs is not None:
                    hs.backoff(host, DEFAULT_BACKOFF_S, status=l_status)

    if hs is not None:
        hs.record(host, result.outcome, result.status)
    if st:
        st.record(result.outcome, result.status, host)
    return result


def _classify_ladder(url: str, kind: str, status: int, html: Optional[str],
                     via: str) -> FetchResult:
    """Re-classify what a stealth tier returned (status + text only; no
    headers, no final URL, so a login redirect cannot be seen here)."""
    data: Any = None
    body_ok = True
    if kind == "json":
        try:
            data = json.loads(html) if html and html.strip() else None
        except ValueError:
            data = None
        body_ok = data is not None
    cls = classify(status, html, None, url=url, requested_url=url,
                   kind="json" if kind == "json" else "html", body_ok=body_ok)
    shell = bool(status < 300 and kind != "bytes"
                 and (not html or looks_like_shell(html)))
    return FetchResult(cls.outcome, cls.reason, status, html, via=via,
                       is_shell=shell, data=data, final_url=url,
                       rate_limited=is_rate_limit(status))


async def _get_once(url: str, *, client: httpx.AsyncClient, kind: str,
                    max_bytes: int, headers: Optional[dict]) -> FetchResult:
    """The single capped GET + classification. Never raises."""
    try:
        async with client.stream("GET", url, headers=headers or None) as resp:
            status = resp.status_code
            final_url = str(resp.url)
            hdrs = resp.headers
            ctype = (hdrs.get("content-type") or "").split(";")[0].strip().lower()
            rate_limited = is_rate_limit(status, hdrs)
            retry_after = parse_retry_after(hdrs.get("retry-after")) if rate_limited else None

            wanted = _wants(kind, ctype)
            body: bytes = b""
            truncated = False
            if kind == "bytes":
                if status < 400 and wanted:
                    body, truncated = await _read_capped(resp, max_bytes)
            else:
                # Always read (capped): an error body names its WAF, and a
                # login page served on an API URL carries the markers.
                body, truncated = await _read_capped(resp, max_bytes)

            text: Optional[str] = None
            data: Any = None
            content: Optional[bytes] = None
            body_ok = True
            if kind == "bytes":
                if status < 400 and wanted and not truncated:
                    content = body
            elif body and (kind != "html" or wanted or status >= 400):
                # For ``html`` a 2xx of another type yields html=None, the
                # honest "no HTML retrieved" the verifier expects.
                text = body.decode(resp.encoding or "utf-8", errors="replace")
            if kind == "json" and status < 300:
                if text is None or not text.strip():
                    body_ok = False
                else:
                    try:
                        data = json.loads(text)
                    except ValueError:
                        body_ok = False

            cls = classify(status, text, hdrs, url=final_url, requested_url=url,
                           kind=kind, body_ok=body_ok)
            if kind == "bytes" and cls.outcome == OK:
                if not wanted:
                    cls = Classification(OK, f"HTTP {status}, unexpected type ({ctype})")
                elif truncated:
                    cls = Classification(OK, f"HTTP {status}, body larger than {max_bytes} B")
            elif kind == "html" and cls.outcome == OK and status < 300:
                if not wanted:
                    cls = Classification(OK, f"HTTP {status}, non-HTML body ({ctype or '?'})")
                elif not body:
                    cls = Classification(OK, f"HTTP {status}, empty body")
            shell = bool(status < 300 and kind in ("html", "text")
                         and wanted and (not text or looks_like_shell(text)))
            return FetchResult(cls.outcome, cls.reason, status, text, via="httpx",
                               retry_after=retry_after, is_shell=shell, data=data,
                               content=content, final_url=final_url,
                               content_type=ctype, truncated=truncated,
                               rate_limited=rate_limited)
    except safeweb.BlockedRequestError as exc:
        return _blocked_exception_result(exc, url)
    except Exception as exc:
        name = type(exc).__name__
        cause = exc.__cause__ or exc.__context__
        if isinstance(cause, socket.gaierror) or "getaddrinfo" in str(exc).lower():
            name = f"{name}: DNS resolution failed"
        return FetchResult(TRANSPORT, f"no response ({name})", None, None,
                           type(exc).__name__, final_url=url)
