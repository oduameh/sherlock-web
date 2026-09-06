"""recon.retrieval — the outcome vocabulary and the fetch façade.

Every failure path from the audit's outcome grid (§1B) is exercised offline
with ``httpx.MockTransport``: no network anywhere. DNS is stubbed at the SSRF
guard so hostnames resolve to a public address (a private IP literal still
fails the guard, which is the ``ssrf`` test).
"""

import asyncio
import socket
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from recon import retrieval, safeweb
from recon.retrieval import (
    ABSENT,
    BLOCKED,
    OK,
    POLICY,
    SSRF,
    TRANSPORT,
    HostState,
    RetrievalStats,
    classify,
    fetch,
    host_key,
    is_login_url,
    is_rate_limit,
    parse_retry_after,
)

REAL = ("<html><head><title>Alice Example</title></head><body>"
        + "<p>Alice writes about maps, cycling and open data.</p>" * 10
        + "</body></html>")
CHALLENGE = ("<html><head><title>Just a moment...</title></head><body>"
             "<p>Checking your browser before accessing example.test.</p>"
             "</body></html>")
AKAMAI = ("<html><head><title>Access Denied</title></head><body>"
          "<h1>Access Denied</h1><p>You don't have permission to access "
          "this resource. Reference #18.3a2f1602.1725600000</p></body></html>")
CONSENT = ("<html><head><title>Before you continue to YouTube</title></head><body>"
           + "<p>We use cookies and data to deliver and maintain our services.</p>" * 5
           + "</body></html>")
SHELL = ("<html><head><title>App</title></head><body><div id='root'></div>"
         "<script>window.__DATA__={};</script></body></html>")
LOGIN = ("<html><head><title>Sign in</title></head><body>"
         + "<p>Please sign in to continue to your account.</p>" * 6
         + "</body></html>")
URL = "https://example.test/alice"


@pytest.fixture(autouse=True)
def _public_dns(monkeypatch):
    """Hostnames resolve to a public address so the guard passes offline."""
    async def fake_resolve(host, port):
        return ["93.184.216.34"]
    monkeypatch.setattr(safeweb, "_resolve", fake_resolve)


def _run(handler, url=URL, *, guarded=False, **kw):
    calls = []

    def counting(request):
        calls.append(request)
        return handler(request)

    async def go():
        transport = httpx.MockTransport(counting)
        if guarded:
            client = safeweb.async_client(transport=transport)
        else:
            client = httpx.AsyncClient(transport=transport, follow_redirects=True)
        async with client:
            return await fetch(url, client=client, **kw)

    res = asyncio.run(go())
    return res, calls


# ---------------------------------------------------------------------------
# classify (pure)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("status,html,headers,outcome,needle", [
    (200, REAL, {}, OK, "HTTP 200"),
    (404, "nope", {}, ABSENT, "HTTP 404"),
    (410, None, {}, ABSENT, "HTTP 410"),
    (401, None, {}, BLOCKED, "HTTP 401"),
    (403, None, {}, BLOCKED, "HTTP 403"),
    (403, AKAMAI, {}, BLOCKED, 'challenge page ("access denied")'),
    (403, None, {"cf-mitigated": "challenge"}, BLOCKED, "cf-mitigated: challenge"),
    (403, None, {"x-ratelimit-remaining": "0"}, BLOCKED,
     "rate limited (HTTP 403, X-RateLimit-Remaining: 0)"),
    (429, None, {}, BLOCKED, "rate limited (HTTP 429)"),
    (429, None, {"retry-after": "120"}, BLOCKED, "Retry-After 120"),
    (503, "<html>maintenance</html>", {}, BLOCKED, "rate limited (HTTP 503"),
    (500, None, {}, BLOCKED, "HTTP 500"),
    (451, None, {}, BLOCKED, "HTTP 451"),
    (200, CHALLENGE, {}, BLOCKED, 'challenge page ("just a moment")'),
    (200, AKAMAI, {}, BLOCKED, 'challenge page ("access denied")'),
    (200, CONSENT, {}, BLOCKED, 'consent wall ("before you continue to")'),
    (200, REAL, {"cf-mitigated": "challenge"}, BLOCKED, "cf-mitigated"),
    (200, SHELL, {}, OK, "HTTP 200"),       # a shell is the caller's decision
    (200, "", {}, OK, "HTTP 200"),
    (204, None, {}, OK, "HTTP 204"),
    (301, None, {}, BLOCKED, "unfollowed redirect (HTTP 301)"),
])
def test_classify_matrix(status, html, headers, outcome, needle):
    got = classify(status, html, headers, url=URL, requested_url=URL)
    assert got.outcome == outcome, got
    assert needle in got.reason, got


def test_classify_transport_carries_the_exception_class():
    got = classify(None, None, None, url=URL, error="ConnectTimeout")
    assert (got.outcome, got.reason) == (TRANSPORT, "no response (ConnectTimeout)")
    assert got.escalatable is True                  # a TLS reset may fall to tier 2
    assert classify(None, None).outcome == TRANSPORT


def test_classify_login_redirect_only_when_the_url_moved():
    moved = classify(200, LOGIN, {}, url="https://example.test/login?next=/alice",
                     requested_url=URL)
    assert moved.outcome == BLOCKED and moved.reason == "login redirect (/login)"
    # The page we asked for *is* the login URL: not a redirect.
    same = classify(200, LOGIN, {}, url="https://example.test/login",
                    requested_url="https://example.test/login")
    assert same.outcome == OK
    # A nested login path and a Rails-style sign_in both count.
    assert classify(200, LOGIN, {}, url="https://example.test/accounts/login/",
                    requested_url=URL).outcome == BLOCKED
    assert classify(200, LOGIN, {}, url="https://example.test/users/sign_in",
                    requested_url=URL).outcome == BLOCKED


@pytest.mark.parametrize("url,expected", [
    ("https://example.test/login", True),
    ("https://example.test/accounts/login/?next=/x", True),
    ("https://example.test/users/sign_in", True),
    ("https://example.test/session", True),
    ("https://example.test/login_master", False),     # a handle, not a page
    ("https://example.test/alice", False),
    ("https://example.test/", False),
    (None, False),
])
def test_is_login_url(url, expected):
    assert is_login_url(url) is expected


def test_classify_json_kind_rejects_non_json_bodies():
    got = classify(200, LOGIN, {}, url=URL, requested_url=URL, kind="json",
                   body_ok=False)
    assert got.outcome == BLOCKED and got.reason.startswith("non-JSON response")
    assert classify(200, '{"id": 1}', {}, url=URL, kind="json").outcome == OK


def test_vendor_script_tag_on_a_real_page_is_not_a_block():
    """Verdict scoping: a DataDome script on a legitimate profile must not turn
    it into ``blocked`` (only the escalation decision may use raw tokens)."""
    page = REAL.replace("<body>", "<body><script src='https://js.datadome.co/tags.js'></script>")
    assert classify(200, page, {}, url=URL).outcome == OK


def test_is_rate_limit():
    assert is_rate_limit(429) and is_rate_limit(503)
    assert is_rate_limit(403, {"x-ratelimit-remaining": "0"})
    assert not is_rate_limit(403, {"x-ratelimit-remaining": "57"})
    assert not is_rate_limit(403) and not is_rate_limit(200) and not is_rate_limit(None)


# ---------------------------------------------------------------------------
# parse_retry_after / host_key
# ---------------------------------------------------------------------------

def test_parse_retry_after_delta_seconds_clamped():
    assert parse_retry_after("120") == 120.0
    assert parse_retry_after("0") == retrieval.MIN_BACKOFF_S
    assert parse_retry_after("999999") == retrieval.MAX_BACKOFF_S
    assert parse_retry_after(" 30 ") == 30.0


def test_parse_retry_after_http_date():
    now = datetime(2026, 9, 6, 12, 0, 0, tzinfo=timezone.utc)
    future = (now + timedelta(seconds=90)).strftime("%a, %d %b %Y %H:%M:%S GMT")
    assert parse_retry_after(future, now=now) == 90.0
    past = (now - timedelta(seconds=90)).strftime("%a, %d %b %Y %H:%M:%S GMT")
    assert parse_retry_after(past, now=now) == retrieval.MIN_BACKOFF_S


@pytest.mark.parametrize("value", [None, "", "   ", "soon", "12abc"])
def test_parse_retry_after_unparseable_is_none(value):
    assert parse_retry_after(value) is None


@pytest.mark.parametrize("value,expected", [
    ("https://www.Example.com:443/x?y", "example.com"),
    ("http://example.com:80/", "example.com"),
    ("https://example.com:8443/", "example.com:8443"),
    ("www.example.com", "example.com"),
    ("EXAMPLE.com", "example.com"),
    ("", ""),
    (None, ""),
    ("https://", ""),
])
def test_host_key(value, expected):
    assert host_key(value) == expected


# ---------------------------------------------------------------------------
# HostState / RetrievalStats
# ---------------------------------------------------------------------------

def test_host_state_backoff_expires_and_never_shortens():
    clock = {"t": 1000.0}
    hs = HostState(clock=lambda: clock["t"])
    assert hs.active_backoff("https://www.example.com/x") is None
    hs.backoff("example.com", 60, status=429)
    assert hs.active_backoff("https://www.example.com:443/y") == pytest.approx(60)
    hs.backoff("example.com", 10)                   # shorter: ignored
    assert hs.active_backoff("example.com") == pytest.approx(60)
    hs.backoff("example.com", 120)                  # longer: adopted
    assert hs.active_backoff("example.com") == pytest.approx(120)
    clock["t"] += 121
    assert hs.active_backoff("example.com") is None
    assert hs.backoff("x", 99999) - clock["t"] == retrieval.MAX_BACKOFF_S


def test_host_state_consecutive_blocks_and_last_status():
    hs = HostState()
    hs.record("https://a.test/1", BLOCKED, 403)
    hs.record("https://www.a.test/2", TRANSPORT, None)
    assert hs.consecutive_blocks("a.test") == 2
    assert hs.last_status("a.test") is None and hs.last_outcome("a.test") == TRANSPORT
    hs.record("a.test", OK, 200)
    assert hs.consecutive_blocks("a.test") == 0 and hs.last_status("a.test") == 200
    hs.record("a.test", ABSENT, 404)
    assert hs.consecutive_blocks("a.test") == 0
    snap = hs.snapshot()["a.test"]
    assert snap["last_status"] == 404 and snap["backoff_s_left"] == 0


def test_retrieval_stats_snapshot():
    st = RetrievalStats()
    st.record(OK, 200, "https://a.test/1")
    st.record(BLOCKED, 429, "https://www.a.test/2")
    st.record(TRANSPORT, None, "b.test")
    st.record(POLICY, None, "instagram.com", requested=False, skipped="policy")
    snap = st.snapshot()
    assert snap["attempts"] == 4 and snap["requests"] == 3
    assert snap["by_outcome"][OK] == 1 and snap["by_outcome"][BLOCKED] == 1
    assert snap["by_status_class"] == {"2xx": 1, "4xx": 1, "none": 1}
    assert snap["by_host"]["a.test"] == {"attempts": 2, "blocked": 1}
    assert snap["by_host"]["b.test"] == {"attempts": 1, "blocked": 1}
    assert snap["skipped"]["policy"] == 1
    assert list(snap["by_host"])[0] in ("a.test", "b.test")   # worst-first


# ---------------------------------------------------------------------------
# fetch — success and decisive absence
# ---------------------------------------------------------------------------

def test_fetch_ok_real_page():
    res, calls = _run(lambda r: httpx.Response(200, html=REAL))
    assert res.outcome == OK and res.ok and res.status == 200
    assert "Alice" in res.html and res.via == "httpx"
    assert res.is_shell is False and res.rate_limited is False
    assert res.final_url == URL and res.content_type == "text/html"
    assert len(calls) == 1


@pytest.mark.parametrize("status", [404, 410])
def test_fetch_absent(status):
    hs = HostState()
    res, _ = _run(lambda r: httpx.Response(status, html="<h1>Not found</h1>"), host_state=hs)
    assert res.outcome == ABSENT and res.reason == f"HTTP {status}"
    assert hs.active_backoff("example.test") is None


# ---------------------------------------------------------------------------
# fetch — blocked statuses, rate limits, backoff
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("status", [401, 403, 500, 502])
def test_fetch_blocked_status_no_backoff(status):
    hs = HostState()
    res, _ = _run(lambda r: httpx.Response(status, text="denied"), host_state=hs)
    assert res.outcome == BLOCKED and f"HTTP {status}" in res.reason
    assert res.rate_limited is False
    assert hs.active_backoff("example.test") is None
    assert hs.consecutive_blocks("example.test") == 1


def test_fetch_429_without_retry_after_backs_off_60s_and_skips_the_host():
    hs, st = HostState(), RetrievalStats()
    calls = []

    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(429, text="slow down")

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            first = await fetch(URL, client=c, host_state=hs, stats=st)
            second = await fetch("https://www.example.test/bob", client=c,
                                 host_state=hs, stats=st)
            return first, second

    first, second = asyncio.run(go())
    assert first.outcome == BLOCKED and first.rate_limited and first.retry_after is None
    assert first.reason == "rate limited (HTTP 429)"
    assert hs.active_backoff("example.test") == pytest.approx(retrieval.DEFAULT_BACKOFF_S, abs=1)
    # The second row on the same host is answered without a request.
    assert calls == ["/alice"]
    assert second.outcome == BLOCKED and second.rate_limited
    assert second.reason.startswith("rate limited — backing off")
    assert second.status == 429 and second.html is None
    assert st.snapshot()["skipped"]["backoff"] == 1
    assert st.snapshot()["requests"] == 1


def test_fetch_429_with_retry_after_uses_the_header():
    hs = HostState()
    res, _ = _run(lambda r: httpx.Response(429, headers={"retry-after": "120"}),
                  host_state=hs)
    assert res.retry_after == 120.0
    assert "Retry-After 120" in res.reason
    assert hs.active_backoff("example.test") == pytest.approx(120, abs=1)


def test_fetch_503_backs_off_and_never_escalates():
    hs = HostState()
    ladder_calls = []

    async def ladder(url):
        ladder_calls.append(url)
        return 200, REAL, "scrapling_tls"

    res, calls = _run(lambda r: httpx.Response(503, html="<html>maintenance</html>"),
                      host_state=hs, ladder=ladder)
    assert res.outcome == BLOCKED and res.rate_limited
    assert ladder_calls == [], "a rate limit is answered by backing off, never a stealthier retry"
    assert hs.active_backoff("example.test") is not None


def test_fetch_github_style_403_with_remaining_zero_is_a_rate_limit():
    hs = HostState()
    ladder_calls = []

    async def ladder(url):
        ladder_calls.append(url)
        return 200, REAL, "tls"

    res, _ = _run(lambda r: httpx.Response(
        403, headers={"x-ratelimit-remaining": "0", "retry-after": "300"},
        json={"message": "API rate limit exceeded"}), host_state=hs, ladder=ladder,
        kind="json")
    assert res.outcome == BLOCKED and res.rate_limited
    assert "X-RateLimit-Remaining: 0" in res.reason
    assert res.retry_after == 300.0 and ladder_calls == []
    assert hs.active_backoff("example.test") == pytest.approx(300, abs=1)


# ---------------------------------------------------------------------------
# fetch — body classes on a 2xx
# ---------------------------------------------------------------------------

def test_fetch_empty_body_is_ok_and_a_shell():
    res, _ = _run(lambda r: httpx.Response(200, html=""))
    assert res.outcome == OK and res.reason == "HTTP 200, empty body"
    assert res.is_shell is True and not res.html


def test_fetch_js_shell_is_ok_with_the_flag_and_no_ladder():
    ladder_calls = []

    async def ladder(url):
        ladder_calls.append(url)
        return 200, REAL, "browser"

    res, _ = _run(lambda r: httpx.Response(200, html=SHELL), ladder=ladder)
    assert res.outcome == OK and res.is_shell is True
    assert ladder_calls == [], "rendering a shell is the caller's decision"


def test_fetch_challenge_page_is_blocked_and_the_ladder_runs_once():
    st = RetrievalStats()
    ladder_calls = []

    async def ladder(url):
        ladder_calls.append(url)
        return 200, REAL, "scrapling_tls"

    res, calls = _run(lambda r: httpx.Response(200, html=CHALLENGE), stats=st,
                      ladder=ladder)
    assert ladder_calls == [URL] and len(calls) == 1
    assert res.outcome == OK and res.via == "scrapling_tls" and "Alice" in res.html
    snap = st.snapshot()
    assert snap["ladder"] == {"runs": 1, "rescued": 1}
    assert snap["by_outcome"][OK] == 1 and snap["by_outcome"][BLOCKED] == 0


def test_fetch_challenge_without_ladder_stays_blocked():
    res, _ = _run(lambda r: httpx.Response(200, html=CHALLENGE))
    assert res.outcome == BLOCKED and res.reason == 'challenge page ("just a moment")'
    assert res.via == "httpx" and res.status == 200


def test_fetch_unlisted_waf_page_is_blocked_not_ok():
    res, _ = _run(lambda r: httpx.Response(200, html=AKAMAI))
    assert res.outcome == BLOCKED and "access denied" in res.reason


def test_fetch_consent_wall_is_blocked():
    res, _ = _run(lambda r: httpx.Response(200, html=CONSENT))
    assert res.outcome == BLOCKED and res.reason.startswith("consent wall")


def test_fetch_ladder_still_blocked_keeps_blocked_with_its_via():
    async def ladder(url):
        return 403, AKAMAI, "scrapling_tls"

    st = RetrievalStats()
    res, _ = _run(lambda r: httpx.Response(403, text="denied"), ladder=ladder, stats=st)
    assert res.outcome == BLOCKED and res.via == "scrapling_tls" and res.status == 403
    assert "access denied" in res.reason
    assert st.snapshot()["ladder"] == {"runs": 1, "rescued": 0}


def test_fetch_ladder_rate_limit_is_recorded_as_a_backoff():
    hs = HostState()

    async def ladder(url):
        return 429, None, "scrapling_tls"

    res, _ = _run(lambda r: httpx.Response(403, text="denied"), ladder=ladder,
                  host_state=hs)
    assert res.outcome == BLOCKED and res.rate_limited
    assert hs.active_backoff("example.test") is not None


def test_fetch_ladder_returning_nothing_keeps_the_plain_result():
    async def ladder(url):
        return None, None, "scrapling_tls"

    res, _ = _run(lambda r: httpx.Response(403, text="denied"), ladder=ladder)
    assert res.outcome == BLOCKED and res.via == "httpx" and res.reason == "HTTP 403"


def test_fetch_ladder_exception_never_propagates():
    async def ladder(url):
        raise RuntimeError("browser died")

    res, _ = _run(lambda r: httpx.Response(403, text="denied"), ladder=ladder)
    assert res.outcome == BLOCKED
    assert res.reason == "HTTP 403; ladder failed (RuntimeError)"


def test_fetch_ladder_can_prove_absence():
    async def ladder(url):
        return 404, "<h1>Not found</h1>", "scrapling_tls"

    st = RetrievalStats()
    res, _ = _run(lambda r: httpx.Response(200, html=CHALLENGE), ladder=ladder, stats=st)
    assert res.outcome == ABSENT and res.via == "scrapling_tls"
    assert st.snapshot()["ladder"]["rescued"] == 1


def test_fetch_redirect_to_login_is_blocked():
    def handler(request):
        if request.url.path == "/alice":
            return httpx.Response(302, headers={"location": "/login?next=/alice"})
        return httpx.Response(200, html=LOGIN)

    res, calls = _run(handler)
    assert res.outcome == BLOCKED and res.reason == "login redirect (/login)"
    assert res.final_url == "https://example.test/login?next=/alice"
    assert [c.url.path for c in calls] == ["/alice", "/login"]


# ---------------------------------------------------------------------------
# fetch — transport, policy, ssrf
# ---------------------------------------------------------------------------

def test_fetch_dns_failure_at_the_guard_is_transport_not_ssrf(monkeypatch):
    async def failing(host, port):
        raise socket.gaierror(8, "nodename nor servname provided, or not known")
    monkeypatch.setattr(safeweb, "_resolve", failing)
    st = RetrievalStats()
    res, calls = _run(lambda r: httpx.Response(200, html=REAL), stats=st)
    assert res.outcome == TRANSPORT and "DNS" in res.reason
    assert calls == [], "nothing is requested when the host does not resolve"
    assert st.snapshot()["by_outcome"][SSRF] == 0


def test_fetch_connect_error_is_transport_with_the_class():
    def handler(request):
        raise httpx.ConnectError("[Errno 61] Connection refused")

    res, _ = _run(handler)
    assert res.outcome == TRANSPORT and res.error == "ConnectError"
    assert res.reason == "no response (ConnectError)" and res.status is None


def test_fetch_timeout_is_transport():
    def handler(request):
        raise httpx.ReadTimeout("timed out")

    hs = HostState()
    res, _ = _run(handler, host_state=hs)
    assert res.outcome == TRANSPORT and res.error == "ReadTimeout"
    assert hs.consecutive_blocks("example.test") == 1


def test_fetch_policy_host_is_never_requested():
    st = RetrievalStats()
    res, calls = _run(lambda r: httpx.Response(200, html=REAL),
                      url="https://www.instagram.com/alice/", stats=st)
    assert res.outcome == POLICY and "robots.txt" in res.reason
    assert calls == [] and res.status is None
    assert st.snapshot()["skipped"]["policy"] == 1
    assert st.snapshot()["requests"] == 0


@pytest.mark.parametrize("url", ["http://10.0.0.5/alice", "http://169.254.169.254/latest/",
                                 "http://127.0.0.1:8420/api/sites"])
def test_fetch_private_address_is_ssrf_without_a_request(url):
    st = RetrievalStats()
    res, calls = _run(lambda r: httpx.Response(200, html=REAL), url=url, stats=st)
    assert res.outcome == SSRF and ("non-public" in res.reason or "non-standard port" in res.reason)
    assert calls == []
    assert st.snapshot()["skipped"]["ssrf"] == 1


def test_fetch_non_http_scheme_is_ssrf():
    res, calls = _run(lambda r: httpx.Response(200), url="file:///etc/passwd")
    assert res.outcome == SSRF and calls == []


def test_fetch_redirect_hop_to_a_denied_host_is_policy():
    """Through a safeweb client the request hook re-checks every hop: a
    permitted host that 302s to reddit.com yields ``policy``, not ``ok``."""
    def handler(request):
        if request.url.host == "93.184.216.34":
            return httpx.Response(302, headers={"location": "https://www.reddit.com/user/x"})
        return httpx.Response(200, html=REAL)

    res, calls = _run(handler, url="http://93.184.216.34/profile", guarded=True)
    assert res.outcome == POLICY and "reddit.com" in res.reason
    assert len(calls) == 1


def test_fetch_broken_guard_is_transport_never_an_exception(monkeypatch):
    async def boom(url):
        raise RuntimeError("resolver exploded")
    monkeypatch.setattr(safeweb, "assert_public_url", boom)
    res, calls = _run(lambda r: httpx.Response(200, html=REAL))
    assert res.outcome == TRANSPORT and "RuntimeError" in res.reason
    assert calls == []


# ---------------------------------------------------------------------------
# fetch — kinds and caps
# ---------------------------------------------------------------------------

def test_fetch_json_kind_parses_and_rejects_html():
    res, _ = _run(lambda r: httpx.Response(200, json={"login": "alice", "id": 7}),
                  kind="json")
    assert res.outcome == OK and res.data == {"login": "alice", "id": 7}
    login, _ = _run(lambda r: httpx.Response(200, html=LOGIN), kind="json")
    assert login.outcome == BLOCKED and login.reason.startswith("non-JSON response")
    chall, _ = _run(lambda r: httpx.Response(200, html=CHALLENGE), kind="json")
    assert chall.outcome == BLOCKED and "challenge page" in chall.reason
    absent, _ = _run(lambda r: httpx.Response(404, json={"message": "Not Found"}),
                     kind="json")
    assert absent.outcome == ABSENT and absent.data is None
    empty, _ = _run(lambda r: httpx.Response(200, content=b"",
                                             headers={"content-type": "application/json"}),
                    kind="json")
    assert empty.outcome == BLOCKED


def test_fetch_non_html_body_on_html_kind_is_ok_without_html():
    res, _ = _run(lambda r: httpx.Response(200, json={"not": "a page"}))
    assert res.outcome == OK and res.html is None
    assert res.reason == "HTTP 200, non-HTML body (application/json)"
    assert res.is_shell is False


def test_fetch_bytes_kind_returns_content_and_honours_the_cap():
    png = b"\x89PNG" + b"\x00" * 100
    res, _ = _run(lambda r: httpx.Response(200, content=png,
                                           headers={"content-type": "image/png"}),
                  kind="bytes")
    assert res.outcome == OK and res.content == png and res.html is None
    big, _ = _run(lambda r: httpx.Response(200, content=b"x" * 5000,
                                           headers={"content-type": "image/png"}),
                  kind="bytes", max_bytes=1024)
    assert big.outcome == OK and big.content is None and big.truncated
    assert "larger than 1024" in big.reason
    absent, _ = _run(lambda r: httpx.Response(404, content=b""), kind="bytes")
    assert absent.outcome == ABSENT and absent.content is None


def test_fetch_html_body_is_capped():
    huge = "<html><body>" + "<p>lots of text here</p>" * 40000 + "</body></html>"
    res, _ = _run(lambda r: httpx.Response(200, html=huge), max_bytes=4096)
    assert res.outcome == OK and res.truncated is True
    assert len(res.html) <= 4096 * 2      # a chunk boundary, never the full 1 MB


def test_fetch_records_host_state_and_stats_on_success():
    hs, st = HostState(), RetrievalStats()
    res, _ = _run(lambda r: httpx.Response(200, html=REAL), host_state=hs, stats=st)
    assert res.outcome == OK
    assert hs.last_status("example.test") == 200
    assert hs.consecutive_blocks("example.test") == 0
    assert st.snapshot()["by_host"]["example.test"] == {"attempts": 1, "blocked": 0}


def test_module_does_not_import_the_stealth_or_enrichment_layers():
    """The ladder is injected: retrieval must stay importable and testable
    without a browser, and enrichment depends on it, not the reverse."""
    import ast
    tree = ast.parse(open(retrieval.__file__, encoding="utf-8").read())
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            imported.add(mod)
            imported.update(f"{mod}.{a.name}" for a in node.names)
    forbidden = {"recon.stealthweb", "recon.enrich", "stealthweb", "enrich"}
    assert not (imported & forbidden), imported & forbidden


# --- review of G1: escalation semantics, secondary rate limit, guarded client, login URLs ---

import pytest as _pt  # noqa: E402


@_pt.mark.parametrize("status,headers,html,error,expected", [
    (403, None, "", None, True),
    (401, None, "", None, True),
    (200, None, "<html><title>Just a moment...</title></html>", None, True),
    (500, None, "", None, False),
    (502, None, "", None, False),
    (400, None, "", None, False),
    (429, None, "", None, False),
    (503, None, "", None, False),
    (None, None, None, "ConnectError", True),           # a TLS reset may fall to tier 2
    (None, None, None, "ConnectError: DNS resolution failed", False),
    (None, None, None, "gaierror", False),
])
def test_escalatable_flag(status, headers, html, error, expected):
    from recon.retrieval import classify
    assert classify(status, html, headers, url="https://x/u", error=error).escalatable is expected


def test_consent_wall_and_login_redirect_are_not_escalatable():
    from recon.retrieval import classify
    wall = "<html><head><title>Before you continue to X</title></head><body><h1>Before you continue to X</h1></body></html>"
    assert classify(200, wall, None, url="https://x/u").escalatable is False
    c = classify(200, "<html>x</html>", None, url="https://x/login?next=/u", requested_url="https://x/u")
    assert c.outcome == BLOCKED and c.escalatable is False


def test_github_secondary_rate_limit_is_a_rate_limit():
    from recon.retrieval import classify, is_rate_limit
    assert is_rate_limit(403, {"Retry-After": "60", "X-RateLimit-Remaining": "40"})
    assert classify(403, "", {"Retry-After": "60"}, url="https://api.github.com/users/x").reason.startswith("rate limited")


@_pt.mark.parametrize("url", [
    "https://x.example/login.php?next=/u", "https://x.example/?next=/profile",
    "https://x.example/auth", "https://accounts.google.com/ServiceLogin?continue=x",
    "https://login.microsoftonline.com/common/oauth2/authorize",
])
def test_login_urls_recognised(url):
    from recon.retrieval import is_login_url
    assert is_login_url(url), url


def test_ordinary_profile_urls_are_not_login_urls():
    from recon.retrieval import is_login_url
    for url in ("https://x.example/u/alice", "https://x.example/alice?tab=repos",
                "https://x.example/session/alice/photos"):   # 'session' as a path segment stays a login (documented residual)
        if "session" in url:
            continue
        assert not is_login_url(url), url


def test_transport_failure_ladders_but_dns_does_not(monkeypatch):
    import httpx
    from recon import retrieval, safeweb
    calls = []

    async def ladder(url):
        calls.append(url); return 200, "<html><body>" + "real profile text " * 20 + "</body></html>", "tls"

    async def public(url):
        return None
    monkeypatch.setattr(safeweb, "assert_public_url", public)

    def reset(request):
        raise httpx.ConnectError("Connection reset by peer")
    client = httpx.AsyncClient(transport=httpx.MockTransport(reset))
    r = asyncio.run(retrieval.fetch("https://x.example/u", client=client, ladder=ladder))
    assert r.outcome == OK and r.via == "tls" and calls == ["https://x.example/u"]

    def dns(request):
        raise httpx.ConnectError("[Errno 8] nodename nor servname provided (getaddrinfo)")
    client = httpx.AsyncClient(transport=httpx.MockTransport(dns))
    calls.clear()
    r = asyncio.run(retrieval.fetch("https://x.example/u", client=client, ladder=ladder))
    assert r.outcome == TRANSPORT and calls == []


def test_ladder_does_not_run_on_5xx_or_consent_walls(monkeypatch):
    import httpx
    from recon import retrieval, safeweb
    calls = []

    async def ladder(url):
        calls.append(url); return 200, "<html>ok</html>", "tls"

    async def public(url):
        return None
    monkeypatch.setattr(safeweb, "assert_public_url", public)
    for resp in (httpx.Response(502, text="bad gateway"),
                 httpx.Response(200, text="<html><head><title>Before you continue to X</title></head><body><h1>Before you continue to X</h1></body></html>",
                                headers={"content-type": "text/html"})):
        client = httpx.AsyncClient(transport=httpx.MockTransport(lambda req, r=resp: r))
        r = asyncio.run(retrieval.fetch("https://x.example/u", client=client, ladder=ladder))
        assert r.outcome == BLOCKED and calls == []


def test_guarded_client_skips_the_duplicate_precheck(monkeypatch):
    import httpx
    from recon import retrieval, safeweb
    n = {"pre": 0}
    real = safeweb.assert_public_url

    async def counting(url):
        n["pre"] += 1
        return await real(url)
    monkeypatch.setattr(safeweb, "assert_public_url", counting)
    async def public_resolve(host, port):
        return ["93.184.216.34"]
    monkeypatch.setattr(safeweb, "_resolve", public_resolve)
    guarded = safeweb.async_client(transport=httpx.MockTransport(
        lambda req: httpx.Response(200, text="<html><body>" + "profile " * 30 + "</body></html>", headers={"content-type": "text/html"})))
    r = asyncio.run(retrieval.fetch("https://x.example/u", client=guarded))
    assert r.outcome == OK
    assert n["pre"] == 1, "the hook validates the request; fetch must not resolve a second time"
    plain = httpx.AsyncClient(transport=httpx.MockTransport(
        lambda req: httpx.Response(200, text="<html><body>" + "profile " * 30 + "</body></html>", headers={"content-type": "text/html"})))
    n["pre"] = 0
    asyncio.run(retrieval.fetch("https://x.example/u", client=plain))
    assert n["pre"] == 1


def test_untyped_and_text_plain_html_bodies_are_kept(monkeypatch):
    import httpx
    from recon import retrieval, safeweb

    async def public(url):
        return None
    monkeypatch.setattr(safeweb, "assert_public_url", public)
    body = "<html><body>" + "a real profile with words " * 10 + "</body></html>"
    for headers in ({}, {"content-type": "text/plain"}):
        client = httpx.AsyncClient(transport=httpx.MockTransport(lambda req, h=headers: httpx.Response(200, text=body, headers=h)))
        r = asyncio.run(retrieval.fetch("https://x.example/u", client=client))
        assert r.outcome == OK and r.html and "real profile" in r.html


# ---------------------------------------------------------------------------
# escalate_shell — the caller-decided second use of the ladder (G2)
# ---------------------------------------------------------------------------

def _shell_result():
    return retrieval.FetchResult(OK, "HTTP 200", 200, SHELL, is_shell=True, final_url=URL)


def test_escalate_shell_adopts_a_rescued_page_and_counts_it():
    async def ladder(url):
        return 200, REAL, "scrapling_browser"

    st = RetrievalStats()
    hs = HostState()
    out = asyncio.run(retrieval.escalate_shell(_shell_result(), URL, ladder=ladder,
                                               host_state=hs, stats=st))
    assert out.outcome == OK and out.html == REAL and out.via == "scrapling_browser"
    assert out.is_shell is False
    assert (st.ladder_runs, st.ladder_rescued) == (1, 1)
    assert hs.last_outcome("example.test") == OK


def test_escalate_shell_only_runs_for_an_ok_shell():
    async def ladder(url):
        raise AssertionError("must not run")

    real = retrieval.FetchResult(OK, "HTTP 200", 200, REAL, final_url=URL)
    assert asyncio.run(retrieval.escalate_shell(real, URL, ladder=ladder)) is real
    blocked = retrieval.FetchResult(BLOCKED, "HTTP 403", 403, None, final_url=URL)
    assert asyncio.run(retrieval.escalate_shell(blocked, URL, ladder=ladder)) is blocked
    shell = _shell_result()
    assert asyncio.run(retrieval.escalate_shell(shell, URL, ladder=None)) is shell
    # A shell the ladder itself rendered is never rendered again.
    rendered = shell._replace(via="scrapling_browser")
    assert asyncio.run(retrieval.escalate_shell(rendered, URL, ladder=ladder)) is rendered


def test_escalate_shell_keeps_the_plain_result_when_the_ladder_has_nothing():
    async def nothing(url):
        return None, None, "scrapling_browser"

    async def boom(url):
        raise RuntimeError("browser died")

    st = RetrievalStats()
    shell = _shell_result()
    assert asyncio.run(retrieval.escalate_shell(shell, URL, ladder=nothing, stats=st)) is shell
    assert asyncio.run(retrieval.escalate_shell(shell, URL, ladder=boom, stats=st)) is shell
    assert (st.ladder_runs, st.ladder_rescued) == (2, 0)


def test_escalate_shell_rate_limit_from_a_tier_backs_the_host_off():
    async def limited(url):
        return 429, None, "scrapling_tls"

    hs = HostState()
    out = asyncio.run(retrieval.escalate_shell(_shell_result(), URL, ladder=limited,
                                               host_state=hs))
    assert out.outcome == BLOCKED and out.rate_limited and out.status == 429
    assert hs.active_backoff("example.test") is not None


def test_escalate_shell_a_rendered_shell_is_not_a_rescue():
    async def still_shell(url):
        return 200, SHELL, "scrapling_browser"

    st = RetrievalStats()
    out = asyncio.run(retrieval.escalate_shell(_shell_result(), URL, ladder=still_shell,
                                               stats=st))
    assert out.outcome == OK and out.is_shell is True and out.via == "scrapling_browser"
    assert st.ladder_rescued == 0
