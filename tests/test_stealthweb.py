"""Pure-function coverage for the stealth fetch ladder (no network)."""

import asyncio
import inspect

import pytest

from recon import stealthweb, safeweb
from recon.safeweb import BlockedRequestError

RICH_PAGE = (
    "<html><head><title>octocat · GitHub</title></head><body>"
    + "Followers 1k, repositories, bio text. " * 20
    + "</body></html>"
)
SHELL_PAGE = (
    '<html><head><title>App</title></head>'
    '<body><div id="root"></div><script>window.boot();</script></body></html>'
)
CHALLENGE_PAGE = (
    "<html><head><title>Just a moment...</title></head>"
    "<body>Checking your browser before accessing the site.</body></html>"
)
AKAMAI_PAGE = (
    "<html><head><title>Access Denied</title></head><body><h1>Access Denied</h1>"
    "<p>You don't have permission to access \"http://www.example.com/johnsmith77\" "
    "on this server.</p><p>Reference #18.4f1d2c17.1725600000.1a2b3c4d</p></body></html>"
)
IMPERVA_PAGE = (
    "<html><head><title>Pardon Our Interruption</title></head><body>"
    "<h1>Pardon Our Interruption...</h1><p>As you were browsing something about your "
    "browser made us think you were a bot. There are a few reasons this might happen.</p>"
    "<p>Incapsula incident ID: 123-456</p></body></html>"
)


# ---------------------------------------------------------------------------
# escalation decision
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", [403, 407, 500])
def test_blocked_statuses_escalate(status):
    assert stealthweb.should_escalate(status, None) is True


@pytest.mark.parametrize("status", [429, 503])
def test_rate_limits_never_escalate(status):
    # V7: a rate limit is answered by backing off. Before this, a 429 triggered
    # two more disguised requests to the same host within seconds — even when
    # the 429 body looked like a challenge page.
    assert stealthweb.should_escalate(status, None) is False
    assert stealthweb.should_escalate(status, CHALLENGE_PAGE) is False


@pytest.mark.parametrize("status", [404, 410])
def test_decisive_absence_never_escalates(status):
    # Absence is already decisive — never spend stealth fetches on it.
    assert stealthweb.should_escalate(status, None) is False


def test_success_does_not_escalate():
    assert stealthweb.should_escalate(200, RICH_PAGE) is False


def test_transport_failure_escalates_once():
    assert stealthweb.should_escalate(None, None) is True


def test_challenge_page_escalates():
    assert stealthweb.should_escalate(200, CHALLENGE_PAGE) is True


def test_unlisted_waf_pages_now_escalate():
    # V2: Akamai and Imperva pages had > 80 visible chars and no listed marker,
    # so the ladder never ran for them and verification called them refuted/lead.
    assert stealthweb.should_escalate(200, AKAMAI_PAGE) is True
    assert stealthweb.should_escalate(200, IMPERVA_PAGE) is True


def test_js_shell_escalates():
    assert stealthweb.should_escalate(200, SHELL_PAGE) is True


def test_challenge_markers_detected():
    assert stealthweb.has_challenge_markers(CHALLENGE_PAGE) is True
    assert stealthweb.has_challenge_markers(RICH_PAGE) is False
    assert stealthweb.has_challenge_markers(None) is False


def test_shell_detection_bounds_false_positives():
    assert stealthweb.looks_like_shell(SHELL_PAGE) is True
    assert stealthweb.looks_like_shell(None) is False
    # A modest but real page (bio-ish text over the threshold) stays a page.
    small_real = ("<html><body>"
                  + "Welcome to my corner of the internet. " * 3
                  + "</body></html>")
    assert stealthweb.looks_like_shell(small_real) is False


def test_page_helpers_are_the_shared_ones():
    # D6: one list, one text helper — stealthweb re-exports recon.htmltext.
    from recon import htmltext
    assert stealthweb.visible_text is htmltext.visible_text
    assert stealthweb.has_challenge_markers is htmltext.has_challenge_markers
    assert stealthweb.looks_like_shell is htmltext.looks_like_shell
    assert stealthweb.CHALLENGE_MARKERS is htmltext.CHALLENGE_MARKERS


# ---------------------------------------------------------------------------
# kill switch
# ---------------------------------------------------------------------------


def test_disabled_by_env(monkeypatch):
    monkeypatch.setenv("RECON_STEALTH", "off")
    assert stealthweb.enabled() is False
    assert asyncio.run(stealthweb.fetch_tls("https://github.com/octocat")) == (
        None,
        None,
    )
    assert asyncio.run(
        stealthweb.fetch_browser("https://github.com/octocat")
    ) == (None, None)


@pytest.mark.skipif(not stealthweb._IMPORTABLE, reason="scrapling not installed")
def test_enabled_by_default(monkeypatch):
    monkeypatch.delenv("RECON_STEALTH", raising=False)
    assert stealthweb.enabled() is True


@pytest.mark.skipif(stealthweb._IMPORTABLE, reason="scrapling installed")
def test_enabled_without_dependency_is_false(monkeypatch):
    monkeypatch.delenv("RECON_STEALTH", raising=False)
    assert stealthweb.enabled() is False


# ---------------------------------------------------------------------------
# SSRF pre-check shared with the non-httpx tiers
# ---------------------------------------------------------------------------


def _run(url):
    return asyncio.run(safeweb.assert_public_url(url))


def test_assert_public_url_blocks_metadata():
    with pytest.raises(BlockedRequestError):
        _run("http://169.254.169.254/latest/meta-data/")


def test_assert_public_url_blocks_loopback_literal():
    with pytest.raises(BlockedRequestError):
        _run("http://127.0.0.1:8420/api/sites")


def test_assert_public_url_blocks_non_http_scheme():
    with pytest.raises(BlockedRequestError):
        _run("file:///etc/passwd")


def test_assert_public_url_blocks_non_standard_port():
    with pytest.raises(BlockedRequestError):
        _run("http://8.8.8.8:8080/")


def test_assert_public_url_blocks_embedded_credentials():
    with pytest.raises(BlockedRequestError):
        _run("http://admin:pass@8.8.8.8/")


def test_assert_public_url_allows_standard_ports():
    _run("http://8.8.8.8:80/")
    _run("https://8.8.8.8:443/")


def test_assert_public_url_allows_public_ip_literal():
    # No network call — an IP literal is validated without resolving.
    _run("http://8.8.8.8/")


# --- tier-3 session lifecycle (regression) ----------------------------------

def _reset_session_state(monkeypatch):
    monkeypatch.setattr(stealthweb, "_session", None)
    monkeypatch.setattr(stealthweb, "_session_dead", False)
    monkeypatch.setattr(stealthweb, "_session_lock", None)
    monkeypatch.setattr(stealthweb, "_fetch_lock", None)
    monkeypatch.setattr(stealthweb, "_last_host", None)


def test_session_is_started_not_just_constructed(monkeypatch):
    """AsyncStealthySession only records options in its constructor — without
    an awaited start() every fetch raises "Context manager has been closed"
    and tier 3 silently returns nothing. This regression guards that await."""
    started = {"n": 0}

    class _FakeSession:
        def __init__(self, **kw):
            self.kwargs = kw

        async def start(self):
            started["n"] += 1

        async def close(self):
            pass

    monkeypatch.setattr(stealthweb, "AsyncStealthySession", _FakeSession)
    _reset_session_state(monkeypatch)

    session = asyncio.run(stealthweb._get_session())
    assert session is not None
    assert started["n"] == 1, "start() was never awaited — tier 3 would be dead"
    # The cost-cutting options must survive.
    assert session.kwargs.get("disable_resources") is True
    assert session.kwargs.get("block_ads") is True


def test_session_posture_never_solves_challenges_or_forges_referers(monkeypatch):
    """F-7 (owner decision): the browser tier renders pages, it does not click
    Turnstile boxes or pretend to arrive from Google. F-12: no downloads."""
    class _FakeSession:
        def __init__(self, **kw):
            self.kwargs = kw

        async def start(self):
            pass

    monkeypatch.setattr(stealthweb, "AsyncStealthySession", _FakeSession)
    _reset_session_state(monkeypatch)
    session = asyncio.run(stealthweb._get_session())
    assert session.kwargs.get("solve_cloudflare") is False
    assert session.kwargs.get("google_search") is False
    assert session.kwargs.get("additional_args", {}).get("accept_downloads") is False
    # The declared options are what is used (inspectable without a browser).
    assert stealthweb.SESSION_OPTIONS["solve_cloudflare"] is False
    assert stealthweb.SESSION_OPTIONS["google_search"] is False


def test_failed_start_disables_tier3_instead_of_raising(monkeypatch):
    """A missing browser binary must degrade to 'tier 3 off', never crash."""
    class _Boom:
        def __init__(self, **kw):
            pass

        async def start(self):
            raise RuntimeError("Executable doesn't exist")

    monkeypatch.setattr(stealthweb, "AsyncStealthySession", _Boom)
    _reset_session_state(monkeypatch)

    assert asyncio.run(stealthweb._get_session()) is None
    assert stealthweb._session_dead is True
    monkeypatch.setattr(stealthweb, "_session_dead", False)


class _RecordingContext:
    def __init__(self):
        self.cleared = 0

    async def clear_cookies(self):
        self.cleared += 1


class _RecordingSession:
    def __init__(self):
        self.calls = []
        self.context = _RecordingContext()

    async def fetch(self, url, **kw):
        self.calls.append((url, kw))

        class _R:
            status = 200
            html_content = "<html>ok</html>"
        return _R()


def _install_fake_session(monkeypatch):
    session = _RecordingSession()

    async def _fake_get_session():
        return session

    async def _ok(url):
        return None

    monkeypatch.setattr(stealthweb, "_get_session", _fake_get_session)
    monkeypatch.setattr(stealthweb, "enabled", lambda: True)
    monkeypatch.setattr(safeweb, "assert_public_url", _ok)
    _reset_session_state(monkeypatch)
    return session


def test_cloudflare_solver_is_never_enabled(monkeypatch):
    """Replaces the old opt-in test: there is no longer any way to turn the
    solver on from fetch_browser, and every fetch says so explicitly."""
    session = _install_fake_session(monkeypatch)
    assert "solve_cloudflare" not in inspect.signature(stealthweb.fetch_browser).parameters
    assert asyncio.run(stealthweb.fetch_browser("https://example.com")) == (200, "<html>ok</html>")
    _, kw = session.calls[0]
    assert kw.get("solve_cloudflare") is False
    assert kw.get("google_search") is False
    with pytest.raises(TypeError):
        asyncio.run(stealthweb.fetch_browser("https://example.com", solve_cloudflare=True))


def test_cookies_are_cleared_when_the_target_host_changes(monkeypatch):
    """F-12: one persistent context serves the whole run; site A's cookies must
    not accompany the request to site B."""
    session = _install_fake_session(monkeypatch)
    asyncio.run(stealthweb.fetch_browser("https://a.example/one"))
    asyncio.run(stealthweb.fetch_browser("https://a.example/two"))
    assert session.context.cleared == 0          # same host: nothing to clear
    asyncio.run(stealthweb.fetch_browser("https://b.example/three"))
    assert session.context.cleared == 1
    asyncio.run(stealthweb.fetch_browser("https://a.example/four"))
    assert session.context.cleared == 2
    assert len(session.calls) == 4


def test_cookie_clear_failure_does_not_fail_the_fetch(monkeypatch):
    session = _install_fake_session(monkeypatch)

    async def _boom():
        raise RuntimeError("context gone")
    session.context.clear_cookies = _boom
    asyncio.run(stealthweb.fetch_browser("https://a.example/"))
    assert asyncio.run(stealthweb.fetch_browser("https://b.example/")) == (200, "<html>ok</html>")
