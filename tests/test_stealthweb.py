"""Pure-function coverage for the stealth fetch ladder (no network)."""

import asyncio

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


# ---------------------------------------------------------------------------
# escalation decision
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", [403, 407, 429, 500, 503])
def test_blocked_statuses_escalate(status):
    assert stealthweb.should_escalate(status, None) is True


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


def test_assert_public_url_allows_public_ip_literal():
    # No network call — an IP literal is validated without resolving.
    _run("http://8.8.8.8/")


# --- tier-3 session lifecycle (regression) ----------------------------------

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
    monkeypatch.setattr(stealthweb, "_session", None)
    monkeypatch.setattr(stealthweb, "_session_dead", False)
    monkeypatch.setattr(stealthweb, "_session_lock", None)

    session = asyncio.run(stealthweb._get_session())
    assert session is not None
    assert started["n"] == 1, "start() was never awaited — tier 3 would be dead"
    # The cost-cutting options must survive.
    assert session.kwargs.get("disable_resources") is True
    assert session.kwargs.get("block_ads") is True


def test_failed_start_disables_tier3_instead_of_raising(monkeypatch):
    """A missing browser binary must degrade to 'tier 3 off', never crash."""
    class _Boom:
        def __init__(self, **kw):
            pass

        async def start(self):
            raise RuntimeError("Executable doesn't exist")

    monkeypatch.setattr(stealthweb, "AsyncStealthySession", _Boom)
    monkeypatch.setattr(stealthweb, "_session", None)
    monkeypatch.setattr(stealthweb, "_session_dead", False)
    monkeypatch.setattr(stealthweb, "_session_lock", None)

    assert asyncio.run(stealthweb._get_session()) is None
    assert stealthweb._session_dead is True
    monkeypatch.setattr(stealthweb, "_session_dead", False)


def test_cloudflare_solver_is_opt_in(monkeypatch):
    """The solver forces a 60s timeout ceiling, so it must default to off."""
    seen = {}

    class _Session:
        async def fetch(self, url, **kw):
            seen.update(kw)

            class _R:
                status = 200
                html_content = "<html>ok</html>"
            return _R()

    async def _fake_get_session():
        return _Session()

    monkeypatch.setattr(stealthweb, "_get_session", _fake_get_session)

    async def _ok(url):
        return None
    monkeypatch.setattr(safeweb, "assert_public_url", _ok)

    asyncio.run(stealthweb.fetch_browser("https://example.com"))
    assert seen.get("solve_cloudflare") is False
    asyncio.run(stealthweb.fetch_browser("https://example.com",
                                         solve_cloudflare=True))
    assert seen.get("solve_cloudflare") is True
