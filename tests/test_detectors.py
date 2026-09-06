"""Content-based HTML detector tests (no network: pure marker/status logic and
an ``httpx.MockTransport`` behind the real SSRF-guarded client — G2 routed
every detector fetch through ``recon.retrieval.fetch``)."""

import asyncio

import httpx
import pytest
from conftest import mock_client

from recon import detectors, policy, retrieval, sources, stealthweb
from recon.ladder import StealthLadder

MARKER = "<html><div class='tgme_page_title'>Pavel</div></html>"
# What a rendered real profile looks like: the marker plus enough visible text
# not to read as a JS shell (a rescue in the ladder's sense).
RENDERED = ("<html><div class='tgme_page_title'>Pavel Durov</div>"
            "<div class='tgme_page_description'>" + "Founder of Telegram. " * 8
            + "</div></html>")
SHELL = "<html><body><div id=root></div></body></html>"
WALL = ("<html><head><title>Just a moment...</title></head><body>"
        "Checking your browser before accessing</body></html>")


@pytest.fixture(autouse=True)
def _dns(public_dns):
    """Every fetch here is offline: the guard resolves to a public address."""


def _html(body, status=200, headers=None):
    h = {"content-type": "text/html; charset=utf-8"}
    if headers:
        h.update(headers)
    return httpx.Response(status, headers=h, text=body)


def _install(monkeypatch, handler, calls=None):
    monkeypatch.setattr(detectors.safeweb, "async_client", mock_client(handler, calls))


def _stealth(monkeypatch, tls, browser):
    monkeypatch.setattr(stealthweb, "enabled", lambda: True)
    monkeypatch.setattr(stealthweb, "fetch_tls", tls)
    monkeypatch.setattr(stealthweb, "fetch_browser", browser)


def test_no_detector_targets_a_denied_host():
    """A detector must never be registered for a robots-denied host."""
    for d in detectors.DETECTORS:
        url = d.profile_url("probe")
        assert not policy.is_denied(url), f"{d.name} targets a denied host"


def test_every_detector_source_is_registered_with_its_host():
    for d in detectors.DETECTORS:
        src = sources.get(d.source)
        assert src is not None, f"{d.name}: source {d.source!r} not in the registry"
        host = httpx.URL(d.profile_url("probe")).host
        assert retrieval.host_key(src.host) == retrieval.host_key(host), d.name


def test_telegram_marker_discriminates():
    t = detectors.detector_for("Telegram")
    assert t is not None
    assert t.classify(200, "<div class='tgme_page_title'>Pavel</div>") == detectors.EXISTS
    # A nonexistent handle returns a bare contact page with no marker.
    assert t.classify(200, "<title>Telegram: Contact @nobody</title>") == detectors.ABSENT
    assert t.classify(404, "") == detectors.ABSENT


def test_steam_present_and_absent_markers():
    s = detectors.detector_for("Steam")
    assert s.classify(200, "var g_rgProfileData = {'x':1}") == detectors.EXISTS
    assert s.classify(200, "The specified profile could not be found.") == detectors.ABSENT
    # A 5xx is genuinely unknown, never "absent".
    assert s.classify(503, "") == detectors.BLOCKED
    assert s.classify(None, None) == detectors.BLOCKED


def test_gravatar_status_based():
    g = detectors.detector_for("Gravatar")
    assert g.classify(200, '<meta property="og:image" content="x">') == detectors.EXISTS
    assert g.classify(404, "") == detectors.ABSENT


def test_detector_policy_gate_blocks_denied_host(monkeypatch):
    """A denied host is reported blocked and never fetched."""
    d = detectors.HtmlDetector("FakeInsta", ("fakeinsta",),
                               "https://instagram.com/{username}",
                               present=("x",))
    calls = []
    _install(monkeypatch, lambda req: _html("x"), calls)
    out = asyncio.run(d.check("someone"))
    assert out["status"] == detectors.BLOCKED
    assert out["signal"].startswith("policy:")
    assert calls == []


def test_discover_via_stubbed_fetch(monkeypatch):
    def handler(req):
        if req.url.host == "t.me":
            return _html("<html><div class='tgme_page_title'>Pavel Durov</div>"
                         "<meta property='og:title' content='Pavel Durov'></html>")
        return httpx.Response(404)

    _install(monkeypatch, handler)
    monkeypatch.setattr(stealthweb, "enabled", lambda: False)
    hits = asyncio.run(detectors.discover("durov"))
    assert len(hits) == 1
    assert hits[0]["site"] == "Telegram"
    assert hits[0]["url"] == "https://t.me/durov"
    assert hits[0]["identity"].get("display_name") == "Pavel Durov"


def test_discover_never_raises_and_empty_is_noop(monkeypatch):
    assert asyncio.run(detectors.discover("")) == []

    def boom(req):
        raise RuntimeError("net")
    _install(monkeypatch, boom)
    monkeypatch.setattr(stealthweb, "enabled", lambda: False)
    stats = {}
    assert asyncio.run(detectors.discover("someone", stats=stats)) == []
    assert all(v["status"] == detectors.BLOCKED for v in stats.values())
    assert all("RuntimeError" in v["signal"] for v in stats.values())


# --- outcome precedence: retrieval's verdict first, markers second -----------------

def test_outcome_precedence_blocked_before_markers():
    """A challenge page that happens to carry no present-marker used to be
    ABSENT (audit §2 item 7); a decisive absent needs no marker at all."""
    t = detectors.detector_for("Telegram")
    blocked = retrieval.FetchResult(retrieval.BLOCKED, 'challenge page ("just a moment")',
                                    200, "<title>Telegram: Contact @nobody</title>")
    assert t.outcome(blocked) == (detectors.BLOCKED, 'challenge page ("just a moment")')
    transport = retrieval.FetchResult(retrieval.TRANSPORT, "no response (ReadError)",
                                      None, None, "ReadError")
    assert t.outcome(transport) == (detectors.BLOCKED, "no response (ReadError)")
    absent = retrieval.FetchResult(retrieval.ABSENT, "HTTP 404", 404,
                                   "<html>whatever</html>")
    assert t.outcome(absent) == (detectors.ABSENT, None)
    ok = retrieval.FetchResult(retrieval.OK, "HTTP 200", 200, MARKER)
    assert t.outcome(ok) == (detectors.EXISTS, None)


def test_login_redirect_is_blocked_not_absent(monkeypatch):
    def handler(req):
        if req.url.path.startswith("/login"):
            return _html("<html><body>" + "<p>Please sign in to continue.</p>" * 8
                         + "</body></html>")
        return httpx.Response(302, headers={"location": "https://t.me/login?next=/x"})

    _install(monkeypatch, handler)
    monkeypatch.setattr(stealthweb, "enabled", lambda: False)
    out = asyncio.run(detectors.detector_for("Telegram").check("x"))
    assert out["status"] == detectors.BLOCKED
    assert "login redirect (/login)" in out["signal"]


# --- tier-3 escalation for JS-rendered / walled pages -----------------------
# The browser fakes accept only ``url``: the detector must never pass a solver
# flag (F-7) — a stray ``solve_cloudflare=`` would raise here.

def test_shell_page_escalates_to_the_browser(monkeypatch):
    """A JS shell must reach the real browser — otherwise `classify` calls a
    live account ABSENT (a false negative)."""
    calls = {"tls": 0, "browser": 0}
    _install(monkeypatch, lambda req: _html(SHELL))

    async def fake_tls(url):
        calls["tls"] += 1
        return 200, SHELL   # still a shell

    async def fake_browser(url):
        calls["browser"] += 1
        return 200, RENDERED

    _stealth(monkeypatch, fake_tls, fake_browser)
    t = detectors.detector_for("Telegram")
    ladder = StealthLadder(detectors.BROWSER_BUDGET)
    out = asyncio.run(t.check("durov", ladder=ladder))
    assert calls["tls"] == 1 and calls["browser"] == 1
    assert out["status"] == detectors.EXISTS   # rescued from a false ABSENT
    assert ladder.snapshot()["browser_ok"] == 1


def test_a_marker_on_a_short_rendered_page_still_decides(monkeypatch):
    """The browser may render a page whose visible text is tiny but whose
    markup carries the marker: the page is handed back for the marker check
    even though the ladder does not count it as a rescue."""
    _install(monkeypatch, lambda req: _html(SHELL))

    async def fake_tls(url):
        return 200, SHELL

    async def fake_browser(url):
        return 200, MARKER

    _stealth(monkeypatch, fake_tls, fake_browser)
    ladder = StealthLadder(1)
    out = asyncio.run(detectors.detector_for("Telegram").check("durov", ladder=ladder))
    assert out["status"] == detectors.EXISTS
    assert ladder.snapshot()["browser_ok"] == 0 and ladder.snapshot()["browser_attempts"] == 1


def test_browser_budget_is_per_ladder(monkeypatch):
    """The budget is the ladder's (one per sweep), not a module global."""
    _install(monkeypatch, lambda req: _html(SHELL))

    async def fake_tls(url):
        return 200, SHELL

    used = {"n": 0}

    async def fake_browser(url):
        used["n"] += 1
        return 200, SHELL

    _stealth(monkeypatch, fake_tls, fake_browser)
    t = detectors.detector_for("Telegram")
    ladder = StealthLadder(1)
    asyncio.run(t.check("a", ladder=ladder))
    asyncio.run(t.check("b", ladder=ladder))
    assert used["n"] == 1, "budget must cap browser escalations"
    assert ladder.snapshot()["browser_budget_left"] == 0


def test_concurrent_sweeps_do_not_reset_each_others_budget(monkeypatch):
    """Audit §6 "also noted": the module-global budget was reset by every
    ``discover`` call. Two sweeps now each spend their own budget of one."""
    _install(monkeypatch, lambda req: _html(SHELL))

    async def fake_tls(url):
        return 200, SHELL

    browser_urls = []

    async def fake_browser(url):
        browser_urls.append(url)
        return 200, SHELL

    _stealth(monkeypatch, fake_tls, fake_browser)
    monkeypatch.setattr(detectors, "DETECTORS", [detectors.detector_for("Telegram")])

    async def both():
        a = StealthLadder(1)
        b = StealthLadder(1)
        await asyncio.gather(detectors.discover("a", ladder=a),
                             detectors.discover("b", ladder=b))
        return a, b

    a, b = asyncio.run(both())
    assert sorted(browser_urls) == ["https://t.me/a", "https://t.me/b"]
    assert a.snapshot()["browser_budget_left"] == 0
    assert b.snapshot()["browser_budget_left"] == 0


def test_rate_limited_detector_is_blocked_without_escalation(monkeypatch):
    """V7 applies to detectors too: a 429 is BLOCKED (never ABSENT) and is not
    answered with a stealthier request."""
    calls = {"tls": 0, "browser": 0}
    _install(monkeypatch, lambda req: _html("<html><body>Too Many Requests</body></html>", 429))

    async def fake_tls(url):
        calls["tls"] += 1
        return 200, MARKER

    async def fake_browser(url):
        calls["browser"] += 1
        return 200, MARKER

    _stealth(monkeypatch, fake_tls, fake_browser)
    hs = retrieval.HostState()
    out = asyncio.run(detectors.detector_for("Telegram").check("durov", host_state=hs))
    assert out["status"] == detectors.BLOCKED
    assert "rate limited (HTTP 429)" in out["signal"]
    assert calls == {"tls": 0, "browser": 0}
    assert hs.active_backoff("t.me") is not None


def test_challenge_page_is_blocked_not_absent():
    """A walled detector used to answer ABSENT (and the circuit breaker
    recorded it as healthy)."""
    t = detectors.detector_for("Telegram")
    assert t.classify(200, WALL) == detectors.BLOCKED
    consent = "<html><head><title>Before you continue to Example</title></head><body><h1>Before you continue to Example</h1><p>We use cookies.</p></body></html>"
    assert t.classify(200, consent) == detectors.BLOCKED
    # A real marker on the page always wins over a stray phrase.
    assert t.classify(200, "<div class='tgme_page_title'>Just a moment</div>") == detectors.EXISTS


def test_walled_page_runs_the_ladder_once_and_stays_blocked_when_it_survives(monkeypatch):
    calls = {"tls": 0, "browser": 0}
    _install(monkeypatch, lambda req: _html(WALL))

    async def fake_tls(url):
        calls["tls"] += 1
        return 200, WALL

    async def fake_browser(url):
        calls["browser"] += 1
        return 200, WALL

    _stealth(monkeypatch, fake_tls, fake_browser)
    out = asyncio.run(detectors.detector_for("Telegram").check("durov"))
    assert out["status"] == detectors.BLOCKED
    assert 'challenge page ("just a moment")' in out["signal"]
    assert calls == {"tls": 1, "browser": 1}


def test_transport_failure_keeps_its_exception_class(monkeypatch):
    def boom(req):
        raise httpx.ConnectTimeout("slow")
    _install(monkeypatch, boom)
    monkeypatch.setattr(stealthweb, "enabled", lambda: False)
    out = asyncio.run(detectors.detector_for("Telegram").check("someone"))
    assert out["status"] == detectors.BLOCKED and "ConnectTimeout" in out["signal"]
    assert out["http_status"] is None


# --- the source registry sees every check --------------------------------------

def test_checks_are_recorded_against_the_source_registry(monkeypatch):
    sources.reset()
    _install(monkeypatch, lambda req: _html(MARKER))
    monkeypatch.setattr(stealthweb, "enabled", lambda: False)
    asyncio.run(detectors.detector_for("Telegram").check("durov"))
    h = sources.health("telegram")
    assert h["observations"] == 1 and h["failures"] == 0
    assert h["ewma_latency_ms"] is not None

    _install(monkeypatch, lambda req: httpx.Response(503))
    asyncio.run(detectors.detector_for("Telegram").check("durov"))
    h = sources.health("telegram")
    assert h["observations"] == 2 and h["failures"] == 1
    assert h["dominant_reason"].startswith("rate limited (HTTP 503")
    # A policy refusal fetched nothing and is not an observation.
    d = detectors.HtmlDetector("FakeInsta", ("fakeinsta",),
                               "https://instagram.com/{username}", present=("x",),
                               source="fakeinsta")
    asyncio.run(d.check("someone"))
    assert sources.health("fakeinsta")["observations"] == 0
    sources.reset()


def test_check_counts_in_the_shared_retrieval_stats(monkeypatch):
    _install(monkeypatch, lambda req: httpx.Response(404))
    monkeypatch.setattr(stealthweb, "enabled", lambda: False)
    st = retrieval.RetrievalStats()
    out = asyncio.run(detectors.detector_for("Telegram").check("nobody", retrieval_stats=st))
    assert out["status"] == detectors.ABSENT
    assert st.snapshot()["by_outcome"]["absent"] == 1
    assert st.snapshot()["by_status_class"] == {"4xx": 1}
