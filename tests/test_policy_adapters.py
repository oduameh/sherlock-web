"""Access policy + per-site adapter tests (no network: adapters are exercised
through their pure decision logic and an ``httpx.MockTransport`` behind the
real SSRF-guarded client — G2 routed every adapter call through
``recon.retrieval.fetch`` and added the shared answer cache)."""

import asyncio

import httpx
import pytest
from conftest import mock_client

from recon import adapters, policy, retrieval, sources


@pytest.fixture(autouse=True)
def _isolated(public_dns):
    """Offline DNS, and a clean answer cache before and after every test (the
    cache is process-wide by design)."""
    adapters.clear_cache()
    yield
    adapters.clear_cache()


def _install(monkeypatch, handler, calls=None):
    monkeypatch.setattr(adapters.safeweb, "async_client", mock_client(handler, calls))


# --- access policy ---------------------------------------------------------

def test_disallowed_hosts_are_denied():
    for url in ("https://www.reddit.com/user/spez/about.json",
                "https://www.instagram.com/someone/",
                "https://www.facebook.com/someone",
                "https://x.com/someone",
                "https://www.pinterest.com/someone/",
                "https://www.flickr.com/photos/someone/"):
        assert policy.is_denied(url), url


def test_allowed_hosts_are_not_denied():
    for url in ("https://api.github.com/users/torvalds",
                "https://github.com/torvalds",
                "https://mastodon.social/@someone"):
        assert not policy.is_denied(url), url


def test_denied_host_in_query_param_is_allowed():
    # The Wayback availability API is queried ON archive.org ABOUT an
    # instagram URL — the request goes to archive.org, which is permitted.
    url = "https://archive.org/wayback/available?url=https://instagram.com/someone"
    assert not policy.is_denied(url)


def test_denied_verdict_is_not_a_finding():
    v = policy.not_examined_verdict(policy.denied_reason("https://reddit.com/user/x"))
    assert v["status"] == "not_examined"
    assert v["score"] == 0
    from recon.confidence import verdict_bucket
    # Must never be counted as a lead or as an absence.
    assert verdict_bucket({"verification": v}) == "not_examined"


# --- adapter registry ------------------------------------------------------

def test_registry_routes_known_sites():
    assert adapters.adapter_for("GitHub").name == "GitHub"
    assert adapters.adapter_for("github").name == "GitHub"       # normalised
    assert adapters.adapter_for("Docker Hub").name == "Docker Hub"
    assert adapters.adapter_for("SomeUnknownSite") is None


def test_no_adapter_targets_a_denied_host():
    """An adapter must never be registered for a host we are not allowed to
    fetch — that would route around the access policy."""
    for a in adapters.ADAPTERS:
        url = a.url.format(username="probe")
        assert not policy.is_denied(url), f"{a.name} targets a denied host"


def test_every_adapter_source_is_registered_with_its_host():
    for a in adapters.ADAPTERS:
        src = sources.get(a.source)
        assert src is not None, f"{a.name}: source {a.source!r} not in the registry"
        host = httpx.URL(a.url.format(username="probe")).host
        assert retrieval.host_key(src.host) == retrieval.host_key(host), a.name


def test_adapter_exists_predicates():
    gh = adapters.adapter_for("GitHub")
    assert gh.exists_when({"id": 1, "login": "torvalds"}) is True
    assert not gh.exists_when({"message": "Not Found"})
    kb = adapters.adapter_for("Keybase")
    # Keybase answers HTTP 200 with a non-zero status code when unknown.
    assert kb.exists_when({"status": {"code": 0}, "them": [{"id": "abc"}]}) is True
    assert not kb.exists_when({"status": {"code": 205}, "them": []})


# --- verdict mapping -------------------------------------------------------

def test_absent_maps_to_false_positive():
    v = adapters.to_verification({"adapter": "GitHub", "status": adapters.ABSENT,
                                  "signal": "not found"})
    assert v["status"] == "likely_false_positive"


def test_blocked_maps_to_indeterminate_not_absent():
    v = adapters.to_verification({"adapter": "GitHub", "status": adapters.BLOCKED,
                                  "signal": "HTTP 429"})
    assert v["status"] == "indeterminate"


def test_exists_confirms_and_attributes_identity():
    res = {"adapter": "GitHub", "status": adapters.EXISTS,
           "signal": "exists", "identity": {"display_name": "Linus Torvalds"}}
    v = adapters.to_verification(res, subject_name="Linus Torvalds")
    assert v["status"] == "confirmed"
    assert v.get("identity_match") is True
    # A different person is recorded but must not hard-flag a real account.
    v2 = adapters.to_verification(res, subject_name="Jane Doe")
    assert v2["status"] == "confirmed"
    assert v2.get("identity_match") is False


# --- outcome mapping (pure) -------------------------------------------------

def test_outcome_matrix():
    gh = adapters.adapter_for("GitHub")
    ok = retrieval.FetchResult(retrieval.OK, "HTTP 200", 200, "{}",
                               data={"id": 1, "login": "torvalds", "name": "Linus"})
    assert gh.outcome(ok)["status"] == adapters.EXISTS
    assert gh.outcome(ok)["identity"]["display_name"] == "Linus"
    empty = retrieval.FetchResult(retrieval.OK, "HTTP 200", 200, "{}", data={"message": "x"})
    assert gh.outcome(empty)["status"] == adapters.ABSENT
    absent = retrieval.FetchResult(retrieval.ABSENT, "HTTP 404", 404, None)
    assert gh.outcome(absent)["status"] == adapters.ABSENT
    limited = retrieval.FetchResult(retrieval.BLOCKED,
                                    "rate limited (HTTP 403, X-RateLimit-Remaining: 0)",
                                    403, None, rate_limited=True)
    out = gh.outcome(limited)
    assert out["status"] == adapters.BLOCKED
    assert out["signal"] == ("blocked: rate limited (HTTP 403, X-RateLimit-Remaining: 0)"
                             " — cannot determine")
    transport = retrieval.FetchResult(retrieval.TRANSPORT, "no response (ReadTimeout)",
                                      None, None, "ReadTimeout")
    assert "ReadTimeout" in gh.outcome(transport)["signal"]
    non_json = retrieval.FetchResult(retrieval.BLOCKED, "non-JSON response (HTTP 200)",
                                     200, "<html>login</html>")
    assert gh.outcome(non_json)["status"] == adapters.BLOCKED
    # Bluesky's 400 is its "no such actor", by the adapter's own rule.
    bsky = adapters.adapter_for("Bluesky")
    bad = retrieval.FetchResult(retrieval.BLOCKED, "HTTP 400", 400, '{"error":"x"}')
    assert bsky.outcome(bad)["status"] == adapters.ABSENT


def test_adapter_check_handles_transport_failure(monkeypatch):
    """A network failure must read as 'blocked', never as 'absent'."""
    def boom(req):
        raise RuntimeError("dns")
    _install(monkeypatch, boom)
    out = asyncio.run(adapters.adapter_for("GitHub").check("someone"))
    assert out["status"] == adapters.BLOCKED
    assert "RuntimeError" in out["signal"]


def test_github_403_with_remaining_zero_reads_as_rate_limited(monkeypatch):
    """Audit defect 10: GitHub's exhausted unauthenticated budget is a 403
    with ``X-RateLimit-Remaining: 0`` — a rate limit, not a refusal, and it
    backs the host off in the shared state."""
    def handler(req):
        return httpx.Response(403, headers={"X-RateLimit-Remaining": "0"},
                              json={"message": "API rate limit exceeded"})
    _install(monkeypatch, handler)
    hs = retrieval.HostState()
    out = asyncio.run(adapters.adapter_for("GitHub").check("torvalds", host_state=hs))
    assert out["status"] == adapters.BLOCKED
    assert "rate limited (HTTP 403, X-RateLimit-Remaining: 0)" in out["signal"]
    assert hs.active_backoff("api.github.com") is not None


def test_backed_off_host_is_not_requested(monkeypatch):
    calls = []
    _install(monkeypatch, lambda req: httpx.Response(200, json={"id": 1, "login": "x"}), calls)
    hs = retrieval.HostState()
    hs.backoff("api.github.com", 60, status=429)
    out = asyncio.run(adapters.adapter_for("GitHub").check("x", host_state=hs))
    assert calls == []
    assert out["status"] == adapters.BLOCKED and "backing off" in out["signal"]


def test_honest_user_agent_is_sent(monkeypatch):
    seen = []

    def handler(req):
        seen.append(req.headers.get("user-agent"))
        return httpx.Response(404)
    _install(monkeypatch, handler)
    asyncio.run(adapters.adapter_for("GitHub").check("nobody"))
    assert seen == [sources.USER_AGENT]


# --- the answer cache (defect 10) ----------------------------------------------

def _gh(req):
    login = req.url.path.rsplit("/", 1)[-1]
    if login == "ghost":
        return httpx.Response(404, json={"message": "Not Found"})
    if login == "limited":
        return httpx.Response(429, headers={"Retry-After": "5"})
    return httpx.Response(200, json={"id": 1, "login": login, "name": "Linus"})


def test_two_checks_for_one_handle_make_one_request(monkeypatch):
    calls = []
    _install(monkeypatch, _gh, calls)
    gh = adapters.adapter_for("GitHub")
    first = asyncio.run(gh.check("torvalds"))
    second = asyncio.run(gh.check("Torvalds"))          # case-insensitive key
    assert len(calls) == 1
    assert first["status"] == second["status"] == adapters.EXISTS
    assert second["cached"] is True and "cached" not in first
    assert adapters.cached_result("github", "torvalds")["identity"]["display_name"] == "Linus"


def test_absent_is_cached_but_blocked_is_not(monkeypatch):
    calls = []
    _install(monkeypatch, _gh, calls)
    gh = adapters.adapter_for("GitHub")
    asyncio.run(gh.check("ghost"))
    asyncio.run(gh.check("ghost"))
    assert sum(1 for r in calls if r.url.path.endswith("/ghost")) == 1
    asyncio.run(gh.check("limited"))
    asyncio.run(gh.check("limited"))
    assert sum(1 for r in calls if r.url.path.endswith("/limited")) == 2
    assert adapters.cached_result("github", "limited") is None


def test_discover_uses_the_cache_and_check_account_shares_it(monkeypatch):
    calls = []
    _install(monkeypatch, lambda req: _gh(req) if "github" in req.url.host
             else httpx.Response(404), calls)
    asyncio.run(adapters.discover("torvalds"))
    n = len(calls)
    assert n == len(adapters.ADAPTERS)
    asyncio.run(adapters.discover("torvalds"))
    assert len(calls) == n, "a second discovery must be served from the cache"
    out = asyncio.run(adapters.check_account("GitHub", "torvalds"))
    assert out["cached"] is True and len(calls) == n


# --- the source registry sees every call ----------------------------------------

def test_calls_are_recorded_against_the_source_registry(monkeypatch):
    sources.reset()
    _install(monkeypatch, _gh)
    gh = adapters.adapter_for("GitHub")
    asyncio.run(gh.check("torvalds"))
    asyncio.run(gh.check("ghost"))
    asyncio.run(gh.check("limited"))
    h = sources.health("github")
    assert h["observations"] == 3 and h["failures"] == 1
    assert h["dominant_reason"].startswith("rate limited (HTTP 429")
    sources.reset()


# --- Mastodon adapter + discovery engine -----------------------------------

def test_mastodon_adapter_registered_and_predicates():
    m = adapters.adapter_for("mastodon.social")
    assert m is not None and m.name == "mastodon.social"
    assert m.exists_when({"id": "1", "username": "Gargron"}) is True
    assert not m.exists_when({"error": "Record not found"})
    assert m.profile_url("Gargron") == "https://mastodon.social/@Gargron"


def test_profile_url_falls_back_to_api_url():
    a = adapters.Adapter("X", ("x",), "https://api.x/{username}",
                         exists_when=lambda d: True)
    assert a.profile_url("bob") == "https://api.x/bob"


def test_discover_returns_only_exists_hits_with_profile_urls(monkeypatch):
    def handler(req):
        if req.url.host == "api.github.com":
            return httpx.Response(200, json={"id": 1, "login": "torvalds",
                                             "name": "Linus Torvalds", "avatar_url": "a",
                                             "created_at": "2011-09-03T15:26:22Z"})
        return httpx.Response(404)   # every other adapter → absent
    _install(monkeypatch, handler)
    hits = asyncio.run(adapters.discover("torvalds"))
    assert len(hits) == 1
    gh = hits[0]
    assert gh["site"] == "GitHub"
    assert gh["url"] == "https://github.com/torvalds"        # human profile, not API
    assert gh["identity"]["display_name"] == "Linus Torvalds"
    assert gh["temporal"]["created_at"].startswith("2011")


def test_discover_empty_username_is_noop():
    assert asyncio.run(adapters.discover("")) == []


def test_discover_never_raises_on_adapter_failure(monkeypatch):
    def boom(req):
        raise RuntimeError("dns")
    _install(monkeypatch, boom)
    # Every adapter errors → discovery yields nothing, but does not raise.
    stats = {}
    assert asyncio.run(adapters.discover("someone", stats=stats)) == []
    assert all(v["status"] == adapters.BLOCKED for v in stats.values())
