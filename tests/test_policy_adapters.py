"""Access policy + per-site adapter tests (no network: adapters are exercised
through their pure decision logic and a stubbed transport)."""

import asyncio


from recon import adapters, policy


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


def test_adapter_check_handles_transport_failure(monkeypatch):
    """A network failure must read as 'blocked', never as 'absent'."""
    class _Boom:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, *a, **k): raise RuntimeError("dns")
    monkeypatch.setattr(adapters.safeweb, "async_client", lambda **k: _Boom())
    out = asyncio.run(adapters.adapter_for("GitHub").check("someone"))
    assert out["status"] == adapters.BLOCKED


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


class _Resp:
    def __init__(self, status, payload):
        self.status_code, self._payload = status, payload

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


class _Client:
    """Stub transport: routes each URL to a canned response."""
    def __init__(self, router):
        self._router = router

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url, **k):
        return self._router(url)


def test_discover_returns_only_exists_hits_with_profile_urls(monkeypatch):
    def router(url):
        if "api.github.com" in url:
            return _Resp(200, {"id": 1, "login": "torvalds",
                               "name": "Linus Torvalds", "avatar_url": "a",
                               "created_at": "2011-09-03T15:26:22Z"})
        return _Resp(404, None)   # every other adapter → absent
    monkeypatch.setattr(adapters.safeweb, "async_client",
                        lambda **k: _Client(router))
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
    class _Boom:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, *a, **k): raise RuntimeError("dns")
    monkeypatch.setattr(adapters.safeweb, "async_client", lambda **k: _Boom())
    # Every adapter errors → discovery yields nothing, but does not raise.
    assert asyncio.run(adapters.discover("someone")) == []
