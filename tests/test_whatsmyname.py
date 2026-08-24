import asyncio

from recon import whatsmyname as wmn


_SITE = {
    "name": "Example",
    "uri_check": "https://example.com/{account}",
    "e_code": 200,
    "e_string": "profile-header",
    "m_code": 404,
    "m_string": "not found",
    "cat": "social",
}


class _FakeResp:
    def __init__(self, status, body):
        self.status_code = status
        self.encoding = "utf-8"
        self._body = body.encode()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def aiter_bytes(self, _n):
        yield self._body


class _FakeClient:
    """Returns a fixed response; records how many times it fetched."""
    def __init__(self, status, body):
        self._status, self._body, self.calls = status, body, 0

    def stream(self, _method, _url):
        self.calls += 1
        return _FakeResp(self._status, self._body)


def test_classify_claimed():
    assert wmn.classify_response(_SITE, 200, "<div class=profile-header>") == wmn.CLAIMED


def test_classify_available_by_missing_code():
    assert wmn.classify_response(_SITE, 404, "whatever") == wmn.AVAILABLE


def test_classify_available_by_missing_string():
    assert wmn.classify_response(_SITE, 200, "sorry, not found here") == wmn.AVAILABLE


def test_classify_found_code_without_found_string_is_available():
    # 200 but the positive marker is absent -> soft-404, not a match.
    assert wmn.classify_response(_SITE, 200, "generic landing page") == wmn.AVAILABLE


def test_classify_unknown():
    assert wmn.classify_response(_SITE, 503, "server error") == wmn.UNKNOWN


def test_classify_no_estring_uses_code_alone():
    site = dict(_SITE, e_string="")
    assert wmn.classify_response(site, 200, "anything") == wmn.CLAIMED


def test_dataset_loads_and_is_substantial():
    sites = wmn.load_sites()
    assert len(sites) > 500
    # Every site has the fields the scanner relies on.
    for s in sites[:50]:
        assert s.get("name")
        assert "{account}" in (s.get("uri_check") or "")


def test_nsfw_filtered_by_default():
    assert len(wmn.all_sites(nsfw=False)) <= len(wmn.all_sites(nsfw=True))
    assert all(not wmn._is_nsfw(s) for s in wmn.all_sites(nsfw=False))


def test_variant_subset_is_high_value_and_smaller():
    variant = wmn.variant_sites()
    assert 0 < len(variant) < len(wmn.all_sites())


# --- P4: policy gate + budgeted stealth retry on UNKNOWN --------------------

def test_denied_host_is_never_fetched():
    # A robots-disallowed host must be skipped before any request and reported
    # as "policy: ...", never available/absent.
    denied = dict(_SITE, name="Facebook",
                  uri_check="https://facebook.com/{account}")
    client = _FakeClient(200, "profile-header")   # would classify CLAIMED if fetched
    res = asyncio.run(wmn._check_site(client, denied, "alice"))
    assert res.status == wmn.UNKNOWN
    assert res.context.startswith("policy:")
    assert client.calls == 0            # never touched the network


def test_stealth_retry_recovers_a_high_value_unknown(monkeypatch):
    # High-value site (GitHub) whose plain fetch is a WAF-ish 503 (UNKNOWN);
    # the tier-2 stealth fetch returns the real found page -> CLAIMED.
    gh = dict(_SITE, name="GitHub")       # normalizes into HIGH_VALUE_SITES
    client = _FakeClient(503, "server error")   # -> UNKNOWN
    monkeypatch.setattr(wmn.stealthweb, "enabled", lambda: True)

    async def fake_tls(_url):
        return 200, "<div class=profile-header>"
    monkeypatch.setattr(wmn.stealthweb, "fetch_tls", fake_tls)

    budget = {"left": 5}
    res = asyncio.run(wmn._check_site(client, gh, "alice",
                                      stealth_retry=True, budget=budget))
    assert res.status == wmn.CLAIMED
    assert res.context == "stealth-recovered"
    assert budget["left"] == 4          # spent exactly one unit


def test_stealth_retry_skips_non_high_value_and_spends_no_budget(monkeypatch):
    client = _FakeClient(503, "server error")   # -> UNKNOWN
    called = {"n": 0}

    async def fake_tls(_url):
        called["n"] += 1
        return 200, "<div class=profile-header>"
    monkeypatch.setattr(wmn.stealthweb, "enabled", lambda: True)
    monkeypatch.setattr(wmn.stealthweb, "fetch_tls", fake_tls)

    budget = {"left": 5}
    res = asyncio.run(wmn._check_site(client, _SITE, "alice",   # "Example" not high-value
                                      stealth_retry=True, budget=budget))
    assert res.status == wmn.UNKNOWN
    assert called["n"] == 0
    assert budget["left"] == 5          # untouched


def test_denied_high_value_host_never_triggers_stealth(monkeypatch):
    # Instagram is high-value AND denied — the policy gate must win, so no
    # browser-impersonating retry ever hits it.
    ig = dict(_SITE, name="Instagram",
              uri_check="https://instagram.com/{account}")
    called = {"n": 0}

    async def fake_tls(_url):
        called["n"] += 1
        return 200, "<div class=profile-header>"
    monkeypatch.setattr(wmn.stealthweb, "enabled", lambda: True)
    monkeypatch.setattr(wmn.stealthweb, "fetch_tls", fake_tls)

    res = asyncio.run(wmn._check_site(_FakeClient(503, "x"), ig, "alice",
                                      stealth_retry=True, budget={"left": 5}))
    assert res.context.startswith("policy:")
    assert called["n"] == 0
