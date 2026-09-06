"""WhatsMyName engine tests. No network: the classification is pure and every
fetch is an ``httpx.MockTransport`` behind the real SSRF-guarded client (G2
routed the scanner through ``recon.retrieval.fetch``)."""

import asyncio

import httpx
import pytest
from conftest import mock_client

from recon import retrieval, safeweb
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
CHALLENGE = ("<html><head><title>Just a moment...</title></head><body>"
             "<p>Checking your browser before accessing example.com.</p></body></html>")


@pytest.fixture(autouse=True)
def _dns(public_dns):
    """Every fetch here is offline: the guard resolves to a public address."""


def _client(handler, calls=None):
    """A guarded client over a MockTransport, for direct ``_check_site`` calls."""
    return mock_client(handler, calls)()


def _fixed(status, body, headers=None):
    def handler(req):
        return httpx.Response(status, headers=headers or {"content-type": "text/html"},
                              text=body)
    return handler


def _check(handler, site=_SITE, username="alice", **kw):
    calls = []
    client = _client(handler, calls)

    async def go():
        async with client:
            return await wmn._check_site(client, site, username, **kw)
    return asyncio.run(go()), calls


# --- classification (pure) --------------------------------------------------------

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


def test_classify_fetch_honesty_overrides():
    """Defect 3: a rate limit is never a vote; a walled 2xx without the
    found-string is unknown, not available; a present found-string still wins."""
    ok = retrieval.FetchResult(retrieval.OK, "HTTP 200", 200, "<div class=profile-header>")
    assert wmn.classify_fetch(_SITE, ok) == (wmn.CLAIMED, "")
    absent = retrieval.FetchResult(retrieval.ABSENT, "HTTP 404", 404, "x")
    assert wmn.classify_fetch(_SITE, absent) == (wmn.AVAILABLE, "")
    limited = retrieval.FetchResult(retrieval.BLOCKED, "rate limited (HTTP 503)", 503,
                                    "x", rate_limited=True)
    site_503_missing = dict(_SITE, m_code=503)     # the dataset calls a 503 "missing"
    assert wmn.classify_fetch(site_503_missing, limited) == (wmn.UNKNOWN, "rate limited (HTTP 503)")
    plain_429 = retrieval.FetchResult(retrieval.BLOCKED, "rate limited (HTTP 429)", 429, "",
                                      rate_limited=True)
    assert wmn.classify_fetch(_SITE, plain_429) == (wmn.UNKNOWN, "rate limited (HTTP 429)")
    walled = retrieval.FetchResult(retrieval.BLOCKED, 'challenge page ("just a moment")',
                                   200, CHALLENGE)
    assert wmn.classify_fetch(_SITE, walled) == (wmn.UNKNOWN, 'challenge page ("just a moment")')
    marker_on_wall = retrieval.FetchResult(retrieval.BLOCKED, 'challenge page ("just a moment")',
                                           200, CHALLENGE + "<div class=profile-header>")
    assert wmn.classify_fetch(_SITE, marker_on_wall) == (wmn.CLAIMED, "")
    forbidden = retrieval.FetchResult(retrieval.BLOCKED, "HTTP 403", 403, "")
    assert wmn.classify_fetch(_SITE, forbidden) == (wmn.UNKNOWN, "HTTP 403")
    transport = retrieval.FetchResult(retrieval.TRANSPORT, "no response (ReadTimeout)",
                                      None, None, "ReadTimeout")
    assert wmn.classify_fetch(_SITE, transport) == (wmn.UNKNOWN, "no response (ReadTimeout)")


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
    # with the distinct POLICY status, never available/absent — and not UNKNOWN
    # either: until 2026-09-06 this returned UNKNOWN + "policy:" context, which
    # the pipeline emitted as an error row and the router recorded as a site
    # failure (audit defect 8).
    denied = dict(_SITE, name="Facebook",
                  uri_check="https://facebook.com/{account}")
    res, calls = _check(_fixed(200, "profile-header"), site=denied)   # would be CLAIMED
    assert res.status == wmn.POLICY
    assert res.status not in (wmn.UNKNOWN, wmn.CLAIMED, wmn.AVAILABLE)
    assert res.context.startswith("policy:")
    assert calls == []            # never touched the network


def test_policy_status_is_distinct_and_not_an_error_class():
    assert wmn.POLICY == "policy"
    assert len({wmn.CLAIMED, wmn.AVAILABLE, wmn.UNKNOWN, wmn.POLICY}) == 4
    # classify_response never produces it: there is no response to classify.
    for code in (200, 404, 403, 503):
        assert wmn.classify_response(_SITE, code, "") != wmn.POLICY


def test_variant_subset_contains_no_denied_host():
    from recon import policy
    for s in wmn.variant_sites():
        assert not policy.is_denied_template(s["uri_check"]), s["name"]
    # The raw subset (for the plan, which filters and reports itself) is a
    # superset; it may still carry denied entries such as Hacker News' Firebase API.
    raw = wmn.variant_sites(policy_filtered=False)
    assert {s["name"] for s in wmn.variant_sites()} <= {s["name"] for s in raw}


def test_url_templates_is_the_fetched_uri_only():
    assert wmn.url_templates({"uri_check": "https://a/{account}",
                              "uri_pretty": "https://b/{account}"}) == ["https://a/{account}"]
    assert wmn.url_templates({}) == []


def test_whatsmyname_scan_yields_policy_result_without_fetching(monkeypatch):
    # Direct callers of the scanner still get a POLICY result per denied site
    # (plan-time filtering normally removes them first).
    calls = []
    monkeypatch.setattr(wmn.safeweb, "async_client",
                        mock_client(_fixed(200, "profile-header"), calls))
    got = []
    sites = [dict(_SITE, name="Instagram", uri_check="https://instagram.com/{account}"),
             dict(_SITE)]
    asyncio.run(wmn.whatsmyname_scan("alice", sites, 5, got.append))
    by = {r.site_name: r for r in got}
    assert by["Instagram"].status == wmn.POLICY
    assert by["Example"].status == wmn.CLAIMED
    assert len(calls) == 1            # only the permitted site was fetched


# --- pipeline handling of POLICY results ------------------------------------

def test_pipeline_neither_observes_nor_reports_policy_results():
    """A POLICY result must reach neither router.observe (a fake failure in
    site_health tripped circuits for sites we never touched) nor the error
    stream; CLAIMED/UNKNOWN/AVAILABLE are handled exactly as before."""
    from recon import pipeline
    from recon.router import RunRouter

    router = RunRouter(None)             # store unavailable: in-memory tallies only
    observed, found, errors = [], [], []

    def dispatch(res):
        return pipeline.dispatch_wmn_result(
            res,
            observe=lambda r: (observed.append(r.site_name),
                               router.observe("whatsmyname", r.site_name,
                                              r.status, r.context or "")),
            on_found=lambda r: found.append(r.site_name),
            on_error=lambda r: errors.append(r.site_name))

    pol = wmn.WmnResult(wmn.POLICY, "Instagram", "https://instagram.com/alice",
                        "social", "policy: instagram.com robots.txt …")
    assert dispatch(pol) == "policy"
    assert observed == [] and errors == [] and found == []
    assert router.observations == 0 and router.error_observations == 0

    assert dispatch(wmn.WmnResult(wmn.CLAIMED, "GitHub", "u", "coding")) == "found"
    assert dispatch(wmn.WmnResult(wmn.UNKNOWN, "Foo", "u", None, "HTTP 503")) == "error"
    assert dispatch(wmn.WmnResult(wmn.AVAILABLE, "Bar", "u", None)) == "available"
    assert observed == ["GitHub", "Foo", "Bar"]
    assert found == ["GitHub"] and errors == ["Foo"]
    assert router.observations == 3 and router.error_observations == 1


def test_stealth_retry_recovers_a_high_value_unknown(monkeypatch):
    # High-value site (GitHub) whose plain fetch is a WAF 403 (UNKNOWN); the
    # tier-2 stealth fetch returns the real found page -> CLAIMED. (Until G2
    # this test used a 503 — a rate limit, which must never be escalated.)
    gh = dict(_SITE, name="GitHub")       # normalizes into HIGH_VALUE_SITES
    monkeypatch.setattr(wmn.stealthweb, "enabled", lambda: True)

    async def fake_tls(_url):
        return 200, "<div class=profile-header>"
    monkeypatch.setattr(wmn.stealthweb, "fetch_tls", fake_tls)

    budget = {"left": 5}
    counters = {}
    res, _ = _check(_fixed(403, "forbidden"), site=gh, stealth_retry=True,
                    budget=budget, counters=counters)
    assert res.status == wmn.CLAIMED
    assert res.context == "stealth-recovered"
    assert budget["left"] == 4          # spent exactly one unit
    assert counters == {"stealth_retries": 1, "stealth_recovered": 1}


def test_rate_limit_is_never_answered_with_a_stealth_retry(monkeypatch):
    """V7 for WhatsMyName: a 429/503 is UNKNOWN "rate limited …" and spends
    no stealth budget, even on a high-value site."""
    gh = dict(_SITE, name="GitHub")
    called = {"n": 0}

    async def fake_tls(_url):
        called["n"] += 1
        return 200, "<div class=profile-header>"
    monkeypatch.setattr(wmn.stealthweb, "enabled", lambda: True)
    monkeypatch.setattr(wmn.stealthweb, "fetch_tls", fake_tls)

    for code in (429, 503):
        budget = {"left": 5}
        res, _ = _check(_fixed(code, "slow down"), site=gh, stealth_retry=True, budget=budget)
        assert res.status == wmn.UNKNOWN
        assert res.context.startswith(f"rate limited (HTTP {code}")
        assert called["n"] == 0 and budget["left"] == 5


def test_stealth_retry_skips_non_high_value_and_spends_no_budget(monkeypatch):
    called = {"n": 0}

    async def fake_tls(_url):
        called["n"] += 1
        return 200, "<div class=profile-header>"
    monkeypatch.setattr(wmn.stealthweb, "enabled", lambda: True)
    monkeypatch.setattr(wmn.stealthweb, "fetch_tls", fake_tls)

    budget = {"left": 5}
    res, _ = _check(_fixed(403, "forbidden"), stealth_retry=True, budget=budget)  # "Example" not high-value
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

    res, _ = _check(_fixed(503, "x"), site=ig, stealth_retry=True, budget={"left": 5})
    assert res.context.startswith("policy:")
    assert called["n"] == 0


# --- defect 3: a walled 200 is not "available" ---------------------------------------

def test_challenge_200_without_found_string_is_unknown_not_available():
    res, _ = _check(_fixed(200, CHALLENGE))
    assert res.status == wmn.UNKNOWN
    assert res.context == 'challenge page ("just a moment")'


def test_plain_200_without_found_string_is_still_available():
    res, _ = _check(_fixed(200, "<html><body>" + "Generic landing page text. " * 10
                           + "</body></html>"))
    assert res.status == wmn.AVAILABLE


def test_json_bodies_are_read_for_the_found_string():
    res, _ = _check(_fixed(200, '{"profile-header": true}',
                           headers={"content-type": "application/json"}))
    assert res.status == wmn.CLAIMED


# --- query_time (latency for the router's EWMA; ops-observability gap 7) ----

async def _slow(req):
    await asyncio.sleep(0.005)
    return httpx.Response(200, headers={"content-type": "text/html"},
                          text="<div class=profile-header>")


def test_check_site_sets_query_time_on_success():
    # 0 of 649 WhatsMyName site_health rows had a latency: query_time was
    # never set. It is the plain request's wall time.
    res, _ = _check(_slow)
    assert res.status == wmn.CLAIMED
    assert isinstance(res.query_time, float) and res.query_time >= 0.005


def test_check_site_sets_query_time_on_failure():
    def boom(req):
        raise httpx.ConnectError("connection reset")

    res, _ = _check(boom)
    assert res.status == wmn.UNKNOWN
    assert res.context == "no response (ConnectError)"
    assert isinstance(res.query_time, float) and res.query_time >= 0.0


def test_policy_result_has_no_query_time():
    ig = dict(_SITE, name="Instagram", uri_check="https://instagram.com/{account}")
    res, _ = _check(_fixed(200, "x"), site=ig)
    assert res.status == wmn.POLICY and res.query_time is None


def test_query_time_feeds_the_router_latency(tmp_path):
    from dbconn import connect as db_connect
    from recon.router import RunRouter, SiteHealthStore, init_tables

    db = tmp_path / "h.db"
    with db_connect(db) as conn:
        init_tables(conn)
    res, _ = _check(_slow)
    r = RunRouter(db)
    r.observe("whatsmyname", res.site_name, res.status, res.context, res.query_time)
    r.finish()
    (row,) = SiteHealthStore(db).all_rows()
    assert row["engine"] == "whatsmyname"
    assert row["ewma_latency_ms"] is not None and row["ewma_latency_ms"] >= 5


# --- the run's shared counters --------------------------------------------------------

def test_scan_counts_every_fetch_in_the_shared_stats(monkeypatch):
    def handler(req):
        if req.url.host == "limited.example":
            return httpx.Response(429)
        return httpx.Response(200, headers={"content-type": "text/html"},
                              text="<div class=profile-header>")
    monkeypatch.setattr(wmn.safeweb, "async_client", mock_client(handler))
    st = retrieval.RetrievalStats()
    got = []
    sites = [dict(_SITE), dict(_SITE, name="Limited", uri_check="https://limited.example/{account}")]
    asyncio.run(wmn.whatsmyname_scan("alice", sites, 5, got.append, stats=st))
    snap = st.snapshot()
    assert snap["requests"] == 2
    assert snap["by_outcome"]["ok"] == 1 and snap["by_outcome"]["blocked"] == 1
    assert snap["by_status_class"] == {"2xx": 1, "4xx": 1}
    assert {r.status for r in got} == {wmn.CLAIMED, wmn.UNKNOWN}


def test_guarded_client_is_used_directly():
    """The scanner's client is the SSRF-guarded one; the guard hook, not a
    second resolution per fetch, checks the URL."""
    client = safeweb.async_client(transport=httpx.MockTransport(_fixed(404, "")))
    assert retrieval._client_is_guarded(client)
