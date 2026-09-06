import asyncio
import socket

import httpx
import pytest

from recon import safeweb, timeline
from recon.cache import TTLCache
from recon.timeline import (
    account_events,
    build_timeline,
    github_login_from_url,
    parse_ts,
)


def test_github_login_from_url():
    assert github_login_from_url("https://github.com/torvalds") == "torvalds"
    assert github_login_from_url("https://www.github.com/torvalds") == "torvalds"
    # No scheme still works.
    assert github_login_from_url("github.com/alice") == "alice"
    # Reserved paths and other hosts are rejected.
    assert github_login_from_url("https://github.com/orgs/acme") is None
    assert github_login_from_url("https://github.com/") is None
    assert github_login_from_url("https://gitlab.com/alice") is None
    assert github_login_from_url(None) is None


def test_parse_ts_formats():
    assert parse_ts("2011-01-25T18:44:36Z").year == 2011      # GitHub ISO
    assert parse_ts("2024-08-12 10:30:00").hour == 10          # stored format
    assert parse_ts("2024-08-12").month == 8                   # bare date
    assert parse_ts("2024-08-12T10:30:00+00:00").year == 2024  # offset stripped
    assert parse_ts("") is None
    assert parse_ts(None) is None
    assert parse_ts("not a date") is None


def test_build_timeline_sorts_ascending_and_flags_dated():
    events = [
        {"date": "2024-08-12 10:00:00", "kind": "scan", "title": "b"},
        {"date": "2011-01-25T18:44:36Z", "kind": "account_created",
         "title": "a"},
    ]
    tl = build_timeline(events)
    assert [e["title"] for e in tl] == ["a", "b"]
    assert all(e["dated"] for e in tl)


def test_build_timeline_undated_sort_last():
    events = [
        {"date": None, "kind": "note", "title": "undated"},
        {"date": "2020-01-01", "kind": "opened", "title": "dated"},
    ]
    tl = build_timeline(events)
    assert tl[0]["title"] == "dated" and tl[0]["dated"] is True
    assert tl[1]["title"] == "undated" and tl[1]["dated"] is False


def test_build_timeline_dedupes_identical_events():
    ev = {"date": "2020-01-01", "kind": "opened", "title": "x"}
    tl = build_timeline([ev, dict(ev), dict(ev)])
    assert len(tl) == 1


def test_account_events_only_for_dated_rows():
    rows = [
        {"username": "alice", "site": "GitHub",
         "url": "https://github.com/alice"},
        {"username": "bob", "site": "GitLab",
         "url": "https://gitlab.com/bob"},
    ]
    dates = {"https://github.com/alice": "2011-01-25T18:44:36Z"}
    evs = account_events(rows, dates)
    assert len(evs) == 1
    assert evs[0]["kind"] == "account_created"
    assert "GitHub" in evs[0]["title"]
    assert "alice" in evs[0]["detail"]


# --- account_creation_dates: temporal first, cached GitHub lookups (D8 / defect 10) ---

@pytest.fixture(autouse=True)
def _public_dns(monkeypatch):
    async def fake_resolve(host, port):
        return ["93.184.216.34"]
    monkeypatch.setattr(safeweb, "_resolve", fake_resolve)


def _factory(handler, calls):
    def counting(request):
        calls.append(request.url.path)
        return handler(request)

    def make(**kw):
        return httpx.AsyncClient(transport=httpx.MockTransport(counting), **kw)
    return make


def _gh_user(request):
    login = request.url.path.rsplit("/", 1)[-1]
    return httpx.Response(200, json={"login": login, "id": 1,
                                     "created_at": f"2011-01-25T18:44:36Z#{login}"})


def _dates(rows, handler, calls, cache=None, **kw):
    return asyncio.run(timeline.account_creation_dates(
        rows, client_factory=_factory(handler, calls), cache=cache, **kw))


def test_rows_with_temporal_cause_zero_fetches():
    calls = []
    rows = [
        {"site": "GitHub", "username": "alice", "url": "https://github.com/alice",
         "temporal": {"created_at": "2011-01-25T18:44:36Z"}},
        {"site": "Bluesky", "username": "alice", "url": "https://bsky.app/profile/alice",
         "temporal": {"created_at": "2023-05-01T00:00:00Z"}},
        {"site": "GitLab", "username": "alice", "url": "https://gitlab.com/alice"},
    ]
    dates = _dates(rows, _gh_user, calls, cache=TTLCache())
    assert dates == {"https://github.com/alice": "2011-01-25T18:44:36Z",
                     "https://bsky.app/profile/alice": "2023-05-01T00:00:00Z"}
    assert calls == []


def test_github_row_without_temporal_is_fetched_once_across_two_calls():
    calls = []
    cache = TTLCache()
    rows = [{"site": "GitHub", "username": "alice", "url": "https://github.com/alice"}]
    first = _dates(rows, _gh_user, calls, cache=cache)
    second = _dates(rows, _gh_user, calls, cache=cache)
    assert first == second == {"https://github.com/alice": "2011-01-25T18:44:36Z#alice"}
    assert calls == ["/users/alice"]


def test_404_is_cached_as_absent_and_not_refetched():
    calls = []
    cache = TTLCache()
    rows = [{"site": "GitHub", "username": "ghost", "url": "https://github.com/ghost"}]

    def handler(request):
        return httpx.Response(404, json={"message": "Not Found"})

    assert _dates(rows, handler, calls, cache=cache) == {}
    assert _dates(rows, handler, calls, cache=cache) == {}
    assert calls == ["/users/ghost"]
    assert cache.is_absent("ghost")


def test_rate_limit_is_not_cached_and_the_next_call_asks_again():
    calls = []
    cache = TTLCache()
    rows = [{"site": "GitHub", "username": "alice", "url": "https://github.com/alice"}]

    def handler(request):
        if len(calls) == 1:
            return httpx.Response(403, headers={"x-ratelimit-remaining": "0"},
                                  json={"message": "API rate limit exceeded"})
        return _gh_user(request)

    assert _dates(rows, handler, calls, cache=cache) == {}
    assert len(cache) == 0
    assert _dates(rows, handler, calls, cache=cache) == {
        "https://github.com/alice": "2011-01-25T18:44:36Z#alice"}
    assert calls == ["/users/alice", "/users/alice"]


def test_transport_failure_is_not_cached():
    calls = []
    cache = TTLCache()
    rows = [{"site": "GitHub", "username": "alice", "url": "https://github.com/alice"}]

    def handler(request):
        if len(calls) == 1:
            raise httpx.ConnectError("boom")
        return _gh_user(request)

    assert _dates(rows, handler, calls, cache=cache) == {}
    assert _dates(rows, handler, calls, cache=cache) != {}
    assert len(calls) == 2


def test_at_most_max_lookups_fetches_per_call():
    calls = []
    rows = [{"site": "GitHub", "username": f"u{i}", "url": f"https://github.com/u{i}"}
            for i in range(20)]
    dates = _dates(rows, _gh_user, calls, cache=TTLCache(), max_lookups=15)
    assert len(calls) == 15 and len(dates) == 15


def test_dns_failure_is_not_cached(monkeypatch):
    async def failing(host, port):
        raise socket.gaierror(8, "nodename nor servname provided")
    monkeypatch.setattr(safeweb, "_resolve", failing)
    calls = []
    cache = TTLCache()
    rows = [{"site": "GitHub", "username": "alice", "url": "https://github.com/alice"}]
    assert _dates(rows, _gh_user, calls, cache=cache) == {}
    assert calls == [] and len(cache) == 0


def test_module_cache_is_used_by_default_and_clearable():
    timeline.clear_cache()
    calls = []
    rows = [{"site": "GitHub", "username": "alice", "url": "https://github.com/alice"}]
    _dates(rows, _gh_user, calls)
    _dates(rows, _gh_user, calls)
    assert calls == ["/users/alice"]
    timeline.clear_cache()
    _dates(rows, _gh_user, calls)
    assert len(calls) == 2
    timeline.clear_cache()
