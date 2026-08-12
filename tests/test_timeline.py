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
