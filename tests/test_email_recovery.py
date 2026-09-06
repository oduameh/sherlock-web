"""Tests for masked recovery-trail handling (recon.email_pivot + graph edge).

Some holehe password-reset checks leak a *masked* recovery phone/email. We
surface those and, when a masked recovery phone matches the subject's number,
stitch the account to the phone in the graph. These verify the matching is
meaningful (tail digits) yet conservative (no coincidental short matches).
"""

import asyncio
import logging

from recon import email_pivot
from recon.email_pivot import annotate_recovery, masked_recovery_matches_phone
from recon.graph import build_graph


# --- access policy on holehe modules (security F-2) -------------------------

def _holehe(monkeypatch, functions, **kw):
    monkeypatch.setattr(email_pivot, "_holehe_functions", lambda: functions)
    got: list = []
    res = asyncio.run(email_pivot.holehe_scan("a@b.com", got.append, delay=0, **kw))
    return res, got


def test_holehe_scan_skips_modules_on_denied_hosts(monkeypatch, caplog):
    """holehe ships instagram/twitter/pinterest/flickr modules that post the
    address to robots-denied hosts, and every one ran on every email pivot.
    They must be skipped and emit nothing (not checked is not 'not
    registered'); permitted modules run unchanged."""
    ran = []

    async def instagram(email, client, out):        # denied by name
        ran.append("instagram")
        out.append({"name": "instagram", "domain": "instagram.com", "exists": True})

    async def twitter(email, client, out):          # denied by name
        ran.append("twitter")
        out.append({"name": "twitter", "domain": "twitter.com", "exists": True})

    async def reset_helper(email, client, out):     # denied by its domain constant
        ran.append("reset_helper")
        domain = "pinterest.com"
        out.append({"name": "helper", "domain": domain, "exists": True})

    async def github(email, client, out):
        ran.append("github")
        out.append({"name": "github", "domain": "github.com", "exists": True,
                    "rateLimit": False})

    caplog.set_level(logging.DEBUG, logger="recon.email_pivot")
    res, got = _holehe(monkeypatch, [instagram, twitter, reset_helper, github])
    assert ran == ["github"]
    assert [e["site"] for e in res] == ["github"]
    assert [e["site"] for e in got] == ["github"]
    assert got[0]["exists"] is True
    assert "skipped by access policy" in caplog.text
    for name in ("instagram", "twitter", "reset_helper"):
        assert name in caplog.text


def test_holehe_only_subset_still_honours_policy(monkeypatch):
    async def instagram(email, client, out):
        out.append({"name": "instagram", "exists": True})

    async def github(email, client, out):
        out.append({"name": "github", "exists": True})

    res, _ = _holehe(monkeypatch, [instagram, github], only={"instagram", "github"})
    assert [e["site"] for e in res] == ["github"]


def test_real_holehe_modules_exclude_denied_platforms():
    """Against the installed holehe (1.61): exactly flickr/instagram/pinterest/
    twitter are denied, derived from policy.DENIED_HOSTS — nothing else."""
    if not email_pivot.holehe_available():
        import pytest
        pytest.skip("holehe not installed")
    from recon import policy
    fns = email_pivot._holehe_functions()
    kept, skipped = policy.partition_check_functions(fns)
    assert sorted(skipped) == ["flickr", "instagram", "pinterest", "twitter"]
    assert len(kept) == len(fns) - 4
    assert {fn.__name__ for fn in kept} >= {"github", "spotify", "snapchat"}


def test_masked_recovery_matches_phone_tail():
    for masked in ("•••-•••-2671", "*******2671", "+1 ••• ••• 2671", "xxx-xxx-2671"):
        assert masked_recovery_matches_phone(masked, "+14155552671") is True, masked


def test_masked_recovery_no_match():
    assert masked_recovery_matches_phone("•••-•••-9999", "+14155552671") is False
    assert masked_recovery_matches_phone("", "+14155552671") is False
    assert masked_recovery_matches_phone("•••-•••-2671", "") is False
    assert masked_recovery_matches_phone(None, "+14155552671") is False
    # Only two visible digits is not a meaningful match.
    assert masked_recovery_matches_phone("••••••••71", "+14155552671") is False


def test_annotate_recovery_sets_flag():
    e = {"site": "X", "exists": True, "phone_number": "•••-•••-2671"}
    annotate_recovery(e, "+14155552671")
    assert e.get("corroborates_phone") is True

    e2 = {"site": "Y", "exists": True, "phone_number": "•••-•••-0000"}
    annotate_recovery(e2, "+14155552671")
    assert "corroborates_phone" not in e2

    e3 = {"site": "Z", "exists": True}  # no recovery phone at all
    annotate_recovery(e3, "+14155552671")
    assert "corroborates_phone" not in e3


def test_graph_links_corroborating_recovery_to_phone():
    summary = {
        "params": {"email": "a@b.com", "phone": "+14155552671"},
        "accounts": [], "variants": [], "name_accounts": [],
        "email": {"gravatar": None, "holehe": [
            {"site": "Twitter", "domain": "twitter.com", "exists": True,
             "phone_number": "•••-•••-2671", "corroborates_phone": True},
            {"site": "Imgur", "domain": "imgur.com", "exists": True},
        ]},
        "phone": {"valid": True, "e164": "+14155552671",
                  "international": "+1 415-555-2671", "region": "US"},
        "correlation": [],
    }
    g = build_graph(summary)
    edges = [e for e in g["edges"]
             if e["source"] == "reg:Twitter" and e["target"] == "phone"]
    assert len(edges) == 1
    assert edges[0]["confidence"] == 80
    # The non-corroborating registration must NOT link to the phone.
    assert not [e for e in g["edges"]
                if e["source"] == "reg:Imgur" and e["target"] == "phone"]


# --- G2: Gravatar "could not check" is not "no profile" -----------------------------

def _grav(monkeypatch, handler, calls=None):
    from conftest import mock_client
    monkeypatch.setattr(email_pivot.safeweb, "async_client", mock_client(handler, calls))


def test_gravatar_profile_distinguishes_no_profile_from_could_not_check(monkeypatch, public_dns):
    import httpx
    from recon import sources
    sources.reset()

    def handler(req):
        return httpx.Response(200, json={"entry": [{
            "displayName": "Alice", "name": {"formatted": "Alice Example"},
            "profileUrl": "https://gravatar.com/alice", "thumbnailUrl": "https://0.gravatar.com/a",
            "aboutMe": "hi", "currentLocation": "Berlin",
            "accounts": [{"name": "Mastodon", "domain": "m.example", "url": "https://m.example/@a",
                          "username": "a"}]}]})
    _grav(monkeypatch, handler)
    res = asyncio.run(email_pivot.gravatar_profile("Alice@Example.com"))
    assert res.error is None
    assert res.profile["display_name"] == "Alice" and res.profile["full_name"] == "Alice Example"
    assert res.profile["accounts"][0]["domain"] == "m.example"
    assert asyncio.run(email_pivot.gravatar_lookup("Alice@Example.com"))["hash"] == res.profile["hash"]

    _grav(monkeypatch, lambda req: httpx.Response(404))
    assert asyncio.run(email_pivot.gravatar_profile("a@b.com")) == (None, None)
    _grav(monkeypatch, lambda req: httpx.Response(200, json={"entry": []}))
    assert asyncio.run(email_pivot.gravatar_profile("a@b.com")) == (None, None)

    _grav(monkeypatch, lambda req: httpx.Response(429, headers={"Retry-After": "30"}))
    res = asyncio.run(email_pivot.gravatar_profile("a@b.com"))
    assert res.profile is None
    assert res.error == "could not check: rate limited (HTTP 429, Retry-After 30)"
    assert asyncio.run(email_pivot.gravatar_lookup("a@b.com")) is None   # compat view

    def boom(req):
        raise httpx.ConnectTimeout("slow")
    _grav(monkeypatch, boom)
    res = asyncio.run(email_pivot.gravatar_profile("a@b.com"))
    assert res.error == "could not check: no response (ConnectTimeout)"

    h = sources.health("gravatar_json")
    assert h["observations"] == 7 and h["failures"] == 3
    sources.reset()


def test_gravatar_url_is_the_md5_of_the_normalised_address(monkeypatch, public_dns):
    import hashlib
    import httpx
    seen = []

    def handler(req):
        seen.append(str(req.url))
        return httpx.Response(404)
    _grav(monkeypatch, handler)
    asyncio.run(email_pivot.gravatar_profile("  Alice@Example.com "))
    digest = hashlib.md5(b"alice@example.com").hexdigest()
    assert seen == [f"https://www.gravatar.com/{digest}.json"]


# --- G2: holehe honesty (defect 6) ----------------------------------------------------

def test_holehe_entry_checked_and_tally():
    from recon.email_pivot import holehe_entry_checked, holehe_tally
    assert holehe_entry_checked({"exists": True}) is True
    assert holehe_entry_checked({"exists": False}) is True
    assert holehe_entry_checked({"exists": False, "rate_limit": True}) is False
    assert holehe_entry_checked({"exists": None, "error": "TimeoutError"}) is False
    assert holehe_entry_checked("junk") is False

    limited = [{"site": f"s{i}", "exists": False, "rate_limit": True} for i in range(100)]
    t = holehe_tally(limited)
    assert t == {"total": 100, "checked_ok": 0, "hits": 0, "rate_limited": 100,
                 "errors": 0, "undetermined": True}
    mixed = ([{"site": "a", "exists": True}, {"site": "b", "exists": False},
              {"site": "c", "exists": False, "rate_limit": True},
              {"site": "d", "exists": None, "error": "TimeoutError"}])
    t = holehe_tally(mixed)
    assert (t["total"], t["checked_ok"], t["hits"], t["rate_limited"], t["errors"]) == (4, 2, 1, 1, 1)
    assert t["undetermined"] is False            # a hit was found
    half = [{"exists": False}] * 5 + [{"exists": False, "rate_limit": True}] * 5
    assert holehe_tally(half)["undetermined"] is False   # half answered: "none found" stands
    assert holehe_tally([])["undetermined"] is False
    assert holehe_tally(None)["total"] == 0


def test_monitor_reexports_the_same_predicate():
    from recon import monitor
    from recon.email_pivot import holehe_entry_checked
    assert monitor.holehe_entry_checked is holehe_entry_checked
