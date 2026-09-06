import asyncio

from recon import monitor
from recon.monitor import (
    account_key,
    compute_signature,
    diff_signatures,
    holehe_entry_checked,
    holehe_key,
)


def _scan(accounts=None, holehe=None):
    return {"accounts": accounts or [], "holehe": holehe or []}


ALICE_GH = {"username": "alice", "site": "GitHub", "url": "u"}


def test_signature_is_stable_and_normalized():
    a = compute_signature(_scan(
        accounts=[{"username": "Alice", "site": "GitHub", "url": "u"}]))
    b = compute_signature(_scan(
        accounts=[{"username": "alice", "site": "github", "url": "u2"}]))
    # Same account regardless of case / URL difference.
    assert set(a.keys()) == set(b.keys())
    assert set(a) == {account_key("GitHub", "alice")}


def test_diff_detects_new_account():
    old = compute_signature(_scan())
    new = compute_signature(_scan(accounts=[ALICE_GH]))
    alerts = diff_signatures(old, new)
    assert len(alerts) == 1
    assert alerts[0]["kind"] == "new_account"
    assert "GitHub" in alerts[0]["message"]


def test_diff_detects_account_gone_when_the_site_was_checked():
    """Checked GitHub for alice and found nothing → the account is gone."""
    old = compute_signature(_scan(accounts=[ALICE_GH]))
    new = compute_signature(_scan())
    alerts = diff_signatures(old, new, checked={account_key("GitHub", "alice")})
    assert [a["kind"] for a in alerts] == ["account_gone"]
    assert alerts[0]["data"]["site"] == "GitHub"


def test_skipped_site_never_reads_as_gone():
    """Defect 5: the old signature has acct:github:alice; the new scan skipped
    GitHub (open circuit / policy / error) → no alert."""
    old = compute_signature(_scan(accounts=[ALICE_GH]))
    new = compute_signature(_scan())
    assert diff_signatures(old, new, checked=set()) == []
    assert diff_signatures(old, new, checked={account_key("Dribbble", "alice")}) == []
    # Without coverage information nothing may be called gone either.
    assert diff_signatures(old, new) == []


def test_new_accounts_alert_regardless_of_coverage():
    old = compute_signature(_scan())
    new = compute_signature(_scan(accounts=[ALICE_GH]))
    assert [a["kind"] for a in diff_signatures(old, new, checked=set())] == ["new_account"]


def test_diff_detects_new_holehe_hit():
    old = compute_signature(_scan())
    new = compute_signature(_scan(holehe=[{"site": "Spotify", "domain": "spotify.com"}]))
    alerts = diff_signatures(old, new)
    assert alerts[0]["kind"] == "new_holehe_hit"


def test_holehe_hit_gone_only_when_that_module_answered():
    old = compute_signature(_scan(holehe=[{"site": "Spotify", "domain": "spotify.com"}]))
    new = compute_signature(_scan())
    assert diff_signatures(old, new, checked=set()) == []            # rate-limited
    alerts = diff_signatures(old, new, checked={holehe_key("Spotify")})
    assert [a["kind"] for a in alerts] == ["holehe_hit_gone"]


def test_no_change_no_alerts():
    scan = _scan(accounts=[ALICE_GH])
    sig = compute_signature(scan)
    assert diff_signatures(sig, sig, checked=set(sig)) == []


def test_holehe_entry_checked():
    assert holehe_entry_checked({"exists": True}) is True
    assert holehe_entry_checked({"exists": False}) is True
    assert holehe_entry_checked({"exists": False, "rate_limit": True}) is False
    assert holehe_entry_checked({"exists": None, "error": "TimeoutError"}) is False
    assert holehe_entry_checked({"exists": None}) is False
    assert holehe_entry_checked("junk") is False


# --- the light scan reports its coverage --------------------------------------------

class _StubRouter:
    degraded = [{"site": "Skipped"}]
    proxy = None

    def __init__(self, db_path=None):
        pass

    def filter_sites(self, site_data, engine):
        return {k: v for k, v in site_data.items() if k != "Skipped"}

    def finish(self):
        pass


def test_light_scan_returns_checked_keys_and_gone_respects_them(monkeypatch):
    def fake_sherlock_light(usernames, site_data, timeout, router):
        assert "Skipped" not in site_data              # open circuit filtered out
        return ([dict(ALICE_GH)],
                {account_key("GitHub", "alice"), account_key("Dribbble", "alice")})

    monkeypatch.setattr(monitor, "RunRouter", _StubRouter)
    monkeypatch.setattr(monitor, "_sherlock_light", fake_sherlock_light)
    monkeypatch.setattr(monitor, "holehe_available", lambda: False)

    scan = asyncio.run(monitor.light_scan(
        {"usernames": ["alice"]}, {"GitHub": {}, "Dribbble": {}, "Skipped": {}}))
    assert scan["accounts"] == [ALICE_GH]
    assert scan["checked"] == sorted([account_key("GitHub", "alice"),
                                      account_key("Dribbble", "alice")])

    old = compute_signature(_scan(accounts=[
        ALICE_GH,
        {"username": "alice", "site": "Dribbble", "url": "d"},
        {"username": "alice", "site": "Skipped", "url": "s"},
    ]))
    alerts = diff_signatures(old, compute_signature(scan), checked=scan["checked"])
    # Dribbble was checked and is no longer found → gone. Skipped was never
    # examined → silence.
    assert [(a["kind"], a["data"]["site"]) for a in alerts] == [("account_gone", "Dribbble")]


def test_sherlock_light_marks_only_decisive_results_as_checked(monkeypatch):
    from sherlock_project.result import QueryStatus

    class _R:
        def __init__(self, site, status):
            self.site_name = site
            self.status = status
            self.username = "alice"
            self.site_url_user = f"https://{site.lower()}.test/alice"
            self.context = None
            self.query_time = 0.1

    def fake_sherlock(username, site_data, notify, timeout=None, proxy=None):
        notify.update(_R("GitHub", QueryStatus.CLAIMED))
        notify.update(_R("Dribbble", QueryStatus.AVAILABLE))
        notify.update(_R("Walled", QueryStatus.WAF))
        notify.update(_R("Flaky", QueryStatus.UNKNOWN))
        notify.update(_R("Illegal", QueryStatus.ILLEGAL))

    monkeypatch.setattr("sherlock_project.sherlock.sherlock", fake_sherlock)
    found, checked = monitor._sherlock_light(["alice"], {"x": {}}, 5, None)
    assert [f["site"] for f in found] == ["GitHub"]
    assert checked == {account_key("GitHub", "alice"), account_key("Dribbble", "alice")}
