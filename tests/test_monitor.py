from recon.monitor import compute_signature, diff_signatures


def _scan(accounts=None, holehe=None):
    return {"accounts": accounts or [], "holehe": holehe or []}


def test_signature_is_stable_and_normalized():
    a = compute_signature(_scan(
        accounts=[{"username": "Alice", "site": "GitHub", "url": "u"}]))
    b = compute_signature(_scan(
        accounts=[{"username": "alice", "site": "github", "url": "u2"}]))
    # Same account regardless of case / URL difference.
    assert set(a.keys()) == set(b.keys())


def test_diff_detects_new_account():
    old = compute_signature(_scan())
    new = compute_signature(_scan(
        accounts=[{"username": "alice", "site": "GitHub", "url": "u"}]))
    alerts = diff_signatures(old, new)
    assert len(alerts) == 1
    assert alerts[0]["kind"] == "new_account"
    assert "GitHub" in alerts[0]["message"]


def test_diff_detects_account_gone():
    old = compute_signature(_scan(
        accounts=[{"username": "alice", "site": "GitHub", "url": "u"}]))
    new = compute_signature(_scan())
    alerts = diff_signatures(old, new)
    assert alerts[0]["kind"] == "account_gone"


def test_diff_detects_new_holehe_hit():
    old = compute_signature(_scan())
    new = compute_signature(_scan(holehe=[{"site": "Spotify", "domain": "spotify.com"}]))
    alerts = diff_signatures(old, new)
    assert alerts[0]["kind"] == "new_holehe_hit"


def test_no_change_no_alerts():
    scan = _scan(accounts=[{"username": "alice", "site": "GitHub", "url": "u"}])
    sig = compute_signature(scan)
    assert diff_signatures(sig, sig) == []
