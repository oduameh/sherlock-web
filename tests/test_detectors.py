"""Content-based HTML detector tests (no network: pure marker/status logic and
a stubbed fetch)."""

import asyncio

from recon import detectors, policy


def test_no_detector_targets_a_denied_host():
    """A detector must never be registered for a robots-denied host."""
    for d in detectors.DETECTORS:
        url = d.profile_url("probe")
        assert not policy.is_denied(url), f"{d.name} targets a denied host"


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
    calls = {"n": 0}

    async def fake_fetch(url):
        calls["n"] += 1
        return 200, "x"
    monkeypatch.setattr(detectors, "_fetch", fake_fetch)
    out = asyncio.run(d.check("someone"))
    assert out["status"] == detectors.BLOCKED
    assert out["signal"].startswith("policy:")
    assert calls["n"] == 0


def test_discover_via_stubbed_fetch(monkeypatch):
    async def fake_fetch(url):
        if "t.me/" in url:
            return 200, ("<html><div class='tgme_page_title'>Pavel Durov</div>"
                         "<meta property='og:title' content='Pavel Durov'></html>")
        return 404, None
    monkeypatch.setattr(detectors, "_fetch", fake_fetch)
    monkeypatch.setattr(detectors.stealthweb, "enabled", lambda: False)
    hits = asyncio.run(detectors.discover("durov"))
    assert len(hits) == 1
    assert hits[0]["site"] == "Telegram"
    assert hits[0]["url"] == "https://t.me/durov"
    assert hits[0]["identity"].get("display_name") == "Pavel Durov"


def test_discover_never_raises_and_empty_is_noop(monkeypatch):
    assert asyncio.run(detectors.discover("")) == []

    async def boom(url):
        raise RuntimeError("net")
    monkeypatch.setattr(detectors, "_fetch", boom)
    monkeypatch.setattr(detectors.stealthweb, "enabled", lambda: False)
    assert asyncio.run(detectors.discover("someone")) == []
