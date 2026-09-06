"""recon.ladder — the one stealth ladder behind ``recon.retrieval.fetch``.

Both stealth tiers are stubbed on ``recon.stealthweb``; nothing here opens a
browser or a socket. The contract under test is the ``(status, html, via)``
the façade adopts, the per-tier counters and the budget.
"""

import asyncio

from recon import stealthweb
from recon.ladder import TIER2, TIER3, StealthLadder

REAL = ("<html><head><title>Alice</title></head><body>"
        + "<p>Alice writes about maps, cycling and open data.</p>" * 10 + "</body></html>")
WALL = ("<html><head><title>Just a moment...</title></head><body>"
        "Checking your browser before accessing.</body></html>")
SHELL = "<html><body><div id=root></div></body></html>"


def _tiers(monkeypatch, tls, browser, enabled=True):
    calls = {"tls": [], "browser": []}

    async def fake_tls(url):
        calls["tls"].append(url)
        return tls(url) if callable(tls) else tls

    async def fake_browser(url):
        calls["browser"].append(url)
        return browser(url) if callable(browser) else browser

    monkeypatch.setattr(stealthweb, "enabled", lambda: enabled)
    monkeypatch.setattr(stealthweb, "fetch_tls", fake_tls)
    monkeypatch.setattr(stealthweb, "fetch_browser", fake_browser)
    return calls


def test_disabled_ladder_is_not_offered_to_fetch(monkeypatch):
    _tiers(monkeypatch, (200, REAL), (200, REAL), enabled=False)
    ladder = StealthLadder(3)
    assert ladder.for_fetch() is None
    assert asyncio.run(ladder("https://x.example/a")) == (None, None, "off")
    monkeypatch.setattr(stealthweb, "enabled", lambda: True)
    assert ladder.for_fetch() is ladder


def test_tier2_rescue_stops_the_ladder(monkeypatch):
    calls = _tiers(monkeypatch, (200, REAL), (200, REAL))
    ladder = StealthLadder(3)
    assert asyncio.run(ladder("https://x.example/a")) == (200, REAL, TIER2)
    assert calls["browser"] == []
    assert ladder.snapshot() == {"tls_attempts": 1, "tls_ok": 1, "browser_attempts": 0,
                                 "browser_ok": 0, "browser_budget": 3,
                                 "browser_budget_left": 3, "rate_limited": 0}


def test_tier3_rescue_after_a_walled_tier2(monkeypatch):
    calls = _tiers(monkeypatch, (200, WALL), (200, REAL))
    ladder = StealthLadder(3)
    assert asyncio.run(ladder("https://x.example/a")) == (200, REAL, TIER3)
    assert calls["tls"] == calls["browser"] == ["https://x.example/a"]
    snap = ladder.snapshot()
    assert snap["browser_attempts"] == 1 and snap["browser_ok"] == 1
    assert snap["browser_budget_left"] == 2


def test_wall_or_shell_that_survives_rendering_is_returned_unrescued(monkeypatch):
    """The last tier's page is handed back for re-classification (a wall
    names its WAF; a rendered shell may carry a detector's marker) but it is
    not a rescue — nothing is counted as ``*_ok``."""
    _tiers(monkeypatch, (200, WALL), (200, WALL))
    ladder = StealthLadder(3)
    assert asyncio.run(ladder("https://x.example/a")) == (200, WALL, TIER3)
    assert ladder.tls_ok == 0 and ladder.browser_ok == 0
    _tiers(monkeypatch, (200, SHELL), (200, SHELL))
    assert asyncio.run(StealthLadder(3)("https://x.example/a")) == (200, SHELL, TIER3)
    # Budget gone: tier 2's own page is what comes back.
    _tiers(monkeypatch, (200, WALL), (200, REAL))
    assert asyncio.run(StealthLadder(0)("https://x.example/a")) == (200, WALL, TIER2)


def test_bare_status_is_returned_only_when_it_is_evidence(monkeypatch):
    _tiers(monkeypatch, (403, None), (404, None))
    assert asyncio.run(StealthLadder(3)("https://x.example/a")) == (404, None, TIER3)
    _tiers(monkeypatch, (403, None), (None, None))
    assert asyncio.run(StealthLadder(3)("https://x.example/a")) == (403, None, TIER2)
    _tiers(monkeypatch, (None, None), (None, None))
    assert asyncio.run(StealthLadder(3)("https://x.example/a")) == (None, None, TIER2)
    # A bare 2xx with no body says nothing: the plain result is the better one.
    _tiers(monkeypatch, (200, None), (200, None))
    assert asyncio.run(StealthLadder(3)("https://x.example/a")) == (None, None, TIER3)


def test_rate_limit_from_any_tier_is_returned_bare_and_counted(monkeypatch):
    calls = _tiers(monkeypatch, (429, WALL), (200, REAL))
    ladder = StealthLadder(3)
    assert asyncio.run(ladder("https://x.example/a")) == (429, None, TIER2)
    assert calls["browser"] == [] and ladder.rate_limited == 1
    _tiers(monkeypatch, (200, WALL), (503, None))
    ladder = StealthLadder(3)
    assert asyncio.run(ladder("https://x.example/a")) == (503, None, TIER3)
    assert ladder.rate_limited == 1


def test_browser_budget_is_spent_and_then_refused(monkeypatch):
    calls = _tiers(monkeypatch, (200, WALL), (200, REAL))
    ladder = StealthLadder(1)
    assert asyncio.run(ladder("https://x.example/a"))[2] == TIER3
    assert asyncio.run(ladder("https://x.example/b")) == (200, WALL, TIER2)
    assert calls["browser"] == ["https://x.example/a"]
    assert ladder.snapshot()["browser_budget_left"] == 0
    assert ladder.snapshot()["tls_attempts"] == 2


def test_browser_fake_accepts_only_the_url(monkeypatch):
    """F-7: there is no solver flag to pass — a fake that takes only ``url``
    is exactly what the ladder calls."""
    async def tls(url):
        return 200, WALL

    async def browser(url):
        return 200, REAL

    monkeypatch.setattr(stealthweb, "enabled", lambda: True)
    monkeypatch.setattr(stealthweb, "fetch_tls", tls)
    monkeypatch.setattr(stealthweb, "fetch_browser", browser)
    assert asyncio.run(StealthLadder(1)("https://x.example/a")) == (200, REAL, TIER3)
