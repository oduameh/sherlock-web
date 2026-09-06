"""recon.sources — the registry of directly-called sources and their health."""

import pytest

from recon import sources
from recon.sources import MECHANISMS, SOURCES, Source, SourceHealth

EXPECTED = {
    "github": "api.github.com",
    "bluesky": "public.api.bsky.app",
    "devto": "dev.to",
    "dockerhub": "hub.docker.com",
    "keybase": "keybase.io",
    "vimeo": "vimeo.com",
    "mastodon_social": "mastodon.social",
    "telegram": "t.me",
    "steam_community": "steamcommunity.com",
    "gravatar_json": "www.gravatar.com",
    "gravatar_html": "gravatar.com",
    "nominatim": "nominatim.openstreetmap.org",
    "ipwhois": "ipwho.is",
    "hudson_rock_cavalier": "cavalier.hudsonrock.com",
    "cloudflare_doh": "cloudflare-dns.com",
    "rdap": "rdap.org",
    "crtsh": "crt.sh",
}


def test_every_expected_source_is_registered_with_its_host():
    for name, host in EXPECTED.items():
        src = sources.get(name)
        assert src is not None, name
        assert src.host == host
    assert set(sources.names()) == set(EXPECTED)


def test_static_facts_are_well_formed():
    for src in SOURCES.values():
        assert src.mechanism in MECHANISMS
        assert 1 <= src.authority <= 5
        assert src.timeout_s > 0 and src.freshness_ttl_s > 0
        assert src.rate_limit and isinstance(src.rate_limit, str)
        assert src.fallback is None or src.fallback in SOURCES


def test_authority_ranking_matches_the_mechanism():
    """official API > structured endpoint > HTML with content markers."""
    assert sources.get("github").authority == 5
    assert sources.get("gravatar_json").authority == 4
    assert sources.get("telegram").authority == 3
    assert sources.get("gravatar_html").fallback == "gravatar_json"


def test_github_is_one_source_with_the_shared_budget_noted():
    """The timeline calls api.github.com too: one entry, one 60/h budget."""
    gh = sources.for_host("api.github.com")
    assert [s.name for s in gh] == ["github"]
    assert "60" in gh[0].rate_limit
    assert "timeline" in gh[0].notes and "shared" in gh[0].notes.lower()


def test_for_host_ignores_www_and_case():
    assert [s.name for s in sources.for_host("T.ME")] == ["telegram"]
    assert {s.name for s in sources.for_host("gravatar.com")} == {"gravatar_json",
                                                                  "gravatar_html"}
    assert sources.for_host("nowhere.example") == []


def test_source_validation():
    with pytest.raises(ValueError):
        Source("x", "x.test", "magic", 3, "n/a", 1, 1)
    with pytest.raises(ValueError):
        Source("x", "x.test", "api", 9, "n/a", 1, 1)


# --- runtime health -------------------------------------------------------------

def test_health_failure_rate_ewma_and_dominant_reason():
    clock = {"t": 1_700_000_000.0}
    h = SourceHealth(window=50, clock=lambda: clock["t"])
    h.record("github", True, 100)
    clock["t"] += 1
    h.record("github", False, 300, "HTTP 429")
    clock["t"] += 1
    h.record("github", False, None, "HTTP 429")
    h.record("github", False, 50, "ConnectTimeout")
    got = h.health("github")
    assert got["observations"] == 4 and got["failures"] == 3
    assert got["failure_rate"] == 0.75
    assert got["dominant_reason"] == "HTTP 429"
    assert got["last_ok_at"] == "2023-11-14T22:13:20Z"
    assert got["last_failure_at"] > got["last_ok_at"]
    # EWMA over the three latencies seen (the None one is skipped).
    expected = 100.0
    for lat in (300.0, 50.0):
        expected = 0.3 * lat + 0.7 * expected
    assert got["ewma_latency_ms"] == round(expected, 1)


def test_health_window_keeps_the_last_n_observations():
    h = SourceHealth(window=3)
    for ok in (False, False, True, True, True):
        h.record("nominatim", ok, 10)
    got = h.health("nominatim")
    assert got["observations"] == 3 and got["failures"] == 0
    assert got["failure_rate"] == 0.0


def test_unknown_source_never_raises_and_appears_in_summary():
    h = SourceHealth()
    h.record("", True, 1)                    # ignored
    h.record("mystery", False, 5, "boom")
    h.record("github", True, "not-a-number")   # bad latency: dropped silently
    rows = h.summary()
    names = [r["name"] for r in rows]
    assert "mystery" in names and set(EXPECTED) <= set(names)
    mystery = next(r for r in rows if r["name"] == "mystery")
    assert mystery["host"] is None and mystery["failure_rate"] == 1.0
    assert rows[0]["name"] == "mystery"     # worst first


def test_summary_shape_is_additive_for_the_health_endpoint():
    h = SourceHealth()
    h.record("crtsh", False, 900, "HTTP 503")
    row = next(r for r in h.summary() if r["name"] == "crtsh")
    for key in ("name", "host", "mechanism", "authority", "observations",
                "failure_rate", "last_ok_at", "ewma_latency_ms", "dominant_reason"):
        assert key in row
    assert row["host"] == "crt.sh" and row["mechanism"] == "structured"
    assert row["dominant_reason"] == "HTTP 503" and row["last_ok_at"] is None


def test_module_level_ledger():
    sources.reset()
    sources.record("ipwhois", True, 12)
    assert sources.health("ipwhois")["observations"] == 1
    assert any(r["name"] == "ipwhois" and r["observations"] == 1
               for r in sources.summary())
    sources.reset()
    assert sources.health("ipwhois")["observations"] == 0
