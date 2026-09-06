from types import SimpleNamespace

import pytest

from recon import engines, policy
from recon.engines import _match_names, normalize_site


# --- access policy on the curated list and engine subsets -------------------

def test_high_value_sites_has_no_denied_member():
    """Twitter, Instagram, Reddit, Pinterest, Facebook and Flickr were listed
    here until 2026-09-06 and so were scanned on every variant pass by all
    three engines. The curated list must never name a denied platform."""
    denied = [n for n in engines.HIGH_VALUE_SITES if policy.denied_name_reason(n)]
    assert denied == []
    for gone in ("Twitter", "Instagram", "Reddit", "Pinterest", "Facebook", "Flickr"):
        assert gone not in engines.HIGH_VALUE_SITES
    assert "GitHub" in engines.HIGH_VALUE_SITES     # the list is still populated
    assert "HackerNews" in engines.HIGH_VALUE_SITES  # permitted on news.ycombinator.com


def test_sherlock_url_templates_lists_every_fetched_url():
    info = {"url": "https://a/{}", "urlProbe": "https://b/{}", "urlMain": "https://a/",
            "errorType": "status_code"}
    assert engines.sherlock_url_templates(info) == ["https://a/{}", "https://b/{}", "https://a/"]
    assert engines.sherlock_url_templates({"url": "https://a/{}"}) == ["https://a/{}"]
    assert engines.sherlock_url_templates({}) == []


def test_maigret_url_templates_resolves_placeholders():
    site = SimpleNamespace(url="{urlMain}{urlSubpath}/users/{username}",
                           url_probe="https://api.example/{username}",
                           url_main="https://forum.example", url_subpath="/f")
    assert engines.maigret_url_templates(site) == [
        "https://forum.example/f/users/probe", "https://api.example/probe",
        "https://forum.example",
    ]
    bare = SimpleNamespace(url="https://x/{username}", url_probe=None, url_main="")
    assert engines.maigret_url_templates(bare) == ["https://x/probe"]


def test_sherlock_variant_site_data_filters_denied_hosts():
    """Defence in depth: even if the curated name maps to a denied URL in some
    site database, the subset must not carry it (default), while the plan can
    ask for the raw subset and filter + report itself."""
    data = {
        "GitHub": {"url": "https://github.com/{}", "urlMain": "https://github.com/"},
        "Keybase": {"url": "https://instagram.com/{}",          # corrupted entry
                    "urlMain": "https://keybase.io/"},
        "Instagram": {"url": "https://instagram.com/{}", "urlMain": "https://instagram.com/"},
    }
    assert list(engines.sherlock_variant_site_data(data)) == ["GitHub"]
    assert list(engines.sherlock_variant_site_data(data, policy_filtered=False)) == \
        ["GitHub", "Keybase"]                                  # Instagram isn't curated at all


def test_maigret_variant_sites_contains_no_denied_url():
    if not engines.maigret_available():
        pytest.skip("maigret not installed")
    filtered = engines.maigret_variant_sites()
    for name, site in filtered.items():
        assert policy.denied_site_reason(engines.maigret_url_templates(site)) is None, name
    raw = engines.maigret_variant_sites(policy_filtered=False)
    assert set(filtered) <= set(raw)
    # Maigret's HackerNews probes the denied Firebase API behind a permitted
    # profile URL: present in the raw subset, gone from the filtered one.
    assert "HackerNews" in raw and "HackerNews" not in filtered
    assert 5 <= len(filtered)                                 # still a useful subset


def test_normalize_site_strips_non_alnum_and_lowercases():
    assert normalize_site("GitHub") == "github"
    assert normalize_site("DEV Community") == "devcommunity"
    assert normalize_site("linktr.ee") == "linktree"
    assert normalize_site("About.me") == "aboutme"


def test_match_names_is_case_and_punctuation_insensitive():
    available = ["GitHub", "twitter", "Dev.to"]
    picked = _match_names(available, ["GitHub", "Twitter"])
    assert picked == ["GitHub", "twitter"]


def test_match_names_uses_aliases():
    # "DEV Community" is aliased to dev.to across engine databases.
    available = ["dev.to"]
    assert _match_names(available, ["DEV Community"]) == ["dev.to"]

    available = ["linktr.ee"]
    assert _match_names(available, ["Linktree"]) == ["linktr.ee"]


def test_match_names_skips_missing():
    assert _match_names(["GitHub"], ["Nonexistent Site"]) == []


def test_maigret_all_sites_thorough_scans_more_than_default():
    if not engines.maigret_available():
        pytest.skip("maigret not installed")
    full = len(engines.load_maigret_db().sites)
    default = engines.maigret_all_sites()          # capped by rank
    thorough = engines.maigret_all_sites(None)     # entire database
    assert len(thorough) > len(default)            # thorough scans more
    assert len(thorough) >= 0.9 * full             # ~the whole database
    assert len(default) < 0.6 * full               # default is a real subset
