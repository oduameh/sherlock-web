import pytest

from recon import engines
from recon.engines import _match_names, normalize_site


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
