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
