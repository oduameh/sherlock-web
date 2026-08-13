from recon.exposure import (
    categorize_site,
    exposure_summary,
    footprint_score,
)


def _summary():
    return {
        "params": {"usernames": ["alice"], "email": "alice@example.com"},
        "accounts": [
            {"username": "alice", "site": "GitHub",
             "url": "https://github.com/alice",
             "engines": ["sherlock", "maigret"],
             "verification": {"status": "confirmed"},
             "enrichment": {"jsonld_name": "Alice Example",
                            "jsonld_image": "https://img/alice.png"}},
            {"username": "alice", "site": "Twitter",
             "url": "https://twitter.com/alice", "engines": ["sherlock"]},
        ],
        "variants": [],
        "name_accounts": [],
        "email": {"gravatar": {"display_name": "Alice"},
                  "holehe": [{"exists": True, "site": "Spotify"},
                             {"exists": False, "site": "X"}]},
        "phone": {"valid": True, "country": "United States"},
        "correlation": [{"confidence": 80}],
    }


def test_categorize_site_known_and_default():
    assert categorize_site("GitHub") == "development"
    assert categorize_site("github") == "development"
    assert categorize_site("Twitter") == "social"
    assert categorize_site("LinkedIn") == "professional"
    assert categorize_site("Totally Unknown Site") == "other"


def test_footprint_score_weighted_by_verification():
    score = footprint_score(_summary())
    # 1 confirmed*6 + 1 email-registration*5 + 10 gravatar + 10 phone.
    # The second account carries no verdict — never examined — so it adds
    # nothing: absence of evidence must not inflate an exposure score.
    assert score["score"] == 6 + 5 + 10 + 10
    assert "parts" in score


def test_footprint_score_ignores_false_positives():
    s = _summary()
    # Flip the unverified Twitter account into a flagged false positive: it must
    # no longer add to the score.
    s["accounts"][1]["verification"] = {"status": "likely_false_positive"}
    score = footprint_score(s)
    # 1 confirmed*6 + 0 leads + 5 email + 10 gravatar + 10 phone.
    assert score["score"] == 6 + 5 + 10 + 10


def test_exposure_counts_and_categories():
    exp = exposure_summary(_summary())
    c = exp["counts"]
    assert c["accounts"] == 2
    assert c["platforms"] == 2
    assert c["verified"] == 1
    assert c["email_registrations"] == 1
    assert c["high_confidence_links"] == 1
    assert exp["categories"] == {"development": 1, "social": 1}


def test_exposure_identity_signals_and_top_accounts():
    exp = exposure_summary(_summary())
    sig = exp["identity_signals"]
    assert sig["has_real_name"] is True
    assert sig["has_avatar"] is True
    assert sig["gravatar"] is True
    assert sig["phone_valid"] is True
    assert "Alice Example" in sig["display_names"]
    # GitHub wins on confidence (two engines + identity + confirmed).
    assert exp["top_accounts"][0]["site"] == "GitHub"
    assert exp["top_accounts"][0]["confidence"] >= exp["top_accounts"][1][
        "confidence"]


def test_exposure_band_and_factors():
    exp = exposure_summary(_summary())
    assert exp["band"] in ("moderate", "significant", "extensive")
    assert any("phone" in f for f in exp["factors"])
    assert exp["factors"][-1].startswith("overall exposure:")


def test_exposure_empty_summary_is_wellformed():
    exp = exposure_summary({})
    assert exp["score"] == 0
    assert exp["band"] == "minimal"
    assert exp["counts"]["accounts"] == 0
    assert exp["categories"] == {}
    assert exp["top_accounts"] == []
    assert "no public exposure detected" in exp["factors"][0]


def test_exposure_handles_none():
    # Never raises on a missing summary.
    assert exposure_summary(None)["score"] == 0
