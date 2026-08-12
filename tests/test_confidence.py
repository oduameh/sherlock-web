from recon.confidence import (
    CORRELATION_LINK_MIN,
    account_confidence,
)


def test_base_single_engine_account():
    assert account_confidence({"engines": ["sherlock"]}) == 45


def test_two_engines_boosts():
    a = account_confidence({"engines": ["sherlock"]})
    b = account_confidence({"engines": ["sherlock", "maigret"]})
    assert b > a


def test_verification_confirmed_raises_false_lowers():
    base = {"engines": ["sherlock"]}
    confirmed = account_confidence({**base, "verification": {"status": "confirmed"}})
    flagged = account_confidence(
        {**base, "verification": {"status": "likely_false_positive"}})
    assert confirmed > 45 > flagged
    assert flagged >= 5  # never below the floor


def test_name_source_penalized():
    strong = account_confidence({"engines": ["sherlock", "maigret"]})
    named = account_confidence(
        {"engines": ["sherlock", "maigret"], "source": "name"})
    assert named < strong


def test_enrichment_identity_boosts():
    plain = account_confidence({"engines": ["sherlock"]})
    enriched = account_confidence(
        {"engines": ["sherlock"], "enrichment": {"jsonld_name": "Alice"}})
    assert enriched > plain


def test_clamped_to_range():
    top = account_confidence({
        "engines": ["sherlock", "maigret"],
        "enrichment": {"og_image": "x"},
        "verification": {"status": "confirmed"},
    })
    assert 5 <= top <= 100


def test_correlation_link_min_is_reasonable():
    assert 0 < CORRELATION_LINK_MIN <= 100
