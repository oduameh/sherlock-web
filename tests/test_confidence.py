from recon.confidence import (
    CORRELATION_LINK_MIN,
    account_confidence,
    account_tier,
    bucket_counts,
    verdict_bucket,
)


def test_unverified_single_engine_is_weak():
    # A bare, unverified "handle exists" hit must not read as a confident
    # account — belief has to be earned by verification.
    assert account_confidence({"engines": ["sherlock"]}) < 40


def test_two_engines_boosts():
    a = account_confidence({"engines": ["sherlock"]})
    b = account_confidence({"engines": ["sherlock", "maigret"]})
    assert b > a


def test_confirmed_beats_unverified_beats_flagged():
    base = {"engines": ["sherlock"]}
    unverified = account_confidence(base)
    confirmed = account_confidence({**base, "verification": {"status": "confirmed"}})
    flagged = account_confidence(
        {**base, "verification": {"status": "likely_false_positive"}})
    assert confirmed > unverified > flagged >= 5


def test_identity_attribution_boosts():
    without = account_confidence(
        {"engines": ["sherlock"], "verification": {"status": "confirmed"}})
    with_attr = account_confidence(
        {"engines": ["sherlock"],
         "verification": {"status": "confirmed", "identity_match": True}})
    assert with_attr > without


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
        "verification": {"status": "confirmed", "identity_match": True},
    })
    assert 5 <= top <= 100


def test_correlation_link_min_is_reasonable():
    assert 0 < CORRELATION_LINK_MIN <= 100


def test_verdict_buckets():
    assert verdict_bucket({"verification": {"status": "confirmed"}}) == "found"
    assert verdict_bucket(
        {"verification": {"status": "likely_false_positive"}}) == "flagged"
    # A row with no verdict was never examined — it is not a "lead" either.
    assert verdict_bucket({}) == "not_examined"
    assert verdict_bucket({"verification": {"status": "unconfirmed"}}) == "lead"
    counts = bucket_counts([
        {"verification": {"status": "confirmed"}},
        {"verification": {"status": "unconfirmed"}},
        {"verification": {"status": "likely_false_positive"}},
    ])
    assert counts["found"] == 1 and counts["lead"] == 1 and counts["flagged"] == 1


def test_blocked_and_unexamined_are_not_leads():
    """'We were blocked' and 'we never looked' must never be counted as leads —
    they are absences of evidence, not weak findings."""
    assert verdict_bucket({"verification": {"status": "indeterminate"}}) == "indeterminate"
    assert verdict_bucket({"verification": {"status": "not_examined"}}) == "not_examined"
    counts = bucket_counts([
        {"verification": {"status": "confirmed"}},
        {"verification": {"status": "unconfirmed"}},
        {"verification": {"status": "likely_false_positive"}},
        {"verification": {"status": "indeterminate"}},
        {"verification": {"status": "not_examined"}},
        {},
    ])
    assert counts == {"found": 1, "lead": 1, "flagged": 1,
                      "indeterminate": 1, "not_examined": 2}


def test_unexamined_never_outranks_examined():
    examined_weak = account_confidence(
        {"engines": ["s"], "verification": {"status": "unconfirmed"}})
    never_looked = account_confidence(
        {"engines": ["s"], "verification": {"status": "not_examined"}})
    assert examined_weak > never_looked


def test_account_tier_maps_onto_verdicts():
    # confirmed page → confirmed tier; false positive → refuted.
    assert account_tier({"verification": {"status": "confirmed"}}) == "confirmed"
    assert account_tier(
        {"verification": {"status": "likely_false_positive"}}) == "refuted"


def test_strong_tier_needs_a_corroborated_lead():
    # A real fetched page (lead) that also clears the corroboration bar
    # (two engines + a parsed identity) is a strong lead.
    strong = {
        "engines": ["sherlock", "maigret"],
        "enrichment": {"jsonld_name": "Alice Example"},
        "verification": {"status": "unconfirmed"},
    }
    assert account_confidence(strong) >= 40
    assert account_tier(strong) == "strong"


def test_weak_tier_covers_bare_leads_and_speculation():
    # A bare unconfirmed single-engine hit is a lead but not a strong one.
    assert account_tier(
        {"engines": ["sherlock"], "verification": {"status": "unconfirmed"}}) == "weak"
    # Speculative name-derived candidate.
    assert account_tier(
        {"engines": ["sherlock"], "source": "name",
         "verification": {"status": "unconfirmed"}}) == "weak"


def test_blocked_and_unexamined_are_weak_not_strong():
    # No evidential weight → weak, never strong (mirrors verdict_bucket).
    assert account_tier({"verification": {"status": "indeterminate"}}) == "weak"
    assert account_tier({"verification": {"status": "not_examined"}}) == "weak"
    assert account_tier({}) == "weak"
