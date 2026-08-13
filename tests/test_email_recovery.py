"""Tests for masked recovery-trail handling (recon.email_pivot + graph edge).

Some holehe password-reset checks leak a *masked* recovery phone/email. We
surface those and, when a masked recovery phone matches the subject's number,
stitch the account to the phone in the graph. These verify the matching is
meaningful (tail digits) yet conservative (no coincidental short matches).
"""

from recon.email_pivot import annotate_recovery, masked_recovery_matches_phone
from recon.graph import build_graph


def test_masked_recovery_matches_phone_tail():
    for masked in ("•••-•••-2671", "*******2671", "+1 ••• ••• 2671", "xxx-xxx-2671"):
        assert masked_recovery_matches_phone(masked, "+14155552671") is True, masked


def test_masked_recovery_no_match():
    assert masked_recovery_matches_phone("•••-•••-9999", "+14155552671") is False
    assert masked_recovery_matches_phone("", "+14155552671") is False
    assert masked_recovery_matches_phone("•••-•••-2671", "") is False
    assert masked_recovery_matches_phone(None, "+14155552671") is False
    # Only two visible digits is not a meaningful match.
    assert masked_recovery_matches_phone("••••••••71", "+14155552671") is False


def test_annotate_recovery_sets_flag():
    e = {"site": "X", "exists": True, "phone_number": "•••-•••-2671"}
    annotate_recovery(e, "+14155552671")
    assert e.get("corroborates_phone") is True

    e2 = {"site": "Y", "exists": True, "phone_number": "•••-•••-0000"}
    annotate_recovery(e2, "+14155552671")
    assert "corroborates_phone" not in e2

    e3 = {"site": "Z", "exists": True}  # no recovery phone at all
    annotate_recovery(e3, "+14155552671")
    assert "corroborates_phone" not in e3


def test_graph_links_corroborating_recovery_to_phone():
    summary = {
        "params": {"email": "a@b.com", "phone": "+14155552671"},
        "accounts": [], "variants": [], "name_accounts": [],
        "email": {"gravatar": None, "holehe": [
            {"site": "Twitter", "domain": "twitter.com", "exists": True,
             "phone_number": "•••-•••-2671", "corroborates_phone": True},
            {"site": "Imgur", "domain": "imgur.com", "exists": True},
        ]},
        "phone": {"valid": True, "e164": "+14155552671",
                  "international": "+1 415-555-2671", "region": "US"},
        "correlation": [],
    }
    g = build_graph(summary)
    edges = [e for e in g["edges"]
             if e["source"] == "reg:Twitter" and e["target"] == "phone"]
    assert len(edges) == 1
    assert edges[0]["confidence"] == 80
    # The non-corroborating registration must NOT link to the phone.
    assert not [e for e in g["edges"]
                if e["source"] == "reg:Imgur" and e["target"] == "phone"]
