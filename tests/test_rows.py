"""recon.rows — the one accessor for account-row fields (D7 / V10)."""

from recon import rows

TITLE = "carmen_pop - Streamer Overview & Stats · TwitchTracker"


def test_display_name_never_reads_the_raw_title():
    row = {"enrichment": {"title": TITLE}}
    assert rows.display_name(row) is None


def test_display_name_precedence():
    assert rows.display_name({"enrichment": {"og_title": "Alice", "title": TITLE}}) == "Alice"
    assert rows.display_name({"enrichment": {"jsonld_name": "Alice R.", "og_title": "Alice",
                                             "title": TITLE}}) == "Alice R."
    assert rows.display_name({"platform_identity": {"display_name": "Alice Real"},
                              "enrichment": {"jsonld_name": "Alice R.",
                                             "og_title": "Alice"}}) == "Alice Real"
    # Blank strings fall through; non-strings are ignored.
    assert rows.display_name({"platform_identity": {"display_name": "  "},
                              "enrichment": {"jsonld_name": 42,
                                             "og_title": " Alice "}}) == "Alice"


def test_avatar_bio_handle_created_at():
    row = {
        "username": "alice",
        "platform_identity": {"avatar": "https://p/a.png", "bio": "maps",
                              "canonical_handle": "Alice"},
        "enrichment": {"jsonld_image": "https://j/a.png", "og_image": "https://o/a.png",
                       "jsonld_description": "jd", "og_description": "od"},
        "temporal": {"created_at": "2011-01-25T18:44:36Z"},
    }
    assert rows.avatar(row) == "https://p/a.png"
    assert rows.bio(row) == "maps"
    assert rows.handle(row) == "Alice"
    assert rows.created_at(row) == "2011-01-25T18:44:36Z"
    del row["platform_identity"]
    assert rows.avatar(row) == "https://j/a.png" and rows.bio(row) == "jd"
    assert rows.handle(row) == "alice"
    del row["enrichment"]["jsonld_image"], row["enrichment"]["jsonld_description"]
    assert rows.avatar(row) == "https://o/a.png" and rows.bio(row) == "od"


def test_every_accessor_is_total():
    for bad in (None, {}, {"enrichment": None}, {"enrichment": "x"},
                {"platform_identity": []}, {"temporal": "2011"}, []):
        assert rows.display_name(bad) is None
        assert rows.avatar(bad) is None
        assert rows.bio(bad) is None
        assert rows.handle(bad) is None
        assert rows.created_at(bad) is None
    assert rows.enrichment({"enrichment": {"a": 1}}) == {"a": 1}
    assert rows.platform_identity({"platform_identity": {"a": 1}}) == {"a": 1}


def test_all_account_rows_order_and_tolerance():
    summary = {
        "accounts": [{"site": "A"}],
        "variants": None,
        "name_accounts": [{"site": "C"}, "junk", None],
    }
    assert rows.all_account_rows(summary) == [{"site": "A"}, {"site": "C"}]
    assert rows.all_account_rows({}) == []
    assert rows.all_account_rows(None) == []
    assert rows.all_account_rows({"accounts": [{"site": "A"}], "variants": [{"site": "B"}],
                                  "name_accounts": [{"site": "C"}]}) == [
        {"site": "A"}, {"site": "B"}, {"site": "C"}]
    assert rows.ROW_LISTS == ("accounts", "variants", "name_accounts")
