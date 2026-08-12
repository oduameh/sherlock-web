from recon import whatsmyname as wmn


_SITE = {
    "name": "Example",
    "uri_check": "https://example.com/{account}",
    "e_code": 200,
    "e_string": "profile-header",
    "m_code": 404,
    "m_string": "not found",
    "cat": "social",
}


def test_classify_claimed():
    assert wmn.classify_response(_SITE, 200, "<div class=profile-header>") == wmn.CLAIMED


def test_classify_available_by_missing_code():
    assert wmn.classify_response(_SITE, 404, "whatever") == wmn.AVAILABLE


def test_classify_available_by_missing_string():
    assert wmn.classify_response(_SITE, 200, "sorry, not found here") == wmn.AVAILABLE


def test_classify_found_code_without_found_string_is_available():
    # 200 but the positive marker is absent -> soft-404, not a match.
    assert wmn.classify_response(_SITE, 200, "generic landing page") == wmn.AVAILABLE


def test_classify_unknown():
    assert wmn.classify_response(_SITE, 503, "server error") == wmn.UNKNOWN


def test_classify_no_estring_uses_code_alone():
    site = dict(_SITE, e_string="")
    assert wmn.classify_response(site, 200, "anything") == wmn.CLAIMED


def test_dataset_loads_and_is_substantial():
    sites = wmn.load_sites()
    assert len(sites) > 500
    # Every site has the fields the scanner relies on.
    for s in sites[:50]:
        assert s.get("name")
        assert "{account}" in (s.get("uri_check") or "")


def test_nsfw_filtered_by_default():
    assert len(wmn.all_sites(nsfw=False)) <= len(wmn.all_sites(nsfw=True))
    assert all(not wmn._is_nsfw(s) for s in wmn.all_sites(nsfw=False))


def test_variant_subset_is_high_value_and_smaller():
    variant = wmn.variant_sites()
    assert 0 < len(variant) < len(wmn.all_sites())
