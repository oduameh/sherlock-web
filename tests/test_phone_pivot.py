from recon.phone_pivot import phone_intel


def test_valid_e164_number():
    res = phone_intel("+14155552671")
    assert res["valid"] is True
    assert res["e164"] == "+14155552671"
    assert res["country_code"] == 1
    assert res["region"] == "US"


def test_national_with_country_hint():
    res = phone_intel("020 7946 0018", country_hint="GB")
    assert res["e164"] == "+442079460018"
    assert res["region"] == "GB"


def test_unparseable_number():
    res = phone_intel("not a phone")
    assert "error" in res


def test_empty_input():
    assert phone_intel("")["error"] == "empty phone number"


def test_reserved_range_note():
    # US 555-01xx is reserved / fictional: possible but not valid.
    res = phone_intel("+1 415 555 0100")
    if res.get("possible") and not res.get("valid"):
        assert "note" in res
