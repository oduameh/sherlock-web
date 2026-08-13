from recon.brokers import reverse_phone_links
from recon.phone_pivot import phone_footprint, phone_intel


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


def test_formats_and_footprint_shape():
    res = phone_intel("+14155552671")
    fmts = res["formats"]
    assert fmts["e164"] == "+14155552671"
    assert fmts["national_digits"] == "4155552671"
    assert fmts["e164_digits"] == "14155552671"
    assert fmts["dashed"] == "415-555-2671"
    kinds = {f["kind"] for f in res["footprint"]}
    assert "search" in kinds and "messaging" in kinds
    # NANP number gets spam/reputation leads.
    assert "reputation" in kinds
    # WhatsApp presence link uses the full-digits number.
    wa = next(f for f in res["footprint"] if f["kind"] == "messaging")
    assert wa["url"] == "https://wa.me/14155552671"


def test_footprint_non_nanp_has_no_reputation():
    res = phone_intel("+442079460018")  # GB
    kinds = {f["kind"] for f in res["footprint"]}
    assert "search" in kinds and "messaging" in kinds
    assert "reputation" not in kinds


def test_phone_footprint_helper():
    out = phone_footprint("+14155552671")
    assert out["formats"]["e164"] == "+14155552671"
    assert out["footprint"]
    assert phone_footprint("not a phone").get("error")


def test_reverse_phone_links_us():
    res = phone_intel("+14155552671")
    links = reverse_phone_links(res["e164"], res["region"])
    assert links, "US number should yield reverse-lookup broker links"
    names = {b["name"] for b in links}
    assert "TruePeopleSearch" in names
    tps = next(b for b in links if b["name"] == "TruePeopleSearch")
    assert "4155552671" in tps["search_url"]
    assert tps["optout_url"]  # opt-out pulled from the broker registry


def test_reverse_phone_links_non_us_gated():
    res = phone_intel("+442079460018")  # GB
    assert reverse_phone_links(res["e164"], res["region"]) == []
    assert reverse_phone_links("", "US") == []
