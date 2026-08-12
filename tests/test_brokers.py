from recon import brokers


def test_registry_loads_with_required_fields():
    reg = brokers.load_brokers()
    assert len(reg) >= 20
    for b in reg:
        assert b.get("name")
        assert b.get("optout_url", "").startswith("http")


def test_name_parts():
    assert brokers.name_parts("John Smith") == ("John", "Smith")
    assert brokers.name_parts("John Q Public") == ("John", "Public")
    assert brokers.name_parts("") == (None, None)


def test_parse_location():
    assert brokers.parse_location("Austin, TX") == ("Austin", "TX")
    assert brokers.parse_location("Austin") == ("Austin", None)
    assert brokers.parse_location("") == (None, None)


def test_build_search_url_fills_placeholders():
    b = {"search_url": "https://x/{first}-{last}_{city}-{state}"}
    assert brokers.build_search_url(b, "John", "Smith", "John Smith", "Austin", "TX") == \
        "https://x/John-Smith_Austin-TX"


def test_build_search_url_missing_field_returns_none():
    b = {"search_url": "https://x/{first}-{last}_{city}-{state}"}
    # no city -> can't build a location-based URL
    assert brokers.build_search_url(b, "John", "Smith", "John Smith", None, None) is None


def test_build_search_url_none_template():
    assert brokers.build_search_url({"search_url": None}, "a", "b", "a b", "c", "d") is None


def test_build_search_url_encodes():
    b = {"search_url": "https://x/{name}"}
    assert brokers.build_search_url(b, "a", "b", "Jo Sm", None, None) == "https://x/Jo%20Sm"
