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


# --- G2: checks go through recon.retrieval.fetch ------------------------------------

def test_classify_page_blocked_is_never_not_found():
    from recon import retrieval
    wall = ("<html><head><title>Just a moment...</title></head><body>"
            "Checking your browser before accessing.</body></html>")
    assert brokers.classify_page(retrieval.FetchResult(
        retrieval.BLOCKED, 'challenge page ("just a moment")', 200, wall), "m") == brokers.BLOCKED
    assert brokers.classify_page(retrieval.FetchResult(
        retrieval.BLOCKED, "rate limited (HTTP 429)", 429, None, rate_limited=True), "m") == brokers.BLOCKED
    assert brokers.classify_page(retrieval.FetchResult(
        retrieval.TRANSPORT, "no response (ReadTimeout)", None, None, "ReadTimeout"), "m") == brokers.BLOCKED
    assert brokers.classify_page(retrieval.FetchResult(
        retrieval.ABSENT, "HTTP 404", 404, "gone"), "m") == brokers.NOT_FOUND
    listed = retrieval.FetchResult(retrieval.OK, "HTTP 200", 200,
                                   "<html><body>" + "Results for John Smith. " * 8
                                   + "<div class=person-card>John</div></body></html>")
    assert brokers.classify_page(listed, "person-card") == brokers.LISTED
    assert brokers.classify_page(listed, "no-such-marker") == brokers.NOT_FOUND
    captcha = retrieval.FetchResult(retrieval.OK, "HTTP 200", 200,
                                    "<html><body><h1>Please complete the CAPTCHA to "
                                    "continue</h1><div class=person-card>x</div></body></html>")
    assert brokers.classify_page(captcha, "person-card") == brokers.BLOCKED


def test_check_over_a_mock_transport(monkeypatch, public_dns):
    import asyncio
    import httpx
    from conftest import mock_client
    from recon import retrieval

    def handler(req):
        p = req.url.path
        if p == "/waf":
            return httpx.Response(200, headers={"content-type": "text/html"},
                                  text="<html><head><title>Access Denied</title></head>"
                                       "<body>Reference #18.3a2f1602</body></html>")
        if p == "/gone":
            return httpx.Response(404)
        if p == "/limited":
            return httpx.Response(429)
        if p == "/boom":
            raise httpx.ConnectTimeout("slow")
        return httpx.Response(200, headers={"content-type": "text/html"},
                              text="<html><body>" + "Results page text. " * 10
                                   + "<div class=person-card>x</div></body></html>")

    factory = mock_client(handler)
    st = retrieval.RetrievalStats()

    async def go():
        async with factory() as client:
            return [await brokers._check(client, f"https://broker.example{p}", "person-card",
                                         stats=st)
                    for p in ("/waf", "/gone", "/limited", "/boom", "/ok")]

    assert asyncio.run(go()) == [brokers.BLOCKED, brokers.NOT_FOUND, brokers.BLOCKED,
                                 brokers.BLOCKED, brokers.LISTED]
    assert st.snapshot()["requests"] == 5
