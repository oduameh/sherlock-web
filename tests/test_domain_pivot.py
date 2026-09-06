from recon.domain_pivot import (
    domain_from_email,
    looks_like_domain,
    parse_crtsh,
    parse_doh,
    parse_rdap,
)


def test_looks_like_domain():
    assert looks_like_domain("example.com")
    assert looks_like_domain("sub.example.co.uk")
    assert not looks_like_domain("jane@example.com")
    assert not looks_like_domain("http://example.com")
    assert not looks_like_domain("notadomain")
    assert not looks_like_domain("")


def test_domain_from_email():
    assert domain_from_email("Jane.Doe@GitHub.com") == "github.com"
    assert domain_from_email("noatsign") is None
    assert domain_from_email("bad@notld") is None


def test_parse_doh_by_type():
    payload = {
        "Answer": [
            {"name": "example.com", "type": 1, "data": "93.184.216.34"},
            {"name": "example.com", "type": 15, "data": "10 mail.example.com."},
            {"name": "example.com", "type": 16, "data": "\"v=spf1 -all\""},
            {"name": "example.com", "type": 2, "data": "a.iana-servers.net."},
        ]
    }
    assert parse_doh(payload, "A") == ["93.184.216.34"]
    assert parse_doh(payload, "MX") == ["10 mail.example.com"]
    assert parse_doh(payload, "TXT") == ["v=spf1 -all"]
    assert parse_doh(payload, "NS") == ["a.iana-servers.net"]
    assert parse_doh(payload, "AAAA") == []
    assert parse_doh({}, "A") == []


def test_parse_rdap():
    payload = {
        "events": [
            {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2026-08-13T04:00:00Z"},
        ],
        "entities": [
            {"roles": ["registrar"],
             "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar, Inc."]]]},
        ],
        "nameservers": [{"ldhName": "A.IANA-SERVERS.NET"}],
        "status": ["client delete prohibited"],
    }
    r = parse_rdap(payload)
    assert r["registrar"] == "Example Registrar, Inc."
    assert r["registered"].startswith("1995")
    assert r["expires"].startswith("2026")
    assert r["nameservers"] == ["a.iana-servers.net"]
    assert r["status"] == ["client delete prohibited"]


def test_parse_rdap_empty():
    r = parse_rdap({})
    assert r["registrar"] is None
    assert r["nameservers"] == []


def test_parse_crtsh_dedupes_and_scopes():
    entries = [
        {"name_value": "www.example.com\n*.example.com"},
        {"name_value": "api.example.com"},
        {"name_value": "example.com"},          # the apex itself is dropped
        {"name_value": "evil-example.com"},     # not a subdomain -> dropped
        {"name_value": "api.example.com"},      # duplicate
    ]
    subs = parse_crtsh(entries, "example.com")
    assert subs == ["api.example.com", "www.example.com"]
    assert "example.com" not in subs
    assert "evil-example.com" not in subs


# --- G2: sources that did not answer are reported, never emptied ----------------------

def _doh(name, rtype, data):
    import httpx
    codes = {"A": 1, "MX": 15, "NS": 2, "TXT": 16, "AAAA": 28}
    return httpx.Response(200, headers={"content-type": "application/dns-json"},
                          json={"Status": 0, "Answer": [{"name": name, "type": codes[rtype],
                                                         "data": d} for d in data]})


def _intel(monkeypatch, handler, calls=None):
    import asyncio
    from conftest import mock_client
    from recon import domain_pivot, retrieval
    monkeypatch.setattr(domain_pivot.safeweb, "async_client", mock_client(handler, calls))
    st = retrieval.RetrievalStats()
    return asyncio.run(domain_pivot.domain_intel("example.com", retrieval_stats=st)), st


def test_domain_intel_crtsh_503_is_an_error_not_zero_subdomains(monkeypatch, public_dns):
    import httpx
    from recon import sources
    sources.reset()

    def handler(req):
        host = req.url.host
        if host == "cloudflare-dns.com":
            rtype = req.url.params["type"]
            return _doh("example.com", rtype, {"A": ["93.184.216.34"],
                                               "NS": ["a.iana-servers.net."]}.get(rtype, []))
        if host == "rdap.org":
            return httpx.Response(200, headers={"content-type": "application/rdap+json"},
                                  json={"events": [{"eventAction": "registration",
                                                    "eventDate": "1995-08-14T04:00:00Z"}],
                                        "nameservers": [{"ldhName": "A.IANA-SERVERS.NET"}]})
        if host == "crt.sh":
            return httpx.Response(503, text="<html>Service Unavailable</html>")
        raise AssertionError(f"unexpected host {host}")

    data, st = _intel(monkeypatch, handler)
    assert data["dns"]["A"] == ["93.184.216.34"] and data["dns"]["NS"] == ["a.iana-servers.net"]
    assert data["rdap"]["registrar"] is None and data["rdap"]["registered"].startswith("1995")
    assert data["subdomains"] == [] and data["subdomain_count"] is None
    assert data["errors"] == [{"source": "crtsh", "query": "example.com",
                               "reason": "rate limited (HTTP 503)"}]
    assert st.snapshot()["requests"] == 7
    h = sources.health("crtsh")
    assert h["failures"] == 1 and h["dominant_reason"] == "rate limited (HTTP 503)"
    assert sources.health("cloudflare_doh")["observations"] == 5
    assert sources.health("rdap")["failures"] == 0
    sources.reset()


def test_domain_intel_all_sources_answering_has_no_errors(monkeypatch, public_dns):
    import httpx

    def handler(req):
        host = req.url.host
        if host == "cloudflare-dns.com":
            return _doh("example.com", req.url.params["type"], [])
        if host == "rdap.org":
            return httpx.Response(404)                       # unregistered: absent, not an error
        if host == "crt.sh":
            assert req.url.params["q"] == "%.example.com" and req.url.params["output"] == "json"
            return httpx.Response(200, json=[{"name_value": "www.example.com\napi.example.com"},
                                             {"name_value": "example.com"}])
        raise AssertionError(host)

    data, _ = _intel(monkeypatch, handler)
    assert data["errors"] == []
    assert data["subdomains"] == ["api.example.com", "www.example.com"]
    assert data["subdomain_count"] == 2
    assert data["rdap"] == {}


def test_domain_intel_transport_failures_carry_the_class(monkeypatch, public_dns):
    import httpx

    def handler(req):
        if req.url.host == "cloudflare-dns.com" and req.url.params["type"] == "MX":
            raise httpx.ReadTimeout("slow")
        if req.url.host == "crt.sh":
            return httpx.Response(200, json=[])
        return httpx.Response(200, json={"Answer": []})

    data, _ = _intel(monkeypatch, handler)
    assert data["errors"] == [{"source": "cloudflare_doh", "query": "MX example.com",
                               "reason": "no response (ReadTimeout)"}]
    assert data["subdomain_count"] == 0
