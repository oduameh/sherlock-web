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
