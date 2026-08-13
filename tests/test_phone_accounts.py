"""Tests for the phone account-existence pivot (recon.phone_accounts).

The ignorant module callables are monkeypatched so no network is touched — we
assert the orchestration shape, streaming, aggregation, and the graceful
degradation paths, exactly like the holehe pivot's contract.
"""

import asyncio

from recon import phone_accounts


def _scan(**kw):
    got = []
    res = asyncio.run(
        phone_accounts.ignorant_scan(kw.pop("phone", "+14155552671"),
                                     got.append, delay=0, **kw))
    return res, got


def test_ignorant_scan_streams_and_shapes(monkeypatch):
    async def amazon(phone, country_code, client, out):
        # ignorant modules receive the national number + country code string.
        assert phone == "4155552671" and country_code == "1"
        out.append({"name": "Amazon", "domain": "amazon.com",
                    "exists": True, "rateLimit": False, "method": "login"})

    async def instagram(phone, country_code, client, out):
        out.append({"name": "Instagram", "domain": "instagram.com",
                    "exists": False, "rateLimit": False, "method": "register"})

    monkeypatch.setattr(phone_accounts, "_ignorant_functions",
                        lambda: [amazon, instagram])
    res, got = _scan()
    assert len(res) == 2 and len(got) == 2  # streamed one per module
    amazon_entry = next(e for e in res if e["site"] == "Amazon")
    assert amazon_entry["exists"] is True
    assert amazon_entry["domain"] == "amazon.com"
    assert amazon_entry["method"] == "login"
    insta = next(e for e in res if e["site"] == "Instagram")
    assert insta["exists"] is False


def test_ignorant_scan_unavailable(monkeypatch):
    monkeypatch.setattr(phone_accounts, "_ignorant_functions", lambda: [])
    res, got = _scan()
    assert res == []
    assert got and got[0].get("error")  # emits an "unavailable" marker


def test_ignorant_scan_module_error_never_raises(monkeypatch):
    async def boom(phone, country_code, client, out):
        raise RuntimeError("endpoint changed")

    monkeypatch.setattr(phone_accounts, "_ignorant_functions", lambda: [boom])
    res, got = _scan()
    assert len(res) == 1
    assert res[0]["exists"] is None and "error" in res[0]


def test_ignorant_scan_unparseable_number():
    # _split_e164 fails before any module runs -> error marker, empty results.
    res, got = _scan(phone="garbage")
    assert res == []
    assert got and got[0].get("error")


def test_ignorant_scan_only_subset(monkeypatch):
    async def amazon(phone, country_code, client, out):
        out.append({"name": "Amazon", "exists": True})

    async def snapchat(phone, country_code, client, out):
        out.append({"name": "Snapchat", "exists": True})

    monkeypatch.setattr(phone_accounts, "_ignorant_functions",
                        lambda: [amazon, snapchat])
    res, _ = _scan(only={"amazon"})
    assert [e["site"] for e in res] == ["Amazon"]
