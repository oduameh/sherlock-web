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

    # (Was a fake ``instagram`` module until 2026-09-06 — a denied host that
    # the access policy now skips, so the shape test uses a permitted one.)
    async def snapchat(phone, country_code, client, out):
        out.append({"name": "Snapchat", "domain": "snapchat.com",
                    "exists": False, "rateLimit": False, "method": "register"})

    monkeypatch.setattr(phone_accounts, "_ignorant_functions",
                        lambda: [amazon, snapchat])
    res, got = _scan()
    assert len(res) == 2 and len(got) == 2  # streamed one per module
    amazon_entry = next(e for e in res if e["site"] == "Amazon")
    assert amazon_entry["exists"] is True
    assert amazon_entry["domain"] == "amazon.com"
    assert amazon_entry["method"] == "login"
    snap = next(e for e in res if e["site"] == "Snapchat")
    assert snap["exists"] is False


def test_ignorant_scan_skips_modules_on_denied_hosts(monkeypatch, caplog):
    """ignorant ships an ``instagram`` module that posts the number to a
    robots-denied host; it ran on every phone pivot (security F-2). The
    policy filter must skip it — emitting nothing, since it was not checked —
    and run the permitted modules unchanged."""
    ran = []

    async def instagram(phone, country_code, client, out):     # denied by name
        ran.append("instagram")
        out.append({"name": "Instagram", "domain": "instagram.com", "exists": True})

    async def lookup(phone, country_code, client, out):        # denied by constant
        ran.append("lookup")
        domain = "instagram.com"
        out.append({"name": "Lookup", "domain": domain, "exists": True})

    async def amazon(phone, country_code, client, out):
        ran.append("amazon")
        out.append({"name": "Amazon", "domain": "amazon.com", "exists": True})

    monkeypatch.setattr(phone_accounts, "_ignorant_functions",
                        lambda: [instagram, lookup, amazon])
    import logging
    caplog.set_level(logging.DEBUG, logger="recon.phone_accounts")
    res, got = _scan()
    assert ran == ["amazon"]                       # denied modules never called
    assert [e["site"] for e in res] == ["Amazon"]  # nothing emitted for them
    assert [e["site"] for e in got] == ["Amazon"]
    assert not any("Instagram" in str(e) or "Lookup" in str(e) for e in got)
    assert "skipped by access policy" in caplog.text
    assert "instagram" in caplog.text and "lookup" in caplog.text


def test_ignorant_only_subset_still_honours_policy(monkeypatch):
    async def instagram(phone, country_code, client, out):
        out.append({"name": "Instagram", "exists": True})

    async def amazon(phone, country_code, client, out):
        out.append({"name": "Amazon", "exists": True})

    monkeypatch.setattr(phone_accounts, "_ignorant_functions",
                        lambda: [instagram, amazon])
    res, _ = _scan(only={"instagram", "amazon"})
    assert [e["site"] for e in res] == ["Amazon"]


def test_real_ignorant_modules_exclude_instagram():
    """Against the installed ignorant (1.2): exactly its Instagram module is
    denied; Amazon and Snapchat stay. Skipped if ignorant is missing."""
    if not phone_accounts.ignorant_available():
        import pytest
        pytest.skip("ignorant not installed")
    from recon import policy
    fns = phone_accounts._ignorant_functions()
    kept, skipped = policy.partition_check_functions(fns)
    assert skipped == ["instagram"]
    assert {fn.__name__ for fn in kept} >= {"amazon", "snapchat"}


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
