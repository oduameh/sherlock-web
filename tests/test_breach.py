"""Infostealer-exposure coverage — identifier selection and, critically, that
harvested secrets never survive summarization. No network."""

import asyncio

from recon import breach


_CAVALIER = {
    "message": "This email address is associated with a computer that was infected…",
    "stealers": [
        {
            "total_corporate_services": 16,
            "total_user_services": 1396,
            "date_compromised": "2026-08-20T00:00:00.000Z",
            "computer_name": "FIIP_EDIT (fixit)",
            "operating_system": "Windows 10",
            "malware_path": "C:\\Users\\fixit\\AppData\\Local\\x.exe",
            "antiviruses": ["Defender"],
            "ip": "49.207.***.***",
            "top_passwords": ["C****************", "9************"],
            "top_logins": ["i***************@gmail.com"],
        },
        {
            "total_user_services": 32482,
            "date_compromised": "2024-01-05T00:00:00.000Z",
            "computer_name": "OTHER-PC",
            "top_passwords": ["z*****"],
        },
    ],
}


# --- the security-critical property ----------------------------------------

def test_credentials_never_survive_summarization():
    """Even masked passwords/logins and the partial IP must be dropped — we
    report that a compromise happened, never the harvested secrets."""
    out = breach.summarize_response(_CAVALIER)
    blob = repr(out)
    for leaked in ("top_passwords", "top_logins", "C****", "9****",
                   "i*****", "z*****", "49.207", "ip"):
        assert leaked not in blob, f"{leaked!r} leaked into the summary"


def test_summary_keeps_the_exposure_shape():
    out = breach.summarize_response(_CAVALIER)
    assert out["compromised"] is True
    assert out["infections"] == 2
    assert out["first_compromise"].startswith("2024-01-05")
    assert out["last_compromise"].startswith("2026-08-20")
    first = out["stealers"][0]
    assert first["user_services"] == 1396
    assert first["computer_name"] == "FIIP_EDIT (fixit)"
    assert first["operating_system"] == "Windows 10"


def test_clean_and_malformed_responses_are_safe():
    for payload in ({}, {"stealers": []}, {"stealers": None},
                    {"stealers": ["junk", 5, None]}, None, "nope", []):
        out = breach.summarize_response(payload)
        assert out["compromised"] is False
        assert out["infections"] == 0


# --- identifier selection ---------------------------------------------------

def _summary(**params):
    return {"params": params}


def test_collects_email_domain_and_searched_usernames():
    ids = breach.collect_identifiers(_summary(
        email="a@b.test", domain="b.test", usernames=["alice", "alice2"]))
    assert ("email", "a@b.test") in ids
    assert ("domain", "b.test") in ids
    assert ("username", "alice") in ids
    assert ("username", "alice2") in ids


def test_speculative_name_candidates_are_never_checked():
    """name_accounts are guesses about *other people* — never query them."""
    s = {"params": {"name": "John Smith", "usernames": []},
         "name_accounts": [{"site": "GitHub", "username": "johnsmith"}]}
    assert breach.collect_identifiers(s) == []


def test_username_count_is_capped_and_deduped():
    ids = breach.collect_identifiers(_summary(
        usernames=["a", "A", "b", "c", "d", "e", "f", "g"]))
    assert len(ids) <= breach.MAX_USERNAMES
    values = [v.lower() for _, v in ids]
    assert len(values) == len(set(values))


def test_empty_summary_yields_nothing():
    assert breach.collect_identifiers({}) == []
    assert breach.collect_identifiers({"params": {}}) == []


# --- orchestration ----------------------------------------------------------

def test_unreachable_service_is_not_reported_as_clean(monkeypatch):
    async def dead(kind, value):
        return None
    monkeypatch.setattr(breach, "_lookup", dead)
    out = asyncio.run(breach.breach_exposure(_summary(email="a@b.test")))
    assert out["checked"] is False        # NOT a clean bill of health
    assert out["compromised_count"] == 0


def test_exposure_aggregates_hits(monkeypatch):
    async def fake(kind, value):
        return {"kind": kind, "identifier": value,
                "compromised": kind == "email", "infections": 1,
                "stealers": []}
    monkeypatch.setattr(breach, "_lookup", fake)
    out = asyncio.run(breach.breach_exposure(
        _summary(email="a@b.test", usernames=["alice"])))
    assert out["checked"] is True
    assert out["identifiers_checked"] == 2
    assert out["compromised_count"] == 1


def test_no_identifiers_short_circuits_without_network(monkeypatch):
    async def boom(kind, value):
        raise AssertionError("must not query the service")
    monkeypatch.setattr(breach, "_lookup", boom)
    out = asyncio.run(breach.breach_exposure({"params": {"name": "John"}}))
    assert out["checked"] is False
    assert out["identifiers_checked"] == 0
