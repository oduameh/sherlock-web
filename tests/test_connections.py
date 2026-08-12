from recon.connections import find_connections, subject_identifiers


def test_subject_identifiers_from_inputs_and_summary():
    inputs = {"usernames": ["alice"], "email": "Alice@Example.com",
              "phone": "+1 415 555 2671", "domain": "Example.com"}
    summary = {
        "params": {},
        "accounts": [{"username": "Alice", "site": "GitHub",
                      "url": "https://github.com/alice"}],
        "phone": {"e164": "+14155552671"},
        "email": {"holehe": [{"exists": True, "site": "Spotify"},
                             {"exists": False, "site": "X"}]},
    }
    ident = subject_identifiers(inputs, summary)
    assert "alice@example.com" in ident["emails"]
    assert "+14155552671" in ident["phones"]
    assert "example.com" in ident["domains"]
    assert "alice" in ident["handles"]
    assert "github|alice" in ident["accounts"]
    assert ident["registrations"] == {"spotify"}


def _ident(**kw):
    base = {"emails": set(), "phones": set(), "domains": set(),
            "accounts": set(), "registrations": set(), "handles": set()}
    base.update({k: set(v) for k, v in kw.items()})
    return base


def test_find_connections_shared_email_is_strong():
    target = _ident(emails=["a@b.com"], handles=["alice"])
    others = [{"id": 2, "label": "case two",
               "ident": _ident(emails=["a@b.com"], handles=["bob"])}]
    conns = find_connections(1, target, others)
    assert len(conns) == 1
    assert conns[0]["investigation_id"] == 2
    assert conns[0]["strength"] >= 40
    assert "a@b.com" in conns[0]["shared"]["emails"]
    assert "email a@b.com" in conns[0]["summary"]


def test_find_connections_shared_handle_is_weak():
    target = _ident(handles=["alice"])
    others = [{"id": 2, "label": "two", "ident": _ident(handles=["alice"])}]
    conns = find_connections(1, target, others)
    assert conns[0]["strength"] == 5
    assert conns[0]["shared"]["handles"] == ["alice"]


def test_find_connections_excludes_self_and_nonoverlap():
    target = _ident(emails=["a@b.com"])
    others = [
        {"id": 1, "label": "self", "ident": _ident(emails=["a@b.com"])},
        {"id": 3, "label": "unrelated", "ident": _ident(emails=["x@y.com"])},
    ]
    assert find_connections(1, target, others) == []


def test_find_connections_ranked_by_strength():
    target = _ident(emails=["a@b.com"], accounts=["github|alice"],
                    handles=["alice"])
    others = [
        {"id": 2, "label": "weak", "ident": _ident(handles=["alice"])},
        {"id": 3, "label": "strong",
         "ident": _ident(emails=["a@b.com"], accounts=["github|alice"],
                         handles=["alice"])},
    ]
    conns = find_connections(1, target, others)
    assert [c["investigation_id"] for c in conns] == [3, 2]
    assert conns[0]["strength"] > conns[1]["strength"]
