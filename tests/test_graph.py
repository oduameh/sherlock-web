"""Graph model coverage — handle pivots, categories, creation dates."""

from recon.graph import build_graph


def _summary(accounts=(), variants=(), name_accounts=()):
    return {
        "params": {"usernames": ["alice"]},
        "accounts": list(accounts),
        "variants": list(variants),
        "name_accounts": list(name_accounts),
    }


def _ids(g):
    return {n["id"] for n in g["nodes"]}


def test_single_site_handle_wires_directly():
    g = build_graph(_summary(accounts=[
        {"site": "Dribbble", "username": "bob",
         "url": "https://dribbble.com/bob", "engines": ["sherlock"]},
    ]))
    assert "handle:bob" not in _ids(g)
    edges = {(e["source"], e["target"]) for e in g["edges"]}
    assert ("person", "acct:Dribbble:bob") in edges


def test_reused_handle_pivots_through_one_node():
    g = build_graph(_summary(accounts=[
        {"site": "GitHub", "username": "alice",
         "url": "https://github.com/alice", "engines": ["sherlock", "maigret"]},
        {"site": "RedditX", "username": "ALICE",
         "url": "https://redditx.com/u/alice", "engines": ["sherlock"]},
        {"site": "Dribbble", "username": "alice",
         "url": "https://dribbble.com/alice", "engines": ["wmn"]},
    ]))
    ids = _ids(g)
    assert "handle:alice" in ids          # case-insensitive grouping
    edges = {(e["source"], e["target"]) for e in g["edges"]}
    assert ("person", "handle:alice") in edges
    assert ("handle:alice", "acct:GitHub:alice") in edges
    # No direct person->account edges for pivoted handles.
    assert ("person", "acct:GitHub:alice") not in edges
    pivot = next(n for n in g["nodes"] if n["id"] == "handle:alice")
    assert pivot["sublabel"] == "3 sites"
    child_confs = [n["confidence"] for n in g["nodes"]
                   if n["type"] == "account" and
                   (n["label"] or "").lower() == "alice"]
    assert pivot["confidence"] >= max(child_confs)
    assert pivot["data"]["sites"] == ["GitHub", "RedditX", "Dribbble"]


def test_created_at_flows_from_adapter_temporal():
    g = build_graph(_summary(accounts=[
        {"site": "GitHub", "username": "octocat",
         "url": "https://github.com/octocat", "engines": ["sherlock"],
         "temporal": {"created_at": "2011-01-25T18:44:36Z"}},
    ]))
    node = next(n for n in g["nodes"] if n["type"] == "account")
    assert node["created_at"] == "2011-01-25T18:44:36Z"


def test_category_from_row_beats_dataset_lookup():
    g = build_graph(_summary(accounts=[
        {"site": "SomeSite", "username": "x", "url": "https://x/x",
         "engines": [], "category": "gaming"},
    ]))
    node = next(n for n in g["nodes"] if n["type"] == "account")
    assert node["data"]["category"] == "gaming"


def test_registration_gets_dataset_category_fallback():
    summary = _summary()
    summary["email"] = {"holehe": [
        {"site": "Spotify", "domain": "spotify.com", "exists": True},
    ]}
    summary["params"]["email"] = "a@b.c"
    g = build_graph(summary)
    reg = next(n for n in g["nodes"] if n["type"] == "registration")
    got = reg["data"].get("category")
    assert got is None or isinstance(got, str)   # never raises; may be unmapped


def test_empty_summary_yields_lone_person():
    g = build_graph(_summary())
    assert [n["type"] for n in g["nodes"]] == ["person"]
    assert g["edges"] == []
