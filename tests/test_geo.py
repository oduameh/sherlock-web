"""Subject-footprint coverage — claim collection, distance, and the spread
assessment. Pure functions only; no network."""

import asyncio

from recon import geo


def _summary(**kw):
    base = {
        "params": {"usernames": ["alice"]},
        "accounts": [], "variants": [], "name_accounts": [],
    }
    base.update(kw)
    return base


# --- collecting claims -----------------------------------------------------

def test_collects_every_source_kind():
    s = _summary(
        params={"usernames": ["alice"], "location": "Austin, TX"},
        accounts=[
            {"site": "GitHub", "platform_identity": {"location": "Redmond"}},
            {"site": "Keybase", "platform_identity": {"location": "Berlin"}},
        ],
        email={"gravatar": {"location": "Lisbon"}},
        phone={"valid": True, "location": "San Francisco, CA"},
        domain={"domain": "example.com", "dns": {"A": ["8.8.8.8"]}},
    )
    kinds = {c["kind"] for c in geo.collect_places(s)}
    assert kinds == {"subject", "profile", "gravatar", "phone", "infra"}


def test_duplicate_places_collapse():
    s = _summary(accounts=[
        {"site": "GitHub", "platform_identity": {"location": "Berlin"}},
        {"site": "GitHub", "platform_identity": {"location": "berlin"}},
    ])
    places = [c for c in geo.collect_places(s) if c["kind"] == "profile"]
    assert len(places) == 1


def test_junk_locations_are_rejected():
    s = _summary(accounts=[
        {"site": "A", "platform_identity": {"location": "https://x.test/me"}},
        {"site": "B", "platform_identity": {"location": "@handle"}},
        {"site": "C", "platform_identity": {"location": "12345"}},
        {"site": "D", "platform_identity": {"location": " "}},
        {"site": "E", "platform_identity": {"location": "Paris"}},
    ])
    places = [c["place"] for c in geo.collect_places(s) if c["kind"] == "profile"]
    assert places == ["Paris"]


def test_invalid_phone_and_errored_domain_contribute_nothing():
    s = _summary(
        phone={"valid": False, "location": "Nowhere"},
        domain={"domain": "x.test", "error": "nxdomain", "dns": {"A": ["8.8.8.8"]}},
    )
    assert geo.collect_places(s) == []


def test_empty_summary_is_safe():
    assert geo.collect_places({}) == []
    assert geo.collect_places(_summary()) == []


# --- distance + spread assessment -----------------------------------------

def test_haversine_known_distance():
    # London -> Paris is ~344 km.
    d = geo.haversine_km(51.5074, -0.1278, 48.8566, 2.3522)
    assert 330 < d < 360
    assert geo.haversine_km(10, 20, 10, 20) == 0


def _pt(kind, lat, lon, country):
    return {"kind": kind, "lat": lat, "lon": lon, "country": country}


def test_same_metro_reads_consistent():
    stats = geo.footprint_stats([
        _pt("profile", 47.6694, -122.1239, "United States"),   # Redmond
        _pt("phone", 47.6062, -122.3321, "United States"),     # Seattle
    ])
    assert stats["consistency"] == "consistent"
    assert stats["person_points"] == 2


def test_cross_country_spread_is_flagged_conflicting():
    stats = geo.footprint_stats([
        _pt("profile", 47.6694, -122.1239, "United States"),
        _pt("gravatar", 52.52, 13.405, "Germany"),
    ])
    assert stats["consistency"] == "conflicting"
    assert stats["person_countries"] == ["Germany", "United States"]
    assert stats["max_spread_km"] > 5000
    assert "countries" in stats["assessment"]


def test_infrastructure_never_drives_the_verdict():
    """Server geography is the host's, not the person's — a far-away IP must
    not turn a single consistent person-location into a conflict."""
    stats = geo.footprint_stats([
        _pt("profile", 47.6694, -122.1239, "United States"),
        _pt("infra", -33.8688, 151.2093, "Australia"),
    ])
    assert stats["consistency"] == "insufficient"   # only ONE person point
    assert stats["person_points"] == 1
    assert "Australia" in stats["countries"]        # still shown on the map


def test_no_points_is_reported_not_crashed():
    stats = geo.footprint_stats([])
    assert stats["resolved"] == 0
    assert stats["consistency"] == "insufficient"


# --- orchestration ---------------------------------------------------------

def test_build_footprint_reports_unresolved(monkeypatch):
    async def no_geocode(place):
        return None
    monkeypatch.setattr(geo, "geocode_place", no_geocode)
    s = _summary(params={"usernames": ["a"], "location": "Atlantis"})
    out = asyncio.run(geo.build_footprint(s))
    assert out["points"] == []
    assert out["unresolved"][0]["place"] == "Atlantis"
    assert out["stats"]["consistency"] == "insufficient"


def test_build_footprint_merges_resolved_points(monkeypatch):
    async def fake_geocode(place):
        return {"lat": 48.8566, "lon": 2.3522, "display": "Paris, France",
                "country": "France"}

    async def fake_ip(ip):
        return {"lat": 1.0, "lon": 2.0, "display": "Somewhere",
                "country": "France", "org": "ACME"}
    monkeypatch.setattr(geo, "geocode_place", fake_geocode)
    monkeypatch.setattr(geo, "geolocate_ip", fake_ip)
    s = _summary(
        params={"usernames": ["a"], "location": "Paris"},
        domain={"domain": "x.test", "dns": {"A": ["8.8.8.8"]}},
    )
    out = asyncio.run(geo.build_footprint(s))
    kinds = {p["kind"] for p in out["points"]}
    assert kinds == {"subject", "infra"}
    assert out["points"][0]["lat"] == 48.8566
    assert out["stats"]["resolved"] == 2
