"""Subject-footprint coverage — claim collection, distance, and the spread
assessment. Pure functions only; no network."""

import asyncio

import httpx

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


# --- caching honesty (defect 10): failures are never cached ------------------------

def _client(handler, calls):
    def counting(request):
        calls.append(str(request.url))
        return handler(request)

    def make(**kw):
        return httpx.AsyncClient(transport=httpx.MockTransport(counting), **kw)
    return make


def _fresh(monkeypatch, handler):
    calls = []
    monkeypatch.setattr(geo.safeweb, "async_client", _client(handler, calls))
    monkeypatch.setattr(geo, "_NOMINATIM_MIN_INTERVAL_S", 0.0)
    monkeypatch.setattr(geo, "_nominatim_lock", None)
    geo._place_cache.clear()
    geo._ip_cache.clear()
    return calls


PARIS = [{"lat": "48.8566", "lon": "2.3522", "display_name": "Paris, France",
          "address": {"country": "France"}}]


def test_geocode_429_is_not_cached_then_the_next_call_asks_again(monkeypatch):
    def handler(request):
        if len(calls) == 1:
            return httpx.Response(429, text="slow down")
        return httpx.Response(200, json=PARIS)
    calls = _fresh(monkeypatch, handler)
    assert asyncio.run(geo.geocode_place("Paris")) is None
    out = asyncio.run(geo.geocode_place("Paris"))
    assert out["lat"] == 48.8566 and out["country"] == "France"
    assert len(calls) == 2
    # And now it is cached (case-insensitively).
    assert asyncio.run(geo.geocode_place("paris"))["lat"] == 48.8566
    assert len(calls) == 2


def test_geocode_empty_result_is_a_definitive_miss_and_cached(monkeypatch):
    calls = _fresh(monkeypatch, lambda r: httpx.Response(200, json=[]))
    assert asyncio.run(geo.geocode_place("Atlantis")) is None
    assert asyncio.run(geo.geocode_place("Atlantis")) is None
    assert len(calls) == 1


def test_geocode_transport_failure_is_not_cached(monkeypatch):
    def handler(request):
        if len(calls) == 1:
            raise httpx.ReadTimeout("slow")
        return httpx.Response(200, json=PARIS)
    calls = _fresh(monkeypatch, handler)
    assert asyncio.run(geo.geocode_place("Paris")) is None
    assert asyncio.run(geo.geocode_place("Paris")) is not None
    assert len(calls) == 2


def test_geocode_keeps_the_honest_user_agent(monkeypatch):
    seen = {}

    def handler(request):
        seen["ua"] = request.headers.get("user-agent")
        return httpx.Response(200, json=PARIS)
    _fresh(monkeypatch, handler)
    asyncio.run(geo.geocode_place("Paris"))
    assert seen["ua"] == geo.USER_AGENT and "sherlock-web" in seen["ua"]


IPWHO_OK = {"success": True, "latitude": 37.4, "longitude": -122.0, "city": "Mountain View",
            "country": "United States", "connection": {"org": "Google"}}


def test_geolocate_ip_429_then_200(monkeypatch):
    def handler(request):
        if len(calls) == 1:
            return httpx.Response(429)
        return httpx.Response(200, json=IPWHO_OK)
    calls = _fresh(monkeypatch, handler)
    assert asyncio.run(geo.geolocate_ip("8.8.8.8")) is None
    out = asyncio.run(geo.geolocate_ip("8.8.8.8"))
    assert out["country"] == "United States" and out["org"] == "Google"
    assert len(calls) == 2
    assert asyncio.run(geo.geolocate_ip("8.8.8.8"))["org"] == "Google"
    assert len(calls) == 2


def test_geolocate_ip_quota_message_is_not_cached_but_invalid_ip_is(monkeypatch):
    def handler(request):
        if len(calls) == 1:
            return httpx.Response(200, json={"success": False,
                                             "message": "You've hit the monthly limit"})
        if "8.8.8.8" in str(request.url):
            return httpx.Response(200, json=IPWHO_OK)
        return httpx.Response(200, json={"success": False, "message": "Invalid IP address"})
    calls = _fresh(monkeypatch, handler)
    assert asyncio.run(geo.geolocate_ip("8.8.8.8")) is None      # quota: not cached
    assert asyncio.run(geo.geolocate_ip("8.8.8.8")) is not None
    assert asyncio.run(geo.geolocate_ip("1.1.1.1")) is None       # "invalid": definitive
    assert asyncio.run(geo.geolocate_ip("1.1.1.1")) is None
    assert len(calls) == 3 and geo._ip_cache.is_absent("1.1.1.1")


def test_private_ip_is_never_sent(monkeypatch):
    calls = _fresh(monkeypatch, lambda r: httpx.Response(200, json=IPWHO_OK))
    assert asyncio.run(geo.geolocate_ip("10.0.0.5")) is None
    assert calls == []
