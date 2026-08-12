"""Unit tests for recon.router: classifier, circuit breaker, retry selection,
proxy banning. All pure or against a tmp SQLite DB — no network."""

import pytest

from dbconn import connect as db_connect
from recon import router
from recon.router import (
    BASE_COOLDOWN_S,
    MAX_COOLDOWN_S,
    RunRouter,
    SiteHealthStore,
    ProxyPool,
    classify,
    init_tables,
    next_cooldown,
    partition_sites,
    proxy_should_ban,
    select_retries,
    should_trip,
    sources_summary,
)

NOW = 1_800_000_000.0  # fixed reference time for deterministic tests


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("status,context,expected", [
    # Sherlock QueryStatus + context strings (see sherlock get_response()).
    ("Unknown", "Timeout Error", "timeout"),
    ("Unknown", "Error Connecting", "conn_reset"),
    ("Unknown", "Proxy Error", "conn_reset"),
    ("WAF", "", "http_403_waf"),
    ("Illegal", "Illegal username format for this site", "detector_stale"),
    # Maigret CheckError strings (str(CheckError) -> "<type> error: <desc>").
    ("Unknown", "Timeout error: connection timed out", "timeout"),
    ("Unknown", "HTTP error: 429 Too Many Requests", "http_429"),
    ("Unknown", "HTTP error: 403 Forbidden", "http_403_waf"),
    ("Unknown", "HTTP error: 503 Service Unavailable", "http_5xx"),
    ("Unknown", "Connecting error: [Errno -2] Name or service not known", "dns"),
    ("Unknown", "Connecting error: getaddrinfo failed", "dns"),
    ("Unknown", "SSL error: certificate verify failed", "tls"),
    ("Unknown", "Connection reset by peer", "conn_reset"),
    ("Unknown", "Parsing error: regex did not match", "detector_stale"),
    ("Unknown", "General Unknown Error", "unknown"),
    ("Unknown", "", "unknown"),
])
def test_classify(status, context, expected):
    assert classify(status, context) == expected


def test_classify_success_returns_none():
    assert classify("Claimed") is None
    assert classify("Available") is None


def test_classify_status_wins_over_context():
    # WAF status is authoritative even with a generic context.
    assert classify("WAF", "General Unknown Error") == "http_403_waf"
    assert classify("Illegal", "timeout") == "detector_stale"


def test_classify_uses_exception_text():
    assert classify("Unknown", "", "socket.timeout: timed out") == "timeout"
    assert classify("Unknown", "", "HTTP 429") == "http_429"


# ---------------------------------------------------------------------------
# Circuit-breaker pure helpers
# ---------------------------------------------------------------------------

def _window(n_ok, n_fail):
    return ([{"ok": 1}] * n_ok) + ([{"ok": 0}] * n_fail)


def test_should_trip_on_consecutive_failures():
    assert should_trip(5, [])
    assert should_trip(7, _window(20, 0))
    assert not should_trip(4, [])


def test_should_trip_on_failure_rate():
    # 13/20 = 65% failures over >= 10 observations -> trip.
    assert should_trip(2, _window(7, 13))
    # Exactly 60% is not > 60% -> no trip.
    assert not should_trip(2, _window(8, 12))
    # Not enough observations -> no trip.
    assert not should_trip(2, _window(1, 8))


def test_next_cooldown_doubles_and_caps():
    assert next_cooldown(BASE_COOLDOWN_S) == BASE_COOLDOWN_S * 2
    assert next_cooldown(MAX_COOLDOWN_S) == MAX_COOLDOWN_S
    assert next_cooldown(MAX_COOLDOWN_S * 2) == MAX_COOLDOWN_S


def test_partition_sites():
    kept, skipped = partition_sites(["A", "B", "C"], {"B": "later"})
    assert kept == ["A", "C"]
    assert skipped == ["B"]


# ---------------------------------------------------------------------------
# Store: circuit trip / half-open / close transitions
# ---------------------------------------------------------------------------

@pytest.fixture
def store(tmp_path):
    db = tmp_path / "t.db"
    with db_connect(db) as conn:
        init_tables(conn)
    return SiteHealthStore(db)


def _circuit(store, site="GitHub", engine="sherlock"):
    for r in store.all_rows():
        if r["site"] == site and r["engine"] == engine:
            return r
    return None


def test_circuit_trips_after_five_consecutive_failures(store):
    for i in range(5):
        store.record("GitHub", "sherlock", ok=False, err_class="http_429",
                     now=NOW + i)
    row = _circuit(store)
    assert row["consecutive_failures"] == 5
    assert row["circuit_open_until"] is not None
    # Open for the base cooldown, next cooldown doubled.
    assert router._parse(row["circuit_open_until"]) == pytest.approx(
        NOW + 4 + BASE_COOLDOWN_S, abs=2)
    assert row["cooldown_seconds"] == BASE_COOLDOWN_S * 2
    # And the site is reported as an open circuit.
    assert "GitHub" in store.open_circuits("sherlock", now=NOW + 10)


def test_circuit_does_not_trip_below_threshold(store):
    for i in range(4):
        store.record("GitHub", "sherlock", ok=False, err_class="timeout",
                     now=NOW + i)
    assert _circuit(store)["circuit_open_until"] is None


def test_success_resets_failures_and_closes_circuit(store):
    for i in range(5):
        store.record("GitHub", "sherlock", ok=False, err_class="timeout",
                     now=NOW + i)
    store.record("GitHub", "sherlock", ok=True, now=NOW + 10)
    row = _circuit(store)
    assert row["consecutive_failures"] == 0
    assert row["circuit_open_until"] is None
    assert row["cooldown_seconds"] == BASE_COOLDOWN_S
    assert store.open_circuits("sherlock", now=NOW + 11) == {}


def test_half_open_failure_retrips_with_doubled_cooldown(store):
    for i in range(5):
        store.record("GitHub", "sherlock", ok=False, err_class="http_403_waf",
                     now=NOW + i)
    # Cooldown elapses; half-open probe fails -> re-trip at 2x base.
    probe = NOW + BASE_COOLDOWN_S + 100
    store.record("GitHub", "sherlock", ok=False, err_class="http_403_waf",
                 now=probe)
    row = _circuit(store)
    assert router._parse(row["circuit_open_until"]) == pytest.approx(
        probe + BASE_COOLDOWN_S * 2, abs=2)
    assert row["cooldown_seconds"] == BASE_COOLDOWN_S * 4
    assert "GitHub" in store.open_circuits("sherlock", now=probe + 1)


def test_failures_while_open_do_not_double_cooldown_again(store):
    for i in range(5):
        store.record("GitHub", "sherlock", ok=False, err_class="timeout",
                     now=NOW + i)
    # Late duplicate observations arriving while the circuit is open.
    store.record("GitHub", "sherlock", ok=False, err_class="timeout",
                 now=NOW + 5)
    store.record("GitHub", "sherlock", ok=False, err_class="timeout",
                 now=NOW + 6)
    assert _circuit(store)["cooldown_seconds"] == BASE_COOLDOWN_S * 2


def test_rate_based_trip(store):
    # Interleaved: never 5 in a row, but >60% failures over 20 observations.
    t = NOW
    for i in range(7):
        store.record("GitHub", "sherlock", ok=True, now=t)
        t += 1
        store.record("GitHub", "sherlock", ok=False, err_class="http_429",
                     now=t)
        t += 1
        store.record("GitHub", "sherlock", ok=False, err_class="http_429",
                     now=t)
        t += 1
    # 14 failures / 21 observations, max 2 consecutive.
    row = _circuit(store)
    assert row["circuit_open_until"] is not None


def test_sliding_window_is_capped(store):
    for i in range(60):
        store.record("GitHub", "sherlock", ok=True, now=NOW + i)
    assert len(_circuit(store)["window"]) == router.WINDOW_SIZE


def test_ewma_latency_tracked(store):
    store.record("GitHub", "sherlock", ok=True, latency_ms=1000, now=NOW)
    store.record("GitHub", "sherlock", ok=True, latency_ms=500, now=NOW + 1)
    assert _circuit(store)["ewma_latency_ms"] == pytest.approx(0.3 * 500 + 0.7 * 1000)


def test_unavailable_store_degrades(tmp_path):
    # No init_tables: every op no-ops, store disables itself, nothing raises.
    store = SiteHealthStore(tmp_path / "missing.db")
    # File exists but has no tables.
    with db_connect(store.db_path):
        pass
    store.record("A", "sherlock", ok=False, err_class="timeout")
    assert not store.available
    assert store.open_circuits() == {}
    assert store.all_rows() == []
    store.record_proxy("http://x", ok=True)  # must not raise


# ---------------------------------------------------------------------------
# RunRouter: filtering, observation, retry selection
# ---------------------------------------------------------------------------

def test_run_router_filters_open_circuits_and_announces(store):
    for i in range(5):
        store.record("GitHub", "sherlock", ok=False, err_class="http_429",
                     now=NOW + i)
    events = []
    r = RunRouter(store.db_path, emit=lambda e, p: events.append((e, p)))
    site_data = {"GitHub": {}, "GitLab": {}}
    kept = r.filter_sites(site_data, "sherlock")
    assert list(kept) == ["GitLab"]
    r.announce_skipped()
    assert events[0][0] == "skipped_degraded"
    assert events[0][1]["count"] == 1
    assert events[0][1]["sites"][0]["site"] == "GitHub"
    assert r.breakdown()["degraded_sources"] == 1


def test_run_router_without_db_is_disabled_noop():
    r = RunRouter(None)
    assert r.disabled
    data = {"GitHub": {}}
    assert r.filter_sites(data, "sherlock") is data
    r.observe("sherlock", "GitHub", "Unknown", "Timeout Error")
    assert r.error_counts["timeout"] == 1  # in-run counting still works


def test_run_router_observation_records(store):
    r = RunRouter(store.db_path)
    r.observe("sherlock", "GitHub", "Claimed", query_time=0.5)
    r.observe("sherlock", "GitHub", "Unknown", "Timeout Error",
              query_time=10.0)
    r.finish()  # observations are buffered and flushed here
    row = _circuit(store)
    assert row is not None
    assert len(row["window"]) == 2
    assert r.error_counts == {"timeout": 1}


def test_observations_are_buffered_until_finish(store):
    # observe() must not touch the DB on the hot path — nothing is persisted
    # until finish() flushes the buffer.
    r = RunRouter(store.db_path)
    r.observe("sherlock", "GitHub", "Unknown", "Timeout Error")
    assert _circuit(store) is None
    r.finish()
    assert len(_circuit(store)["window"]) == 1


def test_record_batch_matches_per_observation_records(store):
    # 5 buffered failures replayed in order trip the circuit exactly as five
    # separate record() calls would.
    buffered = {
        ("GitHub", "sherlock"): [
            {"ok": False, "class": "http_429", "latency_ms": None,
             "ts": NOW + i}
            for i in range(5)
        ]
    }
    store.record_batch(buffered, now=NOW + 5)
    row = _circuit(store)
    assert row["consecutive_failures"] == 5
    assert row["circuit_open_until"] is not None
    assert row["cooldown_seconds"] == BASE_COOLDOWN_S * 2


def test_concurrent_observe_is_race_free(store):
    # Many threads observing the same site concurrently must not lose entries
    # (the old per-observation read-modify-write dropped window rows).
    import threading as _t
    r = RunRouter(store.db_path)

    def worker():
        for _ in range(25):
            r.observe("sherlock", "GitHub", "Unknown", "Timeout Error",
                      username="u")

    threads = [_t.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    r.finish()
    # 100 observations, window is capped at WINDOW_SIZE, all counted.
    assert r.observations == 100
    assert len(_circuit(store)["window"]) == router.WINDOW_SIZE


def test_drain_transient_retries_only_transient_once_capped():
    r = RunRouter(None)
    r.observe("sherlock", "A", "Unknown", "Timeout Error", username="u")
    r.observe("sherlock", "B", "Unknown", "HTTP 429", username="u")
    r.observe("sherlock", "C", "WAF", "", username="u")
    r.observe("sherlock", "D", "Unknown", "HTTP 500", username="u")
    r.observe("maigret", "E", "Unknown", "Timeout Error", username="u")
    picked = r.drain_transient("sherlock", "u")
    sites = [p["site"] for p in picked]
    # Only transient classes, only this engine+username: A (timeout), D (5xx).
    assert sites == ["A", "D"]
    # Drained: nothing left for the same key.
    assert r.drain_transient("sherlock", "u") == []
    # Maigret's entry is still there for its own drain.
    assert [p["site"] for p in r.drain_transient("maigret", "u")] == ["E"]


def test_drain_transient_enforces_retry_cap(monkeypatch):
    monkeypatch.setattr(router, "RETRY_CAP", 3)
    r = RunRouter(None)
    for i in range(10):
        r.observe("sherlock", f"Site{i}", "Unknown", "Timeout Error",
                  username="u")
    r.retries_done = 2  # two retries already spent elsewhere in the run
    picked = r.drain_transient("sherlock", "u")
    assert len(picked) == 1  # cap 3 total, 2 already done


def test_select_retries_pure():
    records = [
        {"site": "A", "class": "timeout"},
        {"site": "B", "class": "http_429"},
        {"site": "C", "class": "dns"},
        {"site": "D", "class": "http_403_waf"},
        {"site": "E", "class": "http_5xx"},
        {"site": "F", "class": "conn_reset"},
    ]
    picked = select_retries(records, cap=3)
    assert [r["site"] for r in picked] == ["A", "C", "E"]
    assert len(select_retries(records, cap=40)) == 4


# ---------------------------------------------------------------------------
# Proxy pool
# ---------------------------------------------------------------------------

def test_proxy_should_ban():
    assert proxy_should_ban(10, 8)       # 80% failures over >=10 uses
    assert not proxy_should_ban(10, 7)   # exactly 70% is not > 70%
    assert not proxy_should_ban(9, 9)    # not enough uses


def test_proxy_pool_unconfigured():
    pool = ProxyPool([])
    assert not pool.configured
    assert pool.pick() is None


def test_proxy_pool_round_robin(store):
    pool = ProxyPool(["http://p1", "http://p2"])
    assert pool.pick(store) == "http://p1"
    assert pool.pick(store) == "http://p2"
    assert pool.pick(store) == "http://p1"


def test_proxy_banned_after_failures_and_skipped(store):
    pool = ProxyPool(["http://p1", "http://p2"])
    for _ in range(10):
        store.record_proxy("http://p1", ok=False, now=NOW)
    assert "http://p1" in store.banned_proxies(now=NOW)
    # Banned proxy is skipped in rotation.
    assert pool.pick(store) == "http://p2"
    assert pool.pick(store) == "http://p2"
    # After the recheck window it is eligible again.
    assert "http://p1" not in store.banned_proxies(
        now=NOW + router.PROXY_RECHECK_S + 1)


def test_proxy_recovers_below_threshold(store):
    for _ in range(9):
        store.record_proxy("http://p1", ok=False, now=NOW)
    assert store.banned_proxies(now=NOW) == set()
    store.record_proxy("http://p1", ok=False, now=NOW)  # 10/10 -> banned
    assert "http://p1" in store.banned_proxies(now=NOW)


def test_run_router_finish_records_proxy_health(store, monkeypatch):
    pool = ProxyPool(["http://p1"])
    r = RunRouter(store.db_path, proxy_pool=pool)
    assert r.proxy == "http://p1"
    # Mostly-successful run -> proxy use recorded as success.
    for _ in range(8):
        r.observe("sherlock", "A", "Available")
    r.observe("sherlock", "B", "Unknown", "Timeout Error")
    r.finish()
    with db_connect(store.db_path) as conn:
        row = conn.execute(
            "SELECT uses, failures FROM proxy_health WHERE proxy='http://p1'"
        ).fetchone()
    assert row == (1, 0)


# ---------------------------------------------------------------------------
# sources_summary
# ---------------------------------------------------------------------------

def test_sources_summary_worst_first(store):
    for i in range(5):
        store.record("Bad", "sherlock", ok=False, err_class="http_429",
                     now=NOW + i)
    store.record("Good", "sherlock", ok=True, latency_ms=200, now=NOW)
    store.record("Good", "sherlock", ok=False, err_class="timeout", now=NOW + 1)
    out = sources_summary(store.db_path, now=NOW + 10)
    assert out["available"]
    assert [s["site"] for s in out["sites"]] == ["Bad", "Good"]
    bad, good = out["sites"]
    assert bad["circuit"] == "open"
    assert bad["failure_rate"] == 1.0
    assert bad["dominant_error"] == "http_429"
    assert bad["cooldown_remaining_s"] > 0
    assert good["circuit"] == "closed"
    assert good["failure_rate"] == 0.5
    assert good["ewma_latency_ms"] == 200
    agg = out["aggregate"]
    assert agg["sites_tracked"] == 2
    assert agg["circuits_open"] == 1
    assert agg["observations"] == 7
