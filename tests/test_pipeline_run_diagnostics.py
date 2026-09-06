"""Pipeline-level test of ``summary["run"]`` — the per-run retrieval record
(architecture §6 / §10 row E; audit ops-observability §10 gap 6 and §11 A;
retrieval-reliability §6 defect 7).

Every engine and pivot is stubbed; there is no network and no maigret. The
acceptance criterion is that the six post-mortem questions — what did we try,
which source failed, why, what fallback ran, did it work, how confident is the
result — are answerable from the persisted summary alone.

The stubbed run: Sherlock scans GitHub (claimed), Flaky (a timeout on the first
pass, claimed on the batched retry) and Instagram (removed by the access
policy at plan time); WhatsMyName scans WmnOK (claimed) and WmnBad (HTTP 503,
retried, still failing); the signals engine reports GitHub exists, Bluesky
blocked by a 429, Telegram absent and Steam refused by policy.
"""

import asyncio
import json
import logging
from types import SimpleNamespace

from sherlock_project.result import QueryResult, QueryStatus

from dbconn import connect as db_connect
from recon import adapters, detectors, engines, pipeline, whatsmyname
from recon.router import ERROR_CLASSES, SiteHealthStore, init_tables

_SHER = {
    "GitHub": {"url": "https://github.com/{}", "urlMain": "https://github.com/"},
    "Flaky": {"url": "https://flaky.example/{}", "urlMain": "https://flaky.example/"},
    "Instagram": {"url": "https://instagram.com/{}",
                  "urlMain": "https://instagram.com/"},
}
_WMN = [
    {"name": "WmnOK", "uri_check": "https://wmnok.example/{account}",
     "e_code": 200, "e_string": "x", "m_code": 404, "cat": "social"},
    {"name": "WmnBad", "uri_check": "https://wmnbad.example/{account}",
     "e_code": 200, "e_string": "x", "m_code": 404, "cat": "social"},
]


class _FakeSherlock:
    """Stands in for ``sherlock_project.sherlock.sherlock``: one call per
    (username, site set). Flaky times out on the first pass and is claimed on
    the retry pass, so the retry is scored as recovered. Like the real
    function it returns the per-site dict with ``http_status`` (200 here; a
    subclass injects a 429 to prove the re-classification)."""

    http_status = {}

    def __init__(self):
        self.calls = []

    def __call__(self, username, site_data, notify, timeout=60, proxy=None, **kw):
        self.calls.append(sorted(site_data))
        retry_pass = len(self.calls) > 1
        ret = {}
        for site, info in site_data.items():
            url = info["url"].format(username)
            if site == "Flaky" and not retry_pass:
                res = QueryResult(username, site, url, QueryStatus.UNKNOWN,
                                  query_time=0.2, context="Timeout Error")
            else:
                res = QueryResult(username, site, url, QueryStatus.CLAIMED,
                                  query_time=0.1)
            notify.update(res)
            ret[site] = {"status": res, "http_status": self.http_status.get(site, 200)}
        return ret


def _fake_wmn_scan(calls):
    async def scan(username, sites, timeout, on_result, proxy=None,
                   stealth_retry=False, **kw):
        calls.append([s["name"] for s in sites])
        for s in sites:
            url = s["uri_check"].replace("{account}", username)
            if s["name"] == "WmnBad":
                on_result(whatsmyname.WmnResult(
                    whatsmyname.UNKNOWN, s["name"], url, s.get("cat"),
                    "HTTP 503", query_time=0.3))
            else:
                on_result(whatsmyname.WmnResult(
                    whatsmyname.CLAIMED, s["name"], url, s.get("cat"), "",
                    query_time=0.1))
    return scan


async def _fake_adapters_discover(username, stats=None, **kw):
    if stats is not None:
        stats["GitHub"] = {"kind": "adapter", "status": "exists",
                           "signal": "GitHub public API confirms this account exists",
                           "http_status": 200}
        stats["Bluesky"] = {"kind": "adapter", "status": "blocked",
                            "signal": "blocked: HTTP 429 — cannot determine",
                            "http_status": 429}
    return [{"site": "GitHub", "url": f"https://github.com/{username}",
             "identity": {"display_name": "Alice"}, "temporal": {},
             "source_url": f"https://api.github.com/users/{username}"}]


async def _fake_detectors_discover(username, stats=None, **kw):
    if stats is not None:
        stats["Telegram"] = {"kind": "detector", "status": "absent",
                             "signal": "Telegram: no such profile",
                             "http_status": 200}
        stats["Steam"] = {"kind": "detector", "status": "blocked",
                          "signal": "policy: steamcommunity.com robots.txt disallows",
                          "http_status": None}
    return []


async def _fake_enrich(rows, on_enriched, subject_name="", stats=None, **kw):
    if stats is not None:
        stats.update({"rate_limited_hosts": 0, "rate_limited_rows": 0, "backoff_s": {},
                      "control_failed_hosts": [], "verify_budget": 120,
                      "verify_budget_used": len(rows), "verify_budget_skipped": 0,
                      "stealth_tls": 0, "stealth_browser": 0})
    for row in rows:
        if row["site"] == "GitHub":
            row["verification"] = {"status": "confirmed", "score": 88, "signals": ["stub"]}
        elif row["site"] == "Flaky":
            row["verification"] = {"status": "indeterminate", "score": 30,
                                   "signals": ["stub"]}
        else:
            row["verification"] = {"status": "unconfirmed", "score": 40, "signals": ["stub"]}
        on_enriched(row, {})


async def _fake_correlate(rows, **kw):
    return []


def _run(monkeypatch, tmp_path, *, wmn_scan=None, investigation_id=None,
         sherlock=None):
    """Run the pipeline on one username with every engine/pivot stubbed."""
    db = tmp_path / "history.db"
    with db_connect(db) as conn:
        init_tables(conn)
    fake_sherlock = sherlock or _FakeSherlock()
    wmn_calls = []
    monkeypatch.setattr(pipeline, "sherlock", fake_sherlock)
    monkeypatch.setattr(pipeline, "retry_delay", lambda: 0.0)
    monkeypatch.setattr(engines, "maigret_available", lambda: False)
    monkeypatch.setattr(whatsmyname, "all_sites", lambda nsfw=False: list(_WMN))
    monkeypatch.setattr(whatsmyname, "variant_sites",
                        lambda policy_filtered=True: list(_WMN))
    monkeypatch.setattr(whatsmyname, "whatsmyname_scan",
                        wmn_scan or _fake_wmn_scan(wmn_calls))
    monkeypatch.setattr(adapters, "discover", _fake_adapters_discover)
    monkeypatch.setattr(detectors, "discover", _fake_detectors_discover)
    monkeypatch.setattr(pipeline, "enrich_profiles", _fake_enrich)
    monkeypatch.setattr(pipeline, "correlate", _fake_correlate)
    events = []

    async def main():
        return await pipeline.run_pipeline(
            usernames=["alice"], sher_data=dict(_SHER), timeout=5,
            emit=lambda ev, payload: events.append((ev, payload)),
            loop=asyncio.get_running_loop(), db_path=db,
            investigation_id=investigation_id,
        )

    summary = asyncio.run(main())
    return summary, events, SimpleNamespace(db=db, sherlock=fake_sherlock,
                                            wmn_calls=wmn_calls)


def _event(events, name):
    return [p for ev, p in events if ev == name]


# ---------------------------------------------------------------------------
# summary["run"] — every key, sane values
# ---------------------------------------------------------------------------

def test_run_diagnostics_has_every_key_with_sane_values(monkeypatch, tmp_path):
    summary, events, ctx = _run(monkeypatch, tmp_path)
    run = summary["run"]
    assert run["schema"] == 1
    assert set(run) >= {
        "planned", "skipped_policy", "skipped_degraded", "errors_by_class",
        "errors_by_engine_class", "failed_checks", "retries", "engine_errors",
        "signals", "verification_counts", "timings_s", "schema", "retrieval",
        # router.breakdown() fields, including the additive retries_done
        "error_breakdown", "degraded_sources", "retries_done",
    }
    # G2: nothing is left unrecorded — the retrieval block carries the rest.
    assert run["not_recorded"] == [] and pipeline.NOT_RECORDED == ()

    planned = run["planned"]
    assert planned["sherlock"] == 2            # Instagram removed by policy
    assert planned["whatsmyname"] == 2
    assert planned["maigret"] == 0             # maigret stubbed as unavailable
    assert planned["signals"] == len(adapters.ADAPTERS) + len(detectors.DETECTORS)
    assert planned["usernames"] == 1 and planned["candidates"] == 0
    assert planned["candidate_sites"] == planned["sherlock_reduced"]
    budgets = planned["budgets"]
    assert set(budgets) == {"verify", "stealth_browser", "detector_browser", "wmn_stealth"}
    assert all(isinstance(v, int) and v >= 0 for v in budgets.values())

    assert run["skipped_policy"] == [{"site": "Instagram", "engine": "sherlock",
                                      "reason": run["skipped_policy"][0]["reason"]}]
    assert "instagram.com" in run["skipped_policy"][0]["reason"]
    assert run["skipped_policy_count"] == 1
    assert run["skipped_degraded"] == [] and run["degraded_sources"] == 0

    assert run["errors_by_class"] == {"timeout": 1, "http_5xx": 2, "http_429": 1}
    assert run["error_breakdown"] == run["errors_by_class"]
    assert run["errors_by_engine_class"] == {
        "sherlock": {"timeout": 1},
        "whatsmyname": {"http_5xx": 2},      # first pass + failed retry
        "signals": {"http_429": 1},
    }
    assert run["errors_total"] == 4 and run["failed_checks_truncated"] == 0

    assert run["verification_counts"] == {"found": 1, "lead": 1, "flagged": 0,
                                          "indeterminate": 1, "not_examined": 0}
    assert run["engine_errors"] == []
    assert run["routing"] is True and run["proxy"] is False

    timings = run["timings_s"]
    assert set(timings) >= {"plan", "scan", "variants", "candidates", "enrich",
                            "correlate", "pivots", "total"}
    assert all(isinstance(v, float) and v >= 0 for v in timings.values())
    assert timings["total"] >= max(v for k, v in timings.items() if k != "total")


def test_stubbed_wmn_failure_appears_in_failed_checks_with_a_class(monkeypatch, tmp_path):
    summary, _events, _ctx = _run(monkeypatch, tmp_path)
    failed = summary["run"]["failed_checks"]
    assert {"engine": "whatsmyname", "site": "WmnBad", "username": "alice",
            "class": "http_5xx", "context": "HTTP 503"} in failed
    # ... and the signals-engine block, with the block reason as its context.
    assert {"engine": "signals", "site": "Bluesky", "username": "alice",
            "class": "http_429",
            "context": "blocked: HTTP 429 — cannot determine"} in failed
    assert all(c["class"] in ERROR_CLASSES for c in failed)
    assert all(len(c["context"]) <= 80 for c in failed)


def test_stubbed_retry_is_counted_and_marked_recovered(monkeypatch, tmp_path):
    summary, events, ctx = _run(monkeypatch, tmp_path)
    # Sherlock retried Flaky (recovered); WhatsMyName retried WmnBad (still 503).
    assert ctx.sherlock.calls == [["Flaky", "GitHub"], ["Flaky"]]
    assert ctx.wmn_calls == [["WmnOK", "WmnBad"], ["WmnBad"]]
    assert summary["run"]["retries"] == {"attempted": 2, "recovered": 1}
    assert summary["run"]["retries_done"] == 2
    assert {(r["engine"], r["site"]) for r in _event(events, "retry")} == {
        ("sherlock", "Flaky"), ("whatsmyname", "WmnBad")}
    # The recovered site is a real row now.
    assert "Flaky" in {r["site"] for r in summary["accounts"]}


def test_signals_outcomes_are_tallied_and_observed(monkeypatch, tmp_path):
    summary, _events, ctx = _run(monkeypatch, tmp_path)
    assert summary["run"]["signals"] == {
        "GitHub": {"kind": "adapter", "exists": 1, "absent": 0, "blocked": 0, "policy": 0},
        "Bluesky": {"kind": "adapter", "exists": 0, "absent": 0, "blocked": 1, "policy": 0},
        "Telegram": {"kind": "detector", "exists": 0, "absent": 1, "blocked": 0, "policy": 0},
        "Steam": {"kind": "detector", "exists": 0, "absent": 0, "blocked": 0, "policy": 1},
    }
    # The router saw them: site_health has the block (and the decisive
    # absent as a success) under engine "signals"; the policy refusal is not
    # an observation at all.
    rows = {(r["site"], r["engine"]): r for r in SiteHealthStore(ctx.db).all_rows()}
    assert rows[("Bluesky", "signals")]["window"][0]["class"] == "http_429"
    assert rows[("Telegram", "signals")]["window"][0]["ok"] == 1
    assert rows[("GitHub", "signals")]["window"][0]["ok"] == 1
    assert ("Steam", "signals") not in rows


def test_engine_crash_is_recorded(monkeypatch, tmp_path):
    async def boom(username, sites, timeout, on_result, proxy=None, stealth_retry=False, **kw):
        raise RuntimeError("boom")

    summary, events, _ctx = _run(monkeypatch, tmp_path, wmn_scan=boom)
    assert summary["run"]["engine_errors"] == [
        {"engine": "whatsmyname", "message": "RuntimeError: boom"}]
    assert _event(events, "engine_error") == [
        {"engine": "whatsmyname", "message": "RuntimeError: boom"}]
    # One source failing did not fail the search.
    assert summary["run"]["verification_counts"]["found"] == 1


# ---------------------------------------------------------------------------
# done event, persistence, log context
# ---------------------------------------------------------------------------

def test_done_event_carries_elapsed_and_retries(monkeypatch, tmp_path):
    summary, events, _ctx = _run(monkeypatch, tmp_path)
    (done,) = _event(events, "done")
    assert isinstance(done["elapsed_s"], float) and done["elapsed_s"] >= 0
    assert done["elapsed_s"] == summary["run"]["timings_s"]["total"]
    assert done["retries"] == {"attempted": 2, "recovered": 1}
    assert done["retries_done"] == 2
    # Nothing the frontend already reads was renamed.
    assert set(done) >= {"found", "leads", "flagged", "indeterminate", "not_examined",
                         "hits", "clusters", "email_hits", "error_breakdown",
                         "degraded_sources"}
    # Additive (defect 6): the email-check honesty keys, zero without an email.
    assert (done["email_checked_ok"], done["email_rate_limited"],
            done["email_undetermined"]) == (0, 0, False)
    # The plan announced what policy kept every engine away from.
    (skipped,) = _event(events, "skipped_policy")
    assert skipped["count"] == 1 and skipped["sites"][0]["site"] == "Instagram"


def test_summary_json_serialises_and_round_trips(monkeypatch, tmp_path):
    summary, _events, _ctx = _run(monkeypatch, tmp_path)
    text = json.dumps(summary)
    assert json.loads(text)["run"] == summary["run"]
    # Bounded: a full run's record is small enough to live in the summary blob.
    assert len(json.dumps(summary["run"])) < 64 * 1024


def test_six_questions_answerable_from_the_stored_summary(monkeypatch, tmp_path):
    """Architecture §6: after a run, history.db alone must answer these."""
    summary, _events, _ctx = _run(monkeypatch, tmp_path)
    stored = json.loads(json.dumps(summary))       # what history.db holds
    run = stored["run"]
    rows = stored["accounts"] + stored["variants"] + stored["name_accounts"]
    # 1. What did we try?
    assert run["planned"]["sherlock"] + run["planned"]["whatsmyname"] > 0
    assert stored["params"]["usernames"] == ["alice"]
    # 2. Which source failed?
    assert {c["site"] for c in run["failed_checks"]} == {"Flaky", "WmnBad", "Bluesky"}
    assert {c["site"] for c in run["skipped_policy"]} == {"Instagram"}
    # 3. Why?
    assert all(c["class"] and c["context"] for c in run["failed_checks"])
    assert run["errors_by_engine_class"]["signals"] == {"http_429": 1}
    # 4. What fallback ran?
    assert run["retries"]["attempted"] == 2
    # 5. Did it work?
    assert run["retries"]["recovered"] == 1
    assert run["signals"]["Bluesky"]["blocked"] == 1
    # 6. How confident is the result?
    assert sum(run["verification_counts"].values()) == len(rows)
    assert all("verification" in r for r in rows)


def test_log_lines_carry_the_investigation_id(monkeypatch, tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="recon.pipeline")
    _run(monkeypatch, tmp_path, investigation_id=54)
    ours = [r.getMessage() for r in caplog.records if r.name == "recon.pipeline"]
    assert ours and all(m.startswith("inv=54 ") for m in ours)
    assert any(m.startswith("inv=54 planned ") for m in ours)
    assert any(m.startswith("inv=54 run diagnostics:") for m in ours)

    caplog.clear()
    second = tmp_path / "second"
    second.mkdir()
    _run(monkeypatch, second, investigation_id=None)
    ours = [r.getMessage() for r in caplog.records if r.name == "recon.pipeline"]
    assert ours and not any("inv=" in m for m in ours)


# ---------------------------------------------------------------------------
# pure helpers
# ---------------------------------------------------------------------------

def test_signal_context_adds_the_http_status_when_missing():
    assert pipeline.signal_context({"signal": "Steam: blocked — cannot determine",
                                    "http_status": 403}) == \
        "HTTP 403: Steam: blocked — cannot determine"
    assert pipeline.signal_context({"signal": "blocked: HTTP 429 — cannot determine",
                                    "http_status": 429}) == \
        "blocked: HTTP 429 — cannot determine"
    assert pipeline.signal_context({"signal": "request failed (ReadTimeout)",
                                    "http_status": None}) == \
        "request failed (ReadTimeout)"
    assert pipeline.signal_context({"http_status": 503}) == "HTTP 503"


def test_tally_signal_counts_by_outcome_and_keeps_policy_apart():
    counts = {}
    pipeline.tally_signal(counts, "X", {"kind": "detector", "status": "exists"})
    pipeline.tally_signal(counts, "X", {"kind": "detector", "status": "absent"})
    pipeline.tally_signal(counts, "X", {"kind": "detector", "status": "blocked",
                                        "signal": "blocked: HTTP 403"})
    pipeline.tally_signal(counts, "X", {"kind": "detector", "status": "blocked",
                                        "signal": "policy: denied host"})
    pipeline.tally_signal(counts, "X", {"kind": "detector", "status": None})
    assert counts == {"X": {"kind": "detector", "exists": 1, "absent": 1,
                            "blocked": 2, "policy": 1}}


# ---------------------------------------------------------------------------
# G2: the retrieval record and engine re-classification (defect 3)
# ---------------------------------------------------------------------------

def test_retrieval_record_is_present_and_bounded(monkeypatch, tmp_path):
    from recon.enrich import STEALTH_BROWSER_BUDGET
    summary, _events, _ctx = _run(monkeypatch, tmp_path)
    rec = summary["run"]["retrieval"]
    assert set(rec) >= {"fetches", "hosts", "hosts_seen", "hosts_backed_off",
                        "stealth", "detector_stealth", "wmn_stealth", "budgets",
                        "enrichment"}
    fetches = rec["fetches"]
    assert set(fetches) >= {"attempts", "requests", "by_outcome", "by_status_class",
                            "by_host", "skipped", "ladder", "by_host_truncated"}
    assert isinstance(fetches["by_status_class"], dict)      # the status histogram
    assert rec["stealth"]["browser_budget"] == STEALTH_BROWSER_BUDGET
    assert rec["stealth"]["tls_attempts"] == 0
    assert rec["detector_stealth"]["sweeps"] == 1             # one signals sweep
    assert rec["detector_stealth"]["browser_budget"] == detectors.BROWSER_BUDGET
    assert rec["wmn_stealth"] == {"budget_per_scan": whatsmyname._STEALTH_RETRY_BUDGET,
                                  "retries": 0, "recovered": 0}
    budgets = rec["budgets"]
    assert budgets["verify"] == {"limit": 120, "used": 3, "skipped": 0}   # 3 stub rows
    assert budgets["stealth_browser"] == {"limit": STEALTH_BROWSER_BUDGET, "used": 0}
    assert budgets["detector_browser"]["limit_per_sweep"] == detectors.BROWSER_BUDGET
    assert budgets["wmn_stealth"]["used"] == 0
    assert "stealth" not in rec["enrichment"]                 # not duplicated
    assert json.loads(json.dumps(rec)) == rec


def test_build_retrieval_record_caps_hosts_and_sums_detector_ladders():
    from recon import retrieval
    from recon.ladder import StealthLadder
    st = retrieval.RetrievalStats()
    hs = retrieval.HostState()
    for i in range(pipeline.RETRIEVAL_HOSTS_CAP + 5):
        host = f"h{i}.example"
        st.record(retrieval.BLOCKED, 503, host)
        hs.record(host, retrieval.BLOCKED, 503)
    hs.backoff("h0.example", 60, status=503)
    a, b = StealthLadder(3), StealthLadder(3)
    a.tls_attempts, a.browser_attempts, a.browser_left = 2, 1, 2
    b.tls_attempts, b.browser_ok = 1, 1
    rec = pipeline.build_retrieval_record(
        stats=st, host_state=hs, enrich_stats={"stealth": {"x": 1}, "rate_limited_rows": 3},
        enrich_ladder=StealthLadder(8), detector_ladders=[a, b],
        wmn_counters={"stealth_retries": 4, "stealth_recovered": 1}, verify_budget=120)
    assert len(rec["fetches"]["by_host"]) == pipeline.RETRIEVAL_HOSTS_CAP
    assert rec["fetches"]["by_host_truncated"] == 5
    assert len(rec["hosts"]) == pipeline.RETRIEVAL_HOSTS_CAP and rec["hosts_truncated"] == 5
    assert rec["hosts_seen"] == pipeline.RETRIEVAL_HOSTS_CAP + 5
    assert rec["hosts_backed_off"] == 1
    assert rec["detector_stealth"] == {"tls_attempts": 3, "tls_ok": 0, "browser_attempts": 1,
                                       "browser_ok": 1, "browser_budget": 6,
                                       "browser_budget_left": 5, "rate_limited": 0,
                                       "sweeps": 2}
    assert rec["wmn_stealth"]["retries"] == 4 and rec["budgets"]["wmn_stealth"]["used"] == 4
    assert rec["enrichment"] == {"rate_limited_rows": 3}
    assert rec["budgets"]["verify"]["limit"] == 120


def test_reclassify_engine_result_matrix():
    f = pipeline.reclassify_engine_result
    assert f("Available", "", 429) == ("blocked", "rate limited (HTTP 429)")
    assert f("Claimed", "", 503) == ("blocked", "rate limited (HTTP 503)")
    assert f("Claimed", "", 403) == ("blocked", "HTTP 403")
    assert f("available", "", 429) == ("blocked", "rate limited (HTTP 429)")
    # Successes with a readable status, errors of any kind, and unknown
    # statuses pass through untouched.
    assert f("Claimed", "", 200) == ("Claimed", "")
    assert f("Available", "", 404) == ("Available", "")
    assert f("Unknown", "Timeout Error", 429) == ("Unknown", "Timeout Error")
    assert f("Claimed", "", None) == ("Claimed", "")
    assert f("Claimed", "", "") == ("Claimed", "")          # maigret's error branch
    assert f("Claimed", "", True) == ("Claimed", "")


def test_sherlock_notify_observes_after_flush_with_the_http_status():
    """Sherlock's QueryResult has no http_status: the observation waits for
    the returned dict and a 429 labelled Available is filed as http_429."""
    from recon.router import RunRouter
    router = RunRouter(None)
    notify = pipeline._SherlockNotify("alice", {"kind": "base"},
                                      lambda *a: None, router)
    notify.update(QueryResult("alice", "Limited", "https://l.example/alice",
                              QueryStatus.AVAILABLE, query_time=0.1))
    notify.update(QueryResult("alice", "Fine", "https://f.example/alice",
                              QueryStatus.CLAIMED, query_time=0.1))
    assert router.observations == 0, "nothing observed before flush"
    n = notify.flush({"Limited": {"http_status": 429}, "Fine": {"http_status": 200}})
    assert n == 2 and notify.pending == []
    assert router.observations == 2 and router.error_observations == 1
    assert dict(router.error_counts) == {"http_429": 1}
    assert [c["site"] for c in router.failed_checks] == ["Limited"]
    assert router.failed_checks[0]["context"] == "rate limited (HTTP 429)"
    # A flush with no results (the scan raised) still observes, unchanged.
    notify.update(QueryResult("alice", "Other", "u", QueryStatus.AVAILABLE))
    assert notify.flush(None) == 1 and router.observations == 3


def test_stubbed_sherlock_429_is_observed_as_a_block(monkeypatch, tmp_path):
    class _Limited(_FakeSherlock):
        http_status = {"GitHub": 429}

    summary, _events, ctx = _run(monkeypatch, tmp_path, sherlock=_Limited())
    run = summary["run"]
    assert run["errors_by_engine_class"]["sherlock"] == {"timeout": 1, "http_429": 1}
    assert {"engine": "sherlock", "site": "GitHub", "username": "alice",
            "class": "http_429", "context": "rate limited (HTTP 429)"} in run["failed_checks"]
    rows = {(r["site"], r["engine"]): r for r in SiteHealthStore(ctx.db).all_rows()}
    assert rows[("GitHub", "sherlock")]["window"][0]["class"] == "http_429"
    # The engine's own "found" still streamed; verification is where the row
    # is judged (a 429 host is rate_limited there).
    assert "GitHub" in {r["site"] for r in summary["accounts"]}
