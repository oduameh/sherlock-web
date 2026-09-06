"""Unified investigation pipeline.

One clue in (name, usernames, email, phone) -> full automated investigation:
name-derived candidate scan, dual-engine username scan, username variants,
email pivot, phone intel, enrichment, correlation. Streams SSE-style events
through the ``emit`` callback and returns a summary dict for persistence.

Runs on the asyncio event loop; Sherlock (synchronous) is executed in worker
threads whose callbacks hop back onto the loop via ``loop.call_soon_threadsafe``.
Everything optional (maigret, holehe, phonenumbers) degrades gracefully.

The returned summary carries ``summary["run"]`` (see
:func:`build_run_diagnostics`): the bounded per-run retrieval record — what was
planned, what was skipped and why, every failed check with its error class,
retries and whether they recovered, engine crashes, signals-engine outcomes,
verification buckets and phase timings — so ``history.db`` alone can answer the
six post-mortem questions (architecture §6). Until 2026-09-06 none of that
survived the SSE stream (architecture V8, audit ops-observability §10 gap 6).
"""

from __future__ import annotations

import asyncio
import contextvars
import logging
import threading
import time
from typing import Callable, Optional

from sherlock_project.notify import QueryNotify
from sherlock_project.result import QueryStatus
from sherlock_project.sherlock import sherlock

from recon import adapters, detectors, engines
from recon.confidence import account_confidence, bucket_counts
from recon.correlate import correlate
from recon.email_pivot import (annotate_recovery, gravatar_lookup,
                                holehe_available, holehe_scan)
from recon.enrich import enrich_profiles, MAX_ENRICH_PER_RUN
from recon.domain_pivot import domain_from_email, domain_intel
from recon.names import generate_name_candidates
from recon.permutations import generate_variants
from recon.phone_accounts import ignorant_available, ignorant_scan
from recon.phone_pivot import phone_intel
from recon.plan import plan_site_sets
from recon.router import RunRouter, is_policy_observation, retry_delay
from recon.validate import is_probably_email
from recon import brokers
from recon import whatsmyname

logger = logging.getLogger("recon.pipeline")

ERROR_STATUSES = {QueryStatus.UNKNOWN, QueryStatus.WAF, QueryStatus.ILLEGAL}

# The investigation id for log lines — architecture §6 asks for ``inv=<id>`` on
# every pipeline line. Set by ``run_pipeline(investigation_id=...)`` in the
# run's task context; Sherlock worker threads are started under a copy of that
# context so their lines carry it too. ``None`` (no id given) omits the prefix.
INV_ID: contextvars.ContextVar[Optional[int]] = contextvars.ContextVar(
    "inv_id", default=None)


def _log_prefix() -> str:
    """``"inv=<id> "`` for the current run, or ``""`` when no id was given."""
    inv = INV_ID.get()
    return f"inv={inv} " if inv is not None else ""


# summary["run"] bounds and schema (bump RUN_SCHEMA on an incompatible change).
RUN_SCHEMA = 1
SKIPPED_LIST_CAP = 300
ENGINE_ERRORS_CAP = 50
ENGINE_ERROR_MESSAGE_CHARS = 300
SIGNAL_OUTCOMES = ("exists", "absent", "blocked")


def run_budgets() -> dict:
    """The per-run budgets in force (env-tunable module constants), read
    defensively so a renamed constant elsewhere can never break a run."""
    from recon import enrich as enrich_mod
    return {
        "verify": getattr(enrich_mod, "MAX_ENRICH_PER_RUN", None),
        "stealth_browser": getattr(enrich_mod, "STEALTH_BROWSER_BUDGET", None),
        "detector_browser": getattr(detectors, "BROWSER_BUDGET", None),
        "wmn_stealth": getattr(whatsmyname, "_STEALTH_RETRY_BUDGET", None),
    }


def signal_context(res: dict) -> str:
    """The router-facing context for one adapter/detector outcome: the signal
    text, prefixed with the HTTP status when the text does not already carry
    it, so :func:`recon.router.classify` can tell a 429 from a 403 from a
    transport failure. Pure."""
    signal = str(res.get("signal") or "")
    code = res.get("http_status")
    if code is not None and str(code) not in signal:
        return f"HTTP {code}: {signal}" if signal else f"HTTP {code}"
    return signal


def tally_signal(counts: dict, name: str, res: dict) -> None:
    """Fold one adapter/detector outcome into ``counts[name]`` —
    ``{kind, exists, absent, blocked, policy}``. Anything that is not a
    decisive exists/absent is counted as blocked ("cannot determine"), except
    a policy refusal, which is counted apart because nothing was fetched.
    Pure apart from mutating ``counts``."""
    entry = counts.setdefault(name, {
        "kind": res.get("kind") or "adapter",
        "exists": 0, "absent": 0, "blocked": 0, "policy": 0,
    })
    status = str(res.get("status") or "")
    if is_policy_observation(status, str(res.get("signal") or "")):
        entry["policy"] += 1
    elif status in SIGNAL_OUTCOMES:
        entry[status] += 1
    else:
        entry["blocked"] += 1


# Retrieval facts the diagnostics do NOT yet record (they live in modules
# other increments own); listed in the blob so a reader never assumes a
# missing key means "nothing happened".
NOT_RECORDED = ("stealth_ladder_attempts", "wmn_stealth_retries",
                "detector_browser_escalations", "budget_consumption",
                "fetch_status_histogram")


def build_run_diagnostics(*, router: RunRouter, planned: dict,
                          skipped_policy: list, engine_errors: list,
                          signals: dict, verification_counts: dict,
                          timings: dict) -> dict:
    """Assemble ``summary["run"]`` — the bounded per-run retrieval record.

    Persisted with the summary by the existing ``done`` write, so a stored
    investigation can answer the six post-mortem questions (architecture §6)
    without the SSE stream or the logs:

    * *what did we try* — ``planned`` (site counts per engine after policy and
      circuit filtering, candidate count, budgets) plus the stored inputs;
    * *which source failed* — ``failed_checks``, ``engine_errors``,
      ``signals``, ``skipped_degraded``;
    * *why* — the error ``class`` and ``context`` on every failed check,
      ``errors_by_class`` / ``errors_by_engine_class``, ``skipped_policy``;
    * *what fallback ran* — ``retries.attempted``, the budgets in force;
    * *did it work* — ``retries.recovered``, the signals counts;
    * *how confident* — ``verification_counts`` (per-row ``verification`` is
      unchanged).

    Bounded: at most ``FAILED_CHECKS_CAP`` failed checks (the overflow is
    counted in ``failed_checks_truncated``), ``SKIPPED_LIST_CAP`` rows per
    skipped list, ``ENGINE_ERRORS_CAP`` engine errors. Pure given its inputs.
    """
    degraded = list(router.degraded)
    failed = list(router.failed_checks)
    run = {
        "schema": RUN_SCHEMA,
        "not_recorded": list(NOT_RECORDED),
        "planned": planned,
        "skipped_policy": list(skipped_policy)[:SKIPPED_LIST_CAP],
        "skipped_policy_count": len(skipped_policy),
        "skipped_degraded": degraded[:SKIPPED_LIST_CAP],
        "skipped_degraded_count": len(degraded),
        "observations": router.observations,
        "errors_total": router.error_observations,
        "errors_by_class": dict(router.error_counts),
        "errors_by_engine_class": router.errors_by_engine_class(),
        "failed_checks": failed,
        "failed_checks_truncated": max(0, router.error_observations - len(failed)),
        "retries": {"attempted": router.retries_done,
                    "recovered": router.retries_recovered},
        "engine_errors": list(engine_errors)[:ENGINE_ERRORS_CAP],
        "signals": signals,
        "verification_counts": verification_counts,
        "timings_s": timings,
        "proxy": bool(router.proxy),
        "routing": not router.disabled,
    }
    run.update(router.breakdown())
    return run


def dispatch_wmn_result(result, *, observe: Callable, on_found: Callable,
                        on_error: Callable) -> str:
    """Route one WhatsMyName result; returns what was done.

    ``policy``: the site's host is robots-denied, so it was never fetched —
    there is nothing to observe (recording it as a failure tripped circuits
    for sites we never touched: audit defect 8) and nothing to report as an
    error. ``found`` / ``error`` / ``available`` are observed by the router as
    before. Pure apart from the callbacks.
    """
    if result.status == whatsmyname.POLICY:
        return "policy"
    observe(result)
    if result.status == whatsmyname.CLAIMED:
        on_found(result)
        return "found"
    if result.status == whatsmyname.UNKNOWN:
        on_error(result)
        return "error"
    return "available"

# Name-candidate scans fan out across a few workers (they can be 20 handles).
NAME_SHERLOCK_SHARDS = 3
NAME_MAIGRET_CONCURRENCY = 3

Emit = Callable[[str, dict], None]


class _SherlockNotify(QueryNotify):
    """Forwards Sherlock per-site results through the threadsafe emitter."""

    def __init__(self, scanned_name: str, group: dict, emit_ts: Callable,
                 router: Optional[RunRouter] = None):
        super().__init__()
        self.scanned_name = scanned_name
        self.group = group
        self.emit_ts = emit_ts
        self.router = router
        self.checked = 0
        self.total = 0

    def update(self, result) -> None:  # called once per site, from scan thread
        self.checked += 1
        status = result.status
        if self.router is not None:
            self.router.observe("sherlock", result.site_name,
                                str(status.value), result.context or "",
                                result.query_time, username=self.scanned_name)
        if status == QueryStatus.CLAIMED:
            self.emit_ts("found", "sherlock", self.scanned_name,
                         result.site_name, result.site_url_user,
                         result.query_time, self.group)
        elif status in ERROR_STATUSES:
            self.emit_ts("error", "sherlock", self.scanned_name,
                         result.site_name, str(status.value),
                         result.context or "", self.group)
        self.emit_ts("progress", "sherlock", self.scanned_name,
                     self.checked, self.total, self.group)


def _sherlock_worker(items: list, site_data: dict, timeout: int,
                     emit_ts: Callable, loop: asyncio.AbstractEventLoop,
                     done_event: asyncio.Event,
                     router: Optional[RunRouter] = None) -> None:
    """Thread entry: scan (username, group) pairs sequentially."""
    try:
        for scanned_name, group in items:
            notify = _SherlockNotify(scanned_name, group, emit_ts, router)
            notify.total = len(site_data)
            emit_ts("engine_start", "sherlock", scanned_name,
                    len(site_data), group)
            sherlock(scanned_name, site_data, notify, timeout=timeout,
                     proxy=router.proxy if router else None)
            _retry_transient(router, "sherlock", scanned_name, site_data,
                             timeout, emit_ts, notify)
            emit_ts("engine_done", "sherlock", scanned_name, group)
    except Exception as exc:
        emit_ts("engine_error", "sherlock", f"{type(exc).__name__}: {exc}")
    finally:
        loop.call_soon_threadsafe(done_event.set)


def _retry_transient(router: Optional[RunRouter], engine: str,
                     scanned_name: str, site_data: dict, timeout: int,
                     emit_ts: Callable, notify) -> None:
    """Retry this pass's transient failures once — all in a single concurrent
    re-scan after one short delay (sync; sherlock only)."""
    if router is None:
        return
    retry_recs = router.drain_transient(engine, scanned_name)
    retry_sites = {rec["site"]: site_data[rec["site"]]
                   for rec in retry_recs if rec["site"] in site_data}
    if not retry_sites:
        return
    router.begin_retries(engine, scanned_name, retry_sites)
    for rec in retry_recs:
        if rec["site"] in retry_sites:
            emit_ts("retry", rec)
    time.sleep(retry_delay())
    try:
        sherlock(scanned_name, retry_sites, notify, timeout=timeout,
                 proxy=router.proxy)
    except Exception:
        logger.exception("%sretry batch failed for %s", _log_prefix(),
                         scanned_name)


def _shard(items: list, n: int) -> list[list]:
    """Split items into n roughly-equal contiguous shards."""
    if not items:
        return []
    n = min(n, len(items))
    return [items[i::n] for i in range(n)]


class _Children:
    """The engine/pivot tasks a run spawns. Cancelling the run's own task only
    cancels the child it happens to be awaiting; the others kept scanning as
    orphans (543 requests were logged after one cancelled run). The run
    registers ``cancel_pending`` as a done-callback so every child stops when
    the run does, whatever the reason."""

    def __init__(self) -> None:
        self.tasks: list = []

    def spawn(self, coro):
        task = asyncio.create_task(coro)
        self.tasks.append(task)
        return task

    def cancel_pending(self) -> int:
        return sum(1 for t in self.tasks if not t.done() and t.cancel())


async def run_pipeline(
    *,
    name: str = "",
    usernames: Optional[list[str]] = None,
    email: str = "",
    phone: str = "",
    domain: str = "",
    location: str = "",
    variants: bool = False,
    thorough: bool = False,
    timeout: int = 10,
    sher_data: dict,
    emit: Emit,
    loop: asyncio.AbstractEventLoop,
    db_path=None,
    investigation_id: Optional[int] = None,
) -> dict:
    """Run the full investigation. Returns the persistable summary dict.

    ``sher_data`` is the already-filtered Sherlock site dict. ``emit`` must be
    called on the event loop only. ``investigation_id`` (optional) prefixes
    this run's log lines with ``inv=<id>``; the summary always carries
    ``summary["run"]`` (:func:`build_run_diagnostics`).
    """
    INV_ID.set(investigation_id)   # unconditionally: a stale id must not leak across runs
    t_run0 = time.monotonic()
    usernames = [u for u in (usernames or []) if u]
    name = (name or "").strip()
    email = (email or "").strip()
    phone = (phone or "").strip()
    domain = (domain or "").strip()

    # Only pivot on a well-formed address; a malformed one would waste a
    # rate-limited holehe run and draw a misleading email node.
    if email and not is_probably_email(email):
        logger.info("%sskipping email pivot: the input is not a valid email address",
                    _log_prefix())
        email = ""

    # Infrastructure pivot: an explicit domain, else the email's domain.
    pivot_domain = domain or (domain_from_email(email) or "")

    # --- shared run state (mutated on the event loop only) -----------------
    rows: dict[tuple[str, str], dict] = {}
    accounts: list[dict] = []
    variant_rows: list[dict] = []
    name_rows: list[dict] = []
    email_state: dict = {"gravatar": None, "holehe": []}
    phone_state: dict = {}
    domain_state: dict = {}
    broker_state: dict = {}
    location = (location or "").strip()
    # Per-run diagnostics (persisted as summary["run"]).
    engine_errors: list[dict] = []
    signals_counts: dict[str, dict] = {}
    timings: dict[str, float] = {}
    _lap_at = [t_run0]

    def lap(phase: str) -> None:
        """Close the current phase: seconds since the previous lap."""
        now = time.monotonic()
        timings[phase] = round(timings.get(phase, 0.0) + (now - _lap_at[0]), 3)
        _lap_at[0] = now

    def emit_threadsafe(kind: str, *args) -> None:
        """Route worker-thread callbacks onto the event loop."""
        handler = {
            "found": _handle_found,
            "error": _handle_error,
            "progress": _handle_progress,
            "retry": _handle_retry,
        }.get(kind)
        if handler is not None:
            loop.call_soon_threadsafe(handler, *args)
        else:
            loop.call_soon_threadsafe(_engine_lifecycle, kind, *args)

    def _handle_found(engine, scanned_name, site, url, query_time, group,
                      category=None):
        key = (scanned_name, engines.normalize_site(site))
        row = rows.get(key)
        if row is not None:
            changed = False
            if engine not in row["engines"]:
                row["engines"].append(engine)
                changed = True
            if category and not row.get("category"):
                row["category"] = category
                changed = True
            if changed:
                emit("merged", {
                    "username": scanned_name, "site": row["site"],
                    "engines": row["engines"], "category": row.get("category"),
                    "source": row["source"],
                    "variant_of": row.get("variant_of"),
                    "from_name": row.get("from_name"),
                    "candidate": row.get("candidate"),
                })
            return
        row = {
            "username": scanned_name, "site": site, "url": url,
            "engines": [engine], "query_time": query_time,
            "category": category,
            "source": group["kind"],
            "variant_of": group.get("variant_of"),
            "from_name": group.get("from_name"),
            "candidate": group.get("candidate"),
        }
        rows[key] = row
        {"base": accounts, "variant": variant_rows,
         "name": name_rows}[group["kind"]].append(row)
        emit("found", dict(row))

    def _handle_error(engine, scanned_name, site, status, context, group):
        emit("error", {
            "engine": engine, "username": scanned_name, "site": site,
            "status": status, "context": context, "source": group["kind"],
            "variant_of": group.get("variant_of"),
            "from_name": group.get("from_name"),
            "candidate": group.get("candidate"),
        })

    def _handle_progress(engine, scanned_name, checked, total, group):
        emit("progress", {
            "engine": engine, "username": scanned_name,
            "checked": checked, "total": total, "source": group["kind"],
            "variant_of": group.get("variant_of"),
            "from_name": group.get("from_name"),
            "candidate": group.get("candidate"),
        })

    def _handle_retry(rec):
        emit("retry", dict(rec))

    def _engine_lifecycle(kind, engine, *args):
        if kind == "engine_start":
            scanned_name, total, group = args
            emit("engine_start", {
                "engine": engine, "username": scanned_name, "total": total,
                "source": group["kind"], "variant_of": group.get("variant_of"),
                "from_name": group.get("from_name"),
                "candidate": group.get("candidate"),
            })
        elif kind == "engine_done":
            scanned_name, group = args
            emit("engine_done", {
                "engine": engine, "username": scanned_name,
                "source": group["kind"], "variant_of": group.get("variant_of"),
                "from_name": group.get("from_name"),
                "candidate": group.get("candidate"),
            })
        elif kind == "engine_error":
            # Kept for summary["run"]["engine_errors"]: a crashed engine used
            # to be a toast and nothing else (ops-observability §5).
            if len(engine_errors) < ENGINE_ERRORS_CAP:
                engine_errors.append({
                    "engine": engine,
                    "message": str(args[0])[:ENGINE_ERROR_MESSAGE_CHARS],
                })
            emit("engine_error", {"engine": engine, "message": args[0]})

    # --- engine workers ----------------------------------------------------
    def start_sherlock(items, site_data, shards=1):
        """Start 1..n sharded sherlock threads. Returns list of done events."""
        events = []
        for shard in _shard(items, shards):
            done = asyncio.Event()
            # Run under a copy of this task's context so the thread's log
            # lines carry the inv= prefix too.
            ctx = contextvars.copy_context()
            threading.Thread(
                target=ctx.run,
                args=(_sherlock_worker, shard, site_data, timeout,
                      emit_threadsafe, loop, done, router),
                daemon=True,
            ).start()
            events.append(done)
        return events

    async def wait_all(events):
        for ev in events:
            await ev.wait()

    async def maigret_worker(items, site_dict, concurrency=1):
        if not site_dict:
            return
        from maigret.result import MaigretCheckStatus

        total = len(site_dict)
        sem = asyncio.Semaphore(concurrency)

        async def one(scanned_name, group):
            async with sem:
                _engine_lifecycle("engine_start", "maigret", scanned_name,
                                  total, group)
                checked = 0

                def on_result(result, _name=scanned_name, _g=group):
                    nonlocal checked
                    checked += 1
                    st = result.status  # MaigretCheckStatus enum
                    router.observe("maigret", result.site_name,
                                   str(st.value), result.context or "",
                                   getattr(result, "query_time", None),
                                   username=_name)
                    if st == MaigretCheckStatus.CLAIMED:
                        _handle_found("maigret", _name, result.site_name,
                                      result.site_url_user, None, _g)
                    elif st in (MaigretCheckStatus.UNKNOWN,
                                MaigretCheckStatus.ILLEGAL):
                        _handle_error("maigret", _name, result.site_name,
                                      str(st.value), result.context or "", _g)
                    _handle_progress("maigret", _name, checked, total, _g)

                try:
                    await engines.maigret_scan(scanned_name, site_dict,
                                               timeout, on_result,
                                               proxy=router.proxy)
                except Exception as exc:
                    _engine_lifecycle("engine_error", "maigret",
                                      f"{type(exc).__name__}: {exc}")
                # Retry this pass's transient failures once — all together in a
                # single concurrent re-scan after one short delay.
                retry_recs = router.drain_transient("maigret", scanned_name)
                retry_sites = {rec["site"]: site_dict[rec["site"]]
                               for rec in retry_recs if rec["site"] in site_dict}
                if retry_sites:
                    router.begin_retries("maigret", scanned_name, retry_sites)
                    for rec in retry_recs:
                        if rec["site"] in retry_sites:
                            emit("retry", dict(rec))
                    await asyncio.sleep(retry_delay())
                    try:
                        await engines.maigret_scan(
                            scanned_name, retry_sites, timeout, on_result,
                            proxy=router.proxy)
                    except Exception:
                        logger.exception("%smaigret retry batch failed for %s",
                                         _log_prefix(), scanned_name)
                _engine_lifecycle("engine_done", "maigret", scanned_name,
                                  group)

        await asyncio.gather(*(one(n, g) for n, g in items))

    async def whatsmyname_worker(items, sites_list, concurrency=1):
        if not sites_list:
            return
        total = len(sites_list)
        by_name = {s["name"]: s for s in sites_list}
        sem = asyncio.Semaphore(concurrency)

        async def one(scanned_name, group):
            async with sem:
                _engine_lifecycle("engine_start", "whatsmyname", scanned_name,
                                  total, group)
                checked = 0

                def on_result(result, _name=scanned_name, _g=group):
                    nonlocal checked
                    checked += 1
                    dispatch_wmn_result(
                        result,
                        observe=lambda r: router.observe(
                            "whatsmyname", r.site_name, r.status,
                            r.context or "", r.query_time, username=_name),
                        on_found=lambda r: _handle_found(
                            "whatsmyname", _name, r.site_name,
                            r.site_url_user, None, _g, r.category),
                        on_error=lambda r: _handle_error(
                            "whatsmyname", _name, r.site_name, r.status,
                            r.context or "", _g),
                    )
                    _handle_progress("whatsmyname", _name, checked, total, _g)

                try:
                    await whatsmyname.whatsmyname_scan(
                        scanned_name, sites_list, timeout, on_result,
                        proxy=router.proxy, stealth_retry=True)
                except Exception as exc:
                    _engine_lifecycle("engine_error", "whatsmyname",
                                      f"{type(exc).__name__}: {exc}")
                # Retry transient failures once, batched (like the other engines).
                retry_recs = router.drain_transient("whatsmyname", scanned_name)
                retry_sites = [by_name[r["site"]] for r in retry_recs
                               if r["site"] in by_name]
                if retry_sites:
                    router.begin_retries("whatsmyname", scanned_name,
                                         [s["name"] for s in retry_sites])
                    for r in retry_recs:
                        if r["site"] in by_name:
                            emit("retry", dict(r))
                    await asyncio.sleep(retry_delay())
                    try:
                        await whatsmyname.whatsmyname_scan(
                            scanned_name, retry_sites, timeout, on_result,
                            proxy=router.proxy)
                    except Exception:
                        logger.exception(
                            "%swhatsmyname retry batch failed for %s",
                            _log_prefix(), scanned_name)
                _engine_lifecycle("engine_done", "whatsmyname", scanned_name,
                                  group)

        await asyncio.gather(*(one(n, g) for n, g in items))

    async def signals_worker(items):
        """SIGNALS — our own discovery engine: query the public-API adapters
        (recon.adapters) directly for each real handle, independent of the
        third-party engines. A hit is a definitive API answer with identity +
        dates, not a page guess, so it discovers accounts the flaky engines miss
        and never invents false positives. Bounded to base/variant handles —
        never fanned across name candidates — so it is at most
        len(ADAPTERS) + len(DETECTORS) checks per handle.

        Every outcome — exists, absent AND blocked — is observed by the router
        under engine ``signals`` (a decisive absent is a success; a block is a
        failure with the block reason as context), so adapter/detector blocks
        reach the circuit breaker, the Health tab and summary["run"]. Until
        2026-09-06 only EXISTS results were ever seen (ops-observability gap
        8). A policy refusal is neither observed nor counted as blocked."""
        total = len(adapters.ADAPTERS) + len(detectors.DETECTORS)

        async def one(scanned_name, group):
            _engine_lifecycle("engine_start", "signals", scanned_name,
                              total, group)
            api_stats: dict = {}
            html_stats: dict = {}
            try:
                api_hits, html_hits = await asyncio.gather(
                    adapters.discover(scanned_name, stats=api_stats),
                    detectors.discover(scanned_name, stats=html_stats),
                )
                found = list(api_hits) + list(html_hits)
            except Exception as exc:
                _engine_lifecycle("engine_error", "signals",
                                  f"{type(exc).__name__}: {exc}")
                found = []
            for name, res in list(api_stats.items()) + list(html_stats.items()):
                tally_signal(signals_counts, name, res)
                status = str(res.get("status") or "")
                if not is_policy_observation(status, str(res.get("signal") or "")):
                    router.observe("signals", name, status, signal_context(res),
                                   username=scanned_name)
            for hit in found:
                _handle_found("signals", scanned_name, hit["site"],
                              hit["url"], None, group)
            _handle_progress("signals", scanned_name, total, total, group)
            _engine_lifecycle("engine_done", "signals", scanned_name, group)

        await asyncio.gather(*(one(n, g) for n, g in items))

    async def email_worker(addr):
        grav = await gravatar_lookup(addr)
        email_state["gravatar"] = grav
        emit("email", {
            "source": "gravatar", "email": addr, "found": bool(grav),
            "profile": grav,
        })
        if holehe_available():
            def on_holehe(entry):
                # Stitch the trail: flag when this account's masked recovery
                # phone matches the subject's number (phone↔email↔account).
                annotate_recovery(entry, phone_state.get("e164"))
                email_state["holehe"].append(entry)
                emit("email", {"source": "holehe", "email": addr, **entry})

            await holehe_scan(addr, on_holehe)
        else:
            emit("email", {"source": "holehe", "email": addr,
                           "error": "holehe not installed"})
        hits = sum(1 for h in email_state["holehe"] if h.get("exists"))
        emit("email_done", {"email": addr, "holehe_hits": hits,
                            "gravatar": bool(grav)})

    async def domain_worker(dom):
        data = await domain_intel(dom)
        domain_state.clear()
        domain_state.update(data)
        emit("domain_intel", data)

    async def broker_worker(person, loc):
        data = await brokers.broker_exposure(person, loc)
        broker_state.clear()
        broker_state.update(data)
        emit("broker_exposure", data)

    async def phone_accounts_worker(e164):
        """Phone analogue of email_worker: which platforms is the number
        registered on (ignorant). Streams per-site hits, accumulates onto
        phone_state so they persist under summary["phone"]["accounts"]."""
        phone_state.setdefault("accounts", [])
        if ignorant_available():
            def on_hit(entry):
                phone_state["accounts"].append(entry)
                emit("phone_account", {"phone": e164, **entry})

            await ignorant_scan(e164, on_hit)
        else:
            emit("phone_account", {"phone": e164,
                                   "error": "ignorant not installed"})
        hits = sum(1 for a in phone_state["accounts"] if a.get("exists"))
        emit("phone_account_done", {"phone": e164, "hits": hits})

    # --- plan --------------------------------------------------------------
    candidates = generate_name_candidates(name) if name else []

    # Site sets: access policy first (robots-denied hosts are removed from
    # every engine's set before any engine runs — recon.policy's promise,
    # previously kept only by our own fetchers), then adaptive routing drops
    # open-circuit sites and records every observation the engines produce
    # (disabled / no-op when the DB is unavailable).
    router = RunRouter(db_path, emit=emit)
    # Flush routing observations on EVERY exit — a cancelled or crashed run
    # used to skip router.finish() and lose the whole run's site-health data.
    # finish() is idempotent, so the normal call at the end stays as is.
    children = _Children()
    spawn = children.spawn
    _task = asyncio.current_task()
    if _task is not None:
        def _on_run_done(_t, _r=router, _c=children):
            n = _c.cancel_pending()
            if n:
                logger.info("%srun ended early — cancelled %d engine/pivot task(s)",
                            _log_prefix(), n)
            _r.finish()
        _task.add_done_callback(_on_run_done)

    # Thorough runs scan maigret's entire database (~3200 sites) for the base
    # username instead of the top ~1200 by rank — broader long-tail coverage at
    # the cost of runtime.
    mai_limit = None if thorough else engines.DEFAULT_MAIGRET_LIMIT
    have_maigret = engines.maigret_available()
    # The curated subsets are taken raw here so the plan filters and *reports*
    # every denied site itself; the helpers filter on their own for other callers.
    site_plan = plan_site_sets(
        sherlock=sher_data,
        maigret=engines.maigret_all_sites(mai_limit) if have_maigret else {},
        maigret_reduced=(engines.maigret_variant_sites(policy_filtered=False)
                         if have_maigret else {}),
        whatsmyname=whatsmyname.all_sites(),
        whatsmyname_reduced=whatsmyname.variant_sites(policy_filtered=False),
        circuit_filter=router.filter_sites,
    )
    sher_data, sher_reduced = site_plan.sherlock, site_plan.sherlock_reduced
    mai_all, mai_reduced = site_plan.maigret, site_plan.maigret_reduced
    wmn_all, wmn_reduced = site_plan.whatsmyname, site_plan.whatsmyname_reduced
    router.announce_skipped()
    # Additive event: what the access policy kept every engine away from, once
    # per (site, engine). Not an error and not a finding — "we did not look".
    if site_plan.skipped_policy:
        emit("skipped_policy", site_plan.skipped_event())

    planned = {
        "usernames": len(usernames), "candidates": len(candidates),
        "variants": bool(variants), "thorough": bool(thorough),
        "sherlock": len(sher_data), "maigret": len(mai_all),
        "whatsmyname": len(wmn_all),
        "signals": len(adapters.ADAPTERS) + len(detectors.DETECTORS),
        "sherlock_reduced": len(sher_reduced),
        "maigret_reduced": len(mai_reduced),
        "whatsmyname_reduced": len(wmn_reduced),
        "candidate_sites": len(sher_reduced),
        "budgets": run_budgets(),
    }
    logger.info("%splanned sherlock=%d maigret=%d whatsmyname=%d signals=%d"
                " candidates=%d policy_skipped=%d degraded=%d",
                _log_prefix(), planned["sherlock"], planned["maigret"],
                planned["whatsmyname"], planned["signals"],
                planned["candidates"], len(site_plan.skipped_policy),
                len(router.degraded))

    emit("meta", {
        "name": name, "usernames": usernames, "email": email, "phone": phone,
        "domain": pivot_domain, "variants": variants, "thorough": thorough,
        "timeout": timeout,
        "sherlock_sites": len(sher_data), "maigret_sites": len(mai_all),
        "whatsmyname_sites": len(wmn_all),
        "candidate_sites": len(sher_reduced), "candidates": len(candidates),
    })

    if candidates:
        emit("candidates", {"name": name, "candidates": candidates})

    # Phone intel is offline — parse, attach reverse-lookup links, emit
    # immediately. A valid number then pivots on account-existence (ignorant),
    # which runs concurrently like the email pivot (started below).
    phone_task = None
    if phone:
        phone_state = phone_intel(phone)
        if phone_state.get("valid"):
            phone_state["reverse_lookup"] = brokers.reverse_phone_links(
                phone_state.get("e164"), phone_state.get("region"))
        emit("phone_intel", phone_state)

    # Base username scans (tri-engine, full site sets).
    base_items = [(u, {"kind": "base"}) for u in usernames]
    if base_items:
        base_events = start_sherlock(base_items, sher_data)
        mai_base = spawn(maigret_worker(base_items, mai_all))
        wmn_base = spawn(whatsmyname_worker(base_items, wmn_all))
        # Our own discovery engine runs on the real handles, concurrently.
        sig_base = spawn(signals_worker(base_items))
    else:
        base_events = []
        mai_base = None
        wmn_base = None
        sig_base = None

    # Name-candidate scans (tri-engine, curated high-value sites, fanned out).
    cand_items = [
        (c, {"kind": "name", "from_name": name, "candidate": c})
        for c in candidates
    ]
    if cand_items:
        cand_events = start_sherlock(cand_items, sher_reduced,
                                     shards=NAME_SHERLOCK_SHARDS)
        mai_cand = spawn(
            maigret_worker(cand_items, mai_reduced,
                           concurrency=NAME_MAIGRET_CONCURRENCY))
        wmn_cand = spawn(
            whatsmyname_worker(cand_items, wmn_reduced,
                               concurrency=NAME_MAIGRET_CONCURRENCY))
    else:
        cand_events = []
        mai_cand = None
        wmn_cand = None

    email_task = spawn(email_worker(email)) if email else None
    domain_task = (spawn(domain_worker(pivot_domain))
                   if pivot_domain else None)
    # Data-broker exposure keys on a real name (brokers index by name/address).
    broker_task = (spawn(broker_worker(name, location))
                   if name else None)
    # Phone account-existence pivot: only worth running on a valid number.
    if phone and phone_state.get("valid") and phone_state.get("e164"):
        phone_task = spawn(
            phone_accounts_worker(phone_state["e164"]))

    # --- phases ------------------------------------------------------------
    lap("plan")
    await wait_all(base_events)
    if mai_base is not None:
        await mai_base
    if wmn_base is not None:
        await wmn_base
    if sig_base is not None:
        await sig_base
    lap("scan")

    # Username variants (reduced high-value site list), like deep recon.
    if variants and usernames:
        for base in usernames:
            vs = generate_variants(base)
            emit("variants_planned", {"base": base, "variants": vs,
                                      "sites": len(sher_reduced)})
            if not vs:
                continue
            v_items = [(v, {"kind": "variant", "variant_of": base})
                       for v in vs]
            v_events = start_sherlock(v_items, sher_reduced)
            await maigret_worker(v_items, mai_reduced)
            await whatsmyname_worker(v_items, wmn_reduced)
            await signals_worker(v_items)
            await wait_all(v_events)
    lap("variants")

    # Candidate scans run concurrently with the base scans from the start, so
    # this lap is the extra wait for the fan-out, not its full duration.
    await wait_all(cand_events)
    if mai_cand is not None:
        await mai_cand
    if wmn_cand is not None:
        await wmn_cand
    lap("candidates")

    # Enrichment over everything found.
    all_rows = accounts + variant_rows + name_rows
    emit("phase", {"phase": "enriching",
                   "targets": min(MAX_ENRICH_PER_RUN, len(all_rows))})

    def on_enriched(row, data):
        emit("enriched", {
            "username": row["username"], "site": row["site"],
            "url": row["url"], "source": row["source"],
            "variant_of": row.get("variant_of"),
            "from_name": row.get("from_name"),
            "candidate": row.get("candidate"),
            "enrichment": data,
            "verification": row.get("verification"),
            "confidence": account_confidence(row),
            "temporal": row.get("temporal"),
            "platform_identity": row.get("platform_identity"),
        })

    await enrich_profiles(all_rows, on_enriched, subject_name=name)
    lap("enrich")

    # Correlation.
    clusters = await correlate(all_rows)
    emit("correlation", {"clusters": clusters})
    lap("correlate")

    # Wait for the email + domain + broker + phone pivots before persisting.
    if email_task is not None:
        await email_task
    if domain_task is not None:
        await domain_task
    if broker_task is not None:
        await broker_task
    if phone_task is not None:
        await phone_task
    lap("pivots")
    timings["total"] = round(time.monotonic() - t_run0, 3)

    summary = {
        "params": {
            "name": name, "usernames": usernames, "email": email,
            "phone": phone, "domain": pivot_domain, "location": location,
            "variants": variants, "thorough": thorough, "timeout": timeout,
        },
        "candidates": candidates,
        "accounts": accounts,
        "variants": variant_rows,
        "name_accounts": name_rows,
        "email": email_state,
        "phone": phone_state or None,
        "domain": domain_state or None,
        "brokers": broker_state or None,
        "correlation": clusters,
    }
    # Honest headline: split the raw union of "handle exists" hits into
    # verification-confirmed accounts, unconfirmed leads, and flagged false
    # positives — instead of reporting every speculative hit as "found".
    buckets = bucket_counts(all_rows)
    # The per-run retrieval record, persisted with the summary (architecture
    # §6). Built after every phase so the counters are final.
    summary["run"] = build_run_diagnostics(
        router=router, planned=planned,
        skipped_policy=site_plan.skipped_policy, engine_errors=engine_errors,
        signals=signals_counts, verification_counts=buckets, timings=timings,
    )
    router.finish()
    logger.info("%srun diagnostics: errors=%s retries=%d/%d engine_errors=%d"
                " degraded=%d timings=%s",
                _log_prefix(), dict(router.error_counts),
                router.retries_recovered, router.retries_done,
                len(engine_errors), len(router.degraded), timings)
    emit("done", {
        "found": buckets["found"],       # verification-confirmed subject accounts
        "leads": buckets["lead"],        # fetched, real page, nothing decisive
        "flagged": buckets["flagged"],   # likely false positives
        "indeterminate": buckets["indeterminate"],  # blocked — existence unknown
        "not_examined": buckets["not_examined"],    # never fetched — no evidence
        "hits": len(all_rows),           # raw existence hits across all sources
        "variant_hits": len(variant_rows),
        "name_hits": len(name_rows),
        "clusters": len(clusters),
        "email_hits": sum(1 for h in email_state["holehe"] if h.get("exists")),
        "phone": bool(phone_state),
        "phone_accounts": sum(
            1 for a in (phone_state.get("accounts") or []) if a.get("exists")),
        "domain": bool(domain_state),
        "brokers": (broker_state.get("summary", {}).get("total")
                    if broker_state else 0),
        **router.breakdown(),
        # Additive (architecture §6 "Live"): wall time and retry outcome.
        "elapsed_s": timings["total"],
        "retries": summary["run"]["retries"],
    })
    return summary
