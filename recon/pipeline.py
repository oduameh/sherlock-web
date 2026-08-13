"""Unified investigation pipeline.

One clue in (name, usernames, email, phone) -> full automated investigation:
name-derived candidate scan, dual-engine username scan, username variants,
email pivot, phone intel, enrichment, correlation. Streams SSE-style events
through the ``emit`` callback and returns a summary dict for persistence.

Runs on the asyncio event loop; Sherlock (synchronous) is executed in worker
threads whose callbacks hop back onto the loop via ``loop.call_soon_threadsafe``.
Everything optional (maigret, holehe, phonenumbers) degrades gracefully.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from typing import Callable, Optional

from sherlock_project.notify import QueryNotify
from sherlock_project.result import QueryStatus
from sherlock_project.sherlock import sherlock

from recon import engines
from recon.confidence import account_confidence, bucket_counts
from recon.correlate import correlate
from recon.email_pivot import (annotate_recovery, gravatar_lookup,
                                holehe_available, holehe_scan)
from recon.enrich import enrich_profiles
from recon.domain_pivot import domain_from_email, domain_intel
from recon.names import generate_name_candidates
from recon.permutations import generate_variants
from recon.phone_accounts import ignorant_available, ignorant_scan
from recon.phone_pivot import phone_intel
from recon.router import RunRouter, retry_delay
from recon.validate import is_probably_email
from recon import brokers
from recon import whatsmyname

logger = logging.getLogger("recon.pipeline")

ERROR_STATUSES = {QueryStatus.UNKNOWN, QueryStatus.WAF, QueryStatus.ILLEGAL}

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
    router.retries_done += len(retry_sites)
    for rec in retry_recs:
        if rec["site"] in retry_sites:
            emit_ts("retry", rec)
    time.sleep(retry_delay())
    try:
        sherlock(scanned_name, retry_sites, notify, timeout=timeout,
                 proxy=router.proxy)
    except Exception:
        logger.exception("retry batch failed for %s", scanned_name)


def _shard(items: list, n: int) -> list[list]:
    """Split items into n roughly-equal contiguous shards."""
    if not items:
        return []
    n = min(n, len(items))
    return [items[i::n] for i in range(n)]


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
) -> dict:
    """Run the full investigation. Returns the persistable summary dict.

    ``sher_data`` is the already-filtered Sherlock site dict. ``emit`` must be
    called on the event loop only.
    """
    usernames = [u for u in (usernames or []) if u]
    name = (name or "").strip()
    email = (email or "").strip()
    phone = (phone or "").strip()
    domain = (domain or "").strip()

    # Only pivot on a well-formed address; a malformed one would waste a
    # rate-limited holehe run and draw a misleading email node.
    if email and not is_probably_email(email):
        logger.info("skipping email pivot: %r is not a valid email", email)
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
            emit("engine_error", {"engine": engine, "message": args[0]})

    # --- engine workers ----------------------------------------------------
    def start_sherlock(items, site_data, shards=1):
        """Start 1..n sharded sherlock threads. Returns list of done events."""
        events = []
        for shard in _shard(items, shards):
            done = asyncio.Event()
            threading.Thread(
                target=_sherlock_worker,
                args=(shard, site_data, timeout, emit_threadsafe, loop, done,
                      router),
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
                    router.retries_done += len(retry_sites)
                    for rec in retry_recs:
                        if rec["site"] in retry_sites:
                            emit("retry", dict(rec))
                    await asyncio.sleep(retry_delay())
                    try:
                        await engines.maigret_scan(
                            scanned_name, retry_sites, timeout, on_result,
                            proxy=router.proxy)
                    except Exception:
                        logger.exception("maigret retry batch failed for %s",
                                         scanned_name)
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
                    router.observe("whatsmyname", result.site_name,
                                   result.status, result.context or "",
                                   result.query_time, username=_name)
                    if result.status == whatsmyname.CLAIMED:
                        _handle_found("whatsmyname", _name, result.site_name,
                                      result.site_url_user, None, _g,
                                      result.category)
                    elif result.status == whatsmyname.UNKNOWN:
                        _handle_error("whatsmyname", _name, result.site_name,
                                      result.status, result.context or "", _g)
                    _handle_progress("whatsmyname", _name, checked, total, _g)

                try:
                    await whatsmyname.whatsmyname_scan(
                        scanned_name, sites_list, timeout, on_result,
                        proxy=router.proxy)
                except Exception as exc:
                    _engine_lifecycle("engine_error", "whatsmyname",
                                      f"{type(exc).__name__}: {exc}")
                # Retry transient failures once, batched (like the other engines).
                retry_recs = router.drain_transient("whatsmyname", scanned_name)
                retry_sites = [by_name[r["site"]] for r in retry_recs
                               if r["site"] in by_name]
                if retry_sites:
                    router.retries_done += len(retry_sites)
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
                            "whatsmyname retry batch failed for %s",
                            scanned_name)
                _engine_lifecycle("engine_done", "whatsmyname", scanned_name,
                                  group)

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

    # Adaptive routing: drop open-circuit sites before any engine runs, and
    # record every observation the engines produce. Disabled (no-op) when the
    # DB is unavailable.
    router = RunRouter(db_path, emit=emit)
    sher_data = router.filter_sites(sher_data, "sherlock")
    # Thorough runs scan maigret's entire database (~3200 sites) for the base
    # username instead of the top ~1200 by rank — broader long-tail coverage at
    # the cost of runtime.
    mai_limit = None if thorough else engines.DEFAULT_MAIGRET_LIMIT
    mai_all = router.filter_sites(
        engines.maigret_all_sites(mai_limit) if engines.maigret_available()
        else {},
        "maigret")
    sher_reduced = engines.sherlock_variant_site_data(sher_data)
    mai_reduced = router.filter_sites(
        engines.maigret_variant_sites() if engines.maigret_available() else {},
        "maigret")
    # WhatsMyName: a third engine over ~700 categorized sites. filter_sites
    # wants a dict, so key the site defs by name, filter open circuits, unwrap.
    wmn_all = list(router.filter_sites(
        {s["name"]: s for s in whatsmyname.all_sites()}, "whatsmyname").values())
    wmn_reduced = list(router.filter_sites(
        {s["name"]: s for s in whatsmyname.variant_sites()},
        "whatsmyname").values())
    router.announce_skipped()

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
        mai_base = asyncio.create_task(maigret_worker(base_items, mai_all))
        wmn_base = asyncio.create_task(whatsmyname_worker(base_items, wmn_all))
    else:
        base_events = []
        mai_base = None
        wmn_base = None

    # Name-candidate scans (tri-engine, curated high-value sites, fanned out).
    cand_items = [
        (c, {"kind": "name", "from_name": name, "candidate": c})
        for c in candidates
    ]
    if cand_items:
        cand_events = start_sherlock(cand_items, sher_reduced,
                                     shards=NAME_SHERLOCK_SHARDS)
        mai_cand = asyncio.create_task(
            maigret_worker(cand_items, mai_reduced,
                           concurrency=NAME_MAIGRET_CONCURRENCY))
        wmn_cand = asyncio.create_task(
            whatsmyname_worker(cand_items, wmn_reduced,
                               concurrency=NAME_MAIGRET_CONCURRENCY))
    else:
        cand_events = []
        mai_cand = None
        wmn_cand = None

    email_task = asyncio.create_task(email_worker(email)) if email else None
    domain_task = (asyncio.create_task(domain_worker(pivot_domain))
                   if pivot_domain else None)
    # Data-broker exposure keys on a real name (brokers index by name/address).
    broker_task = (asyncio.create_task(broker_worker(name, location))
                   if name else None)
    # Phone account-existence pivot: only worth running on a valid number.
    if phone and phone_state.get("valid") and phone_state.get("e164"):
        phone_task = asyncio.create_task(
            phone_accounts_worker(phone_state["e164"]))

    # --- phases ------------------------------------------------------------
    await wait_all(base_events)
    if mai_base is not None:
        await mai_base
    if wmn_base is not None:
        await wmn_base

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
            await wait_all(v_events)

    await wait_all(cand_events)
    if mai_cand is not None:
        await mai_cand
    if wmn_cand is not None:
        await wmn_cand

    # Enrichment over everything found.
    all_rows = accounts + variant_rows + name_rows
    emit("phase", {"phase": "enriching", "targets": min(40, len(all_rows))})

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
        })

    await enrich_profiles(all_rows, on_enriched, subject_name=name)

    # Correlation.
    clusters = await correlate(all_rows)
    emit("correlation", {"clusters": clusters})

    # Wait for the email + domain + broker + phone pivots before persisting.
    if email_task is not None:
        await email_task
    if domain_task is not None:
        await domain_task
    if broker_task is not None:
        await broker_task
    if phone_task is not None:
        await phone_task

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
    router.finish()
    # Honest headline: split the raw union of "handle exists" hits into
    # verification-confirmed accounts, unconfirmed leads, and flagged false
    # positives — instead of reporting every speculative hit as "found".
    buckets = bucket_counts(all_rows)
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
    })
    return summary
