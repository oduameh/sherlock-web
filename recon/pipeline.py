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
from typing import Any, Callable, Optional

from sherlock_project.notify import QueryNotify
from sherlock_project.result import QueryStatus
from sherlock_project.sherlock import sherlock

from recon import engines
from recon.correlate import correlate
from recon.email_pivot import gravatar_lookup, holehe_available, holehe_scan
from recon.enrich import enrich_profiles
from recon.names import generate_name_candidates
from recon.permutations import generate_variants
from recon.phone_pivot import phone_intel

logger = logging.getLogger("recon.pipeline")

ERROR_STATUSES = {QueryStatus.UNKNOWN, QueryStatus.WAF, QueryStatus.ILLEGAL}

# Name-candidate scans fan out across a few workers (they can be 20 handles).
NAME_SHERLOCK_SHARDS = 3
NAME_MAIGRET_CONCURRENCY = 3

Emit = Callable[[str, dict], None]


class _SherlockNotify(QueryNotify):
    """Forwards Sherlock per-site results through the threadsafe emitter."""

    def __init__(self, scanned_name: str, group: dict, emit_ts: Callable):
        super().__init__()
        self.scanned_name = scanned_name
        self.group = group
        self.emit_ts = emit_ts
        self.checked = 0
        self.total = 0

    def update(self, result) -> None:  # called once per site, from scan thread
        self.checked += 1
        status = result.status
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
                     done_event: asyncio.Event) -> None:
    """Thread entry: scan (username, group) pairs sequentially."""
    try:
        for scanned_name, group in items:
            notify = _SherlockNotify(scanned_name, group, emit_ts)
            notify.total = len(site_data)
            emit_ts("engine_start", "sherlock", scanned_name,
                    len(site_data), group)
            sherlock(scanned_name, site_data, notify, timeout=timeout)
            emit_ts("engine_done", "sherlock", scanned_name, group)
    except Exception as exc:
        emit_ts("engine_error", "sherlock", f"{type(exc).__name__}: {exc}")
    finally:
        loop.call_soon_threadsafe(done_event.set)


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
    variants: bool = False,
    timeout: int = 10,
    sher_data: dict,
    emit: Emit,
    loop: asyncio.AbstractEventLoop,
) -> dict:
    """Run the full investigation. Returns the persistable summary dict.

    ``sher_data`` is the already-filtered Sherlock site dict. ``emit`` must be
    called on the event loop only.
    """
    usernames = [u for u in (usernames or []) if u]
    name = (name or "").strip()
    email = (email or "").strip()
    phone = (phone or "").strip()

    # --- shared run state (mutated on the event loop only) -----------------
    rows: dict[tuple[str, str], dict] = {}
    accounts: list[dict] = []
    variant_rows: list[dict] = []
    name_rows: list[dict] = []
    email_state: dict = {"gravatar": None, "holehe": []}
    phone_state: dict = {}

    def emit_threadsafe(kind: str, *args) -> None:
        """Route worker-thread callbacks onto the event loop."""
        handler = {
            "found": _handle_found,
            "error": _handle_error,
            "progress": _handle_progress,
        }.get(kind)
        if handler is not None:
            loop.call_soon_threadsafe(handler, *args)
        else:
            loop.call_soon_threadsafe(_engine_lifecycle, kind, *args)

    def _handle_found(engine, scanned_name, site, url, query_time, group):
        key = (scanned_name, engines.normalize_site(site))
        row = rows.get(key)
        if row is not None:
            if engine not in row["engines"]:
                row["engines"].append(engine)
                emit("merged", {
                    "username": scanned_name, "site": row["site"],
                    "engines": row["engines"],
                    "source": row["source"],
                    "variant_of": row.get("variant_of"),
                    "from_name": row.get("from_name"),
                    "candidate": row.get("candidate"),
                })
            return
        row = {
            "username": scanned_name, "site": site, "url": url,
            "engines": [engine], "query_time": query_time,
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
                args=(shard, site_data, timeout, emit_threadsafe, loop, done),
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
                                               timeout, on_result)
                except Exception as exc:
                    _engine_lifecycle("engine_error", "maigret",
                                      f"{type(exc).__name__}: {exc}")
                _engine_lifecycle("engine_done", "maigret", scanned_name,
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
                email_state["holehe"].append(entry)
                emit("email", {"source": "holehe", "email": addr, **entry})

            await holehe_scan(addr, on_holehe)
        else:
            emit("email", {"source": "holehe", "email": addr,
                           "error": "holehe not installed"})
        hits = sum(1 for h in email_state["holehe"] if h.get("exists"))
        emit("email_done", {"email": addr, "holehe_hits": hits,
                            "gravatar": bool(grav)})

    # --- plan --------------------------------------------------------------
    candidates = generate_name_candidates(name) if name else []
    mai_all = (
        engines.maigret_all_sites() if engines.maigret_available() else {}
    )
    sher_reduced = engines.sherlock_variant_site_data(sher_data)
    mai_reduced = (
        engines.maigret_variant_sites() if engines.maigret_available() else {}
    )

    emit("meta", {
        "name": name, "usernames": usernames, "email": email, "phone": phone,
        "variants": variants, "timeout": timeout,
        "sherlock_sites": len(sher_data), "maigret_sites": len(mai_all),
        "candidate_sites": len(sher_reduced), "candidates": len(candidates),
    })

    if candidates:
        emit("candidates", {"name": name, "candidates": candidates})

    # Phone intel is offline — emit it immediately.
    if phone:
        phone_state = phone_intel(phone)
        emit("phone_intel", phone_state)

    tasks: list = []

    # Base username scans (dual engine, full site sets).
    base_items = [(u, {"kind": "base"}) for u in usernames]
    if base_items:
        base_events = start_sherlock(base_items, sher_data)
        mai_base = asyncio.create_task(maigret_worker(base_items, mai_all))
    else:
        base_events = []
        mai_base = None

    # Name-candidate scans (dual engine, curated high-value sites, fanned out).
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
    else:
        cand_events = []
        mai_cand = None

    email_task = asyncio.create_task(email_worker(email)) if email else None

    # --- phases ------------------------------------------------------------
    await wait_all(base_events)
    if mai_base is not None:
        await mai_base

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
            await wait_all(v_events)

    await wait_all(cand_events)
    if mai_cand is not None:
        await mai_cand

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
        })

    await enrich_profiles(all_rows, on_enriched)

    # Correlation.
    clusters = await correlate(all_rows)
    emit("correlation", {"clusters": clusters})

    # Wait for the email pivot before persisting.
    if email_task is not None:
        await email_task

    summary = {
        "params": {
            "name": name, "usernames": usernames, "email": email,
            "phone": phone, "variants": variants, "timeout": timeout,
        },
        "candidates": candidates,
        "accounts": accounts,
        "variants": variant_rows,
        "name_accounts": name_rows,
        "email": email_state,
        "phone": phone_state or None,
        "correlation": clusters,
    }
    emit("done", {
        "found": len(accounts),
        "variant_hits": len(variant_rows),
        "name_hits": len(name_rows),
        "clusters": len(clusters),
        "email_hits": sum(1 for h in email_state["holehe"] if h.get("exists")),
        "phone": bool(phone_state),
    })
    return summary
