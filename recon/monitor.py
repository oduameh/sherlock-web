"""Watchlist monitoring: periodic light re-scans with change alerts.

A background asyncio task (started with the app, resuming from SQLite after
restarts) picks due watchlist entries every TICK_SECONDS, re-runs a LIGHT
scan — usernames and email against the curated high-value sites only, no
enrichment — and diffs the found-set against the stored signature. Changes
become alert rows ("new account: X on GitHub", "account gone: Y",
"new holehe hit: Z"). The first run of a watch establishes the baseline
signature silently.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import time
from typing import Any, Callable, Optional

from dbconn import connect as db_connect
from recon import engines
from recon.email_pivot import holehe_available, holehe_scan
from recon.names import generate_name_candidates

logger = logging.getLogger("recon.monitor")

TICK_SECONDS = 60
MIN_INTERVAL_HOURS = 6
DEFAULT_INTERVAL_HOURS = 24
LIGHT_TIMEOUT_S = 8
MAX_WATCHES_PER_TICK = 5

# Normalized holehe module names we allow in light scans.
_HOLEHE_WANTED = {engines.normalize_site(s) for s in engines.HIGH_VALUE_SITES}


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

def init_tables(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS watchlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            label TEXT NOT NULL,
            inputs TEXT NOT NULL,
            interval_hours INTEGER NOT NULL,
            last_run_at TEXT,
            last_signature TEXT,
            enabled INTEGER NOT NULL DEFAULT 1
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS watch_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            watch_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            kind TEXT NOT NULL,
            message TEXT NOT NULL,
            data TEXT,
            seen INTEGER NOT NULL DEFAULT 0
        )
        """
    )


# ---------------------------------------------------------------------------
# Light scan
# ---------------------------------------------------------------------------

def _sherlock_light(usernames: list[str], site_data: dict,
                    timeout: int) -> list[dict]:
    """Synchronous sherlock scan of usernames over the high-value subset.

    Runs in a worker thread (via asyncio.to_thread). Returns found rows.
    """
    from sherlock_project.notify import QueryNotify
    from sherlock_project.result import QueryStatus
    from sherlock_project.sherlock import sherlock

    found: list[dict] = []

    class _N(QueryNotify):
        def update(self, result) -> None:
            if result.status == QueryStatus.CLAIMED:
                found.append({"username": result.username,
                              "site": result.site_name,
                              "url": result.site_url_user})

    for username in usernames:
        try:
            sherlock(username, site_data, _N(), timeout=timeout)
        except Exception:
            logger.exception("monitor sherlock scan failed for %s", username)
    return found


async def light_scan(inputs: dict, sher_site_data: dict,
                     timeout: int = LIGHT_TIMEOUT_S) -> dict:
    """Run the light scan for a watch's inputs. Returns found accounts +
    holehe hits. Never raises."""
    usernames = [u.strip() for u in (inputs.get("usernames") or []) if u.strip()]
    if not usernames and inputs.get("name"):
        usernames = generate_name_candidates(inputs["name"])
    email = (inputs.get("email") or "").strip()

    accounts: list[dict] = []
    if usernames and sher_site_data:
        accounts = await asyncio.to_thread(
            _sherlock_light, usernames, sher_site_data, timeout
        )

    holehe_hits: list[dict] = []
    if email and holehe_available():
        def on_result(entry):
            if entry.get("exists"):
                holehe_hits.append({"site": entry.get("site"),
                                    "domain": entry.get("domain")})

        try:
            await holehe_scan(email, on_result, only=_HOLEHE_WANTED,
                              delay=0.15)
        except Exception:
            logger.exception("monitor holehe scan failed")

    return {"accounts": accounts, "holehe": holehe_hits}


# ---------------------------------------------------------------------------
# Signature diffing
# ---------------------------------------------------------------------------

def compute_signature(scan: dict) -> dict[str, dict]:
    """Deterministic key -> display info map persisted as JSON."""
    sig: dict[str, dict] = {}
    for a in scan.get("accounts") or []:
        key = f"acct:{engines.normalize_site(a['site'])}:{a['username'].lower()}"
        sig[key] = {"username": a["username"], "site": a["site"],
                    "url": a.get("url")}
    for h in scan.get("holehe") or []:
        key = f"holehe:{engines.normalize_site(h['site'] or '')}"
        sig[key] = {"site": h.get("site"), "domain": h.get("domain")}
    return sig


def diff_signatures(old: dict[str, dict],
                    new: dict[str, dict]) -> list[dict]:
    """Return alert dicts {kind, message, data} for the old->new change."""
    alerts: list[dict] = []
    for key in sorted(new.keys() - old.keys()):
        info = new[key]
        if key.startswith("acct:"):
            alerts.append({
                "kind": "new_account",
                "message": f"new account: {info['username']} on {info['site']}",
                "data": info,
            })
        else:
            alerts.append({
                "kind": "new_holehe_hit",
                "message": f"new holehe hit: {info.get('site')}",
                "data": info,
            })
    for key in sorted(old.keys() - new.keys()):
        info = old[key]
        if key.startswith("acct:"):
            alerts.append({
                "kind": "account_gone",
                "message": f"account gone: {info['username']} on {info['site']}",
                "data": info,
            })
        else:
            alerts.append({
                "kind": "holehe_hit_gone",
                "message": f"holehe hit gone: {info.get('site')}",
                "data": info,
            })
    return alerts


# ---------------------------------------------------------------------------
# Monitor loop
# ---------------------------------------------------------------------------

def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _due_watches(db_path) -> list[dict]:
    with db_connect(db_path) as conn:
        rows = conn.execute(
            "SELECT id, label, inputs, interval_hours, last_run_at,"
            " last_signature FROM watchlist WHERE enabled = 1"
        ).fetchall()
    due = []
    now = time.time()
    for r in rows:
        last_run_at = r[4]
        if last_run_at:
            try:
                last_ts = time.mktime(time.strptime(last_run_at,
                                                    "%Y-%m-%d %H:%M:%S"))
            except Exception:
                last_ts = 0
            if now - last_ts < r[3] * 3600:
                continue
        due.append({
            "id": r[0], "label": r[1], "inputs": json.loads(r[2]),
            "interval_hours": r[3], "last_run_at": last_run_at,
            "last_signature": json.loads(r[5]) if r[5] else {},
        })
    return due


async def run_watch(db_path, watch: dict, sher_site_data: dict) -> int:
    """Run one watch: light scan, diff, alert. Returns # of alerts written."""
    wid = watch["id"]
    # Stamp last_run_at up front so a crash doesn't hot-loop the same watch.
    with db_connect(db_path) as conn:
        conn.execute("UPDATE watchlist SET last_run_at = ? WHERE id = ?",
                     (_now(), wid))

    scan = await light_scan(watch["inputs"], sher_site_data)
    new_sig = compute_signature(scan)
    old_sig = watch.get("last_signature") or {}
    baseline = not watch.get("last_run_at") and not old_sig

    alerts = [] if baseline else diff_signatures(old_sig, new_sig)
    with db_connect(db_path) as conn:
        for a in alerts:
            conn.execute(
                "INSERT INTO watch_alerts"
                " (watch_id, created_at, kind, message, data, seen)"
                " VALUES (?,?,?,?,?,0)",
                (wid, _now(), a["kind"], a["message"],
                 json.dumps(a["data"])),
            )
        conn.execute(
            "UPDATE watchlist SET last_signature = ? WHERE id = ?",
            (json.dumps(new_sig), wid),
        )
    logger.info("watch %d (%s): %d accounts, %d holehe hits, %d alerts",
                wid, watch["label"], len(scan["accounts"]),
                len(scan["holehe"]), len(alerts))
    return len(alerts)


async def monitor_loop(db_path, sher_site_data: dict,
                       tick_seconds: int = TICK_SECONDS) -> None:
    """Background task: forever pick due watches and re-scan them."""
    logger.info("watchlist monitor started (tick %ds, %d light sites)",
                tick_seconds, len(sher_site_data))
    while True:
        try:
            due = _due_watches(db_path)[:MAX_WATCHES_PER_TICK]
            for watch in due:
                try:
                    await run_watch(db_path, watch, sher_site_data)
                except Exception:
                    logger.exception("watch %d run failed", watch["id"])
        except Exception:
            logger.exception("monitor tick failed")
        await asyncio.sleep(tick_seconds)
