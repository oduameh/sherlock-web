# Spec 03 — Append-only, tamper-evident audit log

**Issue:** [#3 [Compliance] Append-only audit log of all investigation activity](https://github.com/oduameh/sherlock-web/issues/3)
**Status:** proposed · **Priority:** P0 · **Depends on:** spec 01 (Alembic), spec 02 (`users`, actor identity)

## Problem statement

Enterprise/government buyers require an audit trail: who investigated what,
when, and what was exported. It is also our own abuse deterrent — today
nothing records that a customer ran an investigation on a private person, so
stalking misuse is undetectable and unprovable either way.

## Goals

- Append-only `audit_log`, hash-chained (SHA-256) so any tampering with
  history is detectable by an offline verifier.
- Every state-changing endpoint (and every export/download) writes a row.
- Sensitive subject inputs (email, phone, name) are stored as HMAC-SHA256,
  never plaintext.
- Admin-only browser endpoint with pagination and filters.
- `scripts/verify_audit_chain.py` — offline chain verification, runs in CI.

## Non-goals

- No log shipping/SIEM integration (a future export can dump the table).
- No write-ahead to external storage; the chain detects tampering, it does not
  prevent an attacker with full DB + env access from recomputing a fork —
  documented in Threat notes.
- No retroactive audit of pre-existing `runs` rows.

## Current state

No audit capability exists. The state-changing surface (verified against
`app.py`) is:

- `POST /api/investigate` — insert investigation (`app.py:900`)
- `POST /api/investigate/{id}/rerun` — clone + insert (`app.py:928`)
- `GET /api/investigate/{id}/stream` — **executes** the pipeline and writes a
  `runs` row (`app.py:949, 975`); becomes a job enqueue under spec 05, which
  moves the audit point (see below).
- `POST /api/watchlist`, `POST /api/watchlist/{id}/toggle`,
  `DELETE /api/watchlist/{id}` (`app.py:1053-1111`)
- `POST /api/alerts/mark_seen` (`app.py:1132`)
- Exports/downloads (GET, but disclosure events): `GET
  /api/investigate/{id}/report` (`app.py:1023`), `GET
  /api/investigate/{id}/graph` (`app.py:1013`), `GET
  /api/recon/report/{run_id}` (`app.py:778`)
- Auth events (spec 02): login success/failure, logout, password change
- Admin actions (spec 02): user create/disable/enable/reset_password
- Billing events (spec 04): subscription changes arrive via webhook

## Schema (Alembic revision `0003_audit_log`)

```sql
CREATE TABLE audit_log (
    id SERIAL PRIMARY KEY,
    ts TEXT NOT NULL,                       -- UTC ISO-8601
    actor_user_id INTEGER,                  -- NULL = system (monitor, webhooks) or legacy mode
    actor_email_snapshot TEXT NOT NULL,     -- denormalized; survives user deletion
    action TEXT NOT NULL,                   -- dotted verb, enumerated below
    target_type TEXT,                       -- 'investigation' | 'watchlist' | 'run' | 'user' | 'session' | 'alert' | 'subscription'
    target_id TEXT,                         -- TEXT to hold both int ids and stripe ids
    detail_json TEXT NOT NULL DEFAULT '{}', -- action-specific; sensitive fields HMAC'd
    ip TEXT,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);
CREATE INDEX idx_audit_ts ON audit_log(ts);
CREATE INDEX idx_audit_actor ON audit_log(actor_user_id);
CREATE INDEX idx_audit_action ON audit_log(action);
```

There is **no UPDATE or DELETE path** for this table anywhere in the codebase
— enforced by review rule + a CI grep check (spec 06 adds
`git grep -nE "UPDATE audit_log|DELETE FROM audit_log" && exit 1 || true` in
the audit job). Postgres hardening (optional, documented in README):
`REVOKE UPDATE, DELETE ON audit_log FROM <app_role>` once we run migrations
under a separate owner role — deferred, flagged in open questions.

## Hash chain

```
canonical = "|".join([prev_hash, ts, str(actor_user_id or ""),
                      actor_email_snapshot, action, target_type or "",
                      target_id or "", detail_json, ip or ""])
entry_hash = sha256(canonical.encode("utf-8")).hexdigest()
```

- `detail_json` is canonicalized before both storage and hashing:
  `json.dumps(detail, sort_keys=True, separators=(",", ":"))` — what you store
  is what you hash, so verification needs no re-serialization guesses.
- Genesis row: on first audit write after migration, insert
  `audit_log(id=1, ts=<migration ts>, actor_email_snapshot='system',
  action='audit.genesis', detail_json='{}', prev_hash='0'*64)` and hash
  normally. Every later row chains to it.
- Appending is serialized inside one DB transaction: `SELECT entry_hash FROM
  audit_log ORDER BY id DESC LIMIT 1` then `INSERT`. Under Postgres this needs
  no extra lock at current concurrency (the writer is a single process; the
  spec 05 worker writes through the same helper). If replicas ever exceed 1,
  add `pg_advisory_xact_lock(0xA0D17)` in the helper — noted, not built.

## Sensitive-input handling

Subject-identifying values (`email`, `phone`, `name`, and usernames when they
are email-shaped) must not appear in `detail_json` as plaintext. They are
stored as `hmac_sha256(AUDIT_HMAC_KEY, value.lower().strip())` rendered
`"hmac:" + hex`.

- `AUDIT_HMAC_KEY` env var (32+ random bytes, hex or base64).
- **Unset behavior:** local dev falls back to a fixed, in-repo dev key
  constant (`b"sherlock-web-dev-hmac-key-not-secret"`) and logs a loud warning
  at startup. Production (`DATABASE_URL` pointing at Postgres) **refuses to
  boot** without a real key — same fail-fast philosophy as spec 01. Key
  rotation changes all future hashes (old rows keep the old key's hashes;
  document that correlation across rotation is impossible by design).
- Purpose: an admin can check "did anyone investigate email X?" by HMACing X
  and searching, but a DB dump alone doesn't enumerate subjects.

## The `audit()` helper

New module `audit.py`:

```python
def audit(actor: UserContext | None, action: str, *,
          target_type: str | None = None, target_id: str | int | None = None,
          detail: dict | None = None, ip: str | None = None,
          sensitive: dict[str, str] | None = None) -> None:
    """Append one hash-chained audit row. Never raises into the request path:
    failures are logged and (in production) trigger a Sentry-style alarm via
    logging.critical, because a failed audit write in production means the
    compliance guarantee is broken."""
```

- `actor=None` in legacy/open mode → `actor_user_id=NULL`,
  `actor_email_snapshot='legacy'`. System actors (monitor alerts, Stripe
  webhooks) pass `actor=None` and the helper takes
  `actor_email_snapshot='system'` from an explicit kwarg.
- `sensitive` is merged into `detail` after HMACing each value; plaintext keys
  in `detail` are the caller's responsibility and must never contain subject
  PII (review checklist item).

### Action vocabulary and instrumentation points

| action | endpoint / site | target | detail |
|---|---|---|---|
| `auth.login` / `auth.login_failed` / `auth.logout` / `auth.password_change` | spec 02 auth endpoints | `user` / `session` | `{email_hmac}` |
| `investigate.create` | `POST /api/investigate` (`app.py:860`) | `investigation` | input counts + `sensitive={name,email,phone}` + usernames list |
| `investigate.rerun` | `POST /api/investigate/{id}/rerun` (`app.py:916`) | `investigation` | `{rerun_of: id}` |
| `investigate.execute` | currently `GET .../stream` (`app.py:938`); **moves to the job runner in spec 05** (audit written by the worker when the job is claimed, using `owner_user_id` from the job row) | `investigation` | `{job_id}` |
| `watchlist.create` / `watchlist.toggle` / `watchlist.delete` | `app.py:1053/1089/1102` | `watchlist` | `{label, interval_hours}` / `{enabled}` / `{}` |
| `alerts.mark_seen` | `app.py:1132` | `alert` | `{count}` (never alert contents) |
| `export.report` | `GET /api/investigate/{id}/report` (`app.py:1023`) | `investigation` | `{}` |
| `export.graph` | `GET /api/investigate/{id}/graph` (`app.py:1013`) | `investigation` | `{}` |
| `export.recon_report` | `GET /api/recon/report/{run_id}` (`app.py:778`) | `run` | `{}` |
| `admin.user_create` / `admin.user_disable` / `admin.user_enable` / `admin.user_reset_password` | spec 02 admin endpoints | `user` | `{email_hmac, role}` — **never** the password |
| `billing.checkout_started` / `billing.subscription_updated` / `billing.subscription_deleted` / `billing.payment_failed` | spec 04 endpoints + webhook | `subscription` | stripe ids, plan |
| `audit.genesis` | migration | — | `{}` |

`GET /api/history`, `/api/investigate/{id}`, `/api/watchlist`, `/api/alerts`,
`/api/search/stream`, `/api/recon/stream` are reads of the caller's own data
and are **not** audited (volume, no disclosure beyond what the actor already
owns). Exports *are* audited because they move data off-platform.

## Admin audit browser

`GET /api/admin/audit` (`require_admin` from spec 02).

Query params: `page` (default 1), `per_page` (default 50, max 200), `actor`
(user id), `action` (exact or prefix with `*`), `since`, `until` (ISO dates),
`target_type`.

Response:

```json
{
  "page": 1, "per_page": 50, "total": 1234,
  "entries": [
    {"id": 42, "ts": "...", "actor_user_id": 3,
     "actor_email": "analyst@x.com", "action": "investigate.create",
     "target_type": "investigation", "target_id": "17",
     "detail": {...}, "ip": "1.2.3.4", "entry_hash": "...", "prev_hash": "..."}
  ]
}
```

Hashes are included so an auditor can sample-verify rows by hand. 403 for
non-admin; 401 unauthenticated. No update/delete endpoint exists, by design.

## `scripts/verify_audit_chain.py`

```
python scripts/verify_audit_chain.py [--db <DATABASE_URL-or-sqlite-path>]
```

- Reads all rows ordered by `id`, recomputes the canonical string and
  `entry_hash` for each, checks `row[i].prev_hash == row[i-1].entry_hash` and
  genesis `prev_hash == '0'*64`.
- Exit 0 with `OK: N entries, chain head <hash>`; exit 1 on first mismatch
  printing the offending row id and both hashes (never prints `detail_json` —
  it may contain HMACs whose preimage is PII).
- Runs in CI against a fixture DB (spec 06, job 4). The fixture
  `tests/fixtures/make_audit_fixture.py` generates 50 chained rows with two
  synthetic actors so the verifier has a known-good target, and a deliberately
  corrupted copy `audit_fixture_tampered.db` on which the verifier **must**
  exit 1 (asserted in the CI job).

## Retention policy (documented in README)

Audit rows are **exempt from every data-purge / retention feature** (the
user-data purge planned for a later spec). Rationale: the audit log's value is
precisely that it outlives the data it describes — a customer who deletes an
investigation must not delete the record that they ran it (abuse deterrence +
compliance). Rows reference subjects only by HMAC, so the log itself carries
no plaintext PII to purge. Operators needing full log deletion do it at the
database level as an explicit, out-of-band act.

## Threat notes

- Hash chaining detects post-hoc edits/deletions by anyone who cannot
  recompute the full chain undetected. An attacker with DB write + app env can
  fork the chain; the mitigation is periodic pinning — `verify_audit_chain.py`
  prints the head hash, and ops can store it externally (manual v1, automated
  later).
- `actor_email_snapshot` is deliberately denormalized so disabling/deleting a
  user doesn't erase attribution.

## Migration / rollout plan

1. Revision `0003_audit_log` (table + genesis-row helper).
2. `audit.py` helper + instrumentation in the same PR (no endpoint ships
   unaudited after this lands).
3. Set `AUDIT_HMAC_KEY` in Railway before deploy (fail-fast otherwise).
4. Legacy-mode deployments (no users) still audit, with `actor='legacy'` —
   single-user self-hosters get the trail for free.

## Testing plan

- `tests/test_audit.py`: chain append → genesis correct; 3 sequential writes
  verify; tamper one stored `detail_json` → verifier exits 1 and names the
  row; HMAC path stores no plaintext (assert the email string is absent from
  the DB dump); canonicalization stable across dict ordering.
- Endpoint tests: `POST /api/investigate` writes exactly one
  `investigate.create` row with the caller's id; export endpoints write
  `export.*`; viewer 403 path writes nothing.
- `/api/admin/audit`: pagination math, filters, non-admin 403.
- Fixture generator + verifier wired into CI per spec 06.

## Open questions

- Postgres `REVOKE`-based hardening of `audit_log` (needs a split migration /
  runtime DB role) — worth it before the first compliance review?
- External head-hash pinning (e.g. nightly job posts the head hash to an
  append-only store) — which store, if any, do we standardize on?
- Do we audit *views* of other people's data for admins (admin opening user
  B's investigation)? Cheap to add via `_get_investigation`; decision deferred
  to the first enterprise security review.
