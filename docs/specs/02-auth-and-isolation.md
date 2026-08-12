# Spec 02 — Multi-user auth, roles, per-user isolation

**Issue:** [#2 [Platform] Multi-user auth, roles, and per-user data isolation](https://github.com/oduameh/sherlock-web/issues/2)
**Status:** proposed · **Priority:** P0 · **Depends on:** spec 01 (Alembic revision numbering, `dbconn` factory)

## Problem statement

Today the only access control is the optional `APP_PASSWORD` HTTP Basic gate
(`app.py:98-119`): one shared password, any username, every route. All users
see all investigations, watchlists, alerts, and history. There is no identity,
no ownership, and no way to sell a team account.

## Goals

- Email + password accounts with argon2-cffi hashing; opaque session tokens in
  an httponly cookie. No JWT.
- Roles `admin` / `analyst` / `viewer`; viewer is read-only.
- Every investigation, watch, alert, and history run owned by a `user_id`;
  list/get endpoints scoped to the caller. Admin sees everything.
- Existing single-user self-host mode (`APP_PASSWORD`, no accounts) preserved
  exactly until a bootstrap admin is created.
- Admin user-management endpoints; no SMTP dependency (admin sets temporary
  passwords).

## Non-goals

- No SSO/OAuth, no magic links, no email verification, no password reset by
  email (no mailer exists).
- No organizations/teams as a first-class entity (billing's "Team" in spec 04
  is N individual subscriptions, not a shared workspace).
- No per-object sharing between users. A viewer reads only their **own** data
  in v1; shared case files are a future spec.

## Current state

- Gate: `basic_auth_gate` middleware (`app.py:101`) compares the Basic-auth
  password with `APP_PASSWORD` via `secrets.compare_digest` and 401s with
  `WWW-Authenticate: Basic realm="sherlock-web"`.
- No user concept anywhere in the schema (see spec 01 table inventory). All
  list endpoints are unscoped: `get_history` (`app.py:200`),
  `list_watchlist` (`app.py:1035`), `list_alerts` (`app.py:1113`), etc.
- Frontend is a single `static/index.html`; it currently only ever sees 401
  from the browser's Basic-auth prompt.

## Decision

- **Hashing:** `argon2-cffi` (`argon2.PasswordHasher`, default parameters:
  time=3, memory=64 MiB, parallelism=4). Add `argon2-cffi>=23` to
  `requirements.txt`.
- **Sessions:** opaque random token (`secrets.token_urlsafe(32)`), stored
  **as-is** as the `sessions.token` primary key (per the agreed schema), set
  as cookie `sw_session` with `HttpOnly; Secure; SameSite=Lax; Path=/`.
  14-day absolute expiry with **sliding renewal**: any authenticated request
  with < 7 days remaining extends `expires_at` to now+14d (and re-Set-Cookies).
- **Why not JWT:** revocation is a hard requirement (admin disable must kill
  sessions immediately); server-side rows give that for free, and the DB is
  already the bottleneck-free store for this app's scale.

## Schema (Alembic revision `0002_users_sessions`)

```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'analyst'
        CHECK (role IN ('admin','analyst','viewer')),
    disabled INTEGER NOT NULL DEFAULT 0,
    force_password_change INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT
);
CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);

-- Ownership columns. Nullable first; backfilled, then left nullable so the
-- legacy APP_PASSWORD mode (no accounts) can keep writing rows with NULL owner.
ALTER TABLE investigations ADD COLUMN user_id INTEGER REFERENCES users(id);
ALTER TABLE watchlist     ADD COLUMN user_id INTEGER REFERENCES users(id);
ALTER TABLE runs          ADD COLUMN user_id INTEGER REFERENCES users(id);
CREATE INDEX idx_investigations_user ON investigations(user_id);
CREATE INDEX idx_watchlist_user ON watchlist(user_id);
CREATE INDEX idx_runs_user ON runs(user_id);
```

`watch_alerts` gets **no** `user_id`; it is scoped through
`watchlist.user_id` (alerts are always queried joined to `watchlist` already —
`list_alerts` does `LEFT JOIN watchlist w ON w.id = a.watch_id`,
`app.py:1118`).

**Backfill (issue acceptance criterion):** revision 0002 ships with a data
migration guarded by `context.get_bind()`: if a users row exists at migration
time it does nothing; the *bootstrap step* (below) assigns orphans. Concretely,
`scripts/create_admin.py` ends with:

```sql
UPDATE investigations SET user_id = :admin WHERE user_id IS NULL;
UPDATE watchlist     SET user_id = :admin WHERE user_id IS NULL;
UPDATE runs          SET user_id = :admin WHERE user_id IS NULL;
```

so pre-auth data becomes the bootstrap admin's casework.

## Auth model and ordering with the APP_PASSWORD gate

Two mutually exclusive modes, decided per-request by cheap state:

- **Legacy mode:** `users` table is empty **and** `APP_PASSWORD` is set →
  current behavior, unchanged: the existing `basic_auth_gate` middleware
  enforces Basic auth; request proceeds with `current_user = None` and all
  queries run unscoped (single tenant). Writes store `user_id = NULL`.
- **Account mode:** at least one row in `users` → the Basic gate is **fully
  disabled** (even if `APP_PASSWORD` is still set) and the session-cookie
  dependency takes over.
- If neither is configured (no users, no `APP_PASSWORD`) the app is fully open
  exactly as today (unset `APP_PASSWORD` = open, `app.py:98`).

Implementation:

1. `basic_auth_gate` middleware stays but short-circuits when account mode is
   active. The check is `SELECT EXISTS(SELECT 1 FROM users)` cached for 30s in
   module state (avoid a query per request; invalidated on user creation).
2. A FastAPI dependency replaces identity resolution inside handlers:

```python
def current_user(request: Request) -> UserContext | None:
    """Returns None in legacy/open mode (handlers then behave as today),
    else the users row. Raises 401 JSON when account mode is active and the
    session cookie is missing/expired/disabled."""
```

Role guards: `require_analyst` (any write), `require_admin` (`/api/admin/*`).
Viewer = authenticated but write endpoints return 403. `POST
/api/alerts/mark_seen` counts as a write (viewer gets 403) — read-only means
no state changes at all.

Mode decision rule in prose: `account_mode = users_table_non_empty()`. First
`create_admin.py` run flips the deployment from legacy to account mode
permanently; there is no path back other than deleting all users.

## Bootstrap flow — decision: CLI script

`scripts/create_admin.py` (new):

```
python scripts/create_admin.py --email admin@example.com [--password ...]
```

- Refuses to run if any user already exists (unless `--force-new`).
- Generates a random 20-char password if `--password` omitted and prints it
  once to stdout; sets `role='admin'`, `force_password_change=1`.
- Runs the orphan backfill UPDATEs above.
- Works on Railway via the service shell (`railway run` / web shell).

**Why CLI over a first-visit setup screen:** a setup screen is an
unauthenticated "become admin" endpoint that exists until someone claims it —
on a public Railway URL that is a race the operator can lose to a crawler. The
CLI needs shell access, which is already the trust boundary. This is the one
place we accept operator friction for security.

## Endpoints

### `POST /api/auth/login`
Request: `{"email": "...", "password": "..."}`
- Always runs one argon2 verification (against a module-level dummy hash when
  the email doesn't exist) so the response time is indistinguishable.
- Success: creates `sessions` row (ip from `request.client.host`,
  user_agent truncated to 256 chars), sets cookie, returns
  `{"id": 1, "email": "...", "role": "analyst", "force_password_change": false}`.
- Failure: 401 `{"error": "invalid credentials"}` (no user-existence leak).
- Disabled account: 403 `{"error": "account disabled"}`.
- Rate limit: per-IP sliding window, 10 failed logins / 5 min → 429
  `{"error": "too many attempts", "retry_after": N}`. In-memory
  `defaultdict(deque)` in the app process (single-process deployment; note in
  ops docs that multi-replica needs a shared store).

### `POST /api/auth/logout`
Deletes the session row, clears cookie (`Max-Age=0`). Returns `{"ok": true}`.

### `GET /api/auth/me`
`{"id", "email", "role", "force_password_change"}`; 401 when unauthenticated
(in account mode). Frontend uses this to choose login vs. app view.

### `POST /api/auth/change_password`
Request: `{"current_password", "new_password"}` (min length 12).
Re-hashes, clears `force_password_change`, and **deletes all other sessions
for the user** (password change = global re-auth).

### Admin endpoints (`require_admin`)

| Method+path | Body | Response | Notes |
|---|---|---|---|
| `GET /api/admin/users` | — | `[{id,email,role,disabled,created_at,force_password_change}]` | all users |
| `POST /api/admin/users` | `{email, role, password?}` | `{id, email, temporary_password}` | random temp password if omitted; `force_password_change=1` |
| `POST /api/admin/users/{id}/disable` | — | `{id, disabled: true}` | also deletes that user's sessions |
| `POST /api/admin/users/{id}/enable` | — | `{id, disabled: false}` | |
| `POST /api/admin/users/{id}/reset_password` | `{password?}` | `{id, temporary_password}` | sets `force_password_change=1`, deletes sessions |

Admin cannot disable or reset their own account via these endpoints (guard
against self-lockout): 409 `{"error": "cannot modify own account"}`.

### Frontend

`static/index.html` gains a minimal login form shown when `GET /api/auth/me`
returns 401. No design work; reuse existing CSS. Basic-auth (legacy) mode is
untouched — the browser still prompts before the page loads.

## Ownership scoping (endpoint-by-endpoint changes)

All changes are `WHERE user_id = :uid` (non-admin) or unscoped (admin); legacy
mode (`current_user is None`) keeps today's unscoped queries and inserts
`user_id = NULL`:

- `get_history` (`app.py:200`) — scope `runs`.
- `get_run` (`app.py:214`) — 404 when not owner (indistinguishable from
  missing: **no enumeration**).
- `recon_report` (`app.py:778`) — same 404 rule.
- `create_investigation` (`app.py:860`) / `rerun_investigation` (`app.py:916`) —
  insert with `user_id`.
- `_get_investigation` (`app.py:829`) — add ownership filter; used by
  `get_investigation`, `rerun_investigation`, `investigate_stream`,
  `investigate_graph`, `investigate_report` — one choke point, all covered.
  The SSE stream returns the existing `event: fatal` "investigation not found"
  payload for foreign ids, same as missing.
- `list_watchlist` / `create_watch` / `toggle_watch` / `delete_watch`
  (`app.py:1035-1111`) — scoped; toggle/delete 404 on foreign rows.
- `list_alerts` (`app.py:1113`) — `WHERE w.user_id = :uid` (join already
  present); `mark_alerts_seen` (`app.py:1132`) — `UPDATE watch_alerts ... WHERE
  id IN (...) AND watch_id IN (SELECT id FROM watchlist WHERE user_id=:uid)`.
- `save_run` (`app.py:180`) — gains a `user_id` parameter threaded from the
  request context (scan thread and monitor jobs receive it explicitly, since
  they run off-request; spec 05 carries it in the job payload).
- The watchlist monitor (`recon/monitor.py:194 _due_watches`) selects all
  enabled watches regardless of owner (system actor) — no change needed, but
  the alerts it writes stay scoped via the watch's `user_id`.

## Threat model

- **Session fixation:** token is generated server-side at login; we never
  accept a client-supplied token. Login rotates the cookie (old sessions for
  that cookie value can't exist since the value is fresh randomness).
- **Timing attacks on login:** constant-time argon2 verify against a dummy
  hash for unknown emails; identical 401 body. (The Basic gate already uses
  `secrets.compare_digest`, `app.py:110`.)
- **Brute force:** per-IP 10/5min sliding-window 429 on `/api/auth/login`
  (above), plus argon2's ~250ms verify cost as a natural brake. Lockout is
  per-IP, not per-account, to avoid trivial DoS of a known victim's account.
- **Cookie theft / XSS:** `HttpOnly` (no JS read), `Secure` (TLS only — set
  unconditionally; local dev over http is exempted via `request.url.scheme`
  check so `run.sh` still works), `SameSite=Lax` blocks CSRF on cross-site
  POSTs. Session rows store ip/user_agent for **audit display only** — we do
  not bind sessions to IP (mobile users roam).
- **DB-read = session takeover:** tokens are stored as-is per the agreed
  schema; the mitigation is that DB access already implies full data access in
  this system, and Railway Postgres is not publicly exposed. If we ever add
  DB-leak blast-radius reduction, hashing tokens at rest is the follow-up
  (documented, not implemented).
- **Privilege escalation:** role changes only via admin endpoints; `role` is
  re-read from the DB on every request (no caching) so disable/demote is
  immediate.
- **Password storage:** argon2id with per-user salt, parameters from the
  library defaults; hashes never appear in any API response or audit detail
  (spec 03 forbids `password_hash` in `detail_json`).

## Error behavior summary

| Case | Status | Body |
|---|---|---|
| No/expired session (account mode) | 401 | `{"error": "authentication required"}` |
| Viewer attempts write | 403 | `{"error": "read-only role"}` |
| Non-owner resource access | 404 | `{"error": "not found"}` (indistinguishable) |
| Login brute force | 429 | `{"error": "too many attempts", "retry_after": N}` |
| Admin self-modify | 409 | `{"error": "cannot modify own account"}` |

SSE endpoints under auth: same codes, but `/api/investigate/{id}/stream`
keeps its in-band `event: fatal` convention for *business* errors after the
stream starts; auth failures still return plain 401 before streaming.

## Migration / rollout plan

1. Ship revision 0002 + auth code with account mode inactive (no users) — no
   behavior change anywhere.
2. On the production deployment, run `python scripts/create_admin.py
   --email <owner>` once via Railway shell → account mode flips on, legacy
   Basic gate disables, existing data backfilled to the admin.
3. Admin creates analyst/viewer users from the admin endpoints and hands out
   temporary passwords out-of-band.
4. Self-hosters who never run the script keep exactly today's behavior
   (`APP_PASSWORD` or open).

## Testing plan

- `tests/test_auth.py`: argon2 hash/verify round-trip; session create/lookup/
  expiry/sliding-renewal; mode flip (empty users → legacy; one user →
  account); login rate limit triggers at 10 failures; dummy-hash timing path
  executes (mock `PasswordHasher.verify` to assert it's called for unknown
  emails).
- `tests/test_isolation.py` (the issue's acceptance test): two users A/B via
  FastAPI `TestClient`; A creates investigation + watch; B cannot
  `GET /api/investigate/{a_id}`, cannot see it in `/api/history`, cannot
  toggle/delete A's watch, cannot see A's alerts; admin sees both. Viewer role
  gets 403 on every POST/DELETE listed above.
- All existing tests keep passing (they import `recon.*` only; the one
  app-level concern is that `TestClient(app)` with no users + no
  `APP_PASSWORD` stays fully open).

## Open questions

- Do we want an `invited` state + invite tokens later, or is
  admin-sets-temp-password sufficient for the first customers? (Sufficient for
  v1; invites need SMTP.)
- Should failed-login audit rows (spec 03) feed an auto-disable threshold
  (e.g. 50 failures on one account in 24h → disabled + admin alert)? Deferred,
  but the audit schema should not preclude it.
- Session cleanup: lazy delete of expired sessions on access vs. a nightly
  sweep — v1 does lazy + opportunistic delete-on-renew; a sweep job can ride
  the spec 05 scheduler later.
