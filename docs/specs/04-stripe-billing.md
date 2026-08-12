# Spec 04 — Stripe billing with plan-based limits

**Issue:** [#4 [Platform] Stripe billing with plan-based limits](https://github.com/oduameh/sherlock-web/issues/4)
**Status:** proposed · **Priority:** P0 · **Depends on:** spec 01 (Alembic), spec 02 (`users`, roles), spec 03 (audit), consumed by spec 05 (concurrency caps)

## Problem statement

There is no billing and no usage metering. Watchlists (the recurring-value
feature) are free and unlimited: any user can create any number of watches at
`MIN_INTERVAL_HOURS = 6` (`recon/monitor.py:29`). To be a business we need
plans, enforcement, and webhook-driven entitlement sync.

## Goals

- Stripe Checkout (upgrade) + Customer Portal (manage/cancel) + a
  signature-verified webhook that syncs entitlement state onto `users`.
- Plan-based limits enforced server-side at: investigation creation, watchlist
  creation, and watch interval changes.
- Auditable metering (every billable action recorded).
- No Stripe keys configured → billing fully disabled, everything unlimited
  (self-host mode; keeps current behavior).

## Non-goals

- **No team seats in v1.** "Team" in this spec is one subscription with higher
  limits bought per user. An organization that wants 5 seats buys 5
  subscriptions. This is a deliberate simplification of the issue's
  "Team … 5 seats" wording — real shared workspaces need cross-user data
  sharing, which spec 02 explicitly defers. Documented here so sales language
  doesn't promise seats.
- No Org/custom plan machinery (handled manually via Stripe dashboard +
  admin-set `plan` overrides).
- No usage-based/overage pricing, no invoices surfaced in-app, no tax config
  beyond Stripe defaults.
- No free trial logic (Stripe-side trial config is allowed but not modeled
  in-app beyond `plan_status='trialing'` being treated as active).

## Current state

- No Stripe dependency, no plan/limits code anywhere.
- Enforcement points as they exist today: `create_investigation`
  (`app.py:860`) validates inputs only; `create_watch` (`app.py:1053`) clamps
  interval with `max(recon_monitor.MIN_INTERVAL_HOURS, ...)` (`app.py:1074`);
  there is no count-based limit anywhere.
- The only "quota-ish" constants live in `recon/monitor.py`
  (`MAX_WATCHES_PER_TICK = 5` — a scheduler concern, not a plan limit).

## Decision

- `stripe` python SDK (`stripe>=11`, pinned minor in `requirements.txt`).
- Env: `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PRICE_SOLO`,
  `STRIPE_PRICE_TEAM`. **All four unset/empty → self-host mode: no billing
  routes mounted, `plan_limits()` returns unlimited for everyone.** Partial
  config → fail fast at boot with a naming-the-missing-var error.
- Entitlements live on the `users` row (spec 02), synced only by webhook
  handlers (never trust client redirects).

### Plans and limits

| plan | investigations / calendar month | active watch slots | min watch interval | concurrent investigation jobs (spec 05) |
|---|---|---|---|---|
| free (default) | 5 | 1 | 24h | 1 |
| solo | 10 | 3 | 6h (= current `MIN_INTERVAL_HOURS`) | 1 |
| team | 100 | 25 | 1h | 3 |

(The issue suggests Solo 10/mo + 3 slots and Team 100/mo + 25 slots — adopted
verbatim; free tier added for the hosted product; solo price point = whatever
`STRIPE_PRICE_SOLO` says, prices are Stripe-side.)

`team`'s 1h interval requires lowering the floor *for that plan only*: the
clamp in `create_watch` becomes `max(plan_limits(user).min_interval_hours, ...)`.
`recon.monitor.MIN_INTERVAL_HOURS` stays as the absolute floor for free/solo.

## Schema (Alembic revision `0004_billing`)

```sql
ALTER TABLE users ADD COLUMN plan TEXT NOT NULL DEFAULT 'free'
    CHECK (plan IN ('free','solo','team'));
ALTER TABLE users ADD COLUMN stripe_customer_id TEXT UNIQUE;
ALTER TABLE users ADD COLUMN stripe_subscription_id TEXT;
ALTER TABLE users ADD COLUMN plan_status TEXT NOT NULL DEFAULT 'active';
    -- active | trialing | past_due | canceled  (mirrors stripe status;
    --  free plan is always 'active')
ALTER TABLE users ADD COLUMN current_period_end TEXT;  -- UTC ISO-8601

CREATE TABLE usage_events (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    ts TEXT NOT NULL,
    kind TEXT NOT NULL,        -- 'investigation' | 'watch_create' | 'watch_delete'
    ref_id TEXT                -- investigation id / watch id
);
CREATE INDEX idx_usage_user_month ON usage_events(user_id, ts);
```

Metering reads: investigations this calendar month =

```sql
SELECT COUNT(*) FROM usage_events
WHERE user_id = :u AND kind = 'investigation'
  AND ts >= date_trunc('month', now())::text;   -- SQLite: strftime('%Y-%m-01','now')
```

Watch slots = `SELECT COUNT(*) FROM watchlist WHERE user_id=:u AND enabled=1`
(disabled watches don't consume slots but keep their data). Count queries are
cheap at this scale; `usage_events` exists for auditability (issue requirement:
"metering table so limits are auditable") and is written on every billable
action, not read for watch counting.

## Endpoints

All under account mode (spec 02); in self-host mode none of these exist (404).

### `GET /api/billing/plan`
`{"plan": "solo", "plan_status": "active", "current_period_end": "...",
 "usage": {"investigations_used": 4, "investigations_limit": 10,
           "watch_slots_used": 2, "watch_slots_limit": 3,
           "min_interval_hours": 6},
 "billing_enabled": true}`

### `POST /api/billing/checkout` — `{plan: "solo"|"team"}`
- Creates (or reuses) the Stripe Customer (`users.stripe_customer_id`),
  creates a Checkout Session in `subscription` mode with
  `line_items=[{price: STRIPE_PRICE_<PLAN>, quantity: 1}]`,
  `success_url={BASE_URL}/?billing=success`,
  `cancel_url={BASE_URL}/?billing=cancel`,
  `client_reference_id=str(user.id)` + `metadata.user_id`.
- Response: `{"checkout_url": "https://checkout.stripe.com/..."}` — the
  frontend redirects. **The redirect does not change the plan**; only the
  webhook does (a user who closes the tab mid-checkout gains nothing).
- 402 semantics don't apply here; 400 on unknown plan, 409 if already on that
  plan with active subscription.

### `POST /api/billing/portal`
Creates a Customer Portal session for `users.stripe_customer_id`; response
`{"portal_url": "..."}`. Cancel/downgrade happen entirely in the Portal.
404 `{"error": "no billing account"}` if the user has never subscribed.

### `POST /api/billing/webhook`
- Raw-body HMAC verification: `stripe.Webhook.construct_event(raw_body,
  sig_header, STRIPE_WEBHOOK_SECRET)`; 400 on bad signature, and no
  processing. The route must read `await request.body()` **before** any JSON
  parsing (FastAPI route takes no pydantic model).
- Handled events:

| event | action |
|---|---|
| `checkout.session.completed` | resolve user via `client_reference_id`; store `stripe_customer_id`, `stripe_subscription_id`; set `plan` from the session's price id; `plan_status='active'` |
| `customer.subscription.updated` | sync `plan` (price id → plan map), `plan_status`, `current_period_end`; handles upgrades, downgrades-scheduled (`cancel_at_period_end=true` keeps current plan until period end), and reactivations |
| `customer.subscription.deleted` | fires at actual end (including after `cancel_at_period_end`): `plan='free'`, `plan_status='canceled'`, `current_period_end=NULL`, keep `stripe_customer_id` for re-subscribe |
| `invoice.payment_failed` | `plan_status='past_due'` (limits still enforced at the *current* plan until Stripe gives up and deletes the subscription — grace via Stripe's retry schedule, not our code) |

- Unknown event types → 200 `{"ignored": "<type>"}` (Stripe requires 2xx or
  it retries).
- Idempotency: handlers are written to be safely re-applied (set-state, not
  increment); Stripe's at-least-once delivery is thus harmless. No event-log
  table in v1.
- Each handled event writes a spec-03 audit row (`billing.*`, actor = system).

### Enforcement points (402 errors)

Error shape everywhere (frontend keys on `code`):

```json
HTTP 402
{"error": "plan_limit_exceeded", "code": "investigations_monthly",
 "limit": 5, "used": 5, "plan": "free", "upgrade_url": "/api/billing/plan"}
```

- `POST /api/investigate` (`app.py:860`): before insert, count this month's
  `usage_events`; at limit → 402 with `code:"investigations_monthly"`. On
  success write `usage_events(kind='investigation', ref_id=<inv_id>)`.
  `POST /api/investigate/{id}/rerun` (`app.py:916`) counts as a new
  investigation (it creates one) — same check.
- `POST /api/watchlist` (`app.py:1053`): enabled-watch count at limit → 402
  `code:"watch_slots"`. On success write `usage_events(kind='watch_create')`.
- Watch interval clamp (`app.py:1074`): floor becomes the plan's
  `min_interval_hours` (no error; silently clamps, as today).
- `POST /api/watchlist/{id}/toggle` (`app.py:1089`): enabling also consumes a
  slot → same 402 when full.
- `DELETE /api/watchlist/{id}` writes `usage_events(kind='watch_delete')`
  (audit trail of slot churn).

**Downgrade-at-period-end semantics:** when `customer.subscription.deleted`
drops a user to free with, say, 8 active watches: we do **not** delete watches
(destructive surprises are worse than over-quota). Instead, over-quota users
keep existing watches running but cannot create/enable new ones
(`create`/`toggle-on` 402 until under quota). Investigations likewise block at
the free monthly count. This is the "grace-period downgrade behavior" the
issue asks for; documented in the README pricing page.

## Self-host mode

`BILLING_ENABLED = all(env values present)`. When false:
- `/api/billing/*` routes are not registered (404).
- `plan_limits()` returns `{"investigations_month": None, "watch_slots": None,
  "min_interval_hours": recon.monitor.MIN_INTERVAL_HOURS, "concurrent_jobs": 4}`
  (`None` = unlimited, checked explicitly in enforcement code).
- No `stripe` import at module scope (lazy import inside billing module) so
  self-hosters could even omit the package.

## Flows (frontend)

- Upgrade: settings panel → `POST /api/billing/checkout` → redirect to
  `checkout_url` → Stripe → back to `/?billing=success` → frontend refetches
  `/api/billing/plan` (webhook may lag a second; the plan page polls once
  after 2s).
- Manage/cancel: `POST /api/billing/portal` → redirect. Cancellation takes
  effect at `current_period_end` via `subscription.deleted`.
- Limit hit: any 402 shows an upgrade prompt with current usage from
  `GET /api/billing/plan`.

## Migration / rollout plan

1. Revision `0004_billing` + code ships with env vars unset → self-host mode,
   zero behavior change.
2. Create Stripe products/prices (test mode first), set the four env vars in
   Railway, create the webhook endpoint in the Stripe dashboard pointing at
   `/api/billing/webhook` with the five event types above.
3. Test-mode end-to-end on staging (issue acceptance criterion):
   subscribe → `plan=solo`, limits raised; cancel with `cancel_at_period_end`
   → plan retained until period end → (test clock / short period)
   `subscription.deleted` → `plan=free`, creation blocked at free limits.
4. Flip to live mode keys.

## Testing plan

- **No network in CI.** The `stripe` SDK is mocked at the `stripe` module
  boundary (`tests/conftest.py` fixture `fake_stripe`). Webhook tests build
  the event dict by hand and call the handler function directly, plus one
  signature-verification test using `stripe.WebhookSignature` with a known
  test secret (pure HMAC, offline).
- `tests/test_billing.py`: plan map from price ids; limit counters (month
  boundary, disabled-watch exclusion); 402 bodies on all three enforcement
  points; over-quota downgrade keeps watches but blocks new ones;
  `checkout.session.completed`/`updated`/`deleted`/`payment_failed` handlers
  mutate the `users` row correctly and are idempotent when applied twice;
  self-host mode → routes 404, limits unlimited.
- Local development: `stripe listen --forward-to localhost:8420/api/billing/webhook`
  (stripe CLI) documented in README; `stripe trigger
  customer.subscription.deleted` for manual end-to-end.
- Test-mode E2E before launch is a **manual checklist** (step 3 above), not an
  automated CI test — CI never touches real Stripe.

## Open questions

- Annual pricing (second price id per plan)? Trivial config addition
  (`STRIPE_PRICE_SOLO_ANNUAL`); deferred until someone asks.
- Should `past_due` eventually hard-block (after N days) instead of waiting
  for Stripe's retry schedule? Depends on dunning config we choose in Stripe.
- True shared workspaces ("Org") would obsolete the per-seat simplification —
  needs cross-user sharing from spec 02's future work first.
