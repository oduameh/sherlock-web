# Implementation changelog, risks, next steps

Maintained per increment (see `02-target-architecture.md` §10). Each entry records what
changed, how it was verified (tests, replay, live run), and the independent review outcome.

## Baseline — 2026-09-06, `32c061f`
* Tests: 351 passed, 1 skipped, ~1.3 s, no network.
* Known stuck investigations: 7 rows `running`, 4 orphan `pending`.
* Six audits produced (`docs/audit/2026-09-06/`); eleven defects verified directly (target §1.3).

## Increments

### D (part 1) — ops hygiene · PR #47 · 2026-09-06
`run.sh` reinstalls when `requirements.txt` changes (hash stamp) instead of only when three
core imports are missing; CI's pip cache key now tracks `requirements*.txt`, installs the
stealth extra the parser tests need, runs `node --check`, and reports `pip-audit`
(advisory until the lockfile lands); `pytest.ini` silences two third-party deprecation
warnings; `.gitignore` covers `.superdesign/`, `.ruff_cache/`.
Verification: suite green (351), `bash -n`, YAML parse. Review: not separately reviewed
(config-only); covered by the later program review.

### F — frontend dead code and URL hygiene · PR #48 · 2026-09-06
The Cytoscape identity-graph workbench had no caller. Removed ~987 lines of JS, the
`#graphPanel` subtree, three CSS blocks and seven vendor files (~897 KB, including a
bundle that was never loaded). `esc()` escapes quotes; every remote or subject-controlled
`href` / `img.src` / `background-image` goes through an http(s) allow-list on the client
and in the HTML report and dossier (non-http(s) values render as text). Vendor provenance
recorded with sha256.
Verification: `node --check`; all 113 element ids resolve; zero references to removed
ids/classes; suite green (+8 tests, mutation-checked); headless-Chromium pixel diff vs
baseline across 8 views: 0 differing pixels on the case graph, footprint, watchlist and
God's Eye; zero console/page errors; no horizontal overflow.
Review: approved with three should-fixes (report `<img src>` gating, DROP-portal link,
brokers-section test) — all landed before merge.

### C — policy completeness · PR #49 + hotfix #50 · 2026-09-06
The deny list was enforced only by our own fetchers. Now: plan-time filtering of all six
engine site sets (policy first, then circuits) with one additive `skipped_policy` event
and honest per-site reasons; a distinct WhatsMyName `policy` status that is neither
observed nor reported as an error; holehe/ignorant skip modules targeting denied hosts;
avatar downloads refuse denied URLs; images above 4 M pixels are rejected before decode;
the access policy is checked inside `safeweb._guard` on every request and redirect hop.
Deny list corrected from robots.txt observed 2026-09-06: `cdninstagram.com`, `fbcdn.net`,
`pinimg.com`, `redditmedia.com` added (`Disallow: /`); `twimg.com` removed
(`pbs.twimg.com` allows all). Written rule: a scraper mirror is not an alternative source
for a denied platform.
Verification: suite green (404 after #50); the reviewer enumerated every planned set
offline — no denied-host template survives; Sherlock 5, Maigret 9, WMN 8 removed.
Review: approved with two should-fixes, landed. **Process defect**: #49 was merged with
two failing assertions because a multi-step script continued past an aborted patch step;
fixed in #50 and prevented by `scripts/gate.sh` (#51).

### Gate script · PR #51 · 2026-09-06
`./scripts/gate.sh` runs ruff, `node --check` and the suite, failing fast; merges are
gated on it.

## Remaining risks
_(updated at program close)_

## Remaining technical debt
_(updated at program close)_

## Recommended next steps
_(updated at program close)_
