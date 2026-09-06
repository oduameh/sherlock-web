# Architecture documentation

Program opened 2026-09-06 (baseline commit `32c061f`). Start with
[`02-target-architecture.md`](02-target-architecture.md): it holds the principles, the target
component model, the investigation state machine, the retrieval and observability models, the
security decisions and the increment plan every change is reviewed against.

## Deliverables map

| # | Deliverable | Where |
|---|---|---|
| 1 | Current architecture (backend) | [`../audit/2026-09-06/architecture-backend.md`](../audit/2026-09-06/architecture-backend.md) — components, 30 routes, SSE protocol, data model, pipeline stages, integrations, config, 18 surprises |
| 1 | Current architecture (frontend) | [`../audit/2026-09-06/architecture-frontend.md`](../audit/2026-09-06/architecture-frontend.md) — module map, backend contract, SSE listeners, sinks, vendors |
| 2 | Target architecture | [`02-target-architecture.md`](02-target-architecture.md) §3 |
| 3 | Component dependency graph | backend audit §1 (Mermaid import graph); target §3 |
| 4 | Data-flow / request paths | backend audit §3 (three sequence diagrams); target §4 (lifecycle) |
| 5 | Search/retrieval architecture | target §5; [`../audit/2026-09-06/retrieval-reliability.md`](../audit/2026-09-06/retrieval-reliability.md) §1–§3 |
| 6 | Source reliability model | target §5; retrieval audit §5 |
| 7 | Failure-handling strategy | target §5 (outcome vocabulary, host state, fallback); retrieval audit §1B |
| 8 | Technical-debt inventory | [`../audit/2026-09-06/tech-debt.md`](../audit/2026-09-06/tech-debt.md) (D1–D22, coverage matrix, dependency table, do-not-touch list) |
| 9 | Security assessment | [`../audit/2026-09-06/security.md`](../audit/2026-09-06/security.md); decisions in target §8 |
| 10 | Testing strategy | target §9 |
| 11 | Test results | [`08-changelog.md`](08-changelog.md) (per increment) |
| 12 | Observability strategy | target §6; [`../audit/2026-09-06/ops-observability.md`](../audit/2026-09-06/ops-observability.md) §11 |
| 13 | Implementation changelog | [`08-changelog.md`](08-changelog.md) |
| 14 | Remaining risks | [`08-changelog.md`](08-changelog.md) |
| 15 | Remaining technical debt | [`08-changelog.md`](08-changelog.md) |
| 16 | Recommended next steps | [`08-changelog.md`](08-changelog.md) |

The audits are read-only snapshots; their `path:line` references are pinned to `32c061f` and
are not updated as code moves. Archify was not available; the maps were produced by code
inspection and an AST import-graph script.
