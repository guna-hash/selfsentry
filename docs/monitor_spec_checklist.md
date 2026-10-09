# Continuous Monitor Service - completion checklist

Reference: the "Continuous Monitor Service" specification (pasted 2026-10-09). This file is the
completion check. An item is only marked done with evidence (a passing test, or real command
output recorded in docs/). Update it at the end of every milestone.

Legend: DONE = built and validated | PARTIAL = building blocks exist, not wired or incomplete |
TODO = not started

Status as of 2026-10-09 (210 tests passing, HEAD fab1799).

## Final acceptance criteria (spec section 18)

| # | Criterion | Status | What exists / what is missing |
|---|---|---|---|
| 1 | Monitor runs continuously | TODO | Only one-shot scripts (validate_live.py, validate_pipeline.py) |
| 2 | Ingests Falco events for relevant containers | PARTIAL | `runtime-monitor/falco_integration.py` can read/stream the log; no service, no checkpoint |
| 3 | Discovers containers started outside the Deployment Gate | TODO | The gate records approved container ids in `deployments`, which is the registration source |
| 4 | New containers enter learning mode | TODO | Baselines exist only for selfsentry-test (and an old test-container) |
| 5 | Falco detection continues during learning | TODO | Follows from 1 and 4 |
| 6 | Anomaly detection only when the model is ready | PARTIAL | `AnomalyModel` trains/scores manually (validate_live.py); no readiness states |
| 7 | Correlation combines valid evidence correctly | PARTIAL | `risk_scorer.compute_risk_score` works and is tested; it has no "anomaly unavailable" representation |
| 8 | Incidents created and persisted automatically | PARTIAL | `POST /incidents/` works; nothing creates incidents automatically; no deduplication |
| 9 | Eligible incidents auto-confirmed | TODO | `POST /incidents/{id}/confirm` exists; no policy decides |
| 10 | Auto-confirmation auditable as selfsentry-auto | TODO | `confirmed_by` field is available to carry the source |
| 11 | Qualifying incidents trigger policy-controlled isolation | PARTIAL | `event_router` tiers + `auto_isolate` (live-verified); not fed by live incidents; thresholds not configurable; no protected list |
| 12 | Isolation failures recorded accurately | PARTIAL | Router returns `isolation_failed: ...`; not persisted anywhere |
| 13 | Eligible incidents produce candidate rules | PARTIAL | `submit_candidate.py` (live-verified, manual trigger) |
| 14 | Every generated rule requires human approval | DONE | Approve route is the only deploy path; route tests + live dashboard run (rule 3) |
| 15 | Duplicate events do not repeat destructive actions | PARTIAL | `isolate_container` is idempotent; no event-level dedup |
| 16 | Temporary failures do not terminate the monitor | TODO | |
| 17 | AI failures do not block core processing | PARTIAL | Incident creation calls the summarizer inline; failure behaviour must be verified/tested |
| 18 | Unit tests cover the major decision paths | PARTIAL | 210 tests; none for monitor logic yet |
| 19 | Existing tests keep passing | DONE | 210 passed |
| 20 | Evaluation plan with measurable results and limitations | TODO | Real numbers needed: latency, FP rate (backtest 0.84-2.29% already measured), learning time |

## Requirement areas (spec sections 4-14)

| Section | Requirement | Status |
|---|---|---|
| 4 | Falco ingestion: normalization, malformed-event handling, dedup, restart recovery | PARTIAL (parser + stream exist) |
| 5 | Gate bypass: Docker event stream, UNAPPROVED_CONTAINER_START audit event, registration check by container id (not name), restart/replacement handling | TODO |
| 6 | Per-container baseline states NO_BASELINE / LEARNING / BASELINE_READY / MODEL_TRAINING / MODEL_READY / MODEL_UNAVAILABLE, configurable learning, Falco stays active during learning, never fabricate anomaly scores | TODO |
| 7 | Correlation with explicit evidence (Falco present, anomaly unavailable, no cross-layer agreement claimed), configurable window, no double counting | PARTIAL |
| 8 | Automatic incident creation with grouping/dedup and richer fields (baseline/model status, confirmation, response status) | TODO |
| 9 | Auto-confirm: score >= AUTO_CONFIRM_THRESHOLD (90), BOTH layers qualify, same container/window, not already processed, can be disabled independently | TODO |
| 10 | Auto-isolate: AUTO_ISOLATION_ENABLED / THRESHOLD, protected-container list, already-isolated check, per-incident dedup, audited attempts and results, no endless retries | PARTIAL |
| 11 | Rule synthesis from auto-confirmed incidents, duplicate-candidate prevention, validation + backtest, mandatory human approval | PARTIAL |
| 12 | AI explanation from recorded evidence only; failure must not block response | PARTIAL |
| 13 | Service reliability: structured logs, graceful shutdown, bounded retries/backoff, checkpoint so events are not lost, health/status reporting | TODO |
| 14 | Secure defaults: external config validated at startup, no hardcoded secrets, no unauthenticated destructive API, container identity by id, documented privileges | PARTIAL (secrets handling done; API has no authentication yet) |

## Test scenarios required by spec section 15

A ingestion, B container discovery, C baselines, D correlation, E auto-confirmation,
F isolation, G rule synthesis, H reliability: all TODO except the rule-approval paths
(G: human approval, human rejection, deployment without approval, deployment failure,
duplicate candidate) which are covered by tests/test_backend_rules.py.

## Decisions taken

- Auto-confirm follows the spec's Option B. Rule deployment still always needs a human.
- No message broker. Durability uses an on-disk checkpoint of the last processed Falco event;
  trade-off documented when the monitor lands.
- Baselines stay keyed by container id; a replaced container (new id) starts in NO_BASELINE.
- Default response to a gate bypass is detect + alert, not block.
- Protected-container list defaults to empty and is configurable.
- Falco `rule_matching: all` is required (docs/falco_rule_matching.md).

## Not in scope (to be stated in the evaluation)

- Preventing a plain `docker run` (needs a Docker authorization plugin).
- Reusable cross-container profiles and automatic retraining policy beyond a manual retrain.
- Kubernetes.

## Planned milestones

| Milestone | Spec phases | Delivers |
|---|---|---|
| M1 | 1-3 | Audit log table + API, monitor core loop with Falco ingestion and checkpoint, Docker event discovery, UNAPPROVED_CONTAINER_START |
| M2 | 4-5 | Per-container baseline states and learning mode, anomaly + correlation wiring with explicit evidence |
| M3 | 6-8 | Incident creation with dedup, auto-confirm policy, auto-isolation policy, response audit |
| M4 | 9-10 | Candidate rules from auto-confirmed incidents, AI explanation, monitor status API + dashboard page |
| M5 | 11-12 + 16 | Remaining tests, setup/operations doc, evaluation plan and measured results |
