# SelfSentry continuous monitor implementation report

## Final reviewed status — 12 October 2026 IST

This section supersedes the original pending statements retained below as history.
Source reviewed: the uploaded final-review archive at HEAD 45c4dfa with uncommitted
changes; 153 manifest hashes matched. The final polish patch must be applied and its
checks rerun before recording a final release commit. No repository push is claimed.

| Milestone | Delivered and verified |
|---|---|
| M1 | Audit table/API, continuous checkpointed Falco ingestion, Docker discovery and unapproved-start auditing; authenticated writes, bypass and gate registration exercised |
| M2 | Per-container learning/readiness, anomaly scoring and explicit unavailable evidence; ready-model workload trials, live no-baseline fallback and five invalid-model regression cases passed |
| M3 | Durable incident creation/deduplication, both-layer auto-confirmation and opt-in isolation; live PostgreSQL recovery, controlled isolation/resume and protected-container integration passed |
| M4 | Candidate generation/backtesting/human approval, native Falco deployment/re-fire, advisory AI and status/dashboard pages; bounded retry tests and successful post-patch AI request verified |
| M5 | Operating guide, 406-test Python suite, dashboard build and measured 200-trial full run plus retrospective layer comparison delivered; measurement boundaries stated explicitly |

Measured frozen configuration: 100/100 attack trials produced incidents; 13/100
benign trials produced incidents; 5/100 attacks and 0/100 benign trials were
auto-confirmed; 0/200 trials had extra incident rows for their trial key.
Retrospective Falco flags were 100 attacks/10 benign, qualifying ML 7 attacks/3
benign. The union matches all 200 full-pipeline outcomes; quiet windows were not
ML-scored. This dataset does not demonstrate added attack coverage beyond Falco.
Attack-start to database-row timestamp: median 68.154 s, p95 68.588 s (n=100).
See monitor_measured_results_20261011.md for scenario counts and timing semantics.

Additional acceptance evidence:
- Incident 178: real Falco security alert in a new learning container, explicit ML
  unavailable, no agreement/auto-confirm/isolation; container removed.
- Incident 179: queued during a PostgreSQL outage and delivered exactly once after
  recovery; monitor PID unchanged, database active, container removed.
- Protection by name, short ID and full ID: real Docker identity/state with synthetic
  qualifying evidence and a fake backend; no isolation callback, no pause/network
  change; container removed. This is not a separate end-to-end attack trial.
- Invalid/degenerate model, invalid score and review-required paths: five automated
  cases passed. Existing deployed baselines were not corrupted to manufacture a test.
- Incident 177: ready AI explanation after HTTP 200; no isolation because disabled.
  Live 429-to-success recovery was not observed. Retry/cooldown/restart limits passed
  automated tests; the earlier frozen run had 50 HTTP 200 and 63 HTTP 429 responses.

The final polish makes AI ready/unavailable/pending_retry states visible in the
Alerts page, preserves severity when AI is absent, restores /alerts as an alias,
permits both local dashboard origins, clarifies advisory language and cleans lint.
It does not alter the frozen baseline, detection thresholds or recorded trial labels.

Release closeout: apply the polish patch, rerun Python tests/lint and dashboard
checks, restart services, then review and commit the intended source/docs. Baselines,
raw telemetry, state databases and local backups must remain outside the source commit.
No pending rule should be approved solely to make the queue empty.

Unmeasured / outside the completed controlled comparison: independent live
falco_only/hybrid/response runs; raw Falco receipt, ML-processing, correlation,
verified commit, containment and learning latencies; exhaustive daemon/disk faults,
replacement-log rotation under load, long-duration production soak and generalization
to production workloads. Keep these limitations rather than filling absent numbers.
The original four-live-variant design has not been executed; retrospective comparison
is the alternative delivered. Automatic isolation remains off for normal operation.


## Original implementation / evaluation snapshot (historical)

Inspected and extended https://github.com/guna-hash/selfsentry.git at commit d6ca5aa (M1).
Changes are supplied as a patch against that commit. They have not been pushed to GitHub or
installed on your VM. Existing project implementations are reused; no project rebuild.

## Outcome and status

| Milestone | Result |
|---|---|
| M1 | Existing code verified; improve registration history/grace and malformed/disk-failure handling |
| M2 | Implemented and tested offline: baseline lifecycle, learning, model readiness and explicit evidence |
| M3 | Implemented and tested offline: durable incidents, Option B and policy-controlled response |
| M4 | Implemented and tested offline: candidates, advisory AI, status API and dashboard |
| M5 | Tests, operating docs and evaluation aggregator delivered; live measurements still pending |

The project is **not yet declared fully complete**. Native Docker/Falco/PostgreSQL validation,
representative baseline quality and the measured comparison remain required on your test VM.

## Existing architecture and integration

Trivy and the policy checker remain behind the existing deployment gate. Its registration
records remain the trust source. The continuous service consumes existing normalized Falco
alerts, retaining output_fields for the existing baseline parser. Docker events feed the
existing watcher; an exact-ID registration endpoint removes the old 500-record lookup limit.

A local SQLite journal accepts telemetry before the Falco offset advances. Windows are closed
by event timestamp plus configured lateness. Existing extract_features, BaselineStore and
AnomalyModel handle behavioral data. Baselines remain separated by the current 12-character
container-ID contract; full and short representations normalize consistently. No image/name
profile transfer is introduced. Replacement IDs get fresh lifecycle state.

Existing compute_risk_score supplies the risk calculation, and route_incident supplies the
confidence adjustment. Only qualifying ready-model anomaly evidence is correlated. Incidents
carry explicit used/learning/unavailable/failed/late availability and all Falco alerts for the
window. Missing ML is never represented as a normal score or cross-layer agreement.

The backend persists the existing Incident row and additive MonitorIncident metadata in one
transaction, keyed uniquely by event_key. The durable local outbox retries transient backend
failures. Repeated delivery returns the same incident. One incident is grouped per container /
fixed window; late alerts are retained separately, and adjacent windows are not merged.

Option B checks existing effective score, same identity/window, qualifying Falco evidence,
ready ML and qualifying anomaly evidence. Initial threshold is 90, configurable. Confirmation
persists in the existing confirmed_incidents table with selfsentry-auto and timestamp; the
monitor records policy/evidence in workflow and audit. Human confirmation is preserved.

Isolation is independently configurable and defaults off. Eligible actions resolve a full
Docker ID, check protected exact names/IDs, container status and evidence age, then reuse the
existing pause/network-disconnect response. Attempt state is committed before Docker changes.
Success now requires verification; incomplete disconnection/pause is a failure. Interrupted
attempts become unknown_after_restart and require review instead of automatic destructive replay.

Eligible auto-confirmed incidents use the existing pattern extractor, literal Jinja2 generator,
backtester and rule queue. A configured independently verified benign log is required. Empty
or failing backtests cannot produce deployable candidates. The monitor never approves/deploys
rules. Human approval and rejection/deployment results are audited; source, YAML and backtest
results are retained. Structured process fields are preserved and unsafe literals rejected.

The existing summarizer now initializes the provider lazily, receives recorded evidence and
runs in a bounded background worker. Missing keys/provider errors are advisory and do not
prevent detection/response. Existing dashboard pages are retained, with monitor/evidence /
workflow displays added. All backend writes require a shared bearer token; existing gate and
monitor clients send it, and the dashboard stores it only for the browser session.

## Configuration, operation and tests

See monitor_operations.md for every environment variable/default, token setup, baseline
inspection, exact backend/monitor/dashboard start/stop commands, health/log commands, reset
procedure and test commands. See monitor_evaluation.md for controlled trials and measurement
aggregation. No secret or .env is included in this update.

## Executed validation

- Unchanged repository baseline: **282 passed in 7.21s**.
- Final extended Python suite: **353 passed in 8.64s** (pytest tests/ -q).
- Flake8 of monitor and modified backend/behavior/response/rule/AI/gate/evaluation Python
  modules: passed with max line length 100.
- Dashboard production build: passed, 41 modules transformed.
- Tests use isolated SQLite, real feature/model components, mock Docker/AI/HTTP side effects
  and real in-process HTTP/ORM integration. No destructive action touched a real container.
- Earlier development failures (a serialization bug, malformed mock handling and a test clock
  helper typo) were fixed; no failure remains in the final executed suite.

These are software checks, not measured attack-detection percentages or live response latencies.
PostgreSQL concurrency/permissions and the production host were not exercised. Existing test
conventions were preserved; existing tests pass without live external services.

## Additional pending work beyond simply marking M2-M5 done

1. Verify the actual baseline location and feature window size, recapture representative
   workload data where needed, and measure benign false positives. A ready model alone is
   not proof of detection quality; the old small baseline cannot be assumed suitable.
2. Apply the patch, configure the shared token on every writer, restart the backend so it
   creates monitor_incidents, and confirm your database role has required table permissions.
3. Run live Falco/Docker/incident flow and gate-bypass scenarios. Test outages, restarts and
   recovery with the new durable pipeline.
4. Validate response only on disposable containers, including protection/exclusion settings,
   partial failures and manual resume. Then choose whether to enable automatic isolation.
5. Supply an independently reviewed benign corpus, validate native Falco compilation/load,
   human approval/rejection and actual generated-rule re-fire for the integrated flow.
6. Collect real four-variant evaluation numbers. The aggregator leaves absent data null; no
   new live detection/false-positive/latency/confirmation-accuracy result is claimed.

Operational limits: fixed-window delay/splitting; log replacement rotation may lose unread old
lines; transient Docker starts during an outage may be missed; Docker cursor is not persisted
across process restarts; local journal history has no automatic retention; shared token is not
production RBAC; Docker socket access is root-equivalent; no Kubernetes, broker, cross-container
profiles or automatic retraining. The monitor alerts on plain docker run rather than preventing
it. Native Falco semantic validation remains a test-host step.

## Exact created files

- `backend-api/routes/monitor.py`
- `docs/monitor_completion_report.md`
- `docs/monitor_evaluation.md`
- `docs/monitor_operations.md`
- `evaluation/measure_results.py`
- `frontend-dashboard/src/pages/Monitor.jsx`
- `monitor-service/automation_policy.py`
- `monitor-service/backend_auth.py`
- `monitor-service/behavior_pipeline.py`
- `monitor-service/incident_pipeline.py`
- `tests/test_backend_monitor.py`
- `tests/test_behavior_pipeline.py`
- `tests/test_incident_pipeline.py`
- `tests/test_monitor_evaluation.py`
- `tests/test_monitor_reliability.py`

## Exact modified files

- `.env.example`
- `CHANGELOG.md`
- `README.md`
- `ROADMAP.md`
- `TODO.md`
- `ai-analysis/root_cause_summarizer.py`
- `backend-api/main.py`
- `backend-api/models/db_models.py`
- `backend-api/routes/deployments.py`
- `backend-api/routes/incidents.py`
- `backend-api/routes/rules.py`
- `behavioral-engine/baseline_builder.py`
- `correlation-engine/risk_scorer.py`
- `database/schema.sql`
- `deployment-gate/deployment_gate.py`
- `docs/known_limitations.md`
- `docs/monitor_service.md`
- `docs/monitor_spec_checklist.md`
- `frontend-dashboard/src/App.jsx`
- `frontend-dashboard/src/api.js`
- `frontend-dashboard/src/pages/Alerts.jsx`
- `frontend-dashboard/src/pages/AuditLog.jsx`
- `frontend-dashboard/src/pages/Containers.jsx`
- `frontend-dashboard/src/pages/Deployments.jsx`
- `frontend-dashboard/src/pages/RuleReviewQueue.jsx`
- `monitor-service/audit_client.py`
- `monitor-service/container_watcher.py`
- `monitor-service/event_classifier.py`
- `monitor-service/monitor_config.py`
- `monitor-service/monitor_service.py`
- `requirements.txt`
- `response-engine/auto_isolate.py`
- `rule-synthesis-engine/confirmation_manager.py`
- `rule-synthesis-engine/pattern_extractor.py`
- `rule-synthesis-engine/rule_backtester.py`
- `rule-synthesis-engine/rule_template_generator.py`
- `rule-synthesis-engine/submit_candidate.py`
- `runtime-monitor/falco_integration.py`
- `tests/test_backend_deployments.py`
- `tests/test_backend_rules.py`
- `tests/test_container_watcher.py`

## Live validation — 10–11 October 2026

Evidence: evaluation/results/validation-20261011T072902Z/

Verified on the Ubuntu VM:
- 353 tests passed; dashboard production build passed.
- Missing write token rejected with HTTP 401; authenticated invalid body reached validation.
- Existing 60-second baseline reached MODEL_READY.
- Live Falco events produced incidents with anomaly and correlation evidence.
- Restart preserved incident 33 without duplication; backend retries drained queues.
- Direct Docker start produced UNAPPROVED_CONTAINER_START.
- Gate override registration produced no unapproved-start warning.
- AI summaries succeeded; incident 39 recorded an unavailable result.
- Incident 39 automatically queued candidate rule 6 for human review.
- Scoped rule 5 passed native Falco validation, human approval, deployment and live matching.
- Incident 40 auto-confirmed and automatically isolated the test container.
- Manual resume restored bridge networking; monitor healthy, zero failed response actions.

Measured limited backtest: 0 matches across 40 controlled benign process events.
This is not a representative production false-positive rate.

M5 remains incomplete: representative detection/false-positive rates, latency
measurements, comparison trials and remaining failure/recovery scenarios are pending.
Automatic isolation was returned to off after the controlled test.
