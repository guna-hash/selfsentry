# Known limitations and evidence history

## Current evidence reconciliation — 31 October 2026

This section supersedes older pending-status statements only where later
evidence is identified. Historical failures and their original scopes remain.

Completed:
- Four-hour synthetic resource measurement: 14,400.407 seconds, 478 samples,
  no unavailable status samples, 149,368 fresh native events and maximum
  absolute receipt skew 0.124 seconds. Owned-container cleanup succeeded;
  final monitor health was good and both delivery queues were empty.
  Evidence: soak-20261030T181831Z.
- Frozen cross-VM model validation: six windows in each of four stages.
  LOF flagged 0/6 routine benign, 6/6 approved uptime, and all twelve
  controlled-deviation windows. The offline IF comparison qualified every
  window at 0.8. LOF is not accepted for live promotion.
  Evidence: frozen-validation-v2.
- The recorded review-process, native deployment-before-status crash and
  controlled stalled-worker cases passed within their documented boundaries.
  Those specific cases are no longer pending.

Open limitations:
- Representative model quality and handling legitimate behavior changes.
- Recurring event-clock/delivery faults: recovery and a successful guarded
  run do not establish a permanent fix.
- Retention policy and production capacity. The four-hour run measured
  storage growth; it did not prove leak absence, safe indefinite retention
  or zero dropped events.
- Permanently stalled-worker completion bounds and untested fault schedules.

Criterion 3 remains partial. No unconditional production-readiness or complete
original-master-prompt claim is made. Live models and response settings are
unchanged. Detailed evidence and scope are in the repository audit report.


## Historical acceptance follow-up — 29 October 2026

The recorded review/deployment crash cases have now been exercised.
Controlled approval-process termination before and after a private adapter
effect passed. A separate native Falco test passed termination after the
deployer returned but before final deployed-status commit, competing review
exclusion, preserved approval, explicit retry without duplicate append, and
restoration with positive/negative native witnesses.

Controlled stalled-worker verification passed CLI timeout/PID retention,
continued ownership, competing-monitor refusal, orderly shutdown after
release and private restart. This does not impose a completion deadline on
a permanently stalled production worker or reproduce a hung external call.

The first four-hour soak attempt did not complete. Its last resource sample
was at 300.862 seconds; the runner detected host-clock discontinuity and
approximately 17,826 seconds of native event/receipt skew. The owned
container was removed. The monitor was unhealthy immediately afterward
and recovered in a subsequent operator status check. Preserve this failed
attempt; it is not four-hour performance acceptance.

Evidence directories under ~/selfsentry-private-evidence:
- native-deployment-crash-20261029T041642Z
- stalled-worker-20261029T043133Z
- soak-20261029T044301Z

Remaining work includes the deferred uninterrupted soak, clock-fault
investigation, broader independent model validation and scoped provenance
review. Licensing remains an owner decision. Historical failures and
limitations remain intact; no model or automatic-response setting changes.


Authoritative ten-criterion review: [acceptance review](repository-audit/acceptance-review-20261028.md).
Earlier dated assessments below are historical evidence, not current blanket blockers.

## Historical acceptance reconciliation — 28 October 2026

This section supersedes older current-status lists within the scopes below.
Historical results, failed attempts and their limitations remain intact.

Completed and recorded:
- Independent fresh Ubuntu installation passed within the scope in
  docs/repository-audit/clean-install-20261028.md, including operator
  browser checks. Broader production acceptance remains unclaimed.
- Genuine PostgreSQL wire-level COMMIT-reply loss passed for the keyed
  audit endpoint, including uncertain-write reporting and retry deduplication.
- Latest operator release passed 1,278 Python tests plus 104 subtests,
  168 frontend tests, lint, scoped types, build and whitespace checks.
- Native disposable isolation/resume and interrupted resume recovery passed.
  The interruption test required explicit retry; continuous containment
  across a crash was not established.
- Controlled gate start/create/remove interruption tests passed within
  their recorded acknowledgement and persistence boundaries.
- Separate native Falco capture/checkpoint/log-replacement checks passed.
- A 30-minute synthetic workload measurement completed, with resource,
  queue, journal-growth and native drop-counter observations recorded.
  Completion was not performance acceptance; adverse findings remain.
- Prospective LOF evaluation used 24 training and six calibration windows.
  With calibration frozen before validation, LOF flagged 0/6 routine,
  2/2 structural-deviation and 2/2 volume-deviation windows. The unchanged
  Isolation Forest comparison qualified 5/6 routine and all four deviation
  windows at 0.8. These are small synthetic results, not production accuracy.
- After restart and bridged-network configuration, an owned fresh-event
  probe passed: 150 events, maximum absolute receipt lag 0.0742 seconds.
  The probe was removed. This is current timestamp evidence, not a
  permanent fix for the recurring clock fault.

Still open:
- Broader independent model validation, including legitimate behavior
  changes; no experimental candidate has replaced the live model.
- Remaining explicitly untested review/deployment fault interleavings
  and stalled-worker shutdown completion bounds.
- Representative capacity, storage-retention and longer-duration behavior.
- Recurring Falco event-clock fault root cause and durable remediation.
- Owner license decision and any outstanding artifact/OS provenance review.
- Final reconciliation against the original master-prompt criteria.

Automatic isolation remains disabled. Proposed file removals, live archival
and demo recording remain deferred; they are not silently marked complete.


## Historical consolidated acceptance status — 26 October 2026

This section supersedes older current-status statements only within the
evidence scopes below. Historical results and failed attempts remain intact.
Source and verification summaries have been integrated into main through
27a97d2; raw operational evidence remains outside Git.

Verified:
- Latest operator release: 1,272 Python tests plus 104 subtests, 168 frontend
  tests, lint, scoped types, production build and whitespace checks passed.
- Default Isolation Forest anomaly-only file-write and process rule loops
  passed human review, native deployment and linked re-fire verification.
  Both temporary rules were subsequently verified unloaded.
- Scoped PostgreSQL, audit replay, monitor replay and full-monitor Docker
  connection recovery passed. HTTP response loss is not PostgreSQL
  COMMIT-acknowledgement loss.
- Separate bounded native Falco captures verified checkpoint reopening and
  private-log replacement; this does not prove lossless engine downtime.
- Controlled gate start/create/remove interruption boundaries preserved
  uncertain intent and required explicit current-state reconciliation.
  Missing creation identity was correctly left unresolved.
- Existing separate-host recovery and post-reboot checks passed; these are
  not clean-installation evidence.
- Operator reported mobile/theme/keyboard and sample-mode checks passed.
  This is bounded operator evidence, not exhaustive browser accessibility.
- pip check passed; npm audit and the declared Python lock audit reported
  no known vulnerabilities at execution time.

Remaining:
- Independent clean supported-Linux installation.
- Current native response/isolation interruption acceptance in an explicitly
  named disposable environment.
- Remaining review/deployment fault interleavings and genuine PostgreSQL
  COMMIT-acknowledgement-loss testing.
- Representative independent benign/attack evaluation and sustained
  resource, queue, disk, dropped-event and shutdown measurements.
- Recurring Falco clock-skew root-cause investigation.
- Owner license decision and any required artifact/OS provenance review.
- Final documentation and ten-criterion reconciliation after remaining work.

Four proposed file removals remain retained; no deletion is required merely
to complete a checklist. Live archival needs a specific approved cutoff.
Demo recording remains deferred. Multi-user deployment and production
certification are not claimed. Automatic isolation remains disabled.
Full master-prompt completion is not yet established.

---


## 25 October source follow-up: UTC and acceptance tools

New psycopg2 application connections force UTC before the first transaction, preserving
other libpq options. This prevents host/database timezone defaults from shifting new naive
timestamps. Existing ambiguous rows are not rewritten. External SQL clients remain responsible
for their own timezone, and this fix does not address Falco/eBPF event-clock recurrence.

The independent-window evaluator now rejects duration mismatches as unscored validation
windows rather than treating their feature counts as comparable. Both anomaly-template API
chains have regression coverage with native reload mocked. The new read-only native-chain
verifier and disposable PostgreSQL fault runner must actually be executed before claiming
their native acceptance. They do not replace representative labeled trials, pending-work
application crash/replay schedules, clean-host installation or human rule approval.

> Current 23 October follow-up: [individual acceptance assessment](repository-audit/report.md).
> PostgreSQL migration/adoption/restore/concurrency, gate/shell, workload and journal export
> have passes recorded in the committed VM note; raw evidence not inspected here. The dated
> audit-patch paragraphs below describe their original local-test boundary. They are superseded
> for those recorded VM checks, without establishing native outage/full-restore acceptance.
> Manual closed-baseline archives and archive-aware export are implemented and tested locally;
> no live cutoff or archival was applied. The explicit reconciliation ledger retains current
> observations and originals; unknown command outcomes and health counts remain unresolved.
> Native retirement source now exists behind an opt-in flag; native Falco acceptance,
> fresh-host proof, current response acceptance, representative detection,
> live UI and sustained workload/fault acceptance remain open. Isolation stays disabled.


> Engineering review: [22 October repository audit](repository-audit/report.md). Historical checked items below apply only to their recorded source/configuration; they are not acceptance of the audit patch.

Updated 15 October 2026. M1–M4 implementation and controlled VM checks are recorded;
M5 full-run measurements and retrospective comparison are delivered. See
[monitor_final_review.md](monitor_final_review.md) and [TODO.md](../TODO.md).
Historical entries below retain the original observations and dates.

## Current audit patch: deployment recovery boundary

Gate start/removal now require durable local intent; completed decisions enqueue atomically
with their CLI outcome. This does not make Docker and SQLite atomic. Creation now records separate intent before Docker; a lost create response or outcome-write
failure can still leave an unstarted orphan with unknown ID. Successful creation IDs persist
before inspection/scanning; those stages can still be interrupted without a completed gate decision. Interrupted outcome writes retain uncertainty;
no automatic action replay exists. Failed/unfinished actions remain local with aggregate monitor
health, not individual backend deployment records. Operator reconciliation/retention UI and native
crash/filesystem acceptance remain unverified; see [operations](monitor_operations.md).

## Current audit patch: response transport recovery

Docker/requests transport failures now retain failed recovery state and attempt best-effort
pause, including when an unpause response is lost or subsequent inspection fails. Re-pause and
verification failures stay explicit. This cannot guarantee containment with an unreachable
daemon or after a hard process termination. Recovery still unpauses before restoring networks.
Two-thread full-ID lock contention is tested locally; native outages, multi-process schedules,
actual response/recovery and hard-kill acceptance remain unverified. Automatic isolation remains
disabled during audit checks.

## Current audit patch: health interpretation

The API now separates heartbeat freshness from aggregate reported health. Required service
reports, reported running state and an API database read contribute to `healthy`; unknown
snapshots are Unavailable with nullable `running`. This tightens the former heartbeat-only
contract and needs coordinated backend/frontend integration. It does not independently prove
fresh per-component probes or end-to-end detection. Completed control-cycle progress is now
checked separately, but a stale marker cannot distinguish legitimate slow work from a stall. Native outage/browser and
continuous-monitoring acceptance remain unverified.

## Current audit patch: database connection limits

The ORM selects the declared psycopg2 driver for plain PostgreSQL URLs and adds five-second
connect/pool-checkout defaults, respecting a positive URL connection-timeout override. A real
client/silent-local-TCP experiment verifies handshake timeout; it is not PostgreSQL integration.
SQL/lock/established-socket waits, full request deadlines, native pool pressure, migrations,
restart and transaction/backup recovery remain unverified or unbounded. No statement timeout
or automatic mutation retry was silently added.

## Current audit patch: database request errors

Request-time OperationalError and pool TimeoutError now produce sanitized 503 responses, with
unknown-outcome guidance for writes. This does not prove rollback, authorize blind retries or
cover startup failures/every database exception. Local tests distinguish pre-insert failure from
injected commit-ack loss and exercise disposable SQLite pool recovery; native PostgreSQL outage
and ambiguous-commit recovery remain unverified. Full SQL/lock/request deadlines remain open.

## Academic claim boundaries — 15 October 2026

SelfSentry is a hybrid container runtime security system that combines Falco rule matching with per-container behavioral anomaly detection, correlates both into incidents, and converts confirmed anomalies into template-generated, backtested, human-approved Falco rules — demonstrating a supervised adaptive detection loop under controlled evaluation.

- The 16 October extension adds template proposals from ready-model anomalies that
  retain a literal syscall witness; aggregate-only anomalies remain unsupported. The
  new path has local regression coverage and still needs live acceptance. The earlier
  study's synthesis required Falco-backed process metadata. The thesis's confirmed-anomaly loop
  is scoped to representable patterns; no ML-only discovery path is claimed.
- Process/parent templates discard file/TTY context and apply across containers.
  Corpus backtesting estimates an event-level match rate for the supported shape,
  not a production false-positive rate or a complete native-engine replay.
- The frozen 200-trial comparison adds three benign detections and no additional
  labeled attack detections over stored Falco flags. Independent live ablations
  remain unrun. The separate 15 October rule-loop study now supports one native
  approved re-fire chain, not additional coverage.
- The opt-in SVM produced anomaly-only incidents on two of four valid benign windows
  (195/196); it remains experimental. See svm_benign_validation_20261013.md.
- Recurring Falco timestamp skew invalidated 19 windows of the earlier SVM batch.
  Restart restored accuracy temporarily; the root cause/permanent fix is unresolved.
  A healthy process heartbeat does not establish correct event timestamps.
- The reviewed 15 October study completed one approved native re-fire chain and
  one explicit rejection. Two other pattern previews failed backtests; actual failed
  submissions and their after-runs were not performed. Three later benign windows
  were clean, but calibration retained IF false-positive incident 199. See
  academic_results_20261015.md; no additional coverage was demonstrated. C2 is deferred.
- Future academic work prioritizes representative baselines, controlled layer
  comparisons and richer supported pattern extraction. Fleet/commercial features
  mentioned in older documents are outside the present thesis, not requirements.


## Historical release gaps — 13 October 2026

- A1/A2 operator VM acceptance passed on 2026-10-12; see TODO.md for report names.
- Automatic-response attempts 185–187 were correctly declined by existing policy.
  The 20-window baseline has only seven distinct vectors; forest boundary saturation
  gives identical low scores for single/burst binary execution. An opt-in One-Class
  SVM candidate is implemented. Controlled automatic isolation/resume passed on the VM
  for incident 190; independent benign/general response validation remains open.
  See anomaly_model_review.md; default Isolation Forest remains unchanged.
- Default shell feature mapping is fixed in the monitor scoring path when Falco
  supplies a known shell process name. Missing process metadata remains uncredited;
  its security alert is still delivered. Standalone baseline capture remains limited
  to Baseline rules. Existing measured results predate this change; no rerun is claimed.
- Observed timelines persist in monitor evidence and render on Alerts. Older
  incidents are not backfilled. The advisory LLM attack_timeline_builder remains
  disconnected; its narrative output is not claimed as persisted.
- Real direct isolation/resume and controlled SVM automatic isolation/resume are
  recorded in reliability_acceptance_20261013.md. Automatic response was demonstrated
  for one configured scenario, not across models/workloads or production conditions.
- Production RBAC, Kubernetes, automatic retraining, retention, soak testing,
  independent live comparison variants and detailed stage timings remain future work.
- A known rule description does not prove an attack; shell access can be benign.
  Shared-token auth is for local demo use. AI is optional and advisory.

## Resolved items (historical evidence)

- /confirm persistence: fixed in backend routes and covered by ORM tests; original
  2026-10-01 gap below is historical.
- Generated-rule re-fire: resolved with rule_matching: all on 2026-10-08;
  see falco_rule_matching.md. Earlier investigation text is historical.
- Direct live isolation: paused and disconnected a real container on 2026-10-01;
  later isolation/resume acceptance is recorded in monitor_final_review.md.
- Default shell counting: source fix and regression tests added 2026-10-12.

## Historical findings

## Phase 4 — shell_spawned_count does not detect default-ruleset shell alerts (found 2026-09-30)

During Sep 30 re-validation, live scoring correctly flagged windows as anomalous
overall, but the `shell_spawned_count` feature stayed 0 even when a real
`docker exec -it <container> sh` session was confirmed firing Falco's default
"Terminal shell in container" rule. Root cause: `feature_extractor.py`'s
shell-detection only increments on `EventType.PROCESS_SPAWN` events whose
`proc_name` is in `SHELL_PROCESS_NAMES` — this path is fed by our custom
`Baseline Process Spawn` rule, not by Falco's default "Terminal shell in
container" rule, so that alert type is never classified as a process-spawn
event for feature-extraction purposes. It still contributes to
`total_event_count`, so its presence is not lost, but it is not specifically
credited as a shell-spawn signal.

Separately, this session's baseline for '12160024642b' still shows the model
scoring both idle and active windows as anomalous at a small sample size (24
windows) — plausibly an artifact of the small, narrow baseline rather than a
detection failure, since real event volume (148-218 events/window) was clearly
present and varied across windows. A larger baseline capture (Phase 10 scope)
is the planned fix; flagging honestly rather than presenting this as fully
resolved.

Planned fix (Phase 10 or as time allows): extend the Falco-alert-to-Event
classification step to map "Terminal shell in container" (and other relevant
default rules) onto EventType.PROCESS_SPAWN with proc_name populated, and
recapture a larger (60+ sample) baseline before final evaluation.

## Phase 5 — confidence tier comment mismatch (found 2026-09-30)
validate_pipeline.py's Scenario 2 comment states confidence should be
"medium" for a strong Falco-only alert, but actual output shows
confidence="low". Either the comment or the threshold needs revisiting;
not yet investigated further, flagged during Sep 30 validation.

## Phase 6 — auto-generated rule deployment mechanism verified, live re-fire not yet reproduced (2026-10-01)

rule_deployer.py was tested end-to-end against real Falco: a candidate
rule (Auto_Generated_ls_from_sh_8, condition: spawned_process and
proc.name="ls" and proc.pname="sh") was written to
falco-rules/auto-generated-rules.yaml, validated as YAML, and Falco was
reloaded — confirmed via journalctl showing
"auto-generated-rules.yaml | schema validation: ok" with no errors.

A subsequent manual trigger (docker exec -it selfsentry-test sh, then
ls) produced the exact matching Baseline Process Spawn event
(proc_name=ls parent_proc_name=sh) in the real Falco log, but the
Auto_Generated_ls_from_sh_8 rule itself was not observed firing in the
same log window. The deployment mechanism (write + validate + reload)
is confirmed working; the condition syntax (likely proc.pname field
naming or a macro/output-format detail) needs further comparison
against Falco's own default rule syntax. Not yet root-caused due to
time constraints — flagged honestly rather than claimed as fully
working. Planned follow-up: compare against a known-working default
Falco rule's exact condition syntax for parent-process matching.

## Phase 8 backend — /confirm endpoint does not persist to confirmed_incidents (found 2026-10-01)

POST /incidents/{id}/confirm returns {"status": "confirmed", ...} but
does not insert a row into confirmed_incidents, and the incidents
table has no status column to reflect confirmation either — the
confirm action appears to not be persisted anywhere in Postgres.
This blocks the natural confirmed_incidents -> generated_rules chain
from being populated by that endpoint alone.

Workaround used for Phase 6 testing (2026-10-01): manually inserted a
confirmed_incidents row (incident_id=8, confirmed_by='guna') and a
generated_rules row (confirmed_incident_id=1, the deployed
Auto_Generated_ls_from_sh_8 rule, backtested_fp_rate=0.0191) directly
via psql, to validate rule_lifecycle_manager.py's TP/FP tracking
end-to-end. rule_performance correctly tracked true_positives=1,
false_positives=1 and flagged the rule for retirement review (50% FP
ratio >= 0.5 threshold).

This is backend-api (Phase 8) scope, not Rule Synthesis Engine (Phase
6) scope — flagging for the joint Phase 10 integration pass.

## Phase 6 — deployed auto-rule compiles and is enabled but has not been observed firing (updated 2026-10-01)

Extensive investigation performed: confirmed via `falco --list` output that
Auto_Generated_ls_from_sh_8 compiles correctly (condition_compiled:
"proc.name = ls and proc.pname = sh", enabled: true), confirmed no rate-limit
config or drop/throttle log entries in falco.yaml or journalctl, confirmed
the rule loads with schema validation: ok on every restart. Despite this,
manual retriggering of the exact matching behavior has not produced a visible
Auto_Generated_ls_from_sh_8 alert in the JSON output log, even though the
underlying Baseline Process Spawn event for the same action fires correctly
in the same log window.

Root cause not identified as of 2026-10-01 despite investigation into: rule
condition syntax (ruled out), file loading (ruled out), rate limiting (ruled
out), restart vs reload (ruled out). Remaining hypotheses for future
investigation: Falco's internal rule-priority/early-exit behavior when
multiple rules share overlapping conditions on the same event; a possible
interaction with the high alert volume from baseline-capture rules.

This does not invalidate the core deployment mechanism, which is fully
verified: write, YAML validation, Falco reload, and successful rule
compilation are all proven working end-to-end on real infrastructure.

## Phase 10 — auto_isolate.py live verification (2026-10-01)

isolate_container() tested against a real running container
(isolate-test-victim, nginx:1.25), not just the not-found failure case.

Before isolation: confirmed real outbound network access (curl to
google.com returned HTTP 301).

After calling isolate_container(): container state changed to "paused",
NetworkSettings.Networks returned {} (fully disconnected), and a direct
docker exec attempt was refused by the Docker daemon itself ("Container
is paused, unpause the container before exec") - independent
confirmation of the pause state, not just our own code's claim.

Forensic state preserved as designed: container was not stopped or
removed, only paused + network-isolated, so its process/filesystem
state remained inspectable throughout.

## Phase 6 — RESOLVED (2026-10-08): non-firing auto-generated rule was shadowed by Falco `rule_matching: first`

The two earlier Phase 6 entries above (2026-10-01) are kept as investigation history.
Root cause: Falco 0.45.0 defaults to `rule_matching: first`, so the catch-all
`Baseline Process Spawn` rule (loaded first) stopped evaluation for every container
process spawn and the auto-generated rules never ran. With `rule_matching: all`, the
same `ls`-from-`sh` action fires `Auto_Generated_ls_from_sh_8` at the same timestamp as
the baseline rule (2026-10-08 07:35:10 UTC). Full evidence and fix: docs/falco_rule_matching.md.
Remaining caveat: `all` may carry a performance cost per Falco's own docs; not yet measured.

## Current audit patch: deployment journal inspection

A read-only local CLI now exposes individual creation/action metadata alongside aggregate
counts: `bin/selfsentry-run --inspect-journal`. It omits private decision bodies and performs
no Docker/backend actions or state transitions. This helps collect reconciliation evidence;
it does not resolve uncertain outcomes, provide a retention/export policy or replace native
crash acceptance. Multi-page reads are separate snapshots, and existing SQLite WAL sidecars
may be used. See [deployment operations](deployment_gate.md#read-only-journal-inspection).

## Current audit patch: audit delivery contract

Malformed or contradictory success replies remain queued; HTTP 401/403/429 can recover after
operator intervention rather than being treated as permanent payload rejections. This can grow
the backlog during prolonged failure; retention and overall request deadlines are not solved.
The current reply lacks an event-key binding, backend identity comparison excludes timestamps, and the
historical spool and direct API events can still be keyless. Disposable SQLite/route tests cover controlled lost
responses and deterministic connection closure; native PostgreSQL/network/power-loss recovery
remains NOT VERIFIED.

## Current audit patch: corrupt audit record retention

Legacy audit reads no longer create duplicate dead letters. Structural corruption is explicit,
with unknown depth/degraded spool telemetry while ingestion/status updates continue. SQLite
batch validation rejects malformed or key-mismatched entries before sending that batch. Both
paths retain evidence and block affected replay until reviewed repair; later control delivery
stages can be delayed. This is not automatic quarantine/recovery, full schema validation or
storage-failure recovery. Whole-file legacy reads, retention and consistent multi-process repair
remain unresolved. See [audit operations](monitor_operations.md#corrupt-audit-records).

## Current audit patch: pending audit key conflicts

Changed data under a pending durable key is now refused explicitly, preserving the original
row. Automatic timestamp drift is ignored only when the retry omits the event time; an explicit
changed time conflicts. The check is atomic in local SQLite. Local comparison does not cover
deleted rows or the legacy JSONL client; the backend now checks keyed content as described below. Caller investigation
is required after a conflict, and native process/crash/commit-uncertainty validation remains open.

## Current audit patch: backend audit replay identity

Backend keyed dedup now compares event fields/detail and refuses changed data with 409, covering
key reuse after local outbox deletion. Timestamps remain first-write metadata outside server
identity comparison; keys differing only by a later timestamp still acknowledge the original.
The acknowledgement body is not cryptographically bound to the key/content. Keyless events,
producer key selection, ordered backlog handling after a conflict, retention and native
PostgreSQL race/crash/network validation remain limitations. Existing records are not rewritten.

## Historical acceptance update — 26 October 2026

The following supersedes older current-status wording only. Dated historical results,
failed trials and scope boundaries remain unchanged. Evidence was inspected from supplied
operator terminal output; private database/journal files remain outside the repository.

| Evidence | Current result and boundary |
| --- | --- |
| Release checks | Operator VM: 1,268 Python tests plus 104 subtests, 168 frontend tests in 34 files, lint, scoped types over 99 files, production build and whitespace check passed. Evidence directory: `state/evaluation/final-checks-20261026T064610Z`. Chart bundle warning remains non-blocking. |
| Audit durability | Seven disposable PostgreSQL/API checks passed: producer/backend SIGKILL, pending replay, unreachable backend, lost HTTP response after commit, database stop/start and retained changed-content conflict. HTTP acknowledgement loss is not PostgreSQL COMMIT acknowledgement loss. |
| Monitor replay | Five additional checks passed with real separate monitor/API processes and disposable PostgreSQL: pending incident survives SIGKILL during outage, exact-once recovery with original timeline, checkpoint reopening, private-log inode replacement and partial-line completion. Telemetry was explicitly synthetic; native Falco lifecycle was not exercised. |
| Test cleanup | Owned API/monitor stopped and owned database container removed; live monitor healthy with incident outbox zero afterward. Disposable final status had an outbox depth of one, so this run does not establish every disposable workflow drained before shutdown. |
| Rule loops | Default Isolation Forest anomaly-only sources 220 and 224 produced reviewed rules 24 and 25 and linked native re-fire incidents 223 and 226. File-write and process/parent verifier results passed. Each backtest had 36 usable matching-type benign events, zero false positives; no representative accuracy claim. |
| Native cleanup | Rules 24 and 25 retired with `native_rule_unloaded=true`; temporary reload socket override removed, environment settings restored, test container stopped. Earlier blocked retirement attempts were retained. |
| Separate host recovery | Existing separate VM restored and verified database tables/sequences, state/checkpoint/model readback and live ingestion; post-reboot health/UTC and operator browser checks recorded. This is not clean installation proof. |
| Idle health | Authenticated database readiness probe fixes backend-unknown health on an idle monitor. Its 17 targeted regressions and the current full release passed. |

Private replay evidence directory: `~/selfsentry-private-evidence/monitor-replay-20261026T064051Z`.
The terminal report is inspected evidence, not an independent execution on the operator VM.
No credentials, original logs, baselines or database exports are included here.

Open boundaries remain: genuine PostgreSQL COMMIT acknowledgement loss; native Falco engine
lifecycle and live rotation; Docker unavailability and remaining interrupted response/gate
operations; clean host provisioning; representative accuracy and sustained performance;
recurring clock-skew root cause. Original historical rows and rejected/invalid trials are
unchanged. Isolation remains disabled for ordinary operation.
