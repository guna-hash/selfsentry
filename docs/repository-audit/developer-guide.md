# SelfSentry developer understanding guide

Current evidence: [acceptance review](acceptance-review-20261028.md),
[fresh-install record](clean-install-20261028.md), and
[manual setup guide](../fresh-ubuntu-install.md). Source-time and historical runner
sections below describe their own tests and prerequisites, not a blanket current
NOT VERIFIED label or authorization to repeat a disruptive native test.

Read this alongside the audit report. This guide explains the implementation; it does
not certify live operation or eliminate the review gaps recorded in the inventory.

## Completion checks added 25 October 2026

These tools do not change the default model, approve generated rules, enable response
automation, rewrite existing timestamps or publish private runtime evidence.

### PostgreSQL timezone and disposable connection faults

The backend uses startup-packet `options` to force UTC, retaining other options and
the connect timeout. This avoids a transaction-local timezone setting being undone
by pool rollback. The first default `now()` written to a naive timestamp must already
be UTC. Unit checks exercise construction and rejection; only native execution tests
actual PostgreSQL behavior.

On a Docker-enabled Linux host, use a new private result file outside the checkout:

```bash
.venv/bin/python evaluation/verify_database_faults.py \
  --output "$HOME/selfsentry-db-faults-$(date -u +%Y%m%dT%H%M%SZ).json"
```

The runner creates its own PostgreSQL 18 container, binds its randomly allocated port
to loopback, and uses generated credentials. It does not use the application's database
URL or stop existing services. Checks cover the non-UTC server default, first timestamp,
termination of an established uncommitted connection, fresh pool checkout, duplicate-key
replay after a committed write, bounded row-lock failure and a restart of only the owned
container. Exact ID and label ownership are verified before restart/removal. A lost create
response remains unknown and is not retried; inspect the retained name if reported.
Results retain partial successful checks and cleanup failures without connection secrets.

The post-commit case in this tracked runner proves uniqueness at a controlled boundary;
it does not simulate lost PostgreSQL wire replies. A separate private acceptance later
withheld an actual COMMIT CommandComplete reply and exercised the production keyed audit
path through 503 uncertainty, duplicate retry and changed-content refusal. That evidence
is recorded in the audit; it does not broaden this runner's own checks. This suite does not accept monitor queue
replay, application process crashes, multi-service failure or automatic containment.

### Anomaly-only process and file-write loop evidence

`tests/test_final_completion.py` exercises both real API routes over disposable SQLite:
anomaly witness, confirmation, candidate backtest, human review and a linked subsequent
incident. Native validation/reload remains mocked. Fixture tests are not live detections.

For each actual native chain, first collect a qualifying default-model anomaly with its
same-container baseline witness. Capture a separate, operator-reviewed benign JSONL corpus.
Use the existing confirmation and review UI to submit/backtest and explicitly approve
the candidate after inspecting its literals. Repeat the harmless operation in the isolated
workload, await the correlation window, and retain the native log and linked incident.
Human approval is a required action, never something an acceptance script fabricates.

Then run the read-only verifier with the actual IDs and paths:

```bash
.venv/bin/python evaluation/verify_rule_loop.py --help
```

Required arguments are `--source-incident`, `--rule`, `--refire-incident`,
`--template spawned_process` or `--template file_write`, `--falco-log`,
`--benign-corpus` and a new private `--output` outside the checkout. The local API
provides the incident and latest 100 rule-history records. Older rules outside this
bounded history require a reviewed export rather than assuming they were found.
The verifier rejects Falco-backed source incidents, non-ready model states, missing
confirmation, wrong-container/out-of-window witnesses, changed template content,
missing human/deploy lifecycle records, a changed approval-time corpus, failed backtest,
pre-deployment re-fire evidence and missing native-log corroboration. A pass establishes
the recorded loop, not malicious intent or additional detection coverage.

### Independent detection measurements

Use `evaluation/evaluate_holdout.py` only with operator-labeled independent validation
windows following frozen training. Labels must not be inferred from Falco matches or
model predictions. Training and validation must use the same window duration. Keep missing,
invalid, overlapping and unscored windows in declared denominators. The default model and
threshold remain unchanged; no evaluation-time tuning is performed. Its fixture tests do
not establish representativeness, recall or false-positive rates on actual workloads.

Fresh installation, real native loop runs, representative labeled data, live UI permutations,
pending-work crash/replay schedules and owner-approved destructive/real-response actions
remain separate evidence requirements. Never mark them passed merely because these tools exist.

## Follow one container

1. `bin/selfsentry-run` invokes `deployment_gate.run_gate`. Docker creates a stopped
   container. `evaluate` checks its inspect data and scans its actual image ID. A policy
   failure or scanner failure blocks startup unless the operator supplies an override.
   The decision is journaled and posted to the backend. This wrapper cannot prevent a
   Docker administrator from bypassing it.
2. Falco observes syscalls and emits rule matches to JSON. The capture rules emit benign
   telemetry as well as the default rules' security matches. `event_classifier.classify_line`
   separates these categories. Falco is the eBPF collector; `ebpf_collector.py` is a facade.
3. `FalcoTailer.read_batch` reads complete lines. `MonitorService._handle_line` sends
   them to `BehaviorPipeline`. Accepted or rejected events are journaled before the
   tailer advances its checkpoint. At-least-once replay is expected, not exactly-once
   delivery across every failure boundary.
4. `BehaviorPipeline.accept` validates Docker IDs and timezone-bearing timestamps and
   assigns a fixed window. `_close_window` derives eight counts, excludes security-alert
   windows from new learning, and uses a ready model if one exists. Late security alerts
   revoke readiness and require review. The pipeline can still deliver Falco-only incidents.
5. `compute_risk_score` correlates same-container events within a time tolerance. It adds
   Falco base risk, a weighted anomaly score and an agreement bonus, capped at 100.
   `route_incident` applies the confidence adjustment. These are explicit policy scores,
   not probabilities that a container is compromised.
6. `IncidentPipeline.tick` delivers durable outbox entries using a stable event key.
   Backend `/incidents/` creates the row and `monitor_incidents` evidence. Replay returns
   that row instead of creating another. Optional AI enrichment runs separately.
7. `automation_policy.eligible` decides confirmation and automatic response eligibility.
   Anomaly-only acceptance can propose a rule but cannot authorize automatic isolation.
   Enabled dual-layer response still requires ready-model, freshness, score and identity
   evidence. `IncidentPipeline` resolves the full Docker ID and checks protection.
8. Before calling Docker, the monitor saves an isolation-attempt phase and audit event.
   `auto_isolate.isolate_container` locks the full ID, saves network membership, disconnects
   networks, pauses and verifies. Interrupted attempts become unknown for human review;
   the monitor does not blindly repeat them after restart. `resume_container` restores
   saved memberships/aliases and verifies recovery, re-pausing on partial failure where possible.
9. Confirmed incidents with supported literal witnesses can enter `submit_candidate`.
   Pattern extraction and Jinja templates constrain the candidate; the benign backtest
   rejects unknown conditions and zero usable events. The backend repeats the test and
   checks duplicate inventory. Human approval remains separate from submission.
10. `/rules/{id}/approve` records review and calls `rule_deployer`. It writes only the
    generated-rules file and reloads Falco. A later native rule match is linked to the
    deployed rule. A match is not automatically a true positive. The audit explains the
    per-rule review lock held across commits and deployment. Competing review requests
    return 409. Scoped native PostgreSQL locking across commits and exceptions is recorded;
    broader deployment/crash interleavings remain open. Database-only deprecation does not
    unload Falco rules. A separate opt-in, human-reviewed native retirement/rollback workflow
    exists and has recorded bounded native acceptance; it remains disabled in ordinary use.

## State ownership

| State | Owner and maintenance rule |
| --- | --- |
| PostgreSQL incident/audit/rule tables | Backend ORM; back up before schema work; versioned baseline in `database/migrations`; existing adoption requires comparison |
| `state/monitor/pipeline.sqlite` | Ingestion/window thread and separate control connection, WAL mode; preserve on restart |
| `state/monitor/audit.sqlite` | Durable audit delivery, short-lived SQLite connections |
| `state/deployments.sqlite` | Gate decision replay; backend audit keys deduplicate |
| `state/rule-guard` | Persistent duplicate history and deployment receipts; do not clear to retry |
| Baseline JSON | One container's validated features; never transfer to another container by name/image |
| Isolation records | Full-ID network restoration evidence and per-container locks; retain during failed recovery |
| `status.json` | Atomic status snapshot; freshness alone does not prove component health |

The CLI sets a private umask; direct invocations must have appropriate directory permissions.
Do not delete journals, active records or old models to make a dashboard counter look correct.
The current journals have no automated retention policy; disk exhaustion is a real failure mode.

`MonitorService` limits Docker forwarding per cycle using `MONITOR_MAX_BATCH_LINES` so a burst
does not drain indefinitely before the next Falco read. The remaining FIFO events stay in
memory. `ControlWorker` consumes reconciliation requests before work and retains requests
arriving during that work. It checks for shutdown between tasks and closes its SQLite
connection on initialization and cleanup failures. These properties have ordering tests in
`tests/test_control_worker.py` and `tests/test_monitor_service.py`. Neither event queue is
bounded or durable. Shutdown cancels the SDK Docker event stream, waits for event/control
threads and running model/AI executor work, and keeps the instance lock until cleanup returns.
`tests/test_monitor_shutdown.py` uses real threads and flock to check the lock boundary;
`tests/test_docker_events.py` exercises SDK cancellation over a local socket pair. These are
not native Docker transport or VM shutdown tests. A blocked dependency can keep shutdown
waiting indefinitely. The lifecycle CLI reports that condition instead of force-killing it.

Outcome counters use an existing generated-rule parent-row lock before checking for a
performance row. They no longer assume a unique index exists. Duplicate historical rows
fail explicitly instead of being silently merged. psycopg2 connections close on success
and failure. SQLite SQL-adapter tests validate the write behavior, not PostgreSQL locking.

Invalid/unreadable isolation records are preserved and block both response actions.
Inventory reports `record_unavailable`/`isolated=null`; the UI must not treat that as verified
containment or permission to isolate again. Restore only verified original network context.
File/directory sync ordering is tested, but host power-loss durability remains unverified.

## Safe changes

- Start with an audit branch and `pytest tests/ -q`. Keep real automatic isolation disabled.
- Check every caller before changing a route, JSON field, Docker identity format or state path.
- Preserve event-key and feature-order compatibility across restarts. Changing either can
  invalidate replay guarantees or model interpretation.
- Model changes need frozen benign training data and separate labeled validation data.
  A sigmoid anomaly score is not calibrated confidence. Do not select SVM because one demo
  happens to score better or treat a native rule re-fire as novel coverage.
- Template changes affect the generator, backtester, duplicate parser, Falco definitions,
  backend validation and UI review. Passing the Python matcher does not prove Falco accepts
  a rule; validate natively on the isolated lab host.
- Database changes require an explicit migration and duplicate-data inspection. ORM
  `create_all` only creates missing tables. Do not run the historical SQL draft as a migration.
- UI changes must retain sample/live separation, unavailable states, busy-action protection,
  and explicit reviewer/confirmation dialogs. The backend must remain authoritative.

## Debugging

Read `state/logs` and `/monitor/status` component details first. An unavailable model and an
unavailable Falco stream have different consequences. Check the outbox stage and retry time
before treating delayed advisory work as a lost incident. Check the full Docker ID and saved
network IDs before recovery. A failed reload leaves a rule approved for retry; preserve the
duplicate registry and inspect both database state and generated file contents.

The dashboard uses HTTP polling, not WebSockets: global monitor status and collection
views refresh on three-second schedules; incident/overview/rule views use fifteen seconds.
The incident view's inventory context follows its fifteen-second refresh. See the
[transport contract](../interfaces.md#event-transport-and-dashboard-refresh).
These schedules are UI behavior, not monitoring cadence or end-to-end latency guarantees.
Pausing page refresh never pauses Falco or the monitor. Sample mode uses frozen fixtures and blocks writes locally; it proves interface
behavior only. AI summaries are advisory; observed timelines and deterministic guidance remain
the evidence source.

## Questions to prepare for a technical interview or viva

1. What does SelfSentry add around Falco, and what added detection coverage has actually
   been measured? Explain supervised adaptation without claiming an independent eBPF engine.
2. Why use a per-container baseline? What happens for a new, replaced, idle or paused container?
3. Why is the anomaly score not a probability? How do training contamination and fixed windows
   affect false positives and latency?
4. How do checkpoints, local journals and backend unique keys interact after a lost HTTP response?
   Which rotation, disk and restart boundaries can still lose evidence?
5. Which checks are required before automatic isolation? Why can a high routing score alone
   never authorize the diagnostic dispatcher to touch Docker?
6. What is saved before containment? What happens after only one network disconnect succeeds,
   or a process crashes after Docker completes but before the outcome is recorded?
7. What does a benign-only backtest establish? Why are zero events and unsupported conditions blocked?
8. Why is human approval separate from confirmation and candidate creation? Which database/file
   concurrency and crash boundaries are still unresolved?
9. How do you distinguish a native re-fire from a labeled true positive or added attack coverage?
10. What would be required before Internet-facing deployment: authentication, authorization,
    migrations, supervision, secrets handling, recovery, retention and representative load tests?

## Latest safety and resource contracts

The runtime monitor owns its safety settings. The API must never replace them with the
API process's environment: those processes can disagree. Unknown runtime configuration
blocks evaluation workloads. `evaluation/safety.py` centralizes that precondition; it
does not authorize real isolation or protect against concurrent operator reconfiguration.

Docker queues have entry-count bounds, and the main service retains an event when the
control queue is full. Test FIFO and Falco progress together when changing this code.
Training capacity is checked before submitting a model job; persisted baselines provide
retryable deferred work. Neither control bounds total retained database history or model
memory. SQLite context managers commit/rollback but do not close connections: use explicit
closing for short-lived read-only evaluation and rule-registry handles.

## Scan trust boundary and legacy diagnostics

The public scanner validates artifact identity and report structure before normalization.
A malformed service result must never become an empty clean report. Test a malformed
report and a valid empty artifact separately; keep immutable metadata matching in place.
Native scanner configuration and coverage still require operator acceptance.

`collect_baseline.py` and `validate_live.py` are standalone manual tools, not the monitor.
Use the exact container ID present in Falco records and matching baseline window lengths.
They retry partial lines and retain future events but lack production rotation/checkpoint
recovery and clock-discontinuity handling. Recollect rather than silently rewrite old vectors.

## Schema and type maintenance

`database/migrations/versions/20261022_0001_initial.py` freezes the initial SQL schema.
Do not import live ORM metadata into a revision: later model edits must not rewrite history.
The baseline refuses populated databases; adoption is explicit after backup and comparison.
`scripts/verify_schema.py` compares schema metadata under a read-only transaction; a mismatch
is a report, never an automatic repair. SQLite upgrade/repeat/refusal/downgrade tests run in
disposable files; PostgreSQL SQL compilation is not native migration acceptance.

`scripts/verify_types.py` maps hyphenated service directories to flat Python import roots.
It checks application and script sources, including backend routes/models and migrations.
Test code, manual root diagnostics and dependency implementations are outside its scope.
Missing third-party stubs are allowed and imported libraries are not recursively checked.
Untyped function bodies are checked by default, though dynamically typed values still limit
what mypy can prove. A pass is static coverage, not complete typing or proof of correctness.

## Checkpoint maintenance

`falco_ingest.Batch` carries a discard-boundary flag as well as offset/hash evidence.
The tailer must commit all of them together and roll back its in-memory state on a
persistence failure. The service reports a failed commit as unavailable without starving
Docker/window/outbox work. Test corruption, disk/sync faults, restart in an oversized line
and rotation during open together when modifying this boundary. Existing malformed
checkpoints require reviewed repair, not a silent jump to the end of the log.

## Incident mutation discipline

Every workflow JSON writer must lock the same parent `Incident` before loading monitor
metadata. Refresh cached rows before merging, and keep the lock until commit. Test both
orders: worker update after a committed dismissal, and dismissal after a committed worker
update. The regression uses real SQLite stale identity maps; the separate SQL compilation
asserts PostgreSQL `FOR UPDATE` ordering, not native concurrent transactions.

Request validators keep nonempty scan summaries complete and typed; `{}` means no scan.
Do not coerce absent counts to zeros. Confirmation actor normalization precedes automatic
policy dispatch, but labels remain unverified identities. A dismissal's metadata/timestamp
and audit event commit together. None of these database locks synchronizes an external
Docker action already in flight; response cancellation needs a separate reviewed design.

## Gate journal and replay identity

`deployment_outbox.py` owns local SQLite delivery state. Pending records remain immutable
under an event key. Permanent 400/409/422 responses or corrupt JSON produce a retained rejection
marker/copy; the original row remains, and later active records can be sent. Transient failures
and ambiguous 201 acknowledgements remain queued. `ControlWorker` publishes actual journal
counts; the dashboard's component table renders the resulting delivery-health state.

Backend `_replay` checks operation identity, fingerprint and stored material fields. The
version-1 fingerprint is not an authorization mechanism. A future request schema change must
maintain that canonicalization or introduce a reviewed version. Native database contention,
crash recovery and operator rejection resolution remain unverified. The TestClient transport
test proves local API/journal compatibility, not a real HTTP deployment or Docker action.


## Deployment action boundaries

`run_gate` constructs policy evidence before `perform_action`; `begin_action` commits local
intent before Docker and `finish_action` commits the CLI outcome with successful delivery
enqueue. Cleanup has separate intent/outcome. Never dispatch pending action rows on restart:
Docker may already have executed them. Delivery replay is HTTP-only and uses immutable event
keys. Failed/unfinished rows never represent backend deployment registration. Test disk failure
before dispatch, failure after dispatch, nonzero cleanup, transaction rollback and restart flush
using disposable SQLite and fake Docker. Native fault injection remains pending.

Be able to explain why a CLI exit status does not prove lasting host state, why a SQLite
transaction cannot atomically cover Docker, and why a lost create response can still leave an unstarted
orphan whose identity is unknown despite recorded intent. Operator reconciliation needs authoritative full-container-ID evidence,
backup and an explicitly reviewed recovery operation; no automatic resolution API is provided.


Gate `_docker` supplies per-command subprocess timeouts. `DockerCommandTimeout` deliberately
is not a `DockerCommandError`: the latter represents a returned nonzero exit and triggers the
existing start-failure cleanup; timeout means the daemon outcome is unknown and must escape
that cleanup branch. Do not merge these exceptions without preserving that safety distinction.
Regression coverage includes fake daemon outcomes and a real sleeping Python CLI substitute
that is killed/reaped, not a real Docker cancellation experiment.


## Response transport failures and locks

Docker SDK `APIError` does not cover requests transport failures. `auto_isolate` handles both
families during host mutations and verification. Disconnect errors must not bypass pause;
resume failures must enter best-effort re-pause even when an unpause response was lost. Cached
status is insufficient: reload first, attempt pause if state is unknown, then verify and retain
all errors. No local test proves containment while a real daemon is unavailable.

The response decorator resolves the container to a full ID, takes its file lock, then reloads
state inside the operation. Name/full-ID concurrent requests must use the same inode and wait
until the first action finishes, even when it fails. The two-thread regression uses real local
flock and temporary JSON with fake Docker. Cross-process/native daemon schedules and hard kills
still require isolated acceptance. Never release the lock early to hide long daemon waits.


## Creation intent versus gate completion

`begin_creation` commits local intent before Docker. `create_container` requires one full
hexadecimal ID; `finish_creation` saves it before inspection and cannot replace a completed
attempt's identity. A nonzero CLI result saves failure; timeout, malformed identity or storage
failure retains uncertainty. No raw Docker arguments are persisted. `action_health` aggregates
creation and start/removal outcomes. Creation success cannot enqueue backend registration and
is not proof that scanning, policy or startup finished. Later interruption may leave a known
unstarted orphan; lost create responses can leave an unknown one. No restart executor exists.

The type-check runner uses no persistent cache (`--cache-dir` set to the operating system's
null device) as well as `--no-incremental`. A corrupted mypy SQLite plugin snapshot previously
caused an internal error even in nonincremental mode. The broken generated cache is retained;
release checks no longer consume it. Do not treat a tool crash as successful type validation.


## Health is a reported snapshot

`monitor.status` computes heartbeat freshness separately from component health. A running
boolean and fresh timestamp alone cannot establish healthy Docker/Falco/control/backend
reports or a working API database read. Missing required components remain missing and are
listed as degraded; they are not invented as available. Unknown process state uses nullable
`running` with `status_available=false`. Dashboard `monitorState` distinguishes that from an
observed stopped process and handles corrupt component shapes without crashing.

The old API `healthy` field meant heartbeat freshness. Consumers must adopt `heartbeat_fresh`
for that narrower purpose. Do not present aggregate snapshot health as proof of live detection
or thread progress: stale per-component reports, native failures and actual event-path health
need independent acceptance. Tests use real temporary JSON/TestClient/SQLite, injected database
query failures and React DOM/string rendering, not a live monitor or browser.


## Control cycle completion

Publish `control_updated_at` after every control stage, not before the potentially slow incident
and delivery work. A failure/stop must not publish successful progress. The main ingestion loop
can continue refreshing its own snapshot while control is blocked, so those timestamps prove
different observations. `describe_status` owns shared API/CLI interpretation; the API supplies
its extra database read result. Avoid reintroducing separate freshness rules in callers.

A control cycle older than 30 seconds is an inspection signal, not an automatic watchdog. Busy
legitimate work can take longer; do not kill a worker or replay in-flight actions from this
signal. The local blocked-thread regression demonstrates marker ordering while a separate board
write refreshes the heartbeat; native thread/process hangs still require isolated acceptance.


## Database driver and connection budgets

The manifest supplies psycopg2; locked SQLAlchemy 2.1 defaults plain PostgreSQL URLs to psycopg 3.
`create_database_engine` selects the declared driver explicitly without rewriting the environment
URL used by other services. Preserve SSL and connection options when changing this code. Reject
ambiguous/unbounded URL timeouts before construction; use engine disposal in standalone tools.

Distinguish connect timeout, pool checkout wait, stale-connection pre-ping, statement/lock limits
and an overall request deadline. Only the first two receive new five-second defaults here;
application SQL is not automatically replayed. The silent-loopback test uses real libpq to verify
handshake timeout, plus a fixture that always releases its owned listener. It cannot prove
PostgreSQL login, query behavior, transaction recovery or server restart safety.


## Unavailable database operations and unknown writes

`main.database_operation_unavailable` handles only OperationalError and pool TimeoutError in
request processing. Keep that selection narrow: validation, integrity and programming failures
must not be indiscriminately hidden as availability errors. Do not log raw database exceptions;
their statement/parameters/driver text may contain sensitive values. Mutation errors cannot
promise rollback or that no Docker action happened. The read/write-specific response preserves
that distinction and never recommends blind mutation retries.

The actual-app tests include auth/CORS, real disposable QueuePool exhaustion/recovery, safe
error logging, a pre-insert failure and commit-then-error with same-key audit deduplication.
Row visibility on a reused SQLite connection after an initial commit-event fault was not proof
of a durable commit or PostgreSQL transaction behavior. Use explicit fault phases and native server acceptance when changing transaction logic.

### Inspecting uncertain deployment attempts

`bin/selfsentry-run --inspect-journal --limit 50 --offset 0` uses
`deployment_outbox.inspect_actions`, reached before the normal gate workflow. It opens the
existing SQLite journal with `mode=ro`, enables query-only behavior and reads a single snapshot.
A fixed-column union combines creation/action metadata; bound limits/offsets cap output to 200
records. Counts use the same snapshot. Closing the connection releases the read transaction.
Decision bodies and rejection payloads are not exported. Do not replace this connection with
`connect()`: that function is the writer/schema initializer used by the normal gate.

Tests in `tests/test_deployment_outbox.py` cover missing/corrupt/legacy files, bounds, pagination,
URI characters, output fields, closed connections, denied SQL writes and a concurrent WAL writer
between reads. The CLI tests forbid gate execution and HTTP delivery. These are real disposable
SQLite tests, not evidence that a native Docker action was reconciled. Be ready to explain why a
recorded CLI success is not a statement about current host state, and why an unknown create ID
must not be inferred from a container name.

### Audit delivery ownership and acknowledgements

`monitor-service/audit_client.py` shares `_post` between the legacy JSONL and durable SQLite
clients. Only validated insert/dedup reply shapes acknowledge delivery; ambiguous replies and
recoverable authorization/throttling failures retain the event. Explicit 400/422 rejections
are preserved separately. Logging identifies transport exception classes without raw messages.

The SQLite connection context manager governs transactions but does not itself close the
connection. The durable client now wraps each owned handle with `contextlib.closing` and uses
the connection context for commit/rollback. Selection completes and closes before HTTP begins;
acknowledgement deletion opens a separate short transaction. If deletion fails after delivery,
retry the same key: an acknowledged remote write may already exist. Tests retain references to
instrumented real connections and verify close on initialization, enqueue, count, select and
delete faults, plus successful paths. The route/client lost-response test uses actual disposable
SQLite and TestClient, with a controlled exception replacing the network response. It validates
one deduplicated event, not a production recovery guarantee or content-bound acknowledgements.

### Audit corruption barriers

`AuditClient._read_spool` performs reads without quarantine writes. `_decode_payload` checks
JSON object shape and finite values; a sanitized `AuditJournalError` retains source evidence.
`DurableAuditClient.flush_spool` preflights the selected SQLite batch and key/body association
before HTTP, so corrupt local data is not sent or acknowledged. This does not implement a full
schema validator, whole-file streaming, automatic repair or a cross-process migration.

`MonitorService._update_status` handles the declared corruption error narrowly: it reports null
depth/degraded spool and still writes status, preserving ingestion progress. Other storage errors
retain existing handling. The current control-worker exception boundary can postpone deployment
delivery after audit corruption; operator repair remains required. Tests use real temporary
JSONL/SQLite files, repeated reads, invalid encodings/shapes/nonfinite values/key mismatches,
a real file tailer/checkpoint and a simulated reviewed repair with original backup. HTTP is
mocked in these tests; no native Falco/Docker/database recovery is implied.

### New audit identity versus replay identity

`audit_client._event_key` generates only for None and validates supplied keys against the API's
1–128 character string requirement. Both emitters use it; a queued payload contains the chosen
key, so flush/restart does not regenerate it. The legacy HTTP-first emitter previously queued
None after a lost reply, letting the backend insert twice. Real route/disposable SQLite tests
now demonstrate one row after loss and replay for both clients. Two independent keyless emits
remain distinct. Callers needing identity across repeated emit calls must supply their own
stable key; this change does not infer identities for historical records or change the API's
optional field. Existing SHA-1 event keys and already stored payloads remain unchanged.

### Pending audit identity integrity

`DurableAuditClient.emit` serializes finite JSON, inserts-or-ignores the key, then reads and
compares the stored payload within the same write transaction. Sorted JSON object keys make
mapping order irrelevant. The retry's omitted/empty event time is replaced only in the
comparison with the original timestamp; stored data is never updated. A mismatch raises
`AuditEventConflict`; malformed original data raises `AuditJournalError`. Transaction rollback
and deterministic connection close retain the original row on either failure.

The distinction between pending and delivered is essential: this check cannot compare data
whose local row was already deleted. Backend checks described below now cover keyed content
on delivery; legacy JSONL has no local comparison or permanent local identity ledger. Tests cover field differences,
reordered nested mappings, original automatic timestamps, corrupt originals, two simultaneous
writers and nonfinite new input. Normal successful enqueue still returns False because it is
queued, not remotely acknowledged.

### Backend replay content checks

`backend-api/routes/audit.py` uses `_acknowledge_duplicate` for both an initial matching key and
a row found after rolling back a competing unique-key insert. It compares a fixed set of event
fields and finite sorted JSON detail; differing data raises generic 409. Request detail is
checked before writes so nonfinite input cannot poison a new row or obtain duplicate success.
Legacy null detail normalizes to the schema's empty-object default. No new schema/migration,
identity ledger or cryptographic hash is required.

Timestamp is deliberately excluded from server replay identity and remains first-write metadata.
Explain the scope difference from local pending enqueue, which can distinguish an explicit time
from a caller-omitted default. Tests cover matching/racing replays, seven changed fields, nested
mapping order, booleans versus integers, timestamp retention, finite input and invalid historical
data. Client-to-route tests show that a changed event stays pending with 409 after its first
local record was delivered. Native PostgreSQL race and keyless-event limitations remain open.

## Tracked follow-up tools — 23 October 2026

Run from the repository root with its locked `.venv`. These tools do not form a
single all-purpose acceptance command. The current report distinguishes local checks
from the committed native records. Original package/source hashes are retained in
`recovered-runners.json`; adaptations preserve target ownership/cleanup and isolation gates.

| Tool | Scope and prerequisites |
| --- | --- |
| `evaluation/verify_postgres_acceptance.py --repo "$PWD"` | Existing local PostgreSQL and healthy monitor; read-only source snapshot, private dump, two uniquely owned disposable databases; sudo socket identity must match; restores/adopts only the copies |
| `evaluation/verify_postgres_concurrency.py --repo "$PWD"` | Healthy local stack and PostgreSQL/admin socket; one owned fresh DB; actual keyed audit races, outcome counters and pinned review-lock probe; no full native deploy/review chain |
| `evaluation/measure_workload.py --repo "$PWD"` | Explicit runtime isolation OFF, managed process identities, empty delivery queues, existing immutable Alpine image; actual gate and one bounded owned container; cleanup checks name/label/full ID |
| `scripts/export_monitor_journal.py --repo "$PWD"` | Healthy monitor, configured state/PID match; private verified journal **and every referenced archive**, outside checkout/state; no pruning or restore |
| `evaluation/verify_archive_copy.py --repo "$PWD" --snapshot /private/original-export` | Verified pre-archive export; exercises archive/readback/missing-file refusal on disposable copies; `--offline` is fixture-only and must not be called a native run |
| `scripts/archive_journal.py --before <past-ISO-time-with-zone> --limit 1000` | Read-only plan by default. Runtime `--apply` moves live payloads and needs a reviewed cutoff, separate approval and stopped monitor; not run by installation |
| `deployment-gate/reconcile_action.py --kind action --key <32-hex-attempt-key>` | Read-only plan for a **known full ID**; successful local daemon inventory/inspection; refuses unknown creation identity |
| `evaluation/evaluate_holdout.py` | Offline private frozen baseline/validation inputs; reports invalid/missing trials and class denominators; no live workload or threshold tuning |
| `scripts/refresh_audit_inventory.py` | Refresh tracked/nonignored-path metadata, symbols/imports/references and hashes; not a claim to re-review every historical file |
| `scripts/lockfile_sbom.py` | SPDX inventory of pinned Python/npm entries including dev/optional; no dependency/artifact/OS/license verification |

Review native runner source before execution. Native runners have real setup/cleanup
side effects; successful local unit tests are not permission to point them at arbitrary
hosts. Do not restart or disrupt the existing VM merely to reproduce an already recorded
pass. Private dumps and runtime evidence stay outside Git. Record exact source commit,
dirty-state diff, command, versions, failed runs and cleanup status beside native results.
`evaluation/source-hashes.json` is a review gate, never a historical native result; changes
require review of newly pinned source and appropriate acceptance.

### Reconcile a gate observation

First inspect `bin/selfsentry-run --inspect-journal`, retain a verified private export of
`state/deployments.sqlite`, and obtain the attempt's kind/key. The separate observer uses
`SELFSENTRY_STATE_DIR` for the same gate journal. A plan displays its original SHA-256,
full container ID, daemon ID and a bounded current observation. It never prints inspect
environment variables or raw Docker arguments.

After reviewing that plan, the operator can record an observation explicitly:

```bash
.venv/bin/python deployment-gate/reconcile_action.py \
  --kind action --key <full-attempt-key> \
  --apply-original-sha256 <original-sha256-from-plan> \
  --reviewed-by <human-label> --reason '<evidence-based-reason>'
```

Apply obtains the actual ownership flock (expiry alone never permits overriding an owner),
re-reads the original and takes a fresh Docker observation before one SQLite transaction.
The returned observation may differ from the earlier plan because the host can change.
The original hash binds intent, not Docker state. The decision is
`accepted_current_observation`, not `command_succeeded`. `action_reconciliations` keeps one
append-only JSON audit per kind/key, including reviewer/reason/timestamp, original hash
and observed state. Conflicting/repeated decisions refuse replacement. Original attempts,
queued registrations and health counters are untouched; the ledger is local and not yet
mirrored to backend audit/UI. A failed Docker call cannot establish absence. A successful
complete listing can observe absence at that moment, without proving historical removal.
No automatic retry, remediation, orphan-ID guessing or false health clearance exists.

### Independent held-out window accounting

Baseline input is the existing baseline JSON shape. Validation is one JSON object per
line: `{"label":"benign"|"attack","feature_vector":<complete FeatureVector dictionary>}`.
The dictionary includes matching container ID, timezone-aware `window_start/window_end`
and all eight nonnegative integer counts in `FEATURE_NAMES`. Declare labels independently
of the model's prediction. Training is frozen; validation must follow it, with no repeated
or overlapping training/validation windows. Keep failed cases in the input/output.

```bash
.venv/bin/python evaluation/evaluate_holdout.py \
  --baseline /private/frozen-baseline.json \
  --validation /private/independently-labeled-validation.jsonl \
  --expected-windows <declared-number> --output /private/new-holdout-result.json
```

Output is exclusive/private and contains corpus hashes, default model/threshold, fit and
scoring times, predictions, confusion counts, scored-class denominators and unscored counts.
A partial or one-class run exits nonzero with retained results; rates conditional on scored
windows must never be presented as full-corpus accuracy. Synthetic test fixtures do not
establish detection quality, independence of real labels, benignness or representative attack
coverage. This tool does not accept the anomaly-only synthesis/native re-fire chain.

## Native retirement continuation — 23 October 2026

Native retirement is implemented behind `SELFSENTRY_NATIVE_RETIREMENT_ENABLED=false` by
default. The existing `/rules/{id}/deprecate` remains the database-only operation. The new
`GET /rules/{id}/native-retirement-plan` reads file/rule hashes and any retained receipt.
It does not initialize the retirement journal or change native rules. The write route is
`POST /rules/{id}/retire-native`, protected by the app's existing bearer-token middleware.

The write body requires `reviewed_by`, a nonblank `reason`, `expected_file_sha256`,
`expected_rule_sha256`, strict boolean `confirm_native_unload: true`, and an explicit
`action` of `retire` (default) or `rollback`. It requires a retained `RULE_DEPLOYED` audit.
Actor labels remain supplied identities; no per-person authentication is claimed.

Before enabling it on a disposable host, verify the exact Falco 0.45 configuration and
binary. The ordered configured rule inventory must include the generated-rules file exactly
once; runtime overrides must be supported by the existing inventory guard. A unique exact
rule definition is required; changed, duplicate, overridden, missing, symlinked or hard-linked
targets are refused. Prevalidation runs the actual configured Falco executable with ordered
`-V` files, substituting a temporary candidate without editing the live file.

The host must explicitly configure Falco's protected `reload_control` Unix socket and
provide the backend account permission to use it. `FALCO_RELOAD_SOCKET` defaults to
`/run/falco/control.sock`. The app does not enable or change Falco configuration itself,
create the socket directory, grant privileges, restart Falco, or enable real isolation.
Socket peer credentials must match the configured service's MainPID.

The protocol was checked against Falco 0.45.0 source commit
`05d5b3e363d5196c68c8ccea842ca57a2ef05562`, particularly `falco.yaml`,
`userspace/falco/reload_control.cpp`, `webserver.cpp` and
`app/actions/validate_rules_files.cpp`. A POST returns an instance/generation baseline;
only a matching ready instance with a later applied generation beyond the rejected
generation confirms completion. HTTP success alone is insufficient. A lost POST reply
is never automatically repeated; only status observations are retried through reload outages.
The protocol is version-specific and does not attest future Falco interfaces.

### State and recovery contract

The existing per-rule review lock spans DB commits and native work; the permanent inventory
flock also serializes generated-file mutations with deployment. `retirement_pending` remains
an active candidate state, cannot be overwritten by database-only deprecation, appears in
the pending queue, and cannot use ordinary approve/retry controls. Native re-fire evidence
is retained for this state as well as deployed/retired rules.

`RULE_GUARD_STATE_DIR/retirements` is private. It retains the complete original file,
private validation output, a SQLite latest-receipt table and append-only transition history.
The original file and local intent are synced before DB approval/audit is committed. The DB
is marked pending before the atomically replaced live file can trigger Falco's automatic
watcher. The full ordered candidate was already prevalidated. The final receipt is durable
before recording database retirement and a native-result audit.

A known rejected reload permits corrective restoration of the exact original and a verified
rollback reload. Transport ambiguity, interrupted publication, lost DB acknowledgement or
failed result persistence retain pending state. An explicit human rollback revalidates the
original against the current inventory, records recovery intent before restoration, and
verifies its reload. Recovery refuses unrelated file edits, changed database YAML, duplicate
native names, missing originals and unowned identities. No exception guesses that an
uncertain action failed, and no failed/partial backup is deleted automatically.

A durable applied receipt can complete an interrupted DB result without a second native
reload only while file/rule hashes and the exact Falco instance/generations still match.
A process change or subsequent reload requires reconciliation. Successful duplicate audit
replay retains the first result/reviewer timestamp. The duplicate registry's protected
history is never erased by retirement or rollback.

The dashboard says **Native unload recorded**, rather than claiming perpetual current
state, only for a matching successful native audit with a well-formed reload receipt.
Pending/blocked outcomes remain explicit. Native controls have not been added to sample
mode or to an automatic policy path.

Local acceptance covers actual temporary files/SQLite/flock, process kill/recovery, actual
API/journal/file round trips with a controlled native adapter, and controlled HTTP protocol
responses. This host blocks AF_UNIX creation: three real-Unix-peer fixture tests are skipped
with that reason. Those failures/skips are retained, not reported as native passes. Real
Falco validation/socket/reload/re-fire and PostgreSQL/native review interleavings remain
NOT VERIFIED until exercised on an authorized disposable host. Noncooperating external rule
writers, remote/multiple backend hosts, filesystem/power-loss durability and a global
request/shutdown deadline remain outside the guarantee.


## Historical acceptance runners — VM checkpoint ed56643

### Ten-minute workload

Keep the existing managed services running. Isolation must remain disabled. The local
alpine:3.20 image is scanned by immutable ID; a gate refusal is retained, never overridden.
The runner creates and removes only its own restricted, labelled, network-none probe.

```bash
AUTO_ISOLATION_ENABLED=false .venv/bin/python evaluation/measure_workload.py --repo "$PWD" --executions 3000
```

It runs 3,000 /bin/true invocations plus 3,000 pacing sleeps at nominal five per second,
with four concurrent HTTP readers and one-second process/RSS/queue/SQLite-WAL size samples.
The generator deadline is 775 seconds; probe lifetime is bounded independently. Failed or
partial output is retained and is never counted as completion. It records the same safety
and model-status checks as the earlier bounded run. This is sustained observation of one
paced probe, not representative fleet capacity, leak proof, complete disk accounting,
model fit/inference timing or a zero-loss claim. No native drop counters are invented.

## Historical before/unloaded/restored native rule behavior

This example is specific to the original VM and its reviewed rule/file hashes.
Do not run it on a fresh installation merely because the guide contains a command.
Recorded native retirement/rollback and subsequent test-rule cleanup are in the
current audit; uncertain operation records still require inspection before retries.

This explicitly exercises rule 5, whose reviewed SHA256 is
`47216c322ce212dc121f1efd4170df764331f215a3ae2b41de4c02ae8138f25c`.
It requires a human reviewer and the generated-file SHA already reviewed in this session.
It refuses changed source, active/uncertain receipts, enabled isolation/auto-confirmation/
candidate generation, missing listener and blocked deployment. No API token is printed.

The helper enables only a temporary protected socket. It refuses a custom current Falco
command or an existing override, and restores the original service if activation fails.
It uses the directory-group correction verified on this VM. It briefly restarts Falco.
Backend opt-in is separate and scoped to the managed processes, without editing .env.

```bash
sudo bash scripts/retirement_test_socket.sh enable sl0thh &&
SELFSENTRY_NATIVE_RETIREMENT_ENABLED=true FALCO_RELOAD_SOCKET=/run/selfsentry-falco-control/control.sock AUTO_ISOLATION_ENABLED=false bash bin/selfsentry restart &&
FALCO_RELOAD_SOCKET=/run/selfsentry-falco-control/control.sock .venv/bin/python evaluation/verify_retirement_behavior.py --repo "$PWD" --approve-rule-5-retire-and-restore --reviewed-by guna --expected-file-sha256 8aad4c534cb1b96bb06e9cf5a48840c0acf33034db791378f761feac723d2b65
```

The native runner creates one owned restricted Alpine probe through the gate, with an
executable disposable /tmp tmpfs. Three 20-second windows require a baseline process
witness matching container, process validation-true and parent sh. It expects a native
match before retirement, no native match while unloaded, and a native match after the
explicit restore. Kernel/container dispatch may make the renamed harmless binary exit
nonzero; its process exit is retained and a matching native baseline witness is required.
This is a process-name detection test, not a claim that an attack succeeded.

Falco event times must agree with host times and a stable host boot/monotonic clock.
Log rotation, truncation, partial records, missing baseline evidence and oversized logs
invalidate the trial rather than becoming false negatives. Absence is only the observed
window, not a permanent proof. The runner uses the existing protected client and endpoint.
Known applied retirement is explicitly restored even if the unloaded observation fails.
An uncertain write is never retried; native journals and runner requests are retained.
No unapproved existing rule is touched. A hard process kill can require manual recovery;
the owned probe name/full ID/ownership token and operation records are retained for review.

If native_recovery_required is true or a request times out, stop and inspect the receipt;
do not rerun the test, overwrite rules manually, or blindly repeat either POST.
A failed preparation before mutation is a failed attempt, not native acceptance.

After a confirmed successful restore, disable the endpoint and remove the temporary socket:

```bash
SELFSENTRY_NATIVE_RETIREMENT_ENABLED=false AUTO_ISOLATION_ENABLED=false bash bin/selfsentry restart &&
sudo bash scripts/retirement_test_socket.sh disable sl0thh
```

The disable helper removes only an override with its expected contents. Retain all evidence.

## Historical acceptance boundaries — runner preparation

These tools require real VM execution. Their local adapter tests are not native passes.
The next batch does not close the independent representative benign/attack holdout study,
anomaly-only confirmation/backtest/approval/refire loop (process-parent and file-write),
whole-application coordinated restore, fresh supported Linux installation, remaining
native failure/interleaving cases, live browser matrix, lifecycle clock recurrence,
owner-approved retention cutoff/cleanup or real isolation. Real isolation stays disabled
unless separately authorized for a named isolated environment. Fresh-host testing needs
an actual clean supported host. Detection evaluation needs an independently labelled,
separated corpus and declared coverage/denominators; synthetic fixtures cannot replace it.

## Historical validation — runner preparation

Root Python suite: 1,185 passed + 104 subtests, 3 explicit AF_UNIX policy skips.
Focused runner tests: 49 passed. Full lint and type checks passed (95 source files).
Socket helper: bash syntax validated; no local service mutation/native execution.
No frontend source changed, so prior VM build/frontend evidence remains scoped to that code.


## Coordinated durable-state restore — recorded protocol

### Execute on the existing VM

Keep the stack running initially and do not run other gate/review/baseline commands during
capture. The source must have a healthy managed monitor, a ready baseline, no separately
owned mutation locks, the verified local PostgreSQL cluster and adequate private disk space.
Existing application configuration and credentials are read locally. No .env file is copied.
Do not run this against an unreviewed remote PostgreSQL installation.

The flag explicitly authorizes a brief pause of the three managed application processes.
Docker, PostgreSQL, Falco and existing container workloads continue running. The monitor
will catch up from its original checkpoint when resumed; inputs keep accumulating in the
Falco log. Retirements and automatic isolation are kept disabled on resume.

```bash
cd ~/selfsentry &&
sudo -v &&
AUTO_ISOLATION_ENABLED=false SELFSENTRY_NATIVE_RETIREMENT_ENABLED=false \
  .venv/bin/python evaluation/verify_coordinated_restore.py \
  --repo "$PWD" --approve-managed-pause
```

Default private work location: ~/selfsentry-recovery-checks/coordinated-restore-TIMESTAMP.
Failed or partial captures are retained for review and are never accepted as valid backups.
If any step fails, inspect the report and original application status before retrying.
A hard kill, host outage or failed original-app startup can require manual recovery;
`bash bin/selfsentry start` is the existing operator recovery command. The runner never
repeats an uncertain database create/restore operation automatically.

## What the check verifies

1. All three managed source process identities are present and the healthy monitor reports
   automatic isolation disabled. Native PostgreSQL backup tools must match the server major
   version, and the administrator socket must identify the same source cluster.
2. A stopped-process check and actual lifecycle/monitor/rule-guard/operation flocks protect
   the capture. An expired deadline is not evidence that an actual ownership lock is free.
   Tree membership and logical/byte fingerprints must remain stable across capture. These
   checks assume no concurrent operator writes; they are not a global distributed transaction.
3. A single exported read-only PostgreSQL snapshot is dumped. Public application table rows
   and sequence state are compared again before source processes resume. Source database
   writes/restores, role changes, service stops and live schema migrations are never issued.
4. All nonvolatile monitor/baseline/rule-guard/rule files and the deployment journal are copied.
   SQLite backup includes committed WAL data, uses bounded typed row/schema readback and
   checks integrity. Symlinks, hardlinks, oversized files and changing source state refuse.
   Runtime lock files, status/PID snapshots and SQLite WAL/SHM companions are excluded from
   recovery inputs; WAL content is merged through SQLite backup, not discarded.
5. A bounded prefix of the actual Falco log is retained. The saved checkpoint inode and
   offset must identify that log generation and fit within the prefix. A missing old log
   generation or rotation mismatch fails rather than silently inventing replay coverage.
6. The managed app resumes before disposable restore work begins. The resume attempt does
   not depend on writable evidence storage, so a disk-full capture error cannot suppress it.
7. PostgreSQL is restored only into a newly created, ownership-recorded ss_accept_*_restore
   database. Application rows, schema and sequence values must match the captured source.
   Only a confirmed owned database is eligible for automated cleanup.
8. All copied artifact hashes are verified. The ordered copied Falco rules are validated with
   the native binary. Restored journal/archive payloads must remain readable. A tailer is
   reopened against the verified cloned log after explicitly mapping its clone-only inode;
   the original checkpoint and log are never rewritten.
9. Previously ready models are rebuilt using the real pipeline, validated copied baseline
   JSON and unchanged default algorithm. This is model restore/readiness, not detection
   quality. No pickle import, live API delivery or Docker action is performed by that pipeline.
10. The original private capture remains unchanged after mutable-copy replay/model tests.
    Final original-app health, owned-database cleanup and every named acceptance check are
    required. The private filesystem work is retained rather than automatically deleted.

The report records source commit, dirty state and runner hashes. Private dumps, models,
checkpoint keys, raw events, rule backup files, manifests and command logs stay outside Git.
Share only the sanitized final summary and evidence path; do not upload the private folder.

## Scope boundaries

This demonstrates coordinated durable-state capture and same-host disposable component
recovery. It does not by itself establish a fresh Linux install, live failover, restored
container/network runtime, service reattachment on another host, restoration of PostgreSQL
roles/ACLs or secrets, or recovery with pending work when the source queues were empty.
The restored pipeline is exercised offline without starting a second live monitor/backend.
A full host/application takeover still needs a separately isolated destination and its own
operator review. The active production paths/database are never restore destinations.

Independent representative detection evaluation, the anomaly-only human-reviewed rule loop,
remaining native failure cases, live browser matrix, lifecycle clock recurrence and owner
retention/cleanup decisions retain their previous acceptance boundaries. Real isolation
continues to require explicit approval in a named isolated test environment.
