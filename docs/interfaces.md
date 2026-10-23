# SelfSentry service contracts

These contracts describe the current source, not the early phase plans. Keep route
names, field types, the eight-feature order and persisted event keys compatible when
changing producers. Live PostgreSQL/OpenAPI acceptance remains a separate check.

## Falco and baseline telemetry

`runtime-monitor/falco_integration.py:parse_falco_alert` returns a `FalcoAlert`.
`to_dict()` exposes `container_id`, `timestamp`, `rule`, `priority`, and `output`.
Priority is uppercase; Falco Informational is normalized to `INFO`. Containerless host
events are filtered by the continuous monitor.

`monitor-service/event_classifier.py:classify_line` adds `output_fields`, `raw_line`,
`event_key`, and available name/image/process context. Rule names starting with
`Baseline ` are telemetry, not security alerts. `behavior_pipeline.container_identity`
requires a Docker hexadecimal ID of 12–64 characters and normalizes it to 12 characters.
Response actions resolve the full Docker ID rather than trusting a name.

Timestamps entering behavioral windows require a timezone. Raw Falco timestamps may
retain nanosecond precision; Python datetime processing has lower precision. Do not
invent a unique Falco event ID: the tailer hashes normalized raw lines and treats two
byte-identical events as duplicates. Changing that hash would affect replay compatibility.

## Behavioral event

`behavioral-engine/anomaly_model.py:AnomalyResult.to_event_dict()` returns:

```json
{
  "container_id": "abc123def456",
  "timestamp": "2026-10-21T10:00:00+00:00",
  "anomaly_score": 0.87,
  "features": {
    "distinct_process_count": 2,
    "distinct_network_dest_count": 1,
    "distinct_ports_count": 1,
    "distinct_files_accessed": 3,
    "total_event_count": 8,
    "shell_spawned_count": 1,
    "distinct_parent_child_pairs": 2,
    "sensitive_syscall_count": 0
  }
}
```

This is an illustrative payload, not measured evidence. Feature order is defined by
`feature_extractor.FEATURE_NAMES`. The normalized anomaly score is not a probability.
The monitor qualifies events using its configured threshold; the model's `is_anomaly`
flag alone is insufficient. When the model is unavailable, no replacement score is
fabricated. Falco-only incidents remain supported.

## Incident persistence and workflow

`POST /incidents/` accepts `container_id`, finite `risk_score` in 0–100,
optional `confidence`, nullable `falco_alert` and `anomaly_features` (the **whole**
behavioral event, not only its feature map). Monitor callers also supply `event_key`,
`monitor_evidence`, and the legacy accepted `defer_ai` flag. Incident creation persists
deterministic guidance without calling AI. The monitor handles optional AI separately.

The backend assigns integer `id`. A repeated nonempty monitor `event_key` returns the
existing incident. Monitor metadata is stored in `monitor_incidents`, separate from the
incident table. Evidence includes availability, window bounds, observed timeline and
recorded layer inputs; consumers must tolerate absent historical fields.

| Route | Purpose |
| --- | --- |
| `GET /incidents/`, `GET /incidents/{id}` | Current serialization with confirmation, evidence and guidance |
| `POST /incidents/{id}/confirm?confirmed_by=...` | Idempotent confirmation; returns integer `confirmed_incident_id` |
| `POST /incidents/{id}/dismiss` | Marks monitor-backed incident benign; legacy rows without workflow return 409 |
| `POST /monitor/incidents/{id}/workflow` | Merges confirmation, response, candidate, explanation or confirmation_policy |

Confirmation actors are stripped, must be nonblank and fit 128 characters.
`selfsentry-auto` confirmation is checked against backend policy after normalization. Human labels are
operator-supplied; the shared token is not a verified per-person identity. Confirmation
is policy acceptance, not proof that an observation was malicious.

## Rule lifecycle

`POST /rules/` and `POST /rules/preflight` accept:

```json
{
  "confirmed_incident_id": 1,
  "rule_yaml": "<one supported literal Falco template rule>",
  "backtested_fp_rate": 0.02
}
```

The reported rate must be finite and within 0–0.05, but is not authoritative. The backend
runs its own configured benign corpus test on submission and approval and records its
hash and usable-event counts. Missing/empty corpus, unsupported condition, or failing rate
blocks progression. Duplicate preflight/submission can return a recorded
`rejected_duplicate` result. Successful submission returns integer `id` and `pending_review`.

Active statuses are `pending_review`, `approved`, and `deployed`. Historical states also
include `rejected`, `rejected_duplicate`, and `retired`. Approval records the explicit
human reviewer before calling the deployer. Reload failure returns 502 and leaves an
approved rule retryable. This is a file/database boundary, not one atomic transaction.
Approval, rejection and retirement now share a per-rule review lock. PostgreSQL uses a
pinned connection/session lock held across commits and deployment; SQLite/local tests use
a host file lock. Competing reviews return HTTP 409 and must refresh. Native PostgreSQL
concurrency and process-crash recovery remain unverified. Retirement requires an explicit
human reviewer and records an audit, but does not unload the native rule; the response
reports `native_rule_unloaded: false`. Subsequent native matches are still retained for
retired rules and record that database status.

`GET /rules/pending` includes pending and approved rules. `/rules/history` returns at most
100 rules with recorded lifecycle evidence; it is not a complete historical export.
`/rules/for-confirmed/{id}` finds the current active candidate. Native re-fire evidence is
an observed Falco match, not an automatically labeled true positive.

## Gate, audit and operator actions

- `POST /deployments/` records `allowed`, `blocked`, or `overridden`. Overrides require
  a nonempty reason. The gate records the requested image name but scans the created
  container's immutable image ID. A journal event key supports idempotent replay.
- `GET /deployments/registration/{container_id}` is an exact ID lookup across stored
  allowed/overridden records, independent of dashboard history pagination.
- `POST /audit/` appends an event and returns `{id, duplicate}`; duplicate keys return
  HTTP 200, new events HTTP 201. GET supports `event_type`, `container_id`, positive
  `event_id`/`before_id`, and a limit capped at 500. Occurrence time serializes as UTC.
- Container isolation/resume routes require the shared write token. Full-ID filesystem
  locks serialize response actions. Saved network IDs/names/aliases support recovery;
  static IPs and all endpoint options are not preserved. Invalid/unreadable recovery records
  produce per-container `containment_state: "record_unavailable"`, nullable `isolated: null`
  and an explicit error. Both actions return 409 until the recovery state is repaired.
  `get_isolation_record` returns None only for missing state and raises `IsolationRecordError`
  for invalid state. Records require matching full-ID ownership, a known lifecycle state
  and usable network/alias structure; optional legacy network IDs remain supported.
- `GET /monitor/status` separates `heartbeat_fresh` from aggregate `healthy`. Health requires
  a reported running process, a timestamp less than 30 seconds old (not in the future), a
  completed control cycle less than 30 seconds old, all
  required Docker/Falco/control/backend components reporting `ok`/`connected`, a successful
  backend database count, and no reported component failure. Disabled optional components
  are allowed; disabled core components are not. `degraded_components` names missing/failed
  reports and `health_reason` explains the result. This is snapshot health, not end-to-end proof.
- Missing/malformed monitor snapshots return `status_available: false`, `running: null`,
  `healthy: false` and a reason; process state is unknown, not asserted stopped. For available
  snapshots `running` remains the reported boolean. Invalid individual component entries
  become explicit `unknown` reports while other recorded telemetry is retained.

All writes to the actual app require `Authorization: Bearer <token>`. Reads are unauthenticated
on the intended localhost boundary. Router-only test apps do not establish middleware behavior;
use actual-app authentication tests as well. Frontend sample routes never forward API writes.

## State and schema authority

`backend-api/models/db_models.py` defines backend tables. `database/migrations` freezes
a versioned initial baseline for empty databases. Existing installations require a backup,
read-only comparison and explicit adoption; no schema migration runs automatically. `database/schema.sql` is an older draft and must not be used to
initialize a current installation: it adds an incident/container foreign key absent from the
ORM. Outcome recording no longer requires the missing rule_id unique constraint: it locks
the parent generated rule before inserting/updating counters. Existing duplicate counter
rows cause an explicit error without deleting or merging records. This serializes module
writers; it is not a database-wide uniqueness guarantee against arbitrary direct SQL.
A reviewed constraint migration still requires inspecting existing data first. Do not
assume `create_all` repairs a running database.

### Runtime configuration and bounded work (audit follow-up)

`GET /monitor/status.configuration` is the configuration published by the monitor
process, not the backend environment. `backend_configuration` describes the API process
separately. An older monitor can report `{}` for runtime configuration; consumers must
show unknown and must not infer that automatic isolation is off. Restart the monitor to
publish these fields. Heartbeat freshness alone does not prove all dependencies are healthy.

`docker_event_queue_depth` and `control_event_queue_depth` are observed entry counts,
with a capacity of 1,000 each. `docker_event_pending` identifies an event retained by the
main loop while control work is full. These queues are memory-only; they do not establish
crash-safe Docker event delivery. Deferred model jobs remain `BASELINE_READY` until one
of the two training slots is available.

## Write validation and workflow concurrency

Incident workflow updates, dismissal and confirmation lock the parent incident row before
reading state. Workflow/dismissal reads refresh cached ORM metadata before merging JSON,
so unrelated committed response/disposition fields are retained. PostgreSQL provides the
row lock; SQLite tests and PostgreSQL SQL compilation do not prove native concurrency or
bounded lock wait. These endpoints use the same lock order, but arbitrary direct SQL does not.

Workflow patch values must be objects. Ready explanations require an object result.
Dismissal records a UTC timestamp and `INCIDENT_DISMISSED` audit in the same transaction,
with retries of an already-benign disposition returning without another audit. Actor is
explicitly unknown (`null`): the endpoint/shared token cannot establish an individual identity.
Previously dismissed rows are not backfilled with invented historical audit events.
Dismissal does not undo containment or promise to cancel an already in-flight response;
metadata serialization is not an atomic transaction with Docker.

Audit/deployment text fields are bounded by their current SQL column lengths. Supplied
event keys must contain 1–128 characters; omit/use null when no idempotency key exists.
Empty keys are rejected, not stored as ambiguous unique keys. Invalid requests return 422
before writes. These bounds are not a general request-body size or authentication control.

A nonempty deployment scan summary must contain integer `critical`, `high`,
`total_vulnerabilities`, `secrets_found`, and `misconfigurations_found`, each in
0–2147483647. Booleans, numeric strings, negative/fractional/out-of-range and missing
counts are rejected. Extra summary fields remain accepted. An empty/omitted summary
means unavailable and creates no scan row; it does not create a zero-count scan. Findings
and policy violations are lists of objects. This validates recorded report shape, not
cryptographic scan provenance or the truth of a privileged caller's claims. The gate's
actual scanner/policy checks remain the enforcement path.

## Deployment replay identity

A supplied deployment event key now identifies one request. New audit details include
`request_sha256` and `request_fingerprint_version=1` for the canonical request excluding its
key. Changed payloads, cross-operation keys, orphan deployments/scans or inconsistent stored
state return 409 instead of acknowledging another record. Non-finite JSON and scan findings
without a summary return 422. This is additive JSON metadata, not a database schema migration.

Legacy records without a fingerprint remain replayable only when their persisted core fields,
policy, counts and findings agree. Extra summary metadata never persisted in legacy rows cannot
be reconstructed. Existing rows are not backfilled with guessed hashes. Preserve version-1
canonicalization when adding request fields, or define and test an explicit new version.

The successful response contract remains `{id: positive integer, decision: recorded decision}`
with HTTP 201, including valid retries. The journal validates that contract before deleting a
queued delivery. Rejection retention and monitor delivery-health counts are documented in operations.


### Local deployment action journal

The additive `deployment_actions` SQLite table is local to the gate/monitor; it does not change
backend request/response schemas or existing historical decisions. It stores a generated key,
full returned container ID, `start`/`remove`, optional decision JSON, created/completed timestamps
and `outcome_not_recorded`/`command_succeeded`/`command_failed`. Only a successful recorded
outcome with a decision body creates a delivery row, in the same transaction. This is not an
executable work queue. No caller may automatically re-run unfinished actions.

The control worker publishes `deployment_actions` health/counts separately from HTTP delivery
health. No decision rows are fabricated for failed/unfinished actions; backend registration
continues to reflect delivered allowed/override decisions. Local action history/failed override
attempts are not individual backend deployment rows or a dashboard recovery UI.


Gate `DockerCommandTimeout` means no authoritative CLI completion, distinct from a returned
nonzero `DockerCommandError`. Start/removal timeouts retain unfinished action intent and escape
normal start-failure cleanup. No backend contract changes accompany these CLI deadlines.


Response engine Docker API and requests transport failures during isolation/recovery map to
`IsolationError`/`ResumeError` after local failed-state persistence and best-effort containment.
Failure to persist still raises `IsolationRecordError`; it never becomes success. Errors before
an action reaches the engine's guarded operation can remain Docker/requests exceptions; container
routes map both to audited 503 responses. Incomplete response operations remain audited 409
responses. No automatic enablement or retry is added.


`creation_attempts` is an additive local SQLite table with `key`, nullable `container_id`,
`outcome`, `created_at`, and nullable `completed_at`. Outcomes use the same CLI-result labels
as action history. Its successful ID must be full 64-character lowercase Docker hexadecimal.
Creation completion is conditional on unfinished state, preventing identity replacement under
one key. It does not enqueue decisions. Action health counts now include creation outcomes,
without changing its existing count keys or backend deployment schemas.


### ORM database engine construction

`database.create_database_engine` uses psycopg2 for unqualified PostgreSQL URLs to match the
project lockfile. Explicit driver choices and existing URL options remain intact. For the
psycopg2 branch, connect timeout defaults to five seconds (positive integer URL override), pool
checkout wait is five seconds and pre-ping is enabled. SQLite behavior is retained. These
limits do not bound SQL execution, transactions or complete API requests. No migration runs as
a consequence of engine construction alone. Other direct psycopg2 callers retain their own
existing timeout configuration.


### Request-time database failures

The actual FastAPI application maps SQLAlchemy `OperationalError` and connection-pool
`TimeoutError` to HTTP 503 with a sanitized JSON detail. Mutation responses state that a write
may have completed and require reconciliation before retrying. No `Retry-After` or automatic
application retry is introduced. Read responses simply report unavailable database operation.
Known route-level HTTP responses and authorization still take precedence. ProgrammingError,
IntegrityError and unrelated exceptions are not blanket-reclassified by this handler.

The handler logs exception class and method, never underlying SQL/parameters/driver text.
It does not establish that every framework/library log or startup error is sanitized. Startup
schema creation occurs before serving requests and is outside this handler. Existing monitor
status handling still returns diagnostic/degraded state when its own database count fails.

### Monitor audit acknowledgement and retry contract

Both audit clients accept delivery only when `/audit/` replies with a JSON object containing
an integer `id > 0` (booleans are refused) and an actual boolean `duplicate`: `false` for 201
or `true` for 200. Empty, malformed or contradictory success replies keep the original event
queued. This matches the backend's current insert/dedup responses; it does not cryptographically
bind the response to an event key or authenticate an upstream proxy.

HTTP 400/422 payload rejections are retained as dead letters. Authentication/authorization,
throttling, other ambiguous statuses and transport failures remain retryable, so correcting
credentials can recover queued events. Existing periodic flush/order behavior is retained;
no immediate retry loop, action replay or blanket mutation idempotency is added. Use stable
unique `event_key` values for caller-level retries. Both monitor clients generate a key once
per new `emit` call when none is supplied, retaining it in the queued payload across replay.
Supplied client keys must be strings of 1–128 characters; invalid inputs raise before new
delivery or insertion. The API still permits direct keyless events, and historical keyless spool entries remain
unchanged; these cannot guarantee deduplication after a lost response.

### Audit corruption telemetry

A structurally unreadable legacy spool yields `audit_spool_size: null` and a degraded
`components.audit_spool` entry, while the monitor can keep publishing status and ingesting
Falco input. This is unknown depth, not an empty queue. The component's `ok` state means the
size is readable; SQLite payloads are validated separately during delivery. Their validation
failures retain the selected batch and use existing degraded control-workflow reporting.
`AuditJournalError` details omit raw record bodies. No backend endpoint or request schema changes.

### Pending durable audit key conflicts

`DurableAuditClient.emit` compares an existing pending payload when its key already exists in
local SQLite. Different event data raises `AuditEventConflict` rather than silently discarding
the new request; the original row stays unchanged. Identical nested-object data remains a
valid retry regardless of dictionary insertion order. If the retry omits `occurred_at` (or uses
the existing empty-string default behavior), the original pending timestamp is authoritative.
An explicitly supplied different timestamp conflicts. Other payload fields must match.

Malformed existing data raises `AuditJournalError` without replacement, and nonfinite values
in new durable payloads fail serialization before insertion. Comparison and insertion use one
SQLite write transaction; no HTTP occurs during enqueue. This is a pending-journal guarantee:
after local deletion, the backend content checks below apply. The legacy JSONL client has no
local content comparison, but keyed deliveries still receive backend conflict validation.

### Backend audit identity conflicts

For a repeated nonempty `event_key`, POST `/audit/` now compares event type, severity, source,
container ID/name, image name and detail with the stored event before returning 200 duplicate
success. A mismatch returns sanitized HTTP 409 and leaves the stored row unchanged. Both the
initial lookup and unique-insert race recovery use this check. Detail compares finite JSON
values independent of object key order; boolean and integer values remain distinct. Historical
null detail is equivalent to the API's default empty object. Invalid stored detail cannot be
acknowledged as matching.

`occurred_at` and server `created_at` are first-write metadata, excluded from replay identity.
A later request timestamp does not replace the first one or cause a conflict when the other
fields match. This lets callers regenerate a default time after a prior delivery. It also
means the API does not diagnose reuse differing only in timestamp; callers must use separate
keys for distinct occurrences. Pending local durable records retain their stricter explicit-time
comparison. Direct keyless requests remain allowed and are inserted separately.

Nonfinite detail values return a generic 422 before insertion or duplicate acknowledgement,
without echoing input. The existing audit clients retain HTTP 409 in their pending queue, so
changed content is not treated as delivered or automatically dropped. Such conflicts need
operator/caller review and may block ordered replay. This is server-side identity validation,
not cryptographic response binding or native PostgreSQL race verification.
