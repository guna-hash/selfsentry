# Pre-deployment gate (selfsentry-run)

Current acceptance: [review](repository-audit/acceptance-review-20261028.md).
Controlled start/create/remove interruption and explicit observation reconciliation passed;
original uncertain outcomes were preserved. These checks do not establish full scan/policy
crash acceptance, cancellation of an already accepted daemon command or automatic orphan recovery.

## Usage
```bash
bin/selfsentry-run [--override-reason "why"] -- <docker run arguments, without -d>
```
The container is always started detached. Exit codes: 0 allowed or overridden, 1 blocked,
2 Docker failure/timeout or journal/storage error.

## What it does
1. Commit creation intent locally, then run `docker create` with your arguments. Require a
   full 64-character hexadecimal ID and persist that creation result before inspection.
   The container exists but is not running.
2. `docker inspect` it; the result is exactly what the policy checker expects.
3. Trivy scans the immutable Docker image ID and checks the returned report identity,
   then applies the policy check
   (`policy-checker/deploy_policy_validator.py`).
4. Commit action intent to the local SQLite journal, then remove a blocked container or
   start an allowed/overridden container. Persist the outcome; successful completion and
   backend-delivery enqueue share a transaction. Cleanup operations also require journal intent.
5. The decision, the scan summary, the top critical findings and the policy violations are
   recorded in the backend (`deployments` and `scan_results` tables) and shown on the
   dashboard's Deployments page. Blocked deployments are highlighted.

## Safety properties
- Fails closed: failed, malformed, unsupported or mismatched scan output blocks deployment.
  Schema-2 reports with valid image metadata can omit empty results; no finding is invented.
- An admin can override a block with `--override-reason`; the override and its reason are recorded.
- Decisions are written to the local deployment outbox and replayed by the control worker.
  Backend failure delays dashboard visibility. Intent failure prevents the Docker action;
  outcome-write failure leaves explicit uncertainty and requires operator review.
- Failed removal is an error, never a completed block. Failed starts/cleanup have separate
  local outcomes. Failed/unfinished actions are not sent as completed deployment decisions.
- Restart recovery never repeats Docker actions. See [operator recovery](monitor_operations.md#deployment-action-intent-and-recovery).

## Known limitations
- Only deployments made through the wrapper are gated. A plain `docker run` bypasses it; the
  continuous monitor is intended to catch those. System-wide enforcement would need a Docker
  authorization plugin (future work).
- `-d/--detach` is not supported (`docker create` has no such flag).
- Policy checks use the existing four rules (root user, privileged, added capabilities,
  writable root filesystem) plus the image scan verdict.

## Docker command deadlines

The wrapper waits up to 300 seconds for `docker create` (which can pull an image),
30 seconds for inspect, and 60 seconds for start or removal. Trivy separately retains its
300-second scan deadline. These are per-command limits, not a complete workflow SLA.

A timeout terminates the local Docker CLI and returns exit 2. It does not cancel or establish
the Docker daemon's result. Start/removal intents remain `outcome_not_recorded`; no completed
decision is delivered, no retry occurs, and a timed-out start does not trigger forced removal.
A create timeout or malformed success response retains unfinished creation intent and may leave
an unstarted container whose ID the gate never received. A full ID is required; names, short IDs,
empty output and multiple-ID responses are refused without guessing a cleanup target.
Reconcile with Docker evidence before another deployment. Slow image pulls can exceed the
creation limit; the wrapper does not automatically resume them. Normal CLI errors still use
separate failed-command/cleanup paths. Full timeout messages omit potentially sensitive Docker
arguments. Native daemon cancellation, helper process trees and worst-case shutdown bounds
remain unverified.

Creation attempts are separate local history (`creation_attempts`), not deployment decisions.
They retain attempt keys, timestamps, nullable returned IDs and CLI outcomes, without storing
Docker arguments or credentials. Creation success does not prove scan/policy completion,
registration or startup. Unfinished/failed creation counts join the monitor's existing
`deployment_actions` health counts. No restart executor or automatic orphan removal is added.

Gate create/start/removal commands hold a per-attempt file lock before their intent is
committed. Health reports these bounded, live attempts as `active`, without marking
the monitor degraded. The lock must still be held, its metadata must be valid, and its
monotonic deadline must not have expired. That deadline is the command timeout plus
five seconds for intent/outcome persistence. Trivy scanning does not hold an action lock.

An owner exit releases the lock. An exception, timeout, missing/corrupt ownership file,
expired deadline or legacy unfinished intent remains `outcome_not_recorded` and requires
attention. `command_failed` also remains degraded, even while other commands are active.
No intent is automatically repeated, acknowledged, repaired or removed. A successful
completion is rechecked if it races a health read, so releasing its lock cannot create
a false orphan report.

Ownership files contain only attempt keys and monotonic deadlines, under
`state/deployment-action-locks/` (or the configured state directory). Gate and monitor
must use the same local state directory and Unix account. Normal completion/exception
cleans up the file; a hard kill can leave an unlocked file, which is not treated as active.
The SQLite schema, journal keys, payloads, timestamps and outcomes are unchanged.

### Read-only journal inspection

From the repository root, with its Python dependencies installed:

```bash
bin/selfsentry-run --inspect-journal --limit 50 --offset 0
```

Use the same `SELFSENTRY_STATE_DIR` environment as the gate/monitor (default: repository
`state/`). This command reads an existing `deployments.sqlite`; a missing, corrupt or older
incompatible schema returns exit 2 without initialization or repair. It opens SQLite in
read-only mode and reads counts and rows within one transaction. SQLite may still use WAL
shared-memory sidecars; this is not a forensic acquisition tool or a byte-immutable filesystem
operation. Protect the output: attempt keys, container IDs and timestamps are operational data.

The JSON contains up to 200 creation/action records per page, their known full IDs (nullable for
creation), recorded outcomes and timestamps, plus aggregate outcome counts, queued decisions
excluding retained rejections, and the total retained rejection history. Decision/rejection
bodies, override reasons, image configuration and Docker arguments are omitted. `has_more`
indicates another page. Offset pagination is stable for an unchanged journal; concurrent writes
can shift later pages. Each invocation is a new snapshot, not a stable multi-page export.

`outcome_not_recorded` can mean still running, interrupted, timed out or failed outcome storage.
`command_succeeded` describes the recorded CLI result, not current Docker state. Creation success
alone proves neither gate completion nor container startup. No automatic action, backend call,
acknowledgement, outcome edit, retry, registration or cleanup occurs during inspection. Normal
Docker argument forwarding after `--` is preserved.

To investigate an uncertain action, retain the output, check whether the original gate process
is still running, and inspect current Docker state using the exact known full ID. A missing
creation ID cannot safely identify an orphan by guessing a name or short ID. Compare deployment
and audit history with local evidence before deciding on a new action; do not infer a previous
scan/policy approval from current runtime state. This command supplies evidence, not automatic
reconciliation or approval. Reviewed current-state observations are available through the
tracked reconciliation tools and preserve the original outcome. Retention, broader native
crash recovery and automated safe remediation remain open work.
