# VM verification — 23 October 2026

The cumulative audit changes and follow-up fixes were applied and verified on the VM.

- Release checks: 979 Python tests plus 104 subtests; 165 frontend tests;
  whole-tree lint, types across 81 files, and production build passed.
- PostgreSQL schema comparison matched with no differences.
- Native Docker policy probe passed.
- Falco shell probe reached incident 216; its rule, container and timeline
  were visually verified in the live dashboard.
- The existing Isolation Forest model loaded with 20 baseline samples.
- A restart audit-key conflict was corrected after backing up the queue.
  All four queued records were retained and delivered; backend row 1011 remained.
- Recovery and a subsequent application restart both passed health checks.
  Incident 216's recorded evidence remained unchanged.

## Evidence

- state/evaluation/final-checks-20261023T105620Z/
- state/evaluation/reliability-policy-20261023T092034Z.json
- state/evaluation/reliability-shell-20261023T092037Z.json
- state/evaluation/audit-replay-check-20261023T105419151905Z.json
- state/evaluation/audit-replay-check-20261023T105429926589Z.json

## Remaining acceptance

The audit report's remaining work still applies, including database outage and concurrency testing,
representative load measurements,
isolation/recovery validation, and rule retirement/reconciliation work.
Automatic isolation remains disabled. Full production acceptance is not claimed.

React test warnings and the large frontend chart chunk remain follow-up cleanup.

## PostgreSQL backup and migration verification

PostgreSQL 16.15 acceptance passed on the VM.

- Snapshot backup restored with matching public application rows and schema.
- Adoption on the restored copy preserved application data.
- Fresh migrations matched the ORM schema.
- Native uniqueness, foreign keys, savepoints and rollback passed.
- Repeating upgrade head preserved the temporary database's rows.
- Both temporary databases were removed.
- The active monitor remained healthy with the same PID.

Evidence: `state/evaluation/postgres-acceptance-20261023T112636875366Z/results.json`.

The active database was not migrated or stamped. Outage recovery, concurrent
writers, grants/roles, sequence comparison and full-host recovery remain outside
this check's scope. The database dump is retained privately outside Git.

## Native deployment gate verification

The native gate acceptance run passed all three decisions:
- Allowed Alpine deployment: backend record 7.
- Blocked nginx deployment: backend record 8.
- Explicit nginx override: backend record 9, with the operator reason retained.

The gate scanned immutable image IDs. Backend scan counts matched the gate
results, and registration matched each decision. The blocked container was
removed; allowed and overridden probes were observed running before cleanup.
Running probes used a non-root user, read-only root filesystem, no Linux
capabilities, and no network. Cleanup reported no errors.

Evidence: `state/evaluation/gate-acceptance-20261023T113851Z/results.json`.
Post-probe monitoring was healthy, with no pending registrations and empty
audit and incident queues. Evidence: `post-probe-health.json` in that directory.

This verifies deployment gate behavior; it does not establish image safety
or complete the remaining production acceptance work.
