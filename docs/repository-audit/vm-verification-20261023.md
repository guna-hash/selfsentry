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

## Native concurrency verification

PostgreSQL concurrency checks passed in one freshly migrated temporary database:
- Eight matching audit deliveries retained one row and acknowledged the same ID.
- Changed-content deliveries under the same key received strict conflicts.
- Later matching replay retained the original event timestamp.
- Eight workers recorded 80 rule outcomes without lost increments:
  one performance row, 40 true positives and 40 false positives.
- The review guard held its native advisory lock across commits, rejected an
  independent contender, and released after normal completion and exceptions.

The temporary database was removed. The live monitor remained healthy with the
same PID. No active application rows, source files, services or Falco rules were
changed by the runner.

PostgreSQL evidence: `state/evaluation/postgres-concurrency-20261023T115131568870Z/results.json`.

The separate HTTP read measurement completed 100 requests with four paced
concurrent readers and no errors or unhealthy responses. Latency was
17.818 ms median,
33.660 ms p95 and
154.638 ms maximum.
The monitor PID remained unchanged and both delivery queues were empty afterward.

HTTP evidence: `state/evaluation/api-read-concurrency-20261023T114258Z/results.json`.

These results verify the exercised database races and a small local HTTP read
workload. Full review/deployment interleaving, database outage recovery,
sustained event load, memory bounds and shutdown deadlines remain open.

## Gate command health and workload verification

Gate commands now hold bounded per-attempt ownership locks. Live owned commands
are reported as active. Failed, expired or unowned unfinished attempts continue
to require attention; no uncertain Docker action is automatically repeated.
Journal schema, recorded outcomes and retained evidence are unchanged.

The corrected native workload passed with all sampled phases healthy:
200 true commands plus 200 pacing sleeps completed in
43.218 seconds. All 328 concurrent
HTTP reads succeeded; p95 latency was 67.958 ms.
Sampled delivery and event queues stayed empty. Cleanup succeeded, and the
existing ready-model status was preserved.

| Application process tree | Peak RSS MiB | CPU p95, 100% = one core |
| --- | ---: | ---: |
| backend | 110.969 | 60.728 |
| monitor | 170.750 | 24.685 |
| frontend | 20.191 | 0.000 |

RSS may double-count shared pages; these totals exclude external services and
the container. Global Falco and baseline counters each increased by 1,222,
with no additional unusable events. This does not establish zero event loss.

Successful evidence: `state/evaluation/workload-check-20261023T132729374158Z/results.json`.
Both earlier failed runs remain retained:
`workload-check-20261023T120741646497Z` and
`workload-check-20261023T125503160340Z`.

Final VM release checks passed: Python, lint, types, frontend tests and build.
Evidence: `state/evaluation/final-checks-20261023T133247Z/results.json`.
Post-release health verification also passed, including the existing model,
incident 216 fingerprint and original audit row 1011.

Sustained capacity, retention bounds, memory-leak assessment, shutdown deadlines
and native crash/operator reconciliation remain open.

## Verified SQLite journal export

Native export and complete table readback passed on 2026-10-23.
SQLite integrity and independent single-file readback passed.
The monitor remained healthy with the same process.

The snapshot contains 15,408 events, 358 windows, 184 outbox records,
184 actions, 26 lifecycle records and 43 rejected events.
Export size: 37,158,912 bytes.
SHA-256: `53f017d94b54c49d239701ad00bc6d6d64a4185b79a48e3482027db814c99b06`.

Private evidence: `~/selfsentry-journal-exports/20261023T140227781080Z-9f0b998d/manifest.json`.
No live rows were deleted or changed. No service restart was performed.
This verifies journal export integrity; automatic retention, pruning and
whole-application restore acceptance remain open.
