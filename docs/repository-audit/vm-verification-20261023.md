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

The audit report's remaining work still applies, including native database
backup/restore and migration testing, representative load and concurrency,
isolation/recovery validation, and rule retirement/reconciliation work.
Automatic isolation remains disabled. Full production acceptance is not claimed.

React test warnings and the large frontend chart chunk remain follow-up cleanup.
