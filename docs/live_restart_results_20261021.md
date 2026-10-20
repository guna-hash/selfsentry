# Reviewed pending-incident restart result — 21 October 2026 (IST)

**PASS-E for this one controlled graceful application restart during a PostgreSQL
outage.** The operator ran the VM helper and supplied `evidence.json`. The reviewer
checked the supplied JSON offline; the reviewer did not operate the VM or query its
database independently. This result does not close other unperformed fault cases.

## Identity and provenance

| Item | Recorded value |
|---|---|
| Source HEAD | `f134fdc5ed185124a9cf5ab1cb4c0164b326a77d`, dirty tree including the restart helper patch and documentation |
| VM report | `state/evaluation/acceptance/selfsentry-db-recovery-72bc7953/evidence.json` |
| Supplied report SHA-256 | `409e1241893ed29eeb81528e8e6356089452a94138433adfbe6d4a3d8ce1c65e` |
| Fixture | `selfsentry-db-recovery-72bc7953`, container `3c460bf6389a` |
| Durable event key | `abc4b0ec48a72561eb33e66c37f0e06594a73245` |
| Recovered incident | `208` |
| Monitor PID before / after | `74792` / `104301` |
| Falco PID before / after | `97337` / `97337` |
| Generated-rule SHA-256 before and after | `99ad05160795da3d62787cbd39af3d648821cd2385a21f43f5f5eabcce3425a4` |

The source HEAD is not an exact runtime source archive: the working tree was dirty.
The supplied file contains the helper's snapshots, raw Falco record embedded in the
payload and reported cleanup results. Separate lifecycle logs, standalone clock
files and final Docker inspection/log files were not included in this upload.
The full evidence directory should remain intact on the VM.

## Recomputed checks

The reviewer compared payloads and identifiers rather than relying solely on the
report's final `passed` boolean. The following are consistent in the supplied data:

- Before stopping applications, the incident had failed delivery once, was pending,
  and had no backend incident ID. After the stop it was still pending under the same
  key, with an identical full payload; attempts had increased from one to two.
- The recorded post-recovery query contains one matching incident, ID 208. Its full
  `monitor_evidence` equals the queued evidence, including the nonempty observed
  timeline. The outbox row is `done`, references 208 and retains two attempts.
- The embedded raw Falco record identifies `Terminal shell in container`, target
  `3c460bf6389a`, process `sh`, parent `containerd-shim`, native time
  `2026-10-20T19:10:58.036261369Z`. That event lies between the report's database-stop
  and database-restoration timestamps and remains unchanged in the after timeline.
- The monitor PID changed and the resulting status is running/healthy. The Falco
  PID and generated-rule hash are unchanged. Incident and audit spool counts are
  zero in the recorded after-status snapshot.
- Fixture clock preflights before/after each recorded 18 events, passed with zero
  observed out-of-window distance and the existing two-second tolerance. The
  endpoint realtime-minus-monotonic difference changed by approximately zero;
  this interval does not validate a future VM pause/resume cycle.
- Confirmation remained unconfirmed, response was not attempted, and candidate
  synthesis was skipped. The report records PostgreSQL and managed applications
  running at cleanup and removal of the disposable fixture.

The helper made a second duplicate query after five seconds. This is bounded
duplicate checking, not an indefinite exactly-once delivery guarantee. Service
transition timestamps and the timezone-naive incident `created_at` are not used to
claim detection, transaction-commit or recovery latency.

The fixture was still LEARNING, with no anomaly features or qualifying model
assessment. This is Falco-backed functional reliability evidence, not a two-layer
agreement, model-quality, new attack coverage or automatic-isolation experiment.
The optional AI explanation is advisory and was not an acceptance oracle.

## Remaining scope

This supports one live mid-flight *graceful* managed application restart, combined
with a PostgreSQL outage and durable incident replay. Crash/SIGKILL, host power
loss, disk-full, rotation, VM resume and other unperformed fault extensions remain
NOT RUN. The recurring same-boot guest clock-discontinuity issue remains OPEN.
The operator confirmed that incident 208's timeline is visible after dashboard
refresh. This is an operator-reported UI check, not independent browser operation.

## Subsequent release verification

The VM release checks passed: 538 Python tests plus 7 subtests, lint,
150 frontend tests, and the production build.
Evidence: `state/evaluation/final-checks-20261020T193551Z`.
The earlier failed run is retained at
`state/evaluation/final-checks-20261020T192830Z`.
The test fix explicitly checks enabled and disabled auto-confirm policy;
it does not enable automatic confirmation in the running study configuration.

See [helper procedure](live_restart_acceptance.md) and the
[designed-case matrix](academic_case_matrix.md). Historical 200-trial and 15 October
mini-study results are unchanged and are not pooled with this reliability case.
