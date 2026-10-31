# Current limitations

SelfSentry's delivered academic scope is complete; it is not production
certification. This page summarizes active limits, including the API access, pagination and CI
follow-up to source commit `ffc686e`, and the recorded operator evidence. It does not report new native tests.
The [historical limitations](archive/known_limitations_history.md) retain the
original findings and failed attempts. Detailed results and their boundaries
remain in the [repository audit](repository-audit/report.md) and
[acceptance review](repository-audit/acceptance-review-20261028.md).

## Detection and model quality

- Representative accuracy across workloads and legitimate behavior changes
  remains unestablished. Small synthetic studies do not establish production
  false-positive rates or added attack coverage beyond Falco. The original
  200-trial comparison added benign detections, with no extra labeled attack
  detections over the stored Falco flags.
- Isolation Forest remains the default. Experimental candidates have not
  replaced the live model. Frozen cross-VM validation flagged all six approved
  uptime windows with LOF; controlled deviations are not malicious attacks.
- Rule synthesis supports template-representable literal witnesses, rather than
  arbitrary aggregate anomalies. Process/parent templates lose file/TTY context
  and apply across containers. Backtesting measures event matches in the supplied
  corpus, not complete native-engine replay. Human approval remains required.
- Missing process metadata limits shell-feature attribution. Older incidents
  are not backfilled; optional LLM narration is advisory.

## Event clocks and capture

Recurring event-clock faults have no established permanent fix. The configured
boot synchronization mitigation passed one recorded reboot; it is host setup,
not automatically installed by cloning. Unavailable NTP can delay Falco startup.
Later suspension and other fault schedules remain outside that result. A healthy
heartbeat does not prove timestamp correctness or lossless capture. Unread data
in a replaced or truncated log can be lost; invalidate clock-affected captures.

## Recovery, shutdown and deadlines

- Docker, local journals, PostgreSQL and native rule publication are not one
  atomic transaction. Lost replies and interrupted actions can retain unknown
  outcomes; operator reconciliation or explicit retry may be necessary.
- Container pause/disconnect/resume checks do not guarantee continuous
  containment through a hard crash or unreachable Docker daemon. Resume unpauses
  before restoring networks. Automatic isolation remains disabled by default.
- A controlled stalled-worker release passed, but permanently blocked workers
  lack a guaranteed shutdown completion deadline. Connection/pool timeouts do
  not bound all SQL, lock waits, established-socket waits or complete requests.
  Startup still creates missing tables; schema upgrades require Alembic migrations.
- Keyed audit replay checks do not establish idempotency for every endpoint.
  Keyless historical events, timestamps outside backend replay identity,
  acknowledgements without cryptographic content binding, corrupt-record repair,
  storage/power failures and untested process schedules retain their boundaries.
  See [monitor operations](monitor_operations.md) and
  [deployment reconciliation](deployment_gate.md#read-only-journal-inspection).

## Storage and capacity

History retention has no automatic age cutoff or purge. Manual baseline archival
covers eligible closed-window payloads, not every alert, outbox or action record;
health does not continuously attest to archive integrity. The larger export and
archive-on-copy checks did not archive or prune the live journal. See
[journal archives](journal_retention.md).

The completed four-hour synthetic measurement does not establish representative
capacity, leak absence or indefinite storage safety. Native drop counters were
not collected for that run, so it is not a zero-loss result.

## Access and deployment

Protected reads and writes use one shared bearer token, without per-person roles
or verified actor identity; `confirmed_by` is an operator-supplied label. The root
service probe and CORS preflights are public. Localhost CORS is not authentication.
Incident history is paginated, but API rate limiting remains absent. Dashboard
filters and Overview metrics operate on explicitly bounded incident windows.
Keep the backend bound to localhost; Docker socket access grants powerful host
privileges. Multi-user, fleet and Kubernetes operation are outside this release.
CI runs isolated tests/builds, not native host acceptance. No project license has
been selected.

## Completed checks and remaining boundaries

The following are recorded passes, not pending tasks solely because an older
historical paragraph says otherwise:

- Independent supported-Ubuntu installation and migration/schema verification.
- Scoped native rule re-fire, response/recovery, gate interruption, PostgreSQL
  keyed audit COMMIT-reply loss, and review/deployment process-crash checks.
- [Four-hour synthetic measurement](repository-audit/report.md#completed-four-hour-resource-measurement--31-october-2026)
  and [frozen cross-VM candidate evaluation](repository-audit/report.md#frozen-candidate-cross-vm-validation--30-october-2026).
- [One-reboot boot synchronization check](repository-audit/report.md#falco-boot-synchronization-mitigation--31-october-2026);
  [larger journal export](repository-audit/report.md#larger-journal-export-acceptance--31-october-2026)
  and thirteen disposable-copy archive checks, with no live archival.
- Repository cleanup and runtime/development dependency separation. The operator
  reported 1,292 tests plus 104 subtests passing for the dependency update.

Recorded scope is not exhaustive fault coverage, whole-application restore
acceptance or complete OS/artifact supply-chain verification. Private raw
operational evidence remains outside Git. The API/CI follow-up does not change
models, thresholds, response settings or the delivered detection scope.
