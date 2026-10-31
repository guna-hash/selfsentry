# Acceptance review — 28 October 2026

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

Owner decisions/deferred work:
- License selection, demo recording and any live archival cutoff.
- Proposed removals remain retained; no deletion is required for completion.

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


Reviewed input: the operator-supplied documentation archive from `fa7ae3b`.
This is a documentation/evidence reconciliation, not a fresh execution or a full
source/security audit. Private results were inspected through supplied terminal
output; no independent access to the operator databases or raw evidence is claimed.

## Ten recorded acceptance criteria

| Criterion | Current assessment | Evidence and boundary |
| --- | --- | --- |
| 1. Inventory | Recorded pass within scope | The 28 October review listed 388 paths; the latest inventory refresh lists 391, with no removals. This documentation-only archive cannot independently rehash every application file or prove equal semantic review depth. |
| 2. Justified removals | Pass within scope | No original files removed; four proposals remain retained. Deletion is not needed to satisfy this criterion. |
| 3. Critical feature flow | Partial | Native gate/Falco, two supervised default-IF rule loops, direct response/recovery and bounded interruption/replay checks are recorded. Representative model quality remains open; specified review/deployment crash cases subsequently passed, while other fault schedules remain untested. |
| 4. Tests executed | Pass for recorded release | Fresh VM: 1,278 Python tests, 104 subtests, 168 frontend tests, lint and scoped types. Later changes covered by this review are documentation only. |
| 5. Build | Pass for recorded release | Fresh Node 24.21.0/npm 11.19.0 build; chart-size warning remains non-blocking, not performance acceptance. |
| 6. Security findings resolved or documented | Pass within that wording | Risks and defaults are documented. This does not mean every finding is repaired, all current advisories were refreshed or the deployment is certified. |
| 7. Reproducible setup | Pass on one supported environment | Independent fresh Ubuntu 24.04.4 installation, new secrets/database, migration/schema match, locked installs, native telemetry and operator browser checks. Manual corrections were necessary; no unattended installer, other-OS or reboot guarantee is implied. |
| 8. Accurate current docs | Pass within reviewed scope | README, configuration-template comments, monitor/gate operations and developer guide were subsequently reviewed against recorded behavior. A fresh-Ubuntu setup guide records verified corrections. This is not a semantic review of every historical document. |
| 9. Final diff reviewed | Pass within recorded diff scopes | Prior uploaded source diff reviews and subsequent operator checks are retained; this pass reviews the supplied documentation changes only. It is not a new review of every application path. |
| 10. Limitations documented | Pass | Accuracy, clocks, storage, worker shutdown, privilege and incomplete fault coverage remain explicit. |

This does not establish ten unconditional passes or complete original-prompt closure.
Criterion 3 remains partial. Recorded passes retain the boundaries above.

## Completed checks that must not be repeated solely because an old table is stale

- Independent clean Linux installation and migration/schema verification.
- Native pause/disconnect/resume and explicit interrupted-resume recovery.
- Bounded gate start/create/remove interruption and current-state reconciliation.
- Keyed audit COMMIT reply loss: actual PostgreSQL CommandComplete withheld,
  committed row independently observed, application uncertainty, identical replay
  deduplication and changed-content refusal.
- Native Falco checkpoint/log replacement; full-monitor Docker connection recovery.
- Normal managed stop (0.393 s) and explicit CLI timeout/PID retention (15.024 s).
- Two supervised rule loops with native re-fire and verified test-rule unloading.
- 30-minute synthetic measurement and prospective calibrated LOF study.

## Remaining engineering and validation

1. **Clock reliability:** recurring faults have no established permanent fix.
   Preserve timestamp observations and invalidate affected captures.
2. **Model quality:** the completed frozen validation exposed false positives
   on all six approved-activity windows. Keep LOF experimental; do not retune
   on inspected validation outcomes or claim malicious-attack recall.
3. **Fault coverage:** the specified review-owner and native deployment/status
   crash cases passed. Other schedules require explicit protocols before
   testing; permanently stalled production workers still lack a completion bound.
4. **Resources and history:** the four-hour measurement is complete. Capacity,
   leak absence, retention limits and native losslessness remain unestablished.
5. **Provenance:** selected installed-package comparisons were performed within
   their recorded scope. These do not establish complete OS/artifact supply-chain
   verification. Preserve version differences and historical evidence.

## Owner decisions and deferred work

- Licensing: the repository currently has no selected license. Adding a license
  requires the owner's choice; a completion script must not choose one silently.
- File deletion and live archive/pruning are deferred. Retaining files is valid;
  no arbitrary cutoff, database rewrite or deletion is needed for a green checklist.
- Demo recording is deferred by the operator. Additional browser/device coverage
  is optional beyond the recorded scope unless the original requirement demands it.
- Multi-user RBAC, Kubernetes, fleet operation, Internet-facing deployment and
  production certification are outside the present host-local academic scope.

Automatic isolation, confirmation, rule candidates and native retirement remain
disabled in the clean-install evidence. None is enabled by this documentation pass.

## Setup-document follow-up

The subsequent setup-document review used the archive from `c9d2551`. It corrected
stale native retirement, PostgreSQL locking, migration and COMMIT-reply-loss wording;
recorded manual Ubuntu setup, Docker group activation and the Falco additive-list fix;
and clarified conservative configuration examples. No application code, active template
settings, private .env, live service or algorithm was changed. Shell/Python syntax,
patch applicability, changed-base refusal and whitespace checks were performed locally.
The procedure's native evidence is the already recorded fresh VM run, not a newly
executed second installation of this prose. Remaining feature gaps retain their scope.
