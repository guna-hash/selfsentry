# Acceptance review — 28 October 2026

Reviewed input: the operator-supplied documentation archive from `fa7ae3b`.
This is a documentation/evidence reconciliation, not a fresh execution or a full
source/security audit. Private results were inspected through supplied terminal
output; no independent access to the operator databases or raw evidence is claimed.

## Ten recorded acceptance criteria

| Criterion | Current assessment | Evidence and boundary |
| --- | --- | --- |
| 1. Inventory | Recorded pass within scope | Inventory now lists 388 paths with no removals. This documentation-only archive cannot independently rehash every application file or prove equal semantic review depth. |
| 2. Justified removals | Pass within scope | No original files removed; four proposals remain retained. Deletion is not needed to satisfy this criterion. |
| 3. Critical feature flow | Partial | Native gate/Falco, two supervised default-IF rule loops, direct response/recovery and bounded interruption/replay checks are recorded. Representative model quality and broader review/deployment failure coverage remain open. |
| 4. Tests executed | Pass for recorded release | Fresh VM: 1,278 Python tests, 104 subtests, 168 frontend tests, lint and scoped types. Later changes covered by this review are documentation only. |
| 5. Build | Pass for recorded release | Fresh Node 24.21.0/npm 11.19.0 build; chart-size warning remains non-blocking, not performance acceptance. |
| 6. Security findings resolved or documented | Pass within that wording | Risks and defaults are documented. This does not mean every finding is repaired, all current advisories were refreshed or the deployment is certified. |
| 7. Reproducible setup | Pass on one supported environment | Independent fresh Ubuntu 24.04.4 installation, new secrets/database, migration/schema match, locked installs, native telemetry and operator browser checks. Manual corrections were necessary; no unattended installer, other-OS or reboot guarantee is implied. |
| 8. Accurate current docs | Partial | Authoritative status and historical labels are reconciled here. Root README and other operational documents still need a focused wording/setup review; they were not included in this archive. |
| 9. Final diff reviewed | Pass within recorded diff scopes | Prior uploaded source diff reviews and subsequent operator checks are retained; this pass reviews the supplied documentation changes only. It is not a new review of every application path. |
| 10. Limitations documented | Pass | Accuracy, clocks, storage, worker shutdown, privilege and incomplete fault coverage remain explicit. |

This does not establish ten unconditional passes or complete original-prompt closure.
Criteria 3 and 8 remain partial. Recorded passes retain the boundaries above.

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

1. **Clock reliability:** fresh probes pass after recovery, but recurring event-time
   skew has no established permanent cause or fix. Keep freshness observations and
   invalidate affected evaluations. Bridged networking is not proof of remediation.
2. **Model quality:** the default IF produced substantial benign flags. LOF's 0/6
   benign and 4/4 controlled-deviation result is promising but small and synthetic.
   Keep it experimental; use new prospectively labelled workloads and fixed policy
   before any promotion. No malicious-attack recall or production FPR is established.
3. **Review/deployment failure coverage:** native locking was already tested across
   commits and exceptions. Specific remaining cases should be enumerated before new
   tests: owner termination after approval but before deployment; applied native
   state before durable final status; competing approval/rejection during that
   interval. These are proposed test boundaries, not newly reproduced defects.
4. **Worker shutdown/resources/history:** CLI timeout does not bound a running
   worker's completion. Thirty-minute measurements do not establish capacity,
   memory-leak absence, long-duration storage bounds or a safe archival cutoff.
5. **Documentation/provenance:** review the current README/setup instructions and
   remaining source findings against this status. Preserve failures and distinguish
   original-host results from fresh-host results and differing tool versions.

The remaining tests require concrete protocols, bounded owned resources and stated
outcomes. Do not demand every possible fault or repeatedly rerun passing checks.

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
