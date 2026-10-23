# Late-alert baseline review and recovery

A late alert is an alert for an event window that the monitor already closed.
Previously, every such alert removed the in-memory model and persisted
`requires_review=true`. That included alerts for windows long after the baseline
had been collected. Restarting kept the hold; neither waiting for more events nor
restarting restored the existing 20-sample baseline.

The updated handler loads and validates the container's current dataset, then
checks overlap between the alert window and every training window. Intervals are
half-open: an alert starting exactly at the end of the last training window is
outside the baseline. An overlapping alert still revokes readiness. Missing,
malformed or invalid previously recorded samples also fail closed. A late alert
outside training retains its incident/outbox entry and `LATE_EVENT` audit, with
`event_timestamp` and `training_overlap` details, without revoking readiness.
An existing hold is never cleared automatically by this handler.

## Explicit operator review

`monitor_service.py --review-baseline CID` is a separate operator action requiring
`--reviewed-by`, `--reason`, and one or more `--evidence-key` arguments. It cannot
run while another monitor holds the exclusive lock. It loads the repository's
`.env`, while retaining explicitly exported settings, just as the host manager does.

The review validates container ownership, window lengths, duplicate windows,
finite/nonnegative feature values, sample count, learning duration, and feature
variation. It scans **all** security alerts in that container's durable journal,
not only the nominated witnesses. Any alert window overlapping training refuses
restoration. All nominated late-alert keys must exist for the same container,
have consistent timestamps/buckets and have closed windows. Missing or malformed
evidence refuses restoration. Other failure reasons are not review overrides.

A real fit and score probe must succeed before removing the review hold. The
baseline JSON is checked byte-for-byte after fitting; it is never rewritten.
Before updating lifecycle state, the tool saves the original baseline, a SQLite
backup of the journal/lifecycle, and a review report under
`MONITOR_STATE_DIR/baseline-reviews/<review-id>/`. The lifecycle retains the human
review metadata and original dataset SHA-256. `BASELINE_REVIEWED` and lifecycle
transition audits are sent or durably spooled for delivery after backend restart.

The backup contains operational event data: retain it locally with the other
runtime state, rather than committing it to Git. No checkpoint, event history,
incident, rule, deployment or response record is cleared.

## Scope of the evidence

Audit `occurred_at` is when the monitor processed the alert; it is not the original
Falco event timestamp. Recovery reads the journaled event timestamps. This check
establishes no *recorded event-time overlap* and successful model validation. It
does not establish that the baseline is benign, that journal history is complete,
or that Falco's clock is correct. The operator still decides whether the retained
baseline is an appropriate reference. Previously recorded clock discontinuities
remain a separate issue; do not rewrite event times or widen tolerances to hide
those faults. `MODEL_READY` is not an end-to-end telemetry health attestation.

## Apply and operate on the VM

Apply the patch with `git apply --check` before `git apply`; do not overwrite local
conflicting changes. Run the supplied regression tests. Stop the managed app
processes with `bin/selfsentry stop` before review. Docker, PostgreSQL, Falco and
workload containers remain running. Run the review with actual event keys from
`LATE_EVENT.detail.event_key`, then run `bin/selfsentry start` whether review was
accepted or refused. Never remove the review flag manually.

For the operator's reported container `12160024642b`, the retained dataset has
20 windows spanning 2026-10-11 08:49:00–09:09:00 UTC. Audit 961 records the
revocation on 22 October; audits 962/969/989/995 identify four late-alert witnesses:
`6e12cbfb628196460471`, `17411949a75199bb02f8`, `f94dffda298a3ac95d44`,
`9930775d3b24ad2169ac`. Their actual event times must be checked in the VM journal
by the review command; the supplied audit excerpts alone do not prove non-overlap.
No VM recovery outcome is claimed by this implementation's local tests.

After startup, check `/monitor/status` for the target's state, review metadata and
sample count, then check the Models page in live mode. If review was refused, keep
the error and backup/evidence paths for diagnosis. Training data that actually
contains security events requires a deliberate clean recapture rather than this
review path.

Validation: full Python suite 568 passed plus 7 subtests; changed monitor/recovery
code and the added tests passed flake8. Tests exercise overlap boundaries,
late-incident preservation, invalid/missing baselines, legacy holds, missing and
malformed evidence, unrelated failures, explicit identity, failed model probes,
concurrent baseline changes, backup/audit behavior, monitor locking, CLI recovery
and restart persistence. Frontend source and dependencies were unchanged.
