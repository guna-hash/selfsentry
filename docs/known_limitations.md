# Known limitations and evidence history

Updated 15 October 2026. M1–M4 implementation and controlled VM checks are recorded;
M5 full-run measurements and retrospective comparison are delivered. See
[monitor_final_review.md](monitor_final_review.md) and [TODO.md](../TODO.md).
Historical entries below retain the original observations and dates.

## Academic claim boundaries — 15 October 2026

SelfSentry is a hybrid container runtime security system that combines Falco rule matching with per-container behavioral anomaly detection, correlates both into incidents, and converts confirmed anomalies into template-generated, backtested, human-approved Falco rules — demonstrating a supervised adaptive detection loop under controlled evaluation.

- The 16 October extension adds template proposals from ready-model anomalies that
  retain a literal syscall witness; aggregate-only anomalies remain unsupported. The
  new path has local regression coverage and still needs live acceptance. The earlier
  study's synthesis required Falco-backed process metadata. The thesis's confirmed-anomaly loop
  is scoped to representable patterns; no ML-only discovery path is claimed.
- Process/parent templates discard file/TTY context and apply across containers.
  Corpus backtesting estimates an event-level match rate for the supported shape,
  not a production false-positive rate or a complete native-engine replay.
- The frozen 200-trial comparison adds three benign detections and no additional
  labeled attack detections over stored Falco flags. Independent live ablations
  remain unrun. The separate 15 October rule-loop study now supports one native
  approved re-fire chain, not additional coverage.
- The opt-in SVM produced anomaly-only incidents on two of four valid benign windows
  (195/196); it remains experimental. See svm_benign_validation_20261013.md.
- Recurring Falco timestamp skew invalidated 19 windows of the earlier SVM batch.
  Restart restored accuracy temporarily; the root cause/permanent fix is unresolved.
  A healthy process heartbeat does not establish correct event timestamps.
- The reviewed 15 October study completed one approved native re-fire chain and
  one explicit rejection. Two other pattern previews failed backtests; actual failed
  submissions and their after-runs were not performed. Three later benign windows
  were clean, but calibration retained IF false-positive incident 199. See
  academic_results_20261015.md; no additional coverage was demonstrated. C2 is deferred.
- Future academic work prioritizes representative baselines, controlled layer
  comparisons and richer supported pattern extraction. Fleet/commercial features
  mentioned in older documents are outside the present thesis, not requirements.


## Current release gaps

- A1/A2 operator VM acceptance passed on 2026-10-12; see TODO.md for report names.
- Automatic-response attempts 185–187 were correctly declined by existing policy.
  The 20-window baseline has only seven distinct vectors; forest boundary saturation
  gives identical low scores for single/burst binary execution. An opt-in One-Class
  SVM candidate is implemented. Controlled automatic isolation/resume passed on the VM
  for incident 190; independent benign/general response validation remains open.
  See anomaly_model_review.md; default Isolation Forest remains unchanged.
- Default shell feature mapping is fixed in the monitor scoring path when Falco
  supplies a known shell process name. Missing process metadata remains uncredited;
  its security alert is still delivered. Standalone baseline capture remains limited
  to Baseline rules. Existing measured results predate this change; no rerun is claimed.
- Observed timelines persist in monitor evidence and render on Alerts. Older
  incidents are not backfilled. The advisory LLM attack_timeline_builder remains
  disconnected; its narrative output is not claimed as persisted.
- Real direct isolation/resume and controlled SVM automatic isolation/resume are
  recorded in reliability_acceptance_20261013.md. Automatic response was demonstrated
  for one configured scenario, not across models/workloads or production conditions.
- Production RBAC, Kubernetes, automatic retraining, retention, soak testing,
  independent live comparison variants and detailed stage timings remain future work.
- A known rule description does not prove an attack; shell access can be benign.
  Shared-token auth is for local demo use. AI is optional and advisory.

## Resolved items (historical evidence)

- /confirm persistence: fixed in backend routes and covered by ORM tests; original
  2026-10-01 gap below is historical.
- Generated-rule re-fire: resolved with rule_matching: all on 2026-10-08;
  see falco_rule_matching.md. Earlier investigation text is historical.
- Direct live isolation: paused and disconnected a real container on 2026-10-01;
  later isolation/resume acceptance is recorded in monitor_final_review.md.
- Default shell counting: source fix and regression tests added 2026-10-12.

## Historical findings

## Phase 4 — shell_spawned_count does not detect default-ruleset shell alerts (found 2026-09-30)

During Sep 30 re-validation, live scoring correctly flagged windows as anomalous
overall, but the `shell_spawned_count` feature stayed 0 even when a real
`docker exec -it <container> sh` session was confirmed firing Falco's default
"Terminal shell in container" rule. Root cause: `feature_extractor.py`'s
shell-detection only increments on `EventType.PROCESS_SPAWN` events whose
`proc_name` is in `SHELL_PROCESS_NAMES` — this path is fed by our custom
`Baseline Process Spawn` rule, not by Falco's default "Terminal shell in
container" rule, so that alert type is never classified as a process-spawn
event for feature-extraction purposes. It still contributes to
`total_event_count`, so its presence is not lost, but it is not specifically
credited as a shell-spawn signal.

Separately, this session's baseline for '12160024642b' still shows the model
scoring both idle and active windows as anomalous at a small sample size (24
windows) — plausibly an artifact of the small, narrow baseline rather than a
detection failure, since real event volume (148-218 events/window) was clearly
present and varied across windows. A larger baseline capture (Phase 10 scope)
is the planned fix; flagging honestly rather than presenting this as fully
resolved.

Planned fix (Phase 10 or as time allows): extend the Falco-alert-to-Event
classification step to map "Terminal shell in container" (and other relevant
default rules) onto EventType.PROCESS_SPAWN with proc_name populated, and
recapture a larger (60+ sample) baseline before final evaluation.

## Phase 5 — confidence tier comment mismatch (found 2026-09-30)
validate_pipeline.py's Scenario 2 comment states confidence should be
"medium" for a strong Falco-only alert, but actual output shows
confidence="low". Either the comment or the threshold needs revisiting;
not yet investigated further, flagged during Sep 30 validation.

## Phase 6 — auto-generated rule deployment mechanism verified, live re-fire not yet reproduced (2026-10-01)

rule_deployer.py was tested end-to-end against real Falco: a candidate
rule (Auto_Generated_ls_from_sh_8, condition: spawned_process and
proc.name="ls" and proc.pname="sh") was written to
falco-rules/auto-generated-rules.yaml, validated as YAML, and Falco was
reloaded — confirmed via journalctl showing
"auto-generated-rules.yaml | schema validation: ok" with no errors.

A subsequent manual trigger (docker exec -it selfsentry-test sh, then
ls) produced the exact matching Baseline Process Spawn event
(proc_name=ls parent_proc_name=sh) in the real Falco log, but the
Auto_Generated_ls_from_sh_8 rule itself was not observed firing in the
same log window. The deployment mechanism (write + validate + reload)
is confirmed working; the condition syntax (likely proc.pname field
naming or a macro/output-format detail) needs further comparison
against Falco's own default rule syntax. Not yet root-caused due to
time constraints — flagged honestly rather than claimed as fully
working. Planned follow-up: compare against a known-working default
Falco rule's exact condition syntax for parent-process matching.

## Phase 8 backend — /confirm endpoint does not persist to confirmed_incidents (found 2026-10-01)

POST /incidents/{id}/confirm returns {"status": "confirmed", ...} but
does not insert a row into confirmed_incidents, and the incidents
table has no status column to reflect confirmation either — the
confirm action appears to not be persisted anywhere in Postgres.
This blocks the natural confirmed_incidents -> generated_rules chain
from being populated by that endpoint alone.

Workaround used for Phase 6 testing (2026-10-01): manually inserted a
confirmed_incidents row (incident_id=8, confirmed_by='guna') and a
generated_rules row (confirmed_incident_id=1, the deployed
Auto_Generated_ls_from_sh_8 rule, backtested_fp_rate=0.0191) directly
via psql, to validate rule_lifecycle_manager.py's TP/FP tracking
end-to-end. rule_performance correctly tracked true_positives=1,
false_positives=1 and flagged the rule for retirement review (50% FP
ratio >= 0.5 threshold).

This is backend-api (Phase 8) scope, not Rule Synthesis Engine (Phase
6) scope — flagging for the joint Phase 10 integration pass.

## Phase 6 — deployed auto-rule compiles and is enabled but has not been observed firing (updated 2026-10-01)

Extensive investigation performed: confirmed via `falco --list` output that
Auto_Generated_ls_from_sh_8 compiles correctly (condition_compiled:
"proc.name = ls and proc.pname = sh", enabled: true), confirmed no rate-limit
config or drop/throttle log entries in falco.yaml or journalctl, confirmed
the rule loads with schema validation: ok on every restart. Despite this,
manual retriggering of the exact matching behavior has not produced a visible
Auto_Generated_ls_from_sh_8 alert in the JSON output log, even though the
underlying Baseline Process Spawn event for the same action fires correctly
in the same log window.

Root cause not identified as of 2026-10-01 despite investigation into: rule
condition syntax (ruled out), file loading (ruled out), rate limiting (ruled
out), restart vs reload (ruled out). Remaining hypotheses for future
investigation: Falco's internal rule-priority/early-exit behavior when
multiple rules share overlapping conditions on the same event; a possible
interaction with the high alert volume from baseline-capture rules.

This does not invalidate the core deployment mechanism, which is fully
verified: write, YAML validation, Falco reload, and successful rule
compilation are all proven working end-to-end on real infrastructure.

## Phase 10 — auto_isolate.py live verification (2026-10-01)

isolate_container() tested against a real running container
(isolate-test-victim, nginx:1.25), not just the not-found failure case.

Before isolation: confirmed real outbound network access (curl to
google.com returned HTTP 301).

After calling isolate_container(): container state changed to "paused",
NetworkSettings.Networks returned {} (fully disconnected), and a direct
docker exec attempt was refused by the Docker daemon itself ("Container
is paused, unpause the container before exec") - independent
confirmation of the pause state, not just our own code's claim.

Forensic state preserved as designed: container was not stopped or
removed, only paused + network-isolated, so its process/filesystem
state remained inspectable throughout.

## Phase 6 — RESOLVED (2026-10-08): non-firing auto-generated rule was shadowed by Falco `rule_matching: first`

The two earlier Phase 6 entries above (2026-10-01) are kept as investigation history.
Root cause: Falco 0.45.0 defaults to `rule_matching: first`, so the catch-all
`Baseline Process Spawn` rule (loaded first) stopped evaluation for every container
process spawn and the auto-generated rules never ran. With `rule_matching: all`, the
same `ls`-from-`sh` action fires `Auto_Generated_ls_from_sh_8` at the same timestamp as
the baseline rule (2026-10-08 07:35:10 UTC). Full evidence and fix: docs/falco_rule_matching.md.
Remaining caveat: `all` may carry a performance cost per Falco's own docs; not yet measured.
