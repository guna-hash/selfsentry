
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
