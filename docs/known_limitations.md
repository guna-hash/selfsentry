
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
