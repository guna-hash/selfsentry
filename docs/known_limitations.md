
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
