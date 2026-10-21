# Acceptance follow-up — 21 October 2026 (IST)

This records operator-supplied VM console results from 20–21 October IST and an
offline review of the supplied `browser-review.tar.gz`. The reviewer did not
operate the VM or Firefox directly. Raw runtime artifacts remain on the VM;
console excerpts do not establish independent review of their complete contents.

## Recurring clock fault

| Observation | Evidence / value |
|---|---|
| Initial invalid preflight | `state/evaluation/fresh-clock-1g6yfeln/clock-check.json`; 18 events, maximum out-of-window distance 279383.858 s |
| Preserved diagnostics | `state/evaluation/clock-diagnostics-EtW24l8J/`; keep the interrupted second collection `clock-diagnostics-DT8GvcZx/` too |
| Version report | Falco 0.45.0, libs 0.26.0, driver 11.0.0, Ubuntu VMware kernel 7.0.0-38-generic |
| Recovery checks after Falco restart | `state/evaluation/clock-recovery-G5mect8j/clock-check-1.json` and `clock-check-2.json`; 18 events each, zero observed out-of-window distance; about 31 s apart |
| Monitor after recovery | `monitor-after-r8iuov4w.json` in that recovery directory; healthy, 54 baseline events/lines, two processed windows, empty incident/audit queues |
| Target after recovery | `12160024642b`, MODEL_READY, isolation_forest, 20 samples; byte-for-byte baseline hash retention was not checked |
| Recurrence | `state/evaluation/clock-followup-76sl7jq7/clock-check.json`; 18 events, maximum out-of-window distance 73209.747 s, failed |
| Clock-offset comparison | `state/evaluation/clock-recurrence-10rzfhbm.json`; realtime-minus-monotonic increased by 73209.95512270927 s relative to `runtime-clock-yxr38e6i.json` in the first diagnostics directory |
| Boot identity | Earlier journal ID `790446659f3b486abecb1ed8859a147c` equals current `79044665-9f3b-486a-becb-1ed8859a147c` after removing hyphens |

The recurrence's measured skew and wall-minus-monotonic change differ by about
0.208 s. The preflight measures distance outside a host-clock interval, not a
single instant offset, so exact equality is not expected. These observations
strongly link the stale Falco event timestamps to a same-boot guest clock
discontinuity. A stale event-time conversion offset is the working mechanism;
the exact upstream code path has not been established. Guest NTP reporting
"synchronized" does not establish correct Falco event timestamps.

The precise initiating event (VMware suspend/resume, host sleep, snapshot restore,
or another clock correction) has not been confirmed by the operator or a
correlated lifecycle trace. Equal BOOTTIME and MONOTONIC readings do not alone
identify that event. Falco initially starting before NTP synchronization is also
recorded, but startup ordering alone cannot explain or fix the later recurrence.

Status: clock-discontinuity association diagnosed; permanent correction and
resume-cycle validation OPEN. Restart has demonstrated temporary recovery only.
Preserve failed runs and use a new directory for every subsequent preflight.
Do not rewrite event times, widen tolerances to accept the drift, reset baselines,
or count an invalid-clock run as a measured detector miss. Keep automatic
isolation, confirmation and candidate generation disabled for the manual study.

## Dashboard acceptance evidence

- Eight Chromium 156.0.8078.4 sample screenshots were inspected offline: Overview,
  incident drawer, rule drawer and presentation in both themes. No blocking layout
  issue was visible. These are synthetic UI examples, not detection evidence.
- The supplied report records bounded Tab/Shift+Tab/Escape dialog checks and
  390 px Overview/navigation checks in both themes, with no unexpected backend
  requests or page errors. No mobile screenshots were supplied.
- The operator reported complete-cycle Firefox drawer keyboard checks, focus
  restoration and the requested live read-only Steps 3–7 walkthrough passing
  in both themes. These are operator reports, not independently observed automation.
- Minor sample-only wording issue remains: unavailable risk guidance advises a
  backend retry even though sample mode has no backend connection.

## Controlled container actions

Disposable fixture: `ss-ui-check-20261020T181208Z`, full ID
`4e4b116949c7b28d6caad8feb8d08ae533afbd9e00f2e2eb08eee4af6a538982`.
The supplied isolation screenshot shows the accepted response. Independent
operator Docker inspection then showed `Paused=true` and no network attachments.
After dashboard resume, inspection showed running/unpaused with bridge NetworkID
`3c350f9ec31594420a9c4668f2ecd97aaa32579ae38fbd48d02c80d2a7ca5b14`.
The original before-inspection network ID has not been reviewed independently.

Audit 849/850 records isolation request/completion by `guna`; 851/852 records
resume request/completion and bridge restoration. Audit 853 reports policy
compliance with zero violations. Behavioral recheck is scheduled, not verified.
Action `occurred_at` fields are null in the shown export, so no action latency is
calculated. Audit 848 is expected gate-bypass reporting for direct fixture creation;
845–847 are late baseline events, distinct from the later explicit skew probe.

Evidence: `state/evaluation/ui-recovery-audit-gxukzs_2/` and isolation screenshot
supplied by the operator. Final inspection/logs were preserved in
`state/evaluation/ui-cleanup-IMD7avwj/`; Docker stop and removal completed.
Manual isolation/resume functional acceptance PASSED. No automatic response result
or representative detection-quality claim follows from this UI exercise.

Rule confirmation/approval/rejection dialog acceptance with fresh controlled live
records, broader accessibility checks, live mid-flight restart/fault cases, the
new anomaly-only/native process/file-write chain and current-release quality/load/
drop measurements remain pending. Earlier historical rule evidence stays separate.
