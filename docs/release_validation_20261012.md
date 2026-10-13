# Reliability/demo source verification — 12 October 2026

Base: dashboard commit e781e02. Changes are provided as a local release commit and
patch; GitHub has not been updated by this work.

## Checks completed here

- Python suite: 415 passed (including 9 new shell/timeline regression cases).
- Frontend: 7 tests passed across two files.
- Documented release lint passed; verification scripts separately linted.
- Vite production build passed. Nonblocking chart chunk warning (~513 kB) remains.
- git diff --check passed; no tracked behavioral-engine/baselines files found.
- Timeline evidence survived outbox restart and persisted through real ORM database
  sessions/HTTP retrieval using isolated SQLite, without an AI provider.
- Policy probe failure was recorded honestly: this environment cannot access a
  Docker daemon. No live-policy pass or screenshot/recording is claimed.

## Changes and practical limits

Default Terminal shell in container events are scoring inputs only when a known
shell name is provided. They remain security alerts and exclude the window from
training. Overlapping default/baseline output is credited once, including missing
parent metadata. Other rule names and missing process identity are not guessed.
Falco emits rule matches, not a lossless syscall stream; existing timestamp/field
identity may merge indistinguishable events at Python datetime precision.

Observed timelines store chronological Falco evidence and qualifying anomaly
window evidence in monitor_incidents.evidence, then render on Alerts. There is no
schema migration; old incidents are not backfilled. This does not wire or persist
the optional advisory LLM narrative builder.

A1 and A2 VM probes are ready but need retained pass evidence; A2 also needs the
same incident visually confirmed on Alerts. Prior live isolation/resume and rule
re-fire evidence was reconciled, not rerun. Automatic response for this release
needs a model-ready disposable target and independent inspect/workflow evidence.
The direct response probe cannot establish automatic eligibility.

Browser visual verification/screenshot capture was blocked because no local
browser is installed and the browser download returned invalid archives. Use the
VM capture instructions in demo_script.md; C2 and C4 remain open.

The frozen 200-trial evaluation predates these changes. Its metrics are unchanged
and no new attack-coverage/performance claim is made. Source changes may change
scores for future shell-alert windows; rerun evaluation for comparisons.
