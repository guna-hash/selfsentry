# Phase 4/5 Live Validation — 2026-09-22

## Setup
- Container: `selfsentry-test` (12160024642b), nginx:1.25
- Baseline: 21 samples, 60s windows, captured via `collect_baseline.py`
- Live scoring: `validate_live.py --minutes 5 --window-seconds 60` (window size MUST match baseline capture window size)

## Result
| Window | Time | Events | anomaly_score | Flag |
|---|---|---|---|---|
| 1 | 06:42:47-06:43:47 | 389 | 0.0666 | normal |
| 2 | 06:43:47-06:44:47 | 392 | 0.0558 | normal |
| 3 | 06:44:47-06:45:47 | 396 | 0.0360 | normal |
| 4 | 06:45:47-06:46:47 | 430 | **0.7865** | **ANOMALY** |
| 5 | 06:46:47-06:47:47 | 398 | 0.0381 | normal |

Window 4 covers a manual `docker exec -it selfsentry-test sh` session
(cat /etc/passwd, ls /root, whoami) run concurrently with normal
whoami/ls traffic. Correctly flagged; all other windows correctly
scored low.

## Bugs found and fixed during this validation
1. Ran the shell trigger AFTER validate_live.py had already finished —
   nothing was scored. Fix: trigger must happen while the script is
   still actively running.
2. Window-size mismatch: baseline was captured at 60s windows;
   validate_live.py was first run with --window-seconds 30. This made
   every live feature vector look artificially different from baseline
   (roughly half the event count for identical behavior), causing
   every window - even a fully idle one - to score as anomalous.
   Fix: window size must match between baseline capture and live scoring.
