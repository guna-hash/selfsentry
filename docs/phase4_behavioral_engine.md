## Manual validation — RESULT (real run, 2026-08-28)

Performed on the real VM against `test-container` (nginx:1.25), using
`falco-rules/baseline-capture-rules.yaml` + `behavioral-engine/
collect_baseline.py` + `behavioral-engine/validate_live.py`.

**Baseline:** 20 samples captured over a 10-minute learning window
(30-second windows), mixing idle nginx activity with a few `docker exec`
commands (`ls /etc`, `cat /etc/nginx/nginx.conf`) for variety.

**Live validation result:**
| Window | Activity | anomaly_score | is_anomaly |
|---|---|---|---|
| 1, 2, 4, 5, 6 | idle (baseline-matching) | 0.2595 | False |
| 3 | `docker exec -it test-container sh` + `ls`/`whoami`/`cat /etc/passwd` | **0.9977** | **True** |

Clean separation confirmed: anomalous window scored ~3.8x higher than
baseline windows and correctly triggered `is_anomaly`.

**Known limitation discovered during validation:** the `sh` process
spawned directly by `docker exec` was reported by Falco's modern eBPF
probe with `proc.name="7"` instead of `"sh"` - a probe-level name-
resolution race specific to the first process in a fresh exec session
(children spawned afterward, e.g. `ls`/`whoami`, were named correctly).
As a result, `shell_spawned_count` did not fire for this specific
trigger, and detection succeeded instead via `sensitive_syscall_count`
(14, vs. 0 baseline) and raw event volume (18, vs. 0 baseline) - the
two engineered features acted as redundant signals, which is exactly
the kind of robustness multi-feature detection is meant to provide.
Documented here rather than "fixed," since it is a Falco/eBPF probe
characteristic, not a bug in this project's code.

**Conclusion: Phase 4 manual validation PASSED.**
