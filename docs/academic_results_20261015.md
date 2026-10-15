# Supervised adaptive-loop results — 15 October 2026

SelfSentry is a hybrid container runtime security system that combines Falco rule matching with per-container behavioral anomaly detection, correlates both into incidents, and converts confirmed anomalies into template-generated, backtested, human-approved Falco rules — demonstrating a supervised adaptive detection loop under controlled evaluation.

**Observed boundary:** this study validates the supported Falco-backed process-pattern
workflow. It does not establish ML-only rule synthesis, added attack coverage or
representative model accuracy. “Confirmed” denotes operator-labeled controlled
simulation, not a genuine compromise. No detector default or threshold was changed.

## Evidence and review method

The operator executed the study on the Ubuntu/Docker/Falco/PostgreSQL VM and supplied
`selfsentry-academic-study-evidence.tar.gz`. The review extracted and checked those
artifacts offline; the reviewer did not operate the VM independently. Archive SHA-256:

```text
0fa955f30775b8c1edbc2638d87d334091e95c56f1311523024dc0e912383981
```

Study directory: `state/evaluation/academic-loop-20261015T085928Z/`.
See the [machine-readable audit](academic_results_20261015.json) for each capture,
backtest, reviewed row, artifact hash and unmeasured item. Raw runtime data remains
separate from tracked source documentation.

Seventeen captures are present: nine benign calibration windows, three primary before
cases, one additional binary rejection-control before case, one approved binary after
case, and three later benign windows. All 17 reports are valid with closed windows,
accepted baseline telemetry and zero observed per-capture clock skew. Raw record
counts, target/window membership, alert names, incident IDs, delivered outbox IDs and
persisted timeline descriptions were cross-checked. No invalid capture is present in
this supplied archive; this says nothing about attempts not supplied.

All captures used monitor PID 10064, default `isolation_forest` and explicit false
values for isolation, automatic confirmation and automatic candidate generation. The
same target, image and baseline hashes were recorded throughout. Six incident snapshots
(199–204) all report response not attempted because isolation was disabled. Manual
confirmation/submission and human rule approval were separate operator actions.

| Reproducibility item | Recorded value |
|---|---|
| Source HEAD | `f465de1930df502c3ea4b426f0804a47298a2e72` with dirty working tree and applied academic patch |
| Container ID | `12160024642b6244d4ec9b81e5ac7d0010a8d30688e37d9ac4369f0bf2b693df` |
| Image ID | `sha256:a484819eb60211f5299034ac80f6a681b06f89e65866ce91f356ed7c72af059c` |
| Baseline SHA-256 | `f354809d2ad5fa7406e34024bb65c9f3aea37815493050b92741debac412fbba` |
| Benign corpus SHA-256 | `7ce5a6fcc58c9403264e59aad7a2339422489895108727aaa42a24d36955dc38` |
| Generated rules before | `59874ffbd84bad5c80c8a75271d1425d58a4ce3c260e6800fb06867097e601d6` |
| Generated rules after | `99ad05160795da3d62787cbd39af3d648821cd2385a21f43f5f5eabcce3425a4` |

The archive has captures and final rule/decision snapshots; it does not contain a
complete runtime source/configuration/dependency archive, original baseline bytes,
native reload journal or full DB audit export. Source HEAD plus dirty status is not
proof of exact runtime-code identity. Stored model assessments were inspected, not
retrained/recomputed from a baseline absent from this archive.

## Novelty evidence table: all planned primary behaviors and rejection control

| Behavior | Falco before | Incident confirmed | Rule approved | Falco after (re-fire?) | Notes |
|---|---|---|---|---|---|
| B1 copied harmless `ss-study-true` binary | Existing `Drop and execute new binary in container`; incident 200 | Yes: reviewed record links incident 200, confirmed by `guna-academic-review` | Yes: rule 18, reviewed by `guna-review`, final status deployed | **Yes:** exact `Auto_Generated_ss_study_true_from_sh_200` at `2026-10-15T10:12:02.312672440Z`, incident 204 timeline | Candidate matched 0/36 benign process events; stock alert also fires after; no coverage gain |
| B2 sensitive-file read | Existing `Read sensitive file untrusted`; incident 201 | No confirmation evidence supplied for this case | Not submitted/approved; preview backtest fails | NOT RUN; no B2 generated rule in final YAML | `cat` from `sh` matches 3/36 (8.33%); template loses sensitive-path context |
| B3 terminal shell | Existing `Terminal shell in container`; incident 202 | No confirmation evidence supplied for this case | Not submitted/approved; preview backtest fails | NOT RUN; no B3 generated rule in final YAML | `sh` from `containerd-shim` matches 8/36 (22.22%); template loses TTY context |
| Rejection control: additional B1 repeat | Existing copied-binary rule; incident 203 | Yes: reviewed record links incident 203, confirmed by `guna-academic-review` | **Explicitly rejected:** rule 19 by `guna-review` | Exact `_203` rule absent from final YAML and every supplied capture; positive after run fires `_200` only | Separate decision-path control, not a fourth attack class; same matching condition as rule 18 |

Exactly one of the three primary behaviors completed approval and native re-fire.
Two primary patterns stopped at failed backtest previews. An additional passing
candidate was explicitly rejected. These are different outcomes: **a backtest preview
failure is not a recorded human rejection**, and neither missing B2/B3 after-run is
counted as a successful re-fire. Actual failed production submissions for 201/202
were not attempted; source refusal behavior has test coverage, not live refusal
trace in this study.

## Backtest corpus and recomputation

The corpus contains 36 `Baseline Process Spawn` records from nine known-normal
administration/config-read/conventional-curl windows (three rounds). Offline review
reconstructed that exact ordered corpus from the raw capture files and matched its
saved hash. It retained the normal window that produced anomaly-only incident 199.
The corpus is separate from the model's unchanged training baseline.

| Pattern preview from actual incident | Matched / eligible events | Reported match rate | Verdict at existing ≤5% threshold |
|---|---:|---:|---|
| `ss-study-true` from `sh` (200) | 0/36 | 0.0% | Pass; queued rule 18 |
| `cat` from `sh` (201) | 3/36 | 8.33% | Flag for revision; not queued |
| `sh` from `containerd-shim` (202) | 8/36 | 22.22% | Flag for revision; not queued |

Existing `extract_pattern`, `generate_rule` and `backtest_rule` reproduced all three
reported previews against the saved corpus. Submission artifacts and reviewed rows
agree for rules 18/19. Backtest rates are event-level matches over the supported
process/parent template shape, not native full-engine replay or production FPR.
Zero matches in 36 events is not a safety guarantee. Across-container rule breadth
and loss of incident-specific context still require human review.

## Human decisions, native deployment evidence and rejection integrity

`reviewed-rules.json` records rule 18 from incident 200 as deployed, and rule 19 from
incident 203 as rejected. Both were confirmed by `guna-academic-review` and reviewed
by `guna-review`. The final rule-18 YAML equals the corresponding parsed node in
`rules-after.yaml`; rule 19 is absent. Reviewer timestamps are timezone-naive in the
export; no learning or approval latency is calculated from them.

The intermediate `rejection-verification.json` records rule 19 rejected/absent,
the file hash unchanged and rule 18 still pending. The control's before capture
shares the original rule hash. Together these support the rejection outcome; they
are operator-generated snapshots, not an independently signed audit trail. The full
rejection-reason/audit event payload is not included in this archive.

The after raw record contains the exact rule name, target `12160024642b`, process
`ss-study-true`, parent `sh` and native timestamp above. The stock copied-binary rule
has the **same event timestamp**. Incident 204's observed timeline contains both
alerts. Thus the rule was active in Falco after the operator's reported reload;
this goes beyond a database status alone. A separate native reload log and reload
latency were not captured. Rule 19's absence is about that exact rejected artifact;
its identical behavior condition can still match through approved rule 18.

## Behavioral model and benign outcomes

| Window(s) | Qualifying model evidence | Outcome |
|---|---|---|
| Binary before 200, control 203 and after 204 | IF score ~0.1430, not qualifying | Falco-backed incidents; do not call these two-layer agreement |
| Sensitive before 201 | IF score ~0.4736, not qualifying | Falco-backed incident |
| Terminal before 202 | IF score ~0.4907, not qualifying | Falco-backed incident |
| Calibration `benign-2-admin`, incident 199 | IF score ~0.8400, qualifying; effective score 24 | Known-benign anomaly-only false positive; not confirmed, no response |
| Three held-out normal windows | No incident in snapshots; accepted events and closed windows verified | No generated-rule hit; no full-pipeline incident in 3/3 windows |

The approved generated rule had zero native hits in three **later** administration,
config-read and curl windows. Those commands repeat calibration workload families;
they are temporally held-out windows, not independent unseen workloads. This does
not justify a production FPR or improvement claim. Calibration had one incident in
nine windows; later checks had zero in three. Do not pool those small convenience
samples with the historical 200-trial benchmark or tune thresholds to erase incident 199.

## Answers to the research questions

- **RQ1, supported loop closure:** observed once (B1), with incident→confirmation→
  template/backtest→human approval→native re-fire and persisted after timeline.
  No ML-only-to-rule path was exercised or implemented.
- **RQ2, human rejection:** observed once (rule 19), despite a passing 0/36 backtest.
  Reviewer choice prevented that exact candidate being added; positive rule 18 is
  separately approved. Broader pattern suppression is not claimed.
- **RQ3, hybrid contribution/coverage:** none of the three primary before incidents
  had qualifying IF evidence; all had existing Falco detections. There is **no new
  attack coverage demonstrated**. The model contributed a benign false positive
  during calibration. That result is retained rather than reframed as a threat.

## Defensible report paragraph

“In a three-behavior controlled mini-study, one process-pattern candidate completed
confirmation, template generation, a 36-event benign backtest, explicit human approval
and native Falco re-fire, with the after incident preserving both original and learned
rule evidence. Two other generated pattern previews exceeded the existing 5% benign
match-rate threshold and were not submitted. A separate passing candidate was manually
rejected and remained absent from the rules file. Three later normal windows produced
no learned-rule matches or incidents. Existing Falco rules detected all three original
behaviors, so the study supports supervised workflow adaptation, not additional attack
coverage. The calibration phase retained one anomaly-only false positive.”

## Reproduce the backtest review on the VM

This reads saved evidence only; it does not confirm, submit, approve, deploy or retrain:

```bash
cd ~/selfsentry
source .venv/bin/activate
python3 - <<'PY'
import hashlib, json, sys
from pathlib import Path
sys.path.insert(0, 'rule-synthesis-engine')
from pattern_extractor import extract_pattern
from rule_template_generator import generate_rule
from rule_backtester import backtest_rule
p = Path('state/evaluation/academic-loop-20261015T085928Z')
corpus = [json.loads(l) for l in (p/'benign-calibration.jsonl').read_text().splitlines()]
assert hashlib.sha256((p/'benign-calibration.jsonl').read_bytes()).hexdigest() == (
    p/'benign-calibration.sha256').read_text().strip()
for case in ('binary', 'sensitive', 'terminal'):
    incident = json.loads((p/f'{case}-before/incidents.json').read_text())[0]
    candidate = generate_rule(extract_pattern(incident), incident['id'])
    print(case, backtest_rule(candidate, corpus))
PY
```

## Remaining scope

C2 recording is still deferred. Recurring VM/Falco timestamp skew is not permanently
fixed by 17 valid captures. Representative baseline/model validation, independent
live layer comparisons, richer supported extraction, broader fault tests and precise
stage/learning timings remain research limitations. The historical 200-trial results
are unchanged. No SVM default change or production platform expansion is proposed.
