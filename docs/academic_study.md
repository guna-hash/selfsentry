# Supervised adaptive rule-loop mini-study

SelfSentry is a hybrid container runtime security system that combines Falco rule matching with per-container behavioral anomaly detection, correlates both into incidents, and converts confirmed anomalies into template-generated, backtested, human-approved Falco rules — demonstrating a supervised adaptive detection loop under controlled evaluation.

**Protocol and subsequent execution.** Prepared against source `f465de1` on
15 October 2026. The operator later supplied evidence for 17 valid captures: one
primary case completed approval/re-fire, two stopped at failed backtest previews,
and a passing control candidate was explicitly rejected. See the
[filled results and evidence boundaries](academic_results_20261015.md).
The blank table below is reusable for another run; it is not the status of the
completed supplied subset. Recording C2 remains deferred. See [case matrix](academic_case_matrix.md),
[evaluation interpretation](academic_evaluation.md) and [viva/report guide](academic_narrative.md).

## Reusing this historical protocol

The current permanent duplicate guard rejects equivalent conditions across incidents.
The extra binary rejection-control case below can therefore be refused before review
when its condition is already protected. Preserve that refusal as the actual outcome;
do not change the rule name, erase history or bypass the guard to reproduce two
historical equivalent candidates. A new study needs predeclared distinct supported
conditions for separate approval/rejection cases. Saved 15 October results remain
unchanged and describe the earlier implementation.

## Research questions and implementation boundary

- RQ1: Can a recorded incident reach a human-confirmed, template-generated,
  backtested candidate and, after human approval, a natively firing Falco rule?
- RQ2: Does rejecting a candidate leave that candidate absent from the live rules?
- RQ3: Which tested windows contribute Falco-only, ML-only or joint evidence?
  Is any labeled attack detected only after adaptation?

Here, “confirmed anomalies” means operator-confirmed suspicious behavior with
**extractable process/parent metadata in a Falco alert** in the 15 October study.
The later implementation can also use a retained literal baseline syscall witness
for an anomaly-only proposal; aggregate counts alone remain unsupported. That new
live chain was not exercised by this study and still requires acceptance. The mini-study primarily evaluates workflow
adaptation, not discovery of unknown attacks, model retraining or new algorithms.

Predeclare all three cases and preserve every failure, revision and rejection:

| Case / behavior | Repeatable trigger | What a generated rule can express | Expected interpretation |
|---|---|---|---|
| B1: copied harmless binary | Copy `/bin/true` to `ss-study-true`, execute, clean own temp directory | Observed process/parent pair, typically `ss-study-true` from `sh` | Candidate positive loop case; stock Falco may already flag it |
| B2: sensitive-file read | `cat /etc/shadow >/dev/null` in the disposable lab target | Observed process/parent pair, **not** the sensitive pathname | Loss of file context may make candidate too broad: revise/reject is legitimate |
| B3: terminal shell | `docker exec -t ... /bin/sh -c ...` | Observed shell/parent pair, **not** terminal attachment | Broad shell rule may match normal administration; reject if unjustified |

These are three controlled behaviors, not three novel attack classes. B1 is harmless
execution, B2 suppresses output, B3 prints a marker. Use only the existing dedicated
lab container; no external targets. Do not confirm ordinary benign validation
incidents 193–196 as attacks to manufacture a learning example.

## 1. Freeze configuration and create evidence directory

Keep Docker, PostgreSQL, Falco, backend and dashboard running. Stop the existing
monitor with Ctrl+C in **its own terminal**, then start exactly one monitor there:

```bash
cd ~/selfsentry
source .venv/bin/activate
MONITOR_ANOMALY_ALGORITHM=isolation_forest \
AUTO_ISOLATION_ENABLED=false AUTO_CONFIRM_ENABLED=false \
MONITOR_RULE_CANDIDATES_ENABLED=false MONITOR_LOG_FORMAT=json \
python3 monitor-service/monitor_service.py
```

In a separate study terminal:

```bash
cd ~/selfsentry
source .venv/bin/activate
export STUDY="$PWD/state/evaluation/academic-loop-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$STUDY"
git rev-parse HEAD > "$STUDY/source-commit.txt"
git status --short > "$STUDY/source-status.txt"
python3 -m pip freeze > "$STUDY/python-packages.txt"
docker inspect selfsentry-test > "$STUDY/docker-before.json"
sudo systemctl cat falco-modern-bpf.service > "$STUDY/falco-unit.txt"
sudo journalctl -u falco-modern-bpf.service -n 50 --no-pager > "$STUDY/falco-startup.txt"
cp falco-rules/auto-generated-rules.yaml "$STUDY/rules-before.yaml"
python3 evaluation/clock_guard.py --container selfsentry-test
```

Require a readable Falco JSON log, `rule_matching: all`, existing target ID
`12160024642b` in MODEL_READY with Isolation Forest and its unchanged 20-window
baseline. Do not recreate the target or retrain during this study. Configure the
backend shared token in `.env` per `monitor_operations.md`; never echo or record it.
Review actual Falco loaded-rule paths and hash the configuration/rules used; a source
commit alone does not identify runtime configuration. Keep evidence local.

The helper `evaluation/capture_academic_case.py` checks actual monitor process flags,
baseline hash, source status and timestamp accuracy. It captures **one** 60-second
window and writes `capture.json`, raw `falco.jsonl`, and matched `incidents.json`.
It never confirms incidents, changes rules, deploys, trains or isolates. A capture
marked valid is not automatically a successful detection/learning experiment.

If its clock check fails, stop before another case. Preserve the invalid directory.
Restart Falco only after collecting diagnostics, rerun the clock preflight, and use
a new capture directory. Restarts may restore accuracy without fixing the recurring
VM timestamp issue. Keep host and VM awake throughout. No unrelated target workloads.

## 2. Collect and freeze genuinely benign backtest data

The entire mixed `/var/log/falco/alerts.json` is **not** a validated benign corpus.
Collect administration, config reads and conventional HTTP separately, while only
these known-normal commands run. Predeclare three rounds; `&&`/`|| exit` stop on an
invalid capture. This is approximately 25–35 minutes with waiting/delivery allowance.

```bash
for round in 1 2 3; do
  for behavior in admin config http; do
    python3 evaluation/capture_academic_case.py --case "$behavior" \
      --out "$STUDY/benign-$round-$behavior" || exit 1
  done
done
python3 - <<'PY'
import hashlib, json, os
from pathlib import Path
p = Path(os.environ['STUDY'])
events = []
for folder in sorted(p.glob('benign-*')):
    assert json.loads((folder/'capture.json').read_text())['valid'], folder
    for line in (folder/'falco.jsonl').read_text().splitlines():
        event = json.loads(line)
        if event.get('rule') == 'Baseline Process Spawn':
            events.append(event)
assert len(events) >= 30, 'Insufficient process-spawn corpus; retain this failed preparation'
target = p/'benign-calibration.jsonl'
target.write_text(''.join(json.dumps(e)+'\n' for e in events))
(p/'benign-calibration.sha256').write_text(hashlib.sha256(target.read_bytes()).hexdigest()+'\n')
print('Frozen eligible benign process events:', len(events))
PY
```

Thirty is a predeclared **study preparation minimum**, not evidence of statistical
representativeness or a change to production thresholds. If insufficient, mark
preparation incomplete, document the revised collection plan and start a new study;
do not silently remove inconvenient events. Keep any benign incidents as false
positives. Model baseline and rule backtest corpus are separate artifacts.

## 3. Capture “before” for all cases before approving anything

```bash
for behavior in binary sensitive terminal; do
  python3 evaluation/capture_academic_case.py --case "$behavior" \
    --out "$STUDY/$behavior-before" || exit 1
done
python3 evaluation/capture_academic_case.py --case binary \
  --out "$STUDY/binary-reject-before"
```

The additional binary repeat is the reject-path workflow control, not another
attack category. Stop if it is invalid; preserve the report.

Read each `capture.json`, `falco.jsonl` and `incidents.json`. Record **all** rules
that fired, not just the winning incident's Falco alert. Check the exact process,
parent, full target ID and window; inspect `anomaly_assessment.qualifies`, algorithm
and availability. Do not infer ML participation from risk score or the title “hybrid”.
If delivery is slow, re-query the exact target/window and save an additional dated
snapshot; do not relabel an empty API snapshot as a detection miss until the window
and outbox are checked. No incident: mark that case INCOMPLETE for this loop study.

## 4. Operator confirms one case, then queues its candidate

Do this for each actual before-incident, one at a time. Replace `123` with the real
incident ID shown in that case's file, **not** a confirmed_incident or rule ID.
Confirmation records acceptance of a **controlled labeled simulation**, not genuine
compromise. Inspect evidence before confirming.

```bash
export CASE=binary
export INCIDENT_ID=123
python3 - <<'PY'
import json, os, sys
from pathlib import Path
p = Path(os.environ['STUDY'])
case = os.environ['CASE']
iid = int(os.environ['INCIDENT_ID'])
assert case in ('binary', 'sensitive', 'terminal', 'binary-reject')
before = json.loads((p/f'{case}-before/incidents.json').read_text())
assert iid in [i['id'] for i in before], 'Incident must belong to this before capture'
sys.path.insert(0, 'rule-synthesis-engine')
from submit_candidate import submit_candidate
result = submit_candidate(iid, confirmed_by='guna-academic-review',
                          backend_url='http://127.0.0.1:8000',
                          log_path=str(p/'benign-calibration.jsonl'))
(p/f'{case}-candidate.json').write_text(json.dumps(result, indent=2)+'\n')
(p/f'{case}-candidate.yaml').write_text(result['rule_yaml']+'\n')
print('Rule ID:', result['rule_id'], 'Status:', result['status'])
print('Backtest:', result['backtest'])
PY
```

This uses existing production modules: confirmation persistence → pattern extraction
→ Jinja2 YAML → nonempty benign backtest → pending queue. No `--allow-flagged`, no
direct DB insertion, and no direct call to `deploy_rule`. It refuses empty corpora
and failed backtests. On failure retain the error and confirmed incident snapshot;
confirmation can succeed even if candidate creation later fails.

Backtesting currently evaluates the supported process/parent rule shape over
Baseline Process Spawn events. `matched_events / events_tested` is an **event-level
match rate on this corpus**, not the historical trial-level FPR and not a complete
native Falco replay. Passing the ≤5% threshold is necessary, not sufficient for safety.
Inspect zero-match candidates for generalization, missing context and corpus bias.

## 5. Human review: approve, reject or stop

Open Rule Review. Match the returned rule ID, source incident, exact YAML and
backtest counts. The template matches a process/parent pair across containers;
it is **not scoped to the original container** and does not retain file/TTY context.
Review that breadth even for a zero-match backtest.

- **Approve only if justified:** an explicit human clicks Approve with their
  identity. The existing backend records approval, appends to the generated-rules
  file and reloads Falco. Save the rule record, audit trail and reload log. A 502
  means “approved but deployment failed”, not deployed. Diagnose without bypassing.
- **Reject a candidate:** an explicit human clicks Reject with an explanation.
  Record its ID/status and verify its exact rule name was absent before and remains
  absent afterward. A source file diff plus the database decision are required.
- If no acceptable candidate exists, record that outcome. Do not lower the
  backtest threshold, edit the baseline or force approval to make the study pass.

For the reject-path control captured in step 3, repeat step 4 with
`export CASE=binary-reject` and its **own actual** `INCIDENT_ID`, then explicitly
reject its new rule ID in Rule Review before approving B1. The step-4 script reads
`binary-reject-before/incidents.json` and writes separate candidate artifacts.
Record this as an additional workflow control, not a fourth attack class. If the candidate
isn't queueable, report reject-path as NOT RUN and use the existing historical
rejected record only as limited evidence.

Export actual reviewed rows (read-only; includes confirmed incident linkage):

```bash
python3 - <<'PY'
import json, os, sys
from pathlib import Path
sys.path.insert(0, 'backend-api')
from database import SessionLocal
from models.db_models import GeneratedRule, ConfirmedIncident
with SessionLocal() as db:
    rows = []
    for rule, confirmation in db.query(GeneratedRule, ConfirmedIncident).join(
        ConfirmedIncident, GeneratedRule.confirmed_incident_id == ConfirmedIncident.id
    ).all():
        rows.append({'rule_id': rule.id, 'incident_id': confirmation.incident_id,
                     'confirmed_incident_id': confirmation.id, 'status': rule.status,
                     'reviewed_by': rule.reviewed_by, 'reviewed_at': str(rule.reviewed_at),
                     'backtested_fp_rate': rule.backtested_fp_rate, 'rule_yaml': rule.rule_yaml})
p = Path(os.environ['STUDY'])/'reviewed-rules.json'
p.write_text(json.dumps(rows, indent=2)+'\n')
print('Saved:', p)
PY
cp falco-rules/auto-generated-rules.yaml "$STUDY/rules-after.yaml"
sudo journalctl -u falco-modern-bpf.service -n 80 --no-pager > "$STUDY/falco-reload.txt"
```

Repeat this export after final review decisions; save separate dated snapshots when
needed. Check file permissions, native validation and reload before re-fire. YAML
parsing in the deployer is not full Falco semantic validation. Never use `/deprecate`
as a live disable operation: retiring a DB record does not remove the deployed YAML.

## 6. Repeat exactly, after reload; then test held-out normal windows

```bash
for behavior in binary sensitive terminal; do
  python3 evaluation/capture_academic_case.py --case "$behavior" \
    --out "$STUDY/$behavior-after" || exit 1
done
for behavior in admin config http; do
  python3 evaluation/capture_academic_case.py --case "$behavior" \
    --out "$STUDY/holdout-$behavior" || exit 1
done
```

The positive criterion is the **exact candidate rule name** in fresh raw Falco JSON
for the same target and matching process/parent after reload. Database `deployed`,
a restart success, or a generic default rule firing is insufficient. For rejected
rules, verify no corresponding name in live YAML and no matching generated alert;
other default or previously deployed rules may still fire. Held-out windows occur
after candidate selection and are not used to tune rules. Three repeated workloads
are a small convenience sample, not an independent population estimate.

Every reload can reset Falco timestamp behavior; each helper invocation preflights
again. It stops after one invalid capture instead of running a blind long batch.
No automated script in this pack approves a rule.

## Reusable blank results table — for a new run

| Behavior | Falco before | Incident confirmed | Rule approved | Falco after (re-fire?) | Notes |
|---|---|---|---|---|---|
| B1 copied binary | NOT RUN: list default/generated names, target, time | NOT RUN: incident ID + confirmed row + operator | NOT RUN: rule ID, reviewer, decision/time | NOT RUN: exact generated name + raw record | Record ML qualification separately; default coverage may already exist |
| B2 sensitive read | NOT RUN | NOT RUN | NOT RUN: approval/rejection/failure | NOT RUN | Template loses file-path context; rejection is defensible |
| B3 terminal shell | NOT RUN | NOT RUN | NOT RUN | NOT RUN | Template loses TTY context; broad shell pattern is risky |
| Reject-path control | NOT RUN: additional B1 repeat | NOT RUN | Expected rejected; verify real result | Exact rejected name absent | Control is not an additional attack class |

Per case retain: before/after manifests + raw alerts + incident linkage; baseline and
corpus hashes; YAML and backtest matched/tested counts; confirmed ID; reviewed rule ID;
human identity/time; reload outcome; post-review benign results; exclusions/reasons.
Write a short result paragraph including **all attempted cases and denominators**.

**Workflow success:** at least one complete trace from before incident through
confirmation, generated template, nonempty backtest, human approval and native re-fire.
**Rejection success:** actual rejected candidate remains undeployed, independently
checked in file and alerts. Report the two outcomes separately.

**Coverage gain:** only count a new labeled behavior if *all* before security rules
were absent, the after generated rule fired and an incident was correctly linked.
Baseline capture rules do not count as security detections. An existing stock or
generated before alert means **no incremental coverage demonstrated**, even if the
new rule fires. Do not disable stock rules to manufacture a gain. The supported
extractor's need for a Falco alert makes ML-only rule discovery an open boundary.

## Finish

Review the exact additions to `auto-generated-rules.yaml`; generated patterns persist
after the study and can affect later trials. Keep only operator-approved rules
appropriate for this lab. Disable study rules through a reviewed exact YAML edit
and reload if cleanup is needed; do not restore an entire old file over unrelated
reviewed changes. Record cleanup/reload, preserve DB/audit history, preflight again.
Do not stage `.env`, runtime SQLite, baseline JSON or raw evidence into Git. Commit
only source/protocol and a concise results summary after review. Installing this protocol is not execution evidence. The linked 15 October result
records the actual supplied outcomes; no recording completion is claimed.
