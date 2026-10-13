# Anomaly model review — 13 October 2026 IST

This review uses the operator-uploaded baseline for container 12160024642b and the
feature counts reported for incidents 177, 185, 186 and 187. It is an offline replay,
not a new attack evaluation or automatic-response pass. Original evidence is retained.

## Reproduced cause

The baseline contains 20 consecutive one-minute windows but only seven distinct
feature vectors. Isolation Forest reproduces all four reported scores exactly
(with floating-point rounding). Incidents 186 and 187 land in the same leaf in all
100 trees, despite their different event volumes. The forest has no splits beyond
its observed training values, so larger counts following those paths do not become
more anomalous. The training-score logistic normalization preserves that equality;
it is not a calibrated attack probability. No monitor/scorer mismatch was found.

| Incident / recorded vector | Existing Isolation Forest | Experimental scaled One-Class SVM |
|---|---:|---:|
| 177 binary execution | 0.840022 | approximately 1.0 |
| 185 sensitive-file read | 0.662441 | approximately 1.0 |
| 186 binary execution | 0.143008 | approximately 1.0 |
| 187 five-execution burst | 0.143008 | approximately 1.0 |

At the unchanged 0.8 qualification threshold:

| Diagnostic | Isolation Forest | One-Class SVM |
|---|---:|---:|
| Flags on the 20 training samples | 3/20 | 0/20 |
| Leave-one-out flags | 5/20 | 2/20 |

These are correlated, small-sample diagnostics. Training replay is in-sample; the
leave-one-out fits use 19 samples solely for analysis, never for monitor deployment.
Neither number is an independent production false-positive rate. Rare baseline
patterns cause candidate false positives. The candidate is therefore not declared
validated for unattended automatic response.

## Implemented candidate

Isolation Forest remains the default. MONITOR_ANOMALY_ALGORITHM=one_class_svm selects
StandardScaler followed by an RBF OneClassSVM (nu=0.05, gamma=scale). Scaling and fitting
use only the supplied baseline. The same training-score mean/std logistic conversion
and existing anomaly/response thresholds remain in place. Numerical exponent clipping
prevents overflow for extreme margins. No score is a probability.

Unknown algorithm names fail startup. Models retrain from the same JSON on monitor
restart. The selected algorithm is recorded in lifecycle state and incident anomaly
assessment. Interface shape #2 remains compatible. Model-ready still means basic
training readiness, not validated accuracy. No baseline, incident, threshold or old
200-trial result is overwritten. No extra deterministic rule is presented as ML evidence.

## Reproduce on the VM (read-only inputs)

Export the four relevant incident records; this creates a diagnostic copy, not a
mutation of the backend:

```bash
cd ~/selfsentry
source .venv/bin/activate
mkdir -p state/model-review
python3 - <<'PY'
import json
from pathlib import Path
import requests
r = requests.get('http://127.0.0.1:8000/incidents/', timeout=10)
r.raise_for_status()
rows = [i for i in r.json() if i['id'] in (177, 185, 186, 187)]
Path('state/model-review/recorded-incidents.json').write_text(json.dumps(rows, indent=2))
PY
python3 evaluation/compare_anomaly_models.py \
  --baseline behavioral-engine/baselines/12160024642b.json \
  --incidents-json state/model-review/recorded-incidents.json
```

If permissions block reading, copy the baseline with sudo and chown only that copy,
as already done for the upload; point --baseline to that readable copy. Do not change
the production baseline's ownership or permissions merely for this diagnostic.

The JSON report records the input baseline SHA-256, sklearn version, all replay/LOO
scores, case vectors and pairwise forest leaf overlap. It changes no live settings.

## Candidate observation run

Stop the old monitor with Ctrl+C first. Keep backend/Falco running and preserve state.
Run the candidate with all automatic actions below disabled:

```bash
MONITOR_ANOMALY_ALGORITHM=one_class_svm \
AUTO_ISOLATION_ENABLED=false AUTO_CONFIRM_ENABLED=false \
MONITOR_RULE_CANDIDATES_ENABLED=false MONITOR_LOG_FORMAT=json \
python3 monitor-service/monitor_service.py
```

This is an observation run, not a second monitor: use the same single-instance state.
It still records incidents, so label this configuration separately in new evaluation
records. Replay scores do not establish live evidence or containment.

Collect representative, independently held-out clean activity before testing response:
normal traffic, legitimate maintenance, file/config access and workload variation. Use
60+ new clean windows as a starting target, not a guarantee of adequate coverage. Track
benign incident/qualification rates and detection timing under the candidate; retain
all false positives. Re-run controlled scenarios with automation off. Do not tune the
boundary on these reported attacks and then present them as held-out validation.

For a new baseline, the documented reset archives the old JSON; do not reset merely
for a pass. Preserve the original baseline and historical results for comparison.
Controlled automatic isolation acceptance subsequently passed for SVM incident 190:
worker response isolated and independent Docker inspect confirmed paused/no networks;
SelfSentry resume restored running/bridge state. Auto-confirmation and rule candidates
were disabled. See reliability_acceptance_20261013.md. General quality and unattended
response suitability remain unvalidated; this is not default-forest acceptance.

## Revert selection

Stop the candidate monitor, then start the existing default explicitly:

```bash
MONITOR_ANOMALY_ALGORITHM=isolation_forest AUTO_ISOLATION_ENABLED=false \
MONITOR_LOG_FORMAT=json python3 monitor-service/monitor_service.py
```

Existing normal .env settings apply for auto-confirm/candidates on this default run;
set them false explicitly if you want observation-only behavior. No JSON renaming or
baseline recapture is required merely to return to the previous algorithm.

## Sources

- scikit-learn Isolation Forest / novelty detection:
  https://scikit-learn.org/stable/modules/outlier_detection.html
- StandardScaler and RBF One-Class SVM implementation: installed sklearn; version
  recorded by the comparison script. The uploaded VM replay used sklearn 1.9.0;
  local sklearn 1.8.0 reproduced the same historical forest scores.
