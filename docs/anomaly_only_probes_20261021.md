# Anomaly-only acceptance probes — 21 October 2026

Source: 3cdd67b. Default Isolation Forest, existing baseline and thresholds
preserved. Automatic isolation, confirmation and candidate generation disabled.

## Administration probe
Evidence: state/evaluation/anomaly-only-admin-bGGr4aIS/capture
Valid capture: 24 baseline events, zero observed skew, no security alert,
no incident. Separate offline replay scored 0.1430080728562448 against
threshold 0.8; this was not a recorded live model assessment.

## File-write variation
Evidence: state/evaluation/anomaly-only-file-krkxgfkz/capture
Created and removed 20 tiny temporary files using the capture helper.
Valid capture: 40 baseline events, zero observed skew, no security alert,
no incident. No model score is claimed for this window.

## Interpretation
These are two controlled benign windows without incidents, not representative
false-positive-rate measurements or evidence of attack detection.
No qualifying live anomaly-only incident was obtained. Literal-witness
synthesis, approval and native process/file-write re-fire acceptance therefore
remain unverified. No incident, score or passing result was fabricated.

The earlier invalid-clock attempt remains preserved at:
state/evaluation/anomaly-only-admin-7lfIVuPv/capture
Later clock jumps remain unresolved; the boot-order mitigation has bounded
boot validation only.
