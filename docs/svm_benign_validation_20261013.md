# Experimental SVM benign validation — 13 October 2026

The One-Class SVM remains opt-in. Isolation Forest remains the default.

## Live results

- Initial batch: 24 windows; 5 valid and 19 invalid due to Falco
  timestamp skew. Two valid directory-listing windows produced
  anomaly-only incidents (193 and 194).
- After restarting Falco, clock preflight passed with zero observed skew.
- Follow-up batch: all 4 windows valid. Directory listings and a standard
  curl HTTP request produced anomaly-only incidents (195 and 196).
  Administration and configuration reads produced no incidents.
- Both follow-up incidents had effective score 30. Automatic isolation,
  confirmation and rule-candidate generation were disabled.

## Interpretation

The follow-up batch produced incidents in 2 of 4 benign windows.
This small, repeated lab test does not establish a production
false-positive rate. The SVM is not ready to become the default.

Earlier automatic-isolation validation demonstrated the response path
with a controlled simulation; it did not establish model accuracy.
No baseline retraining or threshold tuning was performed in these batches.

## Evidence

- state/evaluation/svm-benign-20261013T075517Z/
- state/evaluation/svm-benign-20261013T090801Z/

Runtime evidence remains local and separate from tracked documentation.
