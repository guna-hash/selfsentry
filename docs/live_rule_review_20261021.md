# Live rule-review acceptance — 21 October 2026

Operator-supplied VM/API outputs establish this controlled case:

- Incident 209: native "Drop and execute new binary in container" alert
  from a harmless copied /bin/true named ssbine995ffb4.
- Human confirmation by guna persisted.
- Rule 21: rejected through the dashboard; reason and reviewer retained
  in audit 949. Rule absent from generated-rules file.
- Rule 22: new review attempt for incident 209; human approval by guna.
  Submission and approval backtests each tested 65 benign events,
  with zero matches. Corpus SHA-256:
  865ceabd90c3f5c0683f2f4473afca7bea04da430707c31c7f9f0a63fb7772e0
- Approval revalidation, approval and deployment: audits 951–953.
- Repeated harmless command produced one native generated-rule match.
  Audit 954 linked rule 22 to incident 210. Capture: 22 events, zero skew.
- Operator observed incident 210 timeline Step 2 showing
  Auto_Generated_ssbine995ffb4_from_sh_209.
- Both disposable fixtures were removed; approved rule remains deployed.

Evidence root: state/evaluation/live-rule-review-2ho8hfwx
Re-fire evidence: ssbine995ffb4/refire-7a961b65
Cleanup: cleanup-0fb5db62.json

Earlier custom-shell attempt produced baseline events only, with no
matching incident. Failed clock and zero-event attempts remain retained.
A subsequent same-boot clock discontinuity of about 67.5 seconds recurred
after the earlier reboot/resume checks. Trigger unknown; restarting Falco
restored freshness after initialization. Permanent clock correction remains open.

This verifies a Falco-backed supervised review/deployment/re-fire workflow.
It does not establish anomaly-only synthesis, additional attack coverage,
production false-positive rates or unattended-use reliability.
Raw evidence remains on the VM; the reviewer assessed supplied outputs.
