# Academic narrative, viva and report outline

SelfSentry is a hybrid container runtime security system that combines Falco rule matching with per-container behavioral anomaly detection, correlates both into incidents, and converts confirmed anomalies into template-generated, backtested, human-approved Falco rules — demonstrating a supervised adaptive detection loop under controlled evaluation.

## Problem and precise contribution

Rule matching recognizes specified behaviors; a per-container behavioral model can
surface deviations from its recorded normal activity. Neither a rule match nor a
deviation alone establishes compromise. The project studies how to preserve both
signals as inspectable incidents and turn operator-confirmed, representable patterns
into reviewed additions to the rule set.

The contribution is the implemented **integration, evidence trail, supervised rule
adaptation workflow and controlled evaluation**, not an invented detector or a claim
that other products lack comparable capabilities. Falco, Trivy, Isolation Forest,
Jinja2 and PostgreSQL are reused. No exhaustive novelty/literature claim is made.

“Learning” here means supervised expansion of explicit detection rules. It is not
continuous neural training, self-modifying code or autonomous deployment. Current
synthesis can use Falco security-alert metadata or a retained literal baseline
syscall witness. Aggregate-only anomalies cannot supply a pattern. The reviewed
15 October study exercised the Falco-backed path; the later anomaly-only extension
still requires a new live acceptance chain.

## Architecture explanation focused on adaptation

Falco supplies security matches and baseline telemetry to the durable monitor. The
per-container default Isolation Forest scores feature windows only after a valid
baseline exists. Correlation preserves alerts, assessments and timelines in incidents.
The operator inspects that evidence and confirms a controlled suspicious behavior.
A literal process/parent pattern is rendered through a template and tested against
a separately curated benign corpus. A human can reject it or approve deployment.
Only then does Falco reload the rule; a repeat trigger must produce the exact native
generated-rule alert to complete the experimental evidence chain. This feedback
changes the explicit rule set, not the anomaly model weights. Scanning/policy are
supporting pre-deployment context; isolation is optional and off in the main story.

## Limitations script — approximately 35–45 seconds

“Our results come from controlled simulations on one Docker virtual machine, using
a small per-container baseline. The historical run detected all one hundred labeled
attack trials, but Falco already detected those cases, so we have not demonstrated
additional attack coverage. Thirteen of one hundred benign windows produced incidents.
The later anomaly-only proposal path needs a literal syscall witness and still
awaits live acceptance. Backtests estimate matches on our benign corpus,
not production safety. SVM remains experimental after benign false positives, and
the VM has a recurring timestamp issue. Every rule deployment requires human approval.”

## Study result answer — approximately 20 seconds

“In our three-behavior study, one candidate completed human confirmation, backtesting,
approval and native re-fire. Two broader pattern previews failed the benign backtest;
a separate passing candidate was rejected by the reviewer. Three later normal windows
had no learned-rule hits. Existing Falco rules already detected the original behaviors,
so this demonstrates supervised adaptation, not additional attack coverage.”

## Examiner answers

- **Why not only Falco?** Falco is our rule engine and already detects all attack
  cases in the historical run. SelfSentry adds per-container deviation evidence,
  correlation, persistent timelines and a reviewed rule-adaptation workflow. Its
  extra attack coverage over Falco is a research question, not an established result.
- **Is this autonomous self-defending AI?** No. Standard academic runs disable
  isolation and automatic confirmation/candidate creation. Rule syntax is templated;
  deployment always requires explicit human approval. Optional AI only explains.
- **What about false positives and auto-confirmation?** The frozen run produced
  13/100 benign incidents, with zero benign auto-confirmations. Five labeled attacks
  were auto-confirmed, which is a small conditional sample. For the mini-study we
  use human confirmation and preserve false positives; we don't equate anomaly with attack.
- **How reliable is ML?** It depends on baseline coverage and feature representation.
  Our baseline is only 20 windows/seven distinct vectors; we observed IF boundary
  limitations and SVM false positives. We freeze it, report both and avoid accuracy
  claims for unseen workloads. SVM is not the default.
- **What is original versus reused?** Original project work is the end-to-end
  orchestration, evidence/decision trace, safety gates and reproducible experiment.
  Falco, Trivy, statistical algorithms and templating libraries are reused components.
  Integration novelty is not a claim of algorithmic or commercial first invention.
- **Is it production-ready?** It is an evaluated academic prototype on a single
  host. Timestamp reliability, baseline diversity, broader fault tests and workload
  validation remain limitations. Production platform expansion is outside this thesis.
- **What exactly adapts?** A human-approved Falco rule is added for a representable
  confirmed pattern; the anomaly model is not automatically retrained. Native re-fire
  plus review/audit linkage is the evidence, not just a database status.
- **Can an ML-only incident create a rule?** The current extension can propose a
  literal template when the incident retains a concrete baseline syscall witness.
  Aggregate counts alone cannot supply a pattern. Backtesting and human approval
  still apply; a new anomaly-only live chain has not yet been accepted. The reviewed
  15 October chain was Falco-backed, so it is not evidence of ML-only discovery.
- **Does a zero-percent backtest prove safety?** No. It means zero matches among
  a stated nonzero number of eligible corpus events. Sampling and template breadth
  matter; human review and held-out normal behavior checks remain necessary.
- **Why use a 60-second window?** It aggregates behavior for stable count features,
  with 10 seconds of lateness for arrivals. It introduces delay. Historical timing
  measures attack start to row timestamp; it does not isolate detector cost.
- **How do you prove new coverage?** Require all before security rules absent and
  an exact new native rule alert after approval for the same labeled behavior. Existing
  before detection means workflow adaptation, not incremental coverage.
- **Can an approval name prove a human identity?** The workflow requires an explicit
  reviewer and rejects the automation identity, but shared-token local auth is not
  production RBAC. Operator supervision is part of this controlled experiment.
- **Why is Trivy included?** It provides image vulnerability context before deployment;
  it does not replace runtime monitoring. Runtime adaptation remains the central thesis.
- **What happens without a baseline?** Falco incidents persist with unavailable/learning
  ML explicitly represented. The system does not invent a score or claim two-layer agreement.
- **What is the strongest demonstrated result?** The reviewed 15 October mini-study
  links incident 200 to human-approved rule 18 and native re-fire in incident 204.
  Rule 19 was explicitly rejected; two other pattern previews failed backtests.
  Three later normal windows had no learned-rule hits. This is one controlled
  adaptation chain, not added attack coverage or a production accuracy estimate.

## Report section outline

1. **Introduction:** container runtime problem; exact thesis; problem statement;
   RQ1 workflow closure, RQ2 rejection integrity, RQ3 layer contribution; bounded scope.
2. **Design:** adaptive-loop architecture; telemetry/features and per-ID baselines;
   IF default; correlation; literal template expressiveness; benign backtest definition;
   human review; durability and observed timelines; optional response/AI boundaries.
3. **Experiments:** VM/software/source/config; historical 200-trial protocol and labels;
   new three-behavior mini-study; frozen calibration/held-out corpus; designed-case
   matrix; clock exclusions; endpoints, denominators and reviewer procedure.
4. **Results:** frozen incident/confirmation outcomes and retrospective comparison;
   exact timing endpoint; the measured 15 October before/confirm/backtest/approve/re-fire
   table; reject/preview-failure outcomes and unrun cases; held-out benign matches;
   separate SVM appendix.
5. **Discussion:** answer each RQ using measured evidence; workflow value versus
   coverage; template context loss; operator tradeoffs; off-the-shelf versus project work.
6. **Limitations:** threats table; small correlated samples; single VM; baseline size;
   timestamp skew; unverified anomaly-only live chain and unsupported aggregate-only
   synthesis; no production/zero-day guarantee.
7. **Conclusion:** supported accomplishments without extrapolation; next research:
   representative baselines, independent layer comparison and supported richer pattern
   extraction. No requirement for fleet, Kubernetes or commercial platform features.

Appendices: exact commands/manifests, corpus/rule hashes, case matrix, selected
sanitized traces, human decisions, reproducibility details and experimental SVM
response evidence. Demo recording remains deferred until explicitly resumed.
