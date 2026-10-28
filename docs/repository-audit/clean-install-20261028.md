# Independent clean-install verification — 28 October 2026

A freshly installed Ubuntu VM under account `test` cloned main at `3da2854`.
No original .env, database, baseline or runtime state was copied.

Environment: Ubuntu 24.04.4 LTS, kernel 7.0.0-42-generic, Python 3.12.3,
Node 24.21.0, npm 11.19.0, Docker 29.9.2, PostgreSQL 16, Falco 0.45.1
with modern eBPF and container plugin 0.7.5, and Trivy 0.76.1.

Locked Python installation and pip check passed. The dashboard installed
with npm ci and built successfully. A dedicated database/role and random
private credentials/token were created. Alembic upgrade and schema
comparison passed with no differences.

Release verification passed 1,278 Python tests plus 104 subtests,
168 frontend tests, lint, scoped types over 99 source files and build.
Evidence: state/evaluation/final-checks-20261028T094503Z.
The chart bundle-size warning remains non-blocking.

Falco JSON/ISO output, rule_matching=all and repository capture rules were
configured. An initial duplicated default-rule list was corrected; final
dry-run validation loaded each rule file once. This installation required
manual host configuration; no unattended installer is claimed.

Four smoke checks passed: authenticated database readiness, dashboard HTML,
authenticated audit creation/identical retry, and fresh native telemetry.
The owned Alpine probe produced 148 events with maximum receipt lag
0.1333 seconds and was removed. Subsequent monitor status showed 154
processed baseline events, two windows, empty delivery queues and no
event-time warning.

The operator reported Overview/Monitor rendering, healthy status,
isolation disabled and the CLEAN_INSTALL_ACCEPTANCE audit event visible.

This verifies fresh installation, migration, build/tests, startup,
native baseline ingestion, keyed audit/API behavior and basic browser
operation on this environment. It does not establish representative model
accuracy, fresh-host rule deployment/response acceptance, reboot recovery,
zero native drops or production readiness. No ready model was claimed.
Automatic isolation, confirmation, rule candidates and native retirement
remain disabled.

Private evidence: ~/selfsentry-private-evidence/clean-install/
