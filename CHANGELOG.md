# Changelog

All notable changes to this project are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added — Phase 1: Image Scanner
- `image-scanner/trivy_wrapper.py`: Trivy CLI wrapper with typed result model (`ScanResult`, `Vulnerability`, `Secret`, `Misconfiguration`), error handling (missing binary, timeout, malformed JSON), and CLI entry point.
- `tests/test_trivy_wrapper.py`: 16 unit tests (all mocked, no live Trivy/network dependency), covering installation checks, subprocess error paths, JSON parsing, and derived risk properties.
- `docs/phase1_image_scanner.md`: Phase 1 documentation, including manual validation checklist for real Trivy scans.
- Project scaffolding: `README.md`, `requirements.txt`, `.gitignore`, `.env.example`, `TODO.md`, `ROADMAP.md`.

### Added — Phase 2: Deployment Policy Checker
- `policy-checker/deploy_policy_validator.py`: validates a `docker inspect`-shaped container spec against four default policy rules (non-root user, no `--privileged`, no added capabilities, read-only root filesystem), with a severity model (`MEDIUM`/`HIGH`/`CRITICAL`) determining which findings block deployment. Includes a CLI entry point.
- `tests/test_deploy_policy_validator.py`: 25 unit tests (all mocked/offline, no Docker daemon dependency), covering every policy rule, the Phase 1 integration hook, derived `PolicyResult` properties, and input validation.
- `docs/phase2_deployment_policy_checker.md`: Phase 2 documentation, including manual validation checklist against a real `docker inspect`.

### Changed
- Marked Phase 1 (Image Scanner) fully complete: real Trivy scan validated end-to-end and repository pushed to GitHub.

## [0.1.0] — Design phase (pre-code)
- Finalized 11-module hybrid architecture (Falco + behavioral ML + Rule Synthesis Engine).
- Produced full academic report, project profile, defense-prep notes, and beginner build guide.
- Selected and verified IEEE base papers.
- Decided: Jinja2 templated rule synthesis (not LLM-freehand), mandatory backtest + human-approval gate, hosted OpenAI-compatible API for LLM layer.

### Validated — Phase 4: Behavioral Baseline + Anomaly Detection (real data)
- Added `falco-rules/baseline-capture-rules.yaml`: four NOTICE-priority
  Falco rules capturing normal (not just malicious) process/file/syscall
  activity, feeding Phase 4's baseline.
- Added `behavioral-engine/baseline_collector.py`: parses Falco's JSON log
  into RawEvents, sharing the log file safely alongside runtime-monitor/
  falco_integration.py's real alert parsing.
- Added `behavioral-engine/collect_baseline.py` and `validate_live.py`:
  real capture and live-scoring drivers.
- Real validation run against `test-container`: 20 real baseline samples,
  live anomaly scores separating normal (0.2595) from a triggered
  `docker exec -it <c> sh` session (0.9977, flagged anomalous).
- Documented a discovered Falco modern-eBPF probe limitation: `proc.name`
  misresolves to a raw identifier for the first process in a fresh exec
  session (see docs/phase4_behavioral_engine.md).
