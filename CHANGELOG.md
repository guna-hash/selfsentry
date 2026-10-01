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

### Added — Phase 5: Correlation Engine
- `correlation-engine/risk_scorer.py`: merges Falco alerts + anomaly events by container/time-window into unified risk_score + 3-tier confidence, matching the real backend schema (no incident_id, confidence string replaces dual_layer_agreement boolean, no status field).
- `correlation-engine/event_router.py`: confidence-weighted routing (effective_score = risk_score adjusted by confidence tier) across 4 tiers (log / ai_analysis_noted / analyst_alert / auto_isolate), with auto_isolate deliberately hard to reach on low-confidence signals alone.
- `correlation-engine/validate_pipeline.py`: local simulation + real backend integration validation driver, with `--post-to-backend` flag.
- `tests/test_risk_scorer.py` (16 tests) and `tests/test_event_router.py` (17 tests), all passing.
- `docs/phase5_correlation_engine.md`: full design notes, routing model, and manual validation results.
- Fixed `GROQ_API_KEY` env var bug in `backend-api/.env` (was misnamed and malformed) blocking real `ai_summary` generation.

### Added — Phase 6: Rule Synthesis Engine (core novelty)
- `rule-synthesis-engine/confirmation_manager.py`: confirms incidents via real backend `/confirm` endpoint.
- `rule-synthesis-engine/pattern_extractor.py`: extracts structured patterns from confirmed incidents' Falco alert text.
- `rule-synthesis-engine/rule_template_generator.py` + `templates/falco_rule_template.yaml.j2`: Jinja2-based Falco YAML rule generation.
- `rule-synthesis-engine/rule_backtester.py`: backtests candidate rules against real historical benign Falco events.
- `rule-synthesis-engine/rule_deployer.py`: deploys approved rules to live Falco via `auto-generated-rules.yaml` + hot-reload.
- `rule-synthesis-engine/rule_lifecycle_manager.py`: tracks TP/FP outcomes in `rule_performance`, flags rules for retirement.
- Fixed: added missing `UNIQUE` constraint on `rule_performance.rule_id`.
- Fixed: Falco config (`/etc/falco/falco.yaml`) was missing `auto-generated-rules.yaml` from `rules_files` — added.
- Documented: two integration findings for Phase 10 (backend `/confirm` not persisting; rule_deployer.py condition re-fire not yet reproduced).

### Fixed — Phase 2/3/4 validation (2026-09-30)
- Phase 2 and Phase 3 validated against real `docker inspect` / real Falco default rules (previously code-complete but unvalidated).
- Fixed duplicate comma syntax error in `collect_baseline.py`.
- Fixed `--storage-dir` relative-path bug in `validate_live.py`.
- Recaptured Phase 4 baseline after discovering the original 21-sample baseline was all-zero (no real events captured).
- Documented: `feature_extractor.py`'s `shell_spawned_count` does not credit Falco's default "Terminal shell in container" rule as a shell-spawn signal.

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
