# Phase 1 — Image Scanner

## What this phase delivers
A Python wrapper (`image-scanner/trivy_wrapper.py`) around the Trivy CLI that:
- Scans a container image for vulnerabilities (CVEs), embedded secrets, and misconfigurations
- Normalizes Trivy's raw JSON into clean dataclasses (`Vulnerability`, `Secret`, `Misconfiguration`, `ScanResult`)
- Exposes a simple `scan_image(image: str) -> ScanResult` function for later phases (Policy Checker, Backend API) to call
- Provides a CLI entry point for manual/standalone use

## What's original vs. off-the-shelf
- **Off-the-shelf:** Trivy itself (the scanning engine/CVE database).
- **Original:** the invocation logic, error handling (missing binary, timeout, bad JSON), normalization into typed Python objects, the `has_blocking_findings` policy-ready flag, and the summary/reporting shape — this is the glue the rest of ContainerGuard AI depends on.

## Automated tests
`tests/test_trivy_wrapper.py` — 16 unit tests, all mocked (no real `trivy` binary or network required). Covers:
- Missing/found trivy binary
- Successful scan → correct JSON parsing
- Non-zero exit code, timeout, and malformed JSON error handling
- Vulnerability/secret/misconfiguration parsing correctness
- Derived properties (`critical_count`, `high_count`, `has_blocking_findings`)
- Input validation (empty/whitespace image name)

Run with:
```bash
python3 -m unittest tests.test_trivy_wrapper -v
# or, once pytest is installed:
pytest tests/ -v
```
**Result as of this phase: 16/16 passed.**

## Manual validation (do this once you have Trivy + Docker installed)
This is the one step that could NOT be run in the current sandbox (no internet access to install Trivy). Do this yourself to close out Phase 1:

1. Install Trivy: https://aquasecurity.github.io/trivy/latest/getting-started/installation/
2. Run a real scan:
   ```bash
   cd containerguard-ai/image-scanner
   python3 trivy_wrapper.py nginx:1.25
   ```
3. Confirm you get a JSON summary back, e.g.:
   ```json
   {
     "image": "nginx:1.25",
     "critical": 2,
     "high": 5,
     "total_vulnerabilities": 40,
     "secrets_found": 0,
     "misconfigurations_found": 0
   }
   ```
4. Try an image you know has a secret baked in (or build a throwaway test image with a fake AWS key in a file) to confirm secret detection works end-to-end.
5. Try a bogus image name (`python3 trivy_wrapper.py not-a-real-image:latest`) to confirm the error path exits cleanly with a useful message instead of a stack trace.

Once step 2–5 pass against real Trivy, mark Phase 1 fully complete in `TODO.md`.

## Known limitations at this stage
- No caching of Trivy's vulnerability DB update behavior is configured yet (first run will be slow — Trivy downloads its DB).
- No registry authentication wired up yet (public images only, for now — see `.env.example` for the planned env vars when private registries are needed).
- Not yet wired into the Deployment Policy Checker (Phase 2) — `has_blocking_findings` exists specifically so Phase 2 can consume it, but Phase 2 doesn't exist yet.
