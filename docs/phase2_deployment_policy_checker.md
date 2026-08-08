# Phase 2 — Deployment Policy Checker

## What this phase delivers
A Python policy engine (`policy-checker/deploy_policy_validator.py`) that inspects a container's deployment configuration (shaped like `docker inspect <container>` output) and returns a `PolicyResult` describing every violation of ContainerGuard AI's default security policy:

1. **Non-root user** — `Config.User` must not be empty, `"root"`, or UID `0` (`HIGH`, blocking).
2. **No `--privileged` mode** — `HostConfig.Privileged` must be `false` (`CRITICAL`, blocking).
3. **No added Linux capabilities** — `HostConfig.CapAdd` must be empty (`HIGH`, blocking).
4. **Read-only root filesystem** — `HostConfig.ReadonlyRootfs` should be `true` (`MEDIUM`, **non-blocking** — flagged as a warning, per the project's "read-only where possible" wording).

It also accepts Phase 1's verdict directly via `image_scan_has_blocking_findings` (e.g. `trivy_wrapper.ScanResult.has_blocking_findings`), so one call to `check_deployment_config()` can express "block this deployment" for a bad image OR a bad runtime config — without this module importing anything from `image-scanner/`. The two phases stay decoupled; the caller (eventually the Phase 8 backend) wires them together.

## What's original vs. off-the-shelf
- **Off-the-shelf:** none — this is a from-scratch policy engine. Only the Docker CLI itself (already required elsewhere in the project) supplies the input data, via `docker inspect`.
- **Original:** all four rule checks, the severity model (which severities block vs. warn), the `PolicyResult` / `PolicyViolation` data model, the Phase 1 integration hook, and the CLI entry point.

## Automated tests
`tests/test_deploy_policy_validator.py` — 25 unit tests, all using plain dict fixtures shaped like real `docker inspect` output (no Docker daemon required). Covers:
- Each policy rule individually — violating case caught, compliant case not flagged (root-user check alone has 5 sub-cases: empty, `"root"`, `"0"`, `"0:0"`, and a missing `Config` key entirely)
- The Phase 1 image-scan integration hook, with and without a summary dict
- Derived `PolicyResult` properties: `is_compliant`, `blocking_violations`, `should_block_deployment`, `summary()`
- That a lone `MEDIUM`-severity finding (writable root FS) does **not** block deployment by itself
- Container name extraction, including fallback to `Id` when `Name` is missing
- Input validation (non-dict/`None` input, missing `Config`/`HostConfig` keys)

Run with:
```bash
python3 -m unittest tests.test_deploy_policy_validator -v
# or, once pytest is installed:
pytest tests/test_deploy_policy_validator.py -v
```
**Result as of this phase: 25/25 passed.** (Verified in the build sandbox — these are fully mocked/offline, no Docker or network needed. The CLI's `--help` and its clean-failure-when-docker-is-missing path were also manually smoke-tested there.)

## Manual validation (do this once, on your real Docker machine)
This is the one step that requires your actual machine — there's no Docker daemon in the sandbox this was built in:

1. Start a deliberately non-compliant container:
   ```bash
   docker run -d --name bad-container --privileged --cap-add=SYS_ADMIN nginx:1.25
   ```
2. Run the checker against it:
   ```bash
   cd containerguard-ai/policy-checker
   python3 deploy_policy_validator.py bad-container
   ```
   Confirm it exits non-zero (`echo $?`) and the JSON output's `violation_rule_ids` includes `POLICY-PRIVILEGED`, `POLICY-EXCESS-CAPS`, and (likely) `POLICY-ROOT-USER` and `POLICY-WRITABLE-ROOTFS`.
3. Start a clean, compliant container for comparison:
   ```bash
   docker run -d --name clean-container --read-only --user 1000:1000 nginx:1.25
   python3 deploy_policy_validator.py clean-container
   ```
   Confirm `"compliant": true` and an exit code of `0`. (nginx itself may not actually *run* correctly as non-root/read-only without extra tmpfs flags — the goal here is proving the checker reads a compliant config correctly, not getting nginx fully functional under this policy.)
4. Clean up:
   ```bash
   docker rm -f bad-container clean-container
   ```
5. Confirm both boxes in `TODO.md` and mark Phase 2 fully closed.

## Known limitations at this stage
- Reads `docker inspect` output directly — does not yet parse `docker-compose.yml` or Kubernetes pod specs (both out of current project scope).
- The capability check flags **any** `--cap-add`, not a curated "dangerous capabilities" subset — simple and conservative by design for a capstone-scale project.
- Not yet wired into an automatic pre-deployment gate/CI hook — it's a callable function + CLI today. Automatic enforcement is Phase 8/9 (backend/dashboard) territory.
