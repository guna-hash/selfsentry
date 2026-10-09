# Pre-deployment gate (selfsentry-run)

## Usage
```bash
bin/selfsentry-run [--override-reason "why"] -- <docker run arguments, without -d>
```
The container is always started detached. Exit codes: 0 allowed or overridden, 1 blocked,
2 docker error.

## What it does
1. `docker create` with your arguments (the container exists but is not running).
2. `docker inspect` it; the result is exactly what the policy checker expects.
3. Trivy image scan (`image-scanner/trivy_wrapper.py`) and policy check
   (`policy-checker/deploy_policy_validator.py`).
4. Blocked: the created container is removed. Allowed: `docker start`.
5. The decision, the scan summary, the top critical findings and the policy violations are
   recorded in the backend (`deployments` and `scan_results` tables) and shown on the
   dashboard's Deployments page. Blocked deployments are highlighted.

## Safety properties
- Fails closed: if the scan cannot run, the deployment is blocked.
- An admin can override a block with `--override-reason`; the override and its reason are recorded.
- If the backend is unreachable the decision is still enforced locally; a warning is printed
  and the dashboard history will have a gap for that deployment.

## Known limitations
- Only deployments made through the wrapper are gated. A plain `docker run` bypasses it; the
  continuous monitor is intended to catch those. System-wide enforcement would need a Docker
  authorization plugin (future work).
- `-d/--detach` is not supported (`docker create` has no such flag).
- Policy checks use the existing four rules (root user, privileged, added capabilities,
  writable root filesystem) plus the image scan verdict.
