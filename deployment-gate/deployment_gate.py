"""
deployment_gate.py
--------------------
Pre-deployment enforcement gate ("selfsentry-run").

Use it exactly like `docker run`, but without -d (the container is always started
detached):

    bin/selfsentry-run [--override-reason "why"] -- <docker run arguments>

Flow:
    docker create -> docker inspect -> Trivy image scan -> policy check
    blocked : the created container is removed, the decision is recorded (dashboard)
    allowed : docker start, the decision is recorded
    override: a blocked deployment started anyway by an admin with a stated reason; the
              override and its reason are recorded

The gate FAILS CLOSED: if the image scan cannot run, the deployment is blocked.
Recording the decision in the backend is best-effort: if the backend is unreachable the
decision is still enforced locally and a warning is printed.

Scope: the gate covers deployments made through this wrapper. A plain `docker run`
bypasses it; the continuous monitor is what catches those.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import subprocess
import sys

import requests

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_REPO_ROOT, "image-scanner"))
sys.path.insert(0, os.path.join(_REPO_ROOT, "policy-checker"))

from deploy_policy_validator import check_deployment_config  # noqa: E402
from trivy_wrapper import TrivyNotInstalledError, TrivyScanError, scan_image  # noqa: E402

DEFAULT_BACKEND_URL = "http://localhost:8000"
OWN_FLAGS = ("--override-reason", "--backend-url")
MAX_FINDINGS = 10


class DockerCommandError(RuntimeError):
    """Raised when a docker command the gate depends on fails."""


def _docker(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=False)


def _docker_ok(*args: str) -> str:
    proc = _docker(*args)
    if proc.returncode != 0:
        raise DockerCommandError(f"docker {args[0]} failed: {proc.stderr.strip()}")
    return proc.stdout.strip()


def parse_args(argv: list[str]):
    """Split SelfSentry's own options from the docker run arguments.

    Own options are only recognised at the very start, and must be followed by `--`.
    Everything else is passed to docker untouched.
    """
    parser = argparse.ArgumentParser(
        prog="selfsentry-run",
        usage="selfsentry-run [--override-reason TEXT] [--backend-url URL] -- <docker run args>",
        description="Scan and policy-check a container before it starts.",
    )
    parser.add_argument("--override-reason")
    parser.add_argument("--backend-url", default=DEFAULT_BACKEND_URL)

    own, docker_args = [], list(argv)
    if argv and argv[0] == "--":
        docker_args = list(argv[1:])
    elif argv and argv[0].split("=")[0] in OWN_FLAGS:
        if "--" not in argv:
            parser.error("put -- between SelfSentry options and the docker run arguments")
        split = argv.index("--")
        own, docker_args = list(argv[:split]), list(argv[split + 1:])
    options = parser.parse_args(own)
    options.override_reason = (options.override_reason or "").strip() or None
    if not docker_args:
        parser.error("no docker run arguments given")
    return options, docker_args


def create_container(docker_args: list[str]) -> str:
    output = _docker_ok("create", *docker_args)
    return output.splitlines()[-1].strip()


def inspect_container(container_id: str) -> dict:
    return json.loads(_docker_ok("inspect", container_id))[0]


def evaluate(spec: dict):
    """Scan the image and check the policy. A scan failure is returned, not raised."""
    image = (spec.get("Config") or {}).get("Image") or spec.get("Image", "")
    scan, scan_error = None, None
    try:
        scan = scan_image(image)
    except (TrivyNotInstalledError, TrivyScanError, ValueError) as exc:
        scan_error = str(exc)
    policy = check_deployment_config(
        spec,
        image_scan_has_blocking_findings=bool(scan and scan.has_blocking_findings),
        image_scan_summary=scan.summary() if scan else None,
    )
    return image, scan, scan_error, policy


def decide(policy, scan_error: str | None, override_reason: str | None) -> str:
    blocked = policy.should_block_deployment or scan_error is not None
    if not blocked:
        return "allowed"
    return "overridden" if override_reason else "blocked"


def _top_findings(scan) -> list[dict]:
    findings = [
        {
            "id": v.id,
            "package": v.pkg_name,
            "installed": v.installed_version,
            "fixed": v.fixed_version,
            "severity": v.severity,
        }
        for v in scan.vulnerabilities
        if v.severity == "CRITICAL"
    ]
    findings += [
        {"id": s.rule_id, "package": s.file_path, "severity": s.severity} for s in scan.secrets
    ]
    return findings[:MAX_FINDINGS]


def build_record(
    container_id, image, scan, scan_error, policy, decision, override_reason
) -> dict:
    violations = [
        {
            "rule_id": v.rule_id,
            "title": v.title,
            "severity": v.severity.value,
            "detail": v.detail,
            "remediation": v.remediation,
        }
        for v in policy.violations
    ]
    if scan_error:
        violations.append(
            {
                "rule_id": "GATE-SCAN-FAILED",
                "title": "Image scan could not run (gate fails closed)",
                "severity": "CRITICAL",
                "detail": scan_error,
                "remediation": "Fix the scanner (is Trivy installed and able to reach "
                "its database?) and redeploy.",
            }
        )
    return {
        "container_name": policy.container_name,
        "container_id": container_id[:12],
        "image_name": image,
        "decision": decision,
        "override_reason": override_reason,
        "requested_by": getpass.getuser(),
        "scan_summary": scan.summary() if scan else {},
        "scan_findings": _top_findings(scan) if scan else [],
        "policy_summary": policy.summary(),
        "policy_violations": violations,
    }


def record_decision(record: dict, backend_url: str) -> bool:
    try:
        response = requests.post(f"{backend_url}/deployments/", json=record, timeout=15)
    except requests.RequestException as exc:
        print(f"WARNING: could not record this decision in the dashboard: {exc}", file=sys.stderr)
        return False
    if response.status_code != 201:
        print(
            f"WARNING: backend rejected the deployment record: HTTP {response.status_code} "
            f"- {response.text}",
            file=sys.stderr,
        )
        return False
    return True


def run_gate(
    docker_args: list[str],
    override_reason: str | None = None,
    backend_url: str = DEFAULT_BACKEND_URL,
) -> dict:
    container_id = create_container(docker_args)
    try:
        spec = inspect_container(container_id)
        image, scan, scan_error, policy = evaluate(spec)
    except Exception:
        _docker("rm", "-f", container_id)  # never leave an unvetted container behind
        raise

    decision = decide(policy, scan_error, override_reason)
    if decision == "blocked":
        _docker("rm", "-f", container_id)
    else:
        try:
            _docker_ok("start", container_id)
        except DockerCommandError:
            _docker("rm", "-f", container_id)
            raise

    record = build_record(container_id, image, scan, scan_error, policy, decision, override_reason)
    recorded = record_decision(record, backend_url)
    return {
        "decision": decision,
        "container_id": container_id[:12],
        "record": record,
        "recorded": recorded,
    }


def print_report(result: dict) -> None:
    record = result["record"]
    decision = result["decision"]
    print(
        f"SelfSentry gate: {decision.upper()}  image={record['image_name']}  "
        f"container={record['container_name']}"
    )
    summary = record["scan_summary"]
    if summary:
        print(
            f"  scan: critical={summary.get('critical')} high={summary.get('high')} "
            f"secrets={summary.get('secrets_found')}"
        )
    for violation in record["policy_violations"]:
        print(f"  [{violation['severity']}] {violation['rule_id']}: {violation['title']}")
    if decision == "blocked":
        print(
            "  Not deployed. Fix the issues above, "
            "or deploy deliberately with --override-reason."
        )
    elif decision == "overridden":
        print(f"  Deployed under override: {record['override_reason']}")
    else:
        print(f"  Started container {result['container_id']}")
    if not result["recorded"]:
        print("  (decision not recorded in the dashboard - see the warning above)")


def main(argv: list[str] | None = None) -> int:
    options, docker_args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        result = run_gate(docker_args, options.override_reason, options.backend_url)
    except DockerCommandError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print_report(result)
    return 1 if result["decision"] == "blocked" else 0


if __name__ == "__main__":
    sys.exit(main())
