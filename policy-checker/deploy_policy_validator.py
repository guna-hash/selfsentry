"""
deploy_policy_validator.py
----------------------------
Module 2 of ContainerGuard AI: Deployment Policy Checker.

Inspects a container's deployment configuration (shaped like ONE element of
the JSON array returned by `docker inspect <container>`) and blocks it if it
violates ContainerGuard AI's default security policy:

  1. Container must not run as root.
  2. Container must not run in --privileged mode.
  3. Container must not be granted additional Linux capabilities (--cap-add).
  4. Container's root filesystem should be read-only (--read-only).

It also accepts the Phase 1 Image Scanner's verdict so a single call to
check_deployment_config() can express "block this deployment" for either a
bad image OR a bad runtime config. This module deliberately does NOT import
anything from image-scanner/ -- the caller passes
`image_scan_has_blocking_findings` (e.g. from trivy_wrapper.ScanResult) in
directly, keeping the two phases decoupled and independently testable.

Design notes:
  - This module is Docker-SDK-free on purpose: it reads a plain dict shaped
    like `docker inspect` output, so it stays cheap to unit test with fixture
    dicts and has no extra runtime dependency beyond the standard library.
  - No credentials or secrets are used or required by this module.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class PolicySeverity(str, Enum):
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Violations at/above these severities block deployment outright.
BLOCKING_SEVERITIES = (PolicySeverity.HIGH, PolicySeverity.CRITICAL)


@dataclass
class PolicyViolation:
    rule_id: str
    title: str
    severity: PolicySeverity
    detail: str
    remediation: str


@dataclass
class PolicyResult:
    container_name: str
    violations: list[PolicyViolation] = field(default_factory=list)

    @property
    def is_compliant(self) -> bool:
        return len(self.violations) == 0

    @property
    def blocking_violations(self) -> list[PolicyViolation]:
        return [v for v in self.violations if v.severity in BLOCKING_SEVERITIES]

    @property
    def should_block_deployment(self) -> bool:
        return len(self.blocking_violations) > 0

    def summary(self) -> dict:
        return {
            "container": self.container_name,
            "compliant": self.is_compliant,
            "total_violations": len(self.violations),
            "blocking_violations": len(self.blocking_violations),
            "should_block_deployment": self.should_block_deployment,
            "violation_rule_ids": [v.rule_id for v in self.violations],
        }


def _extract_container_name(container_spec: dict) -> str:
    name = container_spec.get("Name") or container_spec.get("Id", "unknown")
    return name.lstrip("/")


def _check_root_user(container_spec: dict) -> Optional[PolicyViolation]:
    user = (container_spec.get("Config", {}) or {}).get("User", "") or ""
    user_part = user.split(":")[0].strip()

    if user_part in ("", "root", "0"):
        return PolicyViolation(
            rule_id="POLICY-ROOT-USER",
            title="Container runs as root",
            severity=PolicySeverity.HIGH,
            detail=(
                f"Config.User is {user!r}, which resolves to root (empty means "
                "the image's default user -- commonly root -- will be used)."
            ),
            remediation="Add a USER instruction in the Dockerfile or pass --user <uid> at runtime.",
        )
    return None


def _check_privileged(container_spec: dict) -> Optional[PolicyViolation]:
    privileged = (container_spec.get("HostConfig", {}) or {}).get("Privileged", False)
    if privileged:
        return PolicyViolation(
            rule_id="POLICY-PRIVILEGED",
            title="Container runs in --privileged mode",
            severity=PolicySeverity.CRITICAL,
            detail=(
                "HostConfig.Privileged is true, granting the container "
                "near-host-level access."
            ),
            remediation=(
                "Remove --privileged; grant only the specific capabilities "
                "actually required."
            ),
        )
    return None


def _check_excess_capabilities(container_spec: dict) -> Optional[PolicyViolation]:
    cap_add = (container_spec.get("HostConfig", {}) or {}).get("CapAdd") or []
    if cap_add:
        return PolicyViolation(
            rule_id="POLICY-EXCESS-CAPS",
            title="Container was granted additional Linux capabilities",
            severity=PolicySeverity.HIGH,
            detail=f"HostConfig.CapAdd includes: {', '.join(cap_add)}.",
            remediation=(
                "Remove --cap-add unless the workload specifically requires it; "
                "prefer the default capability set."
            ),
        )
    return None


def _check_writable_root_fs(container_spec: dict) -> Optional[PolicyViolation]:
    read_only = (container_spec.get("HostConfig", {}) or {}).get("ReadonlyRootfs", False)
    if not read_only:
        return PolicyViolation(
            rule_id="POLICY-WRITABLE-ROOTFS",
            title="Container root filesystem is writable",
            severity=PolicySeverity.MEDIUM,
            detail="HostConfig.ReadonlyRootfs is false.",
            remediation=(
                "Run with --read-only and mount explicit writable "
                "volumes/tmpfs only where needed."
            ),
        )
    return None


def check_deployment_config(
    container_spec: dict,
    image_scan_has_blocking_findings: bool = False,
    image_scan_summary: Optional[dict] = None,
) -> PolicyResult:
    """
    Public entry point: validate a container's deployment configuration
    against ContainerGuard AI's default security policy.

    Args:
        container_spec: a dict shaped like ONE element of the JSON array
            returned by `docker inspect <container>`.
        image_scan_has_blocking_findings: pass Phase 1's
            ScanResult.has_blocking_findings here to also block on a bad
            image, without this module importing image-scanner directly.
        image_scan_summary: optionally pass ScanResult.summary() for a
            richer violation detail message.

    Example:
        import json, subprocess
        raw = json.loads(subprocess.check_output(["docker", "inspect", "mycontainer"]))
        result = check_deployment_config(raw[0])
        if result.should_block_deployment:
            ...
    """
    if not isinstance(container_spec, dict):
        raise ValueError(
            "container_spec must be a dict shaped like `docker inspect` output"
        )

    result = PolicyResult(container_name=_extract_container_name(container_spec))

    for check in (
        _check_root_user,
        _check_privileged,
        _check_excess_capabilities,
        _check_writable_root_fs,
    ):
        violation = check(container_spec)
        if violation:
            result.violations.append(violation)

    if image_scan_has_blocking_findings:
        detail = (
            "Phase 1 image scan reported blocking findings "
            "(critical CVE and/or exposed secret)."
        )
        if image_scan_summary:
            detail += f" Summary: {image_scan_summary}"
        result.violations.append(
            PolicyViolation(
                rule_id="POLICY-IMAGE-SCAN-BLOCKING",
                title="Underlying image failed the pre-deployment security scan",
                severity=PolicySeverity.CRITICAL,
                detail=detail,
                remediation=(
                    "Resolve the critical vulnerabilities/secrets found by "
                    "the Image Scanner before deploying."
                ),
            )
        )

    return result


if __name__ == "__main__":
    import argparse
    import json
    import subprocess
    import sys

    parser = argparse.ArgumentParser(
        description="ContainerGuard AI - Deployment Policy Checker"
    )
    parser.add_argument(
        "container", help="Name or ID of a running container to check, e.g. mycontainer"
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    try:
        raw_output = subprocess.run(
            ["docker", "inspect", args.container],
            capture_output=True,
            text=True,
            check=True,
        )
        inspect_data = json.loads(raw_output.stdout)
    except subprocess.CalledProcessError as e:
        print(f"ERROR: docker inspect failed: {e.stderr.strip()}", file=sys.stderr)
        sys.exit(2)
    except FileNotFoundError:
        print("ERROR: docker binary not found on PATH", file=sys.stderr)
        sys.exit(2)
    except json.JSONDecodeError as e:
        print(f"ERROR: failed to parse docker inspect output: {e}", file=sys.stderr)
        sys.exit(1)

    if not inspect_data:
        print(f"ERROR: no container found matching '{args.container}'", file=sys.stderr)
        sys.exit(1)

    policy_result = check_deployment_config(inspect_data[0])
    print(json.dumps(policy_result.summary(), indent=2))
    if policy_result.should_block_deployment:
        sys.exit(1)
