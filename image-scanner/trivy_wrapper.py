"""
trivy_wrapper.py
-----------------
Module 1 of ContainerGuard AI: Image Scanner.

Wraps the Trivy CLI to scan a container image for:
  - Known vulnerabilities (CVEs)
  - Embedded secrets
  - Misconfigurations

Design notes:
  - Trivy itself is used as-is (off-the-shelf tool); this module is the
    original glue code: invocation, parsing, normalization, and a clean
    Python interface for the rest of the pipeline (policy checker,
    backend API, dashboard) to consume.
  - No credentials or API keys are required for local image scanning,
    so there is nothing to load from environment variables here yet.
    If a private registry requires auth later, credentials MUST be
    read from environment variables (e.g. TRIVY_USERNAME / TRIVY_PASSWORD),
    never hardcoded.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class Severity(str, Enum):
    UNKNOWN = "UNKNOWN"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class TrivyNotInstalledError(RuntimeError):
    """Raised when the trivy binary cannot be found on PATH."""


class TrivyScanError(RuntimeError):
    """Raised when trivy runs but exits with an unexpected error."""


@dataclass
class Vulnerability:
    id: str
    pkg_name: str
    installed_version: str
    fixed_version: Optional[str]
    severity: str
    title: Optional[str] = None


@dataclass
class Secret:
    rule_id: str
    category: str
    severity: str
    file_path: str
    match: str  # should already be redacted/truncated by Trivy


@dataclass
class Misconfiguration:
    id: str
    title: str
    severity: str
    resolution: Optional[str] = None


@dataclass
class ScanResult:
    image: str
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    secrets: list[Secret] = field(default_factory=list)
    misconfigurations: list[Misconfiguration] = field(default_factory=list)
    raw: Optional[dict] = None  # full raw trivy JSON, kept for audit/debug

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.HIGH)

    @property
    def has_blocking_findings(self) -> bool:
        """
        Convenience flag for the (future) Deployment Policy Checker:
        True if the scan found anything a sane default policy would block on.
        """
        return self.critical_count > 0 or len(self.secrets) > 0

    def summary(self) -> dict:
        return {
            "image": self.image,
            "critical": self.critical_count,
            "high": self.high_count,
            "total_vulnerabilities": len(self.vulnerabilities),
            "secrets_found": len(self.secrets),
            "misconfigurations_found": len(self.misconfigurations),
        }


def _check_trivy_installed() -> str:
    path = shutil.which("trivy")
    if not path:
        raise TrivyNotInstalledError(
            "trivy binary not found on PATH. Install it first: "
            "https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
        )
    return path


def _run_trivy_json(image: str, timeout_seconds: int = 300) -> dict:
    """
    Runs `trivy image --format json --scanners vuln,secret,misconfig <image>`
    and returns the parsed JSON. Raises TrivyScanError on non-zero exit
    (except for the informational "vulnerabilities found" exit code, which
    trivy does not use by default — default exit code is 0 even with findings
    unless --exit-code is explicitly set, which we deliberately do NOT set
    here so a normal finding-containing scan is not treated as a failure).
    """
    _check_trivy_installed()

    cmd = [
        "trivy",
        "image",
        "--format",
        "json",
        "--scanners",
        "vuln,secret,misconfig",
        "--quiet",
        image,
    ]

    logger.info("Running trivy scan: %s", " ".join(cmd))
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TrivyScanError(f"trivy scan timed out after {timeout_seconds}s") from exc
    except FileNotFoundError as exc:
        raise TrivyNotInstalledError("trivy binary not found on PATH") from exc

    if proc.returncode != 0:
        raise TrivyScanError(
            f"trivy exited with code {proc.returncode}. stderr: {proc.stderr.strip()}"
        )

    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise TrivyScanError(f"failed to parse trivy JSON output: {exc}") from exc


def _parse_scan_result(image: str, raw: dict) -> ScanResult:
    result = ScanResult(image=image, raw=raw)

    for target in raw.get("Results", []) or []:
        for v in target.get("Vulnerabilities", []) or []:
            result.vulnerabilities.append(
                Vulnerability(
                    id=v.get("VulnerabilityID", "UNKNOWN"),
                    pkg_name=v.get("PkgName", "unknown"),
                    installed_version=v.get("InstalledVersion", "unknown"),
                    fixed_version=v.get("FixedVersion") or None,
                    severity=v.get("Severity", Severity.UNKNOWN),
                    title=v.get("Title"),
                )
            )

        for s in target.get("Secrets", []) or []:
            result.secrets.append(
                Secret(
                    rule_id=s.get("RuleID", "unknown"),
                    category=s.get("Category", "unknown"),
                    severity=s.get("Severity", Severity.UNKNOWN),
                    file_path=target.get("Target", "unknown"),
                    match=s.get("Match", ""),
                )
            )

        for m in target.get("Misconfigurations", []) or []:
            result.misconfigurations.append(
                Misconfiguration(
                    id=m.get("ID", "unknown"),
                    title=m.get("Title", "unknown"),
                    severity=m.get("Severity", Severity.UNKNOWN),
                    resolution=m.get("Resolution"),
                )
            )

    return result


def scan_image(image: str, timeout_seconds: int = 300) -> ScanResult:
    """
    Public entry point: scan a container image and return a normalized
    ScanResult. This is what the Deployment Policy Checker and the
    backend API should import and call.

    Example:
        result = scan_image("nginx:1.25")
        if result.has_blocking_findings:
            ...
    """
    if not image or not image.strip():
        raise ValueError("image must be a non-empty string, e.g. 'nginx:1.25'")

    raw = _run_trivy_json(image, timeout_seconds=timeout_seconds)
    return _parse_scan_result(image, raw)


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="ContainerGuard AI - Image Scanner (Trivy wrapper)")
    parser.add_argument("image", help="Container image to scan, e.g. nginx:1.25")
    parser.add_argument("--timeout", type=int, default=300, help="Scan timeout in seconds")
    parser.add_argument("--json", action="store_true", help="Print full raw JSON instead of summary")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    try:
        scan_result = scan_image(args.image, timeout_seconds=args.timeout)
    except TrivyNotInstalledError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)
    except TrivyScanError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(json.dumps(scan_result.raw, indent=2))
    else:
        print(json.dumps(scan_result.summary(), indent=2))
