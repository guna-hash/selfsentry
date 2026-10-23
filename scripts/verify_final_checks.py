"""Run release checks and preserve their output without contacting live services."""

from datetime import datetime, timezone
from pathlib import Path
import json
from importlib.metadata import version, PackageNotFoundError
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
STAMP = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
OUT = ROOT / "state/evaluation" / f"final-checks-{STAMP}"
OUT.mkdir(parents=True, exist_ok=True)
CHECKS = [
    ("python-tests", ROOT, [sys.executable, "-m", "pytest", "tests/", "-q"]),
    (
        "lint", ROOT,
        [sys.executable, "-m", "flake8", ".",
         "--exclude=.git,.venv,venv,node_modules,state,dist,build", "--max-line-length=100"],
    ),
    ("types", ROOT, [sys.executable, str(ROOT / "scripts/verify_types.py")]),
    (
        "frontend-tests",
        ROOT / "frontend-dashboard",
        ["npm", "run", "test", "--", "--run"],
    ),
    ("frontend-build", ROOT / "frontend-dashboard", ["npm", "run", "build"]),
]


def command_version(command):
    try:
        return subprocess.check_output(command, cwd=ROOT, text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unavailable"


versions = {}
for package in ("docker", "scikit-learn", "fastapi", "sqlalchemy", "pytest", "flake8"):
    try:
        versions[package] = version(package)
    except PackageNotFoundError:
        versions[package] = "unavailable"
report = {
    "started_at": datetime.now(timezone.utc).isoformat(),
    "checks": [],
    "source_commit": command_version(["git", "rev-parse", "HEAD"]),
    "source_status": command_version(["git", "status", "--short"]),
    "python": sys.version,
    "packages": versions,
    "node": command_version(["node", "--version"]),
    "npm": command_version(["npm", "--version"]),
}
for name, cwd, command in CHECKS:
    print(f"Running {name}...", flush=True)
    log = OUT / f"{name}.log"
    try:
        with log.open("w") as stream:
            process = subprocess.Popen(
                command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )
            assert process.stdout is not None  # PIPE is requested above.
            for line in process.stdout:
                print(line, end="", flush=True)
                stream.write(line)
            code = process.wait()
    except OSError as exc:
        code = 127
        log.write_text(str(exc) + "\n")
        print(f"{name}: {exc}")
    report["checks"].append(
        {"name": name, "returncode": code, "passed": code == 0, "log": str(log.relative_to(ROOT))}
    )
    report["passed"] = all(c["passed"] for c in report["checks"])
    (OUT / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    if code:
        print(f"Check failed; evidence: {OUT}")
        raise SystemExit(code)
print(f"All {len(CHECKS)} checks passed. Evidence: {OUT}")
