"""Create a source-only review archive; do not change the working tree.

Includes project source/docs/tests plus acceptance-check evidence and selected
measured summaries. Excludes environment files, raw incidents/logs/telemetry,
baselines, database files, dependencies, build output and backup directories.
Stops on likely API-key literals. This is a review bundle, not a deployment image.
"""

from pathlib import Path
from datetime import datetime, timezone
import hashlib
import io
import json
import os
import re
import subprocess
import tarfile

EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "dist",
    "build",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "baselines",
}
SUFFIXES = {
    ".py",
    ".md",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".html",
    ".css",
    ".sh",
    ".json",
    ".yaml",
    ".yml",
    ".sql",
    ".j2",
    ".toml",
    ".ini",
    ".cfg",
}
KEY = re.compile(rb"(?:gsk_[A-Za-z0-9]{20,}|sk-(?:proj-)?[A-Za-z0-9_-]{24,})")


def main():
    root = Path.cwd()
    if not (root / "monitor-service/monitor_service.py").is_file():
        raise SystemExit("Run from ~/selfsentry.")
    files = []

    def consider(p):
        rel = p.relative_to(root)
        if p.is_symlink() or any(x in EXCLUDED_DIRS for x in rel.parts):
            return
        if p.name.startswith(".env") and p.name != ".env.example":
            return
        if p.suffix.lower() not in SUFFIXES and p.name not in (
            "requirements.txt",
            "Dockerfile",
            "Makefile",
            ".gitignore",
            ".dockerignore",
            ".env.example",
        ):
            return
        raw = p.read_bytes()
        if KEY.search(raw):
            raise SystemExit(
                "Possible API-key literal in "
                + str(rel)
                + "; no archive written. Remove it locally before exporting."
            )
        files.append((rel.as_posix(), raw))

    for directory, names, filenames in os.walk(root, followlinks=False):
        names[:] = [
            name
            for name in names
            if name not in EXCLUDED_DIRS
            and name != "state"
            and "backup" not in name.lower()
            and not name.startswith(("before-", "_before", "_pre_"))
        ]
        folder = Path(directory)
        if folder.name == "evaluation":
            names[:] = []
        for filename in filenames:
            p = folder / filename
            if not p.is_file():
                continue
            rel = p.relative_to(root)
            if rel.parts[0] == "evaluation" and p.suffix not in (".py", ".md", ".sh"):
                continue
            consider(p)
    # Structured acceptance evidence is useful; strip nested full incidents/payloads.
    acceptance = root / "state/evaluation/acceptance"
    summaries = []
    if acceptance.is_dir():
        for p in sorted(acceptance.glob("*/evidence.json")):
            row = json.loads(p.read_text())
            summaries.append(
                {
                    k: row[k]
                    for k in (
                        "test",
                        "evidence_type",
                        "passed",
                        "checks",
                        "results",
                        "container_id",
                        "container_name",
                        "started_at",
                        "finished_at",
                        "container_removed",
                        "database_active_at_cleanup",
                        "failure",
                        "cleanup_error",
                    )
                    if k in row
                }
            )
    files.append(("review/acceptance_summary.json", json.dumps(summaries, indent=2).encode()))
    for name in ("full-20261011-results.json", "saved-layer-comparison.json"):
        p = root / "state/evaluation" / name
        if p.is_file():
            files.append(("review/" + name, p.read_bytes()))

    def git(*args):
        return subprocess.check_output(["git", *args], cwd=root, text=True).strip()

    try:
        commit = git("rev-parse", "HEAD")
        status = git("status", "--short")
        diffstat = git("diff", "HEAD", "--stat")
    except subprocess.CalledProcessError:
        commit = status = diffstat = "unavailable"
    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "commit": commit,
        "git_status": status,
        "diff_stat": diffstat,
        "files": {name: hashlib.sha256(raw).hexdigest() for name, raw in sorted(files)},
        "exclusions": (
            "Environment, databases, baseline datasets, raw telemetry/incidents, "
            "dependencies, builds and backups"
        ),
    }
    files.append(("review/source_manifest.json", json.dumps(manifest, indent=2).encode()))
    output = Path.home() / "Downloads" / "selfsentry-final-review.tar.gz"
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output = output.with_name("selfsentry-final-review-" + stamp + ".tar.gz")
    with tarfile.open(output, "w:gz") as archive:
        for name, raw in sorted(files):
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(raw), 0o600
            archive.addfile(info, io.BytesIO(raw))
    print("Source files and summaries:", len(files))
    print("Acceptance records:", len(summaries))
    print("Upload:", output)
    print("Working tree and original evidence unchanged.")


if __name__ == "__main__":
    main()
