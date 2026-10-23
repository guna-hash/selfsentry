"""Configuration and software fingerprints recorded with every evaluation trial.

Two trials are comparable only when their config_fingerprint matches. The
fingerprint covers things that change detection behaviour (baseline, rules,
Falco version, target image, monitor settings). Code commit and kernel are
recorded for context but deliberately excluded, so a documentation commit does
not split an otherwise identical batch.
"""

import hashlib
import json
import platform
import subprocess
from pathlib import Path

SECRET_MARKERS = ("TOKEN", "KEY", "PASSWORD", "SECRET", "URL", "CREDENTIAL")


def sha256_file(path):
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return "unavailable"


def _run(cmd):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable"
    text = (out.stdout or out.stderr).strip()
    return text.splitlines()[0] if text else "unavailable"


def _git_dirty(root):
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return bool(out.stdout.strip()) if out.returncode == 0 else None


def monitor_settings(env):
    """Non-secret MONITOR_* settings only; anything credential-like is dropped."""
    return {
        name: value
        for name, value in sorted(env.items())
        if name.startswith("MONITOR_")
        and value is not None
        and not any(marker in name.upper() for marker in SECRET_MARKERS)
    }


def collect_fingerprint(root, target, env, image_id):
    root = Path(root)
    rule_files = [
        Path("/etc/falco/falco_rules.yaml"),
        root / "falco-rules/baseline-capture-rules.yaml",
        root / "falco-rules/auto-generated-rules.yaml",
    ]
    baseline_dir = Path(env.get("MONITOR_BASELINE_DIR") or "behavioral-engine/baselines")
    if not baseline_dir.is_absolute():
        baseline_dir = root / baseline_dir
    components = {
        "baseline_sha256": sha256_file(baseline_dir / f"{target}.json"),
        "rule_file_sha256": {
            ("falco_rules.yaml" if p.name == "falco_rules.yaml" else p.name): sha256_file(p)
            for p in rule_files
        },
        "falco_version": _run(["falco", "--version"]),
        "target_image_id": image_id,
        "monitor_settings": monitor_settings(env),
    }
    canonical = json.dumps(components, sort_keys=True, separators=(",", ":"))
    context = {
        "code_commit": _run(["git", "-C", str(root), "rev-parse", "HEAD"]),
        "code_dirty": _git_dirty(root),
        "kernel": platform.release(),
        "python": platform.python_version(),
    }
    return {
        "config_fingerprint": hashlib.sha256(canonical.encode()).hexdigest(),
        "fingerprint_components": components,
        "software_context": context,
    }


if __name__ == "__main__":
    import argparse

    from dotenv import dotenv_values

    parser = argparse.ArgumentParser(description="Print the current configuration fingerprint.")
    parser.add_argument("--container", default="selfsentry-test")
    args = parser.parse_args()
    project_root = Path(__file__).resolve().parents[1]
    info = json.loads(subprocess.check_output(["docker", "inspect", args.container]))[0]
    print(
        json.dumps(
            collect_fingerprint(
                project_root, info["Id"][:12], dotenv_values(project_root / ".env"), info["Image"]
            ),
            indent=2,
        )
    )
