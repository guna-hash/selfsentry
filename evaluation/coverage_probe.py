"""Empirical Falco rule coverage: which scenarios fire which enabled rules.

Each probe runs ONE harmless trigger inside the target container and records the
non-baseline Falco rules that fired. A scenario is only "supported" if an expected
rule actually fired; otherwise it is reported as not fired, never assumed.
This is a Falco-layer check, not a rate: one firing shows the rule can fire here.

Side effects (by design): the monitor will see these events and may create incidents
and, if automatic confirmation is on, candidate rules. Automatic isolation must be OFF.
Probe windows are written to state/evaluation/coverage.json so they can be excluded
from trial and benign corpora. Run it with no other workload on the target.
"""

from safety import check_monitor

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from clock_guard import AlertTail, ClockGuardError, DEFAULT_ALERTS_PATH  # noqa: E402

SCENARIOS = [
    {
        "name": "terminal-shell",
        "category": "shell",
        "tty": True,
        "command": "true",
        "expected": ["Terminal shell in container"],
    },
    {
        "name": "new-binary-execution",
        "category": "unexpected-process",
        "tty": False,
        "command": (
            'set -eu; d=$(mktemp -d /tmp/selfsentry-probe.XXXXXX); '
            'trap \'rm -rf "$d"\' EXIT; cp /bin/true "$d/probe-true"; '
            'chmod 700 "$d/probe-true"; '
            '"$d/probe-true"'
        ),
        "expected": ["Drop and execute new binary in container"],
    },
    {
        "name": "execution-from-dev-shm",
        "category": "unexpected-process",
        "tty": False,
        "command": (
            'set -eu; cp /bin/true /dev/shm/probe-true; '
            '/dev/shm/probe-true; '
            'rm -f /dev/shm/probe-true'
        ),
        "expected": ["Execution from /dev/shm"],
    },
    {
        "name": "sensitive-file-read",
        "category": "sensitive-file",
        "tty": False,
        "command": "cat /etc/shadow >/dev/null",
        "expected": ["Read sensitive file untrusted", "Read sensitive file trusted after startup"],
    },
    {
        "name": "symlink-over-sensitive-file",
        "category": "sensitive-file",
        "tty": False,
        "command": "ln -s /etc/shadow /tmp/probe-link; rm -f /tmp/probe-link",
        "expected": ["Create Symlink Over Sensitive Files"],
    },
    {
        "name": "stdio-redirect-to-socket",
        "category": "networking",
        "tty": False,
        "command": (
            "bash -c 'exec 3<>/dev/tcp/127.0.0.1/80; "
            'exec 0<&3 1>&3 2>&3; '
            "true'"
        ),
        "expected": ["Redirect STDOUT/STDIN to Network Connection in Container"],
    },
]


def judge_probe(alerts, expected):
    """Pure: classify the alerts one probe produced."""
    fired = [a for a in alerts if not (a.get("rule") or "").startswith("Baseline")]
    names = sorted({a["rule"] for a in fired})
    matched = [n for n in names if n in expected]
    return {
        "fired_rules": names,
        "expected_rules": expected,
        "expected_rule_fired": bool(matched),
        "matched_rules": matched,
        "status": "fires" if matched else ("other_rule_only" if names else "not_fired"),
    }


def run_probe(scenario, container, tail, wait_seconds):
    check_monitor()
    tail.mark()
    started = datetime.now(timezone.utc).isoformat()
    cmd = (
        ["docker", "exec"]
        + (["-t"] if scenario["tty"] else [])
        + [container, "/bin/sh", "-c", scenario["command"]]
    )
    outcome = subprocess.run(cmd, capture_output=True, text=True)
    time.sleep(wait_seconds)
    target = json.loads(subprocess.check_output(["docker", "inspect", container]))[0]["Id"][:12]
    verdict = judge_probe(tail.new_alerts(target), scenario["expected"])
    return {
        "scenario": scenario["name"],
        "category": scenario["category"],
        "started": started,
        "finished": datetime.now(timezone.utc).isoformat(),
        "command_returncode": outcome.returncode,
        **verdict,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", default="selfsentry-test")
    parser.add_argument("--alerts", default=DEFAULT_ALERTS_PATH)
    parser.add_argument("--wait", type=float, default=8.0)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    tail = AlertTail(args.alerts)
    results = []
    try:
        for scenario in SCENARIOS:
            result = run_probe(scenario, args.container, tail, args.wait)
            results.append(result)
            print(
                f"{result['scenario']:32s} {result['status']:16s} {result['fired_rules']}",
                flush=True,
            )
            time.sleep(5)
    except ClockGuardError as exc:
        raise SystemExit(f"Cannot read Falco output: {exc}")
    out = root / "state/evaluation/coverage.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(
            {
                "container": args.container,
                "results": results,
                "unexercised": [
                    "privilege/container-escape rules: no safe harmless trigger "
                    "in an unprivileged container"
                ],
            },
            indent=2,
        )
        + "\n"
    )
    print("Saved:", out)


if __name__ == "__main__":
    main()
