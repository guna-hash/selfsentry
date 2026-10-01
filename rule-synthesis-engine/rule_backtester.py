"""
rule_backtester.py
----------------------
Rule Synthesis Engine — Rule Backtester.

CRITICAL DESIGN CONSTRAINT: mandatory before any auto-generated rule
goes live. Tests a candidate rule against stored historical BENIGN
traffic to estimate its false-positive rate. A rule with an
unacceptable FP rate must never reach the human-approval queue marked
"ready" — it gets flagged for revision instead.

Source of "historical benign events": this project's own baseline
capture (Phase 4) already produces real, confirmed-normal activity via
the custom "Baseline Process Spawn" Falco rule. That is the benign
corpus used here — no synthetic/invented data.
"""

from __future__ import annotations

import re

FP_RATE_THRESHOLD = 0.05  # above this, flag for revision rather than approve

_CONDITION_PATTERN = re.compile(
    r'proc\.name="([^"]+)"\s+and\s+proc\.pname="([^"]+)"'
)
_OUTPUT_KV_PATTERN = re.compile(r"(\w[\w.]*)=([^\s]+)")


class BacktestError(RuntimeError):
    """Raised when the candidate rule YAML cannot be parsed for backtesting."""


def _extract_condition_fields(candidate_rule_yaml: str) -> tuple[str, str]:
    """
    Parses proc.name and proc.pname out of the rendered rule's condition
    line. This tests the REAL generated artifact (what Falco would
    actually load), not just the original input pattern dict.
    """
    match = _CONDITION_PATTERN.search(candidate_rule_yaml)
    if not match:
        raise BacktestError(
            "Could not find a proc.name=... and proc.pname=... condition in the "
            "candidate rule YAML — backtesting only supports this rule shape currently."
        )
    return match.group(1), match.group(2)


def _event_matches(event: dict, proc_name: str, parent_proc: str) -> bool:
    """
    Checks whether a single historical benign event (a parsed Falco
    alert dict, shape #1) would have been wrongly flagged by the
    candidate rule's process-spawn condition.
    """
    if event.get("rule") != "Baseline Process Spawn":
        return False  # only process-spawn events are relevant to this rule type

    fields = dict(_OUTPUT_KV_PATTERN.findall(event.get("output", "")))
    return (
        fields.get("proc_name") == proc_name
        and fields.get("parent_proc_name") == parent_proc
    )


def backtest_rule(candidate_rule_yaml: str, historical_benign_events: list[dict]) -> dict:
    """
    Returns {"false_positive_rate": float, "matched_events": int,
    "events_tested": int, "verdict": "pass" | "flag_for_revision"}.

    A "match" here means the candidate rule's condition would have
    fired on a historical event we already know was benign — i.e. a
    false positive.
    """
    proc_name, parent_proc = _extract_condition_fields(candidate_rule_yaml)

    process_spawn_events = [
        e for e in historical_benign_events if e.get("rule") == "Baseline Process Spawn"
    ]
    events_tested = len(process_spawn_events)
    matched_events = sum(
        1 for e in process_spawn_events if _event_matches(e, proc_name, parent_proc)
    )

    fp_rate = (matched_events / events_tested) if events_tested > 0 else 0.0
    verdict = "pass" if fp_rate <= FP_RATE_THRESHOLD else "flag_for_revision"

    return {
        "false_positive_rate": round(fp_rate, 4),
        "matched_events": matched_events,
        "events_tested": events_tested,
        "verdict": verdict,
    }


if __name__ == "__main__":
    import argparse
    import json
    import sys

    sys.path.insert(0, "../runtime-monitor")
    sys.path.insert(0, "runtime-monitor")  # works whether run from repo root or this folder

    from falco_integration import read_falco_alerts_from_file

    parser = argparse.ArgumentParser(description="SelfSentry - Backtest a candidate rule against real historical benign events")
    parser.add_argument("rule_yaml_file", help="Path to a .yaml file containing the candidate rule")
    parser.add_argument("--log-path", default="/var/log/falco/alerts.json")
    args = parser.parse_args()

    with open(args.rule_yaml_file) as f:
        candidate_rule_yaml = f.read()

    benign_events = read_falco_alerts_from_file(args.log_path)
    result = backtest_rule(candidate_rule_yaml, benign_events)
    print(json.dumps(result, indent=2))
