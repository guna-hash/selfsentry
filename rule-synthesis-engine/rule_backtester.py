"""Backtest only supported literal templates; never approximate arbitrary Falco conditions."""

from __future__ import annotations
import re
import yaml

FP_RATE_THRESHOLD = 0.05
_LITERAL = r"[A-Za-z0-9_./:+-]{1,256}"
_PROCESS = re.compile(
    rf'^spawned_process and container and proc.name="({_LITERAL})" '
    rf'and proc.pname="({_LITERAL})"$'
)
_FILE = re.compile(
    rf'^open_write and container and proc.name="({_LITERAL})" ' rf'and fd.name="(/{_LITERAL})"$'
)
_OUTPUT_KV_PATTERN = re.compile(r"(\w[\w.]*)=([^\s]+)")


class BacktestError(RuntimeError):
    pass


def condition_fields(candidate_rule_yaml):
    try:
        items = yaml.safe_load(candidate_rule_yaml)
    except yaml.YAMLError as exc:
        raise BacktestError("Invalid candidate YAML") from exc
    if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], dict):
        raise BacktestError("Exactly one supported template rule is required")
    condition = items[0].get("condition", "")
    if not isinstance(condition, str):
        raise BacktestError("Invalid candidate condition")
    match = _PROCESS.fullmatch(condition)
    if match:
        return "Baseline Process Spawn", *match.groups()
    match = _FILE.fullmatch(condition)
    if match:
        return "Baseline File Write", *match.groups()
    raise BacktestError("Unsupported Falco condition; refusing an approximate backtest")


def _extract_condition_fields(candidate_rule_yaml):
    return condition_fields(candidate_rule_yaml)[1:]


def _event_matches(event, proc_name, parent_proc, kind="Baseline Process Spawn"):
    if event.get("rule") != kind:
        return False
    fields = dict(_OUTPUT_KV_PATTERN.findall(event.get("output", "")))
    structured = event.get("output_fields") or {}
    process = structured.get("proc.name") or event.get("proc_name") or fields.get("proc_name")
    if kind == "Baseline File Write":
        other = structured.get("fd.name") or event.get("file_path") or fields.get("file_path")
    else:
        other = (
            structured.get("proc.pname")
            or event.get("parent_proc_name")
            or fields.get("parent_proc_name")
        )
    return process == proc_name and other == parent_proc


def backtest_rule(candidate_rule_yaml, historical_benign_events):
    kind, process, other = condition_fields(candidate_rule_yaml)
    events = [e for e in historical_benign_events if e.get("rule") == kind]
    # Missing comparison fields are unknown, never counted as benign negatives.
    usable = []
    for event in events:
        fields = {
            **dict(_OUTPUT_KV_PATTERN.findall(event.get("output", ""))),
            **(event.get("output_fields") or {}),
        }
        proc = fields.get("proc.name") or event.get("proc_name") or fields.get("proc_name")
        second = (
            (fields.get("fd.name") or event.get("file_path") or fields.get("file_path"))
            if kind == "Baseline File Write"
            else (
                fields.get("proc.pname")
                or event.get("parent_proc_name")
                or fields.get("parent_proc_name")
            )
        )
        if proc and second and proc not in ("<NA>", "<na>") and second not in ("<NA>", "<na>"):
            usable.append(event)
    count = len(usable)
    matched = sum(_event_matches(e, process, other, kind) for e in usable)
    rate = matched / count if count else 0
    return {
        "false_positive_rate": round(rate, 4),
        "matched_events": matched,
        "false_positives": matched,
        "true_negatives": count - matched,
        "true_positives": None,
        "true_positives_reason": "Benign-only corpus; TP not measured",
        "events_tested": count,
        "unusable_events": len(events) - count,
        "verdict": "pass" if count and rate <= FP_RATE_THRESHOLD else "flag_for_revision",
    }


if __name__ == "__main__":
    import argparse
    import json
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime-monitor"))
    from falco_integration import read_falco_alerts_from_file

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rule_yaml_file")
    parser.add_argument("--log-path", default="/var/log/falco/alerts.json")
    args = parser.parse_args()
    result = backtest_rule(
        Path(args.rule_yaml_file).read_text(), read_falco_alerts_from_file(args.log_path)
    )
    print(json.dumps(result, indent=2))
