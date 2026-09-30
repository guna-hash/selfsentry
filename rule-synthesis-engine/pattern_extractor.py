"""
pattern_extractor.py
-----------------------
Rule Synthesis Engine — Pattern Extractor.

Takes a CONFIRMED incident (fetched from the real backend after
confirmation_manager.py succeeds) and extracts a small, structured,
literal pattern describing the triggering behavior — e.g. which
process was spawned by which parent process, under which Falco rule.

Design constraint (non-negotiable): patterns must stay narrow and
literal, not generalized. This is what rule_template_generator.py
renders into Falco YAML, so an overly broad pattern here becomes an
overly broad (noisy or unsafe) auto-generated rule downstream.

Known scope limitation (v1): extraction requires a falco_alert to be
present on the incident, since Falco rule conditions need concrete
process/syscall fields to match against. Anomaly-only incidents (no
falco_alert) are not yet supported for rule synthesis — see
docs/known_limitations.md. This is a deliberate, documented scope
choice, not an oversight.
"""

from __future__ import annotations

import re

# Different Falco rules format their triggering process differently in
# the free-text `output` field. We try each candidate key, in order,
# since there is no single universal field name across rule types.
PROC_NAME_KEYS = ("process", "proc_name", "proc.name")
PARENT_PROC_KEYS = ("parent", "parent_proc_name", "proc.pname")

_KV_PATTERN = re.compile(r"(\w[\w.]*)=([^\s]+)")


class PatternExtractionError(RuntimeError):
    """Raised when a confirmed incident lacks enough structure to extract a pattern from."""


def _parse_output_fields(output_text: str) -> dict:
    """
    Parses Falco's free-text `output` string into a dict of key=value
    pairs. Real Falco output looks like:
        "... process=sh proc_exepath=/usr/bin/dash parent=containerd-shim ..."
    Not every alert's output has these fields (some, like simulated/
    synthetic alerts, use plain prose instead) — callers must handle
    an empty or partial result gracefully.
    """
    return dict(_KV_PATTERN.findall(output_text or ""))


def _first_present(fields: dict, candidate_keys: tuple[str, ...]) -> str | None:
    for key in candidate_keys:
        if key in fields:
            return fields[key]
    return None


def extract_pattern(confirmed_incident: dict) -> dict:
    """
    Extracts a structured pattern dict from a confirmed incident.

    Returns a dict shaped like:
        {
            "container_id": "...",
            "rule_name": "Terminal shell in container",
            "proc_name": "sh",              # may be None if not parseable
            "parent_proc": "containerd-shim",  # may be None if not parseable
            "action": "spawned_process",
        }

    Raises PatternExtractionError if the incident has no falco_alert at
    all — see the module docstring's scope limitation.
    """
    falco_alert = confirmed_incident.get("falco_alert")
    if not falco_alert:
        raise PatternExtractionError(
            f"Incident {confirmed_incident.get('id')} has no falco_alert — "
            "anomaly-only pattern extraction is not yet supported (v1 scope limitation, "
            "see docs/known_limitations.md)."
        )

    output_fields = _parse_output_fields(falco_alert.get("output", ""))
    proc_name = _first_present(output_fields, PROC_NAME_KEYS)
    parent_proc = _first_present(output_fields, PARENT_PROC_KEYS)

    return {
        "container_id": confirmed_incident.get("container_id"),
        "rule_name": falco_alert.get("rule"),
        "proc_name": proc_name,
        "parent_proc": parent_proc,
        "action": "spawned_process",
    }


if __name__ == "__main__":
    import argparse
    import json

    import requests

    parser = argparse.ArgumentParser(description="SelfSentry - Extract a pattern from a confirmed incident")
    parser.add_argument("incident_id", type=int)
    parser.add_argument("--backend-url", default="http://localhost:8000")
    args = parser.parse_args()

    resp = requests.get(f"{args.backend_url}/incidents/{args.incident_id}", timeout=10)
    resp.raise_for_status()
    incident = resp.json()

    try:
        pattern = extract_pattern(incident)
    except PatternExtractionError as exc:
        print(f"ERROR: {exc}")
        raise SystemExit(1)

    print(json.dumps(pattern, indent=2))
