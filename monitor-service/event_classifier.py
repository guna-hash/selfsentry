"""
event_classifier.py
---------------------
Turns one raw Falco log line into a normalized event for the monitor.

Uses runtime-monitor/falco_integration.parse_falco_alert for parsing, so the normalized
fields (container_id, timestamp, rule, priority, output) keep the project's shape #1.
Extra context (container name, image, process names) is read defensively from Falco's
output_fields and left as None when Falco did not provide it.

Events from the baseline-capture rules (rule names starting with "Baseline ") are
behavioural telemetry for the anomaly model, not security alerts; everything else from a
container is a security alert.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "runtime-monitor"))

from falco_integration import FalcoParseError, parse_falco_alert  # noqa: E402

BASELINE_RULE_PREFIX = "Baseline "
_ABSENT = (None, "", "<NA>", "<na>")


class MalformedEvent(ValueError):
    """A log line that could not be parsed as a Falco alert."""


@dataclass
class ClassifiedEvent:
    kind: str  # "alert" or "baseline"
    event: dict


def _first(fields: dict, keys: tuple) -> str | None:
    for key in keys:
        value = fields.get(key)
        if value not in _ABSENT:
            return str(value)
    return None


def _context(fields: dict) -> dict:
    repository = _first(fields, ("container.image.repository", "container_image_repository"))
    tag = _first(fields, ("container.image.tag", "container_image_tag"))
    image = f"{repository}:{tag}" if repository and tag else repository
    return {
        "container_name": _first(fields, ("container.name", "container_name")),
        "image_name": image,
        "proc_name": _first(fields, ("proc.name", "proc_name")),
        "parent_proc_name": _first(fields, ("proc.pname", "parent_proc_name")),
        "cmdline": _first(fields, ("proc.cmdline",)),
    }


def classify_line(line: str, event_key: str | None = None) -> ClassifiedEvent | None:
    """Return the classified event, or None for host-level events (no container)."""
    try:
        alert = parse_falco_alert(line)
    except FalcoParseError as exc:
        raise MalformedEvent(str(exc)) from exc
    if not alert.container_id:
        return None

    event = alert.to_dict()
    event.update(_context(alert.raw.get("output_fields") or {}))
    event["event_key"] = event_key
    kind = "baseline" if alert.rule.startswith(BASELINE_RULE_PREFIX) else "alert"
    return ClassifiedEvent(kind=kind, event=event)
