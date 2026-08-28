"""
baseline_collector.py
----------------------
Module 4d of SelfSentry: Behavioral Runtime Monitor (baseline capture).

Reads Falco's JSON output log — the same file runtime-monitor/
falco_integration.py tails for real security alerts (shape #1) — but
recognizes only the four "Baseline *" rules from falco-rules/
baseline-capture-rules.yaml, converting each matching line into a
RawEvent (feature_extractor.py's input type).

Design notes:
  - This module and falco_integration.py can safely tail the SAME log
    file at the same time. Each one recognizes a disjoint set of rule
    names and silently ignores lines it doesn't recognize - a real
    security alert line is invisible to this module, and a baseline line
    is invisible to falco_integration.py. No coordination between the two
    is required.
  - Falco's own top-level "time" field is used for the event timestamp,
    NOT the custom "timestamp=%evt.time.iso8601" field baked into our
    rules' output text - that field turned out to return a raw nanosecond
    integer rather than a formatted string on this Falco version (see
    docs/phase4_behavioral_engine.md for the verified example). "time" is
    the same reliable field falco_integration.py already depends on, so
    reusing it keeps both modules on consistent footing.
  - Deliberately does NOT import from falco_integration.py, even though
    container-id extraction is nearly identical - the two modules parse
    genuinely different event schemas (security alerts vs. baseline
    events), and falco_integration.py's helpers are private
    (underscore-prefixed) by design, meaning Phase 3 never intended them
    to be a public shared API. A few lines of duplication here is a
    smaller risk than coupling this module's correctness to Phase 3's
    internals changing later. If this duplication grows, it's a good
    candidate to extract into a shared falco_common.py - not needed yet.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Iterator, Optional

from feature_extractor import EventType, RawEvent

logger = logging.getLogger(__name__)


class BaselineParseError(ValueError):
    """Raised when a raw Falco log line cannot be parsed as a baseline event."""


# Maps this project's baseline-capture-rules.yaml rule names to the
# RawEvent.event_type they represent. Any log line whose "rule" isn't in
# this map is silently skipped - it's either a real security alert (not
# ours to handle) or something else entirely.
_RULE_TO_EVENT_TYPE: dict[str, EventType] = {
    "Baseline Process Spawn": EventType.PROCESS_SPAWN,
    "Baseline Network Outbound": EventType.NETWORK_CONNECT,
    "Baseline File Write": EventType.FILE_ACCESS,
    "Baseline Sensitive Syscall": EventType.SYSCALL,
}

# Same field-name/value conventions as falco_integration.py - duplicated
# deliberately, see module docstring.
_CONTAINER_ID_FIELDS = ("container.id", "container_id")
_NON_CONTAINER_ID_VALUES = {"host", "<na>", ""}


def _extract_container_id(output_fields: dict) -> Optional[str]:
    for key in _CONTAINER_ID_FIELDS:
        value = output_fields.get(key)
        if value and str(value).strip().lower() not in _NON_CONTAINER_ID_VALUES:
            return value
    return None


def _build_event_kwargs(event_type: EventType, output_fields: dict) -> dict:
    """Pulls the specific fields each event_type needs out of Falco's
    output_fields - the rest of RawEvent's fields stay None, which
    RawEvent.from_dict()/the dataclass defaults already handle."""
    if event_type == EventType.PROCESS_SPAWN:
        return {
            "proc_name": output_fields.get("proc.name"),
            "parent_proc_name": output_fields.get("proc.pname"),
        }
    if event_type == EventType.NETWORK_CONNECT:
        raw_port = output_fields.get("fd.rport")
        return {
            "dest_ip": output_fields.get("fd.rip"),
            "dest_port": int(raw_port) if raw_port not in (None, "") else None,
        }
    if event_type == EventType.FILE_ACCESS:
        return {"file_path": output_fields.get("fd.name")}
    if event_type == EventType.SYSCALL:
        return {"syscall_name": output_fields.get("evt.type")}
    return {}


def parse_baseline_event(raw_line: str) -> Optional[RawEvent]:
    """
    Parse a single line of Falco JSON output. Returns a RawEvent if the
    line is one of our four baseline rules; returns None (not an error)
    if it's a different rule entirely - that's the expected, common case
    since this log also contains real security alerts. Raises
    BaselineParseError only for lines that are baseline-rule lines but
    are genuinely malformed (bad JSON, missing fields).
    """
    raw_line = raw_line.strip()
    if not raw_line:
        return None

    try:
        raw = json.loads(raw_line)
    except json.JSONDecodeError:
        return None  # not JSON at all - not our concern, skip quietly

    rule_name = raw.get("rule")
    event_type = _RULE_TO_EVENT_TYPE.get(rule_name)
    if event_type is None:
        return None  # a real security alert or unrelated rule - not ours

    if "time" not in raw:
        raise BaselineParseError(f"baseline rule {rule_name!r} line missing 'time' field")

    output_fields = raw.get("output_fields") or {}
    container_id = _extract_container_id(output_fields)
    if container_id is None:
        return None  # host-level event, not tied to a container - skip

    event_dict = {
        "container_id": container_id,
        "timestamp": raw["time"],
        "event_type": event_type.value,
        **_build_event_kwargs(event_type, output_fields),
    }
    return RawEvent.from_dict(event_dict)


def read_baseline_events_from_file(log_path: str) -> list[RawEvent]:
    """
    Read an ENTIRE Falco JSON log file from start to end and return every
    recognized baseline event as a RawEvent. Malformed baseline-rule lines
    are logged and skipped (not raised) so one bad line doesn't abort a
    whole learning-window read.
    """
    events: list[RawEvent] = []
    with open(log_path, "r") as f:
        for line in f:
            try:
                event = parse_baseline_event(line)
            except BaselineParseError as exc:
                logger.warning("Skipping malformed baseline line: %s", exc)
                continue
            if event is not None:
                events.append(event)
    return events


def stream_baseline_events(
    log_path: str,
    poll_interval_seconds: float = 0.5,
    from_start: bool = False,
) -> Iterator[RawEvent]:
    """
    Tail Falco's JSON log file live and yield RawEvents as new baseline
    lines arrive. Mirrors falco_integration.stream_falco_alerts()'s
    tailing behavior exactly (same seek/poll approach) so the two can run
    side by side with consistent, predictable behavior.
    """
    path = Path(log_path)
    with open(path, "r") as f:
        if not from_start:
            f.seek(0, 2)  # seek to end - only see events from now on

        while True:
            line = f.readline()
            if not line:
                time.sleep(poll_interval_seconds)
                continue

            try:
                event = parse_baseline_event(line)
            except BaselineParseError as exc:
                logger.warning("Skipping malformed baseline line: %s", exc)
                continue
            if event is not None:
                yield event


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="SelfSentry - Baseline event stream (Phase 4 manual validation tool)"
    )
    parser.add_argument("log_path", help="Path to Falco's JSON output log file")
    parser.add_argument(
        "--mode",
        choices=["tail", "batch"],
        default="tail",
        help="'tail' follows the file live (default). 'batch' reads the whole file once and exits.",
    )
    parser.add_argument(
        "--from-start",
        action="store_true",
        help="[tail mode only] Read existing file content first, then keep tailing.",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    def _preview(event: RawEvent) -> dict:
        return {
            "container_id": event.container_id,
            "timestamp": event.timestamp.isoformat(),
            "event_type": event.event_type.value,
            "proc_name": event.proc_name,
            "parent_proc_name": event.parent_proc_name,
            "dest_ip": event.dest_ip,
            "dest_port": event.dest_port,
            "file_path": event.file_path,
            "syscall_name": event.syscall_name,
        }

    try:
        if args.mode == "batch":
            for evt in read_baseline_events_from_file(args.log_path):
                print(json.dumps(_preview(evt)))
        else:
            for evt in stream_baseline_events(args.log_path, from_start=args.from_start):
                print(json.dumps(_preview(evt)))
    except FileNotFoundError:
        print(f"ERROR: log file not found: {args.log_path}", file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        sys.exit(0)
