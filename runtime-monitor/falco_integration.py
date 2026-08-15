"""
falco_integration.py
---------------------
Module 3 of ContainerGuard AI: Falco Rule Engine integration.

Wraps Falco's JSON alert output and normalizes it into ContainerGuard AI's
internal Falco alert schema — "shape #1" in docs/interfaces.md — which the
Correlation Engine (Phase 5) and everything downstream depends on:

    {
        "container_id": "abc123",
        "timestamp": "2026-08-09T10:15:00Z",
        "rule": "Terminal shell in container",
        "priority": "WARNING",
        "output": "A shell was spawned in a container (user=root container=abc123)"
    }

Design notes:
  - Falco itself is used as-is (off-the-shelf, CNCF-graduated tool); this
    module is the original glue code: tailing its output, parsing,
    normalizing field names/casing, and handling malformed/partial data
    defensively so a bad line never crashes the pipeline.
  - Falco is configured to write JSON alerts to a log file (the simplest
    output channel to integrate with — see docs/phase3_falco_integration.md
    for the exact falco.yaml settings). This module tails that file.
  - No credentials or API keys are involved in this module, so there is
    nothing to load from environment variables here.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

logger = logging.getLogger(__name__)


class FalcoParseError(ValueError):
    """Raised when a raw Falco output line cannot be parsed/normalized."""


# Falco's own priority strings (see falco_common::priority_names upstream)
# mapped to the upper-case form ContainerGuard AI uses internally. Kept as
# an explicit map (rather than just .upper()) so "Informational" normalizes
# to "INFO" and any future/unexpected value still degrades gracefully via
# _normalize_priority()'s fallback rather than raising.
_PRIORITY_MAP = {
    "EMERGENCY": "EMERGENCY",
    "ALERT": "ALERT",
    "CRITICAL": "CRITICAL",
    "ERROR": "ERROR",
    "WARNING": "WARNING",
    "NOTICE": "NOTICE",
    "INFORMATIONAL": "INFO",
    "INFO": "INFO",
    "DEBUG": "DEBUG",
}

# output_fields keys that may carry the container id. "container.id" is the
# real Falco field name (dotted, per Falco's field syntax); "container_id"
# is kept as a defensive fallback in case of a differently-shaped upstream
# output_fields payload.
_CONTAINER_ID_FIELDS = ("container.id", "container_id")

# Falco sets container.id to the literal string "host" (case can vary by
# version/output path) for events that aren't tied to any container.
_NON_CONTAINER_ID_VALUES = {"host", "<na>", ""}

# The minimum set of keys ContainerGuard AI needs from a raw Falco JSON
# alert. If any are missing, the line is treated as unparseable rather than
# silently producing a half-populated alert.
_REQUIRED_RAW_FIELDS = ("rule", "priority", "output", "time")


@dataclass
class FalcoAlert:
    container_id: Optional[str]
    timestamp: str
    rule: str
    priority: str
    output: str
    raw: dict  # full raw Falco JSON, kept for audit/debug/backtesting

    def to_dict(self) -> dict:
        """
        Shape #1 from docs/interfaces.md — this is what the Correlation
        Engine (Phase 5) and everything downstream consumes. Do not rename
        these keys without updating docs/interfaces.md and syncing with
        whoever owns Phase 5 and later.
        """
        return {
            "container_id": self.container_id,
            "timestamp": self.timestamp,
            "rule": self.rule,
            "priority": self.priority,
            "output": self.output,
        }


def _extract_container_id(output_fields: dict) -> Optional[str]:
    for key in _CONTAINER_ID_FIELDS:
        value = output_fields.get(key)
        if value and str(value).strip().lower() not in _NON_CONTAINER_ID_VALUES:
            return value
    return None


def _normalize_priority(raw_priority: str) -> str:
    return _PRIORITY_MAP.get(
        (raw_priority or "").strip().upper(), (raw_priority or "UNKNOWN").strip().upper()
    )


def parse_falco_alert(raw_line: str) -> FalcoAlert:
    """
    Parse a single line of Falco JSON output (as produced by Falco with
    `json_output: true`) into a normalized FalcoAlert.

    Raises FalcoParseError if the line is empty, not valid JSON, or is
    missing a required field. This function does no I/O — it is a pure
    function over a string, which is what makes it unit-testable without a
    live Falco process (see tests/test_falco_integration.py).
    """
    raw_line = raw_line.strip()
    if not raw_line:
        raise FalcoParseError("empty line")

    try:
        raw = json.loads(raw_line)
    except json.JSONDecodeError as exc:
        raise FalcoParseError(f"invalid JSON: {exc}") from exc

    missing = [k for k in _REQUIRED_RAW_FIELDS if k not in raw]
    if missing:
        raise FalcoParseError(f"missing required field(s): {missing}")

    output_fields = raw.get("output_fields") or {}
    container_id = _extract_container_id(output_fields)

    return FalcoAlert(
        container_id=container_id,
        timestamp=raw["time"],
        rule=raw["rule"],
        priority=_normalize_priority(raw["priority"]),
        output=raw["output"],
        raw=raw,
    )


def _parse_and_filter_line(line: str, container_only: bool) -> Optional[dict]:
    """
    Shared parsing+filtering logic used by both the batch reader and the
    live tailer, so the two entry points can never silently drift apart.
    Returns None (rather than raising) for lines that should be skipped —
    either unparseable, or filtered out because they're not container
    events and container_only=True.
    """
    try:
        alert = parse_falco_alert(line)
    except FalcoParseError as exc:
        logger.warning("Skipping unparseable Falco line: %s", exc)
        return None

    if container_only and alert.container_id is None:
        return None

    return alert.to_dict()


def read_falco_alerts_from_file(log_path: str, container_only: bool = True) -> list[dict]:
    """
    Read and parse an ENTIRE Falco JSON log file from start to end (no
    tailing, no blocking) and return the list of normalized alerts (shape
    #1). Useful for:
      - automated tests (deterministic, finite input)
      - Phase 6's rule backtester, which needs to replay a fixed batch of
        historical events against a candidate rule, not tail a live stream

    Malformed lines are logged and skipped rather than raising, so one bad
    line in a large log doesn't abort the whole read.
    """
    alerts: list[dict] = []
    with open(log_path, "r") as f:
        for line in f:
            normalized = _parse_and_filter_line(line, container_only)
            if normalized is not None:
                alerts.append(normalized)
    return alerts


def stream_falco_alerts(
    log_path: str,
    container_only: bool = True,
    poll_interval_seconds: float = 0.5,
    from_start: bool = False,
) -> Iterator[dict]:
    """
    Tail Falco's JSON output log file and yield normalized alert dicts
    (shape #1) as new lines arrive. This is a live, blocking generator —
    run it in its own thread/process, or iterate it directly in a script.

    container_only: skip alerts that aren't tied to a container (host-level
      events) — the sensible default for a container-security-only project.
    from_start: if True, read the whole existing file first, then keep
      tailing (useful for a first manual test run so you see something
      immediately); if False (default), seek to the end and only yield NEW
      alerts — the behavior you want once this is wired into the real
      pipeline, so you don't replay old alerts on every restart.

    This function's live-tailing behavior (blocking + polling for genuinely
    new lines appended in real time by a running Falco process) is
    validated MANUALLY against a real Falco install — see
    docs/phase3_falco_integration.md — since that is fundamentally an
    I/O-and-timing concern, not parsing logic. The parsing/filtering logic
    it shares with read_falco_alerts_from_file() IS unit-tested.
    """
    path = Path(log_path)
    with open(path, "r") as f:
        if not from_start:
            f.seek(0, 2)  # seek to end of file — only see alerts from now on

        while True:
            line = f.readline()
            if not line:
                time.sleep(poll_interval_seconds)
                continue

            normalized = _parse_and_filter_line(line, container_only)
            if normalized is not None:
                yield normalized


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="ContainerGuard AI - Falco alert stream (Phase 3 manual validation tool)"
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
    parser.add_argument(
        "--include-host", action="store_true", help="Include non-container (host) alerts too."
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    try:
        if args.mode == "batch":
            for normalized_alert in read_falco_alerts_from_file(
                args.log_path, container_only=not args.include_host
            ):
                print(json.dumps(normalized_alert))
        else:
            for normalized_alert in stream_falco_alerts(
                args.log_path,
                container_only=not args.include_host,
                from_start=args.from_start,
            ):
                print(json.dumps(normalized_alert))
    except FileNotFoundError:
        print(f"ERROR: log file not found: {args.log_path}", file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        sys.exit(0)
