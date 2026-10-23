"""Invalid-clock detection for evaluation trials.

Falco once emitted stale timestamps after a VM clock change. Such a trial looks like a
silent miss, because the incident lands in the wrong window. Two independent checks
guard against it, both comparing Falco's own event times with the host clock:

* Preflight (python3 evaluation/clock_guard.py): runs a harmless probe command in the
  target container, finds the resulting Falco events by file position (never by time,
  which is exactly what would be wrong) and records pass/fail in
  state/evaluation/clock_check.json. The collector refuses to run without a recent pass.
* Per trial: every Falco event written during the trial must fall inside the trial's
  host-clock window (+/- tolerance). A trial that ran a command but produced no Falco
  events is also invalid.

The probe runs a process in the target container; run it between trials, not during one.
"""

import argparse
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_MAX_SKEW = 2.0
DEFAULT_MAX_AGE_SECONDS = 1800
DEFAULT_ALERTS_PATH = "/var/log/falco/alerts.json"


class ClockGuardError(RuntimeError):
    pass


def parse_falco_time(value):
    text = re.sub(r"(\.\d{6})\d+", r"\1", value.replace("Z", "+00:00"))
    stamp = datetime.fromisoformat(text)
    if stamp.tzinfo is None:
        raise ValueError("Falco event time has no timezone")
    return stamp.timestamp()


class AlertTail:
    """Reads only what Falco wrote after mark(); tolerant of log rotation."""

    def __init__(self, path):
        self.path = Path(path)
        self.offset = None
        self.inode = None

    def mark(self):
        try:
            info = self.path.stat()
            self.offset, self.inode = info.st_size, info.st_ino
        except OSError as exc:
            raise ClockGuardError(f"cannot read Falco alert file {self.path}: {exc}") from exc

    def new_alerts(self, container_id):
        """Parsed Falco alerts for the container written since mark()."""
        if self.offset is None:
            raise ClockGuardError("mark() must be called before reading alerts")
        try:
            info = self.path.stat()
            rotated = info.st_ino != self.inode or info.st_size < self.offset
            start = 0 if rotated else self.offset
            with self.path.open("rb") as stream:
                stream.seek(start)
                data = stream.read().decode("utf-8", errors="replace")
        except OSError as exc:
            raise ClockGuardError(f"cannot read Falco alert file {self.path}: {exc}") from exc
        alerts = []
        for line in data.splitlines():
            try:
                raw = json.loads(line)
                fields = raw.get("output_fields") or {}
                cid = fields.get("container.id") or fields.get("container_id") or ""
                if cid and (container_id.startswith(cid) or cid.startswith(container_id)):
                    alerts.append(
                        {
                            "time": parse_falco_time(raw["time"]),
                            "rule": raw.get("rule"),
                            "priority": raw.get("priority"),
                        }
                    )
            except (ValueError, KeyError, TypeError, AttributeError):
                continue
        return alerts

    def new_events(self, container_id):
        return [alert["time"] for alert in self.new_alerts(container_id)]


def judge_events(event_times, window_start, window_end, expect_events, max_skew=DEFAULT_MAX_SKEW):
    """Compare Falco event times with the host-clock window. Pure function."""
    result = {"n_events": len(event_times), "max_skew_allowed_seconds": max_skew}
    if not event_times:
        result["valid"] = not expect_events
        result["status"] = (
            "no_events_expected_but_none" if expect_events else "unverified_no_events"
        )
        return result
    skews = [max(window_start - t, t - window_end, 0.0) for t in event_times]
    result["max_observed_skew_seconds"] = round(max(skews), 3)
    result["valid"] = max(skews) <= max_skew
    result["status"] = "ok" if result["valid"] else "falco_clock_skew"
    return result


def require_recent_preflight(path, container_id, max_age_seconds=DEFAULT_MAX_AGE_SECONDS):
    try:
        record = json.loads(Path(path).read_text())
    except (OSError, ValueError) as exc:
        raise ClockGuardError(
            "no clock preflight on record; run: python3 evaluation/clock_guard.py"
        ) from exc
    age = time.time() - record.get("checked_at_epoch", 0)
    if record.get("container_id") != container_id:
        raise ClockGuardError("clock preflight was for a different container")
    if not record.get("passed"):
        raise ClockGuardError(f"last clock preflight failed: {record.get('status')}")
    if age > max_age_seconds:
        raise ClockGuardError(f"clock preflight is {int(age)}s old; rerun it")
    return record


def run_preflight(container, alerts_path, state_path, max_skew=DEFAULT_MAX_SKEW, wait_seconds=15):
    info = json.loads(subprocess.check_output(["docker", "inspect", container]))[0]
    target = info["Id"][:12]
    tail = AlertTail(alerts_path)
    tail.mark()
    before = time.time()
    subprocess.run(["docker", "exec", container, "/bin/true"], check=True, capture_output=True)
    events, deadline = [], time.time() + wait_seconds
    while not events and time.time() < deadline:
        time.sleep(0.5)
        events = tail.new_events(target)
    after = time.time()
    verdict = judge_events(events, before, after, expect_events=True, max_skew=max_skew)
    record = {
        "container_id": target,
        "checked_at_epoch": after,
        "checked_at": datetime.fromtimestamp(after, timezone.utc).isoformat(),
        "passed": verdict["valid"],
        **verdict,
    }
    Path(state_path).parent.mkdir(parents=True, exist_ok=True)
    Path(state_path).write_text(json.dumps(record, indent=2) + "\n")
    return record


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="Clock preflight against live Falco output.")
    parser.add_argument("--container", default="selfsentry-test")
    parser.add_argument("--alerts", default=DEFAULT_ALERTS_PATH)
    parser.add_argument("--max-skew", type=float, default=DEFAULT_MAX_SKEW)
    args = parser.parse_args()
    try:
        record = run_preflight(
            args.container, args.alerts, root / "state/evaluation/clock_check.json", args.max_skew
        )
    except (ClockGuardError, subprocess.CalledProcessError) as exc:
        print(f"CLOCK PREFLIGHT ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
    print(json.dumps(record, indent=2))
    raise SystemExit(0 if record["passed"] else 1)


if __name__ == "__main__":
    main()
