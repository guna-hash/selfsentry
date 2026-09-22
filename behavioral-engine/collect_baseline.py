"""
collect_baseline.py
---------------------
Module 4e of SelfSentry: Behavioral Runtime Monitor (baseline capture
driver).

The script you actually RUN to collect a real learning-window baseline.
Tails Falco's JSON log for a fixed duration, buckets incoming baseline
events into fixed time windows, extracts a FeatureVector per window
(feature_extractor.py), and persists each one via BaselineStore
(baseline_builder.py).

Usage:
    python3 collect_baseline.py <container_id> --minutes 15

Design notes:
  - Does its own tailing loop rather than reusing baseline_collector.py's
    stream_baseline_events() generator, because that generator only
    returns control to its caller when a NEW line actually arrives - it
    can't also notice "a time window just closed" during a quiet stretch
    with no events. This script's loop checks the wall clock on every
    iteration regardless, so windows close on schedule even if the
    container is momentarily idle.
  - Only events for the target container_id are kept - anything else in
    the log (other containers, non-container/host events, real security
    alerts) is ignored, since extract_features() is per-container by
    design (see behavioral-engine/feature_extractor.py's Design notes).
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime, timedelta, timezone

from baseline_builder import BaselineStore
from baseline_collector import BaselineParseError, parse_baseline_event
from feature_extractor import extract_features


def run_capture(
    container_id: str,
    log_path: str,
    duration_minutes: float,
    window_seconds: float,
    storage_dir: str,
    poll_interval_seconds: float = 0.5,
) -> None:
    store = BaselineStore(storage_dir=storage_dir)
    end_time = time.monotonic() + (duration_minutes * 60)

    window_start = datetime.now(timezone.utc)
    window_end = window_start + timedelta(seconds=window_seconds)
    buffer: list = []

    windows_closed = 0
    print(
        f"Capturing baseline for container_id={container_id!r} "
        f"for {duration_minutes} minute(s), {window_seconds}s windows. "
        f"Reading: {log_path}"
    )
    print("Generate normal traffic against the container now. Ctrl+C to stop early.\n")

    with open(log_path, "r") as f:
        f.seek(0, 2)  # only see events from now on, not historical log content

        while time.monotonic() < end_time:
            line = f.readline()
            if line:
                try:
                    event = parse_baseline_event(line)
                except BaselineParseError as exc:
                    print(f"  [skip] malformed baseline line: {exc}", file=sys.stderr)
                    event = None
                if event is not None and event.container_id == container_id:
                    buffer.append(event)
            else:
                time.sleep(poll_interval_seconds)

            now = datetime.now(timezone.utc)
            if now >= window_end:
                fv = extract_features(buffer, container_id, window_start, window_end)
                store.append(fv)
                windows_closed += 1
                print(
                    f"  window {windows_closed} closed "
                    f"[{window_start.strftime('%H:%M:%S')}-{window_end.strftime('%H:%M:%S')}]: "
                    f"{fv.total_event_count} events -> "
                    f"proc={fv.distinct_process_count} "
                    f"net={fv.distinct_network_dest_count} "
                    f"files={fv.distinct_files_accessed} "
                    f"shell={fv.shell_spawned_count} "
                    f"syscall={fv.sensitive_syscall_count}"
                )
                buffer = []
                window_start = window_end
                window_end = window_start + timedelta(seconds=window_seconds)

    dataset = store.load(container_id)
    print(
        f"\nDone. {dataset.sample_count} baseline sample(s) stored for "
        f"{container_id!r}. Ready to train: {dataset.is_ready}"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="SelfSentry - Phase 4 real baseline capture driver"
    )
    parser.add_argument(
        "container_id", help="Container ID to capture baseline for (short or full)"
    )
    parser.add_argument(
        "--log-path",
        default="/var/log/falco/alerts.json",
        help="Path to Falco's JSON alert log",
    )
    parser.add_argument(
        "--minutes", type=float, default=15.0, help="Capture duration in minutes"
    )
    parser.add_argument(
        "--window-seconds", type=float, default=60.0, help="Window size in seconds"
    )
    parser.add_argument(
        "--storage-dir",
        default="baselines",,
        help="Where BaselineStore writes per-container JSON files",
    )
    args = parser.parse_args()

    try:
        run_capture(
            container_id=args.container_id,
            log_path=args.log_path,
            duration_minutes=args.minutes,
            window_seconds=args.window_seconds,
            storage_dir=args.storage_dir,
        )
    except FileNotFoundError:
        print(f"ERROR: log file not found: {args.log_path}", file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        print("\nStopped early by user.")
        sys.exit(0)
