"""
validate_live.py
------------------
Module 4f of SelfSentry: Phase 4 manual validation driver.

Trains AnomalyModel on a container's stored baseline (baseline_builder.py)
and then scores LIVE incoming windows in real time, printing each
window's anomaly_score and is_anomaly flag as it closes. This is the
script that produces Phase 4's required "before/after" evidence: normal
windows should score low; a deliberately-triggered anomalous window
(docker exec -it <container> sh) should score clearly higher.

Usage:
    python3 validate_live.py <container_id> --minutes 3 --window-seconds 30

Let the first window or two run quiet (normal baseline-like behavior),
then trigger the anomalous action partway through the run.
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime, timedelta, timezone

from anomaly_model import AnomalyModel
from baseline_builder import BaselineStore
from baseline_collector import BaselineParseError, parse_baseline_event
from feature_extractor import extract_features


def run_validation(
    container_id: str,
    log_path: str,
    duration_minutes: float,
    window_seconds: float,
    storage_dir: str,
    poll_interval_seconds: float = 0.5,
) -> None:
    store = BaselineStore(storage_dir=storage_dir)
    dataset = store.load(container_id)
    print(f"Loaded baseline: {dataset.sample_count} sample(s) for {container_id!r}")

    model = AnomalyModel(container_id=container_id)
    model.fit(dataset)
    print("Model trained.\n")

    end_time = time.monotonic() + (duration_minutes * 60)
    window_start = datetime.now(timezone.utc)
    window_end = window_start + timedelta(seconds=window_seconds)
    buffer: list = []

    print(
        f"Scoring LIVE windows for {duration_minutes} minute(s), {window_seconds}s each."
    )
    print("Let the first window or two run quiet, then trigger your test behavior.\n")

    window_num = 0
    with open(log_path, "r") as f:
        f.seek(0, 2)  # only see events from now on
        while time.monotonic() < end_time:
            line = f.readline()
            if line:
                try:
                    event = parse_baseline_event(line)
                except BaselineParseError as exc:
                    print(f"  [skip] {exc}", file=sys.stderr)
                    event = None
                if event is not None and event.container_id == container_id:
                    buffer.append(event)
            else:
                time.sleep(poll_interval_seconds)

            now = datetime.now(timezone.utc)
            if now >= window_end:
                window_num += 1
                fv = extract_features(buffer, container_id, window_start, window_end)
                result = model.score_event(fv)
                flag = "  <-- ANOMALY" if result.is_anomaly else ""
                print(
                    f"  window {window_num} "
                    f"[{window_start.strftime('%H:%M:%S')}-{window_end.strftime('%H:%M:%S')}]: "
                    f"events={fv.total_event_count} proc={fv.distinct_process_count} "
                    f"shell={fv.shell_spawned_count} syscall={fv.sensitive_syscall_count} "
                    f"-> anomaly_score={result.anomaly_score:.4f}{flag}"
                )
                buffer = []
                window_start = window_end
                window_end = window_start + timedelta(seconds=window_seconds)

    print("\nDone.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="SelfSentry - Phase 4 live validation driver"
    )
    parser.add_argument("container_id")
    parser.add_argument("--log-path", default="/var/log/falco/alerts.json")
    parser.add_argument("--minutes", type=float, default=3.0)
    parser.add_argument("--window-seconds", type=float, default=30.0)
    parser.add_argument("--storage-dir", default="baselines")
    args = parser.parse_args()

    try:
        run_validation(
            args.container_id,
            args.log_path,
            args.minutes,
            args.window_seconds,
            args.storage_dir,
        )
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        print("\nStopped early.")
        sys.exit(0)
