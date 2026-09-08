"""
Tests for behavioral-engine/feature_extractor.py

Fully mockable - synthetic RawEvent fixtures only, no live Falco/eBPF
process required.
"""

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "behavioral-engine"))

from feature_extractor import (  # noqa: E402
    EventType,
    FeatureVector,
    RawEvent,
    extract_features,
    FEATURE_NAMES,
)

CID = "abc123"
WINDOW_START = datetime(2026, 8, 9, 10, 0, 0, tzinfo=timezone.utc)
WINDOW_END = WINDOW_START + timedelta(minutes=5)


def ts(offset_seconds: int) -> datetime:
    return WINDOW_START + timedelta(seconds=offset_seconds)


class TestExtractFeaturesBasic(unittest.TestCase):
    def test_empty_events_produce_zeroed_vector(self):
        fv = extract_features([], CID, WINDOW_START, WINDOW_END)
        self.assertEqual(fv.container_id, CID)
        for name in FEATURE_NAMES:
            self.assertEqual(getattr(fv, name), 0)

    def test_process_spawn_counts_distinct_names(self):
        events = [
            RawEvent(
                CID,
                ts(1),
                EventType.PROCESS_SPAWN,
                proc_name="nginx",
                parent_proc_name="init",
            ),
            RawEvent(
                CID,
                ts(2),
                EventType.PROCESS_SPAWN,
                proc_name="nginx",
                parent_proc_name="init",
            ),
            RawEvent(
                CID,
                ts(3),
                EventType.PROCESS_SPAWN,
                proc_name="curl",
                parent_proc_name="nginx",
            ),
        ]
        fv = extract_features(events, CID, WINDOW_START, WINDOW_END)
        self.assertEqual(fv.distinct_process_count, 2)  # nginx, curl
        self.assertEqual(fv.total_event_count, 3)

    def test_shell_spawn_detected(self):
        events = [
            RawEvent(
                CID,
                ts(1),
                EventType.PROCESS_SPAWN,
                proc_name="sh",
                parent_proc_name="nginx",
            ),
            RawEvent(
                CID,
                ts(2),
                EventType.PROCESS_SPAWN,
                proc_name="bash",
                parent_proc_name="sh",
            ),
            RawEvent(
                CID,
                ts(3),
                EventType.PROCESS_SPAWN,
                proc_name="nginx",
                parent_proc_name="init",
            ),
        ]
        fv = extract_features(events, CID, WINDOW_START, WINDOW_END)
        self.assertEqual(fv.shell_spawned_count, 2)

    def test_parent_child_pairs_are_distinct_tuples(self):
        events = [
            RawEvent(
                CID,
                ts(1),
                EventType.PROCESS_SPAWN,
                proc_name="curl",
                parent_proc_name="nginx",
            ),
            RawEvent(
                CID,
                ts(2),
                EventType.PROCESS_SPAWN,
                proc_name="curl",
                parent_proc_name="nginx",
            ),
            RawEvent(
                CID,
                ts(3),
                EventType.PROCESS_SPAWN,
                proc_name="wget",
                parent_proc_name="nginx",
            ),
        ]
        fv = extract_features(events, CID, WINDOW_START, WINDOW_END)
        self.assertEqual(fv.distinct_parent_child_pairs, 2)  # (nginx,curl) (nginx,wget)

    def test_network_connect_counts_ips_and_ports(self):
        events = [
            RawEvent(
                CID, ts(1), EventType.NETWORK_CONNECT, dest_ip="8.8.8.8", dest_port=443
            ),
            RawEvent(
                CID, ts(2), EventType.NETWORK_CONNECT, dest_ip="8.8.8.8", dest_port=443
            ),
            RawEvent(
                CID, ts(3), EventType.NETWORK_CONNECT, dest_ip="1.1.1.1", dest_port=80
            ),
        ]
        fv = extract_features(events, CID, WINDOW_START, WINDOW_END)
        self.assertEqual(fv.distinct_network_dest_count, 2)
        self.assertEqual(fv.distinct_ports_count, 2)

    def test_file_access_counts_distinct_paths(self):
        events = [
            RawEvent(CID, ts(1), EventType.FILE_ACCESS, file_path="/etc/passwd"),
            RawEvent(CID, ts(2), EventType.FILE_ACCESS, file_path="/etc/passwd"),
            RawEvent(CID, ts(3), EventType.FILE_ACCESS, file_path="/tmp/x"),
        ]
        fv = extract_features(events, CID, WINDOW_START, WINDOW_END)
        self.assertEqual(fv.distinct_files_accessed, 2)

    def test_sensitive_syscall_counted_not_deduped(self):
        events = [
            RawEvent(CID, ts(1), EventType.SYSCALL, syscall_name="ptrace"),
            RawEvent(CID, ts(2), EventType.SYSCALL, syscall_name="ptrace"),
            RawEvent(
                CID, ts(3), EventType.SYSCALL, syscall_name="read"
            ),  # not sensitive
        ]
        fv = extract_features(events, CID, WINDOW_START, WINDOW_END)
        self.assertEqual(fv.sensitive_syscall_count, 2)  # counted, not deduped
        self.assertEqual(fv.total_event_count, 3)


class TestExtractFeaturesFiltering(unittest.TestCase):
    def test_events_for_other_containers_ignored(self):
        events = [
            RawEvent(
                CID,
                ts(1),
                EventType.PROCESS_SPAWN,
                proc_name="curl",
                parent_proc_name="nginx",
            ),
            RawEvent(
                "other_container",
                ts(1),
                EventType.PROCESS_SPAWN,
                proc_name="evil",
                parent_proc_name="init",
            ),
        ]
        fv = extract_features(events, CID, WINDOW_START, WINDOW_END)
        self.assertEqual(fv.total_event_count, 1)
        self.assertEqual(fv.distinct_process_count, 1)

    def test_events_outside_window_ignored(self):
        events = [
            RawEvent(
                CID,
                WINDOW_START - timedelta(seconds=10),
                EventType.PROCESS_SPAWN,
                proc_name="curl",
            ),
            RawEvent(
                CID,
                WINDOW_END + timedelta(seconds=10),
                EventType.PROCESS_SPAWN,
                proc_name="wget",
            ),
            RawEvent(CID, ts(1), EventType.PROCESS_SPAWN, proc_name="nginx"),
        ]
        fv = extract_features(events, CID, WINDOW_START, WINDOW_END)
        self.assertEqual(fv.total_event_count, 1)


class TestFeatureVectorSerialization(unittest.TestCase):
    def test_to_array_matches_feature_names_order(self):
        fv = FeatureVector(
            container_id=CID,
            window_start=WINDOW_START,
            window_end=WINDOW_END,
            distinct_process_count=3,
            sensitive_syscall_count=7,
        )
        arr = fv.to_array()
        self.assertEqual(len(arr), len(FEATURE_NAMES))
        self.assertEqual(arr[FEATURE_NAMES.index("distinct_process_count")], 3.0)
        self.assertEqual(arr[FEATURE_NAMES.index("sensitive_syscall_count")], 7.0)

    def test_to_dict_serializes_timestamps_as_iso(self):
        fv = FeatureVector(
            container_id=CID, window_start=WINDOW_START, window_end=WINDOW_END
        )
        d = fv.to_dict()
        self.assertEqual(d["window_start"], WINDOW_START.isoformat())
        self.assertEqual(d["window_end"], WINDOW_END.isoformat())


class TestRawEventFromDict(unittest.TestCase):
    def test_parses_iso_timestamp_string(self):
        d = {
            "container_id": CID,
            "timestamp": "2026-08-09T10:15:00Z",
            "event_type": "process_spawn",
            "proc_name": "curl",
            "parent_proc_name": "nginx",
        }
        event = RawEvent.from_dict(d)
        self.assertEqual(event.container_id, CID)
        self.assertEqual(event.event_type, EventType.PROCESS_SPAWN)
        self.assertEqual(event.proc_name, "curl")


if __name__ == "__main__":
    unittest.main()
