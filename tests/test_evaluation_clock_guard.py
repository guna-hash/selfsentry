"""Tests for evaluation/clock_guard.py."""
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "evaluation"))

import clock_guard as cg  # noqa: E402


def line(cid, epoch):
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(epoch)) + ".123456789Z"
    return json.dumps({"time": stamp, "rule": "Baseline Process Spawn",
                       "output_fields": {"container.id": cid}}) + "\n"


class Parsing(unittest.TestCase):
    def test_nanosecond_timestamp(self):
        parsed = cg.parse_falco_time("1970-01-01T00:00:10.327827525Z")
        self.assertAlmostEqual(parsed, 10.327827, places=5)

    def test_naive_timestamp_rejected(self):
        with self.assertRaises(ValueError):
            cg.parse_falco_time("2026-10-11T12:00:00")


class Judging(unittest.TestCase):
    def test_in_window_ok(self):
        self.assertTrue(cg.judge_events([100.5, 101.0], 100, 102, True)["valid"])

    def test_stale_event_is_skewed(self):
        verdict = cg.judge_events([100 - 3600], 100, 102, True)
        self.assertFalse(verdict["valid"])
        self.assertEqual(verdict["status"], "falco_clock_skew")

    def test_no_events_invalid_only_when_expected(self):
        self.assertFalse(cg.judge_events([], 0, 1, True)["valid"])
        self.assertTrue(cg.judge_events([], 0, 1, False)["valid"])
        self.assertEqual(cg.judge_events([], 0, 1, False)["status"], "unverified_no_events")


class Tail(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "alerts.json"
        self.path.write_text(line("aaa111", 1000))

    def test_only_new_events_for_container(self):
        tail = cg.AlertTail(self.path)
        tail.mark()
        with self.path.open("a") as f:
            f.write(line("aaa111222333", 2000))
            f.write(line("bbb999", 2001))
            f.write("not json\n")
        times = tail.new_events("aaa111222333"[:12])
        self.assertEqual(len(times), 1)
        self.assertAlmostEqual(times[0], 2000.12, places=1)

    def test_rotation_reads_new_file_from_start(self):
        tail = cg.AlertTail(self.path)
        tail.mark()
        replacement = self.path.with_name("alerts.new")
        replacement.write_text(line("aaa111", 3000))  # same size as the old file
        replacement.replace(self.path)  # new inode, like logrotate
        self.assertEqual(len(tail.new_events("aaa111")), 1)

    def test_unreadable_file_raises(self):
        with self.assertRaises(cg.ClockGuardError):
            cg.AlertTail(self.path.parent / "missing.json").mark()


class Gate(unittest.TestCase):
    def _state(self, **overrides):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "clock_check.json"
        record = {"container_id": "abc", "passed": True, "checked_at_epoch": time.time(),
                  "clock_snapshot": cg.clock_snapshot()}
        record.update(overrides)
        path.write_text(json.dumps(record))
        return path

    def test_recent_pass_accepted(self):
        self.assertTrue(cg.require_recent_preflight(self._state(), "abc")["passed"])

    def test_missing_failed_old_or_wrong_container_refused(self):
        with self.assertRaises(cg.ClockGuardError):
            cg.require_recent_preflight("/nonexistent/clock.json", "abc")
        for override in ({"passed": False},
                         {"clock_snapshot": {"boot_id": "other", "realtime": 1, "monotonic": 1}},
                         {"container_id": "other"}):
            with self.assertRaises(cg.ClockGuardError):
                cg.require_recent_preflight(self._state(**override), "abc")


if __name__ == "__main__":
    unittest.main()
