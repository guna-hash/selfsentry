"""Tests for monitor-service/event_classifier.py (uses the real Falco parser)."""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "monitor-service"))

import event_classifier  # noqa: E402


def falco_line(rule="Terminal shell in container", container_id="12160024642b", proc="sh"):
    stamp = "2026-10-09T10:00:00.123456789Z"
    fields = {
        "container.id": container_id,
        "container.name": "web",
        "container.image.repository": "nginx",
        "container.image.tag": "1.25",
        "proc.name": proc,
        "proc.pname": "runc",
    }
    return json.dumps(
        {
            "hostname": "vm",
            "output": f"{stamp}: Notice {rule} container_id={container_id}",
            "output_fields": fields,
            "priority": "Notice",
            "rule": rule,
            "source": "syscall",
            "tags": [],
            "time": stamp,
        }
    )


class TestClassifyLine(unittest.TestCase):
    def test_container_alert_is_classified_as_an_alert_with_context(self):
        result = event_classifier.classify_line(falco_line(), "key1")
        self.assertEqual(result.kind, "alert")
        event = result.event
        self.assertEqual(event["container_id"], "12160024642b")
        self.assertEqual(event["rule"], "Terminal shell in container")
        self.assertEqual(event["container_name"], "web")
        self.assertEqual(event["image_name"], "nginx:1.25")
        self.assertEqual(event["proc_name"], "sh")
        self.assertEqual(event["parent_proc_name"], "runc")
        self.assertEqual(event["event_key"], "key1")

    def test_baseline_capture_rule_is_classified_as_baseline(self):
        result = event_classifier.classify_line(falco_line(rule="Baseline Process Spawn"))
        self.assertEqual(result.kind, "baseline")

    def test_host_event_returns_none(self):
        self.assertIsNone(event_classifier.classify_line(falco_line(container_id="host")))

    def test_invalid_json_is_malformed(self):
        with self.assertRaises(event_classifier.MalformedEvent):
            event_classifier.classify_line("not json at all")

    def test_missing_required_fields_is_malformed(self):
        with self.assertRaises(event_classifier.MalformedEvent):
            event_classifier.classify_line(json.dumps({"rule": "x"}))


if __name__ == "__main__":
    unittest.main()
