"""Tests for monitor-service/audit_client.py (HTTP mocked, spool in a temp dir)."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "monitor-service"))

import audit_client  # noqa: E402


def ok():
    return MagicMock(status_code=201)


class AuditClientTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.spool = self.dir / "audit_spool.jsonl"
        patcher = patch.object(audit_client.requests, "post")
        self.post = patcher.start()
        self.addCleanup(patcher.stop)
        self.client = self.new_client()

    def new_client(self):
        return audit_client.AuditClient("http://backend", self.spool)

    def sent_keys(self):
        return [call.kwargs["json"]["event_key"] for call in self.post.call_args_list]


class TestEmit(AuditClientTestCase):
    def test_successful_delivery_posts_the_payload(self):
        self.post.return_value = ok()
        self.assertTrue(self.client.emit("TEST", container_id="abc", event_key="k1"))
        self.assertEqual(self.post.call_args.args[0], "http://backend/audit/")
        payload = self.post.call_args.kwargs["json"]
        self.assertEqual(payload["event_type"], "TEST")
        self.assertEqual(payload["event_key"], "k1")
        self.assertEqual(self.client.spool_size(), 0)
        self.assertEqual(self.client.last_outcome, "ok")

    def test_unreachable_backend_spools_the_event(self):
        self.post.side_effect = requests.ConnectionError("down")
        self.assertFalse(self.client.emit("TEST", event_key="k1"))
        self.assertEqual(self.client.spool_size(), 1)
        self.assertEqual(self.client.last_outcome, "retry")

    def test_server_error_spools_the_event(self):
        self.post.return_value = MagicMock(status_code=503)
        self.assertFalse(self.client.emit("TEST", event_key="k1"))
        self.assertEqual(self.client.spool_size(), 1)

    def test_rejected_event_goes_to_dead_letters_not_the_spool(self):
        self.post.return_value = MagicMock(status_code=422)
        self.assertFalse(self.client.emit("TEST", event_key="k1"))
        self.assertEqual(self.client.spool_size(), 0)
        rejected = (self.dir / "audit_rejected.jsonl").read_text().splitlines()
        self.assertEqual(json.loads(rejected[0])["event_key"], "k1")
        self.assertEqual(self.client.last_outcome, "rejected")

    def test_spool_survives_a_restart(self):
        self.post.side_effect = requests.ConnectionError("down")
        self.client.emit("TEST", event_key="k1")
        self.assertEqual(self.new_client().spool_size(), 1)


class TestFlushAndOrdering(AuditClientTestCase):
    def spool_three(self):
        self.post.side_effect = requests.ConnectionError("down")
        for key in ("k1", "k2", "k3"):
            self.client.emit("TEST", event_key=key)
        self.post.reset_mock()

    def test_flush_stops_at_the_first_failure_and_keeps_order(self):
        self.spool_three()
        self.post.side_effect = [ok(), requests.ConnectionError("x")]
        self.assertEqual(self.client.flush_spool(), 1)
        self.assertEqual(self.client.spool_size(), 2)
        remaining = [json.loads(line)["event_key"] for line in self.spool.read_text().splitlines()]
        self.assertEqual(remaining, ["k2", "k3"])

    def test_flush_clears_the_spool_when_everything_is_delivered(self):
        self.spool_three()
        self.post.side_effect = None
        self.post.return_value = ok()
        self.assertEqual(self.client.flush_spool(), 3)
        self.assertEqual(self.client.spool_size(), 0)
        self.assertFalse(self.spool.exists())

    def test_a_new_event_is_sent_after_older_spooled_ones(self):
        self.post.side_effect = requests.ConnectionError("down")
        self.client.emit("TEST", event_key="k1")
        self.post.reset_mock()
        self.post.side_effect = None
        self.post.return_value = ok()
        self.assertTrue(self.client.emit("TEST", event_key="k2"))
        self.assertEqual(self.sent_keys(), ["k1", "k2"])


if __name__ == "__main__":
    unittest.main()
