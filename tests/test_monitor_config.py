"""Tests for monitor-service/monitor_config.py."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "monitor-service"))

import monitor_config  # noqa: E402


class TestLoadConfig(unittest.TestCase):
    def test_defaults_are_valid_and_conservative(self):
        config = monitor_config.load_config({})
        self.assertEqual(config.unapproved_start_policy, "alert")
        self.assertEqual(config.start_from, "end")
        self.assertEqual(config.registration_grace_seconds, 15.0)

    def test_environment_overrides_are_parsed(self):
        config = monitor_config.load_config(
            {
                "SELFSENTRY_BACKEND_URL": "http://backend:9000/",
                "MONITOR_POLL_INTERVAL": "2",
                "MONITOR_MAX_BATCH_LINES": "50",
                "MONITOR_UNAPPROVED_START_POLICY": "ignore",
                "MONITOR_LOG_FORMAT": "json",
            }
        )
        self.assertEqual(config.backend_url, "http://backend:9000")
        self.assertEqual(config.poll_interval_seconds, 2.0)
        self.assertEqual(config.max_batch_lines, 50)
        self.assertEqual(config.unapproved_start_policy, "ignore")
        self.assertEqual(config.log_format, "json")

    def test_unknown_policy_is_rejected(self):
        with self.assertRaises(monitor_config.ConfigError):
            monitor_config.load_config({"MONITOR_UNAPPROVED_START_POLICY": "destroy"})

    def test_non_numeric_value_is_rejected(self):
        with self.assertRaises(monitor_config.ConfigError):
            monitor_config.load_config({"MONITOR_POLL_INTERVAL": "fast"})

    def test_retry_max_below_base_is_rejected(self):
        with self.assertRaises(monitor_config.ConfigError):
            monitor_config.load_config(
                {"MONITOR_RETRY_BASE_SECONDS": "10", "MONITOR_RETRY_MAX_SECONDS": "5"}
            )

    def test_backend_url_must_be_http(self):
        with self.assertRaises(monitor_config.ConfigError):
            monitor_config.load_config({"SELFSENTRY_BACKEND_URL": "ftp://x"})


if __name__ == "__main__":
    unittest.main()
