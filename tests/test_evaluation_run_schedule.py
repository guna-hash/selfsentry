"""Tests for evaluation/run_schedule.py (pure parts) and aggregator integration."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "evaluation"))

import measure_results as mr  # noqa: E402
import run_schedule as rs  # noqa: E402
import scenarios  # noqa: E402

BOUNDARY = 1_791_700_020  # multiple of 60
CFG = {"target": "abc123456789", "run_id": "r1", "window": 60, "lateness": 10.0, "seed": 1}


def entry(name="new-binary-execution", **extra):
    base = {"index": 3, "scenario": name, "boundary_epoch": BOUNDARY,
            "workload_started_epoch": BOUNDARY + 2, "baseline_samples": 20,
            "config_fingerprint": "fp", "clock_check": {"valid": True, "status": "ok"},
            "fingerprint_components": {"rule_file_sha256": {"a": "1"}}}
    base.update(extra)
    return base


def incident(created_offset=70, window_start=None, **extra):
    row = {"id": 7, "container_id": "abc123456789",
           "created_at": rs.iso(BOUNDARY + created_offset),
           "monitor_evidence": {"window_start": window_start or rs.iso(BOUNDARY)}}
    row.update(extra)
    return row


class Plan(unittest.TestCase):
    def test_default_plan_matches_targets(self):
        plan = dict(rs.parse_plan(scenarios.DEFAULT_PLAN))
        attacks = {n: c for n, c in plan.items() if scenarios.SCENARIOS[n]["label"] == "attack"}
        benign = sum(c for n, c in plan.items() if scenarios.SCENARIOS[n]["label"] == "benign")
        self.assertTrue(all(c == 20 for c in attacks.values()))
        self.assertEqual(len(attacks), 5)
        self.assertEqual(benign, 100)

    def test_unknown_and_bad_counts_rejected(self):
        for bad in ("nope=3", "quiet=0", "quiet=x"):
            with self.assertRaises(ValueError):
                rs.parse_plan(bad)

    def test_schedule_reproducible_and_complete(self):
        plan = rs.parse_plan("quiet=3,terminal-shell=2")
        first, second = rs.build_schedule(plan, 5), rs.build_schedule(plan, 5)
        self.assertEqual(first, second)
        self.assertEqual(sorted(first), sorted(["quiet"] * 3 + ["terminal-shell"] * 2))


class Records(unittest.TestCase):
    def test_detected_attack_gets_creation_latency(self):
        record = rs.build_record(entry(), [incident()], CFG)
        self.assertTrue(record["detected"])
        self.assertNotIn("valid", record)
        self.assertFalse(record["visibility_measured"])
        out = mr.aggregate([record])
        stats = next(iter(out["groups"].values()))["variants"]["full"]
        self.assertEqual(stats["incident_creation_ms"]["n"], 1)
        self.assertAlmostEqual(stats["incident_creation_ms"]["median"], 68000.0)
        self.assertEqual(stats["incident_visibility_ms"]["n_not_measured"], 1)

    def test_missed_attack_has_no_latency_but_stays_in_denominator(self):
        record = rs.build_record(entry(), [], CFG)
        self.assertFalse(record["detected"])
        stats = next(iter(mr.aggregate([record])["groups"].values()))["variants"]["full"]
        self.assertEqual(stats["detection_rate"]["n"], 1)
        self.assertEqual(stats["incident_creation_ms"]["n_incomplete"], 1)
        self.assertIsNone(stats["incident_creation_ms"]["median"])

    def test_incident_in_other_window_not_attributed(self):
        other = incident(window_start=rs.iso(BOUNDARY - 60))
        self.assertFalse(rs.build_record(entry(), [other], CFG)["detected"])

    def test_implausible_created_at_invalidates(self):
        record = rs.build_record(entry(), [incident(created_offset=-3600)], CFG)
        self.assertFalse(record["valid"])
        self.assertIn("created_at", record["exclusion_reason"])

    def test_naive_timestamp_requires_explicit_source_timezone(self):
        naive = incident()
        naive["created_at"] = rs.iso(BOUNDARY + 70).replace("+00:00", "")
        record = rs.build_record(entry(), [naive], CFG)
        self.assertFalse(record["valid"])
        self.assertIn("timezone unspecified", record["exclusion_reason"])

    def test_ist_timestamp_converts_without_changing_latency(self):
        from datetime import datetime
        from zoneinfo import ZoneInfo
        naive = incident()
        naive["created_at"] = datetime.fromtimestamp(
            BOUNDARY + 70, ZoneInfo("Asia/Kolkata")
        ).replace(tzinfo=None).isoformat()
        record = rs.build_record(entry(), [naive], dict(CFG, incident_timezone="Asia/Kolkata"))
        self.assertNotIn("valid", record)
        self.assertTrue(record["incident_created_at_was_naive"])
        self.assertEqual(record["incident_created_at"], rs.iso(BOUNDARY + 70))
        stats = next(iter(mr.aggregate([record])["groups"].values()))["variants"]["full"]
        self.assertAlmostEqual(stats["incident_creation_ms"]["median"], 68000.0)

    def test_aware_timestamp_keeps_its_explicit_offset(self):
        epoch, naive = rs.created_at_epoch("2026-10-11T18:34:10.490351+05:30", "UTC")
        self.assertFalse(naive)
        self.assertEqual(rs.iso(epoch), "2026-10-11T13:04:10.490351+00:00")

    def test_invalid_reasons_are_kept_and_excluded(self):
        record = rs.build_record(entry(invalid_reasons=["workload command failed"]), [], CFG)
        self.assertFalse(record["valid"])
        self.assertEqual(mr.aggregate([record])["excluded_trials"][0]["reason"], "workload command failed")

    def test_skipped_window_has_no_creation_interval(self):
        skipped = {"index": 1, "scenario": "quiet", "boundary_epoch": BOUNDARY,
                   "invalid_reasons": ["workload skipped"]}
        record = rs.build_record(skipped, [], CFG)
        self.assertNotIn("incident_creation_start", record)
        self.assertFalse(record["valid"])

    def test_auto_confirmation_flags(self):
        confirmed = incident(confirmation={"confirmed_by": "selfsentry-auto"})
        record = rs.build_record(entry("quiet"), [confirmed], CFG)
        self.assertTrue(record["auto_confirmed"])
        self.assertFalse(record["auto_confirmation_accuracy"])  # benign scenario

    def test_duplicates_counted(self):
        record = rs.build_record(entry(), [incident(), dict(incident(), id=8)], CFG)
        self.assertEqual(record["duplicate_incident_count"], 1)


if __name__ == "__main__":
    unittest.main()
