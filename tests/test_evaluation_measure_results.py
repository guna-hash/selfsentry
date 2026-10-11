"""Tests for evaluation/measure_results.py and evaluation/fingerprint.py."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "evaluation"))

import fingerprint  # noqa: E402
import measure_results as mr  # noqa: E402

T0 = "2026-10-11T07:00:00+00:00"
T1 = "2026-10-11T07:01:08.500000+00:00"


def legacy(label="attack", detected=True, **extra):
    row = {"variant": "full", "scenario": "s", "label": label, "detected": detected,
           "detection_start": T0, "baseline_samples": 20,
           "rule_file_sha256": {"a": "1"}, "duplicate_incident_count": 0}
    if detected:
        row["detection_end"] = T1
    row.update(extra)
    return row


def v2(label="attack", detected=True, fp="fp1", **extra):
    row = {"schema_version": 2, "variant": "full", "scenario": "s", "label": label,
           "detected": detected, "trial_started_at": T0, "config_fingerprint": fp,
           "duplicate_incident_count": 0}
    if detected:
        row["incident_visible_at"] = T1
    row.update(extra)
    return row


def full(result, key=None):
    group = result["groups"][key or next(iter(result["groups"]))]
    return group["variants"]["full"]


class TimestampContract(unittest.TestCase):
    def test_legacy_undetected_trial_no_longer_crashes_and_stays_in_denominator(self):
        out = mr.aggregate([legacy(), legacy(detected=False)])
        stats = full(out)
        self.assertEqual(stats["detection_rate"]["n"], 2)
        self.assertEqual(stats["detection_rate"]["successes"], 1)
        self.assertEqual(stats["incident_visibility_ms"]["n"], 1)
        self.assertEqual(stats["incident_visibility_ms"]["n_incomplete"], 1)
        self.assertAlmostEqual(stats["incident_visibility_ms"]["median"], 68500.0)

    def test_schema2_undetected_has_no_latency(self):
        stats = full(mr.aggregate([v2(detected=False)]))
        self.assertIsNone(stats["incident_visibility_ms"]["median"])
        self.assertEqual(stats["incident_visibility_ms"]["n_incomplete"], 1)

    def test_detected_without_visible_timestamp_is_rejected(self):
        row = v2()
        del row["incident_visible_at"]
        with self.assertRaises(ValueError):
            mr.aggregate([row])

    def test_undetected_with_visible_timestamp_is_rejected(self):
        with self.assertRaises(ValueError):
            mr.aggregate([v2(detected=False, incident_visible_at=T1)])

    def test_end_without_start_is_rejected(self):
        with self.assertRaises(ValueError):
            mr.aggregate([v2(isolation_end=T1)])

    def test_negative_interval_rejected(self):
        with self.assertRaises(ValueError):
            mr.aggregate([v2(incident_visible_at="2026-10-11T06:00:00+00:00")])


class LatencyScope(unittest.TestCase):
    def test_benign_false_positive_latency_not_mixed_into_attack_latency(self):
        rows = [v2(), v2(label="benign", incident_visible_at="2026-10-11T07:05:00+00:00")]
        stats = full(mr.aggregate(rows))
        self.assertEqual(stats["incident_visibility_ms"]["n"], 1)
        self.assertAlmostEqual(stats["incident_visibility_ms"]["median"], 68500.0)
        self.assertEqual(stats["benign_incident_visibility_ms"]["n"], 1)


class GroupingAndExclusion(unittest.TestCase):
    def test_different_fingerprints_are_not_pooled(self):
        out = mr.aggregate([v2(fp="a"), v2(fp="b")])
        self.assertEqual(set(out["groups"]), {"a", "b"})
        self.assertFalse(out["pooled_across_configurations"])

    def test_legacy_rows_group_by_rules_and_baseline_samples(self):
        out = mr.aggregate([legacy(), legacy(baseline_samples=9)])
        self.assertEqual(len(out["groups"]), 2)

    def test_excluded_trial_requires_reason_and_is_listed(self):
        with self.assertRaises(ValueError):
            mr.aggregate([v2(valid=False)])
        out = mr.aggregate([v2(), v2(valid=False, exclusion_reason="invalid clock", trial_id="x")])
        self.assertEqual(out["excluded_trials"], [{"trial_id": "x", "reason": "invalid clock"}])
        self.assertEqual(full(out)["trials"], 1)


class Metrics(unittest.TestCase):
    def test_confirmation_metrics_are_separate(self):
        rows = [v2(auto_confirmed=True), v2(auto_confirmed=False),
                v2(label="benign", auto_confirmed=True)]
        stats = full(mr.aggregate(rows))
        self.assertEqual(stats["attack_confirmation_coverage"]["successes"], 1)
        self.assertEqual(stats["attack_confirmation_coverage"]["n"], 2)
        self.assertEqual(stats["confirmation_precision"]["successes"], 1)
        self.assertEqual(stats["confirmation_precision"]["n"], 2)

    def test_legacy_confirmation_derivation(self):
        stats = full(mr.aggregate([legacy(auto_confirmation_accuracy=True), legacy()]))
        self.assertEqual(stats["attack_confirmation_coverage"]["successes"], 1)
        self.assertEqual(stats["attack_confirmation_coverage"]["n"], 2)

    def test_wilson_interval(self):
        low, high = mr.wilson_interval(5, 5)
        self.assertLess(low, 1.0)
        self.assertEqual(high, 1.0)
        self.assertIsNone(mr.wilson_interval(0, 0))

    def test_false_positive_rate_counts_benign_only(self):
        stats = full(mr.aggregate([v2(label="benign", detected=False), v2()]))
        self.assertEqual(stats["false_positive_rate"]["successes"], 0)
        self.assertEqual(stats["false_positive_rate"]["n"], 1)

    def test_unknown_variant_rejected(self):
        with self.assertRaises(ValueError):
            mr.aggregate([v2(variant="nope")])


class Fingerprint(unittest.TestCase):
    def _root(self, baseline_text):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "behavioral-engine/baselines").mkdir(parents=True)
        (root / "behavioral-engine/baselines/abc.json").write_text(baseline_text)
        return root

    def test_changes_when_baseline_changes_and_stable_otherwise(self):
        one = fingerprint.collect_fingerprint(self._root("A"), "abc", {}, "img")
        same = fingerprint.collect_fingerprint(self._root("A"), "abc", {}, "img")
        other = fingerprint.collect_fingerprint(self._root("B"), "abc", {}, "img")
        self.assertEqual(one["config_fingerprint"], same["config_fingerprint"])
        self.assertNotEqual(one["config_fingerprint"], other["config_fingerprint"])

    def test_secret_like_settings_never_recorded(self):
        env = {"MONITOR_WINDOW_SECONDS": "60", "MONITOR_WRITE_TOKEN": "s3cret",
               "MONITOR_BACKEND_URL": "http://x", "OTHER": "1"}
        recorded = fingerprint.monitor_settings(env)
        self.assertEqual(recorded, {"MONITOR_WINDOW_SECONDS": "60"})
        blob = json.dumps(fingerprint.collect_fingerprint(self._root("A"), "abc", env, "i"))
        self.assertNotIn("s3cret", blob)


if __name__ == "__main__":
    unittest.main()
