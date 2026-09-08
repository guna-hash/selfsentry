"""
Tests for behavioral-engine/anomaly_model.py

Uses fully synthetic feature data (no live Falco/container needed) - per
the project guide, this is exactly the kind of test that's checkable
without real container data: train on a synthetic "normal" cluster,
confirm an obvious outlier scores clearly higher.
"""

import random
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "behavioral-engine"))

from anomaly_model import (  # noqa: E402
    AnomalyModel,
    AnomalyModelRegistry,
    ModelNotTrainedError,
)
from baseline_builder import (
    BaselineDataset,
    BaselineNotReadyError,
    MIN_BASELINE_SAMPLES,
)  # noqa: E402
from feature_extractor import FeatureVector  # noqa: E402

CID = "abc123"
WINDOW_START = datetime(2026, 8, 9, 10, 0, 0, tzinfo=timezone.utc)


def make_fv(offset_minutes: int, **overrides) -> FeatureVector:
    start = WINDOW_START + timedelta(minutes=offset_minutes)
    end = start + timedelta(minutes=1)
    defaults = dict(
        container_id=CID,
        window_start=start,
        window_end=end,
        distinct_process_count=2,
        distinct_network_dest_count=1,
        distinct_ports_count=1,
        distinct_files_accessed=3,
        total_event_count=10,
        shell_spawned_count=0,
        distinct_parent_child_pairs=1,
        sensitive_syscall_count=0,
    )
    defaults.update(overrides)
    return FeatureVector(**defaults)


def make_normal_baseline(n: int = 40) -> BaselineDataset:
    """
    Simulates ~40 minutes of a well-behaved nginx-like container: a
    couple of processes, one steady upstream connection, light file
    access, no shells, no sensitive syscalls - with small random jitter
    so IsolationForest has real variance to learn from.
    """
    random.seed(42)
    vectors = []
    for i in range(n):
        vectors.append(
            make_fv(
                i,
                distinct_process_count=random.randint(1, 3),
                distinct_network_dest_count=random.randint(1, 2),
                distinct_ports_count=1,
                distinct_files_accessed=random.randint(2, 5),
                total_event_count=random.randint(8, 15),
                shell_spawned_count=0,
                distinct_parent_child_pairs=random.randint(1, 2),
                sensitive_syscall_count=0,
            )
        )
    return BaselineDataset(container_id=CID, feature_vectors=vectors)


class TestAnomalyModelTrainingGuard(unittest.TestCase):
    def test_score_before_fit_raises(self):
        model = AnomalyModel(container_id=CID)
        fv = make_fv(0)
        with self.assertRaises(ModelNotTrainedError):
            model.score_event(fv)

    def test_fit_on_too_few_samples_raises(self):
        model = AnomalyModel(container_id=CID)
        tiny_dataset = BaselineDataset(container_id=CID, feature_vectors=[make_fv(0)])
        with self.assertRaises(BaselineNotReadyError):
            model.fit(tiny_dataset)

    def test_fit_rejects_mismatched_container_id(self):
        model = AnomalyModel(container_id=CID)
        other_dataset = make_normal_baseline()
        other_dataset.container_id = "different_container"
        with self.assertRaises(ValueError):
            model.fit(other_dataset)

    def test_score_rejects_mismatched_container_id(self):
        model = AnomalyModel(container_id=CID)
        model.fit(make_normal_baseline())
        other_fv = make_fv(0)
        other_fv.container_id = "different_container"
        with self.assertRaises(ValueError):
            model.score_event(other_fv)


class TestAnomalyModelScoringBehavior(unittest.TestCase):
    """The core before/after demo required by the project guide's Phase 4
    'Done when' criteria: normal behavior scores low, an obvious,
    deliberately-unusual event scores clearly higher."""

    def setUp(self):
        self.model = AnomalyModel(container_id=CID)
        self.model.fit(make_normal_baseline())

    def test_normal_looking_event_scores_low(self):
        normal_event = make_fv(
            100,
            distinct_process_count=2,
            distinct_network_dest_count=1,
            distinct_ports_count=1,
            distinct_files_accessed=3,
            total_event_count=11,
            shell_spawned_count=0,
            distinct_parent_child_pairs=1,
            sensitive_syscall_count=0,
        )
        result = self.model.score_event(normal_event)
        self.assertLess(result.anomaly_score, 0.5)
        self.assertFalse(result.is_anomaly)

    def test_shell_spawn_and_sensitive_syscalls_score_high(self):
        attack_like_event = make_fv(
            101,
            distinct_process_count=6,
            distinct_network_dest_count=4,
            distinct_ports_count=3,
            distinct_files_accessed=15,
            total_event_count=60,
            shell_spawned_count=3,
            distinct_parent_child_pairs=5,
            sensitive_syscall_count=8,
        )
        result = self.model.score_event(attack_like_event)
        self.assertGreater(result.anomaly_score, 0.5)

    def test_attack_event_scores_higher_than_normal_event(self):
        normal_event = make_fv(100)
        attack_like_event = make_fv(
            101,
            distinct_process_count=7,
            distinct_network_dest_count=5,
            distinct_ports_count=4,
            distinct_files_accessed=12,
            total_event_count=70,
            shell_spawned_count=3,
            distinct_parent_child_pairs=4,
            sensitive_syscall_count=9,
        )
        normal_result = self.model.score_event(normal_event)
        attack_result = self.model.score_event(attack_like_event)
        self.assertGreater(attack_result.anomaly_score, normal_result.anomaly_score)

    def test_anomaly_score_bounded_zero_to_one(self):
        extreme_event = make_fv(
            102,
            distinct_process_count=999,
            shell_spawned_count=999,
            sensitive_syscall_count=999,
            total_event_count=9999,
        )
        result = self.model.score_event(extreme_event)
        self.assertGreaterEqual(result.anomaly_score, 0.0)
        self.assertLessEqual(result.anomaly_score, 1.0)


class TestAnomalyResultEventShape(unittest.TestCase):
    def test_to_event_dict_matches_interface_shape_2(self):
        model = AnomalyModel(container_id=CID)
        model.fit(make_normal_baseline())
        fv = make_fv(50, shell_spawned_count=2)
        result = model.score_event(fv)
        event = result.to_event_dict()

        self.assertEqual(
            set(event.keys()),
            {"container_id", "timestamp", "anomaly_score", "features"},
        )
        self.assertEqual(event["container_id"], CID)
        self.assertIsInstance(event["anomaly_score"], float)
        self.assertIn("shell_spawned_count", event["features"])
        self.assertEqual(event["features"]["shell_spawned_count"], 2)


class TestAnomalyModelRegistry(unittest.TestCase):
    def test_get_or_create_returns_same_instance(self):
        registry = AnomalyModelRegistry()
        m1 = registry.get_or_create(CID)
        m2 = registry.get_or_create(CID)
        self.assertIs(m1, m2)

    def test_is_trained_reflects_fit_state(self):
        registry = AnomalyModelRegistry()
        self.assertFalse(registry.is_trained(CID))
        model = registry.get_or_create(CID)
        model.fit(make_normal_baseline())
        self.assertTrue(registry.is_trained(CID))

    def test_score_event_routes_to_correct_container_model(self):
        registry = AnomalyModelRegistry()
        registry.get_or_create(CID).fit(make_normal_baseline())
        result = registry.score_event(make_fv(0))
        self.assertEqual(result.container_id, CID)


if __name__ == "__main__":
    unittest.main()
