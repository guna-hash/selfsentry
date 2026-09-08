"""
Tests for behavioral-engine/baseline_builder.py

Uses a temp directory for storage so tests never touch real project data
and clean up after themselves.
"""

import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "behavioral-engine"))

from baseline_builder import (  # noqa: E402
    MIN_BASELINE_SAMPLES,
    BaselineNotReadyError,
    BaselineStore,
    require_ready,
)
from feature_extractor import FeatureVector  # noqa: E402

CID = "abc123"
WINDOW_START = datetime(2026, 8, 9, 10, 0, 0, tzinfo=timezone.utc)


def make_fv(offset_minutes: int = 0, **overrides) -> FeatureVector:
    start = WINDOW_START + timedelta(minutes=offset_minutes)
    end = start + timedelta(minutes=1)
    defaults = dict(container_id=CID, window_start=start, window_end=end)
    defaults.update(overrides)
    return FeatureVector(**defaults)


class TestBaselineStore(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.store = BaselineStore(storage_dir=self._tmpdir.name)

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_load_missing_with_allow_missing_returns_empty_dataset(self):
        dataset = self.store.load(CID, allow_missing=True)
        self.assertEqual(dataset.sample_count, 0)
        self.assertFalse(dataset.is_ready)

    def test_load_missing_without_allow_missing_raises(self):
        with self.assertRaises(FileNotFoundError):
            self.store.load(CID)

    def test_append_persists_and_accumulates(self):
        self.store.append(make_fv(0, distinct_process_count=1))
        self.store.append(make_fv(1, distinct_process_count=2))
        dataset = self.store.load(CID)
        self.assertEqual(dataset.sample_count, 2)
        self.assertEqual(dataset.feature_vectors[0].distinct_process_count, 1)
        self.assertEqual(dataset.feature_vectors[1].distinct_process_count, 2)

    def test_is_ready_flips_at_min_samples(self):
        for i in range(MIN_BASELINE_SAMPLES - 1):
            self.store.append(make_fv(i))
        dataset = self.store.load(CID)
        self.assertFalse(dataset.is_ready)

        self.store.append(make_fv(MIN_BASELINE_SAMPLES))
        dataset = self.store.load(CID)
        self.assertTrue(dataset.is_ready)

    def test_reset_removes_stored_baseline(self):
        self.store.append(make_fv(0))
        self.store.reset(CID)
        with self.assertRaises(FileNotFoundError):
            self.store.load(CID)

    def test_reset_on_nonexistent_container_does_not_raise(self):
        self.store.reset(
            "neverexisted123"
        )  # should be a silent no-op (valid alnum id, just unused)

    def test_invalid_container_id_rejected(self):
        with self.assertRaises(ValueError):
            self.store._path_for("../../etc/passwd")

    def test_to_array_shape_matches_feature_count(self):
        self.store.append(make_fv(0))
        self.store.append(make_fv(1))
        dataset = self.store.load(CID)
        arr = dataset.to_array()
        self.assertEqual(len(arr), 2)
        self.assertEqual(len(arr[0]), 8)  # 8 features


class TestRequireReady(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.store = BaselineStore(storage_dir=self._tmpdir.name)

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_raises_when_not_enough_samples(self):
        self.store.append(make_fv(0))
        dataset = self.store.load(CID)
        with self.assertRaises(BaselineNotReadyError):
            require_ready(dataset)

    def test_passes_when_enough_samples(self):
        for i in range(MIN_BASELINE_SAMPLES):
            self.store.append(make_fv(i))
        dataset = self.store.load(CID)
        require_ready(dataset)  # should not raise


if __name__ == "__main__":
    unittest.main()
