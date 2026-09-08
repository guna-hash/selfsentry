"""
anomaly_model.py
-----------------
Module 4c of SelfSentry: Anomaly Detection Model.

Trains a per-container sklearn IsolationForest on that container's
baseline feature vectors, and scores new feature vectors against it.
Also produces output already normalized into interface shape #2
(the "anomaly-model event" contract shared with the Correlation Engine
in Phase 5 and documented in docs/interfaces.md):

    {
      "container_id": "abc123",
      "timestamp": "2026-08-09T10:15:02Z",
      "anomaly_score": 0.87,
      "features": {"proc_name": "curl", "parent_proc": "nginx"}
    }

Design notes:
  - IsolationForest chosen over One-Class SVM as the default - it's
    faster to train, scales better, and its decision_function output is
    easy to normalize into a stable 0-1 "how anomalous" score.
  - Score normalization: sklearn's raw decision_function() output is
    unbounded, and its offset_ attribute is FIXED at -0.5 whenever
    contamination="auto" - it does NOT track where a specific container's
    scores actually land. Anchoring on offset_ was tried first and
    saturated every score to ~0. The fix: at fit() time, compute the
    training set's own mean/std of decision_function output, and
    normalize new scores as a z-score against THAT (sign-flipped so
    higher = more anomalous), squashed through a logistic function into
    [0, 1]. This keeps normalization correctly centered on "what normal
    looks like for this specific container."
  - is_anomaly is derived from this same normalized score (threshold
    0.5), NOT from sklearn's own predict() - predict() uses a separately-
    calibrated internal threshold that can disagree with the normalized
    score right at the boundary, which would expose two different
    "is this bad?" signals from one event.
  - One model per container_id (matches the per-workload baseline
    design) - models are kept in an in-memory registry here; persisting
    trained models to disk (pickle/joblib) is a one-line addition when
    wiring this into the Backend API in Phase 8.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime

import numpy as np
from sklearn.ensemble import IsolationForest

from baseline_builder import BaselineDataset, require_ready
from feature_extractor import FeatureVector

logger = logging.getLogger(__name__)


class ModelNotTrainedError(RuntimeError):
    """Raised when score_event() is called before fit() for a container."""


@dataclass
class AnomalyResult:
    container_id: str
    timestamp: datetime
    anomaly_score: float  # normalized 0.0 (normal) - 1.0 (highly anomalous)
    raw_decision_function: (
        float  # sklearn's original unbounded score, kept for audit/debug
    )
    is_anomaly: bool
    feature_vector: FeatureVector

    def to_event_dict(self) -> dict:
        """
        Interface shape #2 - what the Correlation Engine (Phase 5) and
        anything else downstream consumes. `features` intentionally
        exposes the human-readable engineered features (not the raw
        array) so a dashboard or LLM summary can render them directly.
        """
        return {
            "container_id": self.container_id,
            "timestamp": self.timestamp.isoformat(),
            "anomaly_score": round(self.anomaly_score, 4),
            "features": {
                "distinct_process_count": self.feature_vector.distinct_process_count,
                "distinct_network_dest_count": self.feature_vector.distinct_network_dest_count,
                "distinct_ports_count": self.feature_vector.distinct_ports_count,
                "distinct_files_accessed": self.feature_vector.distinct_files_accessed,
                "total_event_count": self.feature_vector.total_event_count,
                "shell_spawned_count": self.feature_vector.shell_spawned_count,
                "distinct_parent_child_pairs": self.feature_vector.distinct_parent_child_pairs,
                "sensitive_syscall_count": self.feature_vector.sensitive_syscall_count,
            },
        }


class AnomalyModel:
    """
    Per-container IsolationForest wrapper. Create one instance per
    container (or use AnomalyModelRegistry below to manage many).
    """

    def __init__(
        self,
        container_id: str,
        n_estimators: int = 100,
        contamination: float = "auto",
        random_state: int = 42,
    ):
        self.container_id = container_id
        self._model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
        )
        self._trained = False
        self._train_score_mean: float = 0.0
        self._train_score_std: float = 1.0

    def fit(self, dataset: BaselineDataset) -> None:
        """Train on a container's baseline dataset. Raises
        BaselineNotReadyError if there aren't enough samples yet - see
        baseline_builder.MIN_BASELINE_SAMPLES."""
        if dataset.container_id != self.container_id:
            raise ValueError(
                f"dataset is for container {dataset.container_id!r}, "
                f"but this model is for {self.container_id!r}"
            )
        require_ready(dataset)

        X = np.array(dataset.to_array())
        self._model.fit(X)

        # Data-driven normalization anchor + scale, computed from the
        # training set's own decision_function distribution - see module
        # docstring for why offset_ is the wrong anchor.
        train_scores = self._model.decision_function(X)
        std = float(np.std(train_scores))
        self._train_score_mean = float(np.mean(train_scores))
        self._train_score_std = std if std > 1e-6 else 1e-6

        self._trained = True
        logger.info(
            "Trained IsolationForest for container %s on %d baseline samples",
            self.container_id,
            dataset.sample_count,
        )

    def score_event(self, feature_vector: FeatureVector) -> AnomalyResult:
        """Score a new (post-baseline) feature vector against the trained
        model. Raises ModelNotTrainedError if fit() hasn't been called."""
        if not self._trained:
            raise ModelNotTrainedError(
                f"model for container {self.container_id!r} has not been trained yet - "
                "call fit() first"
            )
        if feature_vector.container_id != self.container_id:
            raise ValueError(
                f"feature_vector is for container {feature_vector.container_id!r}, "
                f"but this model is for {self.container_id!r}"
            )

        x = np.array([feature_vector.to_array()])
        raw_score = float(self._model.decision_function(x)[0])
        normalized = self._normalize_score(raw_score)

        return AnomalyResult(
            container_id=self.container_id,
            timestamp=feature_vector.window_end,
            anomaly_score=normalized,
            raw_decision_function=raw_score,
            is_anomaly=(normalized >= 0.5),
            feature_vector=feature_vector,
        )

    def _normalize_score(self, raw_score: float) -> float:
        """
        Map sklearn's unbounded, lower-is-worse decision_function output
        to a 0.0-1.0 range where higher = more anomalous, anchored on the
        training set's own mean/std-dev (a z-score), squashed through a
        logistic function. Not a calibrated probability - a monotonic
        ranking/thresholding score.
        """
        shifted = (self._train_score_mean - raw_score) / self._train_score_std
        steepness = 2.5
        score = 1.0 / (1.0 + np.exp(-steepness * shifted))
        return float(np.clip(score, 0.0, 1.0))


class AnomalyModelRegistry:
    """
    Convenience manager for multiple containers' models, so the runtime
    pipeline doesn't have to track a dict of AnomalyModel instances itself.
    """

    def __init__(self):
        self._models: dict[str, AnomalyModel] = {}

    def get_or_create(self, container_id: str) -> AnomalyModel:
        if container_id not in self._models:
            self._models[container_id] = AnomalyModel(container_id=container_id)
        return self._models[container_id]

    def is_trained(self, container_id: str) -> bool:
        model = self._models.get(container_id)
        return bool(model and model._trained)

    def score_event(self, feature_vector: FeatureVector) -> AnomalyResult:
        model = self.get_or_create(feature_vector.container_id)
        return model.score_event(feature_vector)
