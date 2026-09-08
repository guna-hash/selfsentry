"""
baseline_builder.py
--------------------
Module 4b of SelfSentry: Behavioral Runtime Monitor.

Collects FeatureVectors for a container during a "learning window" (a
period where the container is assumed to be running normal, benign
traffic) and persists them as that container's baseline dataset, which
anomaly_model.py later trains on.

Design notes:
  - Baselines are stored per-container, keyed by container_id, since
    "normal" for an nginx container looks nothing like "normal" for a
    Postgres container - this is the whole reason for using unsupervised,
    per-workload baselining instead of one global model.
  - Persisted as plain JSON on disk for now (simplest option that survives
    a process restart without needing Phase 8's database yet). Swapping
    this for PostgreSQL storage later is a drop-in change behind the same
    BaselineStore interface - only _load/_save need to change.
  - A minimum sample count is enforced before a baseline is considered
    "ready" for training, since IsolationForest on too few samples
    produces a meaningless model - this is a deliberate safety check, not
    boilerplate.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from feature_extractor import FEATURE_NAMES, FeatureVector

logger = logging.getLogger(__name__)

# A baseline needs at least this many feature-vector samples before it's
# considered usable for training. Isolation Forest can technically run on
# fewer, but the resulting model is not meaningfully "learned normal" -
# it would just memorize noise. Tune upward once you have real data volume.
MIN_BASELINE_SAMPLES = 20


class BaselineNotReadyError(RuntimeError):
    """Raised when a baseline is requested/trained on before it has
    enough samples collected."""


@dataclass
class BaselineDataset:
    container_id: str
    feature_vectors: list[FeatureVector]

    def to_array(self) -> list[list[float]]:
        return [fv.to_array() for fv in self.feature_vectors]

    @property
    def sample_count(self) -> int:
        return len(self.feature_vectors)

    @property
    def is_ready(self) -> bool:
        return self.sample_count >= MIN_BASELINE_SAMPLES


class BaselineStore:
    """
    Persists baseline datasets to disk as one JSON file per container,
    under `storage_dir`. Kept intentionally simple (no DB dependency) so
    Phase 4 doesn't have to wait on Phase 8.
    """

    def __init__(self, storage_dir: str | Path = "behavioral-engine/baselines"):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def _path_for(self, container_id: str) -> Path:
        # Docker container IDs are hex strings, so container_id must be
        # alphanumeric only. Reject (rather than silently strip) anything
        # else - stripping would let "../../etc/passwd" quietly become
        # "etcpasswd" and succeed, which defeats the point of the check.
        if not container_id or not container_id.isalnum():
            raise ValueError(
                f"invalid container_id for baseline storage: {container_id!r}"
            )
        return self.storage_dir / f"{container_id}.json"

    def append(self, feature_vector: FeatureVector) -> None:
        """Add one more sample to a container's baseline, persisting immediately."""
        dataset = self.load(feature_vector.container_id, allow_missing=True)
        dataset.feature_vectors.append(feature_vector)
        self._save(dataset)
        logger.info(
            "Baseline for %s now has %d/%d samples",
            feature_vector.container_id,
            dataset.sample_count,
            MIN_BASELINE_SAMPLES,
        )

    def load(self, container_id: str, allow_missing: bool = False) -> BaselineDataset:
        path = self._path_for(container_id)
        if not path.exists():
            if allow_missing:
                return BaselineDataset(container_id=container_id, feature_vectors=[])
            raise FileNotFoundError(
                f"no baseline stored yet for container {container_id!r}"
            )

        raw = json.loads(path.read_text())
        vectors = []
        for item in raw["feature_vectors"]:
            vectors.append(
                FeatureVector(
                    container_id=item["container_id"],
                    window_start=datetime.fromisoformat(item["window_start"]),
                    window_end=datetime.fromisoformat(item["window_end"]),
                    **{name: item[name] for name in FEATURE_NAMES},
                )
            )
        return BaselineDataset(container_id=container_id, feature_vectors=vectors)

    def _save(self, dataset: BaselineDataset) -> None:
        path = self._path_for(dataset.container_id)
        payload = {
            "container_id": dataset.container_id,
            "feature_vectors": [fv.to_dict() for fv in dataset.feature_vectors],
        }
        path.write_text(json.dumps(payload, indent=2))

    def reset(self, container_id: str) -> None:
        """Wipe a container's stored baseline (e.g. to relearn after a
        legitimate workload change)."""
        path = self._path_for(container_id)
        if path.exists():
            path.unlink()
            logger.info("Baseline reset for container %s", container_id)


def require_ready(dataset: BaselineDataset) -> None:
    """Raise BaselineNotReadyError unless the dataset has enough samples
    to train on. Call this immediately before training - fail loudly
    rather than silently training a near-empty model."""
    if not dataset.is_ready:
        raise BaselineNotReadyError(
            f"container {dataset.container_id!r} has only "
            f"{dataset.sample_count}/{MIN_BASELINE_SAMPLES} baseline samples - "
            "keep collecting during the learning window before training."
        )
