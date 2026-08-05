"""
anomaly_model.py
-------------------
Module 5 of ContainerGuard AI: Anomaly Detection Model.

STATUS: NOT YET IMPLEMENTED — Phase 4 stub.

Planned responsibility:
Train an unsupervised model (scikit-learn IsolationForest and/or
OneClassSVM) per-container on baseline feature vectors, then score new
events for deviation from that learned "normal."

Chosen deliberately as unsupervised (see project design decisions):
there's no labeled attack dataset for arbitrary container workloads.

Planned interface:
    from sklearn.ensemble import IsolationForest

    def train_model(baseline_features) -> IsolationForest:
        raise NotImplementedError("Phase 4 not yet built")

    def score_event(model, event_features) -> float:
        \"\"\"Returns an anomaly score; more negative = more anomalous.\"\"\"
        raise NotImplementedError("Phase 4 not yet built")
"""

# Intentionally left as a stub. Implement in Phase 4.
# Dependency: scikit-learn (already listed in requirements.txt).
