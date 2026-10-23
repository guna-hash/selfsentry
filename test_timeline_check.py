"""Optional live AI diagnostic; run explicitly, never during test discovery."""

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent / "ai-analysis"))
from attack_timeline_builder import build_timeline  # noqa: E402

fixture_incident = {
    "incident_id": "inc_001",
    "container_id": "abc123",
    "risk_score": 78,
    "dual_layer_agreement": False,
    "status": "open"
}

fixture_events = [
    {
        "container_id": "abc123",
        "timestamp": "2026-08-09T10:15:00Z",
        "rule": "Terminal shell in container",
        "priority": "WARNING",
        "output": "A shell was spawned in a container (user=root container=abc123)"
    },
    {
        "container_id": "abc123",
        "timestamp": "2026-08-09T10:15:02Z",
        "anomaly_score": 0.87,
        "features": {"proc_name": "curl", "parent_proc": "nginx"}
    }
]


if __name__ == "__main__":
    result = build_timeline(fixture_incident, fixture_events)
    print(result)
