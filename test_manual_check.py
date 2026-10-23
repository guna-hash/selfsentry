"""Optional live AI diagnostic; run explicitly, never during test discovery."""

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent / "ai-analysis"))
from root_cause_summarizer import summarize_incident  # noqa: E402

fixture_incident = {
    "incident_id": "inc_001",
    "container_id": "abc123",
    "risk_score": 78,
    "falco_alert": {
        "container_id": "abc123",
        "timestamp": "2026-08-09T10:15:00Z",
        "rule": "Terminal shell in container",
        "priority": "WARNING",
        "output": "A shell was spawned in a container (user=root container=abc123)"
    },
    "anomaly_event": None,
    "dual_layer_agreement": False,
    "status": "open"
}


if __name__ == "__main__":
    result = summarize_incident(fixture_incident)
    print(result)
