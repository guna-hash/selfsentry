import sys
sys.path.append("ai-analysis")
from root_cause_summarizer import summarize_incident

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

result = summarize_incident(fixture_incident)
print(result)
