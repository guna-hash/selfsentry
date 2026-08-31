import sys
sys.path.append("ai-analysis")
from attack_timeline_builder import build_timeline

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

result = build_timeline(fixture_incident, fixture_events)
print(result)
