"""Chronological observed evidence; no AI call or inferred attacker intent."""

from datetime import datetime, timezone


def build_observed_timeline(alerts, anomaly=None):
    entries = [
        {"timestamp": alert["timestamp"], "source": "falco",
         "description": alert["rule"], "output": alert.get("output"),
         "event_key": alert.get("event_key")}
        for alert in alerts
    ]
    if anomaly:
        entries.append({
            "timestamp": anomaly["timestamp"], "source": "anomaly_model",
            "description": "Behavioral window qualified as anomalous",
            "anomaly_score": anomaly["anomaly_score"],
        })
    entries.sort(key=lambda entry: datetime.fromisoformat(
        entry["timestamp"].replace("Z", "+00:00")
    ).astimezone(timezone.utc))
    return [dict(entry, step=index) for index, entry in enumerate(entries, 1)]
