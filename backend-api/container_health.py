"""Conservative per-container health from live inventory and monitor evidence."""

from datetime import datetime, timezone
import time


def monitoring_health(container, status):
    status = status or {}
    try:
        age = (
            datetime.now(timezone.utc) - datetime.fromisoformat(status["updated_at"])
        ).total_seconds()
        fresh = bool(status.get("running")) and 0 <= age < 30
    except (KeyError, ValueError, TypeError):
        fresh = False
    components = status.get("components") or {}
    ingest = fresh and components.get("falco_ingest", {}).get("state") == "ok"
    ids = status.get("monitored_container_ids") or []
    tracked = container.id in ids
    lifecycle = (status.get("baselines") or {}).get(container.short_id, {})
    last_seen = lifecycle.get("last_event_at")
    last_window = lifecycle.get("last_window_at")
    if container.status == "paused":
        label = "Paused — inventory watched; no new process activity"
    elif container.status != "running":
        label = "Stopped — inventory watched"
    elif not ingest:
        label = "Monitoring degraded — Falco ingestion unavailable or heartbeat stale"
    elif not tracked:
        label = "Monitoring discovering container"
    elif not last_seen or time.time() - last_seen > 180:
        label = "Monitoring awaiting recent container telemetry"
    else:
        label = "Monitoring Active"
    return {
        "label": label,
        "active": label == "Monitoring Active",
        "tracked": tracked,
        "heartbeat_fresh": fresh,
        "falco_ingestion": bool(ingest),
        "baseline_state": lifecycle.get("state", "NO_BASELINE"),
        "last_event_at": last_seen,
        "last_window_at": last_window,
        "behavioral_model_ready": lifecycle.get("state") == "MODEL_READY",
    }
