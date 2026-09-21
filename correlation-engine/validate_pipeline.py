"""
validate_pipeline.py
-----------------------
Module 5c of SelfSentry: Phase 5 manual validation driver (local
simulation stage).

Generates realistic, shape-correct test data - matching EXACTLY what
runtime-monitor/falco_integration.py's FalcoAlert.to_dict() and
behavioral-engine/anomaly_model.py's AnomalyResult.to_event_dict() really
produce - and runs it through the REAL risk_scorer.compute_risk_score()
and event_router.route_incident()/dispatch_incident(). No network calls,
no backend, no database - pure local simulation, per the staged testing
plan (local simulation -> inspect output -> fix if needed -> backend
integration -> end-to-end).

This deliberately does NOT read live Falco/eBPF or run a trained
IsolationForest model - that's what behavioral-engine/validate_live.py
and a future live end-to-end script are for. This script's only job is:
prove risk_scorer.py + event_router.py correctly handle realistic data
shaped exactly like what the real upstream modules emit.

Usage:
    python3 validate_pipeline.py
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from risk_scorer import compute_risk_score
from event_router import route_incident, dispatch_incident

import argparse
import json
import urllib.request
import urllib.error

BACKEND_INCIDENTS_URL = "http://127.0.0.1:8000/incidents/"


def post_incident_to_backend(incident: dict) -> dict | None:
    """
    Sends one incident payload to the real backend's POST /incidents/.
    Uses only the standard library (urllib) - no extra dependency needed
    for this one-off validation script. Returns the parsed JSON response
    on success, or None on failure (with the error printed).
    """
    data = json.dumps(incident).encode("utf-8")
    req = urllib.request.Request(
        BACKEND_INCIDENTS_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        print(f"  !! backend rejected incident (HTTP {exc.code}): {body}")
        return None
    except urllib.error.URLError as exc:
        print(f"  !! could not reach backend at {BACKEND_INCIDENTS_URL}: {exc}")
        print("     Is uvicorn running? (uvicorn main:app --reload, from backend-api/)")
        return None


def _ts(offset_seconds: int = 0) -> str:
    """ISO-8601 UTC timestamp, matching FalcoAlert.timestamp's real
    format (raw["time"] from Falco's JSON output, which is ISO-8601)."""
    base = datetime.now(timezone.utc)
    return (base + timedelta(seconds=offset_seconds)).isoformat()


# --- Scenario 1: dual-layer agreement - Falco + anomaly fire together ---
# Shaped EXACTLY like FalcoAlert.to_dict() and AnomalyResult.to_event_dict().
SCENARIO_1_FALCO = [
    {
        "container_id": "sim_container_dual",
        "timestamp": _ts(0),
        "rule": "Terminal shell in container",
        "priority": "WARNING",
        "output": "A shell was spawned in a container (user=root container=sim_container_dual)",
    }
]
SCENARIO_1_ANOMALY = [
    {
        "container_id": "sim_container_dual",
        "timestamp": _ts(2),  # within the 60s correlation window
        "anomaly_score": 0.91,
        "features": {
            "distinct_process_count": 4,
            "distinct_network_dest_count": 1,
            "distinct_ports_count": 1,
            "distinct_files_accessed": 12,
            "total_event_count": 30,
            "shell_spawned_count": 1,
            "distinct_parent_child_pairs": 3,
            "sensitive_syscall_count": 6,
        },
    }
]

# --- Scenario 2: Falco-only - real rule fires, no anomaly corroboration ---
SCENARIO_2_FALCO = [
    {
        "container_id": "sim_container_falco_only",
        "timestamp": _ts(0),
        "rule": "Write below binary dir",
        "priority": "ERROR",
        "output": "File below a known binary directory opened for writing "
        "(container=sim_container_falco_only)",
    }
]
SCENARIO_2_ANOMALY: list[dict] = []

# --- Scenario 3: anomaly-only - the case the hybrid design exists for ---
# (a novel attack pattern with no matching Falco rule yet)
SCENARIO_3_FALCO: list[dict] = []
SCENARIO_3_ANOMALY = [
    {
        "container_id": "sim_container_anomaly_only",
        "timestamp": _ts(0),
        "anomaly_score": 0.86,
        "features": {
            "distinct_process_count": 9,
            "distinct_network_dest_count": 5,
            "distinct_ports_count": 4,
            "distinct_files_accessed": 40,
            "total_event_count": 120,
            "shell_spawned_count": 0,
            "distinct_parent_child_pairs": 7,
            "sensitive_syscall_count": 15,
        },
    }
]

# --- Scenario 4: low-signal noise - should stay quiet ---
SCENARIO_4_FALCO = [
    {
        "container_id": "sim_container_noise",
        "timestamp": _ts(0),
        "rule": "Unexpected outbound connection",
        "priority": "NOTICE",
        "output": "Outbound connection to unusual port (container=sim_container_noise)",
    }
]
SCENARIO_4_ANOMALY: list[dict] = []


SCENARIOS = [
    ("Dual-layer agreement (Falco + anomaly, same container/window)",
     SCENARIO_1_FALCO, SCENARIO_1_ANOMALY),
    ("Falco-only, strong priority (ERROR)", SCENARIO_2_FALCO, SCENARIO_2_ANOMALY),
    ("Anomaly-only, no matching rule yet (the hybrid design's core case)",
     SCENARIO_3_FALCO, SCENARIO_3_ANOMALY),
    ("Low-signal noise (NOTICE priority, no anomaly)",
     SCENARIO_4_FALCO, SCENARIO_4_ANOMALY),
]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--post-to-backend",
        action="store_true",
        help="Also POST each simulated incident to the real backend "
        f"({BACKEND_INCIDENTS_URL}) and print its persisted response "
        "(including ai_summary). Off by default - local simulation only.",
    )
    args = parser.parse_args()

    mode = "LOCAL + BACKEND POST" if args.post_to_backend else "LOCAL ONLY"
    print("=" * 78)
    print(f"SelfSentry Phase 5 — Pipeline Validation ({mode})")
    print("=" * 78)

    for label, falco_alerts, anomaly_events in SCENARIOS:
        print(f"\n--- Scenario: {label} ---")

        incidents = compute_risk_score(falco_alerts, anomaly_events)
        if not incidents:
            print("  (no incidents produced — unexpected for a non-empty scenario!)")
            continue

        for incident in incidents:
            print(f"  container_id     : {incident['container_id']}")
            print(f"  risk_score       : {incident['risk_score']}")
            print(f"  confidence       : {incident['confidence']}")
            print(f"  falco_alert?     : {'yes' if incident['falco_alert'] else 'no'}")
            print(f"  anomaly_features?: {'yes' if incident['anomaly_features'] else 'no'}")

            decision = route_incident(incident)
            print(f"  effective_score  : {decision.effective_score}")
            print(f"  routed actions   : {decision.actions}")

            results = dispatch_incident(incident, decision)
            print(f"  dispatch results : {results}")

            if args.post_to_backend:
                persisted = post_incident_to_backend(incident)
                if persisted is not None:
                    print(f"  persisted id     : {persisted.get('id')}")
                    print(f"  ai_summary       : {persisted.get('ai_summary')}")
            print()

    print("=" * 78)
    print("Done. Review each scenario above:")
    print("  - Scenario 1 should show confidence=high and a boosted risk_score")
    print("  - Scenario 2 should show confidence=medium (strong Falco alone)")
    print("  - Scenario 3 should show confidence depending on anomaly_score "
          "(>=0.8 -> medium) and PROVE anomaly-only incidents are never dropped")
    print("  - Scenario 4 should stay low risk_score / low confidence / log-only")
    print("=" * 78)


if __name__ == "__main__":
    main()
