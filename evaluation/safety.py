"""Fail closed before evaluation workloads when runtime isolation is not known off."""

import requests


def require_isolation_disabled(status):
    configuration = status.get("configuration")
    if (
        status.get("healthy") is not True
        or not isinstance(configuration, dict)
        or configuration.get("auto_isolation_enabled") is not False
    ):
        raise RuntimeError(
            "Evaluation requires a healthy monitor reporting automatic isolation disabled. "
            "Restart an older monitor to publish its runtime configuration."
        )


def check_monitor(base="http://127.0.0.1:8000"):
    response = requests.get(base.rstrip("/") + "/monitor/status", timeout=10)
    response.raise_for_status()
    require_isolation_disabled(response.json())
