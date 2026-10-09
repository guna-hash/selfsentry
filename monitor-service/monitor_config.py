"""
monitor_config.py
-------------------
Configuration for the SelfSentry continuous monitor, read from environment variables
and validated at startup: a bad value stops the monitor immediately with a clear message.

Defaults are conservative. See docs/monitor_service.md for the full table.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

_REPO_ROOT = Path(__file__).resolve().parents[1]

UNAPPROVED_POLICIES = ("alert", "ignore")
START_FROM_VALUES = ("end", "beginning")
LOG_FORMATS = ("text", "json")


class ConfigError(ValueError):
    """Raised at startup when the monitor configuration is invalid."""


@dataclass(frozen=True)
class MonitorConfig:
    backend_url: str = "http://localhost:8000"
    falco_log_path: str = "/var/log/falco/alerts.json"
    state_dir: Path = _REPO_ROOT / "state" / "monitor"
    start_from: str = "end"
    poll_interval_seconds: float = 0.5
    max_batch_lines: int = 500
    dedup_window: int = 2000
    registration_grace_seconds: float = 15.0
    registration_retry_seconds: float = 5.0
    unapproved_start_policy: str = "alert"
    retry_base_seconds: float = 1.0
    retry_max_seconds: float = 30.0
    log_format: str = "text"

    def validate(self) -> None:
        problems = []
        if not self.backend_url.startswith(("http://", "https://")):
            problems.append("SELFSENTRY_BACKEND_URL must start with http:// or https://")
        if self.start_from not in START_FROM_VALUES:
            problems.append(f"MONITOR_START_FROM must be one of {START_FROM_VALUES}")
        if self.unapproved_start_policy not in UNAPPROVED_POLICIES:
            problems.append(
                f"MONITOR_UNAPPROVED_START_POLICY must be one of {UNAPPROVED_POLICIES}"
            )
        if self.log_format not in LOG_FORMATS:
            problems.append(f"MONITOR_LOG_FORMAT must be one of {LOG_FORMATS}")
        for name in (
            "poll_interval_seconds",
            "registration_retry_seconds",
            "retry_base_seconds",
            "retry_max_seconds",
        ):
            if getattr(self, name) <= 0:
                problems.append(f"{name} must be greater than 0")
        if self.registration_grace_seconds < 0:
            problems.append("MONITOR_REGISTRATION_GRACE_SECONDS must not be negative")
        if self.max_batch_lines < 1:
            problems.append("MONITOR_MAX_BATCH_LINES must be at least 1")
        if self.dedup_window < 1:
            problems.append("MONITOR_DEDUP_WINDOW must be at least 1")
        if self.retry_max_seconds < self.retry_base_seconds:
            problems.append("MONITOR_RETRY_MAX_SECONDS must be >= MONITOR_RETRY_BASE_SECONDS")
        if problems:
            raise ConfigError("; ".join(problems))


def _read(env: Mapping[str, str], name: str, default, cast):
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return cast(raw.strip())
    except ValueError as exc:
        raise ConfigError(f"{name} must be a valid {cast.__name__}, got {raw!r}") from exc


def load_config(env: Mapping[str, str] | None = None) -> MonitorConfig:
    """Build and validate the configuration from environment variables."""
    env = os.environ if env is None else env
    defaults = MonitorConfig()
    config = MonitorConfig(
        backend_url=_read(env, "SELFSENTRY_BACKEND_URL", defaults.backend_url, str).rstrip("/"),
        falco_log_path=_read(env, "FALCO_LOG_PATH", defaults.falco_log_path, str),
        state_dir=_read(env, "MONITOR_STATE_DIR", defaults.state_dir, Path),
        start_from=_read(env, "MONITOR_START_FROM", defaults.start_from, str),
        poll_interval_seconds=_read(
            env, "MONITOR_POLL_INTERVAL", defaults.poll_interval_seconds, float
        ),
        max_batch_lines=_read(env, "MONITOR_MAX_BATCH_LINES", defaults.max_batch_lines, int),
        dedup_window=_read(env, "MONITOR_DEDUP_WINDOW", defaults.dedup_window, int),
        registration_grace_seconds=_read(
            env, "MONITOR_REGISTRATION_GRACE_SECONDS", defaults.registration_grace_seconds, float
        ),
        registration_retry_seconds=_read(
            env, "MONITOR_REGISTRATION_RETRY_SECONDS", defaults.registration_retry_seconds, float
        ),
        unapproved_start_policy=_read(
            env, "MONITOR_UNAPPROVED_START_POLICY", defaults.unapproved_start_policy, str
        ),
        retry_base_seconds=_read(
            env, "MONITOR_RETRY_BASE_SECONDS", defaults.retry_base_seconds, float
        ),
        retry_max_seconds=_read(
            env, "MONITOR_RETRY_MAX_SECONDS", defaults.retry_max_seconds, float
        ),
        log_format=_read(env, "MONITOR_LOG_FORMAT", defaults.log_format, str),
    )
    config.validate()
    return config
