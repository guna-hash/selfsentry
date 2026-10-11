"""Durable incident delivery and bounded, independently configured workflow actions.

The outbox survives lost HTTP responses. Backend event_key prevents duplicate incidents.
Isolation attempts are committed locally BEFORE Docker is touched. Ambiguous attempts after
restart are marked unknown and require operator review rather than destructive replay.
"""

from __future__ import annotations
import json
import logging
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import docker
import requests

ROOT = Path(__file__).resolve().parents[1]
for folder in ("response-engine", "rule-synthesis-engine", "ai-analysis"):
    sys.path.insert(0, str(ROOT / folder))

from automation_policy import eligible  # noqa: E402
from auto_isolate import isolate_container  # noqa: E402
from submit_candidate import submit_candidate  # noqa: E402
from root_cause_summarizer import summarize_incident  # noqa: E402
from audit_client import make_event_key  # noqa: E402
from backend_auth import backend_headers  # noqa: E402

logger = logging.getLogger(__name__)


class IncidentPipeline:
    def __init__(
        self,
        behavior,
        http=requests,
        isolate=isolate_container,
        docker_factory=docker.from_env,
        synthesize=submit_candidate,
        summarize=summarize_incident,
        clock=time.time,
        async_explanations=True,
    ):
        self.behavior, self.config, self.db = behavior, behavior.config, behavior.db
        self.status, self.audit = behavior.status, behavior.audit
        self.http, self.isolate, self.docker_factory = http, isolate, docker_factory
        self.synthesize, self.summarize, self.clock = synthesize, summarize, clock
        self.executor = ThreadPoolExecutor(max_workers=1) if async_explanations else None
        self.explanations = {}
        self.db.execute("""CREATE TABLE IF NOT EXISTS actions (
            key TEXT PRIMARY KEY, body TEXT, phase TEXT, attempts INTEGER DEFAULT 0)""")
        self.db.execute("CREATE TABLE IF NOT EXISTS ai_cooldown (key TEXT PRIMARY KEY, until REAL)")
        self.db.commit()

    def _request(self, method, path, **kwargs):
        response = getattr(self.http, method)(
            self.config.backend_url + path, timeout=10, headers=backend_headers(), **kwargs
        )
        response.raise_for_status()
        return response.json()

    def _save(self, key, body, phase):
        with self.db:
            self.db.execute(
                "INSERT OR REPLACE INTO actions(key,body,phase) VALUES (?,?,?)",
                (key, json.dumps(body), phase),
            )

    def _ai_cooldown(self):
        row = self.db.execute("SELECT until FROM ai_cooldown WHERE key='provider'").fetchone()
        return row[0] if row else 0

    def _ai_retry_delay(self, exc, attempts):
        # Respect Retry-After; use exponential cooldown when the provider omits it.
        import math
        from email.utils import parsedate_to_datetime
        from datetime import timezone

        delay = 120 * 2 ** min(max(attempts - 1, 0), 3)
        headers = getattr(getattr(exc, "response", None), "headers", {}) or {}
        value = headers.get("retry-after") or headers.get("Retry-After")
        if value:
            try:
                seconds = float(value)
            except (ValueError, TypeError):
                try:
                    stamp = parsedate_to_datetime(value)
                    if stamp.tzinfo is None:
                        stamp = stamp.replace(tzinfo=timezone.utc)
                    seconds = stamp.timestamp() - self.clock()
                except (ValueError, TypeError, OverflowError):
                    seconds = 0
            if math.isfinite(seconds):
                delay = max(delay, seconds)
        return delay

    def _audit(self, event_type, key, body):
        self.audit.emit(
            event_type=event_type,
            container_id=body["payload"]["container_id"],
            detail={"incident_id": body["id"], **body.get("workflow", {})},
            event_key=make_event_key(event_type, key),
        )

    def tick(self):
        rows = list(
            self.db.execute(
                """SELECT key,body,stage,incident_id,attempts FROM outbox
            WHERE stage NOT IN ('done','rejected') AND next_retry <= ?
            ORDER BY CASE WHEN stage='pending' THEN 0 ELSE 1 END LIMIT 20""",
                (self.clock(),),
            )
        )
        for key, raw, stage, incident_id, attempts in rows:
            try:
                payload = json.loads(raw)
                saved = self._request("post", "/incidents/", json=payload)
                incident_id = saved["id"]
                action = self.db.execute(
                    "SELECT body,phase FROM actions WHERE key=?", (key,)
                ).fetchone()
                body = (
                    json.loads(action[0])
                    if action
                    else {"id": incident_id, "payload": payload, "workflow": {}}
                )
                body["payload"]["monitor_workflow"] = saved.get("monitor_workflow") or {}
                phase = action[1] if action else "confirm"
                completed = self._process(key, body, phase)
                if not completed:
                    with self.db:
                        self.db.execute(
                            "UPDATE outbox SET stage='advisory',next_retry=? WHERE key=?",
                            (
                                max(
                                    self.clock() + 1,
                                    body.get("ai_retry_at", 0),
                                    self._ai_cooldown(),
                                ),
                                key,
                            ),
                        )
                    continue
                with self.db:
                    self.db.execute(
                        "UPDATE outbox SET stage='done',incident_id=?,error=NULL WHERE key=?",
                        (incident_id, key),
                    )
                self.status.incr("incidents_delivered")
                self.status.set_component("incident_backend", "ok")
            except Exception as exc:
                logger.exception("incident workflow failed; retained in durable outbox")
                self.status.set_component("incident_backend", "degraded", str(exc))
                self.status.incr("incident_delivery_errors")
                attempts += 1
                delay = min(
                    self.config.retry_max_seconds,
                    self.config.retry_base_seconds * 2 ** min(attempts, 10),
                )
                # An incompatible payload is retained for inspection instead of retried forever.
                rejected = isinstance(exc, requests.HTTPError) and (
                    exc.response is not None and exc.response.status_code in (400, 404, 422)
                )
                with self.db:
                    self.db.execute(
                        """UPDATE outbox SET attempts=?,next_retry=?,error=?,
                        stage=?,incident_id=? WHERE key=?""",
                        (
                            attempts,
                            self.clock() + delay,
                            str(exc),
                            "rejected" if rejected else "pending",
                            incident_id,
                            key,
                        ),
                    )
                if isinstance(exc, requests.RequestException) and not rejected:
                    break  # avoid serial timeout storms while the backend is offline
        self.status.set_value(
            "failed_response_actions",
            self.db.execute(
                "SELECT count(*) FROM actions WHERE body LIKE '%isolation_failed%' "
                "OR body LIKE '%unknown_after_restart%'"
            ).fetchone()[0],
        )

    def _process(self, key, body, phase):
        payload, flow = body["payload"], body["workflow"]
        if phase == "confirm":
            allowed, reason = eligible(payload, self.config, now=self.clock())
            policy = {
                "version": "monitor-v1",
                "enabled": self.config.auto_confirm_enabled,
                "threshold": self.config.auto_confirm_threshold,
                "anomaly_threshold": self.config.anomaly_threshold,
                "correlation_seconds": self.config.correlation_seconds,
                "reason": reason,
            }
            flow["confirmation_policy"] = policy
            if allowed:
                try:
                    confirmation = self._request(
                        "post",
                        f"/incidents/{body['id']}/confirm",
                        params={"confirmed_by": "selfsentry-auto"},
                    )
                except requests.HTTPError as exc:
                    if exc.response is None or exc.response.status_code != 409:
                        raise
                    confirmation = {"status": "unconfirmed", "reason": "backend policy denied"}
                flow["confirmation"] = confirmation
                self._audit("INCIDENT_CONFIRMATION", key, body)
            else:
                flow["confirmation"] = {"status": "unconfirmed", "reason": reason}
            self._save(key, body, "isolate")
            phase = "isolate"
        if phase == "isolation_attempted":
            # No safe way to know whether Docker completed before the process crashed.
            flow["response"] = {
                "status": "unknown_after_restart",
                "reason": "isolation attempt interrupted; inspect container manually",
            }
            self._audit("ISOLATION_OUTCOME_UNKNOWN", key, body)
            self._save(key, body, "candidate")
            phase = "candidate"
        if phase == "isolate":
            allowed, reason = eligible(payload, self.config, action="isolate", now=self.clock())
            if allowed:
                try:
                    client = self.docker_factory()
                    try:
                        container = client.containers.get(payload["container_id"])
                        full_id = container.id
                        if len(full_id) != 64 or not full_id.startswith(payload["container_id"]):
                            raise ValueError("Docker identity does not match incident")
                        excluded = self.config.protected_containers
                        if (
                            full_id in excluded
                            or full_id[:12] in excluded
                            or container.name in excluded
                        ):
                            flow["response"] = {"status": "protected", "container_id": full_id}
                        elif container.status not in ("running", "paused"):
                            flow["response"] = {
                                "status": "ineligible",
                                "reason": "container not running",
                            }
                        else:
                            flow["response"] = {
                                "status": "attempted",
                                "container_id": full_id,
                                "threshold": self.config.auto_isolation_threshold,
                                "reason": reason,
                            }
                            self._save(key, body, "isolation_attempted")
                            self._audit("ISOLATION_ATTEMPTED", key, body)
                            self.isolate(full_id, f"incident {body['id']}: {reason}")
                            flow["response"] = {**flow["response"], "status": "isolated"}
                    finally:
                        close = getattr(client, "close", None)
                        if close:
                            close()
                except Exception as exc:
                    flow["response"] = {"status": "isolation_failed", "reason": str(exc)}
                    logger.exception("isolation failed; automatic attempt will not be repeated")
                self._save(key, body, "candidate")
                self._audit("ISOLATION_RESULT", key, body)
            else:
                flow["response"] = {"status": "not_attempted", "reason": reason}
                self._save(key, body, "candidate")
            phase = "candidate"
        # Synchronize actual confirmation/response before advisory work.
        if phase == "candidate":
            self._request("post", f"/monitor/incidents/{body['id']}/workflow", json=flow)
            auto_confirmed = flow.get("confirmation", {}).get("confirmed_by") == "selfsentry-auto"
            if not self.config.rule_candidates_enabled or not auto_confirmed:
                flow["candidate"] = {
                    "status": "skipped",
                    "reason": "not eligible for auto synthesis",
                }
            elif not self.config.benign_log_path:
                flow["candidate"] = {
                    "status": "unavailable",
                    "reason": "operator-validated benign corpus not configured",
                }
            else:
                try:
                    result = self.synthesize(
                        body["id"],
                        "selfsentry-auto",
                        backend_url=self.config.backend_url,
                        log_path=self.config.benign_log_path,
                    )
                    flow["candidate"] = {"status": "pending_review", **result}
                except requests.RequestException:
                    # Network retry is safe: the backend blocks duplicate active candidates.
                    raise
                except Exception as exc:
                    flow["candidate"] = {"status": "validation_failed", "reason": str(exc)}
            self._save(key, body, "explain")
            self._audit("RULE_CANDIDATE_RESULT", key, body)
            phase = "explain"
        if phase in ("explain", "explain_waiting"):
            if key not in self.explanations:
                if max(body.get("ai_retry_at", 0), self._ai_cooldown()) > self.clock():
                    return False
                if self.executor and self.explanations:
                    return False
            try:
                argument = {**payload, "incident_id": body["id"], "workflow": flow}
                if key not in self.explanations:
                    # Count and persist attempts before starting a provider request.
                    if body.get("ai_attempts", 0) >= 4:
                        raise RuntimeError("AI attempt budget exhausted after restart")
                    body["ai_attempts"] = body.get("ai_attempts", 0) + 1
                    body.pop("ai_retry_at", None)
                    self._save(key, body, "explain_waiting")
                if self.executor:
                    if key not in self.explanations:
                        self.explanations[key] = self.executor.submit(self.summarize, argument)
                    future = self.explanations[key]
                    if not future.done():
                        return False
                    self.explanations.pop(key)
                    result = future.result()
                else:
                    result = self.summarize(argument)
                flow["explanation"] = {"status": "ready", "result": result}
            except Exception as exc:
                code = getattr(exc, "status_code", None)
                if code == 429:
                    retry_at = self.clock() + self._ai_retry_delay(exc, body.get("ai_attempts", 1))
                    with self.db:
                        self.db.execute(
                            "INSERT OR REPLACE INTO ai_cooldown(key,until) VALUES ('provider',?)",
                            (max(retry_at, self._ai_cooldown()),),
                        )
                    if body.get("ai_attempts", 0) < 4:
                        body["ai_retry_at"] = retry_at
                        flow["explanation"] = {
                            "status": "pending_retry",
                            "reason": "AI provider rate limited",
                            "http_status": 429,
                            "attempts": body["ai_attempts"],
                            "next_retry_epoch": retry_at,
                        }
                        self._save(key, body, "explain")
                        self._request(
                            "post", f"/monitor/incidents/{body['id']}/workflow", json=flow
                        )
                        logger.warning(
                            "AI rate limited for incident %s; retry scheduled", body["id"]
                        )
                        return False
                logger.warning("AI explanation unavailable for incident %s", body["id"])
                flow["explanation"] = {
                    "status": "unavailable",
                    "reason": (
                        "AI rate limit retry budget exhausted"
                        if code == 429
                        else "AI provider failed or unset"
                    ),
                    "attempts": body.get("ai_attempts", 0),
                }
                if isinstance(code, int):
                    flow["explanation"]["http_status"] = code
            self._save(key, body, "sync")
        self._request("post", f"/monitor/incidents/{body['id']}/workflow", json=flow)
        self._save(key, body, "done")
        return True
