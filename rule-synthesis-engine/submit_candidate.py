"""
submit_candidate.py
---------------------
Rule Synthesis Engine - Candidate Submitter.

Chains the existing Rule Synthesis steps and queues the result for human review:

    confirm incident -> fetch incident -> extract pattern -> generate rule (Jinja2)
    -> backtest against real historical benign events -> POST /rules/ (pending_review)

Safety constraints (non-negotiable project rules):
  - Nothing is deployed here. The rule only enters the Review Queue; deployment
    happens when a human approves it (POST /rules/{id}/approve).
  - A candidate whose backtest verdict is not "pass" is refused unless the caller
    explicitly opts in with allow_flagged=True / --allow-flagged.
  - A backtest that tested zero events is refused: backtest_rule() reports a 0%
    false-positive rate when there is no benign data, which would be a misleading pass.
"""

from __future__ import annotations

import os
import sys

import requests

from confirmation_manager import ConfirmationError, confirm_incident
from pattern_extractor import PatternExtractionError, extract_pattern
from rule_backtester import BacktestError, backtest_rule
from rule_template_generator import RuleGenerationError, generate_rule

DEFAULT_BACKEND_URL = "http://localhost:8000"
DEFAULT_LOG_PATH = "/var/log/falco/alerts.json"


class SubmissionError(RuntimeError):
    """Raised when a candidate rule must not be queued for review."""


def _load_benign_events(log_path: str) -> list[dict]:
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, os.path.join(repo_root, "runtime-monitor"))
    from falco_integration import read_falco_alerts_from_file

    return read_falco_alerts_from_file(log_path)


def submit_candidate(
    incident_id: int,
    confirmed_by: str,
    backend_url: str = DEFAULT_BACKEND_URL,
    log_path: str = DEFAULT_LOG_PATH,
    allow_flagged: bool = False,
    events: list[dict] | None = None,
    timeout_seconds: int = 10,
) -> dict:
    """Run the full synthesis chain for one incident and queue the candidate rule.

    Returns {"rule_id", "status", "backtest", "rule_yaml"}. Raises SubmissionError
    (or the underlying module's error) if the candidate must not be queued.
    """
    confirmation = confirm_incident(incident_id, confirmed_by, backend_url=backend_url)
    confirmed_incident_id = confirmation.get("confirmed_incident_id")
    if confirmed_incident_id is None:
        raise SubmissionError(
            f"Backend did not return a confirmed_incident_id for incident {incident_id}"
        )

    response = requests.get(f"{backend_url}/incidents/{incident_id}", timeout=timeout_seconds)
    response.raise_for_status()
    incident = response.json()

    pattern = extract_pattern(incident)
    rule_yaml = generate_rule(pattern, source_incident_id=incident_id)

    if events is None:
        events = _load_benign_events(log_path)
    backtest = backtest_rule(rule_yaml, events)

    if backtest["events_tested"] == 0:
        raise SubmissionError(
            "Backtest tested 0 events - refusing to queue a rule with no benign evidence"
        )
    if backtest["verdict"] != "pass" and not allow_flagged:
        raise SubmissionError(
            f"Backtest verdict is '{backtest['verdict']}' "
            f"(false-positive rate {backtest['false_positive_rate']}); "
            "refusing to queue. Re-run with --allow-flagged to override."
        )

    post = requests.post(
        f"{backend_url}/rules/",
        json={
            "confirmed_incident_id": confirmed_incident_id,
            "rule_yaml": rule_yaml,
            "backtested_fp_rate": backtest["false_positive_rate"],
        },
        timeout=timeout_seconds,
    )
    if post.status_code != 201:
        raise SubmissionError(f"Backend rejected the rule: HTTP {post.status_code} - {post.text}")

    body = post.json()
    return {
        "rule_id": body["id"],
        "status": body["status"],
        "backtest": backtest,
        "rule_yaml": rule_yaml,
    }


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(
        description="SelfSentry - Confirm an incident, synthesize and backtest a rule, queue it"
    )
    parser.add_argument("incident_id", type=int)
    parser.add_argument("--confirmed-by", required=True)
    parser.add_argument("--backend-url", default=DEFAULT_BACKEND_URL)
    parser.add_argument("--log-path", default=DEFAULT_LOG_PATH)
    parser.add_argument("--allow-flagged", action="store_true")
    args = parser.parse_args()

    try:
        result = submit_candidate(
            args.incident_id,
            args.confirmed_by,
            backend_url=args.backend_url,
            log_path=args.log_path,
            allow_flagged=args.allow_flagged,
        )
    except (
        SubmissionError,
        ConfirmationError,
        PatternExtractionError,
        RuleGenerationError,
        BacktestError,
        requests.RequestException,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    print(json.dumps(result, indent=2))
