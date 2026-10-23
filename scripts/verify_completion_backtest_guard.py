"""Live API acceptance: a fabricated zero FP claim must not bypass a failing backtest.

Run from the SelfSentry checkout. Uses the configured validated benign corpus and a
previously rejected incident's confirmation. Never approves or deploys any rule.
If the backend unexpectedly accepts the test candidate, leave it for explicit human
rejection and report failure. No baseline, corpus, environment or rule file is modified.
"""

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

import requests


def main():
    root = Path.cwd()
    if not (root / "monitor-service/monitor_config.py").is_file():
        raise SystemExit("Run from ~/selfsentry using its Python environment.")
    sys.path[:0] = [str(root / folder) for folder in ("monitor-service", "rule-synthesis-engine")]
    from backend_auth import backend_headers
    from monitor_config import load_config
    from submit_candidate import _load_benign_events
    from rule_backtester import backtest_rule
    from rule_template_generator import generate_rule

    from dotenv import load_dotenv

    load_dotenv(root / ".env")
    cfg = load_config()
    if not cfg.benign_log_path:
        raise SystemExit("Validated benign corpus not configured; no request submitted.")
    path = Path(cfg.benign_log_path)
    fingerprint = hashlib.sha256(path.read_bytes()).hexdigest()
    events = _load_benign_events(str(path))
    pairs: Counter[tuple[str, str]] = Counter()
    for event in events:
        if event.get("rule") != "Baseline Process Spawn":
            continue
        fields = dict(re.findall(r"(\w[\w.]*)=([^\s]+)", event.get("output", "")))
        structured = event.get("output_fields") or {}
        proc = structured.get("proc.name") or event.get("proc_name") or fields.get("proc_name")
        parent = (
            structured.get("proc.pname")
            or event.get("parent_proc_name")
            or fields.get("parent_proc_name")
        )
        if (
            isinstance(proc, str) and isinstance(parent, str)
            and all(re.fullmatch(r"[A-Za-z0-9_./:+-]{1,128}", v) for v in (proc, parent))
        ):
            pairs[proc, parent] += 1
    if not pairs:
        raise SystemExit("No usable process pairs; no request submitted.")
    response = requests.get(cfg.backend_url + "/rules/history", timeout=10)
    response.raise_for_status()
    history = response.json()
    rejected = next((r for r in history if r["id"] == 19 and r["status"] == "rejected"), None)
    if rejected is None:
        raise SystemExit("Expected rejected study rule 19 unavailable; no request submitted.")
    process, parent = pairs.most_common(1)[0][0]
    candidate = generate_rule(
        {"proc_name": process, "parent_proc": parent}, rejected["incident_id"]
    )
    actual = backtest_rule(candidate, events)
    if actual["verdict"] == "pass" or actual["false_positive_rate"] <= 0.05:
        raise SystemExit(
            "Corpus has no qualifying overbroad pair for this test; no request submitted."
        )
    if fingerprint != hashlib.sha256(path.read_bytes()).hexdigest():
        raise SystemExit("Corpus changed; no request submitted.")
    body = {
        "confirmed_incident_id": rejected["confirmed_incident_id"],
        "rule_yaml": candidate,
        "backtested_fp_rate": 0.0,
    }
    response = requests.post(
        cfg.backend_url + "/rules/", json=body, headers=backend_headers(), timeout=30
    )
    try:
        result = response.json()
    except ValueError:
        result = {"detail": "Non-JSON response"}
    detail = result.get("detail")
    passed = (
        response.status_code == 422
        and isinstance(detail, dict)
        and detail.get("reason") == "Candidate failed authoritative backtest"
        and detail.get("verdict") == "flag_for_revision"
    )
    evidence = {
        "test": "authoritative_backend_backtest_guard",
        "evidence_type": "deliberately fabricated client FP claim; real benign corpus",
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "benign_sha256": fingerprint,
        "local_backtest": actual,
        "submitted_candidate": body,
        "http_status": response.status_code,
        "backend_response": result,
        "passed": passed,
    }
    folder = root / "state/evaluation/completion-live"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "backtest-guard.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(
        json.dumps(
            {
                "submitted_fp_rate": 0,
                "actual_backtest": actual,
                "http_status": response.status_code,
                "backend_response": result,
                "passed": passed,
            },
            indent=2,
        )
    )
    print("Evidence:", folder / "backtest-guard.json")
    if response.status_code == 201:
        print(
            "Unexpectedly accepted test candidate:",
            result.get("id"),
            "— reject it explicitly in the review queue. No deployment was requested.",
        )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
