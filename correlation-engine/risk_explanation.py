"""Deterministic, evidence-grounded explanations. No provider imports or network calls."""

from __future__ import annotations

VERSION = "risk-templates-v1"


def severity_for(score, priority=""):
    priority = str(priority).upper()
    if priority in ("EMERGENCY", "ALERT", "CRITICAL") or score >= 90:
        return "critical"
    if priority in ("ERROR", "WARNING") or score >= 70:
        return "high"
    return "medium" if score >= 40 else "low"


def explain_incident(incident):
    from event_router import route_incident

    alert = incident.get("falco_alert") or {}
    anomaly = incident.get("anomaly_features") or {}
    evidence = incident.get("monitor_evidence") or {}
    decision = route_incident(incident)
    cid = incident.get("container_id", "unknown")
    rule = str(alert.get("rule") or "Behavior differs from the learned baseline")
    output = str(alert.get("output") or "")[:1200]
    fields = alert.get("output_fields") or {}
    description = f"Container {cid}: "
    if alert:
        description += f"Falco observed '{rule}'."
        if output:
            description += f" Recorded evidence: {output}"
    else:
        description += "the behavioral model detected an unusual activity window."
    if anomaly:
        description += f" Behavioral anomaly score: {anomaly.get('anomaly_score', 'unavailable')}."
    text = f"{rule} {output} {fields}".lower()
    if any(x in text for x in ("sensitive", "/etc/shadow", "/etc/passwd", "credential")):
        why = "Access to sensitive system files can expose credentials or change access controls."
        fixes = [
            "Remove unnecessary access to the reported sensitive path; use a read-only mount.",
            "Run as a non-root user and drop all unnecessary Linux capabilities.",
            "If credentials were exposed, rotate them and rebuild from a trusted image.",
        ]
    elif any(x in text for x in ("shell", "spawn", "exec", "process")):
        why = "Unexpected processes can indicate command execution or an interactive foothold."
        fixes = [
            "Check the reported process and parent against the workload's expected commands.",
            "Remove shells and debugging tools from the production image where practical.",
            "Run as non-root with --cap-drop=ALL and a read-only root filesystem.",
        ]
    elif any(x in text for x in ("network", "connect", "outbound", "socket")):
        why = "Unexpected connections can enable data exfiltration or remote control."
        fixes = [
            "Check the destination address and port against approved application endpoints.",
            "Restrict outbound traffic to the workload's required destinations.",
            "Review credentials used by the container and rotate any exposed secrets.",
        ]
    else:
        why = (
            "The observed activity differs from expected behavior; unusual activity alone "
            "does not prove an attack."
        )
        fixes = [
            "Review the recorded events and compare them with the intended workload.",
            "Check the container image and configuration for unexpected changes.",
            "If confirmed benign, record the disposition before considering a baseline reset.",
        ]
    layers = (
        "Both detection layers contributed."
        if alert and anomaly
        else "One detection layer contributed."
    )
    rationale = (
        f"Risk score {decision.risk_score:g}/100; confidence {decision.confidence}; "
        f"effective score {decision.effective_score:g}/100 after confidence adjustment. "
        f"{layers} "
        f"{why}"
    )
    if alert:
        rationale += (
            f" Falco priority {alert.get('priority', 'not supplied')} "
            "also sets a minimum severity for this alert."
        )
    if not anomaly:
        rationale += (
            " Behavioral evidence was not used "
            f"({evidence.get('anomaly_status', 'not supplied')}); "
            "this does not establish that behavior was normal."
        )
    return {
        "version": VERSION,
        "source": "deterministic",
        "title": rule,
        "severity": severity_for(decision.effective_score, alert.get("priority")),
        "explanation": description,
        "risk_rationale": rationale,
        "suggested_fixes": fixes[:3],
    }


def explain_deployment(record):
    scan = record.get("scan") or record.get("scan_summary") or {}
    violations = record.get("policy_violations") or []
    decision = record.get("decision", "blocked")
    name = record.get("container_name", "unknown")
    fixes = [v["remediation"] for v in violations if v.get("remediation")]
    if scan.get("critical") or scan.get("high"):
        fixes.insert(0, "Update vulnerable packages or select a patched base image, then rescan.")
    if scan.get("secrets_found"):
        fixes.insert(0, "Remove embedded secrets, rotate them, and inject credentials at runtime.")
    if not scan:
        fixes.insert(0, "Restore Trivy and its vulnerability database access, then retry the gate.")
    if not fixes:
        fixes = ["Keep the image patched and deploy with the validated least-privilege settings."]
    risky = bool(
        violations
        or scan.get("critical")
        or scan.get("high")
        or scan.get("secrets_found")
        or not scan
    )
    severity = (
        "critical"
        if scan.get("critical") or scan.get("secrets_found")
        else ("high" if risky else "low")
    )
    details = "; ".join(str(v.get("title", v.get("rule_id", "Policy finding"))) for v in violations)
    return {
        "version": VERSION,
        "source": "deterministic",
        "severity": severity,
        "title": {
            "blocked": "Blocked Deployment",
            "overridden": "Deployment Override",
            "allowed": "Deployment Allowed",
        }.get(decision, "Deployment Decision"),
        "explanation": (
            f"Deployment of {name} using {record.get('image_name')} was {decision}. "
            f"Scan: {scan.get('critical', 'unknown')} critical, "
            f"{scan.get('high', 'unknown')} high vulnerabilities. {details}"
        ),
        "risk_rationale": (
            "Image or configuration findings require remediation before trusting " "this workload."
            if risky
            else "No blocking findings were recorded."
        )
        + (
            f" Admin override: {record.get('override_reason')}." if decision == "overridden" else ""
        ),
        "suggested_fixes": list(dict.fromkeys(fixes))[:3],
    }
