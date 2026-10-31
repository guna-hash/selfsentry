"""Read-only corroboration of a human-approved anomaly-only native re-fire chain.

Run once per template after collecting actual native evidence. Never confirms an
incident, approves a rule or changes Falco. API evidence and the original JSON log
must agree; a successful request or a declared deployed status alone is insufficient.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any

import yaml
from safety import backend_json

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'rule-synthesis-engine'))
from pattern_extractor import extract_pattern  # noqa: E402
from rule_backtester import backtest_rule  # noqa: E402
from rule_template_generator import generate_rule  # noqa: E402


def require(value, message):
    if not value:
        raise ValueError(message)


def stamp(value):
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(parsed.utcoffset() is not None, 'Native event timestamps must include a timezone')
    return parsed.astimezone(timezone.utc)


def log_prefix(stream):
    """A live append-only log must not extend this verification indefinitely."""
    remaining = os.fstat(stream.fileno()).st_size
    require(remaining <= 2 * 1024**3, 'Native log exceeds the reviewed 2 GiB budget')
    while remaining:
        line = stream.readline(remaining)
        require(line, 'Native log truncated while reading captured prefix')
        remaining -= len(line)
        yield line


def verify(source, rule, refire, log_lines, benign_bytes, template):
    evidence = source.get('monitor_evidence') or {}
    require(not source.get('falco_alert') and not evidence.get('falco_alerts'),
            'Source must be anomaly-only, without security-rule evidence')
    require(evidence.get('baseline_state') == 'MODEL_READY'
            and evidence.get('anomaly_status') == 'used'
            and (evidence.get('anomaly_assessment') or {}).get('qualifies') is True,
            'Ready qualifying anomaly assessment required')
    require((evidence.get('anomaly_assessment') or {}).get('model_algorithm') == 'isolation_forest',
            'This acceptance requires the unchanged default Isolation Forest')
    require(source.get('confirmation'), 'Source incident was not confirmed')
    witness = evidence.get('synthesis_evidence') or {}
    require(witness.get('container_id') == source['container_id'],
            'Literal witness belongs to a different container')
    require(stamp(evidence['window_start']) <= stamp(witness['timestamp'])
            < stamp(evidence['window_end']), 'Witness lies outside the anomaly window')
    pattern = extract_pattern(source)
    require(pattern['action'] == template, 'Source witness uses another template')
    expected_rule = yaml.safe_load(generate_rule(pattern, source['id']))
    require(yaml.safe_load(rule['rule_yaml']) == expected_rule,
            'Stored rule is not the literal template of the source witness')
    require(rule.get('incident_id') == source['id'] and rule.get('status') == 'deployed',
            'Rule is not deployed from this source incident')
    reviewer = rule.get('reviewed_by')
    require(isinstance(reviewer, str) and reviewer.strip()
            and reviewer.strip() != 'selfsentry-auto', 'Human rule approval required')
    lifecycle = rule.get('lifecycle_events') or []
    approved = [item for item in lifecycle if item.get('event_type') == 'RULE_APPROVED'
                and (item.get('detail') or {}).get('reviewed_by') == reviewer]
    deployed = [item for item in lifecycle if item.get('event_type') == 'RULE_DEPLOYED']
    require(approved and deployed, 'Approval and native-deployment lifecycle records required')
    deployed_at = max(stamp(item['occurred_at'] + '+00:00'
                            if datetime.fromisoformat(item['occurred_at']).tzinfo is None
                            else item['occurred_at']) for item in deployed)
    backtests = [(item.get('detail') or {}).get('backtest') for item in lifecycle
                 if item.get('event_type') == 'RULE_BACKTEST_REVALIDATED']
    require(backtests, 'Approval-time authoritative backtest record required')
    benign_sha = hashlib.sha256(benign_bytes).hexdigest()
    require(isinstance(backtests[-1], dict) and backtests[-1].get('benign_sha256') == benign_sha,
            'Supplied benign corpus differs from approval-time evidence')
    benign = [json.loads(line) for line in benign_bytes.decode().splitlines() if line.strip()]
    backtest = backtest_rule(rule['rule_yaml'], benign)
    require(backtest['verdict'] == 'pass' and backtest['events_tested'] > 0,
            'Independent backtest did not pass on the frozen benign corpus')
    require(refire['id'] != source['id'], 'Re-fire must be a subsequent incident')
    name = expected_rule[0]['rule']
    alerts = list((refire.get('monitor_evidence') or {}).get('falco_alerts') or [])
    if refire.get('falco_alert'):
        alerts.append(refire['falco_alert'])
    matches = [item for item in alerts if item.get('rule') == name
               and stamp(item['timestamp']) >= deployed_at]
    require(matches, 'Subsequent incident lacks a post-deployment generated-rule match')
    require(any((item.get('detail') or {}).get('incident_id') == refire['id']
                for item in rule.get('native_refires') or []), 'Re-fire linkage missing')
    corroborated = False
    for line in log_lines:
        try:
            event = json.loads(line)
        except ValueError:
            continue
        fields = event.get('output_fields') or {}
        if event.get('rule') != name or fields.get('container.id') != refire['container_id']:
            continue
        for match in matches:
            if stamp(event['time']) == stamp(match['timestamp']):
                corroborated = True
    require(corroborated, 'Native JSON log does not corroborate the linked re-fire')
    return {'passed': True, 'template': template, 'source_incident_id': source['id'],
            'rule_id': rule['id'], 'refire_incident_id': refire['id'],
            'native_rule_name': name, 'reviewed_by': reviewer,
            'benign_sha256': benign_sha, 'backtest_events_tested': backtest['events_tested'],
            'scope': 'Corroborated supplied/API evidence; no representative accuracy claim'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-incident', type=int, required=True)
    parser.add_argument('--rule', type=int, required=True)
    parser.add_argument('--refire-incident', type=int, required=True)
    parser.add_argument('--template', choices=('spawned_process', 'file_write'), required=True)
    parser.add_argument('--falco-log', type=Path, required=True)
    parser.add_argument('--benign-corpus', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.expanduser().resolve()
    require(not output.is_relative_to(ROOT), 'Private evidence must stay outside Git checkout')
    fd = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    report: dict[str, Any] = {'passed': False}
    try:
        require(min(args.source_incident, args.rule, args.refire_incident) > 0,
                'Positive database identities required')

        def get(path):
            return backend_json("http://127.0.0.1:8000", path)

        rules = get('/rules/history')
        rule = next(item for item in rules if item['id'] == args.rule)
        with args.falco_log.open('rb') as stream:
            report = verify(get(f'/incidents/{args.source_incident}'), rule,
                            get(f'/incidents/{args.refire_incident}'), log_prefix(stream),
                            args.benign_corpus.read_bytes(), args.template)
    except Exception as exc:
        report = {'passed': False, 'error_type': type(exc).__name__,
                  'reason': 'Chain not verified; retain original logs and inspect inputs'}
    finally:
        with os.fdopen(fd, 'w') as stream:
            json.dump(report, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
