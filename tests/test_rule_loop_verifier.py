"""Fabricated fixtures test evidence rejection; they are not native loop results."""

import copy
import hashlib
import json
from pathlib import Path
import sys

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'evaluation'))
from verify_rule_loop import verify, generate_rule, extract_pattern, log_prefix  # noqa: E402


def chain(template):
    kind = 'Baseline Process Spawn' if template == 'spawned_process' else 'Baseline File Write'
    fields = {'proc.name': 'cat', 'proc.pname': 'sh', 'fd.name': '/tmp/check'}
    source = {
        'id': 1, 'container_id': 'a' * 12, 'falco_alert': None,
        'confirmation': {'confirmed_by': 'operator'},
        'monitor_evidence': {
            'baseline_state': 'MODEL_READY', 'anomaly_status': 'used',
            'anomaly_assessment': {'qualifies': True, 'model_algorithm': 'isolation_forest'},
            'falco_alerts': [],
            'window_start': '2026-10-25T00:00:00Z',
            'window_end': '2026-10-25T00:01:00Z',
            'synthesis_evidence': {
                'rule': kind, 'output_fields': fields, 'container_id': 'a' * 12,
                'timestamp': '2026-10-25T00:00:30Z',
            },
        },
    }
    benign = json.dumps({'rule': kind, 'output_fields': {
        'proc.name': 'nginx', 'proc.pname': 'systemd', 'fd.name': '/tmp/other',
    }}).encode()
    generated = generate_rule(extract_pattern(source), 1)
    name = yaml.safe_load(generated)[0]['rule']
    rule = {
        'id': 4, 'incident_id': 1, 'rule_yaml': generated, 'status': 'deployed',
        'reviewed_by': 'guna',
        'lifecycle_events': [
            {'event_type': 'RULE_APPROVED', 'detail': {'reviewed_by': 'guna'}},
            {'event_type': 'RULE_BACKTEST_REVALIDATED', 'detail': {
                'backtest': {'benign_sha256': hashlib.sha256(benign).hexdigest()},
            }},
            {'event_type': 'RULE_DEPLOYED', 'occurred_at': '2026-10-25T00:02:00'},
        ],
        'native_refires': [{'detail': {'incident_id': 5}}],
    }
    refire = {'id': 5, 'container_id': 'b' * 12, 'falco_alert': {
        'rule': name, 'timestamp': '2026-10-25T00:03:00Z',
    }}
    log = json.dumps({'rule': name, 'time': '2026-10-25T00:03:00Z',
                      'output_fields': {'container.id': 'b' * 12}})
    return source, rule, refire, [log], benign, template


@pytest.mark.parametrize('template', ['spawned_process', 'file_write'])
def test_each_literal_template_requires_a_complete_corroborated_chain(template):
    result = verify(*chain(template))
    assert result['passed'] is True and result['backtest_events_tested'] == 1


@pytest.mark.parametrize('failure', [
    'falco_backed', 'learning', 'unconfirmed', 'wrong_owner', 'wrong_window',
    'unreviewed', 'no_deploy', 'changed_corpus', 'predeployment', 'missing_link',
    'missing_native_log', 'changed_rule',
])
def test_missing_or_conflicting_evidence_never_passes(failure):
    args = list(copy.deepcopy(chain('spawned_process')))
    source, rule, refire = args[:3]
    if failure == 'falco_backed':
        source['falco_alert'] = {'rule': 'existing rule'}
    elif failure == 'learning':
        source['monitor_evidence']['baseline_state'] = 'LEARNING'
    elif failure == 'unconfirmed':
        source['confirmation'] = None
    elif failure == 'wrong_owner':
        source['monitor_evidence']['synthesis_evidence']['container_id'] = 'c' * 12
    elif failure == 'wrong_window':
        source['monitor_evidence']['synthesis_evidence']['timestamp'] = '2026-10-24T00:00:00Z'
    elif failure == 'unreviewed':
        rule['reviewed_by'] = 'selfsentry-auto'
    elif failure == 'no_deploy':
        rule['lifecycle_events'].pop()
    elif failure == 'changed_corpus':
        args[4] += b'\n'
    elif failure == 'predeployment':
        refire['falco_alert']['timestamp'] = '2026-10-25T00:01:00Z'
    elif failure == 'missing_link':
        rule['native_refires'] = []
    elif failure == 'missing_native_log':
        args[3] = []
    elif failure == 'changed_rule':
        rule['rule_yaml'] = rule['rule_yaml'].replace('proc.name="cat"', 'proc.name="ls"')
    with pytest.raises(ValueError):
        verify(*args)


def test_native_log_verification_uses_a_finite_prefix_even_when_appended(tmp_path):
    path = tmp_path / 'falco.jsonl'
    path.write_bytes(b'first\nsecond\n')
    with path.open('rb') as stream:
        lines = log_prefix(stream)
        assert next(lines) == b'first\n'
        with path.open('ab') as writer:
            writer.write(b'new-live-event\n')
        assert list(lines) == [b'second\n']
