"""Actual route/SQLite review/audits with controlled native adapter callbacks."""

import hashlib
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from tests.test_backend_rules import RulesApiTestCase, rules_module, RULE_YAML
from models.db_models import GeneratedRule, AuditEvent
import native_retirement as nr


class TestNativeRetirementApi(RulesApiTestCase):
    def prepare(self, deployment_audit=True):
        rule_id = self.add_rule(status='deployed')
        if deployment_audit:
            with self.Session() as db:
                rule = db.get(GeneratedRule, rule_id)
                rules_module._audit_rule(db, 'RULE_DEPLOYED', rule, {'reviewed_by': 'first'})
                db.commit()
        return rule_id

    def body(self, **changes):
        return {'reviewed_by': 'alice', 'reason': 'Reviewed false positives',
                'expected_file_sha256': 'a' * 64,
                'expected_rule_sha256': hashlib.sha256(RULE_YAML.encode()).hexdigest(),
                'confirm_native_unload': True, **changes}

    def post(self, rule_id, **changes):
        return self.client.post(f'/rules/{rule_id}/retire-native', json=self.body(**changes))

    def fake_execute(self, *args, **kwargs):
        intent, complete = args[9:11]
        record = {'phase': 'applied', 'rule_id': str(args[0]), 'operation_id': 'b' * 32,
                  'reviewed_by': args[3], 'previous_db_status': 'deployed'}
        intent(record)
        complete(record, True)
        return record

    def test_disabled_native_endpoint_cannot_change_db_or_call_adapter(self):
        rule_id = self.prepare()
        with patch.dict(os.environ, {'SELFSENTRY_NATIVE_RETIREMENT_ENABLED': 'false'}), \
                patch.object(nr, 'execute') as execute:
            assert self.post(rule_id).status_code == 409
        execute.assert_not_called()
        assert self.rule_status(rule_id) == 'deployed'

    def test_explicit_identity_confirmation_hash_and_deployment_evidence_are_required(self):
        with patch.dict(os.environ, {'SELFSENTRY_NATIVE_RETIREMENT_ENABLED': 'true'}), \
                patch.object(nr, 'execute') as execute:
            rule_id = self.prepare()
            for changes in ({'confirm_native_unload': False}, {'reviewed_by': 'selfsentry-auto'},
                            {'reason': ' '}, {'expected_rule_sha256': 'c' * 64}):
                assert self.post(rule_id, **changes).status_code in (409, 422)
            assert self.post(self.prepare(deployment_audit=False)).status_code == 409
        execute.assert_not_called()

    def test_success_audits_native_result_and_preserves_duplicate_review_metadata(self):
        rule_id = self.prepare()
        with patch.dict(os.environ, {'SELFSENTRY_NATIVE_RETIREMENT_ENABLED': 'true'}), \
                patch.object(nr, 'execute', side_effect=self.fake_execute):
            assert self.post(rule_id).json()['native_rule_unloaded'] is True
            with self.Session() as db:
                first_time = db.get(GeneratedRule, rule_id).reviewed_at
            assert self.post(rule_id).status_code == 200
        with self.Session() as db:
            assert db.get(GeneratedRule, rule_id).status == 'retired'
            assert db.get(GeneratedRule, rule_id).reviewed_at == first_time
            assert db.query(AuditEvent).filter(
                AuditEvent.event_type == 'RULE_NATIVE_RETIRED').count() == 1

    def test_unknown_native_outcome_keeps_pending_db_and_blocks_database_only_retirement(self):
        rule_id = self.prepare()

        def unknown(*args, **kwargs):
            args[9]({'operation_id': 'b' * 32})
            raise nr.RetirementError('ack lost')

        with patch.dict(os.environ, {'SELFSENTRY_NATIVE_RETIREMENT_ENABLED': 'true'}), \
                patch.object(nr, 'execute', side_effect=unknown):
            assert self.post(rule_id).status_code == 409
        assert self.rule_status(rule_id) == 'retirement_pending'
        response = self.client.post(f'/rules/{rule_id}/deprecate', params={'reviewed_by': 'bob'})
        assert response.status_code == 409
        with self.Session() as db:
            assert db.query(AuditEvent).filter(
                AuditEvent.event_type == 'RULE_NATIVE_RETIREMENT_BLOCKED').count() == 1

    def test_inflight_native_retirement_excludes_a_competing_review(self):
        rule_id = self.prepare()
        entered, release = threading.Event(), threading.Event()

        def blocked(*args, **kwargs):
            entered.set()
            assert release.wait(5)
            return self.fake_execute(*args, **kwargs)

        with patch.dict(os.environ, {'SELFSENTRY_NATIVE_RETIREMENT_ENABLED': 'true'}), \
                patch.object(nr, 'execute', side_effect=blocked), \
                ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.post, rule_id)
            try:
                assert entered.wait(5)
                response = self.client.post(f'/rules/{rule_id}/deprecate',
                                            params={'reviewed_by': 'bob'})
                assert response.status_code == 409
            finally:
                release.set()
            assert future.result(timeout=5).status_code == 200

    def test_actual_api_journal_file_and_recovery_round_trip_with_controlled_falco(self):
        from unittest.mock import Mock
        import yaml

        rule_id = self.prepare()
        path = self.config.parent / 'auto.yaml'
        path.write_text(RULE_YAML)
        settings = yaml.safe_load(self.config.read_text())
        settings['rules_files'].append(str(path))
        self.config.write_text(yaml.safe_dump(settings))
        client = Mock()
        value = {'instance_id': 'controlled', 'started_generation': 1,
                 'applied_generation': 1, 'rejected_generation': 0, 'ready': True}
        client.status.side_effect = lambda: value.copy()

        def reload():
            value['started_generation'] += 1
            value['applied_generation'] += 1
            return value.copy()

        client.reload.side_effect = reload
        original_hash = nr.digest(path.read_bytes())
        with patch.dict(os.environ, {'SELFSENTRY_NATIVE_RETIREMENT_ENABLED': 'true'}), \
                patch.object(rules_module.rule_deployer, 'AUTO_GENERATED_RULES_PATH', str(path)), \
                patch.object(rules_module.rule_deployer, 'FALCO_CONFIG_PATH', str(self.config)), \
                patch.object(nr, 'validate'), patch.object(nr, 'ReloadClient', return_value=client):
            plan = self.client.get(f'/rules/{rule_id}/native-retirement-plan').json()
            assert plan['current_file_sha256'] == original_hash
            first = self.post(rule_id, expected_file_sha256=original_hash)
            assert first.status_code == 200 and first.json()['native_rule_unloaded'] is True
            assert not path.read_text().strip()
            assert self.post(rule_id, expected_file_sha256=original_hash).status_code == 200
            assert client.reload.call_count == 1
            recovery = self.post(rule_id, action='rollback', reviewed_by='bob',
                                 expected_file_sha256=nr.digest(path.read_bytes()))
            assert recovery.status_code == 200
            assert recovery.json()['native_rule_unloaded'] is False
        assert path.read_text() == RULE_YAML
        with self.Session() as db:
            rule = db.get(GeneratedRule, rule_id)
            assert rule.status == 'deployed' and rule.reviewed_by == 'bob'
            rows = db.query(AuditEvent).filter(AuditEvent.event_type == 'RULE_NATIVE_RETIRED').all()
            assert len(rows) == 1 and rows[0].detail['rule_id'] == rule_id
            assert db.query(AuditEvent).filter(
                AuditEvent.event_type == 'RULE_NATIVE_RETIREMENT_ROLLED_BACK').count() == 1
