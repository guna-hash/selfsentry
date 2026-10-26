"""Safety/lifecycle tests only; native PostgreSQL contracts require Docker execution."""

import json
from pathlib import Path
import sys
from unittest.mock import Mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'evaluation'))
import verify_database_faults as runner  # noqa: E402


@pytest.fixture
def host(monkeypatch):
    client = Mock()
    container = client.containers.create.return_value
    container.id = 'a' * 64
    container.attrs = {
        'NetworkSettings': {'Ports': {'5432/tcp': [
            {'HostIp': '127.0.0.1', 'HostPort': '54399'},
        ]}},
        'Config': {'Env': ['POSTGRES_PASSWORD=private-test-secret']},
    }
    container.image.id = 'sha256:owned-image'

    def create(*args, **kwargs):
        container.labels = kwargs['labels']
        return container

    client.containers.create.side_effect = create
    monkeypatch.setattr(runner.docker, 'from_env', Mock(return_value=client))
    monkeypatch.setattr(runner, 'create_engine', Mock(return_value=Mock()))
    monkeypatch.setattr(runner, 'wait_ready', Mock())
    monkeypatch.setattr(runner, 'choose_loopback_port', Mock(return_value=54399))
    monkeypatch.setenv('DATABASE_URL', 'sqlite://')
    import database
    monkeypatch.setattr(database, 'create_database_engine', Mock(return_value=Mock()))
    return client, container


def test_start_failure_still_removes_created_container_and_retains_private_result(
    host, monkeypatch, tmp_path, capsys,
):
    client, container = host
    container.start.side_effect = RuntimeError('private-test-secret')
    output = tmp_path / 'result.json'
    assert runner.run('postgres:18-alpine', output) == 1
    result = json.loads(output.read_text())
    assert result['passed'] is False
    assert result['cleanup'] == 'owned_container_removed'
    assert result['error_type'] == 'RuntimeError'
    container.remove.assert_called_once_with(force=True, v=True)
    client.close.assert_called_once()
    assert output.stat().st_mode & 0o777 == 0o600
    assert 'private-test-secret' not in output.read_text() + capsys.readouterr().out


def test_partial_native_checks_are_preserved_when_a_later_step_fails(host, monkeypatch, tmp_path):
    def fail(admin, app, restart, checks):
        checks['first_check'] = True
        raise RuntimeError('later step failed')

    monkeypatch.setattr(runner, 'exercise', fail)
    output = tmp_path / 'result.json'
    assert runner.run('postgres:18-alpine', output) == 1
    assert json.loads(output.read_text())['checks'] == {'first_check': True}
    host[1].remove.assert_called_once()


def test_ownership_mismatch_never_removes_or_restarts_someone_elses_container(
    host, monkeypatch, tmp_path,
):
    container = host[1]

    def change_ownership(*args):
        container.labels = {}
        raise RuntimeError('injected failure')

    monkeypatch.setattr(runner, 'exercise', change_ownership)
    output = tmp_path / 'result.json'
    assert runner.run('postgres:18-alpine', output) == 1
    result = json.loads(output.read_text())
    assert result['cleanup'] == 'manual_review_required'
    assert result['owned_container_id'] == 'a' * 64
    container.remove.assert_not_called()
    container.restart.assert_not_called()


def test_success_requires_cleanup_and_keeps_loopback_binding(host, monkeypatch, tmp_path):
    def succeed(admin, app, restart, checks):
        restart()
        checks.update({name: True for name in runner.REQUIRED_CHECKS})

    monkeypatch.setattr(runner, 'exercise', succeed)
    output = tmp_path / 'result.json'
    assert runner.run('postgres:18-alpine', output) == 0
    result = json.loads(output.read_text())
    assert result['passed'] is True
    assert result['cleanup'] == 'owned_container_removed'
    host[0].containers.create.assert_called_once()
    assert host[0].containers.create.call_args.kwargs['ports'] == {
        '5432/tcp': ('127.0.0.1', 54399),
    }
    host[1].restart.assert_called_once_with(timeout=10)


def test_existing_result_is_never_overwritten_or_followed_as_a_symlink(host, tmp_path):
    existing = tmp_path / 'result.json'
    existing.write_text('original')
    link = tmp_path / 'link.json'
    link.symlink_to(existing)
    for path in (existing, link):
        with pytest.raises(FileExistsError):
            runner.run('postgres:18-alpine', path)
    assert existing.read_text() == 'original'
    host[0].containers.create.assert_not_called()


def test_output_inside_repository_is_refused_before_docker_access(host):
    with pytest.raises(RuntimeError, match='outside the repository'):
        runner.run('postgres:18-alpine', runner.ROOT / 'state/private-result.json')
    host[0].containers.create.assert_not_called()


def test_empty_native_result_cannot_be_a_vacuous_pass(host, monkeypatch, tmp_path):
    monkeypatch.setattr(runner, 'exercise', Mock())
    output = tmp_path / 'result.json'
    assert runner.run('postgres:18-alpine', output) == 1
    assert json.loads(output.read_text())['passed'] is False


def test_lost_create_reply_retains_uncertainty_and_does_not_retry(host, tmp_path):
    client, _ = host
    client.containers.create.side_effect = TimeoutError('private-test-secret')
    output = tmp_path / 'result.json'
    assert runner.run('postgres:18-alpine', output) == 1
    result = json.loads(output.read_text())
    assert result['cleanup'] == 'creation_outcome_unknown'
    assert result['container_name'].startswith('selfsentry-db-fault-')
    client.containers.create.assert_called_once()
    client.containers.run.assert_not_called()


def test_restart_port_change_fails_before_polling_a_stale_endpoint(host, monkeypatch, tmp_path):
    def change_port(*args, **kwargs):
        host[1].attrs['NetworkSettings']['Ports']['5432/tcp'][0]['HostPort'] = '54400'

    host[1].restart.side_effect = change_port

    def exercise(admin, app, restart, checks):
        restart()

    monkeypatch.setattr(runner, 'exercise', exercise)
    output = tmp_path / 'result.json'
    assert runner.run('postgres:18-alpine', output) == 1
    result = json.loads(output.read_text())
    assert result['initial_host_port'] == 54399
    assert result['restart_host_port'] == 54400
    assert result['reason'] == 'Database restart changed the published port; stale endpoint refused'
    assert result['cleanup'] == 'owned_container_removed'


def test_failed_readiness_retains_safe_oom_state_without_environment(host, monkeypatch, tmp_path):
    host[1].attrs['State'] = {
        'Status': 'exited', 'Running': False, 'OOMKilled': True, 'ExitCode': 137,
        'Error': 'private-test-secret',
    }
    monkeypatch.setattr(runner, 'wait_ready', Mock(side_effect=runner.CheckFailed('readiness')))
    output = tmp_path / 'result.json'
    assert runner.run('postgres:18-alpine', output) == 1
    result = json.loads(output.read_text())
    assert result['container_at_failure']['OOMKilled'] is True
    assert result['container_at_failure']['ExitCode'] == 137
    assert 'private-test-secret' not in output.read_text()
    assert result['cleanup'] == 'owned_container_removed'
