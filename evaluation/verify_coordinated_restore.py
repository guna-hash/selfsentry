"""Capture quiescent durable state and verify recovery using disposable copies.

An explicitly approved managed-app pause is required. Docker, Falco, PostgreSQL and
container workloads are never stopped. Original databases/state are never restored into.
This is same-host component recovery, not a fresh-host or live failover acceptance.
"""
import argparse
from contextlib import ExitStack, closing, contextmanager
from dataclasses import replace
from datetime import datetime, timezone
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
from types import SimpleNamespace
from typing import Any
import uuid

from dotenv import load_dotenv
from sqlalchemy import text

from coordinated_state import (capture_log, check_checkpoint_on_copy, check_copy,
                               check_source, copy_tree, regular_files, require, sha)
from postgres_support import IDENTITY, pg_environment, target_url, monitor_status
from verify_postgres_acceptance import fingerprints


def resume_managed(root, safe_env, report, folder, status_getter=monitor_status):
    # Recovery must not depend on writable evidence storage (e.g. disk-full failures).
    result = subprocess.run(['bash', str(root / 'bin/selfsentry'), 'start'],
                            env=safe_env, cwd=root, timeout=90,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        (folder / 'resume-managed-app.log').write_bytes(result.stdout)
    except OSError:
        report['errors'].append('Resume log could not be saved; inspect original app status')
    require(result.returncode == 0, 'Original app start failed; manual recovery required')
    for _ in range(30):
        try:
            current = status_getter()
            if current.get('healthy') is True:
                report['checks']['original_app_healthy_after_capture'] = True
                return
        except Exception:
            pass
        time.sleep(1)
    raise RuntimeError('Original application did not report healthy after capture')


@contextmanager
def held_lock(path):
    require(path.is_file() and not path.is_symlink(), 'Existing regular ownership lock required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def rebuild_models(config, monitor, baseline, ready_ids):
    from behavior_pipeline import BehaviorPipeline
    captured = []
    audit = SimpleNamespace(emit=lambda **record: captured.append(record))
    pipeline = BehaviorPipeline(replace(config, state_dir=monitor, baseline_dir=baseline),
                                SimpleNamespace(), audit)
    try:
        result = {}
        for identifier in ready_ids:
            pipeline.discover(identifier)
            require(pipeline.lifecycle[identifier]['state'] == 'MODEL_READY',
                    'A previously ready model could not be rebuilt from restored baseline')
            result[identifier] = {'state': 'MODEL_READY',
                                  'samples': pipeline.lifecycle[identifier]['samples']}
        return result
    finally:
        pipeline.db.close()


def run(root, output_root, approve_pause):
    require(approve_pause is True, 'Explicit managed-app pause approval required')
    root, output_root = root.resolve(), output_root.resolve()
    require(not output_root.is_relative_to(root),
            'Private restore output must be outside Git checkout')
    load_dotenv(root / '.env')
    sys.path[:0] = [str(root / 'backend-api'), str(root / 'monitor-service'),
                    str(root / 'behavioral-engine'), str(root / 'scripts'),
                    str(root / 'rule-synthesis-engine')]
    from database import Base, engine, create_database_engine
    import models.db_models  # noqa: F401
    from monitor_config import load_config
    from rule_deduplicator import load_inventory, _verify_runtime
    spec = importlib.util.spec_from_file_location(
        'restore_lifecycle', root / 'ops/selfsentry_cli.py')
    if spec is None or spec.loader is None:
        raise RuntimeError('Lifecycle source unavailable')
    lifecycle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lifecycle)
    config = load_config()
    require(config.anomaly_algorithm == 'isolation_forest',
            'This restore acceptance preserves the reviewed default Isolation Forest')
    before = monitor_status()
    require(before.get('healthy') is True and before.get('configuration', {}).get(
        'auto_isolation_enabled') is False, 'Healthy monitor with isolation disabled required')
    ready = [cid for cid, item in before.get('baselines', {}).items()
             if item.get('state') == 'MODEL_READY']
    algorithms_match = all(before['baselines'][cid].get('model_algorithm') ==
                           config.anomaly_algorithm for cid in ready)
    require(ready and algorithms_match,
            'Ready source models using the configured default algorithm are required')
    processes_path = root / 'state/run/processes.json'
    processes = lifecycle.load_records(processes_path)
    require(set(processes) == {'backend', 'monitor', 'frontend'} and all(
        lifecycle.alive(record) for record in processes.values()) and
        before.get('pid') == processes['monitor']['pid'], 'All services must be managed')
    url = engine.url
    require(engine.dialect.name == 'postgresql' and url.host in ('localhost', '127.0.0.1', '::1')
            and url.username and url.database, 'Explicit local PostgreSQL role/database required')
    tools = {name: shutil.which(name) for name in
             ('sudo', 'psql', 'createdb', 'dropdb', 'pg_dump', 'pg_restore', 'falco')}
    require(all(tools.values()), 'Required PostgreSQL/Falco tools missing')
    state_root = Path(os.environ.get('SELFSENTRY_STATE_DIR', str(root / 'state')))
    guard_root = Path(os.environ.get('RULE_GUARD_STATE_DIR', str(root / 'state/rule-guard')))
    sources = {'monitor': config.state_dir, 'baselines': config.baseline_dir,
               'rule_guard': guard_root, 'rules': root / 'falco-rules'}
    for directory in sources.values():
        require(not output_root.is_relative_to(directory.resolve()), 'Output overlaps live state')
        regular_files(directory)
    require((state_root / 'deployments.sqlite').is_file(), 'Deployment journal required')
    config_path = Path(os.environ.get('FALCO_CONFIG_PATH', '/etc/falco/falco.yaml'))
    _verify_runtime(config_path)
    rule_files: list[Path] = []
    load_inventory(config_path, files=rule_files)
    require(rule_files, 'Ordered Falco rule inventory required')
    log_path = Path(config.falco_log_path)
    # WAL pages may merge into the main DB at shutdown; budget both before pausing.
    source_bytes = sum(p.stat().st_size for d in sources.values()
                       for p in d.rglob('*') if p.is_file())
    source_bytes += log_path.stat().st_size
    source_bytes += sum(p.stat().st_size for p in rule_files)
    source_bytes += sum(p.stat().st_size for p in state_root.glob('deployments.sqlite*')
                        if p.is_file())
    with engine.connect() as connection:
        connection.execute(text('SET TRANSACTION READ ONLY'))
        identity = connection.execute(text(IDENTITY)).scalar_one()
        version = int(connection.execute(text('SHOW server_version_num')).scalar_one()) // 10000
        database_bytes = connection.execute(
            text('SELECT pg_database_size(current_database())')).scalar_one()
    free = shutil.disk_usage(output_root if output_root.exists() else output_root.parent).free
    require(free > max(1024**3, 4 * source_bytes + 3 * database_bytes),
            'Insufficient private backup space')
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    folder = output_root / ('coordinated-restore-' + stamp)
    folder.mkdir(parents=True, mode=0o700)
    os.umask(0o077)
    captured_root = folder / 'capture'
    captured_root.mkdir(mode=0o700)
    report: dict[str, Any] = {
        'passed': False, 'checks': {}, 'errors': [], 'cleanup': {},
        'scope': 'quiescent capture and same-host disposable component recovery',
        'limits': ['No fresh-host/native workload failover claim',
                   'No pending-work recovery claim when source queues are empty',
                   'No automatic restore into original paths or database'],
        'commands': [], 'source_commit': subprocess.check_output(
            ['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()}
    report['runner_sources'] = {name: sha(Path(__file__).parent / name) for name in
                                ('verify_coordinated_restore.py', 'coordinated_state.py')}
    report['source_status'] = subprocess.check_output(
        ['git', '-C', str(root), 'status', '--short'], text=True).strip()
    manifest: dict[str, Any] = {'groups': {}}
    records = {}
    source_deployments = state_root / 'deployments.sqlite'
    owned = set()
    restored_engine = None
    stop_attempted = False
    started_again = False
    output = folder / 'results.json'
    admin = [tools['sudo'], '-n', '-u', 'postgres']
    admin_connection = ['--no-password', '--host=/var/run/postgresql',
                        '--port=' + str(url.port or 5432)]
    admin_env = {key: value for key, value in os.environ.items() if not key.startswith('PG')}
    safe_env = dict(os.environ, AUTO_ISOLATION_ENABLED='false',
                    SELFSENTRY_NATIVE_RETIREMENT_ENABLED='false')

    def save():
        output.write_text(json.dumps(report, indent=2) + '\n')

    def command(argv, label, *, env=None, timeout=120, cwd=None):
        report['commands'].append({'label': label})
        save()
        try:
            result = subprocess.run(argv, env=env, cwd=cwd, timeout=timeout,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        except subprocess.TimeoutExpired as exc:
            (folder / (label + '.log')).write_bytes(exc.stdout or b'')
            raise RuntimeError(label + ' timed out; no retry') from None
        (folder / (label + '.log')).write_bytes(result.stdout)
        require(result.returncode == 0, label + ' failed; retained private log')
        return result.stdout.decode().strip()

    def resume():
        nonlocal started_again
        resume_managed(root, safe_env, report, folder)
        started_again = True

    try:
        for tool in ('pg_dump', 'pg_restore'):
            client = command([tools[tool], '--version'], tool + '-version', timeout=10)
            require(re.search(r'PostgreSQL\) ' + str(version) + r'\.', client),
                    'Client/server PostgreSQL major versions differ')
        cluster = command([*admin, tools['psql'], *admin_connection, '--no-psqlrc',
                           '--tuples-only', '--no-align', '--dbname=' + str(url.database),
                           '--command=' + IDENTITY], 'cluster-identity', env=admin_env, cwd='/tmp')
        require(json.loads(cluster) == identity, 'Administrator socket identifies another cluster')
        print('Pausing managed application for coordinated private capture...', flush=True)
        stop_attempted = True
        pause_started = time.monotonic()
        command(['bash', str(root / 'bin/selfsentry'), 'stop'], 'pause-managed-app',
                env=safe_env, timeout=45, cwd=root)
        require(not any(lifecycle.alive(record) for record in processes.values()),
                'A managed source process is still alive')
        with ExitStack() as locks:
            for path in (root / 'state/run/lifecycle.lock', config.state_dir / 'monitor.lock',
                         guard_root / 'guard.lock'):
                locks.enter_context(held_lock(path))
            # Existing ownership files cannot be treated as idle merely because a deadline expired.
            lease_dir = state_root / 'deployment-action-locks'
            for path in sorted(lease_dir.glob('*.lock')):
                locks.enter_context(held_lock(path))
            lease_names = {p.name for p in lease_dir.glob('*.lock')}
            required_bytes = sum(p.stat().st_size for d in sources.values()
                                 for p in regular_files(d)) + log_path.stat().st_size
            require(shutil.disk_usage(folder).free >
                    max(1024**3, 4 * required_bytes + 3 * database_bytes),
                    'Free-space budget changed before capture')
            snapshot_engine = engine.execution_options(isolation_level='REPEATABLE READ')
            with snapshot_engine.connect() as connection:
                with connection.begin():
                    connection.execute(text('SET TRANSACTION READ ONLY'))
                    connection.execute(text("SET LOCAL statement_timeout = '60s'"))
                    snapshot = connection.execute(text('SELECT pg_export_snapshot()')).scalar_one()
                    expected = fingerprints(connection)
                    expected_sequences = sequence_state(connection)
                    command([tools['pg_dump'], '--no-password', '--format=custom',
                             '--snapshot=' + snapshot, '--lock-wait-timeout=5s',
                             '--file=' + str(captured_root / 'database.dump')], 'pg-dump',
                            env=pg_environment(url, url.database), timeout=120)
            for name, directory in sources.items():
                records[name] = copy_tree(directory, captured_root / name)
            # Capture the deployment journal through the same held SQLite readback path.
            from coordinated_state import sqlite_snapshot
            deployment_fp = sqlite_snapshot(
                source_deployments, captured_root / 'deployments.sqlite')
            manifest['deployment_sha256'] = sha(captured_root / 'deployments.sqlite')
            manifest['falco_log'] = capture_log(
                log_path, captured_root / 'falco-alerts.json',
                captured_root / 'monitor/falco_checkpoint.json')
            native = captured_root / 'native-rules'
            native.mkdir(mode=0o700)
            manifest['native_rules'] = []
            for index, path in enumerate(rule_files):
                dest = native / f'{index:04d}.yaml'
                before_hash = sha(path)
                shutil.copyfile(path, dest)
                os.chmod(dest, 0o600)
                require(sha(dest) == before_hash == sha(path), 'Native rule inventory changed')
                manifest['native_rules'].append({'file': dest.name, 'sha256': before_hash})
            require(rule_files == _inventory(config_path), 'Native rule-file membership changed')
            for name, directory in sources.items():
                check_source(directory, records[name])
            from export_monitor_journal import readonly, fingerprint
            with closing(readonly(source_deployments, time.monotonic() + 90)) as db:
                require(fingerprint(db) == deployment_fp,
                        'Deployment journal changed across capture')
            with engine.connect() as connection:
                connection.execute(text('SET TRANSACTION READ ONLY'))
                require(fingerprints(connection) == expected and
                        sequence_state(connection) == expected_sequences,
                        'Source PostgreSQL changed while paused')
            require(lease_names == {p.name for p in lease_dir.glob('*.lock')},
                    'Concurrent deployment action appeared during capture')
            manifest['groups'] = records
            manifest['database_sha256'] = sha(captured_root / 'database.dump')
            manifest['database_rows'] = expected
            manifest['database_sequences'] = expected_sequences
            manifest['monitor_settings'] = {key: getattr(config, key) for key in (
                'window_seconds', 'learning_seconds', 'min_samples', 'anomaly_algorithm')}
            for path, item in zip(rule_files, manifest['native_rules']):
                require(sha(path) == item['sha256'], 'Source native rules changed during capture')
            (folder / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
            report['checks']['coordinated_source_stability'] = True
        report['capture_pause_seconds'] = round(time.monotonic() - pause_started, 3)
        resume()
        print('Original application resumed. Verifying disposable restore...', flush=True)
        restored = folder / 'restored'
        shutil.copytree(captured_root, restored)
        for name in sources:
            check_copy(restored / name, records[name])
        require(sha(restored / 'database.dump') == manifest['database_sha256'],
                'Dump checksum changed')
        require(sha(restored / 'deployments.sqlite') == manifest['deployment_sha256'],
                'Deployment copy checksum changed')
        require(sha(restored / 'falco-alerts.json') == manifest['falco_log']['sha256'],
                'Copied Falco log checksum changed')
        report['checks']['all_captured_artifacts_match'] = True
        name = 'ss_accept_' + uuid.uuid4().hex[:12] + '_restore'
        command([*admin, tools['createdb'], *admin_connection, '--template=template0',
                 '--owner=' + str(url.username), name], 'create-owned-restore',
                env=admin_env, cwd='/tmp')
        owned.add(name)
        target = target_url(url, name, owned)
        command([tools['pg_restore'], '--no-password', '--exit-on-error', '--no-owner',
                 '--no-privileges', '--dbname=' + name, str(restored / 'database.dump')],
                'pg-restore', env=pg_environment(url, name))
        restored_engine = create_database_engine(target)
        from verify_schema import schema_differences
        with restored_engine.connect() as connection:
            connection.execute(text('SET TRANSACTION READ ONLY'))
            require(fingerprints(connection) == expected and not schema_differences(
                connection, Base.metadata), 'Restored PostgreSQL rows/schema differ')
            require(sequence_state(connection) == expected_sequences,
                    'Restored PostgreSQL sequence state differs')
        report['checks']['postgres_rows_and_schema_match'] = True
        report['checks']['postgres_sequences_match'] = True
        native_args = [tools['falco'], '-c', str(config_path)]
        for item in manifest['native_rules']:
            rule_path = restored / 'native-rules' / item['file']
            require(sha(rule_path) == item['sha256'], 'Native rule copy changed')
            native_args.extend(['-V', str(rule_path)])
        command(native_args, 'copied-native-rule-validation', timeout=30)
        report['checks']['copied_native_rules_validate'] = True
        from journal_archive import event_rows
        with closing(sqlite3.connect(restored / 'monitor/pipeline.sqlite')) as db:
            containers = db.execute(
                'SELECT container FROM events UNION SELECT container FROM archived_events'
            ).fetchall()
            for (identifier,) in containers:
                event_rows(db, identifier, -(2**62), 2**62)
        report['checks']['restored_journal_archives_readable'] = True
        report['checkpoint_readback'] = check_checkpoint_on_copy(
            restored / 'falco-alerts.json', restored / 'monitor/falco_checkpoint.json')
        report['checks']['restored_checkpoint_reopens'] = True
        report['rebuilt_models'] = rebuild_models(config, restored / 'monitor',
                                                  restored / 'baselines', ready)
        report['checks']['ready_models_rebuilt_from_copied_baselines'] = True
        # Working copies intentionally changed during replay/model cold-start. The private
        # recovery inputs must remain byte-for-byte intact for another operator-reviewed restore.
        for group in sources:
            check_copy(captured_root / group, records[group])
        require(sha(captured_root / 'database.dump') == manifest['database_sha256'],
                'Original captured dump changed during disposable restore')
        require(sha(captured_root / 'falco-alerts.json') == manifest['falco_log']['sha256'],
                'Original captured log changed during disposable restore')
        report['checks']['private_capture_unchanged_after_restore'] = True
    except Exception as exc:
        # Third-party driver/subprocess errors can embed credentials. Preserve type only.
        report['errors'].append(str(exc) if type(exc) is RuntimeError else type(exc).__name__)
    finally:
        if stop_attempted and not started_again:
            try:
                resume()
            except Exception as exc:
                report['errors'].append(
                    'Original app requires manual recovery: ' + type(exc).__name__)
        if restored_engine is not None:
            restored_engine.dispose()
        for name in owned:
            try:
                target_url(url, name, owned)
                command([*admin, tools['dropdb'], *admin_connection, name],
                        'cleanup-owned-restore', env=admin_env, cwd='/tmp')
                report['cleanup'][name] = 'removed'
            except Exception as exc:
                report['cleanup'][name] = 'needs_manual_review'
                report['errors'].append(
                    'Owned database cleanup requires review: ' + type(exc).__name__)
        try:
            current = monitor_status()
            report['checks']['original_app_healthy_after_restore'] = current.get('healthy') is True
        except Exception:
            report['checks']['original_app_healthy_after_restore'] = False
        engine.dispose()
        report['passed'] = acceptance_passed(report)
        try:
            save()
        except OSError:
            report['passed'] = False
            report['errors'].append('Result file could not be saved; private work needs review')
        summary = {key: report[key] for key in ('passed', 'checks', 'errors', 'cleanup')}
        print(json.dumps(summary, indent=2))
        print('Evidence:', output)
        print('Private work directory retained:', folder)
    return 0 if report['passed'] else 1


REQUIRED_CHECKS = {
    'coordinated_source_stability', 'original_app_healthy_after_capture',
    'all_captured_artifacts_match', 'postgres_rows_and_schema_match',
    'postgres_sequences_match', 'copied_native_rules_validate',
    'restored_journal_archives_readable', 'restored_checkpoint_reopens',
    'ready_models_rebuilt_from_copied_baselines', 'private_capture_unchanged_after_restore',
    'original_app_healthy_after_restore',
}


def acceptance_passed(report):
    return not report['errors'] and all(
        report['checks'].get(key) is True for key in REQUIRED_CHECKS)


def sequence_state(connection):
    quote = connection.dialect.identifier_preparer.quote
    names = connection.execute(text(
        "SELECT sequencename FROM pg_sequences WHERE schemaname='public' ORDER BY sequencename"
    )).scalars().all()
    return {name: list(connection.execute(text(
        f"SELECT last_value,is_called FROM {quote('public')}.{quote(name)}"
    )).one()) for name in names}


def _inventory(config_path):
    from rule_deduplicator import load_inventory
    files: list[Path] = []
    load_inventory(config_path, files=files)
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, default=Path.home() / 'selfsentry')
    parser.add_argument('--output-root', type=Path,
                        default=Path.home() / 'selfsentry-recovery-checks')
    parser.add_argument('--approve-managed-pause', action='store_true')
    args = parser.parse_args()
    return run(args.repo.expanduser(), args.output_root.expanduser(), args.approve_managed_pause)


if __name__ == '__main__':
    def interrupted(_signum, _frame):
        raise RuntimeError('Interrupted; retaining evidence and attempting original-app resume')

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        raise SystemExit(main())
    except Exception as exc:
        message = str(exc) if type(exc) is RuntimeError else type(exc).__name__
        print('Stopped before completion:', message)
        raise SystemExit(1)
