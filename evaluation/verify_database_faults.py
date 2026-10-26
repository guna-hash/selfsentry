"""Exercise PostgreSQL connection faults in one newly owned Docker container.

Never connects to DATABASE_URL or stops host services. Results cover database/driver
contracts, not monitor queue replay or real network commit-ack loss. Credentials and
database content stay private. Requires local Docker and an available PostgreSQL image.
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import socket
import sys
import time
import uuid

import docker
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL
from sqlalchemy.exc import DBAPIError, IntegrityError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend-api'))
LABEL = 'selfsentry.database-fault-check'
REQUIRED_CHECKS = {
    'utc_timestamp_with_non_utc_server',
    'established_connection_failure_and_pool_recovery',
    'committed_key_survives_duplicate_replay',
    'bounded_lock_failure_rolls_back',
    'server_restart_retains_rows_and_utc',
}


class CheckFailed(RuntimeError):
    pass


def require(value, message):
    if not value:
        raise CheckFailed(message)


def owned(container, identifier, token):
    container.reload()
    require(container.id == identifier and container.labels.get(LABEL) == token,
            'Container ownership changed; manual cleanup required')


def choose_loopback_port():
    # Docker must receive an explicit port so a restart cannot allocate another.
    # There is a short allocation race after closing this socket; Docker start
    # fails closed if another process wins. Never retry a start/create blindly.
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def published_port(container):
    bindings = container.attrs.get('NetworkSettings', {}).get('Ports', {}).get('5432/tcp')
    require(isinstance(bindings, list) and len(bindings) == 1,
            'Exactly one published database binding required')
    binding = bindings[0]
    require(binding.get('HostIp') == '127.0.0.1', 'Database exposed beyond loopback')
    port = int(binding['HostPort'])
    require(1 <= port <= 65535, 'Invalid published database port')
    return port


def diagnostics(container, identifier, token):
    owned(container, identifier, token)
    state = container.attrs.get('State') or {}
    # Do not retain Config.Env, connection errors or logs that may contain secrets.
    return {key: state.get(key) for key in (
        'Status', 'Running', 'OOMKilled', 'ExitCode', 'StartedAt', 'FinishedAt',
    )}


def wait_ready(engine, seconds=60):
    deadline = time.monotonic() + seconds
    while True:
        try:
            with engine.connect() as connection:
                connection.execute(text('SELECT 1'))
            return
        except DBAPIError:
            if time.monotonic() >= deadline:
                raise CheckFailed('Disposable database readiness deadline exceeded') from None
            time.sleep(0.5)


def count(engine, key):
    with engine.connect() as connection:
        return connection.execute(text('SELECT count(*) FROM recovery_probe WHERE key=:key'),
                                  {'key': key}).scalar_one()


def exercise(admin, app, restart, checks=None):
    checks = {} if checks is None else checks
    with admin.connect() as connection:
        require(connection.execute(text('SHOW timezone')).scalar_one() == 'Asia/Kolkata',
                'Disposable database must have a non-UTC default')
    with app.begin() as connection:
        require(connection.execute(text('SHOW timezone')).scalar_one() == 'UTC',
                'Application connection did not enforce UTC')
        connection.execute(text('CREATE TABLE recovery_probe '
                                '(key TEXT PRIMARY KEY, at TIMESTAMP DEFAULT now(), value INT)'))
        row = connection.execute(text(
            "INSERT INTO recovery_probe (key,value) VALUES ('durable',1) RETURNING at,now()"
        )).one()
        require(abs((row[0].replace(tzinfo=timezone.utc) - row[1]).total_seconds()) < 0.01,
                'Implicit timestamp default did not record UTC')
    checks['utc_timestamp_with_non_utc_server'] = True
    # An established connection is terminated before commit. The transaction must
    # disappear; a new checkout must recover without replaying the failed mutation.
    with app.connect() as connection:
        transaction = connection.begin()
        connection.execute(text("INSERT INTO recovery_probe (key,value) VALUES ('uncommitted',2)"))
        pid = connection.execute(text('SELECT pg_backend_pid()')).scalar_one()
        with admin.begin() as killer:
            require(killer.execute(text('SELECT pg_terminate_backend(:pid)'),
                                   {'pid': pid}).scalar_one(), 'Could not terminate owned session')
        try:
            transaction.commit()
        except DBAPIError:
            pass
        else:
            raise CheckFailed('Terminated transaction unexpectedly acknowledged commit')
    require(count(app, 'uncommitted') == 0, 'Terminated transaction left a row')
    require(count(app, 'durable') == 1, 'Durable row lost after connection failure')
    checks['established_connection_failure_and_pool_recovery'] = True
    # Model client uncertainty only AFTER a genuine successful commit. This is a
    # controlled fault boundary, not a claim that a TCP acknowledgement was lost.
    with app.begin() as connection:
        connection.execute(text("INSERT INTO recovery_probe (key,value) VALUES ('ack-boundary',3)"))
    try:
        with app.begin() as connection:
            connection.execute(text(
                "INSERT INTO recovery_probe (key,value) VALUES ('ack-boundary',3)"
            ))
    except IntegrityError:
        pass
    else:
        raise CheckFailed('Uniqueness did not reject duplicate replay')
    require(count(app, 'ack-boundary') == 1, 'Commit-boundary duplicate or loss')
    checks['committed_key_survives_duplicate_replay'] = True
    with app.connect() as blocker:
        blocked = blocker.begin()
        blocker.execute(text("SELECT * FROM recovery_probe WHERE key='durable' FOR UPDATE"))
        try:
            started = time.monotonic()
            try:
                with app.begin() as contender:
                    contender.execute(text("SET LOCAL lock_timeout = '500ms'"))
                    contender.execute(text("UPDATE recovery_probe SET value=9 WHERE key='durable'"))
            except DBAPIError as exc:
                require(getattr(exc.orig, 'pgcode', None) == '55P03',
                        'Unexpected lock failure classification')
            else:
                raise CheckFailed('Contended row unexpectedly updated')
            require(time.monotonic() - started < 10, 'Lock wait exceeded acceptance bound')
        finally:
            blocked.rollback()
    checks['bounded_lock_failure_rolls_back'] = True
    # Leave an idle pooled connection across a real restart to exercise pre_ping.
    restart()
    admin.dispose()
    wait_ready(admin)
    require(count(app, 'durable') == count(app, 'ack-boundary') == 1,
            'Committed rows missing after restart')
    with app.connect() as connection:
        require(connection.execute(text('SHOW timezone')).scalar_one() == 'UTC',
                'Reconnected application session lost UTC policy')
        require(connection.execute(text(
            "SELECT value FROM recovery_probe WHERE key='durable'"
        )).scalar_one() == 1, 'Failed lock contender changed committed state')
    checks['server_restart_retains_rows_and_utc'] = True
    return checks


def run(image, output):
    output = output.expanduser().resolve()
    require(not output.is_relative_to(ROOT), 'Store private native results outside the repository')
    fd = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    report = {'started_at': datetime.now(timezone.utc).isoformat(), 'passed': False,
              'checks': {}, 'image': image, 'cleanup': 'not_started',
              'limits': ['Disposable PostgreSQL/driver contracts only',
                         'No application outage, pending-monitor replay or isolation acceptance',
                         'No real network commit-ack loss injection']}
    client = container = admin = app = None
    identifier, token = '', uuid.uuid4().hex
    code = 1
    try:
        client = docker.from_env(timeout=120)
        try:
            client.images.get(image)
        except docker.errors.ImageNotFound:
            client.images.pull(image)
        port = choose_loopback_port()
        report['requested_host_port'] = port
        report['creation_attempted'] = True
        report['container_name'] = 'selfsentry-db-fault-' + token[:12]
        container = client.containers.create(
            image, ['postgres', '-c', 'timezone=Asia/Kolkata'],
            name='selfsentry-db-fault-' + token[:12], labels={LABEL: token},
            environment={'POSTGRES_PASSWORD': secrets.token_urlsafe(32),
                         'POSTGRES_DB': 'selfsentry_disposable'},
            ports={'5432/tcp': ('127.0.0.1', port)},
            mem_limit='512m', nano_cpus=1_000_000_000, pids_limit=128,
        )
        identifier = container.id
        owned(container, identifier, token)
        container.start()
        container.reload()
        report['initial_host_port'] = published_port(container)
        require(report['initial_host_port'] == port, 'Initial database binding differs')
        # Read only our own generated secret from this newly created container.
        password = next(value.split('=', 1)[1] for value in container.attrs['Config']['Env']
                        if value.startswith('POSTGRES_PASSWORD='))
        url = URL.create('postgresql+psycopg2', username='postgres', password=password,
                         host='127.0.0.1', port=port,
                         database='selfsentry_disposable')
        admin = create_engine(url, pool_pre_ping=True, connect_args={'connect_timeout': 2})
        wait_ready(admin)
        # Import after installing an explicitly disposable URL. No production .env is used.
        os.environ['DATABASE_URL'] = url.render_as_string(hide_password=False)
        from database import create_database_engine, engine as initial_engine
        initial_engine.dispose()
        app = create_database_engine(url.render_as_string(hide_password=False))

        def restart():
            owned(container, identifier, token)
            report['restart_attempted'] = True
            container.restart(timeout=10)
            owned(container, identifier, token)
            report['restart_host_port'] = published_port(container)
            require(report['restart_host_port'] == port,
                    'Database restart changed the published port; stale endpoint refused')
            report['container_after_restart'] = diagnostics(container, identifier, token)

        report['image_id'] = container.image.id
        exercise(admin, app, restart, report['checks'])
        report['passed'] = (set(report['checks']) == REQUIRED_CHECKS
                            and all(report['checks'].values()))
    except Exception as exc:
        # Driver/Docker errors may embed credentials, environment or full commands.
        report['error_type'] = type(exc).__name__
        if isinstance(exc, CheckFailed):
            report['reason'] = str(exc)
        if container is not None:
            try:
                report['container_at_failure'] = diagnostics(container, identifier, token)
            except Exception:
                report['container_at_failure'] = 'unavailable_or_ownership_changed'
    finally:
        for engine in (app, admin):
            if engine is not None:
                engine.dispose()
        if container is not None:
            try:
                owned(container, identifier, token)
                container.remove(force=True, v=True)
                report['cleanup'] = 'owned_container_removed'
            except Exception:
                report.update(passed=False, cleanup='manual_review_required',
                              owned_container_id=identifier)
        elif report.get('creation_attempted'):
            # A lost create response is ambiguous: do not claim cleanup or retry
            # the action. Retain the generated name for explicit inspection.
            report['cleanup'] = 'creation_outcome_unknown'
        if client is not None:
            client.close()
        code = 0 if report['passed'] else 1
        with os.fdopen(fd, 'w') as stream:
            json.dump(report, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
    print(json.dumps(report, indent=2))
    print('Evidence:', output)
    return code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', default='postgres:18-alpine')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    return run(args.image, args.output)


if __name__ == '__main__':
    raise SystemExit(main())
