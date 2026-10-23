"""Human-requested Falco 0.45 retirement with durable intent and explicit rollback.

Call under the existing rule review lock. The permanent inventory guard serializes
file/reload work with deployment; its duplicate history is never erased.
"""

from contextlib import closing
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import stat
import subprocess
import tempfile
import time
import uuid

from rule_deduplicator import (definitions, guard, load_inventory, _runtime_arguments,
                               _verify_runtime, InventoryError)


class RetirementError(RuntimeError):
    """Retained state requires review; never infer that native mutation failed."""


class ReloadRejected(RetirementError):
    """Falco explicitly rejected a generation newer than the request baseline."""


def digest(content):
    return hashlib.sha256(content).hexdigest()


def _replace(path, content, mode=0o600):
    fd, name = tempfile.mkstemp(prefix='.selfsentry-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


class ReloadClient:
    """Protected Unix-socket HTTP, bounded reads; never retries a POST."""

    def __init__(self, path='/run/falco/control.sock', timeout=20):
        self.path, self.timeout = path, timeout

    def request(self, method):
        connection = http.client.HTTPConnection('localhost', timeout=2)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(2)
            sock.connect(self.path)
            # SO_PEERCRED binds the observation to the configured running service PID.
            import struct
            peer_pid, _uid, _gid = struct.unpack('3i', sock.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
            args = _runtime_arguments()
            # Runtime arguments alone do not identify a socket peer. Check MainPID too.
            from rule_deployer import FALCO_SERVICE_NAME
            pid = subprocess.check_output(
                ['systemctl', 'show', '--property=MainPID', '--value', FALCO_SERVICE_NAME],
                text=True, timeout=3).strip()
            if not args or peer_pid != int(pid):
                raise RetirementError('Reload socket peer differs from the running Falco service')
            connection.sock = sock
            connection.request(method, '/reload', body=None, headers={'Connection': 'close'})
            response = connection.getresponse()
            data = response.read(8193)
            if len(data) > 8192 or response.status != (202 if method == 'POST' else 200):
                raise RetirementError('Reload response unavailable or invalid')
            result = json.loads(data)
            _status(result, brief=method == 'POST')
            return result
        except (OSError, ValueError, http.client.HTTPException, subprocess.SubprocessError) as exc:
            raise RetirementError(
                'Reload transport outcome unavailable; inspect retained intent') from exc
        finally:
            connection.close()
            sock.close()

    def status(self):
        return self.request('GET')

    def reload(self):
        baseline = self.request('POST')  # A lost response is never blindly retried.
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            try:
                value = self.status()
            except RetirementError:
                time.sleep(0.1)  # Observation only; the listener is recreated during reload.
                continue
            if value['instance_id'] != baseline['instance_id']:
                raise RetirementError(
                    'Falco process changed; reload outcome requires reconciliation')
            if value['rejected_generation'] > baseline['started_generation']:
                raise ReloadRejected('Falco rejected the requested reload generation')
            if (value['ready'] and value['applied_generation'] > max(
                    baseline['started_generation'], value['rejected_generation'])):
                return value
            time.sleep(0.1)
        raise RetirementError('Reload completion deadline exceeded; outcome remains unknown')


def _status(value, brief=False):
    if not isinstance(value, dict) or not isinstance(value.get('instance_id'), str):
        raise RetirementError('Invalid Falco reload identity')
    if not value['instance_id']:
        raise RetirementError('Missing Falco reload identity')
    fields = ('started_generation',) if brief else (
        'started_generation', 'applied_generation', 'rejected_generation')
    if any(type(value.get(key)) is not int or value[key] < 0 for key in fields):
        raise RetirementError('Invalid Falco reload generation')
    if not brief and (type(value.get('ready')) is not bool or any(
            value[key] > value['started_generation'] for key in fields[1:])):
        raise RetirementError('Inconsistent Falco reload status')


def _paths(config):
    paths: list[Path] = []
    rows = load_inventory(config, files=paths)
    return rows, paths


def prepare(rule_yaml, path, config):
    if path.is_symlink() or not path.is_file():
        raise RetirementError('Existing regular generated-rules file required')
    if path.stat().st_nlink != 1:
        raise RetirementError('Hard-linked rule files require operator review')
    _verify_runtime(config)
    original = path.read_bytes()
    own = definitions(rule_yaml)
    current = definitions(original.decode())
    if len(own) != 1 or not isinstance(own[0].get('rule'), str):
        raise RetirementError('Retirement requires exactly one owned rule')
    name = own[0]['rule']
    matches = [row for row in current if row.get('rule') == name]
    if len(matches) != 1 or matches[0] != own[0]:
        raise RetirementError('Rule is missing, changed or duplicated; no removal permitted')
    rows, paths = _paths(config)
    if sum(p.resolve() == path.resolve() for p in paths) != 1:
        raise RetirementError('Generated file must occur exactly once in the runtime inventory')
    if sum(row.get('rule') == name for row in rows) != 1:
        raise RetirementError('Native rule name has additional definitions/overrides')
    # Remove only the selected sequence section; retain the complete original for recovery.
    import yaml
    nodes = yaml.compose(original.decode()).value
    index = next(i for i, row in enumerate(current) if row.get('rule') == name)
    lines = original.splitlines(keepends=True)
    start = nodes[index].start_mark.line
    end = nodes[index + 1].start_mark.line if index + 1 < len(nodes) else len(lines)
    candidate = b''.join(lines[:start] + lines[end:])
    expected = current[:index] + current[index + 1:]
    if definitions(candidate.decode()) != expected:
        raise RetirementError('Rule section cannot be removed without changing other definitions')
    return {'original': original, 'candidate': candidate, 'paths': paths, 'name': name,
            'original_sha256': digest(original), 'candidate_sha256': digest(candidate),
            'rule_sha256': digest(rule_yaml.encode()), 'inventory': rows}


def validate(plan, path, config):
    # Falco -V consumes ordered rule files together, so default macros/plugins are retained.
    with tempfile.TemporaryDirectory(prefix='selfsentry-rule-validation-') as folder:
        candidate = Path(folder) / 'candidate.yaml'
        candidate.write_bytes(plan['candidate'])
        command = [_runtime_arguments()[0], '-c', str(config)]
        for item in plan['paths']:
            command.extend(['-V', str(candidate if item.resolve() == path.resolve() else item)])
        try:
            result = subprocess.run(command, capture_output=True, timeout=20)
            plan['validation_output'] = result.stdout + b'\n' + result.stderr
        except (OSError, subprocess.SubprocessError) as exc:
            plan['validation_output'] = type(exc).__name__.encode()
            raise RetirementError('Native prevalidation unavailable; no live file changed') from exc
        if result.returncode:
            raise RetirementError('Native prevalidation rejected candidate; no live file changed')


class RetirementJournal:
    def __init__(self, directory):
        self.directory = Path(directory)
        if self.directory.is_symlink():
            raise RetirementError('Retirement directory cannot be a symlink')
        self.directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        if self.directory.stat().st_mode & 0o077:
            raise RetirementError('Retirement directory must be private (0700)')

    def connect(self):
        path = self.directory / 'retirements.sqlite'
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        db = sqlite3.connect(path, timeout=1)
        try:
            db.execute('PRAGMA synchronous=FULL')
            db.execute('CREATE TABLE IF NOT EXISTS retirements('
                       'rule_id TEXT PRIMARY KEY, body TEXT)')
            db.execute('CREATE TABLE IF NOT EXISTS history(id INTEGER PRIMARY KEY, body TEXT)')
        except BaseException:
            db.close()
            raise
        return db

    def get(self, rule_id):
        with closing(self.connect()) as db:
            row = db.execute('SELECT body FROM retirements WHERE rule_id=?',
                             (str(rule_id),)).fetchone()
        if row is None:
            return None
        value = json.loads(row[0])
        if (not isinstance(value, dict) or value.get('rule_id') != str(rule_id)
                or value.get('phase') not in {
                    'prepared', 'validation_failed', 'publication_pending', 'published',
                    'applied', 'rollback_requested', 'rollback_pending', 'rolled_back'}
                or value.get('previous_db_status') not in ('deployed', 'retired')
                or any(not isinstance(value.get(key), str)
                       or re.fullmatch(r'[a-f0-9]{64}', value[key]) is None for key in (
                           'original_sha256', 'candidate_sha256', 'rule_sha256'))):
            raise RetirementError('Retained retirement receipt is invalid; no repair performed')
        return value

    def save(self, record, phase, **changes):
        value = {**record, **changes, 'phase': phase,
                 'recorded_at': datetime.now(timezone.utc).isoformat()}
        body = json.dumps(value, sort_keys=True, allow_nan=False)
        with closing(self.connect()) as db, db:
            db.execute('INSERT OR REPLACE INTO retirements VALUES (?,?)',
                       (str(value['rule_id']), body))
            db.execute('INSERT INTO history(body) VALUES (?)', (body,))
        record.clear()
        record.update(value)

    def backup(self, operation, original, suffix='original'):
        if re.fullmatch(r'[a-f0-9]{32}', operation) is None or suffix not in (
                'original', 'validation'):
            raise RetirementError('Invalid retirement artifact identity')
        path = self.directory / (operation + '.' + suffix)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(original)
            stream.flush()
            os.fsync(stream.fileno())
        directory = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def _human(actor, reason):
    if (not isinstance(actor, str) or not actor.strip() or len(actor) > 128
            or actor.strip().lower() == 'selfsentry-auto' or not isinstance(reason, str)
            or not reason.strip() or len(reason) > 2000):
        raise RetirementError('An explicit human reviewer and reason are required')


def execute(rule_id, rule_yaml, expected_file_hash, actor, reason, journal, client,
            path, config, intent, complete, *, rollback=False, previous_status="deployed"):
    """Callbacks persist DB intent/result. Caller owns per-rule review serialization.

    Any uncertain outcome remains pending. Only explicit rollback can resume an
    interrupted attempt; a completed receipt can finish the DB write without reload.
    """
    _human(actor, reason)
    path, config = Path(path), Path(config)
    try:
        with guard(str(config)) as registry:
            previous = journal.get(rule_id)
            if previous and previous['rule_sha256'] != digest(rule_yaml.encode()):
                raise RetirementError('Database rule differs from retained native intent')
            if previous is None and previous_status == 'retirement_pending':
                raise RetirementError('Pending database state has no retained native intent')
            if rollback:
                if digest(path.read_bytes()) != expected_file_hash:
                    raise RetirementError("Recovery file changed since operator review")
                return _rollback(previous, rule_id, journal, client, path, actor, reason,
                                 complete, config, intent=intent)
            if previous and previous['phase'] == 'applied':
                if (expected_file_hash not in (previous['original_sha256'],
                                               previous['candidate_sha256'])
                        or previous['rule_sha256'] != digest(rule_yaml.encode())
                        or digest(path.read_bytes()) != previous['candidate_sha256']):
                    raise RetirementError(
                        'Completed retirement receipt differs from current source')
                live = client.status()
                _status(live)
                receipt = previous['reload_status']
                if (not live['ready'] or live['instance_id'] != receipt['instance_id']
                        or live['applied_generation'] != receipt['applied_generation']
                        or live['started_generation'] != receipt['started_generation']
                        or live['rejected_generation'] != receipt['rejected_generation']
                        or live['applied_generation'] <= live['rejected_generation']):
                    raise RetirementError('Completed receipt cannot attest this Falco instance')
                if any(row.get('rule') == previous['native_rule_name']
                       for row in load_inventory(str(config))):
                    raise RetirementError('Retired rule name is present in the current inventory')
                complete(previous, True)
                return previous
            if previous and previous['phase'] not in ('rolled_back', 'validation_failed'):
                raise RetirementError(
                    'Unfinished retirement requires explicit rollback/reconciliation')
            plan = prepare(rule_yaml, path, config)
            if plan['original_sha256'] != expected_file_hash:
                raise RetirementError('Rule file changed since operator review')
            before = client.status()
            _status(before)
            if not before['ready']:
                raise RetirementError('Falco must be ready before native retirement')
            record = {'rule_id': str(rule_id), 'operation_id': uuid.uuid4().hex,
                      'previous_db_status': previous_status,
                      'reviewed_by': actor.strip(), 'reason': reason.strip(),
                      'original_sha256': plan['original_sha256'],
                      'candidate_sha256': plan['candidate_sha256'],
                      'rule_sha256': plan['rule_sha256'], 'native_rule_name': plan['name']}
            journal.backup(record['operation_id'], plan['original'])
            journal.save(record, 'prepared')
            try:
                validate(plan, path, config)
            except RetirementError:
                journal.save(record, 'validation_failed')
                raise
            finally:
                if 'validation_output' in plan:
                    journal.backup(record['operation_id'], plan['validation_output'], 'validation')
            registry.revalidate()
            if path.read_bytes() != plan['original']:
                raise RetirementError('Generated rules changed during prevalidation')
            intent(record)  # Must return after durable DB approval/audit, before any live write.
            journal.save(record, 'publication_pending')
            mode = stat.S_IMODE(path.stat().st_mode)
            _replace(path, plan['candidate'], mode)
            journal.save(record, 'published')
            try:
                status = client.reload()
            except ReloadRejected:
                # A known rejection permits corrective rollback; unknown outcomes do not.
                _rollback(record, rule_id, journal, client, path, actor, reason, complete, config)
                raise
            if (path.is_symlink() or digest(path.read_bytes()) != plan['candidate_sha256']
                    or any(row.get('rule') == plan['name']
                           for row in load_inventory(str(config)))):
                raise RetirementError('Post-reload inventory changed; outcome needs reconciliation')
            journal.save(record, 'applied', reload_status=status)
            complete(record, True)
            return record
    except (InventoryError, OSError, ValueError, sqlite3.Error) as exc:
        raise RetirementError(
            'Native retirement unavailable; preserve intent and inspect state') from exc


def _rollback(record, rule_id, journal, client, path, actor, reason, complete, config, intent=None):
    if not record or record.get('rule_id') != str(rule_id):
        raise RetirementError('No matching original retirement intent')
    operation = record.get('operation_id', '')
    if re.fullmatch(r'[a-f0-9]{32}', operation) is None:
        raise RetirementError('Invalid retained retirement identity')
    if path.is_symlink() or path.stat().st_nlink != 1:
        raise RetirementError('Generated file identity changed; refuse recovery')
    original_path = journal.directory / (operation + '.original')
    if original_path.is_symlink():
        raise RetirementError('Original backup identity changed')
    original = original_path.read_bytes()
    if digest(original) != record['original_sha256'] or digest(path.read_bytes()) not in (
            record['original_sha256'], record['candidate_sha256']):
        raise RetirementError('Original/current rules differ; refuse overwriting unrelated changes')
    rows, paths = _paths(config)
    if sum(p.resolve() == path.resolve() for p in paths) != 1:
        raise RetirementError('Recovery target is no longer uniquely loaded by Falco')
    expected_names = 1 if digest(path.read_bytes()) == record['original_sha256'] else 0
    if sum(row.get('rule') == record['native_rule_name'] for row in rows) != expected_names:
        raise RetirementError('Recovery would conflict with a changed native rule inventory')
    recovery_plan = {'candidate': original, 'paths': paths}
    artifact = uuid.uuid4().hex
    reviewed_file_hash = digest(path.read_bytes())
    try:
        validate(recovery_plan, path, config)
    except RetirementError:
        journal.save(record, record['phase'], recovery_validation_failed=True,
                     recovery_validation_artifact=artifact + '.validation')
        raise
    finally:
        if 'validation_output' in recovery_plan:
            journal.backup(artifact, recovery_plan['validation_output'], 'validation')
    if load_inventory(str(config)) != rows or digest(path.read_bytes()) != reviewed_file_hash:
        raise RetirementError('Inventory changed during recovery validation')
    journal.save(record, 'rollback_requested', recovery_reviewed_by=actor.strip(),
                 recovery_reason=reason.strip(),
                 recovery_validation_artifact=artifact + '.validation')
    if intent is not None:
        intent({**record, 'requested_action': 'rollback'})
    journal.save(record, 'rollback_pending')
    _replace(path, original, stat.S_IMODE(path.stat().st_mode))
    status = client.reload()
    if path.is_symlink() or path.read_bytes() != original:
        raise RetirementError('Post-recovery file changed; retain the pending recovery')
    journal.save(record, 'rolled_back', reload_status=status)
    complete(record, False)
    return record
