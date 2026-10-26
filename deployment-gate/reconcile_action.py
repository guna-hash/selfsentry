"""Explicit gate reconciliation: observe current Docker state, retain original intent.

No Docker mutation, deployment registration, retry or automatic health clearance.
The operator accepts a current observation, never invents the past CLI outcome.
"""

import argparse
from contextlib import closing, contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "monitor-service"))
import deployment_outbox as outbox  # noqa: E402

TABLES = {'action': 'deployment_actions', 'creation': 'creation_attempts'}


def _encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _hash(value):
    return hashlib.sha256(_encode(value).encode()).hexdigest()


def _read(db, kind, key):
    if kind not in TABLES or re.fullmatch(r'[0-9a-f]{32}', key) is None:
        raise ValueError('A valid attempt kind and full key are required')
    db.row_factory = sqlite3.Row
    row = db.execute('SELECT * FROM ' + TABLES[kind] + ' WHERE key=?', (key,)).fetchone()
    if row is None:
        raise ValueError('Attempt not found')
    item = dict(row)
    cid = item.get('container_id')
    if not isinstance(cid, str) or re.fullmatch(r'[0-9a-f]{64}', cid) is None:
        raise ValueError(
            'Known full container identity required; unknown creation remains unresolved')
    if item['outcome'] not in ('outcome_not_recorded', 'command_failed'):
        raise ValueError('Only unfinished or failed attempts require this reconciliation')
    return item


def _docker(*args):
    try:
        result = subprocess.run(['docker', *args], capture_output=True, text=True,
                                timeout=10, check=True)
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError('Docker observation unavailable; no decision recorded') from exc
    return result.stdout.strip()


def observe(cid):
    """Use a successful complete daemon inventory for absence, never stderr matching."""
    daemon = json.loads(_docker('info', '--format', '{{json .ID}}'))
    if not isinstance(daemon, str) or not daemon:
        raise ValueError('Docker daemon identity unavailable')
    ids = _docker('container', 'ls', '--all', '--no-trunc', '--format', '{{.ID}}').splitlines()
    if any(re.fullmatch(r'[0-9a-f]{64}', item) is None for item in ids):
        raise ValueError('Incomplete Docker inventory identity')
    observation = {'daemon_id': daemon, 'container_id': cid, 'present': cid in ids}
    if cid in ids:
        data = json.loads(_docker('container', 'inspect', '--format', '{{json .}}', cid))
        state = data.get('State', {})
        fields = ('Running', 'Paused', 'Restarting', 'Dead')
        if data.get('Id') != cid or any(type(state.get(k)) is not bool for k in fields):
            raise ValueError('Docker identity/state cannot be verified')
        observation['state'] = {k: state[k] for k in ('Running', 'Paused', 'Restarting', 'Dead')}
        observation['image_id'] = data.get('Image')
    if json.loads(_docker('info', '--format', '{{json .ID}}')) != daemon:
        raise ValueError('Docker daemon changed during observation')
    observation['observed_at'] = datetime.now(timezone.utc).isoformat()
    return observation


def plan(kind, key):
    path = Path(os.environ.get('SELFSENTRY_STATE_DIR', outbox.ROOT / 'state'))
    path = (path / 'deployments.sqlite').resolve()
    with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=1)) as db:
        item = _read(db, kind, key)
    return {'kind': kind, 'key': key, 'original_sha256': _hash(item),
            'container_id': item['container_id'], 'original_outcome': item['outcome'],
            'observation': observe(item['container_id']),
            'scope': 'current state only; original outcome remains unknown/failed'}


@contextmanager
def _exclusive_attempt(key):
    path = outbox._ownership_path(key)
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError('Attempt still has an owner, even if its deadline expired') from exc
        yield
    finally:
        os.close(fd)  # Never unlink ownership evidence, including abandoned lock files.


def reconcile(kind, key, expected_hash, reviewed_by, reason):
    if (not isinstance(reviewed_by, str) or not reviewed_by.strip()
            or reviewed_by.strip().lower() == 'selfsentry-auto' or len(reviewed_by) > 128):
        raise ValueError('An explicit human reviewer is required')
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 2000:
        raise ValueError('A concise operator reason is required')
    if not isinstance(key, str) or re.fullmatch(r'[0-9a-f]{32}', key) is None:
        raise ValueError('Invalid attempt key')
    with _exclusive_attempt(key):
        # Re-read and capture evidence while excluding the command owner. Expiry is irrelevant.
        proposal = plan(kind, key)
        if proposal['original_sha256'] != expected_hash:
            raise ValueError('Original evidence changed; inspect again')
        record = {**proposal, 'reviewed_by': reviewed_by.strip(), 'reason': reason.strip(),
                  'event_type': 'GATE_ACTION_RECONCILED',
                  'decision': 'accepted_current_observation',
                  'reviewed_at': datetime.now(timezone.utc).isoformat()}
        with closing(outbox.connect()) as db, db:
            db.execute('BEGIN IMMEDIATE')
            item = _read(db, kind, key)
            if _hash(item) != expected_hash:
                raise ValueError('Attempt changed during observation')
            db.execute('''CREATE TABLE IF NOT EXISTS action_reconciliations (
                kind TEXT NOT NULL, key TEXT NOT NULL, body TEXT NOT NULL,
                PRIMARY KEY(kind,key))''')
            previous = db.execute('SELECT body FROM action_reconciliations WHERE kind=? AND key=?',
                                  (kind, key)).fetchone()
            if previous:
                raise ValueError('A decision already exists; retain and review the original')
            db.execute('INSERT INTO action_reconciliations VALUES (?,?,?)',
                       (kind, key, _encode(record)))
        return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kind', required=True, choices=TABLES)
    parser.add_argument('--key', required=True)
    parser.add_argument('--apply-original-sha256')
    parser.add_argument('--reviewed-by')
    parser.add_argument('--reason')
    args = parser.parse_args()
    try:
        if args.apply_original_sha256:
            record = reconcile(args.kind, args.key, args.apply_original_sha256,
                               args.reviewed_by, args.reason)
        else:
            record = plan(args.kind, args.key)
    except (ValueError, RuntimeError, OSError, sqlite3.Error):
        parser.exit(1, 'Reconciliation refused; original evidence retained.\n')
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    main()
