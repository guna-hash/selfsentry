# Fresh Ubuntu host installation

This is the manual procedure verified on 28 October 2026, not an unattended
installer or a restore procedure. Use a newly installed host and fresh credentials;
do not copy another host's .env, database, baselines, checkpoints or recovery state.
For existing data, use the backup/adoption procedure in [operations](monitor_operations.md#schema-migrations-and-adoption).

## Verified environment

Ubuntu 24.04.4 LTS, kernel 7.0.0-42-generic, Python 3.12.3, PostgreSQL 16,
Docker 29.9.2, Falco 0.45.1 (modern eBPF; container plugin 0.7.5), Trivy 0.76.1,
Node 24.21.0 and npm 11.19.0. These are observed versions, not compatibility
promises for every kernel, package update or distribution. See the
[clean-install record](repository-audit/clean-install-20261028.md) for results.

## Host tools and checkout

Install basic build tools first:

```bash
sudo apt-get update
sudo apt-get install -y git python3-venv python3-dev build-essential libpq-dev \
  curl ca-certificates unzip gnupg postgresql-16 postgresql-client-16
```

Install Docker Engine using its [official Ubuntu APT repository](https://docs.docker.com/engine/install/ubuntu/).
Install Falco from its [official DEB repository](https://falco.org/docs/setup/packages/),
selecting `FALCO_DRIVER_CHOICE=modern_ebpf`. The verified installation used
`FALCO_FRONTEND=noninteractive FALCOCTL_ENABLED=no` to avoid dialog prompts and
keep automatic rules updates disabled during acceptance. It did not need the
kernel-module build dependencies. Install Trivy from its
[official APT repository](https://www.trivy.dev/docs/latest/getting-started/installation/)
using the `generic` distribution. Do not add multiple conflicting repositories.
Record the installed versions; stop and inspect failed package transactions.

```bash
sudo systemctl enable --now docker postgresql falco-modern-bpf
sudo docker run --rm hello-world
sudo usermod -aG docker "$USER"
```

Docker group membership grants root-equivalent host capability. Sign out and back
in after adding it. `newgrp docker` activates it in a new shell if a full logout
is inconvenient. A terminal opened before the group change may still be denied
access even though `getent group docker` lists the account.

```bash
id -nG
docker info --format 'Docker server {{.ServerVersion}}'
git clone https://github.com/guna-hash/selfsentry.git
cd selfsentry
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip==26.2.1
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python -m pip check
```

Use nvm's [official installer](https://github.com/nvm-sh/nvm#installing-and-updating).
The verified nvm installer version was v0.40.8. Load it in the current shell, then:

```bash
export NVM_DIR="$HOME/.nvm"
. "$NVM_DIR/nvm.sh"
nvm install 24.21.0
nvm alias default 24.21.0
nvm use 24.21.0
(cd frontend-dashboard && npm ci && npm run build)
```

Do not run npm, pip or the application as root. A large chart-chunk warning was
observed in the passing build; a successful build is not a capacity measurement.

## New private configuration and database

Only use the following on a fresh host where `.env`, role `selfsentry` and database
`selfsentry_db` do not already exist. It records generated credentials privately
before creating the database, so a failed SQL operation does not lose the password.
A failure can leave a role or .env behind: inspect it rather than rerunning or
replacing it. No existing role/database is dropped or altered by this procedure.

```bash
sudo -v
.venv/bin/python - <<'PY'
import os, re, secrets, subprocess
from pathlib import Path
os.umask(0o077)
p = Path('.env')
assert not p.exists(), '.env exists; inspect rather than overwrite it'
password = secrets.token_hex(32)
settings = {
    'DATABASE_URL': f'postgresql+psycopg2://selfsentry:{password}@127.0.0.1:5432/selfsentry_db',
    'SELFSENTRY_API_TOKEN': secrets.token_urlsafe(32),
    'AUTO_ISOLATION_ENABLED': 'false',
    'AUTO_CONFIRM_ENABLED': 'false',
    'MONITOR_RULE_CANDIDATES_ENABLED': 'false',
    'SELFSENTRY_NATIVE_RETIREMENT_ENABLED': 'false',
    'MONITOR_ANOMALY_ALGORITHM': 'isolation_forest',
}
text = Path('.env.example').read_text()
for key, value in settings.items():
    pattern = rf'(?m)^{re.escape(key)}=.*$'
    text = re.sub(pattern, lambda _: f'{key}={value}', text) if re.search(pattern, text) else text.rstrip()+f'\n{key}={value}\n'
with p.open('x') as stream:
    stream.write(text)
p.chmod(0o600)
sql = f"CREATE ROLE selfsentry LOGIN PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE;\nCREATE DATABASE selfsentry_db OWNER selfsentry;\n"
r = subprocess.run(['sudo','-n','-u','postgres','psql','-X','-v','ON_ERROR_STOP=1','-d','postgres'], input=sql, text=True, capture_output=True)
if r.returncode:
    raise SystemExit('Database creation failed; private .env retained. Inspect before retry.')
print('Fresh database and private configuration created; credentials not displayed.')
PY
```

Proceed only if creation succeeded:

```bash
.venv/bin/python -m alembic -c alembic.ini upgrade head
.venv/bin/python scripts/verify_schema.py
```

Do not run migrations before DATABASE_URL is configured. Schema comparison must
report a match; it does not prove row correctness, grants or backup quality.
Keep .env out of Git and never paste credentials or access tokens into reports.

## Falco configuration and permissions

The fresh installation used `/etc/falco/config.d/zz-selfsentry.yaml` with the
following contents. Replace `/home/test/selfsentry` with the actual absolute
checkout path. Create this file only if it is not already an operator configuration.

```yaml
json_output: true
time_format_iso_8601: true
rule_matching: all
file_output:
  enabled: true
  keep_alive: false
  filename: /var/log/falco/alerts.json
rules_files:
  - /home/test/selfsentry/falco-rules/baseline-capture-rules.yaml
  - /home/test/selfsentry/falco-rules/auto-generated-rules.yaml
```

Falco appends this list to the base configuration's default rule files. Do not
repeat `/etc/falco/falco_rules.yaml` and `falco_rules.local.yaml` in this override;
that loaded the defaults twice during the initial trial. Inspect actual dry-run
output, rather than assuming a schema-valid file has the intended merged order.
Repository generated-rule definitions are shipped history, not newly reviewed
rules approved for the fresh database. Loading them does not establish a new rule loop.

The verified Ubuntu account was already in `adm`. Give only the intended account
read access to the log; do not make it world-writable. On that setup:

```bash
sudo install -d -o root -g adm -m 0750 /var/log/falco
sudo touch /var/log/falco/alerts.json
sudo chown root:adm /var/log/falco/alerts.json
sudo chmod 0640 /var/log/falco/alerts.json
sudo falco --dry-run -o engine.kind=modern_ebpf
```

If validation fails, restore/remove only the newly introduced override and inspect
it before restarting. After successful validation:

```bash
sudo systemctl restart falco-modern-bpf
systemctl is-active falco-modern-bpf
.venv/bin/python - <<'PY'
from pathlib import Path
from dotenv import set_key
p = Path('.env')
assert p.is_file(), 'Create private configuration first'
for key, value in {
    'FALCO_LOG_PATH': '/var/log/falco/alerts.json',
    'FALCO_CONFIG_PATH': '/etc/falco/falco.yaml',
    'FALCO_SERVICE': 'falco-modern-bpf',
}.items():
    set_key(str(p), key, value)
p.chmod(0o600)
with open('/var/log/falco/alerts.json') as stream:
    stream.read(0)
print('Falco log readable; paths configured.')
PY
```

The package's container plugin must support the local Docker socket. Check startup
logs if container identities are missing. Noninteractive rule reload permissions
and native retirement sockets are separate opt-in setup; this installation does
not grant broad sudo privileges or enable native retirement.

## Start and verify

```bash
bash bin/selfsentry start
bash bin/selfsentry status
.venv/bin/python scripts/verify_final_checks.py
.venv/bin/python scripts/verify_schema.py
git diff --check
```

Open `http://127.0.0.1:5173` on the VM. Verify Overview/Monitor rendering, healthy
status, isolation disabled and an authenticated audit event visible. Use the local
write token only in the intended UI/session or authenticated API client, not chat.

Confirm fresh native container events using a bounded owned probe. Compare event
and receipt timestamps from the probe, not just the status heartbeat. Inspect
monitor counters, window processing and delivery queues; remove only the owned
probe. The recorded clean-install probe produced 148 native events with maximum
lag 0.1333 s; later counters showed 154 events and two windows. Those are historical
observations, not expected exact counts or evidence that future runs passed.

Zero ready models and a null event-time observation can be expected before any
workload activity. Model readiness takes new valid learning windows; do not copy
another host's baseline or bypass readiness merely to change the indicator.
A warning can indicate replay, delay or clock skew. Fresh guarded probes are
needed after restart/resume; restarting Falco is a temporary recovery, not a
permanent clock repair. See [acceptance review](repository-audit/acceptance-review-20261028.md).

## Evidence boundary

Retain initial OS/tool state, actual versions, dependency/build logs, source commit,
migration/schema results, Falco validation, owned probe identities/cleanup and
operator browser results in a private evidence directory outside Git. The record
covers one manual supported-host setup, not reboot recovery, representative model
quality, zero loss, every native action on the new host or production readiness.
