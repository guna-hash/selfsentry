#!/usr/bin/env bash
# Temporary operator-only reload listener for acceptance; no backend opt-in or rule mutation.
set -euo pipefail
if [[ $# != 2 || ( $1 != enable && $1 != disable ) ]]; then
  echo 'Usage: sudo bash scripts/retirement_test_socket.sh enable|disable OPERATOR' >&2
  exit 2
fi
[[ $EUID == 0 ]]
mode=$1
operator=$2
[[ $operator =~ ^[a-z_][a-z0-9_-]*$ ]]
operator_group=$(id -gn "$operator")
[[ $operator_group =~ ^[a-z_][a-z0-9_-]*$ ]]
service=falco-modern-bpf.service
dropin=/run/systemd/system/$service.d/90-selfsentry-reload-test.conf
candidate=$(mktemp /run/selfsentry-socket-dropin.XXXXXX)
trap 'rm -f -- "$candidate"' EXIT
cat > "$candidate" <<UNIT
[Service]
RuntimeDirectory=selfsentry-falco-control
RuntimeDirectoryMode=0750
ExecStart=
ExecStart=/bin/sh -c '/usr/bin/chgrp $operator_group /run/selfsentry-falco-control && exec /usr/bin/falco -o engine.kind=modern_ebpf -o reload_control.enabled=true -o reload_control.socket=/run/selfsentry-falco-control/control.sock'
UNIT
if [[ $mode == disable ]]; then
  [[ -f $dropin && ! -L $dropin ]]
  cmp -s -- "$candidate" "$dropin" || {
    echo 'Refusing to remove an override with different contents.' >&2
    exit 1
  }
  rm -- "$dropin"
  systemctl daemon-reload
  systemctl restart "$service"
  echo 'Temporary override removed; original service configuration restored.'
  exit 0
fi
[[ ! -e $dropin && ! -L $dropin ]]
# Refuse to replace custom service arguments or a non-root Falco process.
python3 - <<'PY'
from pathlib import Path
import subprocess
service = 'falco-modern-bpf.service'
assert subprocess.check_output(['systemctl', 'show', '-p', 'User', '--value', service],
                               text=True).strip() in ('', 'root')
pid = int(subprocess.check_output(['systemctl', 'show', '-p', 'MainPID', '--value', service]))
assert pid > 1
args = Path(f'/proc/{pid}/cmdline').read_bytes().rstrip(b'\0').split(b'\0')
assert args == [b'/usr/bin/falco', b'-o', b'engine.kind=modern_ebpf'], \
    'Custom Falco command: manual review required'
PY
install -d -m 0755 "$(dirname "$dropin")"
install -m 0644 "$candidate" "$dropin"
rollback() {
  rm -f -- "$dropin"
  systemctl daemon-reload
  systemctl restart "$service"
  echo 'Activation failed; original service configuration restored.' >&2
}
trap rollback ERR
systemctl daemon-reload
systemctl restart "$service"
sudo -u "$operator" python3 - <<'PY'
import http.client
import json
import socket
import struct
import subprocess
import time
for attempt in range(20):
    connection = http.client.HTTPConnection('localhost', timeout=2)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(2)
        sock.connect('/run/selfsentry-falco-control/control.sock')
        peer_pid = struct.unpack('3i', sock.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))[0]
        main_pid = int(subprocess.check_output([
            'systemctl', 'show', '-p', 'MainPID', '--value', 'falco-modern-bpf.service']))
        assert peer_pid == main_pid
        connection.sock = sock
        connection.request('GET', '/reload')
        response = connection.getresponse()
        assert response.status == 200
        result = json.loads(response.read(8193))
        assert result.get('ready') is True
        print(json.dumps(result, indent=2))
        break
    except (OSError, ValueError, AssertionError, http.client.HTTPException) as exc:
        error = type(exc).__name__
        time.sleep(1)
    finally:
        connection.close()
        sock.close()
else:
    raise SystemExit('Protected listener unavailable: ' + error)
PY
trap - ERR
echo 'Temporary socket verified. Backend retirement is not enabled by this script.'
