"""Workloads executed inside the target container by the scheduled evaluation runner.

Attack scenarios are only those whose expected Falco rule was observed to fire in
state/evaluation/coverage.json. Each is a harmless, contained simulation. Benign
scenarios represent routine administration and workload variation; "quiet" runs nothing.
"""

SCENARIOS = {
    # --- attack (controlled simulations, one per supported category) ---
    "terminal-shell": {"label": "attack", "category": "shell", "tty": True, "command": "true"},
    "new-binary-execution": {
        "label": "attack",
        "category": "unexpected-process",
        "tty": False,
        "command": (
            'set -eu; d=$(mktemp -d /tmp/selfsentry-eval.XXXXXX); '
            'trap \'rm -rf "$d"\' EXIT; cp /bin/true "$d/validation-true"; '
            'chmod 700 "$d/validation-true"; '
            '"$d/validation-true"'
        ),
    },
    "sensitive-file-read": {
        "label": "attack",
        "category": "sensitive-file",
        "tty": False,
        "command": "cat /etc/shadow >/dev/null",
    },
    "symlink-over-sensitive-file": {
        "label": "attack",
        "category": "sensitive-file",
        "tty": False,
        "command": "ln -s /etc/shadow /tmp/eval-link; rm -f /tmp/eval-link",
    },
    "stdio-redirect-to-socket": {
        "label": "attack",
        "category": "networking",
        "tty": False,
        "command": (
            "bash -c 'exec 3<>/dev/tcp/127.0.0.1/80; "
            'exec 0<&3 1>&3 2>&3; '
            "true'"
        ),
    },
    # --- benign administration and workload variation ---
    "benign-admin": {
        "label": "benign",
        "category": "administration",
        "tty": False,
        "command": (
            'id >/dev/null; ls /usr/share/nginx/html >/dev/null; '
            'uname -s >/dev/null'
        ),
    },
    "benign-ls-from-shell": {
        "label": "benign",
        "category": "administration",
        "tty": False,
        "command": "ls /etc/nginx >/dev/null; ls /usr/share/nginx/html >/dev/null",
    },
    "benign-config-read": {
        "label": "benign",
        "category": "administration",
        "tty": False,
        "command": (
            'cat /etc/nginx/nginx.conf >/dev/null; '
            'grep -c worker /etc/nginx/nginx.conf >/dev/null'
        ),
    },
    "benign-local-http": {
        "label": "benign",
        "category": "workload",
        "tty": False,
        "command": (
            "bash -c 'exec 3<>/dev/tcp/127.0.0.1/80; "
            'printf "GET / HTTP/1.0\\r\\n\\r\\n" >&3; '
            "cat <&3 >/dev/null'"
        ),
    },
    "quiet": {"label": "benign", "category": "quiet", "tty": False, "command": None},
}

# Proposed targets: 20 attack trials per supported scenario; 100 benign windows.
DEFAULT_PLAN = (
    "terminal-shell=20,new-binary-execution=20,sensitive-file-read=20,"
    "symlink-over-sensitive-file=20,stdio-redirect-to-socket=20,"
    "quiet=40,benign-admin=20,benign-ls-from-shell=20,benign-config-read=10,benign-local-http=10"
)
