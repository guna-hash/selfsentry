"""Local host lifecycle manager. Never stops Docker, PostgreSQL, Falco or workloads."""

from __future__ import annotations

import argparse
import fcntl
import glob
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "monitor-service")]


class StartupError(RuntimeError):
    pass


def run(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise StartupError(f"Could not run {command[0]}: {type(exc).__name__}") from exc
    if result.returncode:
        raise StartupError(
            f"Prerequisite failed: {' '.join(command[:3])}. Check the service locally."
        )
    return result.stdout.strip()


def falco_settings(path):
    import yaml

    result = {}
    for filename in [str(path)] + sorted(glob.glob(str(path.parent / "config.d" / "*.yaml"))):
        try:
            data = yaml.safe_load(Path(filename).read_text()) or {}
        except (OSError, ValueError, yaml.YAMLError) as exc:
            raise StartupError(f"Cannot read Falco configuration {filename}") from exc
        if not isinstance(data, dict):
            raise StartupError(f"Invalid Falco configuration {filename}")
        result.update(data)
    return result


def check_prerequisites():
    import docker
    from sqlalchemy import create_engine, text
    from sqlalchemy.engine import make_url
    from monitor_config import load_config

    if not (ROOT / ".env").is_file():
        raise StartupError("Missing .env. Copy .env.example and configure DATABASE_URL and token.")
    cfg = load_config()
    if not os.environ.get("SELFSENTRY_API_TOKEN", "").strip():
        raise StartupError("Set SELFSENTRY_API_TOKEN in .env (required for backend reads/writes).")
    url = os.environ.get("DATABASE_URL", "")
    try:
        parsed = make_url(url)
        if parsed.get_backend_name() != "postgresql":
            raise StartupError("DATABASE_URL must use PostgreSQL for host operation.")
        # Match the backend: SQLAlchemy 2.1 otherwise defaults to undeclared psycopg 3.
        if parsed.drivername == "postgresql":
            parsed = parsed.set(drivername="postgresql+psycopg2")
        engine = create_engine(parsed, connect_args={"connect_timeout": 5})
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
        finally:
            engine.dispose()
    except StartupError:
        raise
    except Exception as exc:
        raise StartupError("PostgreSQL connection failed. Check DATABASE_URL and service.") from exc
    try:
        client = docker.from_env(timeout=5)
        try:
            client.ping()
        finally:
            client.close()
    except docker.errors.DockerException as exc:
        raise StartupError(
            "Docker unavailable. Start Docker and check socket permissions."
        ) from exc
    for tool in ("docker", "trivy", "falco", "systemctl"):
        if not shutil.which(tool):
            raise StartupError(f"Missing prerequisite: {tool}")
    run(["trivy", "--version"])
    service = os.environ.get("FALCO_SERVICE", "falco-modern-bpf")
    run(["systemctl", "is-active", "--quiet", service])
    config_path = Path(os.environ.get("FALCO_CONFIG_PATH", "/etc/falco/falco.yaml"))
    settings = falco_settings(config_path)
    output = settings.get("file_output") or {}
    if (
        settings.get("json_output") is not True
        or settings.get("rule_matching") != "all"
        or settings.get("time_format_iso_8601") is not True
        or output.get("enabled") is not True
        or Path(output.get("filename", "")).resolve() != Path(cfg.falco_log_path).resolve()
    ):
        raise StartupError(
            "Falco requires JSON, ISO timestamps, rule_matching=all and matching file_output."
        )
    rules = settings.get("rules_files", [])
    for needed in (
        ROOT / "falco-rules/baseline-capture-rules.yaml",
        ROOT / "falco-rules/auto-generated-rules.yaml",
    ):
        if not any(
            Path(item).resolve() == needed.resolve()
            or (Path(item).is_dir() and needed.parent.resolve() == Path(item).resolve())
            for item in rules
        ):
            raise StartupError(f"Falco rules_files must load {needed}")
    try:
        with open(cfg.falco_log_path) as handle:
            handle.read(0)
    except OSError as exc:
        raise StartupError(
            "Falco JSON log missing or unreadable. Check file_output and permissions."
        ) from exc
    if cfg.rule_candidates_enabled and not cfg.benign_log_path:
        raise StartupError(
            "Set MONITOR_BENIGN_LOG_PATH to your validated benign corpus for synthesis."
        )
    if cfg.benign_log_path and not Path(cfg.benign_log_path).is_file():
        raise StartupError("MONITOR_BENIGN_LOG_PATH does not exist.")
    if not (ROOT / "frontend-dashboard/dist/index.html").is_file():
        raise StartupError(
            "Dashboard build missing. Run cd frontend-dashboard && npm ci && npm run build."
        )
    for folder in (cfg.state_dir, cfg.baseline_dir, ROOT / "state/logs"):
        folder.mkdir(parents=True, exist_ok=True)
    return cfg


def identity(pid):
    """Linux start time prevents stale PID files from targeting an unrelated process."""
    try:
        value = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return None if value[0] == "Z" else value[19]
    except (OSError, IndexError):
        return None


def alive(record):
    return bool(record.get("start_time")) and identity(record["pid"]) == record["start_time"]


def load_records(path):
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise StartupError(
            "Lifecycle PID file is unreadable; inspect state/run/processes.json."
        ) from exc


def save_records(path, records):
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(records, indent=2))
    tmp.replace(path)


def stop(path):
    records = load_records(path)
    for record in reversed(list(records.values())):
        if alive(record):
            os.killpg(record["pid"], signal.SIGTERM)
    deadline = time.monotonic() + 15
    while any(alive(item) for item in records.values()) and time.monotonic() < deadline:
        time.sleep(0.1)
    if any(alive(item) for item in records.values()):
        raise StartupError("A managed process has not stopped. Inspect logs; PID records retained.")
    path.unlink(missing_ok=True)


def free_port(port):
    try:
        with socket.socket() as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", port))
    except OSError as exc:
        raise StartupError(
            f"Port {port} is already in use. Stop the existing service first."
        ) from exc


def start(path):
    records = load_records(path)
    if records and all(alive(item) for item in records.values()):
        print("SelfSentry already started. Use bin/selfsentry status.")
        return
    if any(alive(item) for item in records.values()):
        raise StartupError("Partially running stack. Use bin/selfsentry restart.")
    cfg = check_prerequisites()
    # The current dashboard default and CORS contract use these local ports.
    if cfg.backend_url not in ("http://localhost:8000", "http://127.0.0.1:8000"):
        raise StartupError("Managed startup requires SELFSENTRY_BACKEND_URL=http://127.0.0.1:8000.")
    free_port(8000)
    free_port(5173)
    commands = {
        "backend": [
            sys.executable,
            "-m",
            "uvicorn",
            "main:app",
            "--app-dir",
            "backend-api",
            "--host",
            "127.0.0.1",
            "--port",
            "8000",
        ],
        "monitor": [sys.executable, "monitor-service/monitor_service.py"],
        "frontend": [sys.executable, "ops/frontend_server.py", "frontend-dashboard/dist"],
    }
    records = {}
    try:
        for name, command in commands.items():
            with open(ROOT / f"state/logs/{name}.log", "ab") as log:
                process = subprocess.Popen(
                    command,
                    cwd=ROOT,
                    stdin=subprocess.DEVNULL,
                    stdout=log,
                    stderr=log,
                    start_new_session=True,
                )
            records[name] = {"pid": process.pid, "start_time": identity(process.pid)}
            save_records(path, records)
            deadline = time.monotonic() + 25
            while True:
                if process.poll() is not None:
                    raise StartupError(f"{name} exited; inspect state/logs/{name}.log.")
                try:
                    if name == "monitor":
                        from monitor_status import read_status

                        status = read_status(cfg.state_dir / "status.json") or {}
                        ready = status.get("pid") == process.pid and status.get("running")
                    else:
                        address = (
                            "http://127.0.0.1:8000/"
                            if name == "backend"
                            else ("http://127.0.0.1:5173/")
                        )
                        with urlopen(address, timeout=1) as response:
                            ready = response.status == 200
                    if ready:
                        if name == "backend":
                            run([sys.executable, "ops/backfill_explanations.py"])
                        break
                except OSError:
                    pass
                if time.monotonic() > deadline:
                    raise StartupError(f"{name} readiness timed out; inspect its log.")
                time.sleep(0.2)
        print("SelfSentry started. Dashboard: http://127.0.0.1:5173")
        print("Automatic isolation: " + ("ENABLED" if cfg.auto_isolation_enabled else "disabled"))
    except BaseException:
        stop(path)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("start", "stop", "status", "restart"))
    args = parser.parse_args(argv)
    os.chdir(ROOT)
    os.umask(0o077)
    from dotenv import load_dotenv

    load_dotenv(ROOT / ".env")
    state = ROOT / "state/run"
    state.mkdir(parents=True, exist_ok=True)
    with open(state / "lifecycle.lock", "a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("ERROR: another lifecycle command is in progress.", file=sys.stderr)
            return 2
        path = state / "processes.json"
        try:
            if args.action == "status":
                records = load_records(path)
                for name in ("backend", "monitor", "frontend"):
                    print(f"{name}: {'running' if alive(records.get(name, {})) else 'stopped'}")
                return 0 if len(records) == 3 and all(alive(x) for x in records.values()) else 1
            if args.action in ("stop", "restart"):
                stop(path)
                print("Managed processes stopped; container workloads and prerequisites retained.")
            if args.action in ("start", "restart"):
                start(path)
            return 0
        except Exception as exc:
            # Avoid accidentally printing DATABASE_URL or provider credentials from third parties.
            message = (
                str(exc) if isinstance(exc, (StartupError, ValueError)) else type(exc).__name__
            )
            print(f"ERROR: {message}", file=sys.stderr)
            return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ImportError as exc:
        print(
            f"ERROR: Missing Python dependency {exc.name}. Install requirements.txt in .venv.",
            file=sys.stderr,
        )
        raise SystemExit(2)
