"""Check process identity and container cleanup boundaries without Docker access."""

import json
import subprocess

import pytest

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "evaluation"))
import measure_workload as measure  # noqa: E402


def stat_line(state="S"):
    fields = [state] + ["0"] * 51
    fields[1] = "12"
    fields[11], fields[12] = "100", "20"
    fields[19], fields[21] = "54321", "16"
    return "42 (name with ) parentheses) " + " ".join(fields)


def test_linux_stat_parse_handles_parentheses_and_correct_field_offsets():
    assert measure.parse_stat(stat_line(), 4096) == {
        "ppid": 12, "ticks": 120, "start": "54321", "rss_bytes": 65536,
    }
    assert measure.parse_stat(stat_line("Z"), 4096) is None


def entry(parent, start, ticks=10, rss=2**20):
    return {"ppid": parent, "start": start, "ticks": ticks, "rss_bytes": rss}


def test_frontend_descendants_are_counted_but_unrelated_processes_are_excluded():
    current = {1: entry(0, "1"), 2: entry(1, "2"), 3: entry(2, "3"), 4: entry(0, "4")}
    metrics = measure.tree_metrics({"frontend": {"pid": 1, "start_time": "1"}},
                                   current, current, 1, 100)["frontend"]
    assert metrics["process_count"] == 3 and metrics["rss_mib"] == 3


def test_root_pid_reuse_stops_measurement():
    with pytest.raises(measure.CheckFailed, match="identity changed"):
        measure.tree_metrics({"monitor": {"pid": 1, "start_time": "old"}},
                             {1: entry(0, "new")}, {}, 1, 100)


def test_reused_child_pid_does_not_create_a_false_cpu_spike():
    previous = {1: entry(0, "root", 100), 2: entry(1, "old-child", 1)}
    current = {1: entry(0, "root", 150), 2: entry(1, "new-child", 10000)}
    metric = measure.tree_metrics({"monitor": {"pid": 1, "start_time": "root"}},
                                  current, previous, 1, 100)["monitor"]
    assert metric["cpu_percent_one_core"] == 50


def test_parallel_cpu_can_exceed_one_hundred_percent_and_phase_start_is_unknown():
    roots = {"monitor": {"pid": 1, "start_time": "same"}}
    current, previous = {1: entry(0, "same", 350)}, {1: entry(0, "same", 100)}
    assert measure.tree_metrics(roots, current, previous, 1, 100)["monitor"][
        "cpu_percent_one_core"] == 250
    assert measure.tree_metrics(roots, current, previous, 0, 100)["monitor"][
        "cpu_percent_one_core"] is None


def test_cleanup_uses_verified_immutable_id(monkeypatch):
    identifier = "a" * 64
    spec = {"Name": "/probe", "Id": identifier,
            "Config": {"Labels": {measure.LABEL: "owned-token"}}}
    calls = []

    def docker(args, **kwargs):
        calls.append(args)
        if args == ["container", "inspect", "probe"]:
            return json.dumps([spec])
        return None

    monkeypatch.setattr(measure, "docker", docker)
    assert measure.cleanup("probe", "owned-token") == "removed"
    assert calls[1] == ["rm", "--force", identifier]
    assert calls[2] == ["container", "inspect", identifier]


@pytest.mark.parametrize("field,value", [
    ("Name", "/different"), ("Id", "short-id"),
    ("Config", {"Labels": {measure.LABEL: "someone-else"}}),
])
def test_cleanup_refuses_unowned_or_ambiguous_container(monkeypatch, field, value):
    spec = {"Name": "/probe", "Id": "a" * 64,
            "Config": {"Labels": {measure.LABEL: "owned-token"}}}
    spec[field] = value
    calls = []

    def docker(args, **kwargs):
        calls.append(args)
        return json.dumps([spec])

    monkeypatch.setattr(measure, "docker", docker)
    with pytest.raises(measure.CheckFailed, match="ownership"):
        measure.cleanup("probe", "owned-token")
    assert len(calls) == 1


def test_missing_probe_is_not_recreated_or_removed(monkeypatch):
    calls = []

    def docker(args, **kwargs):
        calls.append(args)
        return None

    monkeypatch.setattr(measure, "docker", docker)
    assert measure.cleanup("probe", "token") == "already absent"
    assert len(calls) == 1


def test_daemon_error_is_not_treated_as_confirmed_absence(monkeypatch):
    monkeypatch.setattr(measure.subprocess, "run", lambda *args, **kwargs:
                        subprocess.CompletedProcess(args[0], 1, "", "Cannot connect to daemon"))
    with pytest.raises(measure.CheckFailed):
        measure.docker(["container", "inspect", "probe"], missing_ok=True)


def test_percentiles_preserve_unknown_values_and_do_not_invent_zeros():
    assert measure.distribution([None]) is None
    assert measure.distribution(list(range(1, 101))) == {
        "median": 50, "p95": 95, "maximum": 100,
    }


def test_queue_summary_preserves_unavailable_depth_and_observed_backlog():
    samples = [
        {"phase": "workload", "status": {"healthy": True, "audit_spool_size": None}},
        {"phase": "workload", "status": {"healthy": True, "incident_outbox_size": 3}},
    ]
    queues = measure.summarize(samples, [])["phases"]["workload"]["queue_maxima"]
    assert queues["audit_spool_size"] is None and queues["incident_outbox_size"] == 3


def test_posix_generator_runs_external_commands_and_reports_exact_progress():
    completed = subprocess.run(["/bin/sh", "-c", measure.generator_script(3, 0.001)],
                               capture_output=True, text=True, timeout=5, check=True)
    assert measure.progress_output(completed.stdout, count=3, require_done=True) == [
        {"index": 0, "reported_ordinal": 1},
        {"index": 1, "reported_ordinal": 2},
        {"index": 2, "reported_ordinal": 3},
    ]


@pytest.mark.parametrize("output", [
    "SELFSENTRY_WORKLOAD_STEP 2\n",
    "SELFSENTRY_WORKLOAD_STEP 1\nSELFSENTRY_WORKLOAD_STEP 1\n",
    "SELFSENTRY_WORKLOAD_DONE 200\n",
    "unexpected output\n",
])
def test_generator_output_rejects_missing_duplicate_or_fabricated_progress(output):
    with pytest.raises(measure.CheckFailed):
        measure.progress_output(output)


@pytest.mark.parametrize("count,pause", [
    (True, 0.2), (201, 0.2), ("1;touch /tmp/unwanted", 0.2),
    (1, "0.2;echo unwanted"), (1, float("nan")),
])
def test_generator_does_not_interpolate_untrusted_shell_values(count, pause):
    with pytest.raises(measure.CheckFailed):
        measure.generator_script(count, pause)


def test_generator_timeout_retains_completed_steps_without_retry(monkeypatch):
    calls = []

    def timeout(argv, **kwargs):
        calls.append((argv, kwargs))
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"], output=(
            b"SELFSENTRY_WORKLOAD_STEP 1\nSELFSENTRY_WORKLOAD_STEP 2\nSELFSENTRY_WORKLOAD_ST"))

    monkeypatch.setattr(measure.subprocess, "run", timeout)
    report = {"execs": []}
    with pytest.raises(measure.CheckFailed, match="unchanged 75-second deadline"):
        measure.execute_generator("a" * 64, report)
    assert len(calls) == 1 and calls[0][1]["timeout"] == 75
    assert len(report["execs"]) == 2 and report["truncated_progress_line"] is True


def test_nonzero_generator_exit_never_counts_as_success(monkeypatch):
    monkeypatch.setattr(measure.subprocess, "run", lambda argv, **kwargs:
                        subprocess.CompletedProcess(argv, 1, "SELFSENTRY_WORKLOAD_STEP 1\n", ""))
    report = {}
    with pytest.raises(measure.CheckFailed, match="generator failed"):
        measure.execute_generator("a" * 64, report)
    assert report["generator_returncode"] == 1 and len(report["execs"]) == 1


def test_one_docker_call_must_prove_all_200_steps_and_completion(monkeypatch):
    output = "".join(f"SELFSENTRY_WORKLOAD_STEP {i}\n" for i in range(1, 201))
    output += "SELFSENTRY_WORKLOAD_DONE 200\n"
    calls = []

    def execute(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, output, "")

    monkeypatch.setattr(measure.subprocess, "run", execute)
    report = {}
    measure.execute_generator("a" * 64, report)
    assert len(calls) == 1 and calls[0][0][:3] == ["docker", "exec", "a" * 64]
    assert len(report["execs"]) == 200 and report["generator_returncode"] == 0
