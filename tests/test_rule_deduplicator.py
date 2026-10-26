"""Guard comparisons use real YAML, macros, history, and isolated filesystem state."""

import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "rule-synthesis-engine"))
from rule_deduplicator import (  # noqa: E402
    check,
    definitions,
    guard,
    InventoryError,
    DuplicateRule,
)  # noqa: E402
from tests.rule_guard_support import inventory  # noqa: E402


def rule(condition, name="New", **extra):
    return yaml.safe_dump([{"rule": name, "condition": condition, **extra}])


def collector_rows(kind):
    shipped = (
        Path(__file__).resolve().parents[1] / "falco-rules/baseline-capture-rules.yaml"
    )
    collector = next(
        row for row in definitions(shipped.read_text()) if row["rule"] == kind
    )
    return [
        {"macro": "container", "condition": "container.id != host"},
        {"macro": "spawned_process", "condition": "evt.type in (execve, execveat)"},
        {
            "macro": "open_write",
            "condition": "evt.type in (open, openat) and evt.arg.flags contains O_WRONLY",
        },
        collector,
    ]


@pytest.mark.parametrize(
    "kind,condition",
    [
        (
            "Baseline File Write",
            'open_write and container and proc.name="sh" and fd.name="/tmp/eval"',
        ),
        (
            "Baseline Process Spawn",
            'spawned_process and container and proc.name="uname" and proc.pname="sh"',
        ),
    ],
)
def test_literal_security_refinement_of_shipped_collector_is_allowed(kind, condition):
    assert check(rule(condition), collector_rows(kind))


@pytest.mark.parametrize("kind", ["Baseline File Write", "Baseline Process Spawn"])
def test_collector_exact_equivalence_and_name_collisions_still_rejected(kind):
    rows = collector_rows(kind)
    with pytest.raises(DuplicateRule, match="Exact match"):
        check(rule(rows[-1]["condition"]), rows)
    with pytest.raises(DuplicateRule, match="Rule name already exists"):
        check(rule('proc.name="unique"', name=kind), rows)


@pytest.mark.parametrize(
    "mutation", ["name", "priority", "tags", "output", "condition", "description"]
)
def test_modified_or_spoofed_collector_does_not_get_refinement_exception(mutation):
    rows = collector_rows("Baseline File Write")
    row = rows[-1]
    if mutation == "name":
        row["rule"] = "A real security rule"
    elif mutation == "priority":
        row["priority"] = "WARNING"
    elif mutation == "tags":
        row["tags"] = ["baseline", "security"]
    elif mutation == "output":
        row["output"] = "Security detection"
    elif mutation == "condition":
        row["condition"] += " and evt.arg.flags contains O_RDWR"
    else:
        row["desc"] = "Security rule using a collector name"
    with pytest.raises(DuplicateRule):
        check(
            rule('open_write and container and proc.name="sh" and fd.name="/tmp/eval"'),
            rows,
        )


@pytest.mark.parametrize(
    "condition",
    [
        'open_write and container and proc.name="sh"',
        'open_write and container and fd.name="/tmp/eval"',
        'open_write and container and proc.name="sh" and fd.name startswith "/tmp/"',
        '(open_write and container and proc.name="sh" and fd.name="/tmp/eval") or user.uid=0',
        'open_write and (container or user.uid=0) and proc.name="sh" and fd.name="/tmp/eval"',
    ],
)
def test_incomplete_broad_or_non_implying_collector_refinement_stays_blocked(condition):
    with pytest.raises(DuplicateRule):
        check(rule(condition), collector_rows("Baseline File Write"))


def test_collector_exception_does_not_skip_later_security_rule():
    rows = collector_rows("Baseline File Write")
    condition = 'open_write and container and proc.name="sh" and fd.name="/tmp/eval"'
    rows += definitions(rule(condition, "Existing security rule"))
    with pytest.raises(DuplicateRule, match="Existing security rule"):
        check(rule(condition), rows)


def test_collector_refinement_handles_retained_history_and_macro_changes(
    tmp_path, monkeypatch
):
    config, defaults = inventory(tmp_path)
    rows = definitions(defaults.read_text())
    rows = [row for row in rows if row.get("macro") != "open_write"]
    rows += collector_rows("Baseline File Write")[2:]
    defaults.write_text(yaml.safe_dump(rows))
    monkeypatch.setenv("RULE_GUARD_STATE_DIR", str(tmp_path / "guard"))
    monkeypatch.setattr("rule_deduplicator._verify_runtime", lambda _: None)
    candidate = rule(
        'open_write and container and proc.name="sh" and fd.name="/tmp/eval"'
    )
    with guard(config) as locked:
        assert locked.check(candidate)
    # Previously observed collector definitions remain in the protected registry.
    with guard(config) as locked:
        assert locked.check(candidate)
    # An older collector AST must not inherit a different current macro meaning.
    for row in rows:
        if row.get("macro") == "open_write":
            row["condition"] = (
                "evt.type in (open, openat) and evt.arg.flags contains O_RDWR"
            )
    defaults.write_text(yaml.safe_dump(rows))
    with guard(config) as locked:
        with pytest.raises(DuplicateRule):
            locked.check(candidate)


def test_exact_match():
    with pytest.raises(DuplicateRule, match="Exact match.*Existing"):
        check(
            rule("proc.name = bash"), definitions(rule("proc.name = bash", "Existing"))
        )


@pytest.mark.parametrize(
    "condition",
    [
        'proc.name=="bash" and fd.name in ("/etc/shadow")',
        "fd.name=/etc/shadow and (proc.name in (bash))",
        "not (proc.name != bash or fd.name != /etc/shadow)",
        "(proc.name = bash and fd.name=/etc/shadow) or (proc.name=bash and fd.name=/etc/shadow)",
    ],
)
def test_boolean_and_operator_equivalence(condition):
    with pytest.raises(DuplicateRule, match="equivalent"):
        check(
            rule(condition),
            definitions(rule("proc.name = bash and fd.name = /etc/shadow", "Old")),
        )


def test_distributive_equivalence():
    with pytest.raises(DuplicateRule):
        check(
            rule("proc.name=bash and (evt.type=execve or evt.type=execveat)"),
            definitions(
                rule(
                    "(proc.name=bash and evt.type=execve) or "
                    "(proc.name=bash and evt.type=execveat)",
                    "Existing",
                )
            ),
        )


def test_near_duplicate():
    with pytest.raises(DuplicateRule, match="Near-duplicate.*Old"):
        check(
            rule(
                "proc.name=bash and container.id!=host and evt.type=execve and user.uid=0"
            ),
            definitions(
                rule("proc.name=bash and container.id!=host and evt.type=execve", "Old")
            ),
        )


def test_unique_process_file_and_network_rules():
    for field, before, after in [
        ("proc.name", "bash", "curl"),
        ("fd.name", "/etc/a", "/etc/b"),
        ("fd.sip", "10.0.0.1", "10.0.0.2"),
    ]:
        assert check(
            rule(f"{field}={after}"), definitions(rule(f"{field}={before}", "Old"))
        )


def test_case_and_literal_whitespace_are_significant():
    assert check(rule('proc.name="Bash"'), definitions(rule('proc.name="bash"', "Old")))
    assert check(
        rule('proc.cmdline="a b"'), definitions(rule('proc.cmdline="ab"', "Old"))
    )


def test_macro_and_nested_list_equivalence():
    rows = [
        {"list": "base", "items": ["bash"]},
        {"list": "shells", "items": ["base"]},
        {"macro": "shell", "condition": "proc.name in (shells)"},
        {"rule": "Admin Shell", "condition": "shell and container.id!=host"},
    ]
    with pytest.raises(DuplicateRule, match="Admin Shell"):
        check(rule("container.id != host and proc.name = bash"), rows)


@pytest.mark.parametrize(
    "condition",
    [
        "missing_macro",
        "proc.name strange bash",
        "proc.name=bash trailing",
        "proc.name=(bash",
        "",
    ],
)
def test_unknown_syntax_blocks_instead_of_assuming_unique(condition):
    with pytest.raises(InventoryError):
        check(rule("proc.name=curl"), definitions(rule(condition, "Unsupported")))


def test_cyclic_macro_blocks():
    with pytest.raises(InventoryError, match="Cyclic"):
        check(
            rule("proc.name=bash"),
            [
                {"macro": "cycle", "condition": "cycle"},
                {"rule": "Old", "condition": "cycle"},
            ],
        )


def test_cannot_submit_multi_rule_or_override():
    with pytest.raises(InventoryError):
        check(rule("proc.name=bash") + rule("proc.name=curl"), [])
    with pytest.raises(InventoryError):
        check(rule("proc.name=bash", override={"condition": "replace"}), [])


def test_same_name_with_different_condition_is_blocked():
    with pytest.raises(DuplicateRule, match="name already exists"):
        check(rule("proc.name=curl"), definitions(rule("proc.name=bash")))


def test_manual_rule_is_permanently_protected_after_removal(tmp_path, monkeypatch):
    config, path = inventory(tmp_path)
    monkeypatch.setattr(
        "rule_deduplicator._runtime_arguments", lambda: ["falco", "-c", str(config)]
    )
    monkeypatch.setenv("RULE_GUARD_STATE_DIR", str(tmp_path / "guard"))
    original = path.read_text()
    path.write_text(original + rule("proc.name=bash", "Manually Added Shell"))
    with guard(config) as registry:
        with pytest.raises(DuplicateRule, match="Manually Added Shell"):
            registry.check(rule("proc.name=bash"))
    path.write_text(original)
    with guard(config) as registry:
        with pytest.raises(DuplicateRule, match="Manually Added Shell"):
            registry.check(rule("proc.name=bash"))


def test_config_directories_override_and_manual_files(tmp_path, monkeypatch):
    config, path = inventory(tmp_path)
    monkeypatch.setattr(
        "rule_deduplicator._runtime_arguments", lambda: ["falco", "-c", str(config)]
    )
    custom = tmp_path / "rules.d"
    custom.mkdir()
    (custom / "manual.yaml").write_text(rule("proc.name=curl", "Manual Network Tool"))
    includes = tmp_path / "config.d"
    includes.mkdir()
    (includes / "override.yaml").write_text(
        yaml.safe_dump({"rules_files": [str(path), str(custom)]})
    )
    monkeypatch.setenv("RULE_GUARD_STATE_DIR", str(tmp_path / "guard"))
    with guard(config) as registry:
        with pytest.raises(DuplicateRule, match="Manual Network Tool"):
            registry.check(rule("proc.name=curl"))


def test_missing_config_and_unreadable_configured_file_fail_closed(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("RULE_GUARD_STATE_DIR", str(tmp_path / "guard"))
    config, path = inventory(tmp_path)
    monkeypatch.setattr(
        "rule_deduplicator._runtime_arguments", lambda: ["falco", "-c", str(config)]
    )
    path.unlink()
    with pytest.raises(InventoryError):
        with guard(config):
            pass
    config.unlink()
    with pytest.raises(InventoryError):
        with guard(config):
            pass


def test_check_write_is_serialized_across_threads(tmp_path, monkeypatch):
    config, path = inventory(tmp_path)
    monkeypatch.setattr(
        "rule_deduplicator._runtime_arguments", lambda: ["falco", "-c", str(config)]
    )
    monkeypatch.setenv("RULE_GUARD_STATE_DIR", str(tmp_path / "guard"))

    def submit(index):
        with guard(config) as registry:
            candidate = rule("proc.name=whoami", f"Candidate {index}")
            try:
                registry.check(candidate)
            except DuplicateRule:
                return "blocked"
            path.write_text(path.read_text() + candidate)
            return "written"

    with ThreadPoolExecutor(2) as pool:
        assert sorted(pool.map(submit, [1, 2])) == ["blocked", "written"]


def test_scalar_field_absorption_and_contradiction():
    with pytest.raises(DuplicateRule):
        check(
            rule("proc.name=bash and proc.name in (bash, curl)"),
            definitions(rule("proc.name=bash", "Old")),
        )
    with pytest.raises(DuplicateRule):
        check(
            rule("proc.name=bash and proc.name=curl"),
            definitions(rule("false", "Never")),
        )


def test_empty_admin_list_is_false():
    rows = [
        {"list": "empty", "items": []},
        {"rule": "Old", "condition": "proc.name in (empty)"},
    ]
    with pytest.raises(DuplicateRule):
        check(rule("false"), rows)


@pytest.mark.parametrize(
    "condition", ["proc.name glob bash", 'proc.name regex "^bash$"']
)
def test_literal_pattern_equivalence(condition):
    with pytest.raises(DuplicateRule):
        check(rule("proc.name=bash"), definitions(rule(condition, "Admin Pattern")))


def test_uncertain_cross_operator_semantics_are_never_assumed_unique():
    with pytest.raises(DuplicateRule, match="semantic equivalence cannot be excluded"):
        check(
            rule("proc.name=bash and proc.pname=sh"),
            definitions(
                rule('proc.name regex "b[a]sh" and proc.pname=sh', "Regex Shell")
            ),
        )


def test_opaque_predicate_with_proven_different_event_family_is_unique():
    assert check(
        rule("evt.type=execve and proc.name=bash"),
        definitions(rule("evt.type=connect and fd.sip in (10.0.0.0/8)", "Network")),
    )


def test_runtime_config_mismatch_blocks_inventory(tmp_path, monkeypatch):
    config, _ = inventory(tmp_path)
    monkeypatch.setenv("RULE_GUARD_STATE_DIR", str(tmp_path / "guard"))
    monkeypatch.setattr(
        "rule_deduplicator._runtime_arguments",
        lambda: ["falco", "-c", "/other/falco.yaml"],
    )
    with pytest.raises(InventoryError, match="differs"):
        with guard(config):
            pass


@pytest.mark.parametrize(
    "options",
    [
        ["-r", "/tmp/hidden.yaml"],
        ["--rulesfile=/tmp/hidden.yaml"],
        ["-o", "rules_files[0]=/tmp/hidden.yaml"],
        ["--option=rule_matching=first"],
    ],
)
def test_runtime_inventory_overrides_fail_closed(tmp_path, monkeypatch, options):
    config, _ = inventory(tmp_path)
    monkeypatch.setenv("RULE_GUARD_STATE_DIR", str(tmp_path / "guard"))
    monkeypatch.setattr(
        "rule_deduplicator._runtime_arguments",
        lambda: ["falco", "-c", str(config), *options],
    )
    with pytest.raises(InventoryError):
        with guard(config):
            pass


def test_inventory_change_during_decision_is_blocked(tmp_path, monkeypatch):
    config, path = inventory(tmp_path)
    monkeypatch.setenv("RULE_GUARD_STATE_DIR", str(tmp_path / "guard"))
    monkeypatch.setattr(
        "rule_deduplicator._runtime_arguments", lambda: ["falco", "-c", str(config)]
    )
    with guard(config) as registry:
        registry.check(rule("proc.name=whoami"))
        path.write_text(path.read_text() + rule("proc.name=whoami", "Late manual"))
        with pytest.raises(InventoryError, match="changed"):
            registry.revalidate()


def test_historical_rules_use_historical_macros_but_candidate_uses_current_macros(
    tmp_path, monkeypatch
):
    config, path = inventory(tmp_path)
    monkeypatch.setenv("RULE_GUARD_STATE_DIR", str(tmp_path / "guard"))
    monkeypatch.setattr(
        "rule_deduplicator._runtime_arguments", lambda: ["falco", "-c", str(config)]
    )
    path.write_text(
        "- macro: monitored\n  condition: evt.type=execveat\n"
        "- rule: Removed Admin\n  condition: evt.type=execve\n"
    )
    with guard(config):
        pass
    path.write_text(
        "- macro: monitored\n  condition: evt.type=execve\n"
        "- rule: Different\n  condition: evt.type=connect\n"
    )
    with guard(config) as registry:
        with pytest.raises(DuplicateRule, match="Removed Admin"):
            registry.check(rule("monitored"))


def test_ambiguous_yaml_duplicate_condition_cannot_bypass():
    with pytest.raises(InventoryError):
        check(
            "- rule: Evasive\n  condition: proc.name=bash\n  condition: proc.name=curl\n",
            [],
        )


def test_non_template_source_cannot_bypass_inventory():
    with pytest.raises(InventoryError):
        check(rule("proc.name=bash", source="k8s_audit"), [])
