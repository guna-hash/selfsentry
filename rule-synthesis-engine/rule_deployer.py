"""
rule_deployer.py
-------------------
Rule Synthesis Engine — Rule Deployer.

CRITICAL DESIGN CONSTRAINT: only writes to falco-rules/auto-generated-rules.yaml
(never base-rules.yaml), and only AFTER human approval. This module does
NOT check approval status itself — it assumes the caller (the backend's
/rules/{id}/approve endpoint) has already enforced that gate. Then
triggers Falco's hot-reload.

Integration seam (per docs/interfaces.md / Track A guide): the backend's
approve endpoint calls deploy_rule(rule_id) -> bool after marking the
rule approved in Postgres.
"""

from __future__ import annotations

import subprocess

import glob
import os

import yaml
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

AUTO_GENERATED_RULES_PATH = os.path.join(_REPO_ROOT, "falco-rules", "auto-generated-rules.yaml")
FALCO_SERVICE_NAME = "falco-modern-bpf"
FALCO_CONFIG_PATH = "/etc/falco/falco.yaml"
FALCO_CONFIG_DIR = "/etc/falco/config.d"
# Falco defaults to "first", where the catch-all baseline rule shadows every
# auto-generated rule. See docs/falco_rule_matching.md.
REQUIRED_RULE_MATCHING = "all"

class RuleDeploymentError(RuntimeError):
    """Raised when a rule cannot be safely written or Falco cannot be reloaded."""


def _validate_yaml(file_path: str) -> None:
    """Raises RuleDeploymentError if the file is not valid YAML — we must
    never reload Falco against a broken rules file."""
    with open(file_path) as f:
        content = f.read()
    try:
        yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise RuleDeploymentError(f"{file_path} is not valid YAML after write: {exc}") from exc


def _reload_falco() -> None:
    result = subprocess.run(
        ["sudo", "systemctl", "reload", FALCO_SERVICE_NAME],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuleDeploymentError(
            f"Falco reload failed (exit {result.returncode}): {result.stderr.strip()}"
        )


def _read_rule_matching_mode() -> str:
    """Effective Falco rule_matching value. Falco's default is "first" when unset;
    config.d files are read after falco.yaml, so a later value overrides."""
    mode = "first"
    config_files = [FALCO_CONFIG_PATH] + sorted(
        glob.glob(os.path.join(FALCO_CONFIG_DIR, "*.yaml"))
    )
    for path in config_files:
        try:
            with open(path) as f:
                data = yaml.safe_load(f) or {}
        except (OSError, yaml.YAMLError) as exc:
            raise RuleDeploymentError(f"cannot read Falco config {path}: {exc}") from exc
        if isinstance(data, dict) and "rule_matching" in data:
            mode = str(data["rule_matching"])
    return mode


def _require_rule_matching_all() -> None:
    """Refuse to deploy while Falco would let earlier rules shadow auto-generated ones."""
    mode = _read_rule_matching_mode()
    if mode != REQUIRED_RULE_MATCHING:
        raise RuleDeploymentError(
            f"Falco rule_matching is '{mode}', must be '{REQUIRED_RULE_MATCHING}' or "
            "deployed rules will be shadowed by earlier rules. "
            "See docs/falco_rule_matching.md."
        )


def deploy_rule(rule_id: str, rule_yaml: str) -> bool:
    """
    Appends an approved rule's YAML text to auto-generated-rules.yaml and
    triggers Falco's hot-reload. Returns True on success.

    rule_yaml must already be the rendered Falco YAML text (from
    rule_template_generator.generate_rule), not a pattern dict.
    """
    _require_rule_matching_all()

    original = ""
    if os.path.exists(AUTO_GENERATED_RULES_PATH):
        with open(AUTO_GENERATED_RULES_PATH) as f:
            original = f.read()

    with open(AUTO_GENERATED_RULES_PATH, "a") as f:
        f.write("\n" + rule_yaml.strip() + "\n")

    try:
        _validate_yaml(AUTO_GENERATED_RULES_PATH)
    except RuleDeploymentError:
        # Restore the previous file so a broken rule can never stop Falco loading.
        with open(AUTO_GENERATED_RULES_PATH, "w") as f:
            f.write(original)
        raise

    _reload_falco()
    return True


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SelfSentry - Deploy an approved rule to live Falco")
    parser.add_argument("rule_id")
    parser.add_argument("rule_yaml_file", help="Path to a .yaml file containing the approved rule")
    args = parser.parse_args()

    with open(args.rule_yaml_file) as f:
        rule_yaml = f.read()

    try:
        success = deploy_rule(args.rule_id, rule_yaml)
    except RuleDeploymentError as exc:
        print(f"ERROR: {exc}")
        raise SystemExit(1)

    print(f"Rule {args.rule_id} deployed and Falco reloaded: {success}")
