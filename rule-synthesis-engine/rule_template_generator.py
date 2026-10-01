"""
rule_template_generator.py
------------------------------
Rule Synthesis Engine — Rule Template Generator.

CRITICAL DESIGN CONSTRAINT: rule generation is template-based (Jinja2),
NEVER LLM-freehand. This module deterministically renders a structured
pattern dict (from pattern_extractor.py) into valid Falco YAML rule
text, using templates/falco_rule_template.yaml.j2.
"""

from __future__ import annotations

import re

from jinja2 import Environment, FileSystemLoader, select_autoescape

_TEMPLATE_DIR = __file__.rsplit("/", 1)[0] + "/templates"
_SLUG_PATTERN = re.compile(r"[^A-Za-z0-9]+")


class RuleGenerationError(RuntimeError):
    """Raised when a pattern lacks the fields required to render a rule."""


def _slugify(text: str) -> str:
    return _SLUG_PATTERN.sub("_", text).strip("_")


def generate_rule(pattern: dict, source_incident_id: int) -> str:
    proc_name = pattern.get("proc_name")
    parent_proc = pattern.get("parent_proc")

    if not proc_name or not parent_proc:
        raise RuleGenerationError(
            "Cannot generate a rule: pattern is missing proc_name and/or parent_proc "
            f"(got proc_name={proc_name!r}, parent_proc={parent_proc!r}). "
            "This incident's Falco alert output did not contain parseable process fields."
        )

    env = Environment(
        loader=FileSystemLoader(_TEMPLATE_DIR),
        autoescape=select_autoescape(disabled_extensions=("j2",)),
    )
    template = env.get_template("falco_rule_template.yaml.j2")

    rule_slug = _slugify(f"{proc_name}_from_{parent_proc}_{source_incident_id}")

    return template.render(
        rule_slug=rule_slug,
        proc_name=proc_name,
        parent_proc=parent_proc,
        source_incident_id=source_incident_id,
    )


if __name__ == "__main__":
    import argparse
    import requests
    from pattern_extractor import extract_pattern

    parser = argparse.ArgumentParser(description="SelfSentry - Generate a candidate Falco rule from a confirmed incident")
    parser.add_argument("incident_id", type=int)
    parser.add_argument("--backend-url", default="http://localhost:8000")
    args = parser.parse_args()

    resp = requests.get(f"{args.backend_url}/incidents/{args.incident_id}", timeout=10)
    resp.raise_for_status()
    incident = resp.json()

    pattern = extract_pattern(incident)
    rule_yaml = generate_rule(pattern, source_incident_id=args.incident_id)
    print(rule_yaml)
