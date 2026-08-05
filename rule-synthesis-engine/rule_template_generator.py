"""
rule_template_generator.py
------------------------------
Rule Synthesis Engine — Rule Template Generator.

STATUS: NOT YET IMPLEMENTED — Phase 6 stub (CORE NOVELTY MODULE).

CRITICAL DESIGN CONSTRAINT: rule generation is template-based (Jinja2),
NEVER LLM-freehand. An LLM writing raw Falco rule syntax risks
hallucinated/broken conditions that could silently fail to detect
attacks or create false blind spots. This is non-negotiable per
project design decisions.

Planned interface:
    from jinja2 import Environment, FileSystemLoader

    def generate_rule(pattern: dict, rule_id: str) -> str:
        \"\"\"Renders templates/falco_rule_template.yaml.j2 with the
        extracted pattern and returns valid Falco YAML rule text.\"\"\"
        raise NotImplementedError("Phase 6 not yet built")
"""
