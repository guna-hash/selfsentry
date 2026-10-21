"""Real temporary Falco inventory for tests; never use a production fallback."""

from pathlib import Path
import yaml


def inventory(root):
    root = Path(root)
    rules = root / "defaults.yaml"
    rules.write_text(
        yaml.safe_dump(
            [
                {"macro": "spawned_process", "condition": "evt.type in (execve, execveat)"},
                {"macro": "container", "condition": "container.id != host"},
                {"macro": "open_write", "condition": "evt.is_open_write = true"},
                {"rule": "Unrelated default", "condition": "evt.type = unlink"},
            ]
        )
    )
    config = root / "falco.yaml"
    config.write_text(yaml.safe_dump({"rules_files": [str(rules)], "rule_matching": "all"}))
    return config, rules
