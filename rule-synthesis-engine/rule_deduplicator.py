"""Deterministic, fail-closed Falco rule inventory and duplicate guard.

No generated text or model is used. Historical definitions are retained in SQLite;
flock serializes inventory/check/write across workers sharing this host state dir.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import fcntl
from functools import lru_cache
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
TOKEN = re.compile(
    r"""\s*("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|!=|==|<=|>=|[(),=<>]|[^\s(),=<>!]+)"""
)
OPS = {
    "=",
    "==",
    "!=",
    "<",
    ">",
    "<=",
    ">=",
    "in",
    "intersects",
    "pmatch",
    "contains",
    "icontains",
    "startswith",
    "endswith",
    "glob",
    "iglob",
    "bstartswith",
    "bcontains",
    "regex",
}


class InventoryError(RuntimeError):
    """Coverage or comparison cannot be established; never assume an empty inventory."""


class DuplicateRule(InventoryError):
    def __init__(self, reason, name):
        super().__init__(reason)
        self.reason, self.name = reason, name


class UniqueKeyLoader(yaml.SafeLoader):
    """Do not let YAML parser differences select different duplicate-key values."""

    def construct_mapping(self, node, deep=False):
        seen = set()
        for key, _ in node.value:
            value = self.construct_object(key, deep=deep)
            if value in seen:
                raise yaml.constructor.ConstructorError(
                    None, None, "Duplicate YAML key", key.start_mark
                )
            seen.add(value)
        return super().construct_mapping(node, deep=deep)


def _load_yaml(text):
    try:
        return yaml.load(text, Loader=UniqueKeyLoader)
    except (yaml.YAMLError, TypeError, RecursionError) as exc:
        raise InventoryError("Invalid, ambiguous or excessive YAML") from exc


def _value(token):
    if token.startswith(('"', "'")):
        # Falco quoted values use backslash escaping; preserve case and path semantics.
        value = token[1:-1]
        if re.search(r"\\(?![\\'\"])", value):
            raise InventoryError("Unsupported literal escape; comparison refused")
        return re.sub(r"\\([\\\'\"])", r"\1", value)
    return token


def _join(op, nodes):
    flat: set[tuple] = set()
    for node in nodes:
        flat.update(node[1:] if node[0] == op else [node])
    if len(flat) == 1:
        return next(iter(flat))
    return (op, *sorted(flat, key=repr))


class Parser:
    def __init__(self, condition, macros, lists, stack=()):
        if not isinstance(condition, str) or len(condition) > 100000:
            raise InventoryError("Invalid or oversized Falco condition")
        self.tokens = TOKEN.findall(condition)
        if "".join(self.tokens) != re.sub(r"\s+", "", condition):
            # Whitespace inside literals is significant: compare tokenized spans instead.
            tail = TOKEN.sub("", condition)
            if tail.strip():
                raise InventoryError("Unsupported condition token")
        self.i, self.macros, self.lists, self.stack = 0, macros, lists, stack

    def peek(self):
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def take(self):
        value = self.peek()
        if value is None:
            raise InventoryError("Incomplete Falco condition")
        self.i += 1
        return value

    def parse(self):
        node = self.expr("or")
        if self.peek() is not None:
            raise InventoryError(f"Unsupported Falco syntax near {self.peek()}")
        return node

    def expr(self, op):
        read = (lambda: self.expr("and")) if op == "or" else self.unary
        nodes = [read()]
        while self.peek() == op:
            self.take()
            nodes.append(read())
        return _join(op, nodes)

    def unary(self):
        if self.peek() == "not":
            self.take()
            return ("not", self.unary())
        if self.peek() == "(":
            self.take()
            node = self.expr("or")
            if self.take() != ")":
                raise InventoryError("Unbalanced Falco condition")
            return node
        field = self.take()
        if field in self.macros:
            if field in self.stack or len(self.stack) > 64:
                raise InventoryError("Cyclic or excessive macro expansion")
            return Parser(self.macros[field], self.macros, self.lists, (*self.stack, field)).parse()
        if field in ("true", "false"):
            return (field,)
        # Field transforms are distinct from the underlying field.
        if self.peek() == "(":
            self.take()
            inner = self.take()
            if self.take() != ")":
                raise InventoryError("Unsupported field transform")
            field = f"{field}({inner})"
        op = self.take()
        if op == "exists":
            return ("atom", field, op, "")
        if op not in OPS:
            raise InventoryError(f"Unknown macro or operator: {field} {op}")
        values = []
        if self.peek() == "(":
            self.take()
            while self.peek() != ")":
                value = self.take()
                if value != ",":
                    values.extend(self.expand_list(value))
            self.take()
        else:
            values = [_value(self.take())]
        if not values:
            if op in ("in", "intersects", "pmatch"):
                return ("false",)
            raise InventoryError("Empty comparison")
        if len(values) == 1:
            value = values[0]
            if op == "glob" and not any(c in value for c in "*?[]\\"):
                op = "="
            elif op == "regex" and re.fullmatch(r"\^[A-Za-z0-9_ /:-]+\$", value):
                values, op = [value[1:-1]], "="
        if op in ("in", "=", "==", "!="):
            node = _join("or", [("atom", field, "=", v) for v in set(values)])
            return ("not", node) if op == "!=" else node
        return ("atom", field, op, tuple(sorted(set(values))))

    def expand_list(self, token, stack=()):
        if token in self.lists:
            if token in stack or len(stack) > 64:
                raise InventoryError("Cyclic list expansion")
            return [
                v
                for item in self.lists[token]
                for v in self.expand_list(str(item), (*stack, token))
            ]
        return [_value(token)]


def _atoms(node):
    if node[0] == "atom":
        return {node}
    return set().union(*(_atoms(n) for n in node[1:] if isinstance(n, tuple)))


def fingerprint(node):
    """Canonical reduced ordered Boolean DAG built with memoized apply operations.

    Predicates remain exact (no guessed regex/path aliases). Complexity overflow
    fails closed. AND/OR order, distribution, absorption and NOT are canonical.
    """
    # Terminal IDs 0/1 are handled before node lookup; only branches need entries.
    nodes: dict[int, tuple[tuple, int, int]] = {}
    unique: dict[tuple, int] = {}
    applied: dict[tuple, int] = {}
    negated = {0: 1, 1: 0}
    built: dict[tuple, int] = {}

    def make(atom, lo, hi):
        if lo == hi:
            return lo
        key = (atom, lo, hi)
        if key not in unique:
            if len(nodes) + 2 >= 50000:
                raise InventoryError("Semantic comparison complexity limit exceeded")
            index = len(nodes) + 2
            unique[key] = index
            nodes[index] = key
        return unique[key]

    def negate(index):
        if index not in negated:
            atom, lo, hi = nodes[index]
            negated[index] = make(atom, negate(lo), negate(hi))
        return negated[index]

    def apply(op, a, b):
        if a > b:
            a, b = b, a
        key = (op, a, b)
        if key in applied:
            return applied[key]
        if a == b:
            return a
        if op == "and":
            if a == 0:
                return 0
            if a == 1:
                return b
        else:
            if a == 1 or b == 1:
                return 1
            if a == 0:
                return b
        atom = min(nodes[a][0], nodes[b][0], key=repr)
        al, ah = nodes[a][1:] if nodes[a][0] == atom else (a, a)
        bl, bh = nodes[b][1:] if nodes[b][0] == atom else (b, b)
        result = make(atom, apply(op, al, bl), apply(op, ah, bh))
        applied[key] = result
        return result

    def build(n):
        if n in built:
            return built[n]
        if n[0] == "true":
            result = 1
        elif n[0] == "false":
            result = 0
        elif n[0] == "atom":
            result = make(n, 0, 1)
        elif n[0] == "not":
            result = negate(build(n[1]))
        else:
            result = 1 if n[0] == "and" else 0
            for child in n[1:]:
                result = apply(n[0], result, build(child))
        built[n] = result
        return result

    root = build(node)
    restrictions, reduced = {}, {}

    def restrict(index, field, value):
        if index < 2:
            return index
        key = (index, field, value)
        if key not in restrictions:
            atom, lo, hi = nodes[index]
            if atom[1:3] == (field, "="):
                result = restrict(hi if atom[3] == value else lo, field, value)
            else:
                result = make(atom, restrict(lo, field, value), restrict(hi, field, value))
            restrictions[key] = result
        return restrictions[key]

    def reduce(index):
        if index < 2:
            return index
        if index not in reduced:
            atom, lo, hi = nodes[index]
            # Falco scalar fields have one value, not independent Boolean flags.
            # Multi-valued fields need different theory and are kept as predicates.
            if atom[2] == "=" and atom[1] in {
                "proc.name",
                "proc.pname",
                "fd.name",
                "fd.sip",
                "fd.dip",
                "fd.sport",
                "fd.dport",
                "evt.type",
                "container.id",
                "user.uid",
            }:
                hi = restrict(hi, atom[1], atom[3])
            reduced[index] = make(atom, reduce(lo), reduce(hi))
        return reduced[index]

    root = reduce(root)
    digests = {0: "false", 1: "true"}

    def digest(index):
        if index not in digests:
            atom, lo, hi = nodes[index]
            digests[index] = hashlib.sha256(
                repr((atom, digest(lo), digest(hi))).encode()
            ).hexdigest()
        return digests[index]

    return digest(root)


def definitions(text):
    try:
        rows = _load_yaml(text) or []
    except yaml.YAMLError as exc:
        raise InventoryError("Unreadable rule YAML") from exc
    if not isinstance(rows, list) or any(not isinstance(r, dict) for r in rows):
        raise InventoryError("Rule document must be a list of mappings")
    return rows


def _runtime_arguments():
    service = os.environ.get("FALCO_SERVICE", "falco-modern-bpf")
    try:
        result = subprocess.run(
            ["systemctl", "show", "--property=MainPID", "--value", service],
            capture_output=True,
            text=True,
            timeout=3,
            check=True,
        )
        pid = int(result.stdout.strip())
        if pid <= 0:
            raise ValueError("Falco is not running")
        return Path(f"/proc/{pid}/cmdline").read_bytes().decode().rstrip("\0").split("\0")
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        raise InventoryError("Cannot establish the running Falco service inventory") from exc


def _verify_runtime(config_path):
    args = _runtime_arguments()
    configured = Path("/etc/falco/falco.yaml")
    index = 1
    while index < len(args):
        arg = args[index]
        if arg in ("-c", "--config"):
            index += 1
            if index >= len(args):
                raise InventoryError("Invalid runtime config option")
            configured = Path(args[index])
        elif arg.startswith("--config="):
            configured = Path(arg.split("=", 1)[1])
        elif arg.startswith("-c") and len(arg) > 2:
            configured = Path(arg[2:])
        elif arg in ("-r", "--rulesfile") or arg.startswith(("--rulesfile=", "-r")):
            raise InventoryError(
                "Runtime -r rules override is not inventoried; move it into rules_files"
            )
        elif arg in ("-o", "--option"):
            index += 1
            if index >= len(args):
                raise InventoryError("Invalid runtime override")
            option = args[index]
            if option.split("=", 1)[0].split("[", 1)[0] in {
                "rules_files",
                "rules_file",
                "config_files",
                "rule_matching",
            }:
                raise InventoryError("Runtime rules/config override cannot be safely inventoried")
        elif arg.startswith(("--option=", "-o")):
            option = arg.removeprefix("--option=") if arg.startswith("--option=") else arg[2:]
            if option.split("=", 1)[0].split("[", 1)[0] in {
                "rules_files",
                "rules_file",
                "config_files",
                "rule_matching",
            }:
                raise InventoryError("Runtime rules/config override cannot be safely inventoried")
        index += 1
    if configured.resolve() != Path(config_path).resolve():
        raise InventoryError("FALCO_CONFIG_PATH differs from the running Falco configuration")


def load_inventory(config_path=None):
    """Read ordered configured files, including config_files and rule directories.

    Every observed version is protected, including overrides and disabled rules.
    This deliberately errs on the side of blocking regeneration.
    """
    config_path = Path(config_path or os.environ.get("FALCO_CONFIG_PATH", "/etc/falco/falco.yaml"))
    config: dict[str, Any] = {}
    visited: set[Path] = set()

    def read_config(path, strategy="override"):
        path = path.resolve()
        if path in visited:
            raise InventoryError("Repeated/cyclic Falco config include")
        visited.add(path)
        try:
            data = _load_yaml(path.read_text())
        except (OSError, yaml.YAMLError) as exc:
            raise InventoryError(f"Cannot read Falco configuration: {path}") from exc
        if not isinstance(data, dict):
            raise InventoryError("Invalid Falco configuration")
        if strategy not in ("append", "override", "add-only"):
            raise InventoryError("Unknown Falco config merge strategy")
        for key, value in data.items():
            if strategy == "add-only" and key in config:
                continue
            if (
                strategy == "append"
                and isinstance(value, list)
                and isinstance(config.get(key), list)
            ):
                config[key] = config[key] + value
            else:
                config[key] = value
        includes = data.get("config_files", [])
        if not isinstance(includes, list):
            raise InventoryError("Invalid config_files")
        for entry in includes:
            merge = "append"
            if isinstance(entry, dict) and set(entry) <= {"path", "strategy"}:
                merge, entry = entry.get("strategy", "append"), entry.get("path")
            if not isinstance(entry, str):
                raise InventoryError("Unsupported Falco config include")
            target = Path(entry)
            if not target.is_absolute():
                target = path.parent / target
            if target.is_dir():
                for child in sorted(target.glob("*.yaml")):
                    read_config(child, merge)
            elif target.exists():
                read_config(target, merge)
            else:
                raise InventoryError(f"Missing config include: {target}")

    read_config(config_path)
    # Older installations use config.d without config_files.
    for child in sorted((config_path.parent / "config.d").glob("*.yaml")):
        if child.resolve() not in visited:
            read_config(child, "append")
    entries = config.get("rules_files", config.get("rules_file"))
    if not isinstance(entries, list) or not entries:
        raise InventoryError("Falco rules_files missing; refusing incomplete inventory")
    rows = []
    for entry in entries:
        if not isinstance(entry, str):
            raise InventoryError("Invalid Falco rules_files entry")
        path = Path(entry)
        if not path.is_absolute():
            path = config_path.parent / path
        paths = sorted(path.glob("*.yaml")) if path.is_dir() else [path]
        for file in paths:
            try:
                rows.extend(definitions(file.read_text()))
            except OSError as exc:
                raise InventoryError(f"Cannot read configured rules: {file}") from exc
    if not any("rule" in r and "condition" in r for r in rows):
        raise InventoryError("Falco inventory has no rules; coverage unverified")
    return rows


def compile_rules(rows):
    return _compiled(json.dumps(rows, sort_keys=True))


@lru_cache(maxsize=16)
def _compiled(serialized):
    rows = json.loads(serialized)
    macros: dict[str, str] = {}
    lists: dict[str, list] = {}
    rules: list[dict] = []
    for row in rows:
        key = next((k for k in ("macro", "list", "rule") if k in row), None)
        if key is None:
            continue
        if key == "list":
            items = row.get("items", [])
            if not isinstance(items, list):
                raise InventoryError("Invalid Falco list")
            if row.get("append") or row.get("override", {}).get("items") == "append":
                items = lists.get(row[key], []) + items
            lists[row[key]] = items
        elif key == "macro":
            condition = row.get("condition")
            if row.get("append") or row.get("override", {}).get("condition") == "append":
                condition = macros.get(row[key], "") + " " + str(condition)
            macros[row[key]] = condition
        elif "condition" in row:
            # Protect all observed rule definitions, even after replacement/disable.
            condition = row["condition"]
            if row.get("append") or row.get("override", {}).get("condition") == "append":
                previous = next((r for r in reversed(rules) if r["rule"] == row["rule"]), None)
                if previous is None:
                    raise InventoryError("Rule append has no original definition")
                condition = previous["condition"] + " " + condition
            rules.append({**row, "condition": condition})
    result = []
    for row in rules:
        try:
            node = Parser(row["condition"], macros, lists).parse()
            result.append((row, node, fingerprint(node)))
        except (RecursionError, TypeError, ValueError) as exc:
            raise InventoryError(f'Cannot compare active rule: {row["rule"]}') from exc
    return result, macros, lists


def _domain(node, field):
    """Conservative necessary scalar values; None means unconstrained/unknown."""
    if node[0] == "atom":
        return {node[3]} if node[1:3] == (field, "=") else None
    if node[0] == "and":
        sets = [_domain(child, field) for child in node[1:]]
        sets = [values for values in sets if values is not None]
        return set.intersection(*sets) if sets else None
    if node[0] == "or":
        sets = [_domain(child, field) for child in node[1:]]
        return set.union(*sets) if all(v is not None for v in sets) else None
    return None


def _disjoint(left, right):
    for field in ("proc.name", "proc.pname", "fd.name", "evt.type", "container.id"):
        a, b = _domain(left, field), _domain(right, field)
        if a is not None and b is not None and not a & b:
            return True
    return False


def check(candidate_yaml, rows, candidate_environment=None):
    existing, macros, lists = compile_rules(rows)
    if candidate_environment is not None:
        macros, lists = candidate_environment
    return _compare(candidate_yaml, existing, macros, lists)


def _compare(candidate_yaml, existing, macros, lists):
    candidates = definitions(candidate_yaml)
    if len(candidates) != 1 or "rule" not in candidates[0] or "condition" not in candidates[0]:
        raise InventoryError("Exactly one rule required")
    candidate = candidates[0]
    if candidate.get("source", "syscall") != "syscall":
        raise InventoryError("Only syscall template candidates are supported")
    if any(k in candidate for k in ("macro", "list", "override", "append", "exceptions")):
        raise InventoryError("Candidate directives/overrides are forbidden")
    try:
        node = Parser(candidate["condition"], macros, lists).parse()
        digest = fingerprint(node)
    except (RecursionError, TypeError, ValueError) as exc:
        raise InventoryError("Candidate comparison unavailable") from exc
    atoms = _atoms(node)
    processes = {a[3] for a in atoms if a[:3] == ("atom", "proc.name", "=")}
    for row, other, other_digest in existing:
        if candidate["rule"] == row["rule"]:
            raise DuplicateRule(f'Rule name already exists: {row["rule"]}', row["rule"])
        if candidate.get("source", "syscall") != row.get("source", "syscall"):
            continue
        if digest == other_digest:
            exact = candidate["condition"].strip() == row["condition"].strip()
            label = (
                "Exact match with existing rule"
                if exact
                else "Semantically equivalent to deployed rule"
            )
            raise DuplicateRule(f'{label}: {row["rule"]}', row["rule"])
        other_atoms = _atoms(other)
        # Boolean canonicalization never guesses that two different string,
        # regex, numeric or network predicates are independent. Where those
        # theories could overlap, fail closed as a conservative near-duplicate.
        # A necessary conflicting scalar value proves the rules distinct.
        candidate_fields = {a[1] for a in atoms}
        other_fields = {a[1] for a in other_atoms}
        opaque_fields = {a[1] for a in atoms | other_atoms if a[2] != "="}
        # Different independent fields constrain different event dimensions; a
        # path-only rule is not equivalent to a process-name/parent template.
        # Cross-operator comparisons of the same fields stay conservative.
        opaque = (
            bool(opaque_fields)
            and (other_fields <= candidate_fields or candidate_fields <= other_fields)
            and bool(opaque_fields & candidate_fields & other_fields)
        )
        if opaque and not _disjoint(node, other):
            raise DuplicateRule(
                f'Near-duplicate of existing rule: {row["rule"]} '
                "(overlapping predicates; semantic equivalence cannot be excluded)",
                row["rule"],
            )
        other_processes = {a[3] for a in other_atoms if a[:3] == ("atom", "proc.name", "=")}
        similarity = len(atoms & other_atoms) / max(1, len(atoms | other_atoms))
        if processes & other_processes and similarity >= 0.75:
            raise DuplicateRule(f'Near-duplicate of existing rule: {row["rule"]}', row["rule"])
    return digest


def _freeze(value):
    return tuple(_freeze(v) for v in value) if isinstance(value, list) else value


def _remember_rules(db, compiled):
    for row, node, digest in compiled:
        content = json.dumps(row, sort_keys=True)
        tree = json.dumps(node)
        identity = hashlib.sha256((content + tree).encode()).hexdigest()
        db.execute(
            "INSERT OR IGNORE INTO protected_rules VALUES (?, ?, ?, ?)",
            (identity, content, tree, digest),
        )
    db.commit()


@contextlib.contextmanager
def guard(config_path=None):
    state = Path(os.environ.get("RULE_GUARD_STATE_DIR", str(ROOT / "state" / "rule-guard")))
    state.mkdir(parents=True, exist_ok=True)
    with (state / "guard.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        with contextlib.closing(sqlite3.connect(state / "registry.sqlite3")) as db, db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS protected_rules ("
                "identity TEXT PRIMARY KEY, content TEXT NOT NULL, "
                "tree TEXT NOT NULL, fingerprint TEXT NOT NULL)"
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS protected_fingerprint "
                "ON protected_rules(fingerprint)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS receipts (owner TEXT PRIMARY KEY, digest TEXT NOT NULL)"
            )
            effective_path = config_path or os.environ.get(
                "FALCO_CONFIG_PATH", "/etc/falco/falco.yaml"
            )
            _verify_runtime(effective_path)
            rows = load_inventory(effective_path)
            if rows != load_inventory(effective_path):
                raise InventoryError("Falco inventory changed during read; retry")
            compiled, macros, lists = compile_rules(rows)
            _remember_rules(db, compiled)  # Persist even when candidate is rejected.
            # Each historical AST retains the macro/list meaning at observation.
            protected = [
                (json.loads(row), _freeze(json.loads(tree)), digest)
                for row, tree, digest in db.execute(
                    "SELECT content, tree, fingerprint FROM protected_rules"
                )
            ]
            yield RuleGuard(db, rows, protected, macros, lists, effective_path)


class RuleGuard:
    def __init__(self, db, rows, protected, macros, lists, config_path):
        self.db, self.rows, self.protected = db, rows, protected
        self.macros, self.lists, self.config_path = macros, lists, config_path

    def revalidate(self):
        _verify_runtime(self.config_path)
        if load_inventory(self.config_path) != self.rows:
            raise InventoryError("Falco inventory changed during decision; retry")

    def check(self, text, extra=()):
        digest = _compare(text, self.protected, self.macros, self.lists)
        for document in extra:
            check(
                text,
                [r for r in self.rows if "rule" not in r] + definitions(document),
                (self.macros, self.lists),
            )
        return digest

    def check_retry(self, text):
        own = definitions(text)
        other = [(row, node, digest) for row, node, digest in self.protected if row not in own]
        _compare(text, other, self.macros, self.lists)

    def receipt(self, owner, text):
        digest = hashlib.sha256(text.encode()).hexdigest()
        row = self.db.execute("SELECT digest FROM receipts WHERE owner=?", (owner,)).fetchone()
        return row == (digest,)

    def remember(self, owner, text):
        self.db.execute(
            "INSERT OR REPLACE INTO receipts VALUES (?, ?)",
            (owner, hashlib.sha256(text.encode()).hexdigest()),
        )
        compiled, _, _ = compile_rules(
            [r for r in self.rows if "rule" not in r] + definitions(text)
        )
        _remember_rules(self.db, compiled)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Verify and seed the permanent Falco rule registry"
    )
    parser.add_argument(
        "--check-yaml", type=Path, help="Optional offline-rendered candidate to check"
    )
    args = parser.parse_args()
    try:
        with guard() as registry:
            if args.check_yaml:
                registry.check(args.check_yaml.read_text())
            registry.revalidate()
            print(
                json.dumps(
                    {
                        "status": "unique" if args.check_yaml else "ready",
                        "protected_definitions": len(registry.protected),
                    }
                )
            )
    except (InventoryError, OSError, sqlite3.Error) as exc:
        print(str(exc))
        raise SystemExit(1)
