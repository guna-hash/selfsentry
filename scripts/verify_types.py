"""Check application/script types with the repository's flat runtime import paths."""

import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    # Hyphenated service folders are Python search roots, not package names.
    roots = sorted(
        {p.parent for p in ROOT.glob("*/*.py") if p.parent.name != "tests"}
        | {ROOT / "database"}
    )
    files = sorted(
        str(p.relative_to(ROOT))
        for root in roots for p in root.rglob("*.py")
        if p.name != "__init__.py" and "__pycache__" not in p.parts
    )
    env = dict(os.environ, MYPYPATH=os.pathsep.join(map(str, roots)))
    return subprocess.call(
        [sys.executable, "-m", "mypy", "--explicit-package-bases",
         "--follow-imports=silent", "--ignore-missing-imports", "--no-incremental",
         "--cache-dir", os.devnull,
         "--check-untyped-defs",
         *sys.argv[1:], *files],
        cwd=ROOT, env=env,
    )


if __name__ == "__main__":
    raise SystemExit(main())
