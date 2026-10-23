"""Refresh review metadata for tracked and nonignored follow-up source paths."""

import ast
import csv
import hashlib
import io
import re
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
FOLDER = ROOT / 'docs/repository-audit'
GENERATED = {'docs/repository-audit/file_inventory.csv',
             'docs/repository-audit/validation.json'}


def paths():
    return sorted(set(subprocess.check_output(
        ['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'],
        cwd=ROOT).decode().strip('\0').split('\0')))


def main():
    inventory = FOLDER / 'file_inventory.csv'
    with inventory.open(newline='') as stream:
        reader = csv.DictReader(stream)
        fields = reader.fieldnames
        previous = {row['path']: row for row in reader}
    assert fields is not None
    names = paths()
    (FOLDER / 'final-tree.txt').write_text(
        'Current follow-up source paths (runtime state/dependency installs excluded)\n'
        + '\n'.join(names) + '\n')
    source = {name: (ROOT / name).read_bytes() for name in names}
    text = {name: data.decode('utf-8', errors='replace') for name, data in source.items()
            if b'\0' not in data}
    output = io.StringIO(newline='')
    writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for name in names:
        row = previous.get(name, dict.fromkeys(fields, ''))
        row['path'] = name
        if not row['purpose']:
            lines = text.get(name, '').splitlines() or ['Empty tracked artifact']
            row['purpose'] = lines[0][:200]
            row['issues'] = 'See current follow-up assessment; native acceptance remains scoped'
            row['action'] = 'KEEP'
            row['reason'] = 'Reviewed follow-up source, regression or provenance artifact'
            row['review_status'] = ('Focused source review and affected local checks' if
                                    name.endswith('.py') else 'Documentation/metadata review')
        pattern = re.compile(re.escape(name) if name != '-c' else r'[\x60\x22\x27]-c[\x60\x22\x27]')
        references = [other for other, body in text.items()
                      if other != name and other not in GENERATED
                      and not other.endswith('final-tree.txt') and pattern.search(body)]
        row['references'] = '; '.join(references)
        row['usage'] = ('Literal path references; dynamic/CLI use reviewed separately' if references
                        else 'No literal full-path reference; not proof of non-use')
        if name.endswith('.py'):
            tree = ast.parse(text[name], filename=name)
            row['symbols'] = '; '.join(node.name for node in tree.body
                                       if isinstance(node, (ast.FunctionDef, ast.ClassDef)))
            row['dependencies'] = '; '.join(sorted({
                node.module or '' for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
            } | {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
                 for alias in node.names}))
        if not row['base_sha256']:
            result = subprocess.run(['git', 'show', 'HEAD:' + name], cwd=ROOT,
                                    capture_output=True)
            if result.returncode == 0:
                row['base_sha256'] = hashlib.sha256(result.stdout).hexdigest()
        digest = hashlib.sha256(source[name]).hexdigest()
        row['final_sha256'] = '' if name in GENERATED else digest
        if name in GENERATED:
            row['issues'] = ('Hash excluded to avoid metadata self-reference; '
                             'package manifest binds bytes')
        if name == '-c' or name.endswith('.before-clock-followup'):
            row.update(action='PROPOSE_REMOVE_PENDING_APPROVAL',
                       reason='See deletion-manifest.json; original bytes retained in Git',
                       review_status='Compared current originals, Git blobs and source references')
        writer.writerow(row)
    inventory.write_text(output.getvalue())
    print(f'Inventoried {len(names)} paths; no paths removed')


if __name__ == '__main__':
    main()
