"""SPDX package inventory of declared locks; no installed-artifact or license attestation."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import uuid

ROOT = Path(__file__).resolve().parents[1]


def main():
    sources = ['requirements.lock', 'requirements-dev.lock',
               'frontend-dashboard/package-lock.json']
    hashes = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in sources}
    packages = []
    for source in sources[:-1]:
        for line in (ROOT / source).read_text().splitlines():
            if not line.strip() or line.startswith('#'):
                continue
            if source == 'requirements-dev.lock' and line.strip() == '-r requirements.lock':
                continue  # Runtime pins are already included above.
            match = re.fullmatch(r'([A-Za-z0-9_.-]+)==([^\s;]+)', line.strip())
            if not match:
                raise ValueError('Unsupported lock entry; refuse incomplete SBOM')
            packages.append({'name': match[1], 'versionInfo': match[2],
                             'sourceInfo': f'Declared Python lock entry: {source}'})
    lock = json.loads((ROOT / sources[-1]).read_text())
    for path, item in sorted(lock['packages'].items()):
        if not path:
            continue  # Root project is described by the document, not a third-party package.
        if 'version' not in item:
            raise ValueError('Missing npm package version')
        packages.append({'name': item.get('name') or path.rsplit('node_modules/', 1)[-1],
                         'versionInfo': item['version'],
                         'sourceInfo': f'Declared npm lock entry: {path}; '
                                       f'dev={bool(item.get("dev"))}; '
                                       f'optional={bool(item.get("optional"))}'})
    for index, package in enumerate(packages, 1):
        package.update(SPDXID=f'SPDXRef-Package-{index}', downloadLocation='NOASSERTION',
                       filesAnalyzed=False, licenseConcluded='NOASSERTION',
                       licenseDeclared='NOASSERTION', copyrightText='NOASSERTION')
    identity = uuid.uuid5(uuid.NAMESPACE_URL, json.dumps(hashes, sort_keys=True))
    report = {'spdxVersion': 'SPDX-2.3', 'dataLicense': 'CC0-1.0',
              'SPDXID': 'SPDXRef-DOCUMENT', 'name': 'SelfSentry declared lock packages',
              'documentNamespace': 'urn:uuid:' + str(identity),
              'creationInfo': {
                  'created': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                  'creators': ['Tool: SelfSentry lockfile_sbom.py']},
              'documentComment': 'Lock entries only, including development/optional packages. '
                                 'No complete dependency edges, installed artifacts, OS/images '
                                 'or verified licenses. Inputs SHA-256: ' + json.dumps(hashes),
              'packages': packages}
    target = ROOT / 'docs/repository-audit/lockfile-sbom.spdx.json'
    if target.exists():
        previous = json.loads(target.read_text())
        if previous['documentNamespace'] == report['documentNamespace']:
            report['creationInfo'] = previous['creationInfo']
    target.write_text(json.dumps(report, indent=2) + '\n')
    print(f'{len(packages)} declared lock entries; unchanged dependency locks')


if __name__ == '__main__':
    main()
