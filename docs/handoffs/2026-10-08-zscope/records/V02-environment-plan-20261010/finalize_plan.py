"""Archive the read-only plan and verify docs; proposed scripts are never run."""
import ast
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import yaml

HERE = pathlib.Path(__file__).resolve().parent
ROOT = pathlib.Path('/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope')
HANDOFF = ROOT / 'docs/handoffs/2026-10-08-zscope'
DEST = HANDOFF / 'records/V02-environment-plan-20261010'
REPORT = HANDOFF / 'records/V02-environment-plan-20261010.md'
PREVIOUS = HANDOFF / 'records/V01-current-ASAN-acceptance-20261010'

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def read(path):
    return json.loads(path.read_text(encoding='utf-8'))

def save(path, data):
    with path.open('x', encoding='utf-8', newline='\n') as file:
        json.dump(data, file, ensure_ascii=False, indent=2)
        file.write('\n')

assert sys.platform == 'linux'
assert not DEST.exists()
old = read(PREVIOUS / 'final-evidence-manifest.json')
for rel, info in old['artifacts'].items():
    assert digest(PREVIOUS / rel) == info['sha256'], rel
source_changes = [rel for rel, before in old['source_and_handoff'].items() if digest(ROOT / rel) != before]
assert sorted(source_changes) == sorted(['docs/handoffs/2026-10-08-zscope/TASKS.yaml', 'docs/handoffs/2026-10-08-zscope/PROGRESS.md'])
asan = read(PREVIOUS / 'current-asan-result.json')
assert all(digest(ROOT / rel) == before for rel, before in asan['inputs_after'].items())
parsed = []
for path in HERE.glob('*.py'):
    ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
    parsed.append(path.name)

# Check the proposed bundle still describes installed files, without staging them.
bundle = read(HERE / 'proposed-bundle-manifest.json')
assert bundle['file_count'] == 397 and bundle['total_file_bytes'] == 299239592
assert all(digest(pathlib.Path(item['source'])) == item['sha256'] for item in bundle['files'].values())
DEST.mkdir()
for path in HERE.iterdir():
    if path.is_file():
        shutil.copyfile(path, DEST / path.name)
env = {key: os.environ[key] for key in ('PATH', 'HOME', 'USER', 'LANG', 'LC_ALL', 'TZ') if key in os.environ}
env.update(PYTHONDONTWRITEBYTECODE='1', PYTEST_DISABLE_PLUGIN_AUTOLOAD='1')
checks = []
for label, argv in (
    ('handoff-docs', [sys.executable, '-m', 'pytest', '-q', '-p', 'no:cacheprovider', '--tb=short', '--junitxml=' + str(DEST / 'handoff-docs.xml'), 'tests/test_agent_docs.py']),
    ('git-diff-check', ['git', '-c', 'core.whitespace=cr-at-eol', 'diff', '--check']),
):
    with (DEST / (label + '.stdout.log')).open('xb') as out, (DEST / (label + '.stderr.log')).open('xb') as err:
        result = subprocess.run(argv, cwd=ROOT, env=env, stdout=out, stderr=err, timeout=90)
    checks.append({'label': label, 'argv': argv, 'exit_code': result.returncode})
    assert result.returncode == 0, label
cases = list(ET.parse(DEST / 'handoff-docs.xml').getroot().iter('testcase'))
assert len(cases) == 6 and not any(case.find(tag) is not None for case in cases for tag in ('failure', 'error', 'skipped'))
for path in (REPORT, HANDOFF / 'PROGRESS.md', HANDOFF / 'TASKS.yaml'):
    raw = path.read_bytes()
    raw.decode('utf-8', errors='strict')
    assert not raw.startswith(b'\xef\xbb\xbf') and b'\r' not in raw and raw.endswith(b'\n')
tasks = {item['id']: item for item in yaml.safe_load((HANDOFF / 'TASKS.yaml').read_text(encoding='utf-8'))['tasks']}
assert tasks['V01']['status'] == 'done'
assert tasks['V02']['status'] == 'blocked' and tasks['V02']['result_record'] == 'records/V02-environment-plan-20261010.md'
assert all(digest(ROOT / rel) == before for rel, before in asan['inputs_after'].items())
result = {
    'at': datetime.now(timezone.utc).isoformat(), 'checks': checks,
    'docs_counts': {'passed': 6, 'failed': 0, 'errors': 0, 'skipped': 0},
    'python_syntax_only': parsed, 'proposed_scripts_executed': False,
    'proposed_bundle_files': 397, 'proposed_bundle_bytes': 299239592,
    'installed_bundle_file_hashes_verified': True,
    'previous_ASAN_archive_artifacts_verified': len(old['artifacts']),
    'existing_input_count': 403, 'changed_existing_inputs': [],
    'declared_handoff_changes': source_changes, 'product_or_test_changes': False,
    'new_containers': 0, 'probe_or_fixture_builds': 0, 'probe_or_fixture_executions': 0,
    'software_asset_downloads': 0, 'software_installs': 0, 'model_dispatches': 0,
    'source_sha256': asan['source_sha256'], 'V01': 'done', 'V02': 'blocked/not_run',
}
save(DEST / 'final-validation.json', result)
manifest = {'at': result['at'], 'V01': 'done', 'V02': 'blocked/not_run', 'source_sha256': asan['source_sha256'], 'handoff': {path.relative_to(ROOT).as_posix(): digest(path) for path in (REPORT, HANDOFF / 'TASKS.yaml', HANDOFF / 'PROGRESS.md')}, 'artifacts': {path.relative_to(DEST).as_posix(): {'bytes': path.stat().st_size, 'sha256': digest(path)} for path in sorted(DEST.rglob('*')) if path.is_file()}}
save(DEST / 'final-evidence-manifest.json', manifest)
assert all(digest(DEST / rel) == info['sha256'] for rel, info in manifest['artifacts'].items())
print(json.dumps({key: result[key] for key in ('docs_counts', 'proposed_bundle_files', 'proposed_bundle_bytes', 'previous_ASAN_archive_artifacts_verified', 'changed_existing_inputs', 'new_containers', 'probe_or_fixture_executions', 'V01', 'V02')}))
