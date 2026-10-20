"""Validate the handoff update in WSL and seal an append-only evidence index."""
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import yaml

ROOT = pathlib.Path('/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope')
RECORDS = ROOT / 'docs/handoffs/2026-10-08-zscope/records'
DEST = RECORDS / 'V01-current-ASAN-acceptance-20261010'
HANDOFF = ROOT / 'docs/handoffs/2026-10-08-zscope'
REPORT = RECORDS / 'V01-current-ASAN-acceptance-20261010.md'
OLD = RECORDS / 'V01-V02-resource-repair-20261010'

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def read(path):
    return json.loads(path.read_text(encoding='utf-8'))

def save(path, data):
    with path.open('x', encoding='utf-8', newline='\n') as file:
        json.dump(data, file, ensure_ascii=False, indent=2)
        file.write('\n')

assert sys.platform == 'linux'
asan = read(DEST / 'current-asan-result.json')
assert all(digest(ROOT / rel) == h for rel, h in asan['inputs_after'].items())
checks = []
env = {key: os.environ[key] for key in ('PATH', 'HOME', 'USER', 'LANG', 'LC_ALL', 'TZ') if key in os.environ}
env.update(PYTEST_DISABLE_PLUGIN_AUTOLOAD='1', PYTHONDONTWRITEBYTECODE='1')
for label, command in (
    ('handoff-docs', [sys.executable, '-m', 'pytest', '-q', '-p', 'no:cacheprovider', '--tb=short', '--junitxml=' + str(DEST / 'handoff-docs.xml'), 'tests/test_agent_docs.py']),
    ('git-diff-check', ['git', '-c', 'core.whitespace=cr-at-eol', 'diff', '--check']),
):
    start = time.monotonic()
    stdout = DEST / (label + '.stdout.log')
    stderr = DEST / (label + '.stderr.log')
    with stdout.open('xb') as out, stderr.open('xb') as err:
        proc = subprocess.run(command, cwd=ROOT, env=env, stdout=out, stderr=err, timeout=90)
    checks.append({'label': label, 'command': command, 'cwd': str(ROOT), 'exit_code': proc.returncode, 'elapsed_seconds': round(time.monotonic() - start, 3), 'stdout': stdout.name, 'stderr': stderr.name})
    assert proc.returncode == 0, label + ' failed; original logs preserved'

cases = list(ET.parse(DEST / 'handoff-docs.xml').getroot().iter('testcase'))
counts = dict(passed=0, failed=0, errors=0, skipped=0)
for case in cases:
    state = 'errors' if case.find('error') is not None else 'failed' if case.find('failure') is not None else 'skipped' if case.find('skipped') is not None else 'passed'
    counts[state] += 1
assert counts == dict(passed=6, failed=0, errors=0, skipped=0)

markdowns = [REPORT, HANDOFF / 'PROGRESS.md']
encoding_checks = {}
for path in markdowns:
    raw = path.read_bytes()
    raw.decode('utf-8', errors='strict')
    encoding_checks[path.relative_to(ROOT).as_posix()] = {'utf8': True, 'no_bom': not raw.startswith(b'\xef\xbb\xbf'), 'LF_only': b'\r' not in raw, 'final_newline': raw.endswith(b'\n')}
    assert all(encoding_checks[path.relative_to(ROOT).as_posix()].values())
tasks = yaml.safe_load((HANDOFF / 'TASKS.yaml').read_text(encoding='utf-8'))
task_map = {task['id']: task for task in tasks['tasks']}
assert task_map['V01']['status'] == 'done' and task_map['V01']['blocking_reason'] is None
assert task_map['V02']['status'] == 'blocked' and task_map['V02']['blocking_reason']
assert task_map['V01']['result_record'] == task_map['V02']['result_record'] == 'records/V01-current-ASAN-acceptance-20261010.md'
prior = read(OLD / 'final-evidence-manifest.json')
changes = [rel for rel, before in prior['source_and_test'].items() if digest(ROOT / rel) != before]
assert sorted(changes) == sorted(['docs/handoffs/2026-10-08-zscope/TASKS.yaml', 'docs/handoffs/2026-10-08-zscope/PROGRESS.md'])
changed_inputs = [rel for rel, h in asan['inputs_after'].items() if digest(ROOT / rel) != h]
assert not changed_inputs

result = {
    'at': datetime.now(timezone.utc).isoformat(), 'linux_python': sys.executable,
    'source_sha256': asan['source_sha256'], 'checks': checks, 'docs_counts': counts,
    'markdown_encoding_checks': encoding_checks,
    'current_ASAN_counts': asan['counts'],
    'changed_existing_inputs': changed_inputs, 'existing_input_count': 403,
    'declared_existing_handoff_changes': changes,
    'product_or_test_changes': False, 'new_TSAN_probe_or_fixture_executions': 0,
    'new_external_dispatch': False, 'V01': 'done', 'V02': 'blocked',
}
save(DEST / 'final-validation.json', result)
shutil.copyfile(pathlib.Path(__file__), DEST / 'finalize.py')
artifacts = {path.relative_to(DEST).as_posix(): {'bytes': path.stat().st_size, 'sha256': digest(path)} for path in sorted(DEST.rglob('*')) if path.is_file()}
index = {
    'at': datetime.now(timezone.utc).isoformat(),
    'source_sha256': asan['source_sha256'],
    'source_and_handoff': {path.relative_to(ROOT).as_posix(): digest(path) for path in (ROOT / 'zscope/core/validation/dynamic_reproduction.py', ROOT / 'tests/test_dynamic_reproduction.py', ROOT / 'tests/test_dynamic_reproduction_execution.py', HANDOFF / 'TASKS.yaml', HANDOFF / 'PROGRESS.md', REPORT)},
    'current_ASAN_counts': asan['counts'], 'docs_counts': counts,
    'previous_ordinary_counts': prior['ordinary_counts'],
    'previous_compileall_exit': prior['compileall_exit'], 'previous_mypy_exit': prior['mypy_exit'],
    'existing_input_count': 403, 'changed_existing_inputs': [],
    'declared_handoff_changes': changes,
    'V01': 'done', 'V02': 'blocked', 'real_TSAN': 'not_run',
    'artifacts': artifacts,
}
save(DEST / 'final-evidence-manifest.json', index)
assert all(digest(DEST / rel) == info['sha256'] for rel, info in artifacts.items())
assert all(digest(ROOT / rel) == h for rel, h in index['source_and_handoff'].items())
print(json.dumps({'docs': counts, 'current_ASAN': asan['counts'], 'artifacts_verified': len(artifacts), 'changed_inputs': changed_inputs, 'V01': 'done', 'V02': 'blocked'}))
