"""Seal completed gates and current handoff; do not re-run any fixture or model."""
import hashlib
import json
import pathlib
import shutil
import subprocess
import zipfile
from datetime import datetime, timezone
import yaml

LOCAL = pathlib.Path(__file__).resolve().parent
ROOT = pathlib.Path('/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope')
PREP = LOCAL / 'java-maven-preparation-20261012'
DEST = ROOT / 'docs/handoffs/2026-10-08-zscope/records/V02-java-maven-closure-20261012'
OLD = ROOT / 'docs/handoffs/2026-10-08-zscope/records/V02-current-TSAN-acceptance-20261012'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
read = lambda p: json.loads(p.read_text())
docs_dir = LOCAL / 'java-closure-docs-20261012'
docs = read(docs_dir / 'docs-container-result.json')
assert docs['status'] == 'passed' and docs['counts'] == {'passed': 6, 'failed': 0, 'errors': 0, 'skipped': 0}
assert not docs['changed_inputs'] and docs['isolation']['verified'] and docs['owned_container_cleanup']['exit_code'] == 0
review = read(DEST / 'independent-java-review.json')
assert review['passed'] and review['ordinary_total_counts'] == {'passed': 1736, 'failed': 0, 'errors': 0, 'skipped': 0}
manifest = read(PREP / 'input-manifest.json')
run = read(PREP / 'java-two-nodes-result.json')
work = pathlib.Path(run['work'])
assert run['two_nodes']['counts'] == {'passed': 2, 'failed': 0, 'errors': 0, 'skipped': 0}
for entry in manifest['files']:
    assert sha(pathlib.Path(entry['physical_source'])) == entry['sha256']
    assert sha(work / 'tool-inputs' / entry['destination']) == entry['sha256']
for entry in manifest['project_files']:
    assert sha(pathlib.Path(entry['source'])) == entry['sha256']
frozen = read(ROOT / 'docs/handoffs/2026-10-08-zscope/records/V01-V02-resource-repair-20261010/repo-format-validation.json')['inputs_after']
assert len(frozen) == 403 and all(sha(ROOT / name) == h for name, h in frozen.items())
assert all(sha(OLD / name) == info['sha256'] for name, info in read(OLD / 'evidence-manifest.json')['files'].items())
protected = {
    '/mnt/c/Users/10273/.kimi-code/config.toml': 'f732186f6a5b8d16f29489d78140034b01893ad3c333796a0098cfd5f0311403',
    '/mnt/c/Users/10273/.agent-bridge/agents.toml': 'f3e114415838ba0b35ef78c5d8193acdd120db39cc623f69cc2c4a3408a48cc7',
    '/mnt/c/Users/10273/AppData/Roaming/uv/tools/agent-bridge/Lib/site-packages/agent_bridge/probes.py': '00db25ef02a51255125aac70647da09d1eb1df65b04d28b0aa22c8f65d9274a4',
    '/mnt/c/Users/10273/AppData/Roaming/uv/tools/agent-bridge/Lib/site-packages/agent_bridge/adapters/acp.py': '24be1a984b8a600053ae6c03aba1d1d39280d48b530a5cee8cab2ee509bfd11d',
    '/usr/share/containers/seccomp.json': 'cc374cf23846ce1f62f4dc807a8e2b8673c783c6f56cb475467621035d281e6c',
}
assert all(sha(pathlib.Path(path)) == h for path, h in protected.items())
assert pathlib.Path('/proc/sys/kernel/randomize_va_space').read_text().strip() == '2'
assert int(pathlib.Path('/proc/self/personality').read_text().strip(), 16) == 0
image = json.loads(subprocess.run(['podman', 'image', 'inspect', manifest['image_id']], capture_output=True, text=True, check=True, timeout=30).stdout)[0]
assert image['Id'].removeprefix('sha256:') == manifest['image_id']
head = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
assert head == read(OLD / 'final-integrity-proof.json')['HEAD']
tasks = yaml.safe_load((ROOT / 'docs/handoffs/2026-10-08-zscope/TASKS.yaml').read_text())['tasks']
assert next(x for x in tasks if x['id'] == 'V01')['status'] == 'done'
v02 = next(x for x in tasks if x['id'] == 'V02')
assert v02['status'] == 'done' and v02['result_record'] == 'records/V02-java-maven-closure-20261012.md'
for path in [ROOT / 'docs/handoffs/2026-10-08-zscope/TASKS.yaml', ROOT / 'docs/handoffs/2026-10-08-zscope/PROGRESS.md',
             ROOT / 'docs/handoffs/2026-10-08-zscope/records/V02-java-maven-closure-20261012.md']:
    raw = path.read_bytes()
    assert not raw.startswith(b'\xef\xbb\xbf') and b'\r' not in raw and raw.endswith(b'\n')
    raw.decode('utf-8', errors='strict')
diff = subprocess.run(['git', '-c', 'core.autocrlf=true', 'diff', '--check'], cwd=ROOT, capture_output=True, text=True, timeout=60)
assert diff.returncode == 0
owned = read(OLD / 'final-integrity-proof.json')['owned_container_names'] + [run['container_name'], docs['command'][docs['command'].index('--name') + 1]]
containers = json.loads(subprocess.run(['podman', 'ps', '-a', '--format', 'json'], capture_output=True, text=True, check=True, timeout=30).stdout)
assert not any(any(name in c.get('Names', []) for name in owned) for c in containers)
maven_core = next(e for e in manifest['files'] if e['destination'] == 'maven/lib/maven-core-3.x.jar')
with zipfile.ZipFile(maven_core['physical_source']) as archive:
    props = archive.read('META-INF/maven/org.apache.maven/maven-core/pom.properties').decode()
assert 'version=3.8.7' in props
jdk_release = next(e for e in manifest['files'] if e['destination'] == 'jdk/release')
assert 'JAVA_VERSION="21.0.12.1"' in pathlib.Path(jdk_release['physical_source']).read_text()
assert not (DEST / 'final-docs-result.json').exists()
shutil.copyfile(docs_dir / 'docs-container-result.json', DEST / 'final-docs-result.json')
shutil.copytree(docs_dir / 'docs-container-evidence', DEST / 'final-docs-evidence')
for name in ('docs-container.py', 'docs-inside.py'):
    shutil.copyfile(docs_dir / name, DEST / ('final-' + name))
summary = read(DEST / 'closure-summary.json')
summary['V02'] = 'done'
summary.pop('common_candidate_accepted_pending_handoff_validation')
summary['common_candidate_accepted'] = True
summary['final_documentation'] = docs['counts']
summary['new_java_test_attempts'] = 1
summary['owned_containers_remaining'] = []
summary['old_1734_and_sanitizers_reexecuted'] = 0
(DEST / 'closure-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
proof = {
    'checked_utc': datetime.now(timezone.utc).isoformat(), 'HEAD': head, 'V01': 'done', 'V02': 'done',
    'image_id': manifest['image_id'], 'common_candidate_accepted_for_approved_scope': True,
    'TSAN': summary['TSAN'], 'ASAN': summary['ASAN'], 'ordinary': summary['ordinary'],
    'new_java_nodes': run['two_nodes']['counts'], 'compileall_mypy': summary['compileall_mypy'], 'final_documentation': docs['counts'],
    'original_frozen_inputs': 403, 'changed_frozen_inputs': [], 'new_project_inputs': len(manifest['project_files']),
    'new_tool_unique_sources': 3510, 'normalized_targets': 3579, 'tool_source_and_staged_hashes_verified': True,
    'jdk_version': '21.0.12.1', 'maven_version': '3.8.7', 'actual_copy_bytes': run['actual_copy_bytes'],
    'prepared_manifest_sha256': run['prepared_manifest_sha256'], 'old_sealed_evidence_unchanged': True,
    'product_or_test_changes_this_continuation': False, 'old_1734_tests_or_sanitizers_reexecuted': 0,
    'model_requests_and_material_exports': 0, 'protected_config_and_bridge_files_unchanged': True,
    'host_aslr': '2', 'parent_personality': '0', 'default_profile_unchanged': True,
    'owned_container_names': owned, 'owned_containers_remaining': [],
    'owned_tool_snapshot_preserved_for_review': str(work), 'rollback_script_not_executed': True,
    'git_diff_check': {'exit_code': diff.returncode, 'stdout': diff.stdout, 'stderr': diff.stderr, 'configuration': 'core.autocrlf=true per command, matching Windows checkout'},
    'scope_limit': 'Approved bounded fixtures/common ordinary matrix; no CBMC/generator/formal Range/portable release claim',
}
(DEST / 'final-integrity-proof.json').write_text(json.dumps(proof, indent=2) + '\n')
shutil.copyfile(pathlib.Path(__file__), DEST / 'finalize-java-closure.py')
(DEST / 'evidence-manifest.json').write_text(json.dumps({'files': {p.relative_to(DEST).as_posix(): {'sha256': sha(p), 'bytes': p.stat().st_size}
    for p in DEST.rglob('*') if p.is_file() and p.name != 'evidence-manifest.json'}}, indent=2) + '\n')
assert all(sha(DEST / name) == info['sha256'] for name, info in read(DEST / 'evidence-manifest.json')['files'].items())
print(json.dumps({k: proof[k] for k in ('V01', 'V02', 'ordinary', 'new_java_nodes', 'compileall_mypy', 'final_documentation', 'changed_frozen_inputs', 'owned_containers_remaining')}))
