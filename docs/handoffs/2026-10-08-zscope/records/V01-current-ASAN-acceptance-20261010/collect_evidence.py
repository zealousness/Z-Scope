"""Read-only identity checks and append-only archival of this acceptance round."""
import collections
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
from datetime import datetime, timezone

ROOT = pathlib.Path('/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope')
LOCAL = pathlib.Path(__file__).resolve().parent
RECORDS = ROOT / 'docs/handoffs/2026-10-08-zscope/records'
DEST = RECORDS / 'V01-current-ASAN-acceptance-20261010'
OLD = RECORDS / 'V01-V02-resource-repair-20261010'
READINESS = RECORDS / 'V01-V02-resource-repair-readiness-20261010'

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def read(path):
    return json.loads(path.read_text(encoding='utf-8'))

def save(path, data):
    with path.open('x', encoding='utf-8', newline='\n') as file:
        json.dump(data, file, ensure_ascii=False, indent=2)
        file.write('\n')

asan = read(LOCAL / 'current-asan-result.json')
evidence = pathlib.Path(asan['archived_evidence'])
observed = read(evidence / 'observed-executions.json')
toolchain = read(evidence / 'toolchain-preflight.json')
assert asan['status'] == 'asan_checks_passed'
assert asan['counts'] == dict(passed=5, failed=0, errors=0, skipped=0)
assert asan['isolation']['verified'] and not asan['changed_inputs']
assert not observed['observer_errors']
assert asan['owned_container_cleanup']['exit_code'] == 0
assert len(asan['inputs_before']) == 403
assert all(digest(ROOT / rel) == h for rel, h in asan['inputs_after'].items())
assert all(digest(evidence / rel) == info['sha256'] for rel, info in asan['evidence_files'].items())

prior = read(OLD / 'final-evidence-manifest.json')
assert prior['source_sha256'] == asan['source_sha256']
assert prior['ordinary_counts'] == dict(passed=1736, failed=0, errors=0, skipped=0)
assert all(digest(ROOT / rel) == h for rel, h in prior['source_and_test'].items())
for rel, info in prior['artifacts'].items():
    assert digest(OLD / rel) == info['sha256'], 'previous archive drift: ' + rel

replays, executions, raw_count = [], [], collections.Counter()
for event in observed['events']:
    if event['event'] == 'raw_runner_process':
        raw_count[event['tag'].split('-')[0]] += 1
        for value in event['streams'].values():
            path = evidence / 'raw' / pathlib.Path(value['path']).name
            assert path.stat().st_size == value['bytes'] and digest(path) == value['sha256']
    if event['event'] == 'execute':
        rec = event['evidence']
        executions.append({
            'node': event['node'],
            **{key: rec.get(key) for key in ('outcome', 'detail', 'binary_digest', 'binary_identity_source', 'input_verification_digest', 'build_exit_code')},
            'findings': [{'kind': f['kind'], 'site': f['site'], 'source_mapping': f['source_mapping']} for f in rec.get('findings', [])],
            'run_count': len(rec.get('runs', [])),
            'output_truncated': any(run['output_truncated'] for run in rec.get('runs', [])),
        })
    if event['event'] == 'replay_witness':
        rec = event['evidence']
        assert rec['consistent'] is True
        replays.append({'node': event['node'], 'consistent': rec['consistent'], 'binary_digest': rec['binary_digest'], 'classifications': rec['classifications']})
assert len(executions) == 13 and len(replays) == 4
assert sum(e['run_count'] for e in executions) == 12
assert not any(e['output_truncated'] for e in executions)

old_inventory_outer = read(READINESS / 'V01-V02-TSAN-inventory-20261010-i7jo5c81.json')
old_inventory = read(READINESS / 'toolchain-inventory-evidence/existing-toolchain-inventory.json')
assert old_inventory_outer['image_id'] == asan['image_id']
assert old_inventory['distinct_compiler_count'] == 1
old_compiler = next(iter(old_inventory['unique_compilers'].values()))
assert toolchain['compiler_sha256'] == old_compiler['sha256']
host_inventory_path = READINESS / 'TSAN-existing-host-toolchain-inventory-20261010.json'
host_inventory = read(host_inventory_path)
host_current = []
for item in host_inventory['compilers']:
    compiler = pathlib.Path(item['compiler'])
    runtime = pathlib.Path(item['runtime'])
    host_current.append({
        'compiler': str(compiler), 'compiler_sha256': digest(compiler) if compiler.is_file() else None,
        'compiler_unchanged': compiler.is_file() and digest(compiler) == item['sha256'],
        'runtime': str(runtime), 'runtime_sha256': digest(runtime) if runtime.is_file() else None,
        'runtime_unchanged': runtime.is_file() and digest(runtime) == item['runtime_sha256'],
        'compiler_or_fixture_executed': False,
    })
diagnostic = {
    'at': datetime.now(timezone.utc).isoformat(),
    'kernel': os.uname().release,
    'current_approved_image_id': asan['image_id'],
    'immutable_image_matches_previous_inventory': True,
    'current_ASAN_compiler_matches_previous_inventory': True,
    'approved_image_distinct_compilers': 1,
    'approved_image_compiler': old_compiler,
    'host_existing_toolchains': host_current,
    'host_toolchains_approved_inside_container': False,
    'new_TSAN_probe_executions': 0,
    'new_thread_fixture_builds': 0,
    'new_thread_fixture_executions': 0,
    'TSAN_status': 'blocked/not_run',
    'historical_runtime_error': 'FATAL: ThreadSanitizer: unexpected memory mapping',
    'root_cause_beyond_observed_startup_failure': 'not established',
    'minimum_missing_condition': 'A compatible TSAN compiler/runtime runnable in an approved offline nonroot environment with equivalent isolation; the approved immutable image has no alternate runtime.',
    'security_or_mount_changes': False,
    'downloads_or_installs': False,
    'previous_inventory_sha256': digest(READINESS / 'toolchain-inventory-evidence/existing-toolchain-inventory.json'),
    'previous_inventory_outer_sha256': digest(READINESS / 'V01-V02-TSAN-inventory-20261010-i7jo5c81.json'),
    'previous_host_inventory_sha256': digest(host_inventory_path),
}
save(LOCAL / 'tsan-current-diagnostic.json', diagnostic)

bridge_base = pathlib.Path('/mnt/c/Users/10273/Documents/Codex/2026-10-10/task-3/e2e-checks/20261010T080545Z')
patch = bridge_base / 'route.patch.yml'
patch_hash = digest(patch)
assert patch_hash == 'c5ba097daaf9e2037852817a8703c2ad609f9e144db7024a99b632b22613021d'
bridge = {
    'coordinator_message_received': True,
    'connection_evidence': str(bridge_base / 'result-summary.json'),
    'process_route_patch_sha256': patch_hash,
    'connection_only': True,
    'project_tools_or_sandbox_qualified': False,
    'new_dispatch': False, 'new_external_payload': False,
    'long_term_configuration_changed': False,
}
save(LOCAL / 'bridge-materials-receipt.json', bridge)

summary = {
    'at': datetime.now(timezone.utc).isoformat(),
    'source_sha256': asan['source_sha256'],
    'current_ASAN_counts': asan['counts'],
    'current_ASAN_elapsed_seconds': asan['elapsed_seconds'],
    'isolation_verified': True,
    'existing_inputs_count': 403,
    'changed_existing_inputs': [],
    'prior_archive_artifacts_verified': len(prior['artifacts']),
    'previous_ordinary_counts': prior['ordinary_counts'],
    'previous_ordinary_not_rerun': 'Same 403 inputs, no product/test changes this round; current real ASAN and handoff checks are new.',
    'previous_compileall_exit': prior['compileall_exit'],
    'previous_mypy_exit': prior['mypy_exit'],
    'executions': executions, 'independent_replays': replays,
    'fixture_runs': 12, 'runner_invocations': 13, 'raw_runner_processes': dict(raw_count),
    'raw_log_files': observed['raw_files'], 'raw_log_bytes': observed['raw_bytes'],
    'observer_errors': [],
    'original_V01_minimum_gate_result': 'passed; subject to final handoff checks',
    'V02': 'blocked/not_run',
    'new_external_dispatch': False,
}
save(LOCAL / 'acceptance-summary.json', summary)

DEST.mkdir(exist_ok=False)
for name in ('prepare_asan.py', 'current-asan-container.py', 'current-asan-inside.py', 'driver-preparation.json', 'current-asan-result.json', 'tsan-current-diagnostic.json', 'bridge-materials-receipt.json', 'acceptance-summary.json', 'collect_evidence.py'):
    shutil.copyfile(LOCAL / name, DEST / name)
shutil.copytree(evidence, DEST / 'ASAN-evidence')
save(DEST / 'prior-evidence-link.json', {'path': str(OLD / 'final-evidence-manifest.json'), 'sha256': digest(OLD / 'final-evidence-manifest.json'), 'verified_artifact_count': len(prior['artifacts'])})
print(json.dumps({key: summary[key] for key in ('source_sha256', 'current_ASAN_counts', 'existing_inputs_count', 'prior_archive_artifacts_verified', 'fixture_runs', 'V02')}))
