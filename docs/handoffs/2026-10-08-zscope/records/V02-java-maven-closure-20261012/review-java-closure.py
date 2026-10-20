"""Independent evidence adjudication and archive. No runtime/test/model requests."""
import hashlib
import json
import pathlib
import shutil
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

LOCAL = pathlib.Path(__file__).resolve().parent
PREP = LOCAL / 'java-maven-preparation-20261012'
ROOT = pathlib.Path('/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope')
OLD = ROOT / 'docs/handoffs/2026-10-08-zscope/records/V02-current-TSAN-acceptance-20261012'
DEST = ROOT / 'docs/handoffs/2026-10-08-zscope/records/V02-java-maven-closure-20261012'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
read = lambda p: json.loads(p.read_text())
identity = PREP / 'prepared-artifact-manifest.json'
assert sha(identity) == '9eedca30b0cb8c602d43320bec2a43a7ed666a328555e2694833e43bd6403c4f'
assert all(sha(PREP / name) == info['sha256'] for name, info in read(identity)['files'].items())
r = read(PREP / 'java-two-nodes-result.json')
evidence = PREP / 'java-two-nodes-evidence'
assert r['status'] == 'two_nodes_passed_pending_independent_review' and r['exit_code'] == 0
assert not r['source_drift'] and not r['project_drift'] and not r['python_dependency_drift']
assert r['owned_container_cleanup']['exit_code'] == 0 and r['default_seccomp_unchanged'] and r['host_aslr_after'] == '2'
assert all(read(evidence / 'isolation.json')['checks'].values())
receipt = read(evidence / 'two-nodes-result.json')
assert receipt['counts'] == {'passed': 2, 'failed': 0, 'errors': 0, 'skipped': 0} and not receipt['audit_errors']
cases = list(ET.parse(evidence / 'two-nodes.xml').getroot().iter('testcase'))
assert len(cases) == 2 and all(c.find('skipped') is None and c.find('failure') is None and c.find('error') is None for c in cases)
new_nodes = ['tests/test_java_source_backend.py::' + c.attrib['name'] for c in cases]
old = read(OLD / 'ordinary-attempt5-evidence/ordinary-inside-result.json')
old_nodes = old['prior_compatibility_passed_reused'] + old['prior_remaining_passed_reused'] + old['clang_repair_nodes']
blocked = [x['node'] for x in old['blocked_java_nodes']]
assert set(new_nodes) == set(blocked)
assert len(old_nodes) == len(set(old_nodes)) == 1541
assert not set(old_nodes) & set(new_nodes)
assert set(old_nodes + new_nodes) == set(old['original_selected_nodes']) and len(old_nodes + new_nodes) == 1543
audit = read(evidence / 'subprocess-audit.json')
assert not audit['errors'] and len(audit['calls']) == 5
for call in audit['calls']:
    for stream in ('stdout', 'stderr'):
        assert sha(evidence / call[stream]['path']) == call[stream]['sha256']
assert [c['exit_code'] for c in audit['calls']] == [0, 0, 2, 0, 0]
jar_hashes = {x['sha256'] for x in receipt['generated_jars']}
for index in (1, 2, 4):
    assert audit['calls'][index]['jar_before_execution']['sha256'] in jar_hashes
assert audit['calls'][1]['jar_before_execution']['sha256'] == audit['calls'][2]['jar_before_execution']['sha256']
spoon = read(evidence / audit['calls'][1]['stdout']['path'])
ap = spoon['build']['annotation_processing']
assert spoon['frontend'] == 'spoon' and ap['enabled'] and ap['detected_lombok']
assert 'lombok_ecj_agent_incompatible' in ap['fallback_reason']
klass = next(x for x in spoon['classes'] if x['fullName'] == 'com.example.LombokController')
assert klass['fields']['log'] == 'org.slf4j.Logger'
method = next(x for x in klass['methods'] if x['name'] == 'run')
assert method['structure_precision'] == 'source_level_exact' and any(x['name'] == 'info' for x in method['calls'])
off_stderr = (evidence / audit['calls'][2]['stderr']['path']).read_text()
assert 'log cannot be resolved' in off_stderr or 'Spoon structure export failed' in off_stderr
jp = read(evidence / audit['calls'][4]['stdout']['path'])
assert jp['frontend'] == 'javaparser'
method = next(x for x in jp['classes'] if x['fullName'] == 'com.example.UserController')['methods'][0]
assert method['frontend'] == 'javaparser' and method['structure_precision'] == 'source_level_approx'
assert method['annotations'][0]['name'] == 'PostMapping' and method['calls'][0]['name'] == 'trim'
frozen = read(ROOT / 'docs/handoffs/2026-10-08-zscope/records/V01-V02-resource-repair-20261010/repo-format-validation.json')['inputs_after']
assert all(sha(ROOT / name) == h for name, h in frozen.items())
prior = read(OLD / 'acceptance-summary.json')
assert prior['ordinary_actual'] == {'passed': 1734, 'failed': 0, 'errors': 0, 'skipped': 2}
assert prior['TSAN'] == prior['ASAN'] == {'passed': 5, 'failed': 0, 'errors': 0, 'skipped': 0}
assert prior['quality_exit_codes'] == {'compileall-final': 0, 'mypy': 0}
assert all(sha(OLD / name) == info['sha256'] for name, info in read(OLD / 'evidence-manifest.json')['files'].items())
assert pathlib.Path('/proc/sys/kernel/randomize_va_space').read_text().strip() == '2'
assert sha(pathlib.Path('/usr/share/containers/seccomp.json')) == 'cc374cf23846ce1f62f4dc807a8e2b8673c783c6f56cb475467621035d281e6c'
containers = json.loads(subprocess.run(['podman', 'ps', '-a', '--format', 'json'], capture_output=True, text=True, check=True, timeout=30).stdout)
assert not any(r['container_name'] in c.get('Names', []) for c in containers)
review = {
    'checked_utc': datetime.now(timezone.utc).isoformat(), 'passed': True,
    'two_original_nodes': new_nodes, 'java_test_counts': receipt['counts'],
    'ordinary_compatibility_counts': {'passed': 1543, 'failed': 0, 'errors': 0, 'skipped': 0},
    'ordinary_total_counts': {'passed': 1736, 'failed': 0, 'errors': 0, 'skipped': 0},
    'composition': '193 original accepted group executions + disjoint compatibility nodes 1259 + 248 + 34 + 2',
    'old_1734_tests_reexecuted': 0, 'TSAN_ASAN_probes_or_models_reexecuted': 0,
    'raw_java_process_exit_codes': [c['exit_code'] for c in audit['calls']],
    'negative_control': 'Lombok off exits 2 with the original expected error; this is an asserted negative case, not a pytest failure.',
    'source_frozen_count': len(frozen), 'source_drift': [], 'product_or_test_changes': False,
    'image_id': r['image_id'], 'new_mounts_runtime_verified': True, 'source_and_tool_identities_verified': True,
    'same_image_offline_execution_observed': True, 'default_seccomp_unchanged': True,
    'old_sealed_evidence_unchanged': True, 'owned_container_remaining': False,
    'V01': 'done', 'V02': 'done_pending_handoff_validation',
}
(PREP / 'independent-java-review.json').write_text(json.dumps(review, indent=2) + '\n')
assert not DEST.exists()
shutil.copytree(PREP, DEST)
shutil.copyfile(pathlib.Path(__file__), DEST / 'review-java-closure.py')
summary = {'V01': 'done', 'V02': 'done_pending_handoff_validation', 'common_candidate_accepted_pending_handoff_validation': True,
           'image_id': r['image_id'], 'TSAN': prior['TSAN'], 'ASAN': prior['ASAN'],
           'ordinary': review['ordinary_total_counts'], 'compileall_mypy': prior['quality_exit_codes'],
           'prior_sealed_record': str(OLD), 'new_java_counts': receipt['counts'],
           'product_or_test_changes': False, 'old_tests_reexecuted': False, 'source_frozen_count': len(frozen)}
(DEST / 'closure-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
(DEST / 'evidence-manifest.json').write_text(json.dumps({'files': {p.relative_to(DEST).as_posix(): {'sha256': sha(p), 'bytes': p.stat().st_size}
    for p in DEST.rglob('*') if p.is_file()}}, indent=2) + '\n')
print(json.dumps({'independent_review_passed': True, 'ordinary': review['ordinary_total_counts'], 'product_changes': False, 'archive': str(DEST)}))
