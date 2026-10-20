"""Freeze the actual original Job failure without promoting downstream misses."""
from collections import Counter
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
JOB = ROOT / '.coordination/20261014/workspaces/job-runtime-footprint-repair-r34/artifacts/job_runtime_footprint_r34'
RED = JOB / 'runner-v7/red-lookup-v8'
OUT = ROOT / 'artifacts/coordinator-job-valid-red-audit-r35-20261017'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
read = lambda p: json.loads(Path(p).read_text(encoding='utf-8'))
if sys.platform != 'linux' or sys.flags.optimize:
    raise RuntimeError('Unoptimized Linux required')
pins = {
    RED / 'receipt.json': 'e502fb5cc94337f26c8a3689ad84714906b8030234591e1802f877ad624ea30b',
    RED / 'results.xml': 'f94451dede6f3dc92e44e4ac1f6d3533a803a712132347776822cf42c19af92b',
    JOB / 'red-lookup-v8-classification.json': '5043304bac12545e35a7fa6174ce112592c5b0d65defdf1c5438767ce2bf885c',
    ROOT / '.coordination/20261014/workspaces/shared-job-probes-r34/artifacts/shared_job_probes_r34/currentness-cause.json': 'e4b6a17402c955056faa318161e8c2c6a25e9054bea5076a4b04bc7a70611f0e',
}
assert all(sha(p) == digest for p, digest in pins.items())
raw = read(RED / 'receipt.json')
tree = ET.parse(RED / 'results.xml').getroot()
counter = Counter((n.get('classname', ''), n.get('name', '')) for n in tree.iter('testcase'))
rows = [list(key) + [count] for key, count in sorted(counter.items())]
counts = dict(tests=sum(counter.values()), failures=len(list(tree.iter('failure'))), errors=len(list(tree.iter('error'))), skipped=len(list(tree.iter('skipped'))))
assert counts == dict(tests=53, failures=33, errors=0, skipped=0)
assert raw['test_started'] and raw['evidence_guards_passed'] and raw['guards'] and all(v is True for v in raw['guards'].values())
assert raw['junit'] == counts and raw['case_counter'] == rows and raw['artifact_sha256']['results.xml'] == sha(RED / 'results.xml')
test_sha = 'ac34d7a64e0998e052780fc1f23283875781fc784d2c1141b52e3b827cc09b57'
assert raw['new_test_sha256'] == test_sha and any(row['returncode'] == 1 for row in raw['commands'])
classification = read(JOB / 'red-lookup-v8-classification.json')
assert classification['evidence_valid'] and classification['fixed_test_sha256'] == test_sha
by_id = {(r['classname'], r['name']): r for r in classification['cases']}
assert len(by_id) == len(counter) == 53 and set(by_id) == set(counter)
for node in tree.iter('testcase'):
    row = by_id[(node.get('classname', ''), node.get('name', ''))]
    failure = node.find('failure')
    assert row['outcome'] == ('failed' if failure is not None else 'passed')
    assert row['failure_message'] == (failure.get('message', '') if failure is not None else '')
original = ('tests.test_scan_session_jobs', 'test_job_scan_runs_exact_instances_on_the_queue')
assert counter[original] == 1 and by_id[original]['outcome'] == 'failed'
assert 'instance_semantics_not_current' in by_id[original]['failure_message']
cause = read(next(p for p in pins if p.name == 'currentness-cause.json'))
assert cause['diagnostic_evidence_valid'] is True and cause['primary_cause_confirmed'] is True
assert cause['all_input_host_guards'] and all(v is True for v in cause['all_input_host_guards'].values())
assert cause['freeze_event'] == 3 and cause['first_changed_namespace_event'] == 5
assert cause['freeze_statuses'] == ['current', 'current'] and cause['first_changed_statuses'] == ['stale_include_search', 'stale_include_search']
refs = {str(p): digest for p, digest in pins.items()}
refs[str(Path(__file__))] = sha(Path(__file__))
when = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
if OUT.exists():
    raise RuntimeError('Preserve previous audit')
OUT.mkdir()
projection = dict(actual_task='/root', checked_at=when, causal_review_passed=True,
    confirmed_target_failure_identities=[list(original)], actual53_classification=classification['cases'],
    interpretation='Original SessionJobs causal failure is confirmed by the independent first-write observer. Remaining outcomes are observations or unmet interfaces; no claim of 33 independently confirmed defects.',
    reference_sha256=refs)
path = OUT / 'causal-projection.json'
path.write_text(json.dumps(projection, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
refs = dict(refs, **{str(path): sha(path)})
audit = dict(schema='zscope.stage-native-job-valid-red.r35.v1', actual_task='/root', checked_at=when,
    causal_review_passed=True, evidence_guards_passed=True, results_xml=str(RED / 'results.xml'),
    results_xml_sha256=sha(RED / 'results.xml'), test_sha256=test_sha, case_counter=rows, junit=counts,
    raw_red_receipt=dict(path=str(RED / 'receipt.json'), sha256=sha(RED / 'receipt.json')),
    causal_projection=dict(path=str(path), sha256=sha(path)), valid_target_failure_identities=[list(original)],
    reference_sha256=refs, producer_green=False, independent_native_job_passed=False, stage_intake=False, root_intake=False)
(OUT / 'review.json').write_text(json.dumps(audit, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
print(json.dumps(dict(checked_at=when, actual_red=counts, confirmed_causal_targets=[list(original)], native_acceptance=False)))
