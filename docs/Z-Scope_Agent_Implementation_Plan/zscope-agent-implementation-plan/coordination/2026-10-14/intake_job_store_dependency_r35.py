"""Supply independently accepted Store bytes to the isolated Job candidate only."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
JOB = ROOT / '.coordination/20261014/workspaces/job-runtime-footprint-repair-r34/artifacts/job_runtime_footprint_r34'
WORK = JOB / 'candidate-src-v2'
COOR = ROOT / '.coordination/20261014/workspaces/coordinator-store-active-transactions-r35'
BASE = ROOT / 'artifacts/coordinator-store-active-transactions-r35-20261017'
OUT = ROOT / 'artifacts/job-runtime-footprint-repair-r34-20261017/store-readonly-dependency-override-r35'
FLOOR = ROOT / 'artifacts/stage-checkpoint-contract-intake-r34-20261017/receipt.json'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
read = lambda p: json.loads(Path(p).read_text(encoding='utf-8'))
if sys.platform != 'linux' or sys.flags.optimize:
    raise RuntimeError('Unoptimized Linux required')
assert sha(HERE / 'verify_store_independent_r35.py') == '932c5c2b296b8f9e4f376adba3090d54cc9f89de7199e4a98160e9fd74955540'
sys.path.insert(0, str(HERE))
from verify_store_independent_r35 import snapshot
freeze = JOB / 'python-candidate-v2/source-freeze.json'
override = ROOT / 'artifacts/job-runtime-footprint-repair-r34-20261017/hook-fixture-readonly-override-r35/receipt.json'
assert sha(freeze) == 'a144dda18e558a6213a5956c2b1e99e80c4075c147f0cb1392dbe5b0b352fa14'
assert sha(override) == '3b86cb981d7bbd067ea7b9883e691e3791af6c4567bed352b4de99d3952b6824'
frozen = read(freeze)['full_candidate_sha256']
frozen[read(override)['path']] = read(override)['after_sha256']
before = snapshot(WORK)
assert len(before) == 1083 and before == frozen
independent_path = BASE / 'independent/review.json'
independent = read(independent_path)
assert independent['actual_task'] == '/root' and independent['passed'] is True
assert independent['gates'] and all(v is True for v in independent['gates'].values())
assert len(independent['commands']) == 8 and all(row['returncode'] == 0 for row in independent['commands'])
assert independent['junit'] == {'results.xml': dict(tests=369, failures=0, errors=0, skipped=0), 'trace.xml': dict(tests=5, failures=0, errors=0, skipped=0), 'long-usr.xml': dict(tests=1, failures=0, errors=0, skipped=0)}
assert independent['source_before'] == independent['source_after'] == snapshot(COOR)
paths = independent['owned_sources_sha256']
assert len(paths) == 3 and all(sha(COOR / name) == digest for name, digest in paths.items())
assert sha(FLOOR) == 'b9d8cc7874d3f224f514ec43feebad99f75eb659a9aa194ec068545dc605a69f'
floor = read(FLOOR)
stage = ROOT / '.coordination/20261014/workspaces/coordinator-instance-integration-r24'
assert snapshot(stage) == floor['complete_inputs_after']
assert all(sha(ROOT / name) == digest for name, digest in floor['root_inputs'].items())
source_review = ROOT / 'artifacts/store-active-transactions-source-review-r35-20261017/final-three-source-review.json'
assert sha(source_review) == 'fdd54d2ed825f5850581963e8b0eed164b24d10f9b0497cc18754ed462950343'
assert read(source_review)['owned_sources_sha256'] == paths
if OUT.exists():
    raise RuntimeError('Preserve previous dependency intake')
OUT.mkdir()
for name in paths:
    target = WORK / name
    if target.exists():
        saved = OUT / 'original-candidate' / name
        saved.parent.mkdir(parents=True, exist_ok=True)
        saved.write_bytes(target.read_bytes())
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes((COOR / name).read_bytes())
after = snapshot(WORK)
expected = dict(before, **paths)
assert after == expected and len(after) == 1085
assert snapshot(stage) == floor['complete_inputs_after'] and all(sha(ROOT / name) == digest for name, digest in floor['root_inputs'].items())
refs = {str(p): sha(p) for p in (independent_path, source_review, freeze, override, FLOOR, Path(__file__), BASE / 'independent/results.xml', BASE / 'independent/trace.xml', BASE / 'independent/long-usr.xml')}
record = dict(actual_task='/root', applied_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(),
    candidate_source_root=str(WORK), full_source_before=before, full_source_after=after,
    owned_sources_sha256=paths, reference_sha256=refs, independent_store_passed=True,
    candidate_dependency_paths_worker_readonly=True, original_red53_bytes_unchanged=after['tests/test_job_runtime_footprint_r34.py'] == 'ac34d7a64e0998e052780fc1f23283875781fc784d2c1141b52e3b827cc09b57',
    stage1082_root1065_unchanged=True, job_native_behavior_accepted=False, stage_intake=False, root_intake=False)
(OUT / 'receipt.json').write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
adapter = dict(schema='zscope.stage-store-evidence.r35.v1', actual_task='/root', checked_at=record['applied_at'], independent_store_passed=True,
    owned_sources_sha256=paths, complete_inputs_sha256=independent['source_before'],
    results_xml=str(BASE / 'independent/results.xml'), results_xml_sha256=sha(BASE / 'independent/results.xml'),
    trace_results_xml=str(BASE / 'independent/trace.xml'), trace_results_xml_sha256=sha(BASE / 'independent/trace.xml'),
    case_counter=independent['case_counters']['results.xml'], trace_case_counter=independent['case_counters']['trace.xml'],
    independent_command_returncodes=[row['returncode'] for row in independent['commands']], reference_sha256=refs,
    stage_intake=False, root_intake=False, new_native_acceptance=False)
(BASE / 'stage-evidence-adapter.json').write_text(json.dumps(adapter, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
print(json.dumps(dict(applied_at=record['applied_at'], candidate_inputs=len(after), source_paths=paths, stage_intake=False, root_intake=False)))
