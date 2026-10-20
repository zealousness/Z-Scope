"""Coordinator intake of an idle, unfixed native candidate for the third-TU probe."""
from pathlib import Path
from collections import Counter
import datetime as dt
import hashlib
import json
import sys
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
JOB = ROOT / '.coordination/20261014/workspaces/job-runtime-footprint-repair-r34/artifacts/job_runtime_footprint_r34'
SOURCE = JOB / 'candidate-src-v2'
WORK = ROOT / '.coordination/20261014/workspaces/coordinator-indexed-input-prewrite-r35'
BASE = ROOT / 'artifacts/coordinator-indexed-input-prewrite-r35-20261017'
NEW_TEST = 'tests/test_job_indexed_input_prewrite_r35.py'
DRAFT = ROOT / 'artifacts/job-indexed-input-probe-r35-20261017/revision-3' / NEW_TEST
REVIEW = ROOT / 'artifacts/job-indexed-input-probe-source-review-r35-20261017/revision-3-review.json'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
read = lambda p: json.loads(Path(p).read_text(encoding='utf-8'))
if sys.platform != 'linux' or sys.flags.optimize:
    raise RuntimeError('Unoptimized Linux required')
assert len(sys.argv) == 3, 'Concrete completed original risk receipt and its actual SHA required'
red_path = Path(sys.argv[1]).resolve(strict=True)
assert red_path.is_relative_to(JOB.resolve(strict=True)) and red_path.name == 'receipt.json'
assert sha(red_path) == sys.argv[2]
red = read(red_path)
assert red['phase'] == 'red' and red['test_started'] and red['command_started']
assert red['evidence_guards_passed'] and red['guards'] and all(v is True for v in red['guards'].values())
assert red['finished_at'] and red['candidate_before'] == red['candidate_after']
assert red['junit']['tests'] == 7 and red['junit']['errors'] == red['junit']['skipped'] == 0
xml_path = red_path.parent / 'results.xml'
assert sha(xml_path) == red['artifact_sha256']['results.xml']
nodes = list(ET.parse(xml_path).getroot().iter('testcase'))
counter = Counter((n.get('classname', ''), n.get('name', '')) for n in nodes)
assert red['case_counter'] == [list(k) + [v] for k, v in sorted(counter.items())]
collection_path = JOB / 'prewrite-collect-v2/receipt.json'
positive_path = JOB / 'prewrite-positive-v3/receipt.json'
assert sha(collection_path) == '7ad263288301b3e51bea24efc996e2b82ac20879834003fbb36fe12f47301578'
assert sha(positive_path) == '5ea9825d35b508844774a29cfe39c50cec07157f4244931191e9522265f352fe'
collection, positive = read(collection_path), read(positive_path)
assert collection['passed'] and collection['evidence_guards_passed']
assert collection['case_counter'] == red['case_counter']
assert positive['passed'] and positive['evidence_guards_passed']
assert positive['junit'] == dict(tests=2, failures=0, errors=0, skipped=0)
assert all(v is True for v in positive['guards'].values())
assert positive['candidate_before'] == positive['candidate_after'] == red['candidate_after']
for value in ('False', 'True'):
    selected = [n for n in nodes if n.get('classname') == 'tests.test_job_runtime_prewrite_r35' and n.get('name') == f'test_prewrite_probe_native_job_positive_closes_queue[{value}]']
    assert len(selected) == 1 and all(selected[0].find(kind) is None for kind in ('failure', 'error', 'skipped'))
assert sha(HERE / 'verify_store_independent_r35.py') == '932c5c2b296b8f9e4f376adba3090d54cc9f89de7199e4a98160e9fd74955540'
sys.path.insert(0, str(HERE))
from verify_store_independent_r35 import snapshot
before = snapshot(SOURCE)
assert before == red['candidate_after'] and len(before) == 1086
assert before['tests/test_job_runtime_footprint_r34.py'] == 'ac34d7a64e0998e052780fc1f23283875781fc784d2c1141b52e3b827cc09b57'
assert before['tests/test_job_runtime_prewrite_r35.py'] == '74cd68ba5a5c45afa25c2c3d48695c2c3f56b7252664ffc51f9060304f45c054'
assert before['zscope/orchestration/jobs/store.py'] == '8e54401f366af32e0044a91b54933960c2f3ad0560a7daac43184b9ec487dc61'
assert before['zscope/retrieval/indexing_identity.py'] == '4078f3ea4fd798332ff9958e241dd378c2236ee08be10d72de44a8fc5bd162b1'
assert sha(DRAFT) == 'b6f412c8446edcc1365abbc3628bd8754a80fbd164e90f56b015f71986bd0777'
assert sha(REVIEW) == 'cabd3878fd78dd5f2d11461713f9fb4eb5fc1c61567aff0dec45e56a03054548'
floor_path = ROOT / 'artifacts/stage-checkpoint-contract-intake-r34-20261017/receipt.json'
assert sha(floor_path) == 'b9d8cc7874d3f224f514ec43feebad99f75eb659a9aa194ec068545dc605a69f'
floor = read(floor_path)
stage = ROOT / '.coordination/20261014/workspaces/coordinator-instance-integration-r24'
assert snapshot(stage) == floor['complete_inputs_after']
assert all(sha(ROOT / name) == digest for name, digest in floor['root_inputs'].items())
assert sha('/home/zeal/.cache/zscope-job-runtime-footprint-r34/install/bin/zscope-clang-indexer') == 'f4e2ff8aef71027447afe497b4c8872a4b2bc2f596166ff543492a623fdda860'
parent = (ROOT / '.coordination/20261014/workspaces').resolve(strict=True)
assert WORK.resolve().is_relative_to(parent) and WORK.name == 'coordinator-indexed-input-prewrite-r35'
if WORK.exists() or BASE.exists():
    raise RuntimeError('Preserve existing workspace/receipt')
BASE.mkdir()
WORK.mkdir()
for name, digest in before.items():
    relative = Path(name)
    assert not relative.is_absolute() and '..' not in relative.parts
    data = (SOURCE / relative).read_bytes()
    assert hashlib.sha256(data).hexdigest() == digest
    target = WORK / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
(WORK / NEW_TEST).write_bytes(DRAFT.read_bytes())
after = snapshot(WORK)
assert after == dict(before, **{NEW_TEST: sha(DRAFT)}) and len(after) == 1087
assert snapshot(SOURCE) == before and snapshot(stage) == floor['complete_inputs_after']
assert all(sha(ROOT / name) == digest for name, digest in floor['root_inputs'].items())
record = dict(actual_task='/root', prepared_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(),
    status='prepared_for_reviewed_test_format_only', workspace=str(WORK), original_candidate=str(SOURCE),
    original_complete_inputs=before, complete_inputs=after, root_inputs=floor['root_inputs'], stage_inputs=floor['complete_inputs_after'],
    ownership=dict(product_source='Coordinator readonly dependency; only /root integrates any later product fix',
        test_owner='/root/stage_currentness_repair_r33', owned_test=NEW_TEST, allowed_mutation='Only reviewed whole-AST-preserving Black of the new test; no other existing source/test/config changes'),
    reference_sha256={str(p): sha(p) for p in (Path(__file__), red_path, xml_path, collection_path, positive_path, DRAFT, REVIEW, floor_path)},
    original_source_unchanged=True, stage1082_root1065_unchanged=True, third_tu_executed=False,
    risk_causality_accepted=False, stage_intake=False, root_intake=False)
(BASE / 'preparation.json').write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
print(json.dumps(dict(prepared_at=record['prepared_at'], inputs=len(after), status=record['status'], stage_intake=False, root_intake=False)))
