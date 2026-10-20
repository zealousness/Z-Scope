"""Freeze actual authority-probe failure before the same worker is repaired."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
BRANCH = ROOT / '.coordination/20261014/workspaces/s01-instance-semantics-min-r23'
OUT = ROOT / 'artifacts/s01-authority-probe-r24-20261016'
def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):
    return json.loads(p.read_text(encoding='utf-8'))
def write(p,v):
    p.write_text(json.dumps(v,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
expected = {'zscope/semantics/instance_semantics.py':'25fae2288805b46313bb64aec6ee7fe56588d353dbdb4458fd7b3d1832aa5bba', 'tests/test_instance_semantics.py':'7b6c221cd50ebed817eb3567db0ed5fcda7807382ca06ac44e733513571c539b'}
after = {p:sha(BRANCH/p) for p in expected}
assert after == expected
source = read(ROOT/'artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json')['after']
assert all(sha(ROOT/p)==h for p,h in source.items())
native=Path('/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer')
assert sha(native)=='d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399'
initial = ET.parse(OUT/'results.xml').getroot()
final = ET.parse(OUT/'results-rerun-01.xml').getroot()
def counts(tree):
    cases=list(tree.iter('testcase'))
    return dict(tests=len(cases), failures=sum(c.find('failure') is not None for c in cases), errors=sum(c.find('error') is not None for c in cases),skipped=sum(c.find('skipped') is not None for c in cases))
assert counts(final)==dict(tests=4,failures=4,errors=0,skipped=0)
assert counts(initial)==dict(tests=4,failures=2,errors=2,skipped=0)
frozen=OUT/'failed-candidate'
assert not frozen.exists()
frozen.mkdir()
copied=[]
for relative in [*expected,'DELIVERY.md']:
    target=frozen/relative
    target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(BRANCH/relative,target)
    copied.append(relative)
shutil.copytree(BRANCH/'artifacts/instance-semantics-r23',frozen/'artifacts/instance-semantics-r23')
copied.extend(p.relative_to(frozen).as_posix() for p in (frozen/'artifacts/instance-semantics-r23').rglob('*') if p.is_file())
at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
review=dict(logical_task='S01-INSTANCE-SEMANTICS-MIN-R23',actual_task_id='task_d986e8232c',session_id='sess_6ecde27723',producer_finished_at='2026-10-16T03:44:01.753215+00:00',recorded_at=at,probe_started_clock='2026-10-16 03:55:20 UTC',junit=counts(final),returncode=1,junit_path='artifacts/s01-authority-probe-r24-20261016/results-rerun-01.xml',source_before=expected,source_after=after,probe_sha256=sha(OUT/'test_s01_authority_probe.py'),initial_probe_sha256=sha(OUT/'test_s01_authority_probe.initial.py'),initial_junit=counts(initial),initial_coordinator_error='Two plan_entry_instances callsites had reversed index/entries arguments. Corrected in the probe only, original probe/JUnit/log retained; setup errors do not count as GLM development failures.',independent_module_dependency_review='artifacts/coordinator-s01-module-dependency-r24-20261016/review.json',module_dependency_tests=118,module_dependency_passed=True,source_review='artifacts/s01-module-source-review-r24-20261016/review.json',actual_authority_findings=['S01-R24-P1-01','S01-R24-P1-02','S01-R24-P1-03','S01-R24-P2-04'],independent_acceptance=False,integrated=False,joint_verification=False,root_source_inputs_unchanged=len(source),native_sha256=sha(native),frozen_candidate={p:sha(frozen/p) for p in copied},real_native_probe_cases=3,synthetic_negative_cases=1,whole_package_complete=False)
write(OUT/'review.json',review)
ledger=read(HERE/'tasks.json')
row=next(r for r in ledger['tasks'] if r['id']==review['logical_task'])
assert row['bridge_task_id']==review['actual_task_id'] and row['producer_status']=='completed'
assert row.get('consecutive_failed_actual_deliveries',0)==0
row.update(status='independent_authority_probes_failed_same_session_repair_required',independent_acceptance=False,consecutive_failed_actual_deliveries=1,independent_failure_evidence='artifacts/s01-authority-probe-r24-20261016/review.json',module_dependency_review=review['independent_module_dependency_review'],frozen_failed_candidate='artifacts/s01-authority-probe-r24-20261016/failed-candidate',checked_at=at)
row.setdefault('glm_delivery_rounds',[]).append(dict(round=1,task_id=review['actual_task_id'],producer_finished_at=review['producer_finished_at'],independent_result='4 authority probes failed, 118 dependency tests passed; module not accepted',evidence=row['independent_failure_evidence'],counted_development_failure=True,coordinator_initial_setup_errors_excluded=True))
ledger['updated_at']=at
write(HERE/'tasks.json',ledger)
print(json.dumps({k:review[k] for k in ('actual_task_id','recorded_at','junit','probe_sha256','root_source_inputs_unchanged','independent_acceptance')},ensure_ascii=False))
