"""Freeze the S08 candidate and actual multi-path failure; do not dispatch."""
from pathlib import Path
import datetime as dt
import hashlib,json,shutil,time
import xml.etree.ElementTree as ET
from uuid import uuid4
from bridge_queue_publish_r23 import publish_request
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[4]
BRANCH=ROOT/'.coordination/20261014/workspaces/s08-instance-recovery-min-r23'
OUT=ROOT/'artifacts/s08-multipath-probe-r24-20261016'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text(encoding='utf-8'))
def write(p,v):p.write_text(json.dumps(v,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
expected={'zscope/orchestration/jobs/instance_results.py':'2455016d9526dc7ca6187bffa28461883af682fabecca5a1ef7a3719fc5a6b52','tests/test_instance_result_recovery.py':'ced928894644ac6d01735c1f3e244e2241a6394f44e02b137a8ced68a7746c66'}
assert all(sha(BRANCH/p)==h for p,h in expected.items())
cases=list(ET.parse(OUT/'results.xml').getroot().iter('testcase'))
counts=dict(tests=len(cases),failures=sum(c.find('failure') is not None for c in cases),errors=sum(c.find('error') is not None for c in cases),skipped=sum(c.find('skipped') is not None for c in cases))
assert counts==dict(tests=1,failures=1,errors=0,skipped=0)
source=read(ROOT/'artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json')['after']
assert all(sha(ROOT/p)==h for p,h in source.items())
frozen=OUT/'failed-candidate';frozen.mkdir(exist_ok=False)
for p in [*expected,'DELIVERY.md']:
    (frozen/p).parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(BRANCH/p,frozen/p)
shutil.copytree(BRANCH/'artifacts/instance-recovery-r23',frozen/'artifacts/instance-recovery-r23')
at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
proof=dict(logical_task='S08-INSTANCE-RECOVERY-MIN-R23',actual_task_id='task_4d8c492e1d',session_id='sess_d9cfbf4113',producer_finished_at='2026-10-16T04:01:48.832129+00:00',recorded_at=at,returncode=1,junit=counts,source_before=expected,source_after={p:sha(BRANCH/p) for p in expected},probe_sha256=sha(OUT/'test_s08_multipath_probe.py'),junit_path='artifacts/s08-multipath-probe-r24-20261016/results.xml',actual_failure_reason='Legal same occurrence_uid with two distinct path rows is rejected as occurrence count mismatch; UID set and full occurrence-row counts are different.',synthetic_module_boundary_probe=True,independent_acceptance=False,integrated=False,joint_verification=False,root_inputs_unchanged=len(source),frozen_candidate={p.relative_to(frozen).as_posix():sha(p) for p in frozen.rglob('*') if p.is_file()})
write(OUT/'review.json',proof)
ledger=read(HERE/'tasks.json');row=next(r for r in ledger['tasks'] if r['id']==proof['logical_task'])
assert row['bridge_task_id']==proof['actual_task_id'] and row['producer_status']=='completed' and row.get('consecutive_failed_actual_deliveries',0)==0
row.update(status='independent_multipath_probe_failed_dependency_checks_and_same_session_repair_pending',consecutive_failed_actual_deliveries=1,independent_failure_evidence='artifacts/s08-multipath-probe-r24-20261016/review.json',frozen_failed_candidate='artifacts/s08-multipath-probe-r24-20261016/failed-candidate',checked_at=at)
row.setdefault('glm_delivery_rounds',[]).append(dict(round=1,task_id=proof['actual_task_id'],producer_finished_at=proof['producer_finished_at'],independent_result='one actual legal multipath roundtrip failed; dependency checks/source review pending',evidence=row['independent_failure_evidence'],counted_development_failure=True))
ledger['updated_at']=at;write(HERE/'tasks.json',ledger)
route=HERE/'route-check';name='r24-s08-result-'+uuid4().hex[:12];response=route/('bridge-response-'+name+'.json')
publish_request(route/'bridge-queue',dict(id=name,tool='get_result',arguments=dict(task_id=proof['actual_task_id'],max_chars=60000)))
until=time.monotonic()+40
while time.monotonic()<until:
    if response.exists():
        try:result=read(response);break
        except json.JSONDecodeError:pass
    time.sleep(.25)
else:raise RuntimeError('Unknown original-owner response; inspect persisted request only')
assert result.get('task_id')==proof['actual_task_id'] and result.get('status')=='completed'
print(json.dumps(dict(at=at,task_id=proof['actual_task_id'],junit=counts,get_result_receipt=response.relative_to(HERE).as_posix(),has_more=result.get('has_more'),next_cursor=result.get('next_cursor'),independent_acceptance=False),ensure_ascii=False))
