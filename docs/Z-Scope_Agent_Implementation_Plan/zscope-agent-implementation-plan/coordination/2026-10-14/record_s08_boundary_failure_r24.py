from pathlib import Path
import datetime as dt
import hashlib,json
import xml.etree.ElementTree as ET
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[4]
OUT=ROOT/'artifacts/s08-multipath-probe-r24-20261016'
BRANCH=ROOT/'.coordination/20261014/workspaces/s08-instance-recovery-min-r23'
def read(p):return json.loads(p.read_text(encoding='utf-8'))
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def write(p,v):p.write_text(json.dumps(v,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
before=read(OUT/'review.json')['source_before']
assert all(sha(BRANCH/p)==h for p,h in before.items())
cases=list(ET.parse(OUT/'boundary-results.xml').getroot().iter('testcase'))
counts=dict(tests=len(cases),failures=sum(c.find('failure') is not None for c in cases),errors=sum(c.find('error') is not None for c in cases),skipped=sum(c.find('skipped') is not None for c in cases))
assert counts==dict(tests=5,failures=5,errors=0,skipped=0)
at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
proof=dict(logical_task='S08-INSTANCE-RECOVERY-MIN-R23',actual_task_id='task_4d8c492e1d',recorded_at=at,junit=counts,returncode=1,source_before=before,source_after={p:sha(BRANCH/p) for p in before},probe_sha256=sha(OUT/'test_s08_boundary_probe.py'),junit_path='artifacts/s08-multipath-probe-r24-20261016/boundary-results.xml',failure_families=['mutable bytearray outcome retained in PreparedInstanceResult','completion.state list raises TypeError instead of typed miss','record.status list raises TypeError instead of typed miss','outcome string raises AttributeError instead of typed miss','deeply nested disk JSON raises RecursionError instead of typed miss'],same_producer_delivery_as_multipath_failure=True,additional_failed_delivery_increment=0,independent_acceptance=False,integrated=False,joint_verification=False)
write(OUT/'boundary-review.json',proof)
ledger=read(HERE/'tasks.json');row=next(r for r in ledger['tasks'] if r['id']==proof['logical_task'])
assert row['bridge_task_id']==proof['actual_task_id'] and row['consecutive_failed_actual_deliveries']==1
row['independent_boundary_failure_evidence']='artifacts/s08-multipath-probe-r24-20261016/boundary-review.json'
row['glm_delivery_rounds'][-1]['independent_result']='Multipath positive 1 failure plus immutable/malformed boundary 5 failures, no errors/skips; same first delivery, dependency checks pending'
write(HERE/'tasks.json',ledger)
print(json.dumps(dict(task_id=proof['actual_task_id'],at=at,junit=counts,additional_failed_delivery_increment=0)))
