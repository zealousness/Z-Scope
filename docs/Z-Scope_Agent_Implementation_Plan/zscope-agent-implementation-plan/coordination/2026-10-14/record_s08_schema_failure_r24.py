from pathlib import Path
import datetime as dt
import hashlib,json
import xml.etree.ElementTree as ET
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[4];OUT=ROOT/'artifacts/s08-multipath-probe-r24-20261016';BRANCH=ROOT/'.coordination/20261014/workspaces/s08-instance-recovery-min-r23'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
before=json.loads((OUT/'review.json').read_text(encoding='utf-8'))['source_before']
assert all(sha(BRANCH/p)==h for p,h in before.items())
cases=list(ET.parse(OUT/'schema-results.xml').getroot().iter('testcase'))
counts=dict(tests=len(cases),failures=sum(c.find('failure') is not None for c in cases),errors=sum(c.find('error') is not None for c in cases),skipped=sum(c.find('skipped') is not None for c in cases))
assert counts==dict(tests=1,failures=1,errors=0,skipped=0)
at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
proof=dict(logical_task='S08-INSTANCE-RECOVERY-MIN-R23',actual_task_id='task_4d8c492e1d',recorded_at=at,junit=counts,returncode=1,source_before=before,source_after={p:sha(BRANCH/p) for p in before},probe_sha256=sha(OUT/'test_s08_schema_probe.py'),junit_path='artifacts/s08-multipath-probe-r24-20261016/schema-results.xml',actual_failure_reason='Expected candidate schema v3.5 accepts inner candidate schema v999',same_first_producer_delivery=True,additional_failed_delivery_increment=0,independent_acceptance=False,integrated=False,joint_verification=False)
(OUT/'schema-review.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
ledger=json.loads((HERE/'tasks.json').read_text(encoding='utf-8'));row=next(r for r in ledger['tasks'] if r['id']==proof['logical_task'])
assert row['bridge_task_id']==proof['actual_task_id'] and row['consecutive_failed_actual_deliveries']==1
row['independent_schema_failure_evidence']='artifacts/s08-multipath-probe-r24-20261016/schema-review.json'
row['glm_delivery_rounds'][-1]['independent_result']='Seven independently executed module boundary cases failed (multipath1, immutable/malformed5, inner schema1), all no error/skip; same first delivery'
(HERE/'tasks.json').write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
print(json.dumps(dict(task_id=proof['actual_task_id'],at=at,junit=counts,additional_failed_delivery_increment=0)))
