"""One same-session repair, no blind retry and no second Bridge owner."""
from pathlib import Path
import datetime as dt
import hashlib,json,time
from uuid import uuid4
from bridge_queue_publish_r23 import publish_request
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
route=HERE/'route-check'
def read(p):return json.loads(p.read_text(encoding='utf-8'))
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def require(ok,message):
    if not ok:raise RuntimeError(message)
def call(tool,args,label):
    name=label+'-'+uuid4().hex[:12]
    response=route/('bridge-response-'+name+'.json')
    publish_request(route/'bridge-queue',dict(id=name,tool=tool,arguments=args))
    until=time.monotonic()+40
    while time.monotonic()<until:
        if response.exists():
            try:return read(response),response
            except json.JSONDecodeError:pass
        time.sleep(.25)
    raise RuntimeError('Unknown original-owner outcome; inspect existing request only')
ledger=read(HERE/'tasks.json')
row=next(r for r in ledger['tasks'] if r['id']=='S08-INSTANCE-RECOVERY-MIN-R23')
require(row['bridge_task_id']=='task_4d8c492e1d' and row['producer_status']=='completed' and row['consecutive_failed_actual_deliveries']==1 and not row['integrated'],'Wrong logical/active task')
review=read(ROOT/'artifacts/s08-multipath-probe-r24-20261016/review.json')
require(review['junit']==dict(tests=1,failures=1,errors=0,skipped=0),'Missing actual failed probe')
dependency_review=read(ROOT/'artifacts/coordinator-s08-module-dependency-r24-20261016/review.json')
require(dependency_review['module_dependency_checks_passed'] and dependency_review['source_unchanged'] and dependency_review['root_unchanged'],'Dependency checks must finish before same-session repair')
boundary=read(ROOT/'artifacts/s08-multipath-probe-r24-20261016/boundary-review.json')
require(boundary['junit']==dict(tests=5,failures=5,errors=0,skipped=0),'Missing immutable/malformed input failures')
schema=read(ROOT/'artifacts/s08-multipath-probe-r24-20261016/schema-review.json')
require(schema['junit']==dict(tests=1,failures=1,errors=0,skipped=0),'Missing schema failure')
branch=ROOT/'.coordination/20261014/workspaces/s08-instance-recovery-min-r23'
require(all(sha(branch/p)==h for p,h in review['source_after'].items()),'Candidate changed since independent failure')
source=read(ROOT/'artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json')['after']
require(all(sha(ROOT/p)==h for p,h in source.items()),'Root drift')
for manifest in ('s08-instance-recovery-min-r23-baseline.json','s08-instance-recovery-min-r23-dependencies.json'):
    require(all(sha(branch/r['path'])==r['sha256'] for r in read(HERE/'followups-r12'/manifest)['files']),'Readonly input drift')
agents,agent_path=call('list_agents',{},'r24-s08-repair-agents')
require(agents.get('ok') and agents['coordinator']['dispatch_enabled'],'Dispatch not enabled')
require(any(a.get('agent')=='zcode' and a.get('available') for a in agents['agents']),'Requested ZCode unavailable')
sessions,session_path=call('list_sessions',dict(active_only=True),'r24-s08-repair-active')
require(sessions.get('ok'),'Session preflight failed')
for session in sessions.get('sessions',[]):
    require(session.get('agent')=='zcode' and session.get('model')=='97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3','Unreconciled worker route')
    require(session['session_id']=='sess_6ecde27723' or (session['session_id']=='sess_d9cfbf4113' and session.get('proc_state')=='ready'),'Unreconciled active worker; do not dispatch')
completed,completed_path=call('check_task',dict(task_id='task_4d8c492e1d'),'r24-s08-repair-completed')
require(completed.get('task_id')=='task_4d8c492e1d' and completed.get('session_id')=='sess_d9cfbf4113' and completed.get('status')=='completed','Original S08 task must be completed before same-session repair')
payload=read(HERE/'followups-r12/s08-instance-recovery-repair-r24-request.json')
require(payload.get('branch')=='s08-instance-recovery-min-r23','Wrong isolated branch')
require(payload['arguments']['session_id']=='sess_d9cfbf4113' and payload['arguments']['model']=='97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3','Wrong route/session')
response=route/('bridge-response-'+payload['id']+'.json')
target=route/'bridge-queue'/('080-'+payload['id']+'.request.json')
require(not target.exists() and not response.exists(),'Existing dispatch outcome must be reconciled, never replay')
publish_request(route/'bridge-queue',payload)
until=time.monotonic()+40
while time.monotonic()<until:
    if response.exists():
        try:result=read(response);break
        except json.JSONDecodeError:pass
    time.sleep(.25)
else:raise RuntimeError('Unknown original-owner dispatch outcome; do not retry or reroute')
require(result.get('ok'),'Owner rejected repair dispatch; stop affected action without route change: '+str(result.get('error')))
require(result['session_id']=='sess_d9cfbf4113' and result['model']==payload['arguments']['model'],'Unexpected accepted route')
at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
ledger=read(HERE/'tasks.json');row=next(r for r in ledger['tasks'] if r['id']=='S08-INSTANCE-RECOVERY-MIN-R23')
row.setdefault('prior_actual_task_ids',[]).append(row['bridge_task_id'])
execution_fields=('bridge_task_id','worker_process_started_at','actual_tool_execution_observed_at','execution_evidence','worker_finished_at','observed_model','producer_status','dispatch_evidence','dispatched_at')
row.setdefault('prior_actual_task_observations',[]).append({key:row.get(key) for key in execution_fields})
for key in ('worker_process_started_at','actual_tool_execution_observed_at','execution_evidence'):
    row.pop(key,None)
row.update(bridge_task_id=result['task_id'],request_id=payload['arguments']['request_id'],producer_status='dispatched',status='same_session_authority_repair_dispatched_execution_unconfirmed',dispatched_at=at,dispatch_evidence=response.relative_to(HERE).as_posix(),artifact_available=False,observed_model=None,worker_finished_at=None,independent_acceptance=False,checked_at=at)
ledger['updated_at']=at
(HERE/'tasks.json').write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
proof=dict(logical_task=row['id'],task_id=result['task_id'],session_id=result['session_id'],at=at,dispatch_accepted=True,actual_execution_confirmed=False,independent_acceptance=False,integrated=False,original_task_id='task_4d8c492e1d',consecutive_failed_actual_deliveries=1,preflights=[agent_path.relative_to(HERE).as_posix(),session_path.relative_to(HERE).as_posix()],dispatch_receipt=row['dispatch_evidence'],root_inputs_verified=len(source))
(HERE/'followups-r12/s08-repair-r24-dispatch-receipt.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
print(json.dumps(proof,ensure_ascii=False))
