"""Publish evidence-backed progress, retaining every historical result."""
from pathlib import Path
import datetime as dt
import hashlib,json,uuid
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[4]
def read(p):return json.loads(p.read_text(encoding='utf-8'))
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def write(p,v):p.write_text(json.dumps(v,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
joint=read(ROOT/'artifacts/coordinator-r23-ui-projection-union-20261016/review.json')
source=read(ROOT/'artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json')['after']
assert joint['all_current_selected_validation_passed'] and all(sha(ROOT/p)==h for p,h in source.items())
ledger=read(HERE/'tasks.json')
rows=[r for r in ledger['tasks'] if r['id'] in {'S01-INSTANCE-SEMANTICS-MIN-R23','S08-INSTANCE-RECOVERY-MIN-R23'}]
assert len(rows)==2 and all(not r['integrated'] and not r['independent_acceptance'] for r in rows)
summaries=[]
for row in rows:
    short='s01' if row['id'].startswith('S01') else 's08'
    path=ROOT/('artifacts/coordinator-'+short+'-module-dependency-r24-20261016/review.json')
    dependency=read(path)
    assert dependency['module_dependency_checks_passed']
    row['module_dependency_review']=path.relative_to(ROOT).as_posix()
    row['module_dependency_result']=dict(finished_at=dependency['finished_at'],junit=dependency['junit'],commands_passed=4,scope='original failed candidate dependency checks, not repaired candidate acceptance')
    summary={k:row.get(k) for k in ('id','bridge_task_id','bridge_session_id','producer_status','dispatched_at','worker_process_started_at','actual_tool_execution_observed_at','artifact_available','independent_acceptance','integrated','joint_verification','consecutive_failed_actual_deliveries','prior_actual_task_ids','dispatch_evidence','execution_evidence')}
    summary['original_candidate_dependency_result']=row['module_dependency_result'];summaries.append(summary)
at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
out=ROOT/'artifacts'/('coordinator-module-progress-r24-'+uuid.uuid4().hex[:12]);out.mkdir()
proof=dict(recorded_at=at,current_root_joint='artifacts/coordinator-r23-ui-projection-union-20261016/review.json',root_joint_finished_at=joint['finished_at'],root_result=dict(passed=2551,failed=0,errors=0,skipped=0,test_files=171,commands_passed=6),root_bound_inputs_unchanged=len(source),tasks=summaries,source_reviews=['artifacts/s01-module-source-review-r24-20261016/review.json','artifacts/s08-module-source-review-r24-20261016/review.json'],independent_failures=['artifacts/s01-authority-probe-r24-20261016/review.json','artifacts/s08-multipath-probe-r24-20261016/review.json','artifacts/s08-multipath-probe-r24-20261016/boundary-review.json','artifacts/s08-multipath-probe-r24-20261016/schema-review.json'],root_new_intake=False,coordinator_stage='coordinator-instance-integration-r24',stage_acceptance=False,whole_packages_complete=False,clock_problem_resolved=False,archived_S06_operations=0,services_started_or_restarted=0,manual_wsl_process_inspection=False,separate_not_executed=['Real-project/LLM effect acceptance','Formal benchmark / portable smoke','Conditional S10 and Q01/Q02','Full S01/S08/U01 packages and remaining parent DAG nodes'])
write(out/'review.json',proof)
ledger.update(updated_at=at,current_root_status='R23 selected2551/171/six remains current; original S01/S08 candidates failed independent boundary probes; same-session GLM repairs dispatched; coordinator integration isolated/unaccepted',latest_module_progress=(out/'review.json').relative_to(ROOT).as_posix())
write(HERE/'tasks.json',ledger)
continuation=read(HERE/'continuation-r6.json')
continuation.update(updated_at=at,active_phase=ledger['current_root_status'],latest_handoff=ledger['latest_module_progress'],next_module_tasks=summaries,whole_packages_complete=False)
write(HERE/'continuation-r6.json',continuation)
lines='\n'.join(f"- {row['id']}: repair {row['bridge_task_id']} / {row['bridge_session_id']}, dispatched {row['dispatched_at']}; process {row.get('worker_process_started_at') or 'not yet observed'}, actual tool execution {row.get('actual_tool_execution_observed_at') or 'unconfirmed'}; accepted/integrated/joint=False/False/False. Prior IDs: {row.get('prior_actual_task_ids')}." for row in summaries)
note=f'''## {at} · R24 independent module failures preserved; same-session repairs and isolated coordinator integration

Root remains the exact R23 version accepted at {joint['finished_at']}: 2551/171, six commands0, zero failure/error/skip; all1065 bound inputs still match. No new Root intake or unchanged Root rerun. Evidence {proof['current_root_joint']}.

Original S01 task_d986e8232c completed11:44:01; coordinator118 dependency tests and four quality commands passed11:50:42, but four independent authority probes failed. Original S08 task_4d8c492e1d completed12:01:48; coordinator269 dependency tests and four commands passed12:12:00, but seven independently executed cases failed (multipath1, immutable/malformed5, inner-schema1), each with0error/skip. These counts have different scopes and are not added. Failed source/delivery/old logs are frozen under the respective probe artifact failed-candidate directories. Each logical task records one failed actual development delivery, not one failure per probe; initial S01 coordinator argument errors and later S08 overstrict-ready-session guard failure are retained and excluded from worker development failures.

{lines}

S01/S08 repairs fixed ZCode GLM-5.3 in their original sessions and separate two-file ownership. Kimi remains paused for new tasks per current DISPATCH_POLICY. Astra reviews source/UI/complex seams; coordinator alone owns shared integration files in .coordination/20261014/workspaces/coordinator-instance-integration-r24. No worker modules copied to Root or integration stage. New observer marks busy repairs artifact_available=false, so old DELIVERY files do not count as new delivery. Stage collection close, source currentness, trusted reader/claim settlement, full28-wire+diagnostics model, P/R/E and current validation/checkpoint work remain unaccepted; preliminary syntax receipt artifacts/coordinator-syntax-r24-5f23617e7f34/review.json binds only its earlier snapshot (tests0), subsequent changes await functional/quality checks.

Actual capture ENOENT cause and ext4/default-fd launcher repair remain in artifacts/coordinator-capture-probe-20261014/120350/review.json; no lowered timing assertion/skip/capture standard. No new Bridge/service, manual WSL process inspection or archived S06 action. Real-project/LLM effect, formal/portable, complete packages, conditional extensions and unresolved host clock are separate. Current progress evidence {proof['current_root_joint']}; detailed new handoff {out.relative_to(ROOT).as_posix()}/review.json.

---

'''
for name in ('PROGRESS.md','DAG.md'):
    p=HERE/name;p.write_text(note+p.read_text(encoding='utf-8'),encoding='utf-8',newline='\n')
(HERE/'CURRENT_STATE_R24.md').write_text(note,encoding='utf-8',newline='\n')
print(json.dumps(dict(at=at,receipt=(out/'review.json').relative_to(ROOT).as_posix(),root_bound_inputs_unchanged=len(source),tasks=[dict(id=r['id'],task_id=r['bridge_task_id'],actual_tool_execution_observed_at=r['actual_tool_execution_observed_at']) for r in summaries]),ensure_ascii=False))
