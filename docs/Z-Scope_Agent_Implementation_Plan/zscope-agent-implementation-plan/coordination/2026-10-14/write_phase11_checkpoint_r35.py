"""Record independent Store acceptance separately from pending native behavior."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
BASE = ROOT / 'artifacts/coordinator-stage-repairs-r33-20261017'
OUT = BASE / 'phase11-checkpoint.json'
read = lambda p: json.loads(p.read_text(encoding='utf-8'))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
if sys.platform != 'linux' or sys.flags.optimize:
    raise RuntimeError('Unoptimized Linux required')
floor_path = ROOT / 'artifacts/stage-checkpoint-contract-intake-r34-20261017/receipt.json'
assert sha(floor_path) == 'b9d8cc7874d3f224f514ec43feebad99f75eb659a9aa194ec068545dc605a69f'
floor = read(floor_path)
stage = ROOT / '.coordination/20261014/workspaces/coordinator-instance-integration-r24'
assert len(floor['complete_inputs_after']) == 1082 and len(floor['root_inputs']) == 1065
assert all(sha(stage / p) == v for p, v in floor['complete_inputs_after'].items())
assert all(sha(ROOT / p) == v for p, v in floor['root_inputs'].items())
store_path = ROOT / 'artifacts/coordinator-store-active-transactions-r35-20261017/independent/review.json'
store = read(store_path)
assert store['passed'] and store['gates'] and all(v is True for v in store['gates'].values())
assert len(store['commands']) == 8 and all(row['returncode'] == 0 for row in store['commands'])
red_path = ROOT / 'artifacts/coordinator-job-valid-red-audit-r35-20261017/review.json'
red = read(red_path)
assert red['causal_review_passed'] and red['evidence_guards_passed']
refs = [store_path, red_path, floor_path, BASE / 'phase10-checkpoint.json',
    BASE / 'bridge-readonly-r35-1459.json',
    ROOT / 'artifacts/store-active-transactions-source-review-r35-20261017/final-three-source-review.json',
    ROOT / 'artifacts/job-runtime-footprint-source-review-r34-20261017/python-candidate-v1-blocked-review.json',
    ROOT / 'artifacts/job-runtime-footprint-repair-r34-20261017/hook-fixture-readonly-override-r35/receipt.json']
when = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
record = dict(actual_task='/root', checked_at=when,
    store_producer_actual_task='/root/stage_currentness_repair_r33',
    store_coordinator_independent_actual_task='/root', store_coordinator_finished_at=store['finished_at'],
    store_coordinator_junit=store['junit'], store_independent_passed=True,
    store_independent_eight_command_returncodes=[row['returncode'] for row in store['commands']],
    store_all_evidence_guards_passed=True, store_owned_sources_sha256=store['owned_sources_sha256'],
    store_stage_intake=False, store_root_intake=False,
    job_actual_task='/root/stage_cost_repair_r33',
    job_valid_red_junit=red['junit'], job_valid_red_audited=True,
    job_confirmed_causal_targets=red['valid_target_failure_identities'],
    job_red_interpretation='53 actual cases =20 pass/33 fail, no errors or skips; failures include unmet interfaces and early refusals, not 33 independently proved defects.',
    job_two_prewrite_source_blockers='Static only; isolated 7-case probe draft/launcher requires review corrections and real positive closure before risk red.',
    native_real_build_independently_verified=True, native_python_behavior_independent_passed=False,
    original_hook_red1_preserved=True, hook_fixture_captured_input_only_override=True, hook_fixture_green_pending=True,
    source_stage1082_root1065_exact=True, stage_full_current_joint_passed=False, root_new_intake=False, root_full_current_joint_passed=False,
    failed_delivery_counts=dict(store=0, job=0, historical_cost=1, historical_s01=3),
    bridge_original_tasks_public_unknown=True, service_started_or_restarted=False,
    archived_s06_r02_touched=False, whole_work_packages_complete=False, real_project_effect_acceptance=False,
    reference_sha256={str(p.relative_to(ROOT)): sha(p) for p in refs})
if OUT.exists():
    raise RuntimeError('Preserve checkpoint')
OUT.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
tasks = read(HERE / 'tasks.json')
for task in tasks['tasks']:
    if task.get('id') == 'STORE-ACTIVE-TRANSACTION-SEAM-R35':
        task.update(status='coordinator_independent369_trace5_longUSR_and_eight_commands_passed_stage_pending', producer_quality_passed=True,
            independent_acceptance=True, independent_actual_task='/root', independent_receipt=str(store_path.relative_to(ROOT)),
            independent_finished_at=store['finished_at'], independent_junit=store['junit'], stage_intake=False, root_intake=False, checked_at=when)
    elif task.get('id') == 'JOB-RUNTIME-FOOTPRINT-REPAIR-R34':
        task.update(status='valid_red53_audited_two_static_prewrite_blockers_incremental_probe_review_pending', valid_red_accepted=True,
            valid_red_audit=str(red_path.relative_to(ROOT)), valid_red_junit=red['junit'], independent_acceptance=False,
            prewrite_probe_status='artifact_draft_only_two_review_corrections_pending', checked_at=when)
tasks.update(updated_at=when, latest_phase11_checkpoint=str(OUT.relative_to(ROOT)))
(HERE / 'tasks.json').write_text(json.dumps(tasks, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
paragraph = f'\n\n---\n\n### {when} · Store协调者独验通过，Job有效红已核且新风险待探针\n\nStore实际生产者/root/stage_currentness_repair_r33最终三源已冻；协调者/root于{store["finished_at"]}完成369主回归、单独永久trace5、原长USR1，全部0F/E/skip，八条验证/质量命令全0，全部源码/config/Root/Stage/refs/native-host与原始Counter守卫真。这三个测试范围重叠，不相加为整体。Store有界独验通过，尚无Stage或Root产品接入。\n\nJob实际/root/stage_cost_repair_r33保留有效53红20P/33F/0Eskip，协调者已按raw XML/原Counter/完整守卫及独立first-write证据核实原SessionJobs因果；缺schema/interface与早期拒绝分列，不称33个独立缺陷。新ordinary-lookup工具已真实构建，Python行为仍未接纳。两个写前风险仍为静态P1；7项增量探针草稿需闭合真实2正控制和backup精确门观测，不能用collect或泛异常当通过。旧Hook正例真实1F已保留，仅夹具新增已捕获input_revision，所有原assert保留，真实绿待新Store依赖。\n\n最新公开Bridge复查原task_f702313db8/task_0d7256802a仍unknown、原scope会话dead/turns0；已由现有隔离续任务继续，不重复派发、不重启服务、不触碰S06-R02。Stage1082/Root1065全部实际SHA仍精确，完整当前Stage联合、Root导入和当前Root联合均未通过。历史成本失败1/S01失败3、Store/Job交付失败0分别保留；真实项目/LLM效果、条件扩展、formal/portable与整工作包不宣称完成。证据 {OUT.relative_to(ROOT).as_posix()}。\n'
for name in ('DAG.md', 'PROGRESS.md', 'CURRENT_STATE_R33.md'):
    path = HERE / name
    path.write_text(path.read_text(encoding='utf-8').rstrip() + paragraph, encoding='utf-8', newline='\n')
continuation = read(HERE / 'continuation-r6.json')
continuation.update(latest_phase11_checkpoint=str(OUT.relative_to(ROOT)), latest_checked_at=when,
    current_stage_inputs=1082, current_stage_joint_validation_passed=False, next_root_intake_performed=False,
    store_current_independent_passed=True, job_valid_red53_audited=True)
(HERE / 'continuation-r6.json').write_text(json.dumps(continuation, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
print(json.dumps(dict(checked_at=when, store_independent_passed=True, stage_current_joint=False, root_current_joint=False)))
