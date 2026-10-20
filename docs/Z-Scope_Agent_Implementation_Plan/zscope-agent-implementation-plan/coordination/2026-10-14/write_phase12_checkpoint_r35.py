"""Preserve real positive-control failures and pending prewrite causality."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
JOB = ROOT / '.coordination/20261014/workspaces/job-runtime-footprint-repair-r34/artifacts/job_runtime_footprint_r34'
BASE = ROOT / 'artifacts/coordinator-stage-repairs-r33-20261017'
OUT = BASE / 'phase12-checkpoint.json'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
read = lambda p: json.loads(p.read_text(encoding='utf-8'))
if sys.platform != 'linux' or sys.flags.optimize:
    raise RuntimeError('Unoptimized Linux required')
positive_path = JOB / 'prewrite-positive-v2/receipt.json'
collect_path = JOB / 'prewrite-collect-v2/receipt.json'
assert sha(positive_path) == 'b7cc57e2755aac313882af42761ae093b7d94ac7b10256d3752e332b6aad976c'
assert sha(collect_path) == '7ad263288301b3e51bea24efc996e2b82ac20879834003fbb36fe12f47301578'
positive, collected = read(positive_path), read(collect_path)
assert positive['junit'] == dict(tests=2, failures=2, errors=0, skipped=0)
assert positive['evidence_guards_passed'] and all(v is True for v in positive['guards'].values())
assert not positive['passed'] and collected['passed'] and collected['evidence_guards_passed']
assert len(collected['case_counter']) == 7 and sum(row[2] for row in collected['case_counter']) == 7
assert not (JOB / 'prewrite-red-v2').exists(), 'Risk red should remain stopped after positive failures'
floor_path = ROOT / 'artifacts/stage-checkpoint-contract-intake-r34-20261017/receipt.json'
assert sha(floor_path) == 'b9d8cc7874d3f224f514ec43feebad99f75eb659a9aa194ec068545dc605a69f'
floor = read(floor_path)
stage = ROOT / '.coordination/20261014/workspaces/coordinator-instance-integration-r24'
assert all(sha(stage / p) == v for p, v in floor['complete_inputs_after'].items())
assert all(sha(ROOT / p) == v for p, v in floor['root_inputs'].items())
refs = [positive_path, collect_path, BASE / 'phase11-checkpoint.json',
    ROOT / 'artifacts/job-runtime-footprint-repair-r34-20261017/store-readonly-dependency-override-r35/receipt.json',
    ROOT / 'artifacts/coordinator-store-active-transactions-r35-20261017/stage-evidence-adapter.json',
    ROOT / 'artifacts/job-runtime-footprint-source-review-r34-20261017/sdk-alias-positive-first-cause-plan-review.json',
    ROOT / 'artifacts/job-runtime-footprint-source-review-r34-20261017/third-tu-protection-source-risk-review.json',
    ROOT / 'artifacts/job-indexed-input-probe-source-review-r35-20261017/initial-review.json',
    ROOT / 'artifacts/coordinator-stage-joint-rev5-v2-source-review-r35-20261017/review.json',
    ROOT / 'artifacts/runtime-footprint-module-docs-r35-20261017/revision-2/preparation.json']
when = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
record = dict(actual_task='/root', checked_at=when,
    store_independent_passed=True, store_readonly_dependency_copied_to_job_at='2026-10-17T15:01:51.253131+08:00',
    job_actual_task='/root/stage_cost_repair_r33', actual_collection7_passed=True,
    actual_positive_junit=positive['junit'], actual_positive_finished_at=positive['finished_at'], actual_positive_guards_all_true=True,
    actual_positive_passed=False, subsequent_risk_red_executed=False,
    positive_first_cause='Actual system HeaderSearch SDK alias /usr/include/clang/18.1.3/include resolves to /usr/lib/llvm-18/lib/clang/18/include; current consumer accepts only its different ResourceDir alias and refuses at indexing_identity.py:523 before scope/queue closure.',
    sdk_fix_status='Exact current SDK mapping plan reviewed; concrete artifact delta/physical proof being reviewed; no candidate fix yet.',
    original_three_prewrite_risks_actual_reproduced=False,
    third_tu_probe_actual_task='/root/stage_currentness_repair_r33', third_tu_probe_status='Artifact-only pair; initial fixture orphan .h static blocker, literal-only .lookup revision pending; no collection/native execution.',
    joint_rev5_v2_static_source_review_passed=True, joint_rev5_v2_installed=False, joint_executed=False,
    module_documents_revision2_draft_only=True, stage1082_root1065_exact=True,
    stage_new_intake=False, root_new_intake=False, stage_current_joint_passed=False, root_current_joint_passed=False,
    failed_delivery_counts=dict(store=0, job=0, historical_cost=1, historical_s01=3),
    failed_delivery_interpretation='Actual internal positive2 failure and static draft findings retained separately; not new delivered-development failures and not three causal risk reproductions.',
    bridge_restarted=False, archived_s06_r02_touched=False, whole_packages_complete=False, real_project_effect_acceptance=False,
    reference_sha256={str(p.relative_to(ROOT)): sha(p) for p in refs})
if OUT.exists():
    raise RuntimeError('Preserve checkpoint')
OUT.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
tasks = read(HERE / 'tasks.json')
for task in tasks['tasks']:
    if task.get('id') == 'JOB-RUNTIME-FOOTPRINT-REPAIR-R34':
        task.update(status='actual7_collected_positive2_failed_system_sdk_alias_risk_red_stopped', checked_at=when,
            current_positive_junit=positive['junit'], current_positive_receipt=str(positive_path.relative_to(ROOT)),
            positive_guards_passed=True, risk_red_executed=False, independent_acceptance=False)
    elif task.get('id') == 'STORE-ACTIVE-TRANSACTION-SEAM-R35':
        task.update(readonly_dependency_supplied_to_job=True, dependency_intake_at='2026-10-17T15:01:51.253131+08:00', stage_intake=False, root_intake=False)
    elif task.get('id') == 'ASTRA-INSTANCE-CONSUMERS-R25':
        task.update(status='accepted_repaired_consumer_stage_integrated_bounded1147_shared_core_mypy_resolved_new_joint_pending_no_root_intake',
            historical_four_s01_mypy_errors_preserved=True, shared_core_quality_receipt='artifacts/coordinator-shared-style-r34-20261017/independent/review.json', checked_at=when)
if not any(task.get('id') == 'JOB-ALL-INDEX-INPUT-PROBE-R35' for task in tasks['tasks']):
    tasks['tasks'].append(dict(id='JOB-ALL-INDEX-INPUT-PROBE-R35', actual_agent_id='/root/stage_currentness_repair_r33',
        owner='Codex native 6.1-sol/xhigh', status=record['third_tu_probe_status'], ownership='Only unique Root artifact draft directory; no live candidate/product writes or execution',
        artifact_directory='artifacts/job-indexed-input-probe-r35-20261017', planned_test_count=2, actual_test_count=0,
        independent_acceptance=False, stage_intake=False, root_intake=False, checked_at=when))
tasks.update(updated_at=when, latest_phase12_checkpoint=str(OUT.relative_to(ROOT)))
(HERE / 'tasks.json').write_text(json.dumps(tasks, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
paragraph = f'\n\n---\n\n### {when} · 实际7收集通过，正控2F已定位SDK别名并停止风险红\n\nRoot独验Store369/trace5/USR及八质量全绿维持；15:01:51三路径仅接入Job隔离候选。实际/root/stage_cost_repair_r33原7新probe已同源收集7/0/全部守卫真；随后两个真正native正控均F、0Eskip且13守卫真，完成时间{positive["finished_at"]}，b7cc/0a122原receipt/XML不改。实际原生HeaderSearch使用当前root-owned SDK别名/usr/include/clang/18.1.3/include→/usr/lib/llvm-18/lib/clang/18/include，而消费者仅许可另一ResourceDir别名，故在indexing_identity:523提前拒绝；完整lookup和独立首因4b38已核。只允许固定当前SDK物理/版本/权限/实际native-tool-lib-header绑定的最窄修复，普通project alias仍deny。正控未过，不执行风险7红，更不能把2F当backup/tool/third目标已复现。\n\n独立/root/stage_currentness_repair_r33新子项仅准备thirdTU保护探针2稿，真实3context/plan2/非选TU已读pending输入必须由实际write/replace损坏证明；当前未运行。初审发现孤立.h会在strict native初始化提前失败，已要求仅新草稿字面值改.lookup，保留原7ee及fe545审计；原7/53不改。联合启动器rev5v2通过Root静态增量核查，22原函数和160原main语句/八命令均保留，尚未安装运行。三模块文档revision2仍draft。\n\nStage1082/Root1065实际字节未变，无当前完整联合通过或Root导入。既有Astra消费端已在Stage，历史四S01 mypy错误已由13:12核心150/七质量有界修复核实，旧失败保留、当前完整联合未通过。Store/Job交付失败0、历史成本1/S01三均不清不增；静态草案/内部正控失败单列。无Bridge重启、S06-R02恢复或整工作包/真实项目效果结论。证据 {OUT.relative_to(ROOT).as_posix()}。\n'
for name in ('DAG.md', 'PROGRESS.md', 'CURRENT_STATE_R33.md'):
    path = HERE / name
    path.write_text(path.read_text(encoding='utf-8').rstrip() + paragraph, encoding='utf-8', newline='\n')
continuation = read(HERE / 'continuation-r6.json')
continuation.update(latest_phase12_checkpoint=str(OUT.relative_to(ROOT)), latest_checked_at=when,
    current_stage_inputs=1082, current_stage_joint_validation_passed=False, next_root_intake_performed=False,
    store_current_independent_passed=True, job_positive2_current_passed=False, job_risk_red_executed=False)
(HERE / 'continuation-r6.json').write_text(json.dumps(continuation, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
print(json.dumps(dict(checked_at=when, positive=positive['junit'], risk_red=False, store_independent=True, stage_current_joint=False)))
