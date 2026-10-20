"""Preserve confirmed red evidence and the separate unfixed third-TU copy."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
JOB = ROOT / '.coordination/20261014/workspaces/job-runtime-footprint-repair-r34/artifacts/job_runtime_footprint_r34'
BASE = ROOT / 'artifacts/coordinator-stage-repairs-r33-20261017'
OUT = BASE / 'phase13-checkpoint.json'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
read = lambda p: json.loads(Path(p).read_text(encoding='utf-8'))
if sys.platform != 'linux' or sys.flags.optimize:
    raise RuntimeError('Unoptimized Linux required')
pins = {
    JOB / 'prewrite-positive-v3/receipt.json': '5ea9825d35b508844774a29cfe39c50cec07157f4244931191e9522265f352fe',
    JOB / 'prewrite-red-v3/receipt.json': '175fcb22c0639a75030da2bbb7489bbd3fb7c55d015ba8bb7d3a5c9eaca37fe8',
    ROOT / 'artifacts/coordinator-prewrite-red-audit-r35-20261017/review.json': 'c6e1296a01c34a091c7b1cded20f49ed5459df0c35ca54abd5695ca39911d476',
    ROOT / 'artifacts/coordinator-indexed-input-prewrite-r35-20261017/preparation.json': '1cd32e25ab250b408153a6897c271d447053c086ff77c455d032ea6b0be11bf9',
    ROOT / 'artifacts/coordinator-native-independent-launcher-source-review-r35-20261017/review.json': '376b52cf0b032d9192466c40194c394de0f219da54c004e099dbc705cec1e7f7',
}
assert all(sha(p) == v for p, v in pins.items())
positive, red, audit, copied, launcher_review = map(read, pins)
assert positive['junit'] == dict(tests=2, failures=0, errors=0, skipped=0)
assert red['junit'] == dict(tests=7, failures=5, errors=0, skipped=0)
assert all(r['evidence_guards_passed'] and all(v is True for v in r['guards'].values()) for r in (positive, red))
assert len(red['guards']) == 13
assert audit['causal_review_passed'] and len(audit['valid_target_failure_identities']) == 5
assert len(copied['complete_inputs']) == 1087 and copied['original_source_unchanged']
floor = read(ROOT / 'artifacts/stage-checkpoint-contract-intake-r34-20261017/receipt.json')
stage = ROOT / '.coordination/20261014/workspaces/coordinator-instance-integration-r24'
assert all(sha(stage / n) == v for n, v in floor['complete_inputs_after'].items())
assert all(sha(ROOT / n) == v for n, v in floor['root_inputs'].items())
when = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
record = dict(actual_task='/root', checked_at=when,
    store_independent_passed=True, store_stage_intake=False, store_root_intake=False,
    job_actual_task='/root/stage_cost_repair_r33', actual_positive2=positive['junit'], positive_finished_at=positive['finished_at'],
    actual_risk7=red['junit'], risk_finished_at=red['finished_at'], risk_all13_guards_true=True,
    causal_review_passed=True, causal_review_at=audit['checked_at'], actual_confirmed_risk_cases=5,
    risk_interpretation='Four actual input-alias backup overwrites and one real revoked-tool verifier occurring after three Store connections; no third-TU claim.',
    third_actual_task='/root/stage_currentness_repair_r33', unfixed_external_copy_at=copied['prepared_at'], external_inputs=1087,
    third_actual_tests=0, third_tooling_revision2_static_review_passed=True,
    cost_hold_released_at='2026-10-17T15:52:28+08:00', two_owned_file_repair_authorized=True,
    repair_actual_frozen_diff_pending=True, original53_and7_test_bytes_immutable=True,
    legal_existing_report_backup_positive_required=True,
    independent_launcher_v1_static_blocked=True, independent_launcher_v2_pending=True,
    stage1082_root1065_unchanged=True, current_stage_joint_passed=False, current_root_joint_passed=False,
    failed_delivery_counts=dict(historical_s01=3, historical_cost=1, new_store=0, new_job=0),
    failure_count_note='Intentional valid risk red and blocked tooling drafts are retained separately; they are not additional delivered-development failures.',
    bridge_public_access_unrestored=True, bridge_restarted=False, archived_s06_r02_touched=False,
    whole_packages_complete=False, real_project_effect_acceptance=False,
    reference_sha256={str(p.relative_to(ROOT)): v for p, v in pins.items()})
for p in (BASE / 'bridge-readonly-r35-1548.json',
          ROOT / 'artifacts/job-indexed-input-probe-source-review-r35-20261017/tooling-v2-review.json',
          ROOT / 'artifacts/coordinator-indexed-probe-phase-records-source-review-r35-20261017/format-helper-review.json'):
    record['reference_sha256'][str(p.relative_to(ROOT))] = sha(p)
assert not OUT.exists(), 'Preserve checkpoint'
OUT.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
tasks = read(HERE / 'tasks.json')
for task in tasks['tasks']:
    if task.get('id') == 'JOB-RUNTIME-FOOTPRINT-REPAIR-R34':
        task.update(status='actual7_valid_red2P5F_independent_causality_confirmed_unfixed_copy_saved_owned_repair_authorized',
            actual_agent_id=record['job_actual_task'], checked_at=when, current_positive_junit=positive['junit'],
            current_risk_junit=red['junit'], actual_risk_causality_confirmed=True, risk_red_executed=True,
            independent_acceptance=False, stage_intake=False, root_intake=False)
    elif task.get('id') == 'JOB-ALL-INDEX-INPUT-PROBE-R35':
        task.update(status='external_unfixed1087_copy_ready_tooling_v2_reviewed_format_metadata_preparing_no_tests_yet',
            actual_agent_id=record['third_actual_task'], actual_test_count=0, checked_at=when,
            workspace='.coordination/20261014/workspaces/coordinator-indexed-input-prewrite-r35',
            independent_acceptance=False, stage_intake=False, root_intake=False)
tasks.update(updated_at=when, latest_phase13_checkpoint=str(OUT.relative_to(ROOT)))
(HERE / 'tasks.json').write_text(json.dumps(tasks, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
paragraph = f'\n\n---\n\n### {when} · 原7真实红独审闭合，未修复副本已保存并释放修复\n\n实际/root/stage_cost_repair_r33正控v3为2P/0F/E/skip，随后原7为2P5F/0Eskip，完整13材料守卫真。协调者于{audit["checked_at"]}独核原XML/命令/Counter/import/211refs和逐ID首因，确认四个真实backup链接覆盖及一次工具已撤回却先发生三次Store连接；不能将原7当成第三TU风险验收。未修复1086已于{copied["prepared_at"]}受控复制至第三probe独立WORK并增加已审唯一测试为1087，原源/Stage1082/Root1065复核同。15:52:28释放Cost，仅按两owned文件修真实已证风险，Store3/Scheduler/Hook/原53与7只读。合法已有报告backup正控另列必测，不以一律拒绝当正确。\n\n第三实际/root/stage_currentness_repair_r33工具revision2经Root静审解决全refs真实重哈希和7green循环依赖，尚无第三实际测试；Root准备具体format元数据。完整native独验启动器原稿静审2P1+3P2阻断已保留，原作者修订，不得提前标ready。既有Store独验369/trace5/USR及八命令全0仍为有界独验，未Stage/Root接入。完整当前Stage/Root联合均未通过，旧Root2551不替代。\n\n公开原task_f702313db8/task_0d7256802a仍unknown，scope仅dead sess_99a5552202/turns0；PID17892不存在，80748为CUA Node，未重启Bridge或恢复S06-R02。历史成本失败1/S01三与新Store/Job交付失败0保留，真实红和草稿源审阻断不新增失败交付。不宣称整工作包或真实项目/LLM/formal/portable通过。证据 {OUT.relative_to(ROOT).as_posix()}。\n'
for name in ('DAG.md', 'PROGRESS.md', 'CURRENT_STATE_R33.md'):
    p = HERE / name
    p.write_text(p.read_text(encoding='utf-8').rstrip() + paragraph, encoding='utf-8', newline='\n')
continuation = read(HERE / 'continuation-r6.json')
continuation.update(latest_phase13_checkpoint=str(OUT.relative_to(ROOT)), latest_checked_at=when,
    job_positive2_current_passed=True, job_risk_red_executed=True, job_risk7_causality_independently_confirmed=True,
    third_unfixed_external_copy_prepared=True, third_probe_actual_tests=0,
    current_stage_joint_validation_passed=False, next_root_intake_performed=False)
(HERE / 'continuation-r6.json').write_text(json.dumps(continuation, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
print(json.dumps(dict(checked_at=when, causal_risks=5, third_copy_inputs=1087, stage_root_joint_passed=False)))
