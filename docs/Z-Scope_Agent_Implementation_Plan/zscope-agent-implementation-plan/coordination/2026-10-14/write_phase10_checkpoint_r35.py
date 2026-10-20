"""Preserve passing producer scope and actual quality failure separately."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
BASE = ROOT / "artifacts/coordinator-stage-repairs-r33-20261017"
OUT = BASE / "phase10-checkpoint.json"
read = lambda p: json.loads(p.read_text(encoding="utf-8"))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
if sys.platform != "linux" or sys.flags.optimize:
    raise RuntimeError("Unoptimized Linux Python required")
when = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
floor = read(ROOT / "artifacts/stage-checkpoint-contract-intake-r34-20261017/receipt.json")
stage = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
assert len(floor["complete_inputs_after"]) == 1082 and len(floor["root_inputs"]) == 1065
assert all(sha(stage / p) == v for p, v in floor["complete_inputs_after"].items())
assert all(sha(ROOT / p) == v for p, v in floor["root_inputs"].items())
store = ROOT / ".coordination/20261014/workspaces/store-active-transactions-r35/artifacts/store_active_transactions_r35"
regression = store / "regression-20261017T062944.334287Z"
quality = store / "quality-20261017T063212.233940Z"
result = read(regression / "receipt.json")
assert result["all_selected_checks_green"] and all(result["gates"].values())
assert result["junit"] == dict(tests=364, failures=0, errors=0, skips=0)
quality_journals = [quality / f"quality-{i}-command.json" for i in range(5)]
codes = [read(p)["returncode"] for p in quality_journals]
assert codes == [0, 1, 1, 1, 0]
refs = [
    BASE / "phase9-checkpoint.json", regression / "receipt.json", regression / "pytest.xml", regression / "before.json", regression / "after.json",
    *quality_journals,
    ROOT / "artifacts/store-active-transactions-source-review-r35-20261017/candidate-v4-review.json",
    ROOT / "artifacts/job-runtime-footprint-source-review-r34-20261017/native-build-v4-evidence-review.json",
    ROOT / "artifacts/coordinator-store-independent-launcher-source-review-r35-20261017/revised-review.json",
    ROOT / "artifacts/stage-joint-launcher-install-r35-20261017/revision-4.json",
    ROOT / "artifacts/job-runtime-footprint-repair-r34-20261017/scheduler-readonly-dependency-override-r35/receipt.json",
    ROOT / "artifacts/runtime-footprint-module-docs-r35-20261017/preparation.json",
]
record = dict(actual_task="/root", checked_at=when, stage1082_root1065_exact=True,
    store_actual_task="/root/stage_currentness_repair_r33", store_current_bounded_regression=dict(finished_at=result["finished_at_utc"], tests=364, failures=0, errors=0, skipped=0, original227_exact=True, all_guards=True, source_sha256="b036cf484b5836bceabea228fdff18a81273df7914f6488e150701a8e5504403"),
    store_quality_command_returncodes=codes,
    store_quality_passed=False,
    store_quality_issue="Actual sqlite3 supertype accepts Callable[[str], object] | None; two owned annotations currently narrow return to None. Final candidate correction and same-source regression/quality pending.",
    store_prior_v3_actual65=dict(passed=62, failures=3, errors=0, skipped=0, status="preserved; two foreign-wrapper SQL-order failures and one test return-shape mismatch corrected in reviewed V4"),
    store_prior_trace_v2_actual5=dict(passed=3, failures=2, errors=0, skipped=0, status="preserved genuine transaction-generation reentry failure; later artifact5 passed"),
    store_final_3_source_candidate_accepted=False, store_independent_passed=False,
    job_actual_task="/root/stage_cost_repair_r33", job_valid_red_running=True,
    job_actual_corrected_collection_count=53, job_valid_red_accepted=False,
    native_real_build_independently_verified=True, native_behavior_independent_passed=False,
    joint_rev4_installed_inert=True, joint_execution=False,
    module_docs_draft_only=True, stage_new_intake=False, root_intake=False,
    stage_full_joint_passed=False, root_full_joint_passed=False,
    failed_delivery_counts=dict(store=0, job=0, historical_cost=1, historical_s01=3),
    bridge_restarted=False, archived_s06_r02_touched=False,
    real_project_effect_acceptance=False, whole_packages_complete=False,
    reference_sha256={str(p.relative_to(ROOT)): sha(p) for p in refs})
if OUT.exists():
    raise RuntimeError("Preserve existing checkpoint")
OUT.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
tasks = read(HERE / "tasks.json")
for task in tasks["tasks"]:
    if task.get("id") == "STORE-ACTIVE-TRANSACTION-SEAM-R35":
        task.update(status="producer364_and_old227_passed_quality_annotation_error_final3source_pending", producer_regression_passed=True,
            producer_regression_tests=364, producer_original227_exact=True, producer_regression_receipt=str((regression / "receipt.json").relative_to(ROOT)),
            producer_quality_passed=False, producer_quality_returncodes=codes, independent_acceptance=False, checked_at=when)
    elif task.get("id") == "JOB-RUNTIME-FOOTPRINT-REPAIR-R34":
        task.update(status="native_build_verified_corrected53_formal_red_running_python_candidate_wiring", corrected_actual_collection_count=53,
            native_build_independently_verified=True, valid_red_accepted=False, independent_acceptance=False, checked_at=when)
    elif task.get("id") == "STAGE-JOINT-LAUNCHER-DRAFT-R35":
        task.update(status="revision4_additive_trace_gate_reviewed_installed_separately_readiness_pending", source_review_passed=True,
            installed_path=str((HERE / "verify_stage_joint_r35_rev4.py").relative_to(ROOT)), execution_confirmed=False)
tasks.update(updated_at=when, latest_phase10_checkpoint=str(OUT.relative_to(ROOT)))
(HERE / "tasks.json").write_text(json.dumps(tasks, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
paragraph = f"\n\n---\n\n### {when} · Store364真实通过但质量失败，53项有效红仍执行\n\n实际/root/stage_currentness_repair_r33的V4于{result['finished_at_utc']}完成364/0F/E/skip，原227与完整364原始身份/次数完全一致，完整source/config/Root/Stage/refs/host守卫真。新artifact5已通过；随后质量命令实际返回{codes}，normal/fresh mypy同报Store trace callback返回注解比真实stdlib类型更窄。仅两处None→object注解修正已授权，待原phase/USR结束后与永久5一并形成最终1084源；严格当前SHA绑定不豁免，需最终同源364+永久5/质量及协调者369+USR/质量独验。旧364绿不能冒充新注解版本通过，旧62P/3F、trace2F及全部日志保留。\n\n实际/root/stage_cost_repair_r33的新native工具已真实构建且独立核实，仍无Python行为接纳；修正fixture实际同53项已collection通过，正式红已获WSL slot0执行，前一invalid53不补称有效。协调者在artifact候选仅补Scheduler已捕获input_revision这一共享参数；原red树/Stage/Root不改。R35 rev4联合启动器在保留ec9原件的另名路径安装，永久trace门禁已审，真实ready依赖未齐不执行。三模块文档仅draft，最终实现审后应在完整独验freeze前纳入。\n\nStage1082/Root1065与HEAD010f402均仍是原版本，无新Stage/Root产品接入及新联合通过。Store/Job交付失败计数0、成本历史1/S01历史3分别保留；内部失败和无效探针另列，不混同交付次数。不重启Bridge、不恢复S06-R02，不宣称完整工作包或真实项目/LLM/formal/portable验收。证据 {OUT.relative_to(ROOT).as_posix()}。\n"
for name in ("DAG.md", "PROGRESS.md", "CURRENT_STATE_R33.md"):
    path = HERE / name
    path.write_text(path.read_text(encoding="utf-8").rstrip() + paragraph, encoding="utf-8", newline="\n")
continuation = read(HERE / "continuation-r6.json")
continuation.update(latest_phase10_checkpoint=str(OUT.relative_to(ROOT)), latest_checked_at=when,
    current_stage_inputs=1082, current_stage_joint_validation_passed=False, next_root_intake_performed=False)
(HERE / "continuation-r6.json").write_text(json.dumps(continuation, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps(dict(checked_at=when, store364_passed=True, quality=codes, joint_passed=False)))
