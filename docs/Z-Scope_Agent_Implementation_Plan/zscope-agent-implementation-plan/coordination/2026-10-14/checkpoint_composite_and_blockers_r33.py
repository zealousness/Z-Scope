"""Preserve bounded independent results and newly discovered unfinished edges."""
from pathlib import Path
import datetime as dt
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
OUT = ROOT / "artifacts/coordinator-stage-repairs-r33-20261017"
read = lambda path: json.loads(path.read_text(encoding="utf-8"))
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


now = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
composite_path = ROOT / "artifacts/coordinator-native-composite-r33-20261017/review.json"
composite = read(composite_path)
assert composite["bounded_composite_native_independent_passed"]
assert composite["junit"] == {name: dict(tests=49, failures=0, errors=0, skipped=0) for name in ("native", "classifier")}
legacy_path = ROOT / "artifacts/coordinator-contract-tests-r33-20261017/review.json"
legacy = read(legacy_path)
assert legacy["junit"] == dict(tests=57, failures=1, errors=0, skipped=0)
probe_path = legacy_path.parent / "raii-first-gate-probe.json"
assert read(probe_path)["reproduced_first_refusal_gate"]
cost = ROOT / ".coordination/20261014/workspaces/stage-cost-repair-r33/artifacts/stage-cost-r33"
assert read(cost / "quality-cost/receipt.json")["source_unchanged"]
references = [composite_path, legacy_path, probe_path, cost / "green-cost/receipt.json", cost / "quality-cost/receipt.json", ROOT / "artifacts/stage-final-repair-source-review-r33-20261017/cost-2c8a-blocked-source-review.json", ROOT / "artifacts/coordinator-review-revision-repair-r33-20261017/candidate.json"]
target = OUT / "composite-and-blockers-checkpoint.json"
assert not target.exists()
blockers = ["P1 frozen native dependency-set removal still needs actual red and repair", "P2 prior shared-client lifetime usage must not count in current batch", "Review checker rejects 11 exact current catalog revisions; actual RAII first gate confirmed", "Current Stage still needs fresh full-input guarded joint+UI browser environment and quality verification"]
evidence = dict(actual_task="/root", observed_at=now, composite_finished_at=composite["finished_at"], composite_junit=composite["junit"], composite_source="Context d78 + private V3 64c3; P2 cost old", composite_independent_scope_passed=True, P1_final_acceptance=False, cost_original9_producer_green=True, cost_original_candidate_full_quality_passed=True, cost_original_candidate_source_blocked=True, new_cost16_red_in_progress=True, legacy_junit=legacy["junit"], actual_raii_reason="unqualified_rule_contract_revision", independent_current_revision_source_audit_in_progress=True, current_shared_blockers=blockers, evidence_sha256={path.relative_to(ROOT).as_posix(): sha(path) for path in references}, stage_repair_intake=False, root_intake=False, joint_validation_passed=False, old_s01_failed_deliveries=3, new_failed_deliveries=0)
write(target, evidence)
tasks = read(HERE / "tasks.json")
by_id = {row["id"]: row for row in tasks["tasks"]}
by_id["COORD-INSTANCE-INTEGRATION-R24"].update(checked_at=now, status="r33_bounded_composite_passed_new_dependency_usage_and_review_revision_edges_unfinished", current_shared_blockers=blockers, latest_composite_checkpoint=target.relative_to(ROOT).as_posix(), shared_stage_source_review_passed=False, full_stage_quality_passed=False, joint_validation_passed=False)
by_id["STAGE-CURRENTNESS-REPAIR-R33"].update(status="original45_full_gate_repaired_and_independent_composite_pass_new_input_set_red_pending", latest_composite_checkpoint=target.relative_to(ROOT).as_posix(), independent_acceptance=False, original_bounded_composite_independent_passed=True, artifact_delivered=False)
by_id["STAGE-COST-REPAIR-R33"].update(status="original9_green_and_quality_passed_source_blocked_shared_usage_new16_red_actual_running", latest_composite_checkpoint=target.relative_to(ROOT).as_posix(), independent_acceptance=False, artifact_delivered=False)
if "COORD-REVIEW-REVISION-REPAIR-R33" not in by_id:
    tasks["tasks"].append(dict(id="COORD-REVIEW-REVISION-REPAIR-R33", owner="coordinator", actual_task_id="/root", workspace=".coordination/20261014/workspaces/coordinator-contract-tests-r33", write_paths=["zscope/core/validation/review_checks.py", "tests/test_review_current_revisions_r33.py"], status="actual_native_first_gate_confirmed_narrow_candidate_prepared_new_test_format_pending", dispatched=False, execution_confirmed=True, artifact_available=True, artifact_delivered=False, independent_acceptance=False, integrated=False, joint_validation_passed=False, whole_package_complete=False, candidate="artifacts/coordinator-review-revision-repair-r33-20261017/candidate.json", actual_native_probe=probe_path.relative_to(ROOT).as_posix(), ownership_extension="followups-r12/coordinator-instance-integration-r24-ownership-extension-09.json", checked_at=now))
tasks["updated_at"] = now
write(HERE / "tasks.json", tasks)
continuation = read(HERE / "continuation-r6.json")
continuation.update(updated_at=now, latest_composite_checkpoint=target.relative_to(ROOT).as_posix(), current_shared_blockers=blockers)
write(HERE / "continuation-r6.json", continuation)
note = f"""## {now} · R33 有界组合独验通过，后续边界仍未完成

协调者/root在{composite['finished_at']}完成固定d78 Context+V3 64c3组合独验：native/recovery49项与classifier撤回49项分别0fail/0error/0skip；原4+45及新增49精确Counter、完整1080输入、Root1065、配置、引用与真实tool/libs/header安装前后守卫全真。两组范围不同，不合算工作包通过。当前性producer原45 XML曾因launcher误筛classname导致outer1，旧false-gate收据保留并更正；修复后原45完整gate补跑通过。后续新发现冻结依赖集合被删、同时header失信的消费风险待实际红和修复，不能据原49+49宣布P1最终通过。

成本owner /root/stage_cost_repair_r33 的2c8候选原9case实际green及Black/compileall/normal+fresh mypy360全返回0；独立源审仍阻断共享客户端全生命周期usage串轮。保持原9绿色和blocked-source收据不回写；仅EOF扩展7个真实LLMClient离线accounting用例（原fc0字节prefix保留），新16case红已实际运行。离线usage记录不是provider费用或真实LLM效果验收。

协调者四个旧测试契约适配全57项实际56pass/1fail，所有材料与旧Counter守卫真，不能宣布其独验通过。真实native同fixture首拒绝gate已确认：RAII候选11遭Review表[1,10]拒绝、未进入lifecycle、无proof。只读审计另核11/11当前catalog revisions都被旧表拒绝；正在准备逐ID增加其已当前确切版本，未知revision仍拒绝，算法/绑定/收据格式与实验默认开关不改，尚未进入WORK/Stage/Root。

当前阻塞：{'; '.join(blockers)}。证据 {target.relative_to(ROOT).as_posix()}；原R32 3543/42F/4E/8skip、旧准备/launcher错误、历史S01失败3均保留。当前无Stage修复集成、无Root导入或新联合通过，无完整S01/S08/U01/真实项目/formal结论。
"""
for path in (HERE / "CURRENT_STATE_R33.md", HERE / "PROGRESS.md", HERE / "DAG.md"):
    path.write_text(note + "\n---\n\n" + path.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
print(json.dumps(dict(receipt=target.relative_to(ROOT).as_posix(), observed_at=now)))
