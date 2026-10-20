"""Preserve confirmed probe scope and dependency blockers, without acceptance."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
OUT = ROOT / "artifacts/coordinator-stage-repairs-r33-20261017"
P1 = ROOT / ".coordination/20261014/workspaces/stage-currentness-repair-r33/artifacts/stage-currentness-r33"
P2 = ROOT / ".coordination/20261014/workspaces/stage-cost-repair-r33/artifacts/stage-cost-r33"

def read(path):
    return json.loads(path.read_text(encoding="utf-8"))

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

def counts(path):
    tree = ET.parse(path).getroot()
    return dict(tests=len(list(tree.iter("testcase"))), failures=len(list(tree.iter("failure"))), errors=len(list(tree.iter("error"))), skipped=len(list(tree.iter("skipped"))))

now = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
files = [P1 / "red-20261017T024343.006572Z/pytest.xml", P1 / "red-20261017T024820.183258Z/pytest.xml", P2 / "red/pytest.xml", P2 / "diagnostic-original/pytest.xml", P2 / "diagnostic-bridge/pytest.xml", OUT / "supplemental-inputs.json", ROOT / "artifacts/stage-repair-probe-source-review-r33-20261017/initial-currentness-red-causal-audit.json", ROOT / "artifacts/stage-repair-probe-source-review-r33-20261017/supplemental-input-audit.json"]
assert all(path.is_file() for path in files)
probe_counts = {path.relative_to(ROOT).as_posix(): counts(path) for path in files if path.suffix == ".xml"}
assert counts(files[0]) == dict(tests=38, failures=34, errors=0, skipped=0)
assert counts(files[1]) == dict(tests=45, failures=39, errors=0, skipped=0)
assert counts(files[2]) == dict(tests=3, failures=0, errors=3, skipped=0)
assert counts(files[3]) == dict(tests=1, failures=0, errors=1, skipped=0)
assert counts(files[4]) == dict(tests=1, failures=0, errors=1, skipped=0)
evidence = dict(observed_at=now, actual_task="/root", probe_counts=probe_counts, evidence_sha256={path.relative_to(ROOT).as_posix(): sha(path) for path in files}, currentness_initial_red_causal_split=dict(valid_target_failures=27, readonly_view_exceptions=4, consumer_baseline_failures=3, passed_controls=4), corrected_currentness_red_producer_split=dict(valid_exact_target_failures=29, analyzer_recovery_store_guard_failures=7, consumer_baseline_failures=3, passed_controls=6, independently_rechecked=False), cost_target_reproduction_confirmed=False, original_native_without_metric_injection_failed=True, lookup_bridge_original_function_info_error_removed_but_collection_still_blocked=True, complete_readonly_material_baseline=1077, supplemental_set=108, already_guarded_pyproject=1, missing_stage_execution_guard_count=107, supplemental_copied_each=106, joint_r32_still_running=True, root_intake=False, stage_repair_intake=False, current_shared_blockers=["tool/loader/header trust currentness", "restored historical cost attribution", "native full-signature query to physical entry lookup and collection closure", "parallel_analyzer:492 full-mypy no-any-return", "R32 Stage actual supplemental input guard incomplete"], prior_s01_actual_failed_deliveries=3, prior_s01_bounded_module_accepted=True, new_producer_failed_deliveries=0)
write(OUT / "probe-checkpoint.json", evidence)
task_path = HERE / "tasks.json"
tasks = read(task_path)
by_id = {item["id"]: item for item in tasks["tasks"]}
for logical in ("STAGE-CURRENTNESS-REPAIR-R33", "STAGE-COST-REPAIR-R33"):
    row = by_id[logical]
    row.update(execution_confirmed=True, status="actual_native_probes_executed_isolated_repair_in_progress_dependent_consumer_closure_blocked", latest_probe_checkpoint="artifacts/coordinator-stage-repairs-r33-20261017/probe-checkpoint.json", artifact_delivered=False, independent_acceptance=False, stage_intake=False, integrated=False, joint_validation_passed=False, actual_failed_deliveries=0)
by_id["COORD-INSTANCE-INTEGRATION-R24"].update(current_shared_blockers=evidence["current_shared_blockers"], full_stage_quality_passed=False, shared_stage_source_review_passed=False, latest_probe_checkpoint="artifacts/coordinator-stage-repairs-r33-20261017/probe-checkpoint.json", supplemental_complete_baseline_count=1077)
tasks["updated_at"] = now
write(task_path, tasks)
continuation_path = HERE / "continuation-r6.json"
continuation = read(continuation_path)
continuation.update(updated_at=now, latest_probe_checkpoint="artifacts/coordinator-stage-repairs-r33-20261017/probe-checkpoint.json", latest_parallel_snapshot=evidence)
write(continuation_path, continuation)
note = f"""## {now} · R33 实际探针与材料守卫精确更正

两个新6.1-sol/xhigh隔离任务已有真实Linux/native探针执行，尚无最终交付/独验/Stage接入。currentness首轮38/34F/0E/0skip，独审精确拆为27目标未撤回、4只读视图异常、3变更前consumer基线不闭合及4通过对照；不能将34全算当前性复现。校正第二红45/39F/0E/0skip，producer拆为29纯exact遗漏、7Analyzer/恢复/SQL早晚guard未撤回、3同一consumer基线阻断及6对照通过，最终独审待复核。Context仅在自己隔离目录修复，未接入Stage。

成本首轮3setup errors尚未到成本断言，不能视为P2有效红；无任何指标注入的原all-restored单例也实际setup calls6而非2，证明共享native入口回归。Parallel受限物理lookup桥消除function_info_not_found，但原单例仍1setup error，真实report函数completed2/failed0而队列failed2/结算0，收集闭合原因继续查；未降低2实例/receipt断言，P2成本修复仍等待有效红。

完整材料审计：Root1065比Stage969受控投影多108项，实际Stage副本全部同SHA。pyproject已由原configuration guard保护，因此原R32实际完全漏保护107项（其中32份实际relative docs测试），此前“108全部漏保护”更正为107；原完整清单/收据保留。两个R33工作目录各缺106项，协调者已顺序复制补全，完整基线1077+各自新增测试。原969与历史验证收据未改，Root/Stage产品未改。R32联合继续执行但本轮不能正式接纳联合通过；后续启动器必须保护所有实际Stage副本。

证据：artifacts/coordinator-stage-repairs-r33-20261017/probe-checkpoint.json、supplemental-inputs.json；artifacts/stage-repair-probe-source-review-r33-20261017/。S01有界模块接纳与旧三次失败计数不变；未宣称完整工作包、真实项目或formal通过。
"""
for path in (HERE / "CURRENT_STATE_R33.md", HERE / "PROGRESS.md", HERE / "DAG.md"):
    path.write_text(note + "\n---\n\n" + path.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
print(json.dumps(dict(receipt=(OUT / "probe-checkpoint.json").relative_to(ROOT).as_posix(), observed_at=now)))
