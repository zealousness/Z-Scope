"""Reconcile frozen R30 evidence; keep full dependency gates failed/pending."""
from collections import Counter
from pathlib import Path
import datetime as dt
import hashlib
import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

assert sys.platform == "linux" and not sys.flags.optimize
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
STAGE = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
OUT = ROOT / "artifacts/coordinator-stage-final-r30-20261017"


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def cases(path):
    return Counter((node.get("classname", ""), node.get("name", "")) for node in ET.parse(path).getroot().iter("testcase"))


def artifact(name):
    return ROOT / "artifacts" / name


intake_path = artifact("consumer-stage-intake-r30-20261017/receipt.json")
repair_path = artifact("stage-quality-repair-r30-20261017/repair-source.json")
regression_path = artifact("coordinator-stage-regression-r30-20261017/review.json")
quality_path = artifact("coordinator-stage-quality-r30-20261017/review.json")
source_review_path = artifact("stage-independent-quality-review-r30-20261017/review.json")
bridge_path = artifact("coordinator-bridge-readonly-final-r30-20261017/review.json")
intake, repair, regression, quality, source_review, bridge = map(read, (intake_path, repair_path, regression_path, quality_path, source_review_path, bridge_path))
assert intake["stage_intake"] and len(intake["changed_paths"]) == 14 and not intake["root_intake"]
assert len(repair["modified_paths"]) == 9 and not repair["tests_or_assertions_weakened"]
assert source_review["actual_task"] == "/root/store_source_review_r28"
assert source_review["source_review_passed"] and source_review["blocking_findings"] == []
assert source_review["bounded_regression_accepted"] and not source_review["full_stage_quality_passed"]
for receipt in (regression, quality):
    assert receipt["bounded_checks_passed"] and all(item["returncode"] == 0 for item in receipt["commands"])
    assert all(receipt[key] for key in ("sources_unchanged", "configurations_unchanged", "root_unchanged", "producer_unchanged", "references_unchanged"))
    assert not receipt["full_stage_quality_passed"] and not receipt["root_joint_verification"]
assert regression["junit"] == dict(tests=1147, failures=0, errors=0, skipped=0)
assert regression["required1120_case_counter_preserved"] and regression["prior14_failure_probe_case_counter_preserved"]
current_xml = regression_path.parent / "results.xml"
required = cases(artifact("coordinator-consumer-repair-r29-20261017/results.xml")) + cases(artifact("coordinator-store-queue-r26-e0560b7b2e9d/results.xml"))
probe_cases = cases(artifact("coordinator-stage-quality-probe-corrected-before-r30-20261017/results.xml"))
actual_cases = cases(current_xml)
assert sum(actual_cases.values()) == 1147 and sum(required.values()) == 1120 and sum(probe_cases.values()) == 14
assert not required - actual_cases and not probe_cases - actual_cases
assert not any(node.tag in {"failure", "error", "skipped"} for node in ET.parse(current_xml).getroot().iter())

snapshot = {path.relative_to(STAGE).as_posix(): sha(path) for directory in ("zscope", "scripts", "test", "tests", "docs/modules") for path in (STAGE / directory).rglob("*") if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"}
assert snapshot == repair["full_stage_source_after"] == regression["source_before"]
assert len(snapshot) == 967
assert all(sha(STAGE / path) == digest for path, digest in intake["copied_source_sha256"].items())
assert not (STAGE / "zscope/semantics/instance_semantics.py").exists()
root_inputs = read(artifact("coordinator-r23-ui-projection-union-20261016/source-evidence.json"))["after"]
assert len(root_inputs) == 1065 and all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
assert head == "010f40210b54ba0f79a088312ce5d8be3a82ace0"
producer_inputs = read(artifact("coordinator-consumer-repair-r29-20261017/review.json"))["source_before"]
assert all(sha(ROOT / ".coordination/20261014/workspaces/consumer-exact-repair-r29" / path) == digest for path, digest in producer_inputs.items())
state_path = ROOT / ".coordination/20261014/bridge-route-check/state.json"
assert sha(state_path) == "a7b8c7bb52be3e4eb2a3a50ad7ff872abde794529f0a5682379ec5cd0bf7a4a3"
assert not bridge["original_public_access_restored"] and bridge["bridge_dispatches"] == 0
assert not bridge["s01_fourth_dispatched"] and bridge["s01_actual_failed_delivery_count_preserved"] == 3

mypy_evidence = {}
for mode in ("mypy-after", "mypy-fresh-after"):
    path = artifact(f"coordinator-stage-{mode}-r30-20261017/review.json")
    receipt = read(path)
    lines = (path.parent / "command-0.log").read_text(encoding="utf-8").splitlines()
    errors = [line for line in lines if re.match(r"zscope/.*: error:", line)]
    assert receipt["commands"][0]["returncode"] == 1 and not receipt["bounded_checks_passed"]
    assert len(errors) == 4 and all("zscope.semantics.instance_semantics" in line and "[import-untyped]" in line for line in errors)
    assert "Found 4 errors in 4 files (checked 359 source files)" in lines
    mypy_evidence[mode] = dict(receipt=path.relative_to(ROOT).as_posix(), finished_at=receipt["finished_at"], returncode=1, error_count=4, errors=errors)

refs = [intake_path, repair_path, regression_path, quality_path, source_review_path, source_review_path.parent / "DELIVERY.md", source_review_path.parent / "initial-analysis.json", bridge_path, current_xml, Path(__file__), HERE / "test_slot.py", HERE / "check_stage_r30.py"]
for name in ("quality-probe-before", "quality-probe-corrected-before", "quality-probe-after", "mypy-before", "mypy-fresh-before", "mypy-after", "mypy-fresh-after", "format"):
    refs.append(artifact(f"coordinator-stage-{name}-r30-20261017/review.json"))
refs += [HERE / f"followups-r12/coordinator-instance-integration-r24-ownership-extension-{suffix}.json" for suffix in ("05", "06")]
reference_hashes = {path.relative_to(ROOT).as_posix(): sha(path) for path in refs}
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
OUT.mkdir(exist_ok=False)
proof = dict(recorded_at=at, actual_coordinator_task="/root", logical_task="COORD-INSTANCE-INTEGRATION-R24", actual_consumer_repair_task="/root/consumer_exact_repair_r29", actual_source_reviewer_task=source_review["actual_task"], source_review_frozen_at=source_review["frozen_at"], reviewer_model="gpt-6.1-sol", reviewer_reasoning_effort="xhigh", stage_consumer_intake_at=intake["integrated_at"], stage_consumer_files=14, quality_modified_source_test_doc_paths=9, stage_frozen_inputs=967, source_review_passed=True, bounded_stage_regression=regression["junit"], bounded_stage_regression_finished_at=regression["finished_at"], required1120_case_counter_preserved=True, previous14_probe_counter_preserved=True, compileall_and_black20_returncodes=[item["returncode"] for item in quality["commands"]], compileall_black_finished_at=quality["finished_at"], independent_eight_mypy_diagnostics_removed=True, complete_mypy=mypy_evidence, full_stage_quality_passed=False, bounded_stage_verification_passed=True, full_stage_native_instance_acceptance=False, real_s01_advisory_context_path_verified=False, new_native_currentness_parameter_executed=False, independent_acceptance=False, root_intake=False, root_joint_verification=False, root_r23=dict(head=head, bound_inputs=1065, tests=2551, selected_files=171, six_commands_zero=True, unchanged=True, new_rerun=False), consumer_prior_actual_failed_delivery_preserved=1, consumer_repaired_slice_consecutive_failures=0, s01=dict(task_id="task_f702313db8", session_id="sess_6ecde27723", actual_failed_deliveries=3, origin_p1_findings=2, fourth_dispatched=False, original_public_access_restored=False), original_s08_task_id="task_0d7256802a", services_started_or_restarted=0, bridge_dispatches=0, archived_s06_operations=0, private_rpc_calls=0, platform_bypass=False, original_bridge_state_unchanged=True, all_failure_receipts_retained=True, whole_packages_complete=False, references_sha256=reference_hashes)
write(OUT / "review.json", proof)
next_actions = dict(recorded_at=at, no_new_dispatch=True, independently_ready_slices_already_in_stage=["accepted S08 MIN codec", "accepted consumer exact repair", "accepted Store receipt bound repair"], completed_this_turn=["consumer14 Stage intake", "eight independent mypy diagnostics repaired", "same14 runtime/boundary probes passed", "current Stage1147 bounded regression passed", "compileall and Black20 passed", "independent source review passed"], actual_blockers=["Original public task/session owner access remains unknown; maintenance recovery unverified", "S01 third actual delivery retains two real native-origin P1 findings; failure count3/fourth not dispatched", "Both complete standard and fresh mypy still4S01import errors/359 rc1", "Full native instance/currentness/recovery/PRE/current Validator not accepted"], after_original_access_restored=["Read-only recheck original owner/task/session and all live file ownership", "Continue original S01 fourth repair using existing pending specification and failure history", "Independently accept exact source and native-origin probes, then coordinator integrates S01 into Stage", "Execute new native currentness parameter and actual advisory-context path, full Stage quality and native integration", "Only after current exact acceptance, controlled Root intake and fresh Root union regression"], remaining_parallel_work="Maintenance public-access restoration may proceed separately; no new product task with all required dependencies proven ready is dispatched in this receipt.", routing="Complex allowed tasks prefer6.1-sol/xhigh; ordinary nonUI originalZCode policy and crossIDfailurecount retained; KimiNEWpaused, DSHsimple, UIAstra; no model routing bypass", separate_unaccepted=["WholeS01/S08/U01 and downstream work packages", "Real-project/LLM scan effects", "ConditionalS10/Q01/Q02", "Formal benchmark/portable release and external waits"], root_product_writes_authorized_by_this_record=False)
write(OUT / "next-actions.json", next_actions)

ledger = read(HERE / "tasks.json")
rows = {row["id"]: row for row in ledger["tasks"]}
assert rows["S01-INSTANCE-SEMANTICS-MIN-R23"]["consecutive_failed_actual_deliveries"] == 3
assert rows["ASTRA-INSTANCE-CONSUMERS-R25"]["prior_failed_actual_deliveries_before_acceptance"] == 1
for identity in ("ASTRA-INSTANCE-CONSUMERS-R25", "CONSUMER-EXACT-REPAIR-R29"):
    row = rows[identity]
    row.update(status="accepted_repaired_consumer_integrated_stage_r30_bounded1147_verified_full_mypy_four_s01_errors_no_root_intake", coordinator_stage_intake=True, stage_regression_pending=False, stage_bounded_regression_passed=True, stage_regression_receipt=regression_path.relative_to(ROOT).as_posix(), stage_full_quality_passed=False, integrated=False, joint_verification=False, checked_at=at)
coordinator = rows["COORD-INSTANCE-INTEGRATION-R24"]
coordinator.update(status="consumer14_stage_intaken_eight_independent_quality_errors_fixed_source_review_and_bounded1147_passed_full_mypy_four_s01_errors_blocked", bounded_stage_regression_passed=True, stage_bounded_checks_receipt=(OUT / "review.json").relative_to(ROOT).as_posix(), stage_independent_source_review=source_review_path.relative_to(ROOT).as_posix(), stage_compileall_black_passed=True, stage_full_quality_passed=False, full_stage_mypy_accepted=False, fresh_mypy_remaining_error_count=4, fresh_mypy_returncode=1, current_stage_revalidation_required_after_intake=True, bounded_current_stage_revalidation_complete=True, full_native_and_dependency_validation_still_required=True, independent_acceptance=False, integrated=False, joint_verification=False, checked_at=at)
ledger.update(updated_at=at, latest_handoff=(OUT / "review.json").relative_to(ROOT).as_posix(), latest_next_actions=(OUT / "next-actions.json").relative_to(ROOT).as_posix(), bridge_public_access_observation=bridge_path.relative_to(ROOT).as_posix(), current_root_status="RootR23 unchanged2551/171/six/1065; consumer14 integratedStage; currentStage bounded1147/0/0/0 andcompileallBlack20 passed; independent source reviewpassed; fullstandard/freshmypy4S01errors/359 rc1; S01failure3/fourthnotdispatched; noRootintake/fullpackageclaim")
for entry in ledger["next_module_tasks"]:
    row = rows[entry["id"]]
    entry.update({key: row.get(key) for key in entry})
    entry.update({key: row[key] for key in ("stage_bounded_regression_passed", "stage_full_quality_passed", "bounded_stage_regression_passed") if key in row})
write(HERE / "tasks.json", ledger)
continuation = read(HERE / "continuation-r6.json")
continuation.update(updated_at=at, active_phase=ledger["current_root_status"], latest_handoff=ledger["latest_handoff"], next_module_tasks=ledger["next_module_tasks"], bridge_public_access_observation=ledger["bridge_public_access_observation"], latest_next_actions=ledger["latest_next_actions"], whole_packages_complete=False)
write(HERE / "continuation-r6.json", continuation)

note = f"""## {at} · R30 Stage 有界验证完成，完整质量与 S01 仍阻塞

协调者 /root 已于 {intake['integrated_at']} 将 /root/consumer_exact_repair_r29 独验通过的消费端返修及匹配依赖共14文件集成至 Stage；所有权 extension05，无冲突。随后仅在协调者所有权内修改9个产品/测试/模块文档路径，修复8个独立 mypy 诊断与异常记录问题；原14消费端输入未变，967个 Stage 输入冻结。详见 artifacts/consumer-stage-intake-r30-20261017/receipt.json 和 artifacts/stage-quality-repair-r30-20261017/repair-source.json。

当前 Stage 实际回归于 {regression['finished_at']} 完成：1147 passed，0 failed/error/skipped，33仓库测试文件加不可变外部探针。独立重建 Counter 确认原消费端893和Store227的1120个身份全部保留，原14失败探针身份也全部保留；1147来自本次真实执行，不是历史数字相加。compileall 与 Black20 于 {quality['finished_at']} 完成，两命令均0。真实 Linux/WSL、默认fd捕获、ext4临时目录、外层测试槽不变。证据 artifacts/coordinator-stage-regression-r30-20261017/review.json 和 artifacts/coordinator-stage-quality-r30-20261017/review.json。

独立源码审查 /root/store_source_review_r28（6.1-sol/xhigh）于 {source_review['frozen_at']} 冻结，阻断项0；仅接受已核实的有界修复与回归。标准与 --no-incremental 的完整 mypy 均仍4个 S01 import-untyped 错误/359文件、退出1，完整 Stage 质量门禁未通过。未使用忽略、替身模块、类型强转或弱化测试。新增真实 native currentness 参数与实际 S01 advisory-context 路径未验收，不能由独立探针替代。源码审查见 artifacts/stage-independent-quality-review-r30-20261017/review.json。

Bridge 最终只读检查记录于 {bridge['recorded_after_readonly_checks_utc']}：task_f702313db8/task_0d7256802a 的 check_task 与 get_result 均 unknown task，当前实例 sessions 空、另5个存活实例。原17892不存在，80748是00:17:48创建的Codex CUA Node复用PID；原公开访问恢复未证明。协调者未启动或重启服务、未重复派单、未访问私有RPC或恢复旧S06-R02。S01第三轮仍2个native-origin P1，实际失败计数3，第四轮未派发；消费端原失败交付1及修复切片通过后连续失败0均保留。证据 artifacts/coordinator-bridge-readonly-final-r30-20261017/review.json。

Root HEAD010f40210b54ba0f79a088312ce5d8be3a82ace0 与1065绑定输入未变；R23原2551项/171文件/六命令0仍为该Root版本的有界验证，本轮未导入Root、未重新运行Root。原有失败日志和收据全部保留。完整S01/S08/U01、native恢复/PRE/current Validator与下游包仍未完成；真实项目效果、条件S10/Q01/Q02、正式benchmark/portable与外部等待单列。

下一步须维护会话恢复原公开owner/task/session，再只读核对活跃任务和文件所有权，按原失败历史推进S01第四轮，独验后集成Stage，完成真实依赖/native/完整质量，最后才允许受控Root导入和新联合回归。本记录没有新派单，也没有授权绕过平台限制。最终收据 artifacts/coordinator-stage-final-r30-20261017/review.json；后续依赖 artifacts/coordinator-stage-final-r30-20261017/next-actions.json。

---

"""
for name in ("PROGRESS.md", "DAG.md"):
    path = HERE / name
    path.write_text(note + path.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
(HERE / "CURRENT_STATE_R30.md").write_text(note, encoding="utf-8", newline="\n")
(OUT / "DELIVERY.md").write_text(note, encoding="utf-8", newline="\n")
assert all(sha(ROOT / path) == digest for path, digest in reference_hashes.items())
recorded = read(HERE / "tasks.json")
assert recorded["latest_handoff"] == (OUT / "review.json").relative_to(ROOT).as_posix()
assert all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
print(json.dumps(dict(recorded_at=at, receipt=(OUT / "review.json").relative_to(ROOT).as_posix(), bounded_stage_tests=1147, full_stage_quality_passed=False, root_intake=False)))
