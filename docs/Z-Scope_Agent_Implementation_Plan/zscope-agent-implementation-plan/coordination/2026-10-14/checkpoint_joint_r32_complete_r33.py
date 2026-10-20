"""Record actual failed joint run and later valid probes without replacing history."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
OUT = ROOT / "artifacts/coordinator-stage-repairs-r33-20261017"
JOINT = ROOT / "artifacts/coordinator-stage-joint-r32-20261017"
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
joint = read(JOINT / "review.json")
assert joint["junit"]["main"] == dict(tests=3543, failures=42, errors=4, skipped=8)
assert not joint["selected_stage_joint_checks_passed"]
assert counts(P2 / "bridge-v3-check/pytest.xml") == dict(tests=4, failures=0, errors=0, skipped=0)
assert counts(P2 / "red-valid/pytest.xml") == dict(tests=9, failures=6, errors=0, skipped=0)
rows = []
for node in ET.parse(JOINT / "results.xml").getroot().iter("testcase"):
    for kind in ("failure", "error", "skipped"):
        outcome = node.find(kind)
        if outcome is not None:
            rows.append(dict(classname=node.get("classname"), name=node.get("name"), outcome=kind, message=outcome.get("message")))
references = [JOINT / "review.json", JOINT / "results.xml", JOINT / "command-2.log", P2 / "bridge-v3-check/receipt.json", P2 / "bridge-v3-check/pytest.xml", P2 / "red-valid/receipt.json", P2 / "red-valid/pytest.xml", ROOT / "artifacts/stage-repair-product-source-review-r33-20261017/bridge-v3-source-review.json"]
evidence = dict(actual_task="/root", observed_at=now, joint_finished_at=joint["finished_at"], joint_junit=joint["junit"], joint_command_returncodes=[row["returncode"] for row in joint["commands"]], joint_outcomes=rows, evidence_sha256={path.relative_to(ROOT).as_posix(): sha(path) for path in references}, fd_capture_enoent_reproduced=False, missing_ui_browser_environment_caused_all8_skips=True, quality_same_parallel492_error_in_three_mypy_commands=True, producer_bridge_v3=dict(actual_task="/root/stage_cost_repair_r33", tests=4, failures=0, errors=0, skipped=0, independent_acceptance=False), valid_cost_red=dict(tests=9, failures=6, errors=0, skipped=0, actual_native_codec_SQL_restore_settlement_prerequisites_passed=True), composite_independent_pending=True, prior_actual_stage_guard_gap=107, root_intake=False, stage_repair_intake=False, joint_validation_passed=False, prior_s01_actual_failed_deliveries=3, prior_s01_bounded_acceptance_unchanged=True)
target = OUT / "joint-complete-checkpoint.json"
assert not target.exists()
write(target, evidence)
tasks = read(HERE / "tasks.json")
by_id = {row["id"]: row for row in tasks["tasks"]}
by_id["COORD-INSTANCE-INTEGRATION-R24"].update(status="stage_r32_joint_failed_r33_isolated_repairs_and_composite_verification_in_progress", checked_at=now, current_stage_joint_receipt_pending=False, current_stage_joint_junit=joint["junit"], fresh_mypy_remaining_error_count=1, fresh_mypy_returncode=1, latest_completed_joint_checkpoint=target.relative_to(ROOT).as_posix(), joint_validation_passed=False)
by_id["STAGE-CURRENTNESS-REPAIR-R33"].update(status="owned_currentness_target_probes_green_waiting_readonly_v3_dependency_and_final_checks", latest_completed_joint_checkpoint=target.relative_to(ROOT).as_posix())
by_id["STAGE-COST-REPAIR-R33"].update(status="native_bridge4_producer_pass_valid_cost_red9_6fail_3pass_cost_repair_actual_in_progress", latest_valid_red=(P2 / "red-valid/receipt.json").relative_to(ROOT).as_posix(), latest_completed_joint_checkpoint=target.relative_to(ROOT).as_posix())
tasks["updated_at"] = now
write(HERE / "tasks.json", tasks)
continuation = read(HERE / "continuation-r6.json")
continuation.update(updated_at=now, latest_completed_joint_checkpoint=target.relative_to(ROOT).as_posix(), current_stage_joint_running=False, current_stage_joint_validation_passed=False)
write(HERE / "continuation-r6.json", continuation)
note = f"""## {now} · R32 联合结束未通过，R33 有效成本红与组合独验

Stage R32 在 {joint['finished_at']} 结束，198 文件主集3543项：3489pass/42fail/4error/8skip；另R24原权威探针4pass。8个UI跳过均因启动器漏传R23已使用的Playwright/Chromium环境，必须恢复原验收环境重跑，不能以skip接纳。输出捕获FileNotFoundError未复现。normal/fresh完整mypy及scripts/mypy均报同一parallel_analyzer:492错误，compileall/Black/web-assets返回0。原实际Stage副本107项漏保护问题仍单列，不能补称本次已完整守卫。

42F/4E原始ID/消息及命令退出码已固定到{target.relative_to(ROOT).as_posix()}。多数真实native/session/recovery项有入口lookup/entry workflow闭合/标准调用classification前置失败，修复后仍须逐项复验；另3个规则revision快照及3个缺少新的mandatory semantics_by_instance的测试需协调者核对当前契约，不改生产门禁来适配旧测试。

实际 /root/stage_cost_repair_r33 冻结V3桥64c3…，生产者原native恢复+identity/project矩阵4pass，独立静态11:20:04+08有界通过（不是行为接纳）。P2有效红9项为6fail/3pass/0error/0skip，真实native→codec→SQL→恢复→结算及当前validation前置通过；历史成本混入与零值回落已确证，开始隔离修复。协调者冻结d78 Context+V3组合1079输入，并单独补充1个49-case撤回probe到1080守卫集合，准备独验，未进入Stage/Root。

实际任务：/root/stage_currentness_repair_r33、/root/stage_cost_repair_r33、独审/root/consumer_source_review_r28；Root1065既有通过版本未改，S01有界接纳和历史失败3保留，无完整工作包/真实项目验收结论。
"""
for path in (HERE / "CURRENT_STATE_R33.md", HERE / "PROGRESS.md", HERE / "DAG.md"):
    path.write_text(note + "\n---\n\n" + path.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
print(json.dumps(dict(receipt=target.relative_to(ROOT).as_posix(), observed_at=now)))
