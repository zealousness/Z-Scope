"""Prepare disjoint read-only audits only after the current Root gate passes."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys
from uuid import uuid4

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
WINDOWS_ROOT = r"C:\Users\10273\home\work\Z-Scope_1.31\Z-Scope"
WINDOWS_COORD = WINDOWS_ROOT + r"\docs\Z-Scope_Agent_Implementation_Plan\zscope-agent-implementation-plan\coordination\2026-10-14"
gate = ROOT / "artifacts/coordinator-r22-unchanged-union-20261016/review.json"
review = json.loads(gate.read_text(encoding="utf-8"))
assert review["all_current_selected_validation_passed"] and review["is_current_root"]
assert review["commands_passed"] == 6 and review["failed"] == review["errors"] == review["skipped"] == 0
source = json.loads((gate.parent / "source-evidence.json").read_text(encoding="utf-8"))["after"]
assert all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == h for p, h in source.items())
ledger = json.loads((HERE / "tasks.json").read_text(encoding="utf-8"))
existing = {r["id"] for r in ledger["tasks"]}
parents = {
    "S01-INSTANCE-MODELING-DESIGN-R21": ["S01-INST-EXEC", "CONTRACT-VALIDATION-R12", "VALIDATION-CONTEXT-R18"],
    "S08-PARTIAL-RECOVERY-DESIGN-R21": ["S08-SESSION-SCHEDULER", "SCAN-SESSION-R12", "SCAN-CHECKPOINT-R17", "U01-STOP-AT-R18", "U01-FIRST-CAUSE-R20"],
}
specs = [
    ("S01-INSTANCE-MODELING-DESIGN-R21", "s01-instance-modeling-design-r21", "instance-modeling-design-r21", "S01 已确认边界与待核实问题"),
    ("S08-PARTIAL-RECOVERY-DESIGN-R21", "s08-partial-recovery-design-r21", "partial-recovery-design-r21", "S08 已确认边界与待核实问题")
]
common = f"""用户授权的后续并行工作，当前 Root R22 完整选定联合集合及六条严格 Linux 命令已通过，收据 {WINDOWS_ROOT}\\artifacts\\coordinator-r22-unchanged-union-20261016\\review.json。你是 ZCode，模型必须固定 97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3。普通非 UI 优先 ZCode；Kimi 暂停新派单，已有成果冻结；UI/前端/用户体验由 Astra 独占。不要重做已验收 S01 实例索引/contract 消费、S08 队列/window/token 或 R20 CLI/SQL/首次取消原因成果。
这是只读依赖设计审计，不是功能实现。只在下述新隔离目录的 DELIVERY.md 和指定 artifacts 目录写审计产物，所有复制源码/旧测试/文档/native/配置/资源锁只读，不写 Root 或其他副本，不创建任何产品/测试代码。不得启动服务、Bridge、扫描、真实模型或 benchmark，不查看 ground truth，不操作 task_0947f2854f 或恢复任何归档 S06-R02 会话，不更改平台/凭据/环境/时钟，不 reset/clean/stash/commit/push。出现平台拦截准确停止，不换模型/会话绕过。
先读隔离副本 AGENTS.md、docs/architecture.md 和对应 docs/modules；再读 {WINDOWS_COORD}\\DISPATCH_POLICY.md 与 {WINDOWS_COORD}\\NEXT_BACKEND_CONTRACT_R21.md，不能在副本相对目录找不到后忽略 Root 合同。严格以当前源码、真实调用与已有执行收据为准，文档可能过期。不能把源码审计、声明字段、合成数据或一个切片通过标为完整包/真实项目效果已验收。
请在限定审计范围形成可执行的最小后续开发合同：逐项给源码路径、行号、完整 SHA、调用链、真实已实现能力、当前缺口、非缺陷、接口、所有权、依赖、精确正反例和未覆盖范围。必须追踪消费者实际调用与身份/缓存/发布/重用边界，不能仅凭字段名推断。引用 native 证明只读已有真实收据，不执行/重建 native。标准库读取和 SHA 可用 WSL Ubuntu zeal /home/zeal/venv313/bin/python；本项不要求新测试，未运行记为0，不能给伪通过数。必要短探针须先说明理由，并以 WSL login 环境经 Root test_slot.py 单层两槽、默认 fd/ext4 执行，不降低门禁。
交付 DELIVERY.md 与指定 artifacts/audit.json，audit 至少包含 task_id、started_at、finished_at、status、source_hashes_before/after、findings、capabilities、non_defects、proposed_slices、dependencies、exclusive_write_paths、shared_coordinator_paths、acceptance_examples、executed_commands、limits。未执行就是未执行；结论为只读设计成果，不是实现验收。完成后停止所有写入。
"""
prepared = []
contract = (HERE / "NEXT_BACKEND_CONTRACT_R21.md").read_text(encoding="utf-8")
for identity, name, artifact, heading in specs:
    assert identity not in existing
    branch = ROOT / ".coordination/20261014/workspaces" / name
    branch.mkdir(exist_ok=False)
    for p, h in sorted(source.items()):
        target = branch / p
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / p).read_bytes())
        assert hashlib.sha256(target.read_bytes()).hexdigest() == h
    assert set(parents[identity]) <= existing
    task = {"id": identity, "workspace": name, "owner": "ZCode", "owns": [], "write_paths": [], "artifact_write_paths": ["DELIVERY.md", f"artifacts/{artifact}/**"], "depends_on": ["CURRENT-JOINT-R22", *parents[identity]], "related_existing_tasks": parents[identity], "packages": ["S01" if identity.startswith("S01") else "S08"], "scope": "Read-only source/call/identity/recovery design; no product implementation", "root_product_write_permission": False, "prior_producer_failure_histories_preserved": True}
    at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
    baseline = {"captured_at": at, "task": task, "files": [{"path": p, "sha256": h} for p, h in sorted(source.items())], "current_root_review": gate.relative_to(ROOT).as_posix(), "dispatch_state": "prepared_not_dispatched", "product_changed": False}
    path = HERE / "followups-r12" / (name + "-baseline.json")
    assert not path.exists()
    path.write_text(json.dumps(baseline, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    relevant = contract.split("## " + heading, 1)[1].split("\n## ", 1)[0]
    message = common + f"\n本项 {identity}。隔离 Windows 目录 {WINDOWS_ROOT}\\.coordination\\20261014\\workspaces\\{name}；Linux 目录 {branch}。仅可写本副本 DELIVERY.md 与 artifacts/{artifact}/。重点合同如下：\n" + relevant
    (HERE / "followups-r12" / (name + "-message.txt")).write_text(message, encoding="utf-8", newline="\n")
    payload = {"id": name, "branch": name, "tool": "dispatch_task", "arguments": {"agent": "zcode", "cwd": WINDOWS_ROOT, "title": identity, "model": "97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3", "user_requested": True, "request_id": str(uuid4()), "message": message}}
    (HERE / "followups-r12" / (name + "-request.json")).write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    prepared.append({"task_id": identity, "workspace": name, "inputs": len(source), "dispatch_state": "not_dispatched"})
print(json.dumps(prepared), flush=True)
