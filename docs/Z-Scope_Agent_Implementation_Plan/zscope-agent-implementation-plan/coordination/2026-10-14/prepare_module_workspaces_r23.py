"""Prepare disjoint worker copies; never dispatch before the Root/contract gates."""
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

def read(p):
    return json.loads(p.read_text(encoding="utf-8"))

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def write(p, value):
    p.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

intake = read(ROOT / "artifacts/intake-ui-projection-r23-20261016/receipt.json")
source = dict(intake["expected_root"])
source.update(read(ROOT / "artifacts/root-launcher-review-r23-20261016/final-review.json")["reviewed_hashes"])
assert len(source) == 1065 and all(sha(ROOT / p) == h for p, h in source.items())
contract_paths = ["artifacts/design-contract-r23-20261016/DELIVERY.md", "artifacts/design-contract-r23-20261016/contracts.json"]
source.update({p: sha(ROOT / p) for p in contract_paths})
contract = read(ROOT / contract_paths[1])
assert contract["tests_executed"] == 0 and contract["product_files_changed"] == 0
assert contract["source_hashes_before"] == contract["source_hashes_after"]
assert all(sha(ROOT / p) == h for p, h in contract["source_hashes_after"].items())
ledger = read(HERE / "tasks.json")
rows = {r["id"]: r for r in ledger["tasks"]}
specs = [
    ("S01-INSTANCE-SEMANTICS-MIN-R23", "s01-instance-semantics-min-r23", "instance-semantics-r23", "s01", ["zscope/semantics/instance_semantics.py", "tests/test_instance_semantics.py"], "S01-INSTANCE-MODELING-DESIGN-R21"),
    ("S08-INSTANCE-RECOVERY-MIN-R23", "s08-instance-recovery-min-r23", "instance-recovery-r23", "s08", ["zscope/orchestration/jobs/instance_results.py", "tests/test_instance_result_recovery.py"], "S08-PARTIAL-RECOVERY-DESIGN-R21"),
]
prepared = []
for identity, name, artifact, interface, owned, parent in specs:
    assert identity not in rows and all(not (ROOT / p).exists() for p in owned)
    branch = ROOT / ".coordination/20261014/workspaces" / name
    branch.mkdir(exist_ok=False)
    for p, h in sorted(source.items()):
        target = branch / p
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / p).read_bytes())
        assert sha(target) == h
    at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
    task = {"id": identity, "workspace": name, "owner": "ZCode", "owns": owned, "write_paths": owned, "artifact_write_paths": ["DELIVERY.md", f"artifacts/{artifact}/**"], "depends_on": ["CURRENT-JOINT-R23", "ASTRA-DESIGN-CONTRACT-REVIEW-R23"], "related_existing_tasks": [parent], "inherits": parent, "scope": "New module and unit-test delivery only; real consumers/coordinator integration pending", "root_product_write_permission": False, "status": "prepared_not_dispatched_root_joint_and_contract_gates_pending", "artifact_available": False, "independent_acceptance": False, "integrated": False, "joint_verification": False, "whole_package_complete": False, "consecutive_failed_actual_deliveries": 0, "prior_histories_preserved": True, "checked_at": at}
    baseline = {"captured_at": at, "task": task, "files": [{"path": p, "sha256": h} for p, h in sorted(source.items())], "root_intake": "artifacts/intake-ui-projection-r23-20261016/receipt.json", "contract_sha256": source[contract_paths[1]], "dispatch_state": "prepared_not_dispatched", "joint_result_claimed": False}
    write(HERE / "followups-r12" / (name + "-baseline.json"), baseline)
    windows_branch = WINDOWS_ROOT + "\\.coordination\\20261014\\workspaces\\" + name
    message = f"""用户明确授权的 Z-Scope 并行实施，逻辑项 {identity}，保留与父 {parent} 的关系与历史。普通非UI由 ZCode 固定模型 97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3；Kimi暂停新派单，UI与复杂设计由Astra，不能通过换路由绕平台限制。此请求仅会在当前Root R23完整171files/six commands通过及合同独立复核通过后派发，不能借旧R22结果。
唯一隔离 Windows 目录 {windows_branch}；Linux {branch}。一切产品操作必须在该隔离副本；Root/别的副本/旧交付只读。仅可新增这2个产品/测试文件：{json.dumps(owned)}；仅该副本DELIVERY.md与artifacts/{artifact}/可写交付。不得改任何既有源码、旧测试、__init__、文档、配置、runtime prompts、native或资源锁；共享scan_work/scan_session/parallel_analyzer/store/session_scheduler/candidates/Analyzer由协调者单写集成。不得创建第二Bridge或服务、不得读取凭据/provider配置、不得检查WSL进程（ps/pgrep/proc）、不得访问/恢复/派发归档S06-R02/task_0947f2854f。禁止reset/clean/stash/commit/push、改变时钟、降低测试或绕拦截。
先读副本AGENTS.md、docs/architecture.md与相关modules；严格读副本{contract_paths[0]}和{contract_paths[1]}，这是冻结精确合同。你只实现typed_interfaces.{interface}及对应模块级正反例；不得将coordinator typed seams冒充既有API，也不要为让模块测试通过而私自接线。源码事实若要求合同调整，报告准确位置给协调者，不能扩大写权限。版本/数据字段必须吻合合同；不可用占位函数假通过。
S01首片必须 builtin_current_manual_advisory_no_inferred.v1：所有inferred执行效果排除，manual只advisory，工作簿自报builtin/USR/verification/pair角色不能进入执行registry/overlay；builtin权威来自包内factory并保留实际系统声明/ABI/shadowing/currentness检查。精确scope、不可变payload、每消费者独立深拷贝、dependencies unknown/stale拒绝，不启用globalmodeler/prepare_semantics。
S08首片模块负责完整成功prevalidation结果编码、不可变原子文件和严格byte/schema/identity验证；receipt typed数据本身不授权，不能导入store/scan_work/scheduler/ParallelAnalyzer形成循环。严格完整候选/义务/occurrence与来源保留，拒绝旧裁决/证明、错误/取消/defer/partial/unknown/截断、无成功completion marker；路径/filename/digest/duplicate JSON keys/NaN/类型等都检查。store可信reader、真实claim settle、Ledger原子导入、R/E屏障和真实consumer接线另由协调者实现；跨run年龄/attempts/fairness明确延期，不能伪造。
只在WSL Ubuntu zeal /home/zeal/venv313/bin/python Linux venv形成测试结论。每条检查只包一次原Root {HERE / 'test_slot.py'} --workspace {branch} -- <argv>，不能再包外层slot。使用wsl -d Ubuntu -u zeal -- bash -lc的login PATH，默认fd capture和ext4 TMP不改；native工具只读 /home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer，SHA d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399。先跑自己新test和真实直接相关旧回归，随后full compileall -f -q zscope scripts test tests、mypy zscope、Black --check自己的2文件；只格式化自己的新Python。JUnit记录零skip标准，未跑的不能记通过。模型/扫描/正式benchmark/portable不执行。
交付DELIVERY.md与artifacts/{artifact}/review.json、JUnit和每命令完整日志，记录真实首/末工具时钟（不要发明worker开始时间）、原逻辑/实际taskID可由coordinator补public信息、实际命令/exitcode、所有1067基线输入before/after SHA、2新文件SHA、任何失败历史原样保留、未覆盖项。不得把模块单测计作整个S01/S08切片/工作包/真实项目效果通过。完成后停止所有写入等待协调者独立验收。
"""
    (HERE / "followups-r12" / (name + "-message.txt")).write_text(message, encoding="utf-8", newline="\n")
    payload = {"id": name, "branch": name, "tool": "dispatch_task", "arguments": {"agent": "zcode", "cwd": WINDOWS_ROOT, "title": identity, "model": "97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3", "user_requested": True, "request_id": str(uuid4()), "message": message}}
    write(HERE / "followups-r12" / (name + "-request.json"), payload)
    ledger["tasks"].append(task)
    prepared.append({"task": identity, "workspace": name, "inputs": len(source), "owns": owned, "dispatch_state": "not_dispatched", "at": at})
ledger["updated_at"] = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
write(HERE / "tasks.json", ledger)
print(json.dumps(prepared), flush=True)
