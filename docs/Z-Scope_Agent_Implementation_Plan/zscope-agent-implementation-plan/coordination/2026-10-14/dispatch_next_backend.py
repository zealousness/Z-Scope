"""Prepare disjoint backend-only slices from the accepted current source.

Queues use the existing official MCP owner. No agent/config/process restart.
"""

from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
MODEL = "97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3"
baseline = json.loads((HERE / "baseline.json").read_text(encoding="utf-8"))
names = {item["path"] for item in baseline["files"]}
for directory in ("zscope", "tests", "scripts"):
    for path in (ROOT / directory).rglob("*"):
        if path.is_file() and path.suffix in {".py", ".json", ".yaml", ".yml", ".cjs"} and "__pycache__" not in path.parts:
            names.add(path.relative_to(ROOT).as_posix())

common = """本轮用户授权Agent-Bridge并行开发；Kimi此前反复普通API故障，用户明确允许转交既定ZCode hw/glm-5.3。你的任务是新解锁独立后端切片，不是被拦分支恢复。只能写下述项目内隔离目录中指定新文件和自己的DELIVERY/artifacts；其他复制输入只读。根checkout、公共scan_session/code_index/config/Web路由、静态/UI测试、共享文档/锁全部不改。全部前端和用户体验只能Astra亲自开发，你只产机器后端数据，不写用户流程或文案。禁止操作task_0947f2854f及此前被拦caller无通知/受限超时工作，禁止修改native/async_paths/lifecycle/protocol/rules/catalog或其测试。用户已确认旧观察线程归档，不需要你恢复/查询任何旧任务。不reset/clean/stash/commit/push，不改项目外配置/凭据，不重启任何Bridge/Agent；新拒绝准确停报，不换会话/模型绕过。
先读隔离AGENTS、根coordination/2026-10-14/NEXT_BACKEND_CONTRACT.md和有关现有源码/规格。保持此前intake实现字节，不重复实现已接受的core。测试只能WSL Ubuntu /home/zeal/venv313/bin/python，使用你隔离目录绝对PYTHONPATH，最多一pytest；不得Windows形成结论，不安装共享venv、不重建native、不做真实模型扫描/formal/Range。真实native需用现有Z_SCOPE_TEST_CLANG_INDEXER=/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer。不把合成facts/controlled执行算native/完整扫描。提交稳定SHA/JUnit/compileall/mypy/Black与实际限制，前后字节一致，不与旧集合相加。先直接实现切片，在有限时间交付可审查模块；无法接全链路必须保持未接线，不能让字段冒充执行或完成。
"""
branches = [
    ("S01-CDB-COVERAGE", "s01-coverage", 41, "s01-cdb-coverage", "high", "high", ["zscope/orchestration/entry_instance_coverage.py", "tests/test_entry_instance_coverage.py"], """输入为当前已接入entry_instances.py/CodeIndex与原BuildContext工具。已有helper只枚举存储contexts，无法证明CDB中每个预期命令已索引；整个scan_coverage_complete固定false，本任务不关闭它。新增readonly reconcile_entry_instance_coverage(code_index, *, compile_commands_path: Path, source_root: Path, include_paths=None, exclude_paths=None)->dict。复用indexing_identity.load_commands/source_path/command_identity/digest_json及build_context.context_input_status，不另造身份哈希或执行JSON命令。明确path选择范围与原索引一致；无法证明过滤一致时保留gap，不能假完整。逐预期(source,command_id)核对真实storedcontext，不能仅比总数/同source/name；同宏/不同宏命令分开，重复相同命令可明确dedup，额外/旧context不能补缺失命令。缺CDB/损坏/空/未知/工具收据或索引失败均保守gap；当前source/header/response/CDB/include否定依赖变化必须由现有context_input_status复核，不用缓存stat。返回schema zscope.entry-instance-coverage.v1, status, expected_commands(index选择分母未知则null), current_commands, missing_commands, stale_contexts, unexpected_contexts, gaps[{source,command_id,build_context_id?,reason,detail}], command_coverage_complete bool, scan_coverage_complete false。不推导链接归属/entry存在/Analyzer已运行。独立测试：单TU双宏少一context、等计数但错命令、重复命令、失效依赖/CDB/response/缺收据、过滤、Java/nonCDB无法解释边界。至少一个现有native真实两宏context对照，工具可用不skip假通过。不能修改旧模块；协调者负责scan_session/report最小公共接线。"""),
    ("S08-QUEUE-CORE", "s08-scheduling", 42, "s08-fair-queue", "high", "high", ["zscope/orchestration/jobs/work_queue.py", "tests/test_scan_job_work_queue.py"], """输入当前已接入jobs/owner/store与冻结作业接口；owner目前只在截止时终止scanner，不满足JOB04/06。本任务新增独立persistent WorkQueue，不改旧jobs/store/owner/scan_session。SQLite持久队列存于传入项目内path，明确job_id/input_revision范围，未知revision拒绝。项目隔离、真实事务/并发、工作identity按kind+stable scope key+精确build（未知不是跨构建通配）去重；不得储存/执行任意argv、动态收据或密钥。API enqueue(items, batch_no)、claim_batch(max_items, now?, stop_time?)、complete(item_id)、defer(item_id, reason)、snapshot()、recover(new_input_revision)形状可先提出后实现，但机器payload须有真实pending/active/completed/deferred/failed数、剩余items身份/原因。新发现仅下一批，有限max_attempts/max_batches防无限递归；困难/长期未决项按公平轮次/年龄而非只挑易例，同identity重复不重试无新输入。到窗口关闭不claim新项；已claim工作可有限finish，记录未完成真实remaining。重开DB读取队列/lease，owner崩溃不能伪completed；input_revision不同恢复重新待核而非授予旧completion。不得以队列本身声称已接scanner/取消正在运行的LLM；旧report/currentv3stop_at consumer仍pending。测试用真实SQLite和有界controlledworker（不mockDB），窗口早关闭/边界/active有限收尾、动态新根下一批、相同与跨build去重、长期defer不饥饿、重开/并发claim/输入变更恢复，保存JUnit与明确未接线限制。协调者负责共享scan_session/owner接线，Astra负责全部UI。"""),
]

for branch, isolate_name, number, label, difficulty, risk, owned, task in branches:
    destination = ROOT / ".coordination/20261014/workspaces" / isolate_name
    if destination.exists():
        raise RuntimeError("isolate already exists; inspect outcome before another dispatch")
    destination.mkdir(parents=True)
    manifest = []
    for name in sorted(names):
        source = ROOT / name
        if not source.is_file():
            continue
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        raw = source.read_bytes()
        target.write_bytes(raw)
        manifest.append({"path": name, "sha256": hashlib.sha256(raw).hexdigest()})
    proof = {"at": dt.datetime.now(dt.timezone.utc).isoformat(), "branch": branch, "isolate": str(destination.relative_to(ROOT)), "files": manifest, "owned_new_files": owned}
    (HERE / f"baseline-{isolate_name}.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    arguments = {"agent": "zcode", "model": MODEL, "cwd": str(ROOT), "title": label, "user_requested": True, "request_id": str(uuid.uuid4()), "message": common + "\n实际隔离目录：" + str(destination) + "\n仅可写新文件：" + ", ".join(owned) + "\n" + task}
    request = {"id": label, "branch": branch, "tool": "dispatch_task", "arguments": arguments}
    queue = HERE / "route-check/bridge-queue" / f"{number:03d}-{label}.request.json"
    with queue.open("x", encoding="utf-8", newline="\n") as output:
        output.write(json.dumps(request, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"branch": branch, "request_id": arguments["request_id"], "model": MODEL, "isolate": proof["isolate"], "input_files": len(manifest), "difficulty": difficulty, "risk": risk}, ensure_ascii=False), flush=True)

