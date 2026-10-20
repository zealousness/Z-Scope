"""Archive the stable failed R1 and authorize isolated transactional repair."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil
from uuid import uuid4
from audit_followup_r6 import audit, ROOT

HERE = Path(__file__).resolve().parent
OUT = ROOT / "artifacts/coordinator-s08-r1-durability-20261014"
WORK = ROOT / ".coordination/20261014/workspaces/s08-session-r6"
ownership = audit(WORK.name)
assert ownership["safe_to_review"], ownership
expected = {
    "zscope/orchestration/jobs/session_scheduler.py": "018cc74dcb3da743d0139265abe394ebf8406ee39546610ebcdca3b574d099e2",
    "zscope/orchestration/jobs/scheduler_hook.py": "599ff388a2263301edc0fec8eb2aca56e0904236fa345d0a986cbbbdeb903878",
    "zscope/orchestration/jobs/owner.py": "6d125c4c989c690136ef21ca6104ca1e178dc3921ac010b7be5f89b716efef9c",
    "tests/test_job_session_scheduler.py": "635ac0a8ecfc3bb2c1611a97b8e447c9bdb8262b70b32ac8de41aab556d1933d",
}
actual = {name: hashlib.sha256((WORK / name).read_bytes()).hexdigest() for name in expected}
assert actual == expected
archive = OUT / "initial-delivery"
archive.mkdir(exist_ok=False)
for name in list(expected) + ["DELIVERY/DELIVERY.md", "DELIVERY/junit-guard-probes.xml", "DELIVERY/junit-regression.xml", "DELIVERY/junit-session-scheduler.xml"]:
    target = archive / name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(WORK / name, target)
shutil.copyfile(HERE / "followups-r6/test_scheduler_discovery_durability.py", OUT / "failed-probe.py")
at = dt.datetime.now(dt.timezone.utc).isoformat()
review = {"task_id": "task_b41bc0eb99", "finished_at": "2026-10-14T21:22:55.397455+08:00", "checked_at": at,
          "junit": {"passed": 3, "failed": 2, "errors": 0, "skipped": 0}, "owned_source_hashes": actual,
          "ownership": ownership, "independent_acceptance_passed": False, "integrated": False,
          "reason": "Batch bound loses child with no remaining; real process exit between durable parent verdict and child enqueue loses all recoverable work.",
          "result_receipt": str(HERE / "route-check/bridge-response-r6-public-09eb72cf1f.json"),
          "whole_package_complete": False}
(OUT / "review.json").write_text(json.dumps(review, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
added = ["zscope/orchestration/jobs/work_queue.py", "zscope/orchestration/jobs/store.py", "tests/test_scan_job_work_queue.py"]
baseline = json.loads((HERE / "followups-r6/s08-session-r6-baseline.json").read_text(encoding="utf-8"))
baseline_hashes = {row["path"]: row["sha256"] for row in baseline["files"]}
for name in added:
    assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == baseline_hashes[name]
    assert hashlib.sha256((WORK / name).read_bytes()).hexdigest() == baseline_hashes[name]
extension = {"authorized_at": at, "task": "S08-SESSION-SCHEDULER-R2", "workspace": str(WORK),
             "added_owned_paths": added, "root_integration_owner": "coordinator",
             "basis": "User-authorized dependency-driven isolated repair; no other worker owns these paths. Original baseline remains unchanged.",
             "original_hashes": {name: baseline_hashes[name] for name in added}}
(HERE / "followups-r6/s08-session-r6-ownership-extension.json").write_text(json.dumps(extension, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
message = """S08 R2：继续原 sess_3b6b9a19b2 和原 s08-session-r6 副本，task_b41bc0eb99 已21:22:55 completed，get_result完整无failure/warnings，observed_model为精确glm-5.3。原3个守卫反例已由协调者真实重跑通过，不重复返工。
独立验收新增2fail：max_batches=1时parent完成但child被丢弃，run=drained/remaining=0；真实fork子进程在父项完成落库与子项入队之间退出73，重开SQLite同输入也remaining=0。证据根artifacts/coordinator-s08-r1-durability-20261014/{review.json,results.xml,initial-delivery}，原稳定4源码和全部JUnit已归档，暂不导入根。
本轮明确扩展隔离目录独占文件：原4文件 + jobs/work_queue.py + jobs/store.py + tests/test_scan_job_work_queue.py，共7文件。扩展收据followups-r6/s08-session-r6-ownership-extension.json；这3文件原根与副本SHA已核对，没人并行修改。根目录及其他共享文件仍只读，由协调者独立验收/集成。无需等待协调者写共享API，现在由你在副本实现并测试上述新增所有权文件。
必须让父项verdict和全部可接纳discoveries在同一queue事务持久化，token/输入版本不匹配全拒绝，任何子入队异常回滚父项，不能出现完成但子项丢失；batch/容量上限保留明确持久未决工作并停止该轮，不能仅增加dropped计数后drained。可原子回滚后延期父项并保留重放来源、或可靠outbox，选择小而完整的实现；恢复不执行保存命令/旧证明，仍按当前进程登记callback。
同时闭合job绑定读取与queue写入的实际竞态：只检查queue input_revision不足以保护owner/run翻转。建议JobStore提供bound_attempt写锁上下文，BEGIN IMMEDIATE内校验job/run/owner/input/非终态，保持锁直到queue事务提交；统一store→queue锁顺序，不在锁内执行handler，避免事件append反向锁/死锁。owner的同事务job/attempt终态修复必须保留。也可更小正确方案，但不能把竞态改名成理论限制后通过。
协调探针在根followups-r6/test_scheduler_guard_probes.py和test_scheduler_discovery_durability.py，只读。耐久性探针将从旧_submit_discoveries方法注入调整为queue事务提交后的真实进程退出，避免绑定旧实现；验收仍是数据库恢复后有子项或可重验父项。批次限制探针只检查真实剩余，不规定计数标签。不能删除/放宽实际剩余、旧claim/input/owner/run拒绝、有界收尾/公平/取消与新子发现要求。
补并发输入/owner翻转和队列提交失败的真实SQLite正反例，保留24/119/3历史JUnit，最终新文件名。所有pytest/质量在WSL Ubuntu /home/zeal/venv313/bin/python经根test_slot.py --workspace本副本 -- <argv>，TMPDIR独立ext4、最多两槽。运行完整相关pytest、compileall zscope scripts test tests、mypy zscope及局部Black。最终DELIVERY.md与artifact收据放顶层/或原DELIVERY目录（仅说明和JUnit），稳定逐文件SHA和实际时间。
DELIVERY首句“task_28...因API故障cancel”与事实不符：原轮是协调者为提交3个明确代码反例正常cancel，未见API故障。本轮metadata/LICENSE由协调者补齐，不能说环境抖动。时钟回跳既可能延后也可能提前墙钟窗口，不得宣称只延后。不得改provider/审核权限，不重启服务，不操作旧S06，不commit/push/reset/clean。仍不接完整ScanSession/ParallelAnalyzer，不关闭S08/JOB04/JOB06；交付后停止写入等待独立验收。"""
request = {"id": "s08-session-r6-review2", "branch": "s08-session-r6-review2", "tool": "dispatch_task",
           "arguments": {"agent": "zcode", "session_id": "sess_3b6b9a19b2", "model": "97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3",
                         "cwd": str(ROOT), "title": "S08-SESSION-SCHEDULER-R2", "message": message,
                         "request_id": str(uuid4()), "user_requested": True}}
(HERE / "followups-r6/s08-session-r6-review2-request.json").write_text(json.dumps(request, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"review": str(OUT / "review.json"), "request": request["id"], "added_paths": added}))
