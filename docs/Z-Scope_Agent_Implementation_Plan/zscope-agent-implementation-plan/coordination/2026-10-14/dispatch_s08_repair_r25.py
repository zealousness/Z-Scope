"""One third S08 delivery in the existing ready fixed-route session."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import time
from uuid import uuid4
from bridge_queue_publish_r23 import publish_request

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
route = HERE / "route-check"
branch = ROOT / ".coordination/20261014/workspaces/s08-instance-recovery-min-r23"
session_id = "sess_d9cfbf4113"
old_task = "task_8886dcf232"
model = "97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3"
request_name = "s08-instance-recovery-repair-r25"

def read(path):
    return json.loads(path.read_text(encoding="utf-8"))

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def require(ok, message):
    if not ok:
        raise RuntimeError(message)

def write_new(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(value, ensure_ascii=False, indent=2) + "\n")

def call(tool, arguments, label):
    name = label + "-" + uuid4().hex[:12]
    response = route / ("bridge-response-" + name + ".json")
    publish_request(route / "bridge-queue", dict(id=name, tool=tool, arguments=arguments))
    until = time.monotonic() + 40
    while time.monotonic() < until:
        if response.exists():
            try:
                return read(response), response
            except json.JSONDecodeError:
                pass
        time.sleep(.25)
    raise RuntimeError("Unknown original-owner response; inspect existing request only")

ledger = read(HERE / "tasks.json")
row = next(row for row in ledger["tasks"] if row["id"] == "S08-INSTANCE-RECOVERY-MIN-R23")
require(row["bridge_task_id"] == old_task and row["producer_status"] == "completed" and row["consecutive_failed_actual_deliveries"] == 2 and not row["integrated"], "Wrong logical task")
failure = read(ROOT / "artifacts/s08-consumer-probe-r25-20261016/failure-review.json")
require(failure["task_id"] == old_task and failure["round"]["counted_development_failure"], "Missing actual second failure")
require(all(sha(branch / path) == digest for path, digest in failure["source_after"].items()), "Failed candidate drift")
source_review = read(ROOT / "artifacts/s08-module-source-review-r25-20261016/review.json")
require(source_review.get("producer_task_id") == old_task and source_review.get("source_review_passed") is False, "Missing current source review")
root_sources = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
require(all(sha(ROOT / path) == digest for path, digest in root_sources.items()), "Root drift")
for name in ("s08-instance-recovery-min-r23-baseline.json", "s08-instance-recovery-min-r23-dependencies.json"):
    require(all(sha(branch / item["path"]) == item["sha256"] for item in read(HERE / "followups-r12" / name)["files"]), "Readonly input drift")
response_path = route / ("bridge-response-" + request_name + ".json")
require(not response_path.exists() and not (HERE / "followups-r12" / (request_name + "-request.json")).exists(), "Existing dispatch needs reconciliation")
for suffix in (".request.json", ".request.consumed"):
    require(not (route / "bridge-queue" / ("080-" + request_name + suffix)).exists(), "No dispatch replay")
agents, agents_path = call("list_agents", {}, "r25-s08-agents")
require(agents.get("ok") and agents["coordinator"]["dispatch_enabled"] and any(agent.get("agent") == "zcode" and agent.get("available") for agent in agents["agents"]), "Fixed ZCode route unavailable")
sessions, sessions_path = call("list_sessions", dict(active_only=True), "r25-s08-active")
require(sessions.get("ok"), "Session check failed")
require(isinstance(sessions.get("sessions"), list) and all(isinstance(session, dict) for session in sessions["sessions"]), "Malformed active session inventory; outcome unknown")
targets = [session for session in sessions.get("sessions", []) if session.get("session_id") == session_id]
require(len(targets) <= 1, "Duplicate active target sessions")
if targets:
    require(targets[0].get("agent") == "zcode" and targets[0].get("model") == model and targets[0].get("proc_state") == "ready", "An active target must be fixed-route and ready")
for session in sessions.get("sessions", []):
    require(session.get("session_id") in {session_id, "sess_6ecde27723"} and session.get("agent") == "zcode" and session.get("model") == model, "Unknown active worker")
completed, completed_path = call("check_task", dict(task_id=old_task), "r25-s08-completed")
require(completed.get("task_id") == old_task and completed.get("session_id") == session_id and completed.get("status") == "completed" and completed.get("observed_model") == model, "Old target task must be completed")
# A completed exited worker is absent from active_only. Its exact completed
# task/session/model binding is required before resuming that same session.
message = """继续 SAME S08-INSTANCE-RECOVERY-MIN-R23 第三轮实际开发返修，原session sess_d9cfbf4113，修复第二轮task_8886dcf232。连续实际开发交付失败计2，仍固定GLM-5.3，不换工作项重置。Root当前R23保持，未导入新模块。先读Root artifacts/s08-module-source-review-r25-20261016/{DELIVERY.md,review.json}、artifacts/coordinator-s08-module-dependency-r25-20261016/{review.json,identity-reconciliation.json,results.xml}、artifacts/coordinator-s08-consumer-r25-20261016/{review.json,results.xml,command-0.log}、artifacts/s08-consumer-probe-r25-20261016/test_s08_consumer_probe.py。第二轮原307/0/0/0四命令0；overall false中的7个Root probe classname差异已精确对账，是协调者问题不计workerfail，不需要为它重跑旧producer日志。新2probe实际2fail/0error/0skip，属于原lossless/prepare-success roundtrip义务，非新consumer接线范围。

执行目录 C:/Users/10273/home/work/Z-Scope_1.31/Z-Scope/.coordination/20261014/workspaces/s08-instance-recovery-min-r23。ONLY owned zscope/orchestration/jobs/instance_results.py、tests/test_instance_result_recovery.py；产物 DELIVERY.md + artifacts/instance-recovery-r23/**，新日志/JUnit用repair-r25子目录，历史原样保留。原1069readonly全部前后核哈希，不动Root/shared/native/probes/评审/其他worker。完整第二轮冻结Root artifacts/s08-consumer-probe-r25-20261016/failed-candidate。

必须修复两个真实缺陷：
1 实际CandidateLedger.add同ticket从entry_a和entry_b合法合并一个validation cluster，保留2个context_signatures和各自occurrence.context_signature；candidate_envelope明确cluster不含entry/path。当前codec把所有occurrence.context_signature强制等于record.primary context而拒绝该合法28字段投影。须核验完整已声明validation_contexts成员与逐行UID/entry/context一致性、保留所有真实paths/UID/owners，不把合法多context压成primary。未知/未声明context、UID覆盖不符、重复行/UID、同UID冲突仍拒绝；既有ctx-other negative应保留身份并维持未声明context拒绝，不弱化为无条件允许。新probe用当前Root真实Ledger生成而非合成记录，必须原样通过。
2 _strict_loads各record/outcome单独64MiB/深256/节点4M检查，但prepare拼完整封套未用相同资源策略，发布可返回成功而verify自己拒绝。须对最终整个document及canonical bytes应用与verify一致的资源约束，在发布前typed miss/no artifact，或明确支持的完整边界成功往返；不放宽现有限额/decoder、不降低0skip测试。新增depth封套、总字节/总节点累计、合法边界成功、拒绝无文件和历史不可变测试。不要catch-all吞程序错误。

保持4个原修复、原104测试身份/断言和原162回归、28wire和完整occurrence数据。codec record_count/obligation UID去重/occurrence UID count原口径不改，不改dataclass frozen接口，不把coordinator role/build/cluster全manifest工作挪入codec或删除诊断凑计数。prepare/verify typed miss不能写artifact/receipt，prepared payload bytes immutable。

所有测试/质量 ONLY WSL Ubuntu zeal /home/zeal/venv313/bin/python/Linux login PATH，每条验证单层Root test_slot.py --workspace <Linux隔离目录> -- <argv>，default fd/ext4 tmp。native Z_SCOPE_TEST_CLANG_INDEXER=/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer SHA d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399前后核对，只读不重建。跑owned新单测+原11文件162回归+Root原7及新增2独立probe（Rootprobes只读禁字节码，保持原断言），compileall -f -q zscope scripts test tests、mypy zscope、black --check两owned，全真实日志/JUnit、精确argv数组/实际时间/exitcode/sourceSHA/1069清单/prior IDs。actual_task_id未知填null不填旧task。0skip/error/failure才自报通过，停止写入后coordinator独验。

不读凭据/provider、不查WSL进程、不启停服务、不操作Bridge、不访问归档S06、不git reset/clean/stash/commit/push。仅模块返修，不宣称Store/Queue/Ledger/真实scan或all-restored已接入，不宣称整S08/S01/U01完成。"""
payload = dict(id=request_name, branch="s08-instance-recovery-min-r23", tool="dispatch_task", arguments=dict(agent="zcode", cwd="C:\\Users\\10273\\home\\work\\Z-Scope_1.31\\Z-Scope", session_id=session_id, model=model, effort=None, title="S08-INSTANCE-RECOVERY-MIN-R23 repair-r25", user_requested=True, request_id=str(uuid4()), message=message))
write_new(HERE / "followups-r12" / (request_name + "-request.json"), payload)
publish_request(route / "bridge-queue", payload)
until = time.monotonic() + 40
while time.monotonic() < until:
    if response_path.exists():
        try:
            result = read(response_path)
            break
        except json.JSONDecodeError:
            pass
    time.sleep(.25)
else:
    raise RuntimeError("Unknown dispatch outcome; no replay or reroute")
require(result.get("ok"), "Original owner rejected action; stop without route change: " + str(result.get("error")))
require(result.get("session_id") == session_id and result.get("model") == model, "Wrong accepted route")
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
ledger = read(HERE / "tasks.json")
row = next(row for row in ledger["tasks"] if row["id"] == "S08-INSTANCE-RECOVERY-MIN-R23")
require(row["bridge_task_id"] == old_task, "Task changed during dispatch; reconcile accepted response")
fields = ("bridge_task_id", "worker_process_started_at", "actual_tool_execution_observed_at", "execution_evidence", "worker_finished_at", "observed_model", "producer_status", "dispatch_evidence", "dispatched_at")
row.setdefault("prior_actual_task_observations", []).append({key: row.get(key) for key in fields})
row.setdefault("prior_actual_task_ids", []).append(old_task)
for key in ("worker_process_started_at", "actual_tool_execution_observed_at", "execution_evidence"):
    row.pop(key, None)
row.update(bridge_task_id=result["task_id"], request_id=payload["arguments"]["request_id"], producer_status="dispatched", status="same_session_third_delivery_repair_dispatched_execution_unconfirmed", dispatched_at=at, dispatch_evidence=response_path.relative_to(HERE).as_posix(), artifact_available=False, observed_model=None, worker_finished_at=None, independent_acceptance=False, checked_at=at)
ledger["updated_at"] = at
(HERE / "tasks.json").write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
proof = dict(logical_task=row["id"], task_id=result["task_id"], session_id=session_id, at=at, dispatch_accepted=True, actual_execution_confirmed=False, independent_acceptance=False, integrated=False, original_task_id=old_task, consecutive_failed_actual_deliveries=2, preflights=[path.relative_to(HERE).as_posix() for path in (agents_path, sessions_path, completed_path)], dispatch_receipt=row["dispatch_evidence"], root_inputs_verified=len(root_sources), dispatcher_sha256=sha(Path(__file__)))
write_new(HERE / "followups-r12/s08-repair-r25-dispatch-receipt.json", proof)
require(all(sha(ROOT / path) == digest for path, digest in root_sources.items()), "Root drift")
print(json.dumps(proof, ensure_ascii=False))
