"""One same-session third delivery with a reviewed shared readonly dependency."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil
import time
from uuid import uuid4
from bridge_queue_publish_r23 import publish_request

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
ROUTE = HERE / "route-check"
BRANCH = ROOT / ".coordination/20261014/workspaces/s01-instance-semantics-min-r23"
STAGE = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
MODEL = "97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3"
SESSION = "sess_6ecde27723"
OLD_TASK = "task_1297f2c18f"
REQUEST_NAME = "s01-instance-semantics-repair-r25"

def read(path):
    return json.loads(path.read_text(encoding="utf-8"))

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def require(ok, message):
    if not ok:
        raise RuntimeError(message)

def write(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(value, ensure_ascii=False, indent=2) + "\n")

def call(tool, arguments, label):
    name = label + "-" + uuid4().hex[:12]
    response = ROUTE / ("bridge-response-" + name + ".json")
    publish_request(ROUTE / "bridge-queue", dict(id=name, tool=tool, arguments=arguments))
    until = time.monotonic() + 40
    while time.monotonic() < until:
        if response.exists():
            try:
                return read(response), response
            except json.JSONDecodeError:
                pass
        time.sleep(.25)
    raise RuntimeError("Unknown original-owner outcome; inspect persisted request only")

ledger = read(HERE / "tasks.json")
row = next(row for row in ledger["tasks"] if row["id"] == "S01-INSTANCE-SEMANTICS-MIN-R23")
require(row["bridge_task_id"] == OLD_TASK and row["producer_status"] == "completed" and row["consecutive_failed_actual_deliveries"] == 2 and not row["integrated"], "Wrong active logical task")
failure = read(ROOT / "artifacts/s01-origin-probe-r25-20261016/failure-review.json")
require(failure["task_id"] == OLD_TASK and failure["round"]["counted_development_failure"], "Missing second actual failure")
require(all(sha(BRANCH / path) == digest for path, digest in failure["source_after"].items()), "Failed candidate drift")
root_sources = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
require(all(sha(ROOT / path) == digest for path, digest in root_sources.items()), "Root drift")
models_review_path = ROOT / "artifacts/instance-shadow-consumer-precheck-r25-20261016/review.json"
models_review = read(models_review_path)
require(models_review.get("shared_models_patch_source_review_passed") is True, "Shared model dependency must pass independent source review")
dependency_paths = ("zscope/semantics/models.py", "tests/test_semantics_shadow_overlay.py")
shared_review = models_review["shared_models_patch"]
require(shared_review["models_sha256_before"] == shared_review["models_sha256_after"] and shared_review["test_sha256_before"] == shared_review["test_sha256_after"], "Shared dependency changed during source review")
reviewed_hashes = {dependency_paths[0]: shared_review["models_sha256_after"], dependency_paths[1]: shared_review["test_sha256_after"]}
require(set(reviewed_hashes) == set(dependency_paths), "Wrong shared dependency source binding")
require(all(sha(STAGE / path) == digest for path, digest in reviewed_hashes.items()), "Shared patch drift after review")
focused = read(ROOT / "artifacts/coordinator-shared-overlay-r25-20261016/review.json")
require(focused["focused_checks_passed"] and focused["junit"] == dict(tests=18, failures=0, errors=0, skipped=0), "Shared overlay functional check failed")
require(all(focused["source_before"][str(STAGE / path)] == digest for path, digest in reviewed_hashes.items()), "Focused tests do not bind reviewed bytes")
baseline = {}
for name in ("s01-instance-semantics-min-r23-baseline.json", "s01-instance-semantics-min-r23-dependencies.json"):
    baseline.update({entry["path"]: entry["sha256"] for entry in read(HERE / "followups-r12" / name)["files"]})
require(len(baseline) == 1069 and all(sha(BRANCH / path) == digest for path, digest in baseline.items()), "Original readonly input drift")
require(not (BRANCH / dependency_paths[1]).exists(), "Unexpected preexisting shared test")
response_path = ROUTE / ("bridge-response-" + REQUEST_NAME + ".json")
for suffix in (".request.json", ".request.consumed"):
    require(not (ROUTE / "bridge-queue" / ("080-" + REQUEST_NAME + suffix)).exists(), "Dispatch already published; do not replay")
require(not response_path.exists(), "Existing dispatch response must be reconciled")
agents, agents_path = call("list_agents", {}, "r25-s01-agents")
require(agents.get("ok") and agents["coordinator"]["dispatch_enabled"], "Dispatch disabled")
require(any(agent.get("agent") == "zcode" and agent.get("available") for agent in agents["agents"]), "Fixed ZCode route unavailable")
sessions, sessions_path = call("list_sessions", dict(active_only=True), "r25-s01-active")
require(sessions.get("ok"), "Session preflight failed")
require(isinstance(sessions.get("sessions"), list) and all(isinstance(session, dict) for session in sessions["sessions"]), "Malformed active session inventory; outcome unknown")
targets = [session for session in sessions.get("sessions", []) if session.get("session_id") == SESSION]
require(len(targets) <= 1, "Duplicate active target sessions")
if targets:
    require(targets[0].get("agent") == "zcode" and targets[0].get("model") == MODEL and targets[0].get("proc_state") == "ready", "An active target must be fixed-route and ready")
for session in sessions.get("sessions", []):
    require(session.get("session_id") in {SESSION, "sess_d9cfbf4113"} and session.get("agent") == "zcode" and session.get("model") == MODEL, "Unknown active worker or route")
    if session["session_id"] == SESSION:
        require(session.get("proc_state") == "ready", "Target session is busy; no duplicate repair")
completed, completed_path = call("check_task", dict(task_id=OLD_TASK), "r25-s01-completed")
require(completed.get("task_id") == OLD_TASK and completed.get("session_id") == SESSION and completed.get("status") == "completed" and completed.get("observed_model") == MODEL, "Target old task must be complete on the fixed route")
# active_only omits a completed worker that has exited. Exact completed-task
# identity above authorizes resuming this owned session when it is absent;
# an active busy target is still rejected before any dependency or dispatch.

# The worker remains a two-file owner. The coordinator supplies precisely one
# reviewed shared replacement and one readonly shared regression, with the
# original manifest and old dependency bytes retained unchanged.
dependency_receipt_path = HERE / "followups-r12/s01-repair-r25-readonly-dependencies.json"
require(not dependency_receipt_path.exists(), "Existing dependency installation needs reconciliation")
backup = ROOT / "artifacts/s01-origin-probe-r25-20261016/readonly-dependency-before"
backup.mkdir(exist_ok=False)
shutil.copyfile(BRANCH / dependency_paths[0], backup / "models.py")
for path in dependency_paths:
    (BRANCH / path).parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(STAGE / path, BRANCH / path)
effective = dict(baseline)
effective.update(reviewed_hashes)
require(len(effective) == 1070 and all(sha(BRANCH / path) == digest for path, digest in effective.items()), "Installed readonly dependency mismatch")
write(dependency_receipt_path, dict(installed_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), coordinator_owned=True, worker_write_paths=row["write_paths"], original_readonly_count=1069, current_readonly_count=1070, only_shared_replacement=dependency_paths[0], only_shared_addition=dependency_paths[1], original_models_sha256=baseline[dependency_paths[0]], new_shared_sha256=reviewed_hashes, source_review=models_review_path.relative_to(ROOT).as_posix(), source_review_sha256=sha(models_review_path), focused_check="artifacts/coordinator-shared-overlay-r25-20261016/review.json", files=[dict(path=path, sha256=digest) for path, digest in effective.items()], root_intake=False))

message = """继续 SAME S01-INSTANCE-SEMANTICS-MIN-R23 第三轮实际开发返修，原session sess_6ecde27723，修复第二轮 task_1297f2c18f。连续实际交付失败=2，仍固定 ZCode GLM-5.3；不是新任务/换ID清零。先完整读 Root artifacts/s01-module-source-review-r25-20261016/{DELIVERY.md,review.json}、artifacts/coordinator-s01-module-dependency-r25-20261016/{review.json,results.xml,command-0.log}、artifacts/coordinator-s01-origin-r25-20261016/{review.json,results.xml,command-0.log} 和 artifacts/s01-origin-probe-r25-20261016/test_s01_origin_probe.py。第二轮原137测试136pass/1fail（三质量0）；新增真实native wrong-signature probe1fail/0error/0skip。该标准根/ABI义务已在原返修要求里，未完成，不能把 is_system_header=True 当标准根证明。

执行目录保持 C:/Users/10273/home/work/Z-Scope_1.31/Z-Scope/.coordination/20261014/workspaces/s01-instance-semantics-min-r23。ONLY owned两文件 zscope/semantics/instance_semantics.py、tests/test_instance_semantics.py，交付 DELIVERY.md + artifacts/instance-semantics-r23/**（本轮新增 repair-r25 子目录，旧历史一字不改）。无Root/shared/native/其他worker写权。

协调者已提供并独立review/18case验证 shared models.py merge_overlay 最小裁剪修复，以及 readonly tests/test_semantics_shadow_overlay.py。读取 Root docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/coordination/2026-10-14/followups-r12/s01-repair-r25-readonly-dependencies.json：原1069清单保持历史不改，唯一替换models.py及新增sharedtest，使本轮readonly清单1070。它们由协调者拷贝，worker不得再改，所有1070前后哈希。此接缝不代表Graph/Regex/Clang全部消费者已通过。原failedcandidate完整冻结 artifacts/s01-origin-probe-r25-20261016/failed-candidate。

必须完成：
1 标准授权不能只看同名/is_system_header，也不能只看文件basename、主机OS/位宽或可伪造来源字符串。独立真实native -fno-builtin -isystem vendor/header 中 int malloc(int) 当前被授权错误；精确核对当前native USR/完整canonical signature/声明身份、无项目定义、适用ABI/平台证据与packaged contract。来源/ABI无法核验的根保持deny/unknown/明确unavailable，不回退名称。真实stdlib malloc/free正例必须继续通过；不能让所有合法输入永久unavailable躲避正例。当前工具没有足够证据的其他API保持缺口，不改native工具、shared contract或experiment开关，不伪造native收据。
2 标准root universe覆盖 packaged checker-only名称（如graph delete、Clang bcopy）及role/contracts/pairs/checker models，missing/unproven origin必须deny；materialized local/overlay的deny完整一致。协调者单独负责裸消费者重新加入默认名的接线，不在本worker修改那些shared消费者。
3 原P1-02原始empty/default registry oracle必须原样通过。你的owned test:960把 residual in default.allocators 当成功的断言，现在已过期：保留测试身份，收紧为 absence/guards/effects皆deny，注明shared dependency变化依据，不删弱化断言。不能把prose报告当runtime unavailable。保留原39及新增所有合法测试身份、原132回归、默认fd/0skip，新增真实wrong-signature/身份/未知ABI负例及真实正例。
4 修正DELIVERY/review actual_task_id：本轮未知填null不要旧task；由coordinator公开收据绑定。记录精确argv数组，不要&&链、<nine files>等占位替代真实命令；JUnit路径可解析、before/after SHA、实际时间、1070输入清单、保持prior identities。

所有测试/质量 ONLY WSL Ubuntu zeal /home/zeal/venv313/bin/python/Linux login PATH。每条验证恰好单层Root test_slot.py --workspace <Linux本隔离目录> -- <argv>，默认fd capture、ext4 tmp；native /home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer SHA d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399 前后核对，只读不重建。跑新owned测试+原9文件132对应回归+readonlyshared2文件18case+Root原四authority及新增stdlib positive共5case+新的wrong-signature1case（Root probes只读禁写字节码，保持原assertions），compileall -f -q zscope scripts test tests、mypy zscope、black --check两owned。完整真实日志/JUnit不覆写旧轮；测试失败不能自称通过。不读credentials/provider、不查WSL进程、不启停服务、不操作Bridge、不访问归档S06，不git reset/clean/stash/commit/push。

本轮只模块及已提供shared依赖，不是consumer真实扫描接线/整S01/S08/U01验收。停止写入后coordinator独验，保留失败历史。"""
payload = dict(id=REQUEST_NAME, branch="s01-instance-semantics-min-r23", tool="dispatch_task", arguments=dict(agent="zcode", cwd=str(ROOT).replace("/mnt/c/", "C:/", 1), session_id=SESSION, model=MODEL, effort=None, title="S01-INSTANCE-SEMANTICS-MIN-R23 repair-r25", user_requested=True, request_id=str(uuid4()), message=message))
# Bridge expects the host repository path, while all execution instructions
# explicitly name the isolated workspace and Linux-only verification.
payload["arguments"]["cwd"] = "C:\\Users\\10273\\home\\work\\Z-Scope_1.31\\Z-Scope"
write(HERE / "followups-r12/s01-instance-semantics-repair-r25-request.json", payload)
publish_request(ROUTE / "bridge-queue", payload)
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
    raise RuntimeError("Unknown original-owner dispatch outcome; no replay or reroute")
require(result.get("ok"), "Original owner rejected repair; stop affected action without route change: " + str(result.get("error")))
require(result.get("session_id") == SESSION and result.get("model") == MODEL, "Unexpected accepted route")
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
ledger = read(HERE / "tasks.json")
row = next(row for row in ledger["tasks"] if row["id"] == "S01-INSTANCE-SEMANTICS-MIN-R23")
require(row["bridge_task_id"] == OLD_TASK, "Logical task changed during dispatch; reconcile accepted response")
fields = ("bridge_task_id", "worker_process_started_at", "actual_tool_execution_observed_at", "execution_evidence", "worker_finished_at", "observed_model", "producer_status", "dispatch_evidence", "dispatched_at")
row.setdefault("prior_actual_task_observations", []).append({key: row.get(key) for key in fields})
row.setdefault("prior_actual_task_ids", []).append(OLD_TASK)
for key in ("worker_process_started_at", "actual_tool_execution_observed_at", "execution_evidence"):
    row.pop(key, None)
row.update(bridge_task_id=result["task_id"], request_id=payload["arguments"]["request_id"], producer_status="dispatched", status="same_session_third_delivery_repair_dispatched_execution_unconfirmed", dispatched_at=at, dispatch_evidence=response_path.relative_to(HERE).as_posix(), artifact_available=False, observed_model=None, worker_finished_at=None, independent_acceptance=False, checked_at=at, readonly_dependency_manifest=dependency_receipt_path.relative_to(HERE).as_posix(), prepared_readonly_input_files=1070)
ledger["updated_at"] = at
(HERE / "tasks.json").write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
proof = dict(logical_task=row["id"], task_id=result["task_id"], session_id=SESSION, at=at, dispatch_accepted=True, actual_execution_confirmed=False, independent_acceptance=False, integrated=False, original_task_id=OLD_TASK, consecutive_failed_actual_deliveries=2, preflights=[path.relative_to(HERE).as_posix() for path in (agents_path, sessions_path, completed_path)], dispatch_receipt=row["dispatch_evidence"], readonly_dependency_manifest=row["readonly_dependency_manifest"], root_inputs_verified=len(root_sources), dispatcher_sha256=sha(Path(__file__)))
write(HERE / "followups-r12/s01-repair-r25-dispatch-receipt.json", proof)
require(all(sha(ROOT / path) == digest for path, digest in root_sources.items()), "Root drift")
print(json.dumps(proof, ensure_ascii=False))
