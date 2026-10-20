"""Record the complex native handoff without resetting the logical history."""
from pathlib import Path
import datetime as dt
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
path = HERE / "tasks.json"
ledger = json.loads(path.read_text(encoding="utf-8"))
row = next(r for r in ledger["tasks"] if r["id"] == "U01-JOB-CLI-WINDOW-R20")
assert row["status"] == "quiescent_complex_sql_handoff_ready" and row["consecutive_failed_actual_deliveries"] == 1
closed = json.loads((HERE / "followups-r12/job-cli-window-r20-network-closed.json").read_text(encoding="utf-8"))
assert closed["session_state_after"] == "dead" and not closed["tool_execution_observed"]
deps = json.loads((HERE / "followups-r12/job-cli-window-r20-dependencies.json").read_text(encoding="utf-8"))
branch = ROOT / ".coordination/20261014/workspaces/job-cli-window-r20"
owned_before = {p: hashlib.sha256((branch / p).read_bytes()).hexdigest() for p in row["owns"]}
assert owned_before == closed["owned_source_unchanged"]
assert all(hashlib.sha256((branch / r["path"]).read_bytes()).hexdigest() == r["sha256"] for r in deps["files"])
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
handoff = {"at": at, "logical_work_item": row["id"], "native_task_id": "/root/astra_job_cli_sql_r20", "model": "gpt-6-astra", "reasoning_effort": "xhigh", "previous_bridge_task_id": row["bridge_task_id"], "previous_session_id": row["bridge_session_id"], "bridge_session_closed": True, "own_paths": row["owns"], "owned_before": owned_before, "readonly_dependencies": deps, "development_failure_streak_before": 1, "routing_reason": "Explicit user policy permits particularly complex work to Astra/xhigh. Atomic SQL identity/window, project-store and persisted run-directory authority requires deeper review. GLM network-only failure is not a fourth development failure or a platform rejection; history and first delivery retained."}
proof_path = HERE / "followups-r12/job-cli-window-r20-native-handoff.json"
proof_path.write_text(json.dumps(handoff, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
row.update(owner="Astra", agent_kind="native_subagent", agent_task_id=handoff["native_task_id"], requested_model=handoff["model"], reasoning_effort="xhigh", previous_requested_model=row["requested_model"], status="native_complex_sql_repair_dispatched_execution_pending", producer_status="dispatched", observed_model=None, actual_execution_at=None, worker_finished_at=None, dispatch_evidence=proof_path.relative_to(HERE).as_posix(), artifact_available=False, checked_at=at)
ledger["updated_at"] = at
path.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
path = HERE / "continuation-r6.json"
continuation = json.loads(path.read_text(encoding="utf-8"))
continuation.update(updated_at=at, native_active_job_cli={"agent_task_id": row["agent_task_id"], "status": row["status"], "workspace": row["workspace"], "requested_model": row["requested_model"], "reasoning_effort": "xhigh", "independent_acceptance": False, "integrated": False, "handoff": proof_path.relative_to(HERE).as_posix()}, active_phase="Complex SQL authority repair isolated; first-cause independently397 accepted frozen, Root R19 unchanged")
path.write_text(json.dumps(continuation, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
note = f"## {at} · Complex SQL authority native handoff, no duplicate writer\n\nGLM task_d98c531060 failed22:17:56 after five Network error retries, no model/tool development observed; sess_e10155a00c closed and branch journal reconciled through existing API. Evidence: followups-r12/job-cli-window-r20-network-closed.json. Original owner80748 remains running; no service/provider/credential/policy change. Logical U01-JOB-CLI-WINDOW-R20 actual development failure streak remains1 (task_492e7a7037, independent8pass3fail), both transport failures excluded. Under explicit complex-work Astra/xhigh policy, native /root/astra_job_cli_sql_r20 now dispatched to same isolated workspace, exact3 owned files; readonly accepted first-cause2 + staged coordinator docs4 installed with dependency receipt. Native actual execution pending. Parent accepted slices retained; Root1041 unchanged, current selected R19 2314/six0 does not cover outstanding SQL and first-cause gates.\n\n---\n\n"
for filename in ("DAG.md", "PROGRESS.md", "CURRENT_STATE_R20.md"):
    path = HERE / filename
    path.write_text(note + path.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
print(json.dumps({"at": at, "task_id": row["agent_task_id"], "owned_files": len(row["owns"]), "development_failure_streak": 1, "root_changed": False}), flush=True)
