"""Publish actual next-stage status while preserving the accepted Root bytes."""
from pathlib import Path
import datetime as dt
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]

def read(p):
    return json.loads(p.read_text(encoding="utf-8"))

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def write(p, value):
    p.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

joint_dir = ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016"
joint = read(joint_dir / "review.json")
source = read(joint_dir / "source-evidence.json")
assert joint["passed"] == 2551 and joint["commands_passed"] == 6 and joint["pytest_file_count"] == 171
assert all(sha(ROOT / p) == h for p, h in source["after"].items()), "Accepted Root inputs drifted after worker dispatch"
native = Path("/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer")
assert sha(native) == source["native_after"]
ledger = read(HERE / "tasks.json")
rows = {r["id"]: r for r in ledger["tasks"]}
tasks = []
for key in ("S01-INSTANCE-SEMANTICS-MIN-R23", "S08-INSTANCE-RECOVERY-MIN-R23"):
    row = rows[key]
    assert row.get("bridge_task_id") and row["accepted_model"] == "97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3"
    assert row["original_owner_preflight"] == "followups-r12/parallel-preflight-r23-d02c4e4abf50.json"
    row["fresh_active_preflight_done"] = True
    assert all(not (ROOT / p).exists() for p in row["write_paths"]), "A worker wrote its new module to Root without intake"
    tasks.append({"logical_task": key, "task_id": row["bridge_task_id"], "session_id": row["bridge_session_id"], "model": row["accepted_model"], "observed_model": row.get("observed_model"), "dispatched_at": row["dispatched_at"], "worker_process_started_at": row.get("worker_process_started_at"), "actual_tool_execution_observed_at": row.get("actual_tool_execution_observed_at"), "producer_status": row.get("producer_status"), "workspace": row["workspace"], "write_paths": row["write_paths"], "artifact_available": row["artifact_available"], "independent_acceptance": row["independent_acceptance"], "integrated": row["integrated"], "joint_verification": row["joint_verification"], "dispatch_evidence": row["dispatch_evidence"], "execution_evidence": row.get("execution_evidence")})
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
out = ROOT / "artifacts/coordinator-module-handoff-r23-20261016"
out.mkdir(exist_ok=False)
proof = {"at": at, "current_root_joint": (joint_dir / "review.json").relative_to(ROOT).as_posix(), "current_root_joint_finished_at": joint["finished_at"], "current_root_result": {"passed": 2551, "failed": 0, "errors": 0, "skipped": 0, "test_files": 171, "commands_passed": 6}, "live_root_bound_inputs": len(source["after"]), "live_root_bound_hashes_match": True, "native_sha256": sha(native), "owner_windows_pid": 80748, "owner_started_at": "2026-10-14T16:58:25+08:00", "owner_observed_at": "2026-10-16T10:59:33+08:00", "fresh_active_preflight": "followups-r12/parallel-preflight-r23-d02c4e4abf50.json", "fresh_active_preflight_at": "2026-10-16T10:59:41.686844+08:00", "active_before_dispatch": [], "services_started_or_restarted": 0, "archived_S06_operations": 0, "manual_wsl_process_inspection": False, "tasks": tasks, "root_product_changed_after_joint": False, "whole_packages_complete": False, "remaining_dependencies": ["New module candidates await delivery and independent module acceptance", "Coordinator-only actual S01 Analyzer/Validator/advisory/version wiring", "Coordinator-only S08 trusted read/claim settlement/full ledger/R-E/current validation/checkpoint wiring", "Cross-run attempts/age/fairness and complete variant modeling remain separate", "U01 remaining declared-only consumption and parent S02-S07 DAG work"], "separate_not_executed": ["Actual LLM/real-project effect acceptance", "Formal benchmark and portable smoke", "Conditional S10 and post-S08 Q01/Q02"], "clock_problem_resolved": False}
write(out / "review.json", proof)
ledger.update(updated_at=at, next_module_tasks=tasks, current_root_status="R23 current selected union2551/171/six passed and live1065 inputs stable; two isolated GLM module candidates dispatched, no intake")
write(HERE / "tasks.json", ledger)
continuation = read(HERE / "continuation-r6.json")
continuation.update(updated_at=at, active_phase="Two isolated ZCode module candidates dispatched; independently accept candidates then coordinator-only integration; current Root R23 preserved", next_module_tasks=tasks, latest_handoff=(out / "review.json").relative_to(ROOT).as_posix(), whole_packages_complete=False)
write(HERE / "continuation-r6.json", continuation)
lines = "\n".join(f"- {r['logical_task']}: {r['task_id']}/{r['session_id']}, dispatched {r['dispatched_at']}, process started {r['worker_process_started_at']}, first actual-tool observation {r['actual_tool_execution_observed_at'] or 'unconfirmed'}, status {r['producer_status']}; artifact/independent/integrated/joint={r['artifact_available']}/{r['independent_acceptance']}/{r['integrated']}/{r['joint_verification']}." for r in tasks)
note = f"## {at} · Current Root accepted; isolated next-stage GLM tasks dispatched\n\nRoot R23 final proof {joint['finished_at']}:2551 passed,0failed/error/skip,171files,six commands0; original JUnit identities and unchanged timing assertion retained. Live1065 bound inputs/native still match after dispatch; no candidate module exists in Root. Evidence {proof['current_root_joint']}; handoff {out.relative_to(ROOT).as_posix()}/review.json. Owner80748 original start16:58:25 Oct14 still observed10:59:33; fresh atomic active-only preflight10:59:41 returnedempty. No service restart, archived S06 action or manual WSL process inspection.\n\n{lines}\n\nBoth workers fixed GLM and own only2 new paths each; shared files remain coordinator-only. Kimi new dispatch paused under current DISPATCH_POLICY; Astra UI/complex design split retained. Module candidates are not slice/whole-package acceptance. Real-project/LLM/formal/portable and conditional extensions remain separate, host clock observation unresolved.\n\n---\n\n"
for name in ("PROGRESS.md", "DAG.md"):
    p = HERE / name
    p.write_text(note + p.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
(HERE / "CURRENT_STATE_R23.md").write_text(note, encoding="utf-8", newline="\n")
print(json.dumps({"at": at, "current_Root_passed": 2551, "bound_inputs_stable": len(source["after"]), "tasks": tasks, "receipt": (out / "review.json").relative_to(ROOT).as_posix()}), flush=True)
