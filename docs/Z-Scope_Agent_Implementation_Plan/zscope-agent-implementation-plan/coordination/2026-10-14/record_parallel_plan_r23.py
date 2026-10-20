"""Record accepted contracts and prepared work separately from actual dispatch."""
from pathlib import Path
import datetime as dt
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]

def read(p):
    return json.loads(p.read_text(encoding="utf-8"))

def write(p, value):
    p.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

ledger = read(HERE / "tasks.json")
rows = {r["id"]: r for r in ledger["tasks"]}
review_path = ROOT / "artifacts/design-contract-independent-review-r23-20261016/review.json"
review = read(review_path)
assert review["source_review_passed"] and review["design_dispatch_ready"]
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
prepared = []
for key in ("S01-INSTANCE-SEMANTICS-MIN-R23", "S08-INSTANCE-RECOVERY-MIN-R23"):
    row = rows[key]
    assert not row.get("bridge_task_id") and row["contract_review_passed"]
    prepared.append({"logical_task": key, "workspace": row["workspace"], "owns": row["write_paths"], "readonly_inputs": row["prepared_readonly_input_files"], "dispatched": False, "actual_execution": False, "artifact_available": False, "independent_acceptance": False, "integrated": False, "joint_verification": False})
out = ROOT / "artifacts/coordinator-r23-parallel-plan-20261016"
out.mkdir(exist_ok=False)
proof = {"at": at, "contract_producer": "/root/astra_design_contract_r23", "contract_independent_reviewer": "/root/astra_design_review_r23", "contract_review": review_path.relative_to(ROOT).as_posix(), "contract_review_sha256": hashlib.sha256(review_path.read_bytes()).hexdigest(), "contract_review_finished_at": review["clock_observations"]["final_source_review_external_utc"], "contract_source_review_passed": True, "functional_acceptance": False, "prepared_modules": prepared, "current_root_joint": "CURRENT-JOINT-R23", "current_root_exec_session": 82911, "current_root_joint_passed": False, "actual_blocker_to_dispatch": "Root R23 complete171-file collection and six strict commands still executing; then fresh existing-owner/active-session preflight required", "shared_paths_single_writer": "Coordinator: scan_session/parallel_analyzer/scan_work/store/session_scheduler/candidates/Analyzer and integration tests/docs", "remaining": ["Real S01 consumer/advisory/semantic identity wiring and later current inferred implementation proof/full variant modeling", "Real S08 trusted reader/current claim settlement/full Ledger restore and all-restored validation barrier", "Cross-run attempts/age/fairness and continuous plan admission accounting", "U01 remaining focus/reproduction/max_workers/platform and entrypoint consumer work", "Parent S02-S07 work from original DAG; no reopening archived S06-R02 session"], "separate_not_executed": ["Actual LLM/real-project effects", "Formal benchmark and portable acceptance", "Conditional S10 and post-S08 Q01/Q02"], "whole_packages_complete": False}
write(out / "review.json", proof)
note = f"## {at} · R23 contracts accepted; two module copies prepared, not dispatched\n\nAstra contract producer /root/astra_design_contract_r23 and independent reviewer /root/astra_design_review_r23 completed; exact contract source review passed at10:27:25, tests0/product0. Contracts preserve builtin-only effects/manual advisory/no inferred, trusted result read/current claim settlement, full Ledger and R/E all-restored validation barrier. Evidence {proof['contract_review']}.\n\nS01-INSTANCE-SEMANTICS-MIN-R23 and S08-INSTANCE-RECOVERY-MIN-R23 each own only one new module and one new test in separate workspaces,1069 readonly inputs each. Both are prepared, not dispatched/executed/delivered/accepted/integrated. Current Root R23 exec82911 is still running all171 files and six original strict commands; no final result. After pass, recheck original Bridge owner/current sessions then dispatch fixed ZCode GLM; Kimi new tasks remain paused by DISPATCH_POLICY. Shared files remain coordinator-only. Artifact {out.relative_to(ROOT).as_posix()}/review.json. No old S06-R02 operation or package/real-project completion claim.\n\n---\n\n"
for name in ("PROGRESS.md", "DAG.md"):
    p = HERE / name
    p.write_text(note + p.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
print(json.dumps({"at": at, "prepared": 2, "dispatched": 0, "root_joint_passed": False, "evidence": (out / "review.json").relative_to(ROOT).as_posix()}), flush=True)
