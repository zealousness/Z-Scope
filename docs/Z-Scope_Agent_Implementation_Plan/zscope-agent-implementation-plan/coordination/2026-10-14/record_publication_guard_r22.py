"""Register the completed read-only publication-guard review."""
from pathlib import Path
import datetime as dt
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
out = ROOT / "artifacts/publication-guard-review-r22-20261016"
review_path = out / "review.json"
assert hashlib.sha256(review_path.read_bytes()).hexdigest() == "9e5e97c72d2db3ee29ed92f77104cb26b0edbf0d5b45e28dbc9471eef445efc3"
assert hashlib.sha256((out / "DELIVERY.md").read_bytes()).hexdigest() == "0488b9fc81bd28b471104f9cb6fec0514b6a4bf36cd87aa3581168cd31c5bf1f"
review = json.loads(review_path.read_text(encoding="utf-8"))
assert review["source_review_passed"] and review["blocking_findings"] == []
assert review["tests_executed"] == 0 and not review["product_changed"]
assert review["input_files_unchanged"] and review["native_unchanged"]
assert review["unexpected_input_changes"] == []
assert not review["wrapper_executed"] and not review["publisher_executed"]
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
path = HERE / "tasks.json"
ledger = json.loads(path.read_text(encoding="utf-8"))
rows = {r["id"]: r for r in ledger["tasks"]}
identity = "ASTRA-PUBLICATION-GUARD-REVIEW-R22"
assert identity not in rows
row = {"id": identity, "depends_on": ["ASTRA-ROOT-LAUNCHER-DELTA-REVIEW-R22"], "owner": "Astra", "agent_kind": "native_subagent", "agent_task_id": "/root/astra_job_cli_sql_r20", "accepted_model": "gpt-6-astra", "reasoning_effort": "xhigh", "status": "readonly_publication_guard_review_completed_no_blocking_findings", "producer_status": "completed", "actual_execution_at": review["started_at"], "worker_finished_at": review["finished_at"], "artifact_available": True, "independent_static_review": True, "independent_acceptance": False, "integrated": False, "joint_verification": False, "product_changed": False, "whole_package_complete": False, "evidence": review_path.relative_to(ROOT).as_posix(), "tests_executed": 0, "checked_at": at}
ledger["tasks"].append(row)
rows["CURRENT-JOINT-R22"]["depends_on"].append(identity)
rows = {r["id"]: r for r in ledger["tasks"]}
pending, done, layers = set(rows), set(), []
while pending:
    ready = sorted(p for p in pending if set(rows[p].get("depends_on", [])) <= done)
    assert ready
    layers.append(ready)
    done.update(ready)
    pending.difference_update(ready)
ledger.update(updated_at=at, topological_layers=layers)
path.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"at": at, "logical_task": identity, "actual_task_id": row["agent_task_id"], "finished_at": row["worker_finished_at"], "tests_executed": 0, "joint_passed": False}), flush=True)
