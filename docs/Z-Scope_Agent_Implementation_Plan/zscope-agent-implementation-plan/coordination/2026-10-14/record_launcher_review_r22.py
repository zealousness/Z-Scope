"""Record the independent read-only R22 review without declaring a joint pass."""
from pathlib import Path
import datetime as dt
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
out = ROOT / "artifacts/root-launcher-delta-review-r22-20261016"
review_path = out / "review.json"
assert hashlib.sha256(review_path.read_bytes()).hexdigest() == "ab070a7e979d7c6adbb15003124dee951fe67dc195e0e9e6c28afe68ff4c9891"
assert hashlib.sha256((out / "DELIVERY.md").read_bytes()).hexdigest() == "bfa7317c8a0bcaeb0a1ce13b902efdc5b6c57b8d4e3db478f0d9a1d8256e0eb6"
review = json.loads(review_path.read_text(encoding="utf-8"))
assert review["source_review_passed"] and review["blocking_findings"] == []
assert review["tests_executed"] == 0 and not review["product_changed"]
assert review["reviewed_files_unchanged"] and review["native_unchanged"]
assert review["unexpected_reviewed_file_changes"] == []
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
path = HERE / "tasks.json"
ledger = json.loads(path.read_text(encoding="utf-8"))
rows = {r["id"]: r for r in ledger["tasks"]}
identity = "ASTRA-ROOT-LAUNCHER-DELTA-REVIEW-R22"
assert identity not in rows
row = {"id": identity, "depends_on": ["CURRENT-JOINT-R21", "ASTRA-ROOT-LAUNCHER-REVIEW-R21"], "owner": "Astra", "agent_kind": "native_subagent", "agent_task_id": "/root/astra_job_cli_sql_r20", "accepted_model": "gpt-6-astra", "reasoning_effort": "xhigh", "status": "readonly_source_review_completed_no_blocking_findings_live_publication_check_required", "producer_status": "completed", "actual_execution_at": review["started_at"], "worker_finished_at": review["finished_at"], "artifact_available": True, "independent_static_review": True, "independent_acceptance": False, "integrated": False, "joint_verification": False, "product_changed": False, "whole_package_complete": False, "evidence": review_path.relative_to(ROOT).as_posix(), "tests_executed": 0, "checked_at": at}
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
