"""Record the completed read-only launcher review as a publication dependency."""
from pathlib import Path
import datetime as dt
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
out = ROOT / "artifacts/root-launcher-review-r21-20261016"
review_path = out / "review.json"
assert hashlib.sha256(review_path.read_bytes()).hexdigest() == "5f09382311979177687afb376c4037b2022331065b076d8130aa08b6488c9626"
assert hashlib.sha256((out / "DELIVERY.md").read_bytes()).hexdigest() == "d0ef275f7ed3182669fcb23766b93f47b61d9f0b528472276b79433cd097f30f"
review = json.loads(review_path.read_text(encoding="utf-8"))
assert review["source_review_passed"] and review["blocking_findings"] == []
assert review["tests_executed"] == 0 and not review["product_changed"]
assert review["source_observations"]["unexpected_changes"] == review["source_observations"]["root_inventory_drift"] == []
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
path = HERE / "tasks.json"
ledger = json.loads(path.read_text(encoding="utf-8"))
rows = {r["id"]: r for r in ledger["tasks"]}
identity = "ASTRA-ROOT-LAUNCHER-REVIEW-R21"
assert identity not in rows
row = {"id": identity, "depends_on": ["COORD-ROOT-FIXTURES-R21"], "owner": "Astra", "agent_kind": "native_subagent", "agent_task_id": "/root/astra_job_cli_sql_r20", "accepted_model": "gpt-6-astra", "reasoning_effort": "xhigh", "status": "readonly_source_review_completed_no_blocking_findings_live_publication_check_required", "producer_status": "completed", "actual_execution_at": review["started_at"], "worker_finished_at": review["finished_at"], "artifact_available": True, "independent_static_review": True, "independent_acceptance": False, "integrated": False, "joint_verification": False, "product_changed": False, "whole_package_complete": False, "evidence": review_path.relative_to(ROOT).as_posix(), "tests_executed": 0, "checked_at": at}
ledger["tasks"].append(row)
rows["CURRENT-JOINT-R21"]["depends_on"].append(identity)
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
