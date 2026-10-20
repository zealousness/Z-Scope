"""Record actual independent execution and the retained startup correction."""
from pathlib import Path
import datetime as dt
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
path = HERE / "tasks.json"
ledger = json.loads(path.read_text(encoding="utf-8"))
row = next(r for r in ledger["tasks"] if r["id"] == "U01-JOB-CLI-WINDOW-R20")
assert row["producer_status"] == "completed" and not row["integrated"]
row.update(status="final_byte_full_independent_verification_running", verification_evidence="artifacts/coordinator-job-cli-window-r20-final-acceptance-20261015", coordinator_startup_correction="artifacts/coordinator-job-cli-window-r20-interrupted-nested-startup-20261015/interruption-receipt.json", checked_at=at)
ledger["updated_at"] = at
path.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
path = HERE / "continuation-r6.json"
continuation = json.loads(path.read_text(encoding="utf-8"))
continuation.update(updated_at=at, native_active_job_cli={"agent_task_id": row["agent_task_id"], "status": "producer_frozen_final_byte_coordinator_independent_running", "finished_at": row["worker_finished_at"], "workspace": row["workspace"], "requested_model": row["requested_model"], "reasoning_effort": "xhigh", "independent_acceptance": False, "integrated": False, "verification_evidence": row["verification_evidence"]})
path.write_text(json.dumps(continuation, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
note = f"## {at} · R20 final-byte independent verification running\n\nNative /root/astra_job_cli_sql_r20 stopped22:40:37; final3 source SHAs and DELIVERY/evidence SHA verified. Producer525 self-tests belong to pre-Optional-annotation bytes, final-byte mypy/compileall/Black0; final pytest is not claimed yet. Coordinator full collection began22:45 with exactly one internal slot. Earlier coordinator invocation incorrectly added an outer slot; it was interrupted, test children exited, all3 source SHAs unchanged, no product failure counted. Startup proof retained in artifacts/coordinator-job-cli-window-r20-interrupted-nested-startup-20261015/interruption-receipt.json. Shared helper now refuses nested invocations before acquiring a slot; explicit rejection probe passed. Strict tests/capture/timeouts unchanged. Root R19 remains unchanged; two frozen native deliveries not intaken, current full Root union still pending.\n\n---\n\n"
for filename in ("DAG.md", "PROGRESS.md", "CURRENT_STATE_R20.md"):
    path = HERE / filename
    path.write_text(note + path.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
print(json.dumps({"at": at, "task_id": row["agent_task_id"], "status": row["status"], "root_changed": False}), flush=True)
