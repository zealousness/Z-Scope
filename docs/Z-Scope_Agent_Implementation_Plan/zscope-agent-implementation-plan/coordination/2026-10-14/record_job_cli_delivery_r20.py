"""Record a frozen native delivery without treating earlier-byte self-tests as final."""
from pathlib import Path
import datetime as dt
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
branch = ROOT / ".coordination/20261014/workspaces/job-cli-window-r20"
expected = {"zscope/cli/cli.py": "9964cc77ce1527d8f543153b98bb4b757492429e2da7569d82c8647921376b15", "zscope/orchestration/execution_profile.py": "38c2bf125935031af5040d273373ba831c2b408a3e50c5f3989b54c49288164a", "tests/test_job_cli_stop_window.py": "1ab43bee01fc6c90f6b4fc75a6a07e9fe6614666df5e4eefdd1e2400d771a419"}
assert all(hashlib.sha256((branch / p).read_bytes()).hexdigest() == h for p, h in expected.items())
assert hashlib.sha256((branch / "DELIVERY.md").read_bytes()).hexdigest() == "cb3cec41511466b77cbb1a0f49c5dd4fbc0d9e8b65467b11c85f42e6de7d2331"
assert hashlib.sha256((branch / "artifacts/astra-r20/evidence.json").read_bytes()).hexdigest() == "3c453c1a90b987e7cce38a073a1f9b6b480ad8cc9441b67f57c5515e5a2ee15d"
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
path = HERE / "tasks.json"
ledger = json.loads(path.read_text(encoding="utf-8"))
row = next(r for r in ledger["tasks"] if r["id"] == "U01-JOB-CLI-WINDOW-R20")
assert row["agent_task_id"] == "/root/astra_job_cli_sql_r20" and row["consecutive_failed_actual_deliveries"] == 1
row.update(status="native_frozen_delivery_final_bytes_full_independent_acceptance_pending", producer_status="completed", worker_finished_at="2026-10-15T22:40:37+08:00", artifact_available=True, delivery_evidence=".coordination/20261014/workspaces/job-cli-window-r20/DELIVERY.md", producer_evidence=".coordination/20261014/workspaces/job-cli-window-r20/artifacts/astra-r20/evidence.json", delivered_hashes=expected, final_byte_self_pytest_passed=False, self_pytest_scope="525 passed/zero skipped on pre-Optional-annotation bytes 04cc0753; final-byte mypy/compileall/Black passed. Coordinator full final-byte pytest pending", checked_at=at)
ledger["updated_at"] = at
path.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"at": at, "task_id": row["agent_task_id"], "stopped_at": row["worker_finished_at"], "independent_acceptance": False, "integrated": False}), flush=True)
