"""Checkpoint owned bytes, then normally cancel only the verified failing S08 turn."""

from pathlib import Path
import datetime as dt
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
state = json.loads((HERE / "bridge-response-s08-before-api-transfer.json").read_text(encoding="utf-8"))
assert state["task_id"] == "task_f2a4721a58"
assert state["status"] == "running", "inspect actual terminal before deciding recovery"
source = ROOT / ".coordination/20261014/workspaces/s08-owner"
names = sorted(p.relative_to(source).as_posix() for p in (source / "zscope/orchestration/jobs").glob("*.py"))
names += ["tests/test_scan_jobs.py", "tests/test_scan_job_execution.py", "DELIVERY.md"]
directory = ROOT / ".coordination/20261014/checkpoints/s08-before-zcode-api-recovery"
directory.mkdir(parents=True)
files = []
for name in names:
    path = source / name
    raw = path.read_bytes()
    target = directory / name
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("xb") as output:
        output.write(raw)
    files.append({"path": name, "sha256": hashlib.sha256(raw).hexdigest(), "mtime_ns": path.stat().st_mtime_ns})
proof = {
    "captured_at": dt.datetime.now(dt.timezone.utc).isoformat(), "task_id": state["task_id"],
    "state_before": state["status"], "checkpoint": str(directory), "files": files,
    "api_failure_metadata": [
        {"at": "2026-10-14T06:41:22.990000+00:00", "errorName": "APIEmptyResponseError", "nextAttempt": 2},
        {"at": "2026-10-14T06:52:50.684000+00:00", "errorName": "APIEmptyResponseError", "nextAttempt": 2},
    ],
    "qualification": "No new APITimeoutError in this repair turn; repeated empty API responses are a distinct ordinary API failure. Existing older timeouts retained, not relabeled.",
    "source": "Readonly native Kimi session_c219a6de wire whitelist: type/time/errorName/attempt/modelAlias only. No bodies, tool arguments, credentials captured.",
    "modelAlias": "volceapi/kimi-k3", "new_zcode_dispatch_allowed_only_after": "exact cancelled/failed/completed task receipt and identical post-stop bytes",
}
with (HERE / "s08-api-failure-checkpoint.json").open("x", encoding="utf-8", newline="\n") as output:
    output.write(json.dumps(proof, ensure_ascii=False, indent=2) + "\n")
request = {"id": "s08-api-failure-stop", "tool": "cancel_task", "arguments": {"task_id": state["task_id"]}}
with (HERE / "bridge-queue/139-s08-api-failure-stop.request.json").open("x", encoding="utf-8", newline="\n") as output:
    output.write(json.dumps(request) + "\n")
print(json.dumps({"checkpoint_files": len(files), "cancel_requested_for": state["task_id"], "new_dispatch": False}))
