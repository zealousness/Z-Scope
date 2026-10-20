"""Freeze disjoint cancellation work without importing the active CLI branch."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
base = json.loads((ROOT / "artifacts/coordinator-r19-all-intaken-20261015/source-evidence.json").read_text(encoding="utf-8"))["after"]
assert all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == h for p, h in base.items())
name = "astra-first-cause-r20"
workspace = ROOT / ".coordination/20261014/workspaces" / name
workspace.mkdir(exist_ok=True)
for p, sha in base.items():
    target = workspace / p
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        assert hashlib.sha256(target.read_bytes()).hexdigest() == sha
    else:
        shutil.copyfile(ROOT / p, target)
    assert hashlib.sha256(target.read_bytes()).hexdigest() == sha
task = {"id": "U01-FIRST-CAUSE-R20", "workspace": name, "owner": "Astra", "agent_kind": "native_subagent", "requested_model": "gpt-6-astra", "reasoning_effort": "xhigh", "write_paths": ["zscope/common/cancellation.py", "tests/test_cancellation_first_cause.py"], "owns": ["zscope/common/cancellation.py", "tests/test_cancellation_first_cause.py"], "depends_on": ["U01-STOP-AT-R18"], "parent_work_item": "U01-STOP-AT-R18", "isolated_workspace": str(workspace), "isolated_workspace_linux": "/mnt/c/Users/10273/home/work/Z-Scope_1.31/Z-Scope/.coordination/20261014/workspaces/" + name, "status": "prepared_not_dispatched", "independent_acceptance": False, "integrated": False, "joint_verification": False, "whole_package_complete": False, "glm_delivery_rounds": [], "routing_reason": "User-authorized complex concurrency work may use Astra xhigh; no platform block, no reset or redo of accepted parent3 slices"}
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
baseline = {"captured_at": at, "task": task, "files": [{"path": p, "sha256": h} for p, h in sorted(base.items())], "root_changed": False, "scope": "Exact accepted Root R19; no active GLM CLI overlay; only token plus new tests owned"}
(HERE / "followups-r12" / (name + "-baseline.json")).write_text(json.dumps(baseline, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
path = HERE / "tasks.json"
ledger = json.loads(path.read_text(encoding="utf-8"))
assert not any(r["id"] == task["id"] for r in ledger["tasks"])
ledger["tasks"].append({**task, "baseline_receipt": "followups-r12/" + name + "-baseline.json", "checked_at": at})
next(r for r in ledger["tasks"] if r["id"] == "CURRENT-JOINT-R20")["depends_on"].append(task["id"])
ledger["updated_at"] = at
path.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"workspace": str(workspace), "inputs": len(base), "at": at}), flush=True)
