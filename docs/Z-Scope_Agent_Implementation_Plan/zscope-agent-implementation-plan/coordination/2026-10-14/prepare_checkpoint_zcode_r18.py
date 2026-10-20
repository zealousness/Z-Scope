"""Preserve the idle Kimi producer and stage its known-failing bytes for ZCode."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil
import sys

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent;ROOT = HERE.parents[4]
proof_path = ROOT / "artifacts/coordinator-checkpoint-r17-fenced-acceptance-20261015/review.json"
proof = json.loads(proof_path.read_text(encoding="utf-8"))
assert proof["independent_acceptance_passed"] and proof["source_unchanged"] and proof["junit"]["tests"] == "433"
producer = ROOT / ".coordination/20261014/workspaces/scan-checkpoint-r17"
workspace_name = "checkpoint-zcode-r18"
workspace = ROOT / ".coordination/20261014/workspaces" / workspace_name
workspace.mkdir(exist_ok=False)
for name, sha in proof["after_all_inputs"].items():
    assert hashlib.sha256((producer / name).read_bytes()).hexdigest() == sha
    target = workspace / name;target.parent.mkdir(parents=True, exist_ok=True);shutil.copyfile(producer / name, target)
    assert hashlib.sha256(target.read_bytes()).hexdigest() == sha
old = json.loads((HERE / "followups-r12/scan-checkpoint-r17-baseline.json").read_text(encoding="utf-8"))
task = dict(old["task"])
task.update(workspace=workspace_name, isolated_workspace="C:\\Users\\10273\\home\\work\\Z-Scope_1.31\\Z-Scope\\.coordination\\20261014\\workspaces\\" + workspace_name, isolated_workspace_linux=str(workspace), owner="zcode", agent="zcode", model="97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3", requested_model="97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3", session_id="sess_3b6b9a19b2", bridge_session_id="sess_3b6b9a19b2")
main = json.loads((ROOT / "artifacts/coordinator-scan-session-r12-r3-acceptance-20261015/review.json").read_text(encoding="utf-8"))
ancestor = {row["path"]: row["sha256"] for row in old["files"]}
assert all(ancestor[p] == sha for p, sha in main["delivered_hashes"].items())
data = {"captured_at": dt.datetime.now(dt.timezone.utc).isoformat(), "task": task, "files": [{"path": name, "sha256": sha} for name, sha in proof["after_all_inputs"].items()], "ancestor_main_files": main["delivered_hashes"], "handover_reason": "Human changed future work assignment to ZCode, retaining Astra UI ownership; not timeout/review circumvention.", "original_kimi_task": "task_b21e0df6a7", "original_kimi_workspace_frozen": str(producer), "bounded_regression_passed": "artifacts/coordinator-checkpoint-r17-fenced-acceptance-20261015/review.json", "known_failed_dependency_boundary": "artifacts/coordinator-checkpoint-r17-dependency-uri-probes-20261015/review.json", "whole_checkpoint_acceptance": False, "root_changed": False}
(HERE / "followups-r12" / (workspace_name + "-baseline.json")).write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"workspace": str(workspace), "inputs": len(data["files"]), "old_kimi_preserved": True, "root_changed": False}))
