"""Freeze a fresh disjoint current-root replay repair workspace and actual metrics."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import re
import shutil
import sys

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
evidence = ROOT / "artifacts/coordinator-current-native-replay-r19-20261015"
review = json.loads((evidence / "review.json").read_text(encoding="utf-8"))
assert review["source_unchanged"] and review["junit"]["failures"] == "1" and review["junit"]["skipped"] == "0"
temporary = Path(re.search(r"temp=(\S+)", (evidence / "command-0.log").read_text(encoding="utf-8"))[1])
report_path = next(temporary.glob("pytest-of-*/pytest-0/test_real_mutation_replay0/real replay/report.json"))
report = json.loads(report_path.read_text(encoding="utf-8"))
assert report["complete"] and report["unexplained_semantic_differences"] == 0
(evidence / "actual-native-report.json").write_bytes(report_path.read_bytes())
metrics = {"original_report": str(report_path), "report_sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(), "mutations": [{"mutation": r["mutation"], "status": r["status"], "stages": {k: {p: v.get(p) for p in ("rebuilt_tus", "reused_tus", "failed_tus", "compilation_instances_complete", "projection_complete")} for k, v in r["stages"].items()}} for r in report["mutations"]]}
(evidence / "native-metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8", newline="\n")
source = json.loads((ROOT / "artifacts/coordinator-r18-queue-receipt-repaired-20261015/source-evidence.json").read_text(encoding="utf-8"))["after"]
assert all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == sha for p, sha in source.items())
name = "native-hot-cache-r19"
workspace = ROOT / ".coordination/20261014/workspaces" / name
workspace.mkdir(exist_ok=False)
for p, sha in source.items():
    target = workspace / p
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / p, target)
    assert hashlib.sha256(target.read_bytes()).hexdigest() == sha
assert (workspace / "tests/test_incremental_replay.py").is_file()
owns = ["zscope/retrieval/clang_batch.py", "zscope/retrieval/incremental_replay.py", "tests/test_native_replay_hot_cache.py"]
task = {"id": "S07-NATIVE-HOT-R19", "workspace": name, "owner": "zcode", "owns": owns, "write_paths": owns, "depends_on": ["S01-SYMBOL", "S07-ORACLE"], "session_id": "sess_3b6b9a19b2", "model": "97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3", "isolated_workspace_linux": str(workspace)}
proof = {"captured_at": dt.datetime.now(dt.timezone.utc).isoformat(), "task": task, "files": [{"path": p, "sha256": sha} for p, sha in sorted(source.items())], "root_changed": False, "interface_contracts": "Exact current R18 root; full selected joint failed only on clock-sensitive deadline. Actual native replay failure independently reproduced; no unaccepted context/stop code overlaid."}
(HERE / "followups-r12" / (name + "-baseline.json")).write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8", newline="\n")
path = HERE / "tasks.json"
ledger = json.loads(path.read_text(encoding="utf-8"))
assert not any(r["id"] == task["id"] for r in ledger["tasks"])
assert set(task["depends_on"]) <= {r["id"] for r in ledger["tasks"]}
ledger["tasks"].append({**task, "status": "prepared_current_native_failure_not_dispatched", "agent_kind": "agent_bridge", "requested_model": task["model"], "baseline_receipt": "followups-r12/" + name + "-baseline.json", "independent_acceptance": False, "integrated": False, "joint_verification": False, "whole_package_complete": False})
ledger["updated_at"] = proof["captured_at"]
path.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
print(json.dumps({"workspace": str(workspace), "inputs": len(source), "metrics": metrics}), flush=True)
