"""Prepare coordinator-only integration, leaving accepted Root untouched."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]

def read(p):
    return json.loads(p.read_text(encoding="utf-8"))

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def write(p, value):
    p.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

source = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
assert all(sha(ROOT / p) == h for p, h in source.items())
contract_path = ROOT / "artifacts/design-contract-r23-20261016/contracts.json"
contract = read(contract_path)
source = dict(source)
for directory in ("design-contract-r23-20261016", "design-contract-independent-review-r23-20261016"):
    for name in (("contracts.json", "DELIVERY.md") if directory.startswith("design-contract-r23-") else ("review.json", "DELIVERY.md")):
        path = "artifacts/" + directory + "/" + name
        source[path] = sha(ROOT / path)
assert len(source) == 1069
name = "coordinator-instance-integration-r24"
branch = ROOT / ".coordination/20261014/workspaces" / name
branch.mkdir(exist_ok=False)
for path, expected in sorted(source.items()):
    target = branch / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes((ROOT / path).read_bytes())
    assert sha(target) == expected
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
task = {"id": "COORD-INSTANCE-INTEGRATION-R24", "workspace": name, "owner": "coordinator", "owns": contract["ownership"]["coordinator_exclusive_paths"], "write_paths": contract["ownership"]["coordinator_exclusive_paths"], "depends_on": ["CURRENT-JOINT-R23", "S01-INSTANCE-SEMANTICS-MIN-R23", "S08-INSTANCE-RECOVERY-MIN-R23"], "status": "isolated_shared_wiring_preparation_modules_in_flight", "root_product_write_permission": False, "artifact_available": False, "independent_acceptance": False, "integrated": False, "joint_verification": False, "whole_package_complete": False, "checked_at": at}
write(HERE / "followups-r12" / (name + "-baseline.json"), {"captured_at": at, "task": task, "files": [{"path": p, "sha256": h} for p, h in sorted(source.items())], "contract_sha256": sha(contract_path), "root_current_joint": "artifacts/coordinator-r23-ui-projection-union-20261016/review.json"})
extension = {"coordinator_authorized": True, "at": at, "write_paths": ["zscope/orchestration/instance_semantics_context.py", "tests/test_instance_semantics_context.py"], "reason": "Coordinator-only workbook/dependency/snapshot-manifest glue reused by ScanSession and ParallelAnalyzer; no worker grant, no inferred authority or contract version change"}
write(HERE / "followups-r12" / (name + "-ownership-extension-01.json"), extension)
ledger = read(HERE / "tasks.json")
assert not any(r["id"] == task["id"] for r in ledger["tasks"])
ledger["tasks"].append(task)
ledger["updated_at"] = at
write(HERE / "tasks.json", ledger)
print(json.dumps({"at": at, "workspace": name, "inputs": len(source), "shared_writer": "coordinator only", "Root_product_changed": False, "new_module_dependencies": "in flight, not copied or accepted"}), flush=True)
