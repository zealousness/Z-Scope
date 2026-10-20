"""Guard the accepted UI/doc intake behind a passed current R17 root joint."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import subprocess
import sys
from audit_followup_r12 import ROOT, HERE

assert sys.platform == "linux"
def read(path):
    return json.loads(path.read_text(encoding="utf-8"))
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
root_out = ROOT / "artifacts/coordinator-r17-fixture-repaired-20261015"
root = read(root_out / "source-evidence.json")
verified = read(root_out / "review.json")
assert verified["is_current_root"] and verified["current_bytes_match"]
assert len(root["commands"]) == 6 and all(r["returncode"] == 0 for r in root["commands"])
assert root["direct_source_unchanged"] and root["native_before"] == root["native_after"]
assert all(sha(ROOT / p) == h for p, h in root["after"].items())
sources = {}
for workspace, label, identity in (("astra-instance-ui-r18", "coordinator-astra-instance-r18-acceptance-20261015", "ASTRA-INSTANCE-UI-R18"), ("doc-identity-r18", "coordinator-dsh-doc-r18-acceptance-20261015", "DOC-IDENTITY-R18")):
    proof = read(ROOT / "artifacts" / label / "review.json")
    assert proof["independent_acceptance_passed"] and proof["source_unchanged"]
    assert all(r["returncode"] == 0 for r in proof["commands"])
    assert all(proof["junit"][k] == "0" for k in ("failures", "errors", "skipped"))
    branch = ROOT / ".coordination/20261014/workspaces" / workspace
    assert all(sha(branch / p) == h for p, h in proof["after_all_inputs"].items())
    assert not json.loads(subprocess.check_output([sys.executable, str(HERE / "inspect_workspace_processes.py"), workspace], text=True))["processes"]
    for p, h in proof["delivered_hashes"].items():
        assert p not in sources and sha(Path(proof["source_snapshot"]) / p) == h
        sources[p] = (Path(proof["source_snapshot"]) / p, h, identity)
light = read(ROOT / "artifacts/coordinator-lightweight-r18-20261015/review.json")
assert light["coordinator_validation_passed"] and light["source_unchanged"]
assert light["junit"]["tests"] == "77" and all(light["junit"][k] == "0" for k in ("failures", "errors", "skipped"))
assert len(light["commands"]) == 4 and all(r["returncode"] == 0 for r in light["commands"])
branch = ROOT / ".coordination/20261014/workspaces/coordinator-lightweight-r18"
assert all(sha(branch / p) == h for p, h in light["after"].items())
for p in light["owned"]:
    assert p not in sources
    sources[p] = (branch / p, light["after"][p], "coordinator_lightweight")
staged = read(HERE / "staged-ui-doc-r18.json")
assert not staged["new_literal_classes"] and not staged["vendor_or_css_changed"]
for p, item in staged["updates"].items():
    assert sha(ROOT / p) == item["before_sha256"] == root["after"][p]
for p in sources:
    assert sha(ROOT / p) == root["after"].get(p), (p, "current root changed")
out = ROOT / "artifacts/intake-ui-doc-r18-20261015"
out.mkdir(exist_ok=False)
for p in set(sources) | set(staged["updates"]):
    if (ROOT / p).is_file():
        target = out / "root-before" / p
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / p).read_bytes())
ledger_path = HERE / "tasks.json"
ledger = read(ledger_path)
assert not any(r["id"] == "CURRENT-JOINT-R18" for r in ledger["tasks"])
at = dt.datetime.now(dt.timezone.utc).isoformat()
ledger["current_accepted_stage"].update(is_current_root=False, current_root_status="R18 accepted UI/doc batch intake; fresh full current-root joint pending")
ledger_path.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
files = []
for p, (source, h, owner) in sources.items():
    target = ROOT / p
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(source.read_bytes())
    assert sha(target) == h
    files.append({"path": p, "before": root["after"].get(p), "after": h, "owner": owner})
for p, item in staged["updates"].items():
    (ROOT / p).write_text(item["contents"], encoding="utf-8", newline="\n")
    assert sha(ROOT / p) == item["after_sha256"]
    files.append({"path": p, "before": item["before_sha256"], "after": item["after_sha256"], "owner": "coordinator_metadata_or_module"})
receipt = {"started_at": at, "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(), "files": files, "previous_root_joint": str(root_out.relative_to(ROOT)), "astra_independent": "artifacts/coordinator-astra-instance-r18-acceptance-20261015/review.json", "dsh_independent": "artifacts/coordinator-dsh-doc-r18-acceptance-20261015/review.json", "lightweight_coordinator_validation": "artifacts/coordinator-lightweight-r18-20261015/review.json", "joint_verification_passed": False, "whole_package_complete": False, "static_lock_delta": ["index.html", "dashboard_workbench.js"], "new_tailwind_classes": False}
(out / "receipt.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
for r in ledger["tasks"]:
    if r["id"] in {"ASTRA-INSTANCE-UI-R18", "DOC-IDENTITY-R18"}:
        r.update(status="independent_accepted_intaken_joint_pending", integrated=True, joint_verification=False, intake_evidence="artifacts/intake-ui-doc-r18-20261015/receipt.json", whole_package_complete=False)
ledger["tasks"].append({"id": "CURRENT-JOINT-R18", "owner": "coordinator", "depends_on": ["CURRENT-JOINT-R17", "ASTRA-INSTANCE-UI-R18", "DOC-IDENTITY-R18"], "status": "intaken_current_root_joint_pending", "evidence": "artifacts/coordinator-r18-ui-doc-intaken-20261015", "whole_package_complete": False})
ledger["updated_at"] = receipt["finished_at"]
remaining = {r["id"] for r in ledger["tasks"]}
done = set()
layers = []
while remaining:
    ready = [r["id"] for r in ledger["tasks"] if r["id"] in remaining and set(r.get("depends_on", [])) <= done]
    assert ready
    layers.append(ready)
    remaining.difference_update(ready)
    done.update(ready)
ledger["topological_layers"] = layers
ledger_path.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
continuation_path = HERE / "continuation-r6.json"
continuation = read(continuation_path)
continuation.update(updated_at=receipt["finished_at"], current_root_status="R18 accepted UI/doc batch intaken; fresh full joint pending", prior_pass_is_current_root=False, latest_joint_attempt="artifacts/coordinator-r18-ui-doc-intaken-20261015", latest_joint_attempt_passed=False, whole_packages_complete=False)
continuation_path.write_text(json.dumps(continuation, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
note = f"## {receipt['finished_at']} · R18 accepted UI/doc batch intaken; current joint pending\n\n10 accepted files and metadata/module updates intaken, receipt artifacts/intake-ui-doc-r18-20261015/receipt.json. R17 repaired pass is historical after this intake. New current-root full collection, native browser chain and six quality commands required. ZCode inner context/stop-at work remains isolated and unaccepted. No whole-package/real-project/formal/portable claim.\n\n---\n\n"
for filename in ("PROGRESS.md", "DAG.md"):
    path = HERE / filename
    path.write_text(note + path.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
print(json.dumps({"files": len(files), "receipt": str(out / "receipt.json"), "fresh_joint_required": True}))
