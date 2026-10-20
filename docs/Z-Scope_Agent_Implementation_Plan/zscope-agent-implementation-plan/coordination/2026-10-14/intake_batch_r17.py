"""Guarded batch intake of independently accepted descendants and shared API.

Run only after the current contract/checkpoint producers stop and their full
independent collections pass. This script never launches tests or workers.
"""
from pathlib import Path
import datetime as dt
import hashlib
import json
import subprocess
import sys
from audit_followup_r12 import ROOT, HERE

assert sys.platform == "linux"
contract_label, checkpoint_label = sys.argv[1:3]
def read(path):
    return json.loads(path.read_text(encoding="utf-8"))
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
root_proof = read(ROOT / "artifacts/coordinator-r16-astra-projection-intaken-20261015/source-evidence.json")
assert all(sha(ROOT / p) == digest for p, digest in root_proof["after"].items())
ledger_path = HERE / "tasks.json"
ledger = read(ledger_path)
rows = {row["id"]: row for row in ledger["tasks"]}
proofs = {
    "main": read(ROOT / "artifacts/coordinator-scan-session-r12-r3-acceptance-20261015/review.json"),
    "contract": read(ROOT / "artifacts" / contract_label / "review.json"),
    "checkpoint": read(ROOT / "artifacts" / checkpoint_label / "review.json"),
}
assert proofs["main"]["junit"]["tests"] == "423"
for kind, proof in proofs.items():
    assert proof["independent_acceptance_passed"] and proof["source_unchanged"]
    assert len(proof["commands"]) == 4 and all(command["returncode"] == 0 for command in proof["commands"])
    assert all(proof["junit"][key] == "0" for key in ("failures", "errors", "skipped"))
    assert proof["before_all_inputs"] == proof["after_all_inputs"]
    workspace = {"main": "scan-session-r12", "contract": "contract-validation-r12", "checkpoint": "scan-checkpoint-r17"}[kind]
    if kind=="checkpoint":workspace=rows["SCAN-CHECKPOINT-R17"]["workspace"]
    producer = ROOT / ".coordination/20261014/workspaces" / workspace
    assert all(sha(producer / p) == digest for p, digest in proof["after_all_inputs"].items())
    processes = json.loads(subprocess.check_output([sys.executable, str(HERE / "inspect_workspace_processes.py"), workspace], text=True))
    assert not processes["processes"]
    if kind != "main":
        identity = "CONTRACT-VALIDATION-R12" if kind == "contract" else "SCAN-CHECKPOINT-R17"
        label = "zcode" if kind == "contract" else "checkpoint"
        public = read(max((HERE / "route-check").glob("bridge-response-r12-current-" + label + "-*.json"), key=lambda p: p.stat().st_mtime_ns))
        assert public["task_id"] == proof["task_id"] == rows[identity]["bridge_task_id"] and public["status"] == "completed"
        assert public["observed_model"] == rows[identity]["accepted_model"]
api = read(ROOT / "artifacts/coordinator-bound-events-r17-same-bytes-20261015/review.json")
assert api["coordinator_validation_passed"] and api["source_unchanged"] and api["before"] == api["after"]
assert not api["independent_worker_acceptance"] and api["junit"]["tests"] == "195"
assert len(api["commands"]) == 4 and all(row["returncode"] == 0 for row in api["commands"])
assert all(api["junit"][key] == "0" for key in ("failures", "errors", "skipped"))
sources = {}
owners = {}
for kind in ("main", "checkpoint", "contract"):
    proof = proofs[kind]
    snapshot = Path(proof["source_snapshot"])
    for name, digest in proof["delivered_hashes"].items():
        assert sha(snapshot / name) == digest
        if name in sources:
            assert kind == "checkpoint" and owners[name] == "main"
        sources[name] = (snapshot / name, digest)
        owners[name] = kind
checkpoint_baseline = read(HERE / "followups-r12" / (rows["SCAN-CHECKPOINT-R17"]["workspace"] + "-baseline.json"))
inherited = {row["path"]: row["sha256"] for row in checkpoint_baseline["files"]}
inherited.update(checkpoint_baseline.get("ancestor_main_files",{}))
assert all(inherited[p] == digest for p, digest in proofs["main"]["delivered_hashes"].items())
for name in ("zscope/orchestration/jobs/store.py", "tests/test_job_bound_completion.py"):
    assert name not in sources
    producer = ROOT / ".coordination/20261014/workspaces/coordinator-bound-events-r17"
    digest = api["after"][name]
    assert sha(producer / name) == digest
    sources[name] = (producer / name, digest);owners[name] = "coordinator_api"
name = "tests/test_scan_session_resume_svf.py"
producer = ROOT / ".coordination/20261014/workspaces/scan-session-r12"
digest = proofs["main"]["after_all_inputs"][name]
assert sha(producer / name) == digest
sources[name] = (producer / name, digest);owners[name] = "coordinator_main_test_migration"
for dependency in read(HERE / "followups-r12/contract-test-migration-ready-r17.json")["files"]:
    name = dependency["path"]
    assert name not in sources and proofs["contract"]["after_all_inputs"][name] == dependency["sha256"]
    producer = ROOT / ".coordination/20261014/workspaces/contract-validation-r12"
    sources[name] = (producer / name, dependency["sha256"]);owners[name] = "coordinator_contract_test_migration_validated_by_final_independent_collection"
notes = read(HERE / "staged-module-updates-r17.json")["updates"]
for name, item in notes.items():
    assert sha(ROOT / name) == item["before_sha256"] == root_proof["after"][name]
for name, (_, digest) in sources.items():
    assert sha(ROOT / name) == root_proof["after"].get(name), (name, "root changed since R16")
out = ROOT / "artifacts/intake-batch-r17-20261015"
out.mkdir(exist_ok=False)
for name in set(sources) | set(notes):
    if (ROOT / name).is_file():
        backup = out / "root-before" / name;backup.parent.mkdir(parents=True, exist_ok=True);backup.write_bytes((ROOT / name).read_bytes())
at = dt.datetime.now(dt.timezone.utc).isoformat()
assert not any(row["id"] == "CURRENT-JOINT-R17" for row in ledger["tasks"])
joint = {"id": "CURRENT-JOINT-R17", "owner": "coordinator", "depends_on": ["CURRENT-JOINT-R16", "SCAN-SESSION-R12", "CONTRACT-VALIDATION-R12", "SCAN-CHECKPOINT-R17", "COORD-BOUND-EVENTS-R17"], "status": "batch_intake_in_progress_joint_pending", "packages": ["S01", "S08", "U01", "U02"], "whole_package_complete": False}
ledger["tasks"].append(joint)
ledger["current_accepted_stage"].update(is_current_root=False, current_root_status="R17 accepted batch intake; R16 is historical until fresh current-root joint")
ledger_path.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
copied = []
for name, (source, digest) in sources.items():
    target = ROOT / name;target.parent.mkdir(parents=True, exist_ok=True);target.write_bytes(source.read_bytes());assert sha(target) == digest
    copied.append({"path": name, "before": root_proof["after"].get(name), "after": digest, "owner": owners[name]})
for name, item in notes.items():
    (ROOT / name).write_text(item["contents"], encoding="utf-8", newline="\n");assert sha(ROOT / name) == item["after_sha256"]
    copied.append({"path": name, "before": item["before_sha256"], "after": item["after_sha256"], "owner": "coordinator_modules"})
receipt = {"started_at": at, "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(), "files": copied, "accepted_contract": contract_label, "accepted_checkpoint": checkpoint_label, "accepted_main": "coordinator-scan-session-r12-r3-acceptance-20261015", "main_inherited_via_checkpoint": True, "api_coordinator_authored": True, "joint_verification_passed": False, "whole_package_complete": False}
(out / "receipt.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
for identity in ("SCAN-SESSION-R12", "CONTRACT-VALIDATION-R12", "SCAN-CHECKPOINT-R17", "COORD-BOUND-EVENTS-R17"):
    rows[identity].update(integrated=True, joint_verification=False, intake_evidence="artifacts/intake-batch-r17-20261015/receipt.json", status="accepted_intaken_current_joint_pending_bounded_slice", whole_package_complete=False)
    if identity!="COORD-BOUND-EVENTS-R17":rows[identity]["independent_acceptance"]=True
joint["status"] = "intaken_current_root_joint_pending";joint["evidence"] = "artifacts/coordinator-r17-batch-intaken-20261015"
ledger["updated_at"] = receipt["finished_at"]
remaining = {row["id"] for row in ledger["tasks"]};done = set();layers = []
while remaining:
    ready = [row["id"] for row in ledger["tasks"] if row["id"] in remaining and set(row.get("depends_on", [])) <= done]
    assert ready, "dependency cycle"
    layers.append(ready);remaining.difference_update(ready);done.update(ready)
ledger["topological_layers"] = layers
ledger_path.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
continuation = read(HERE / "continuation-r6.json")
continuation.update(updated_at=receipt["finished_at"], current_root_status="R17 batch intaken/current joint pending; R16 pass historical", prior_pass_is_current_root=False, latest_joint_attempt="artifacts/coordinator-r17-batch-intaken-20261015", latest_joint_attempt_passed=False, whole_packages_complete=False)
(HERE / "continuation-r6.json").write_text(json.dumps(continuation, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
note = f"## {receipt['finished_at']} · R17 accepted batch intaken; current joint pending\n\nRoot changed after all independent gates. Intake receipt artifacts/intake-batch-r17-20261015/receipt.json records actual files, before/after hashes and backups. Main R3 is inherited through the independently accepted checkpoint descendant; contract, shared API, coordinator readonly test migrations and module notes are included. R16 1207 is now historical. Fresh R17 full collection/six quality commands/Astra browser checks are required; no whole-package or real-project claim.\n\n---\n\n"
for name in ("PROGRESS.md", "DAG.md"):
    path = HERE / name;path.write_text(note + path.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
print(json.dumps({"receipt": str(out / "receipt.json"), "files": len(copied), "current_joint_pending": True}))
