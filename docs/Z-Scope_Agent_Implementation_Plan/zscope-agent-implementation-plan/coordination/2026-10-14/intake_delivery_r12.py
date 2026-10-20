"""Controlled R12 delivery intake from independently tested immutable files."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
kind, acceptance_label, intake_label = sys.argv[1:4]
workspace_name, identifier = {
    "astra":("astra-queue-ux-r12", "ASTRA-QUEUE-UX-R12"),
    "astra_r15":("astra-job-projection-r15", "ASTRA-JOB-PROJECTION-R15"),
    "contract":("contract-validation-r12", "CONTRACT-VALIDATION-R12"),
    "main":("scan-session-r12", "SCAN-SESSION-R12"),
    "mcp":("mcp-findings-r12", "MCP-FINDINGS-R12"),
}[kind]
branch = ROOT / ".coordination/20261014/workspaces" / workspace_name
accepted = ROOT / "artifacts" / acceptance_label
proof = json.loads((accepted / "review.json").read_text(encoding="utf-8"))
if (accepted / "visual-review.json").exists():
    assert json.loads((accepted / "visual-review.json").read_text(encoding="utf-8"))["resolved"], "visual review hold remains open"
assert proof["independent_acceptance_passed"] and proof["source_unchanged"]
assert not proof["after_ownership"]["nonowned_changes"]
files = proof["delivered_hashes"]
baseline = json.loads((HERE / "followups-r12" / (workspace_name + "-baseline.json")).read_text(encoding="utf-8"))
original = {row["path"]:row["sha256"] for row in baseline["files"]}
out = ROOT / "artifacts" / intake_label
out.mkdir(exist_ok=False)
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
for name, sha in files.items():
    target = ROOT / name
    current = hashlib.sha256(target.read_bytes()).hexdigest() if target.is_file() else None
    assert current == original.get(name), (name, current, original.get(name))
    assert isinstance(sha, str) and hashlib.sha256((branch / name).read_bytes()).hexdigest() == sha
    frozen = accepted / "source-before" / name
    assert hashlib.sha256(frozen.read_bytes()).hexdigest() == sha
    if target.exists():
        backup = out / "before" / name
        backup.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(target,backup)
    target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(frozen,target)
static_receipt = None
if kind in {"astra","astra_r15"}:
    lock_path = ROOT / "requirements/portable/web-assets.lock.json"
    old = json.loads(lock_path.read_text(encoding="utf-8"))
    new = json.loads(lock_path.read_text(encoding="utf-8"))
    static_names=("index.html", "dashboard_workbench.js") if kind=="astra" else ("dashboard_workbench.js",)
    for name in static_names:
        new["first_party"][name]["sha256"] = files["zscope/web/static/" + name]
    shutil.copyfile(lock_path, out / "web-assets.lock.before.json")
    lock_path.write_text(json.dumps(new,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
    static_receipt = {"at":at,"changed_sha_fields":[f"first_party.{name}.sha256" for name in static_names],"vendor_license_css_unchanged":True,"source_before":old,"source_after":new,"full_verify":False}
    (out / "static-lock-update.json").write_text(json.dumps(static_receipt,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
receipt = {"at":at,"task_id":proof["task_id"],"identifier":identifier,"accepted_files":files,"independent_acceptance":True,"acceptance_evidence":str((accepted / "review.json").relative_to(ROOT)).replace("\\","/"),"integrated":True,"joint_verification":False,"whole_package_complete":False,"scope":proof["scope"]}
(out / "receipt.json").write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
ledger_path = HERE / "tasks.json"
ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
row = next(row for row in ledger["tasks"] if row["id"] == identifier)
row.update(status="independent_passed_integrated_joint_pending",artifact_available=True,independent_acceptance=True,acceptance_evidence=receipt["acceptance_evidence"],independent_result=proof["junit"],integrated=True,integrated_at=at,intake_evidence=str((out / "receipt.json").relative_to(ROOT)).replace("\\","/"),joint_verification=False,whole_package_complete=False,checked_at=at)
ledger["updated_at"] = at
ledger["current_accepted_stage"]["current_root_status"] = "new R12 delivery intaken; joint pending; prior receipt historical"
ledger_path.write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps({"intake":str(out / "receipt.json"),"files":files,"joint_pending":True},ensure_ascii=False))
