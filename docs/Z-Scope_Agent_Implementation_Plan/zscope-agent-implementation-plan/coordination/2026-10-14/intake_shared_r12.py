"""Intake only the four stable coordinator-owned accounting files and refresh Astra."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
follow = HERE / "followups-r12"
accepted = ROOT / "artifacts/coordinator-shared-r12-acceptance-20261015"
review = json.loads((accepted / "review.json").read_text(encoding="utf-8"))
assert review["passed"] and review["source_unchanged"] and review["junit"]["tests"] == "190"
baseline = json.loads((follow / "coordinator-shared-baseline.json").read_text(encoding="utf-8"))
files = review["changed_files"]
assert set(files) == {"zscope/orchestration/jobs/owner.py", "zscope/orchestration/jobs/work_queue.py", "tests/test_scan_job_execution.py", "tests/test_job_remaining.py"}
out = ROOT / "artifacts/intake-coordinator-remaining-r12-20261015"
out.mkdir(exist_ok=False)
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
for name, sha in files.items():
    target = ROOT / name
    actual = hashlib.sha256(target.read_bytes()).hexdigest() if target.exists() else None
    assert actual == baseline["files"].get(name), (name, actual)
    frozen = accepted / "source-before" / name
    assert hashlib.sha256(frozen.read_bytes()).hexdigest() == sha
    if target.exists():
        backup = out / "before" / name
        backup.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(target, backup)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(frozen, target)
receipt = {"at":at,"files":files,"validation":"artifacts/coordinator-shared-r12-acceptance-20261015/review.json","coordinator_authored_and_validated":True,"independent_worker_acceptance":False,"integrated":True,"joint_verification":False,"prior_joint_now_historical":"artifacts/coordinator-r11-all-intaken-20261015/review.json","whole_package_complete":False}
(out / "receipt.json").write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
# Astra confirmed no running service/check before this refresh. Only backend
# readonly inputs change; no edit to its three owned UI paths or initial baseline.
astra = ROOT / ".coordination/20261014/workspaces/astra-queue-ux-r12"
dependencies = []
for name in ("zscope/orchestration/jobs/owner.py", "zscope/orchestration/jobs/work_queue.py", "tests/test_scan_job_execution.py"):
    target = astra / name
    old = hashlib.sha256(target.read_bytes()).hexdigest()
    assert old == baseline["files"][name]
    shutil.copyfile(accepted / "source-before" / name, target)
    dependencies.append({"path":name,"before":old,"after":files[name]})
refresh = {"at":at,"workspace":str(astra),"files":dependencies,"source_review":receipt["validation"],"changes_owned_by":"coordinator","worker_baseline_preserved":True,"active_check_at_refresh":False}
(follow / "astra-readonly-dependencies.json").write_text(json.dumps(refresh,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
ledger_path = HERE / "tasks.json"
ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
ledger["tasks"].append({"id":"COORD-REMAINING-R12","title":"Measured remaining and truthful terminal accounting","packages":["S08","U01"],"owner":"coordinator","depends_on":["CURRENT-JOINT-R11"],"status":"coordinator_validated_integrated_joint_pending","write_paths":list(files),"validation":receipt["validation"],"coordinator_validation_passed":True,"independent_acceptance":None,"integrated":True,"integrated_at":at,"joint_verification":False,"whole_package_complete":False,"intake_evidence":str((out / "receipt.json").relative_to(ROOT)).replace("\\","/")})
ledger["current_accepted_stage"]["current_root_status"] = "R12 accounting intaken; current joint pending; R11 receipt is historical"
ledger["updated_at"] = at
left, done, layers = {r["id"] for r in ledger["tasks"]}, set(), []
while left:
    ready = [r["id"] for r in ledger["tasks"] if r["id"] in left and set(r["depends_on"]) <= done]
    assert ready
    layers.append(ready); left.difference_update(ready); done.update(ready)
ledger["topological_layers"] = layers
ledger_path.write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
note = f"""## {at} · R12 measured remaining intaken, current joint pending

- Coordinator-authored owner/work_queue accounting plus two test files passed190/0fail/error/skip and compileall/mypy353/Black at02:18:18. Input hashes stable. Frozen validation artifacts/coordinator-shared-r12-acceptance-20261015/review.json; four-file intake artifacts/intake-coordinator-remaining-r12-20261015/receipt.json. This is coordinator validation, not an independent worker-delivery claim.
- Owner now reads read-only SQL counts for exact job/input; business question count is separate, missing/foreign/corrupt queue remains unknown. Remaining or failed measured work prevents completed even with scanner exit0. Existing actual cooperative owner test confirms pending survives finalization with no watchdog kill. Controlled work/report inputs, not actual scan-effect acceptance.
- Root bytes changed: old1123 R11 receipt is historical until new same-byte joint passes. Kimi task_1cee9c8e9d and ZCode task_315195c1a1 still running in disjoint copies. Astra readonly owner/work_queue/execution-test refreshed only after checks stopped, exact SHA receipt followups-r12/astra-readonly-dependencies.json; original baseline preserved.
- Two actual-native validation-thread probes fail on pre-R12 root, proving preparation inherited outer build and validator threads had empty build under both executor/ScanScheduler. Full ScanSession probes also reproduce global semantic call in ordinary/resume paths. These are remaining integration regressions, not tests removed from acceptance.

---

"""
for name in ("PROGRESS.md", "DAG.md"):
    target = HERE / name
    target.write_text(note + target.read_text(encoding="utf-8"),encoding="utf-8",newline="\n")
print(json.dumps({"intake":str(out / "receipt.json"),"astra_refresh":str(follow / "astra-readonly-dependencies.json"),"files":files},ensure_ascii=False))
