"""Intake independently accepted worker-plus-coordinator bytes and mark root pending."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
out = ROOT / "artifacts/coordinator-s01-r4-final-acceptance-20261014"
receipt_path = out / "review.json"
receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
assert receipt["independent_acceptance_passed"] and receipt["source_unchanged"]
receipt.update(source_snapshot=str((out / "source-before").resolve()),
               worker_status="cancelled",worker_finished_at="2026-10-14T22:48:19.038170+08:00",
               accepted_version="Kimi R4 stopped bytes plus coordinator context isolation repair",
               coordinator_repair="artifacts/coordinator-s01-context-repair-r9-20261014/repair.json",
               accepted_model="volceapi/kimi-k3",observed_model=None)
receipt_path.write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
repair_path = ROOT / receipt["coordinator_repair"]
repair = json.loads(repair_path.read_text(encoding="utf-8"))
repair.update(independent_acceptance=True, acceptance_evidence=str(receipt_path.relative_to(ROOT)),
              tested_hashes=receipt["after_hashes"],
              worker_late_change="Worker cleared callees before stop; coordinator forced include_context=False, cleared comments, kept one native owner guard, and added non-mutating cache regression.")
repair_path.write_text(json.dumps(repair,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
subprocess.run([sys.executable,str(HERE/"intake_followup_r6.py"),"s01-analysis-r6",str(receipt_path),
                str(ROOT/"artifacts/intake-s01-r4-r9-20261014")],check=True)
at = dt.datetime.now(dt.timezone.utc).isoformat()
ledger_path = HERE / "tasks.json"
ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
row = next(row for row in ledger["tasks"] if row["id"] == "S01-INST-EXEC")
row.update(status="independent_passed_integrated_current_joint_pending",worker_status="cancelled",
           independent_acceptance=True,integrated=True,joint_verification=False,checked_at=at,
           acceptance_evidence=str(receipt_path.relative_to(ROOT)),
           intake_evidence="artifacts/intake-s01-r4-r9-20261014/receipt.json",whole_package_complete=False)
ledger["current_accepted_stage"]["current_root_status"] = "S01 newly intaken; full joint pending; preceding 686 is historical before this intake"
ledger_path.write_text(json.dumps(ledger,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
stage_path = HERE / "continuation-r6.json"
stage = json.loads(stage_path.read_text(encoding="utf-8"))
stage.update(updated_at=at,current_joint_status="s01_newly_intaken_full_joint_pending",
             current_joint="artifacts/coordinator-r9-s01-s08-intaken-20261014")
stage_path.write_text(json.dumps(stage,ensure_ascii=False,indent=2)+"\n",encoding="utf-8",newline="\n")
