"""Accept the read-only audit artifact, not product or real-project validation."""
from pathlib import Path
import datetime as dt
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
out = ROOT / "artifacts/astra-ux-remaining-audit-r21-20261015"
audit = json.loads((out / "audit.json").read_text(encoding="utf-8"))
assert audit["status"] == "audit_complete_stopped_writing" and not audit["input_drift"]
assert len(audit["source_hashes"]) == 15 and len(audit["findings"]) == 2
assert all(r["observed_sha256"] == r["end_sha256"] == hashlib.sha256((ROOT / r["path"]).read_bytes()).hexdigest() for r in audit["source_hashes"])
assert hashlib.sha256((out / "DELIVERY.md").read_bytes()).hexdigest() == "451dc316538c122925280e3779938556a5b3c385abc49089025eca6eea1f7e30"
assert hashlib.sha256((out / "audit.json").read_bytes()).hexdigest() == "4ac47846bb5f41dc954d31434c594af52ffbd0f1d7149d006346a7b5a3bdbf9b"
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
path = HERE / "tasks.json"
ledger = json.loads(path.read_text(encoding="utf-8"))
row = next(r for r in ledger["tasks"] if r["id"] == "ASTRA-UX-REMAINING-AUDIT-R21")
row.update(status="readonly_audit_completed_artifact_and_static_review_confirmed", producer_status="completed", worker_finished_at=audit["finished_at"], artifact_available=True, delivery_evidence=(out / "DELIVERY.md").relative_to(ROOT).as_posix(), audit_evidence=(out / "audit.json").relative_to(ROOT).as_posix(), independent_static_review=True, independent_acceptance=False, integrated=False, product_changed=False, findings=["R21-F01", "R21-F02"], next_contract="NEXT_UI_CONTRACT_R21.md", checked_at=at)
ledger["updated_at"] = at
path.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
note = f"## {at} · R21 read-only UI audit completed, two findings confirmed\n\nLogical ASTRA-UX-REMAINING-AUDIT-R21, native /root/astra_instance_ui_r18, actual22:48:34–22:52:34.210394+08. Artifacts/astra-ux-remaining-audit-r21-20261015/DELIVERY.md and audit.json frozen,15 source SHAs stable; coordinator independently checked HTML stop/config wording and acceptance._coverage_gaps false→unwired mapping. Existing R18 native HTTP receipt scheduled2/analyzed2/identity complete/scan incomplete contradicts the unconditional unwired explanation. These are two P2 source/UX defects, no new test/scan/product change or product acceptance. Existing counters/unknown/report binding and declared-only fields/multi-target guard are not new defects. Next exclusive ownership and positive/negative acceptance recorded NEXT_UI_CONTRACT_R21.md; implementation dispatch waits current Root R20 full joint. This passing future selected union will not close these separate remediation items or whole packages.\n\n---\n\n"
for filename in ("DAG.md", "PROGRESS.md", "CURRENT_STATE_R20.md"):
    path = HERE / filename
    path.write_text(note + path.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
print(json.dumps({"at": at, "findings": 2, "product_changed": False, "artifact_review_confirmed": True, "product_acceptance": False}), flush=True)
