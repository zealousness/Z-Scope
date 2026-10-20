"""Publish the completed native delivery and its independent, bounded acceptance."""
from pathlib import Path
import datetime as dt
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
review_path = ROOT / "artifacts/coordinator-first-cause-r20-final-acceptance-20261015/review.json"
review = json.loads(review_path.read_text(encoding="utf-8"))
assert review["independent_acceptance_passed"] and review["source_unchanged"] and review["independent_probes_unchanged"]
assert len(review["commands"]) == 4 and all(r["returncode"] == 0 for r in review["commands"])
assert review["junit"]["tests"] == "397" and all(review["junit"][k] == "0" for k in ("errors", "failures", "skipped"))
assert review["native_before"] == review["native_after"] == "d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399"
branch = ROOT / ".coordination/20261014/workspaces/astra-first-cause-r20"
assert set(review["delivered_hashes"]) == {"zscope/common/cancellation.py", "tests/test_cancellation_first_cause.py"}
assert all(hashlib.sha256((branch / p).read_bytes()).hexdigest() == h for p, h in review["delivered_hashes"].items())
assert hashlib.sha256((branch / "DELIVERY.md").read_bytes()).hexdigest() == "e2365cc7b8dc843704185b2392e51aa5811231c854e834ab80f9965213783f29"
root_before = json.loads((ROOT / "artifacts/coordinator-r19-all-intaken-20261015/source-evidence.json").read_text(encoding="utf-8"))["after"]
assert all(hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == h for p, h in root_before.items())
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
path = HERE / "tasks.json"
ledger = json.loads(path.read_text(encoding="utf-8"))
row = next(r for r in ledger["tasks"] if r["id"] == "U01-FIRST-CAUSE-R20")
assert not row["integrated"]
row.update(status="independently_accepted_frozen_not_intaken", producer_status="completed", worker_finished_at="2026-10-15T22:06:15.213751+08:00", artifact_available=True, delivery_evidence=".coordination/20261014/workspaces/astra-first-cause-r20/DELIVERY.md", independent_acceptance=True, acceptance_evidence=review_path.relative_to(ROOT).as_posix(), independent_result=review["junit"], independent_finished_at=review["finished_at"], joint_verification=False, whole_package_complete=False, checked_at=at)
ledger["updated_at"] = at
path.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
path = HERE / "continuation-r6.json"
continuation = json.loads(path.read_text(encoding="utf-8"))
continuation.update(updated_at=at, native_active_first_cause={"agent_task_id": row["agent_task_id"], "status": "completed_independently_accepted_not_intaken", "review": row["acceptance_evidence"], "finished_at": review["finished_at"], "junit": review["junit"], "independent_acceptance": True, "integrated": False})
path.write_text(json.dumps(continuation, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
note = f"## {at} · R20 first-cause independent acceptance passed, not intaken\n\nNative /root/astra_first_cause_r20 (gpt-6-astra/xhigh) producer frozen22:06:15; coordinator independent397 passed, zero failures/errors/skips, four commands0, final input proof22:15:01.668884+08. Evidence: artifacts/coordinator-first-cause-r20-final-acceptance-20261015/review.json. Two owned file SHAs, all inputs, independent probes and native tool stable. Root R19 protected1041 inputs still unchanged; this is not Root joint acceptance or full U01/S08/project completion. Known opaque-parent occurrence time remains unknown. Job-to-CLI SQL authority3 failures remain a separate gate; no counts summed.\n\n---\n\n"
for filename in ("DAG.md", "PROGRESS.md", "CURRENT_STATE_R20.md"):
    path = HERE / filename
    path.write_text(note + path.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
print(json.dumps({"at": at, "task_id": row["agent_task_id"], "independent_passed": 397, "integrated": False}), flush=True)
