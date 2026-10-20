"""Record final-byte independent acceptance separately from Root intake."""
from pathlib import Path
import datetime as dt
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
review_path = ROOT / "artifacts/coordinator-job-cli-window-r20-final-acceptance-20261015/review.json"
review = json.loads(review_path.read_text(encoding="utf-8"))
assert review["independent_acceptance_passed"] and not review["boundary_preflight_only"]
assert review["source_unchanged"] and review["independent_probes_unchanged"]
assert len(review["commands"]) == 4 and all(r["returncode"] == 0 for r in review["commands"])
assert all(review["junit"][k] == "0" for k in ("failures", "errors", "skipped"))
assert review["native_before"] == review["native_after"] == "d39cbe72fafad1fbfa989a51346cdf4785101e32855c0ee0d11a1e2748263399"
branch = ROOT / ".coordination/20261014/workspaces/job-cli-window-r20"
assert all(hashlib.sha256((branch / p).read_bytes()).hexdigest() == h for p, h in review["after_all_inputs"].items())
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
path = HERE / "tasks.json"
ledger = json.loads(path.read_text(encoding="utf-8"))
row = next(r for r in ledger["tasks"] if r["id"] == "U01-JOB-CLI-WINDOW-R20")
assert row["producer_status"] == "completed" and review["task_id"] == row["agent_task_id"] and not row["integrated"]
assert row["delivered_hashes"] == review["delivered_hashes"]
row.setdefault("execution_history", []).append({"agent_task_id": row["agent_task_id"], "provider": "gpt-6-astra/xhigh", "status": "full_final_byte_independent_acceptance_passed_not_intaken", "review": review_path.relative_to(ROOT).as_posix(), "finished_at": review["finished_at"], "counts_as_glm_actual_delivery_failure": False, "failure_streak_after": 0})
row.update(status="final_byte_independently_accepted_frozen_not_intaken", independent_acceptance=True, acceptance_evidence=review_path.relative_to(ROOT).as_posix(), independent_result=review["junit"], independent_finished_at=review["finished_at"], consecutive_failed_actual_deliveries=0, checked_at=at)
ledger["updated_at"] = at
path.write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
note = f"## {at} · R20 final-byte SQL consumer independently accepted, not intaken\n\nNative {row['agent_task_id']} final3 bytes: coordinator {review['junit']['tests']} passed, zero failures/errors/skips, four commands0, proof finish {review['finished_at']}. Evidence {review_path.relative_to(ROOT).as_posix()}; entire captured source, native, ownership and original probes stable. GLM task_492e7a7037 first-delivery8pass3fail retained, both network-only continuations excluded from development failures; this full same-logical-item acceptance ends streak, history remains. Astra first-cause independently397/four0 also frozen. Root R19 still unchanged; nine-file intake and strict current full union pending. Separate R21 UI wording/coverage-projection findings and whole-package/project limits remain.\n\n---\n\n"
for filename in ("DAG.md", "PROGRESS.md", "CURRENT_STATE_R20.md"):
    path = HERE / filename
    path.write_text(note + path.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
print(json.dumps({"at": at, "task_id": row["agent_task_id"], "tests": review["junit"]["tests"], "independently_accepted": True, "integrated": False}), flush=True)
