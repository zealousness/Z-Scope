"""Record fixed dispatch tooling without pretending that workers were sent."""
from pathlib import Path
import datetime as dt
import hashlib
import json

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]

def read(p):
    return json.loads(p.read_text(encoding="utf-8"))

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def write(p, value):
    p.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

review_path = ROOT / "artifacts/module-dispatch-independent-review-r23-20261016/final-review.json"
assert sha(review_path) == "af8fe5e7bd01455c354faa5729d5c97672c4545cc1f5fbd9c1049aa226c127d7"
review = read(review_path)
assert review["source_review_passed"] and review["tests_executed"] == 0
assert len(review["reviewed_hashes"]) == 8 and all(sha(ROOT / p) == h for p, h in review["reviewed_hashes"].items())
probe = read(ROOT / "artifacts/coordinator-atomic-queue-probe-r23-20261016/review.json")
assert probe["completed_json_atomically_published"] and probe["existing_target_refused"] and probe["bridge_requests_published"] == 0
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
ledger = read(HERE / "tasks.json")
rows = {r["id"]: r for r in ledger["tasks"]}
assert "ASTRA-MODULE-DISPATCH-REVIEW-R23" not in rows
ledger["tasks"].append({"id": "ASTRA-MODULE-DISPATCH-REVIEW-R23", "actual_task": "/root/astra_design_review_r23", "owner": "Astra", "status": "final_corrected_source_review_passed_initial_atomicity_block_retained", "artifact_available": True, "source_review_passed": True, "tests_executed": 0, "product_changed": False, "evidence": review_path.relative_to(ROOT).as_posix(), "initial_review": "artifacts/module-dispatch-independent-review-r23-20261016/review.json", "checked_at": at})
for key in ("S01-INSTANCE-SEMANTICS-MIN-R23", "S08-INSTANCE-RECOVERY-MIN-R23"):
    assert not rows[key].get("bridge_task_id")
    rows[key].update(dispatch_tooling_source_review_passed=True, dispatch_tooling_review=review_path.relative_to(ROOT).as_posix(), fresh_active_preflight_done=False, checked_at=at)
ledger["updated_at"] = at
write(HERE / "tasks.json", ledger)
out = ROOT / "artifacts/coordinator-dispatch-readiness-r23-20261016"
out.mkdir(exist_ok=False)
write(out / "review.json", {"at": at, "dispatch_tooling_source_review_passed": True, "dispatch_review": review_path.relative_to(ROOT).as_posix(), "dispatch_review_sha256": sha(review_path), "atomic_publication_probe_passed": True, "owner_crash_observed": False, "bridge_requests_published_by_probe": 0, "workers_dispatched": 0, "current_root_joint_passed": False, "fresh_active_preflight_pending": True, "whole_packages_complete": False})
note = f"## {at} · Atomic dispatch tooling source review passed, Root gate still running\n\nOriginal-owner queue parser race found in initial static review, before any new worker dispatch: direct write could expose partial JSON. New helper closes/fsyncs a same-directory nonrequest temporary then exclusively os.links the final name. Actual queue-filesystem probe10:42:20 passed full UTF-8 JSON and existing-target refusal;0 Bridge requests/services/tests/product changes. No owner crash observed. Dispatch/observe/new R23 preflight use atomic writer; response reads only await existing complete JSON, no blind retry. Final independent review /root/astra_design_review_r23 passed exact8 script/request hashes; initial blocked review retained. Evidence {review_path.relative_to(ROOT).as_posix()}.\n\nBoth new modules remain prepared/not dispatched. Current Root171/six is still executing, followed by live publication guard and fresh original-owner/active-only session preflight. Kimi paused; ordinary candidates fixed ZCode GLM; UI/complex design Astra. Source review is not functional or whole-package acceptance.\n\n---\n\n"
for name in ("PROGRESS.md", "DAG.md"):
    p = HERE / name
    p.write_text(note + p.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
print(json.dumps({"at": at, "dispatch_source_review_passed": True, "workers_dispatched": 0, "Root_joint_passed": False}), flush=True)
