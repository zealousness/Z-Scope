"""Install coordinator-only readonly notes after the producer is quiescent."""
from pathlib import Path
import datetime as dt
import hashlib
import json
from audit_followup_r12 import audit, HERE, ROOT

name = "job-cli-window-r20"
row = next(r for r in json.loads((HERE / "tasks.json").read_text(encoding="utf-8"))["tasks"] if r["id"] == "U01-JOB-CLI-WINDOW-R20")
assert (row["producer_status"] == "completed" and row["worker_finished_at"]) or row["status"] == "quiescent_complex_sql_handoff_ready"
ownership = audit(name)
assert not ownership["nonowned_changes"]
branch = ROOT / ".coordination/20261014/workspaces" / name
assert (branch / "DELIVERY.md").is_file()
staged = ROOT / "artifacts/staged-job-cli-notes-r20-20261015"
staging = json.loads((staged / "staging.json").read_text(encoding="utf-8"))
baseline = json.loads((HERE / "followups-r12" / (name + "-baseline.json")).read_text(encoding="utf-8"))
parents = {r["path"]: r["sha256"] for r in baseline["files"]}
receipt_path = HERE / "followups-r12" / (name + "-dependencies.json")
assert not receipt_path.exists()
rows = []
pending_copies = []
core_review = json.loads((ROOT / "artifacts/coordinator-first-cause-r20-final-acceptance-20261015/review.json").read_text(encoding="utf-8"))
assert core_review["independent_acceptance_passed"] and core_review["source_unchanged"] and core_review["independent_probes_unchanged"]
assert len(core_review["commands"]) == 4 and all(r["returncode"] == 0 for r in core_review["commands"])
assert all(core_review["junit"][k] == "0" for k in ("errors", "failures", "skipped"))
core_branch = ROOT / ".coordination/20261014/workspaces/astra-first-cause-r20"
assert set(core_review["delivered_hashes"]) == {"zscope/common/cancellation.py", "tests/test_cancellation_first_cause.py"}
for p, sha in core_review["delivered_hashes"].items():
    before = hashlib.sha256((branch / p).read_bytes()).hexdigest() if (branch / p).exists() else None
    assert before == parents.get(p)
    data = (core_branch / p).read_bytes()
    assert hashlib.sha256(data).hexdigest() == sha
    pending_copies.append((p, data))
    rows.append({"path": p, "previous_sha256": before, "sha256": sha, "owner": "/root/astra_first_cause_r20", "independent_review": "artifacts/coordinator-first-cause-r20-final-acceptance-20261015/review.json", "worker_write_permission": False})
for r in staging["files"]:
    p = r["path"]
    assert parents[p] == r["before"] == hashlib.sha256((branch / p).read_bytes()).hexdigest() == hashlib.sha256((ROOT / p).read_bytes()).hexdigest()
    data = (staged / p).read_bytes()
    assert hashlib.sha256(data).hexdigest() == r["after"]
    pending_copies.append((p, data))
    rows.append({"path": p, "previous_sha256": r["before"], "sha256": r["after"], "owner": "coordinator_readonly_module_notes", "worker_write_permission": False})
for p, data in pending_copies:
    (branch / p).parent.mkdir(parents=True, exist_ok=True)
    (branch / p).write_bytes(data)
receipt_path.write_text(json.dumps({"captured_at": dt.datetime.now(dt.timezone.utc).isoformat(), "coordinator_authorized": True, "files": rows, "scope": "Independently accepted two-file Astra cancellation dependency and four staged readonly coordinator docs; producer ownership remains exactly three code/test files; Root unchanged"}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
assert not audit(name)["nonowned_changes"]
print(json.dumps({"readonly_docs": len(rows), "root_changed": False}), flush=True)
