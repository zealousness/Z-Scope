"""Read-only producer review over synthetic receipts or real isolated SQLite."""
from pathlib import Path
import hashlib
import json
import sys
import uuid

assert sys.platform == "linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
label = sys.argv[1]
workspace = ROOT / ".coordination/20261014/workspaces" / ("s01-coverage" if label == "s01" else "s08-scheduling")
sys.path.insert(0, str(workspace))
sys.path.insert(0, str(workspace / "tests"))
output = HERE / "review-repro" / ("producer-identity-" + label) / uuid.uuid4().hex[:8]
output.mkdir(parents=True)
source = workspace / ("zscope/orchestration/entry_instance_coverage.py" if label == "s01" else "zscope/orchestration/jobs/work_queue.py")
before = hashlib.sha256(source.read_bytes()).hexdigest()
if label == "s01":
    from test_entry_instance_coverage import _write_project, _stored_context, _fake_index
    from zscope.orchestration.entry_instance_coverage import reconcile_entry_instance_coverage
    project = output / "project"
    project.mkdir()
    rows, cdb = _write_project(project)
    contexts = [_stored_context(row, cdb) for row in rows]
    valid = reconcile_entry_instance_coverage(_fake_index(contexts), compile_commands_path=cdb, source_root=project)
    for context in contexts:
        context["build_context_id"] = ""
    missing = reconcile_entry_instance_coverage(_fake_index(contexts), compile_commands_path=cdb, source_root=project)
    for context in contexts:
        context["build_context_id"] = "foreign-arbitrary-identity"
    foreign = reconcile_entry_instance_coverage(_fake_index(contexts), compile_commands_path=cdb, source_root=project)
    proof = {"synthetic_only": True, "valid": valid, "missing_build_identity": missing, "foreign_build_identity": foreign}
else:
    from zscope.orchestration.jobs.work_queue import WorkQueue
    queue = WorkQueue(output / "queue.db", job_id="job-a", input_revision="input-a", lease_seconds=1)
    queue.enqueue([{"kind": "entry", "scope_key": "main", "build": "build-a", "payload": {}}], batch_no=1)
    first = queue.claim_batch(1, now=100)["claimed"][0]
    second = queue.claim_batch(1, now=102)["claimed"][0]
    assert first["claim_token"] != second["claim_token"]
    try:
        queue.complete(first["item_id"], claim_token=first["claim_token"], now=102.1)
    except Exception as error:
        explicit_old_token = str(error)
    else:
        explicit_old_token = "unexpectedly accepted"
    try:
        tokenless_old_owner = queue.complete(first["item_id"], now=102.2)
    except Exception as error:
        tokenless_old_owner = {"status": "rejected", "reason": str(error)}
    proof = {"real_sqlite_no_mock": True, "controlled_clock": True, "first_claim": first, "reclaimed": second, "explicit_old_token": explicit_old_token, "old_owner_omits_token": tokenless_old_owner, "snapshot": queue.snapshot(now=102.3)}
after = hashlib.sha256(source.read_bytes()).hexdigest()
proof.update(source_sha256=before, source_unchanged=before == after, worker_terminal_not_required_for_readonly_probe=True)
(output / "review.json").write_text(json.dumps(proof, indent=2) + "\n")
print(json.dumps({"path": str(output / "review.json"), "source_unchanged": before == after,
                  "finding": {"missing_build_coverage_complete": proof["missing_build_identity"]["command_coverage_complete"], "foreign_build_coverage_complete": proof["foreign_build_identity"]["command_coverage_complete"]} if label == "s01" else {"old_token_rejected": proof["explicit_old_token"], "tokenless_old_owner_completed_reclaimed_item": proof["old_owner_omits_token"]["status"]}}))
