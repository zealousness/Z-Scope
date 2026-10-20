"""Guard ownership, then copy only the accepted consumer slice into Stage."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import subprocess
import sys

assert sys.platform == "linux" and not sys.flags.optimize
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
STAGE = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
PRODUCER = ROOT / ".coordination/20261014/workspaces/consumer-exact-repair-r29"
OUT = ROOT / "artifacts/consumer-stage-intake-r30-20261017"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


accept_path = ROOT / "artifacts/coordinator-consumer-acceptance-r29-20261017/review.json"
accept = read(accept_path)
assert accept["independent_acceptance"] and not accept["root_intake"] and not accept["coordinator_stage_intake"]
assert all(sha(ROOT / path) == digest for path, digest in accept["references_sha256"].items())
execution_path = ROOT / "artifacts/coordinator-consumer-repair-r29-20261017/review.json"
execution = read(execution_path)
assert execution["independent_execution_checks_passed"] and execution["junit"] == dict(tests=893, failures=0, errors=0, skipped=0)
assert all(sha(PRODUCER / path) == digest for path, digest in execution["source_before"].items())
old_producer = read(ROOT / ".coordination/20261014/workspaces/astra-instance-consumers-r25/artifacts/instance-consumers-r25/review.json")
paths = list(old_producer["ownership"]["owned_paths"]) + [
    "tests/test_lock_modes.py", "tests/test_rule_runtime_governance.py", "tests/test_analyzer_semantics.py",
]
assert len(paths) == len(set(paths)) == 14
baseline = read(HERE / "followups-r12/coordinator-instance-integration-r24-baseline.json")
expected = {row["path"]: row["sha256"] for row in baseline["files"]}
allowed = set(baseline["task"]["write_paths"])
for suffix in ("01", "02", "03", "04"):
    allowed.update(read(HERE / f"followups-r12/coordinator-instance-integration-r24-ownership-extension-{suffix}.json")["write_paths"])
assert not allowed & set(paths), "Existing shared owner conflict; do not copy"
assert all(sha(STAGE / path) == digest for path, digest in expected.items() if path not in allowed)
store_before = read(ROOT / "artifacts/coordinator-store-queue-r26-e0560b7b2e9d/review.json")["source_before"]
assert all(sha(STAGE / path) == digest for path, digest in store_before.items())
root_sources = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
assert len(root_sources) == 1065 and all(sha(ROOT / path) == digest for path, digest in root_sources.items())
head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
assert head == "010f40210b54ba0f79a088312ce5d8be3a82ace0"
state_path = ROOT / ".coordination/20261014/bridge-route-check/state.json"
assert sha(state_path) == "a7b8c7bb52be3e4eb2a3a50ad7ff872abde794529f0a5682379ec5cd0bf7a4a3"
state = read(state_path)
tasks = list(state["tasks"].values()) if isinstance(state["tasks"], dict) else state["tasks"]
original_tasks = [{key: row.get(key) for key in ("task_id", "session_id", "status", "finished_at", "owner_pid", "owner_create_time")} for row in tasks if row.get("task_id") in {"task_f702313db8", "task_0d7256802a"}]
assert len(original_tasks) == 2 and all(row["status"] == "completed" for row in original_tasks)
assert not any(row.get("status") in {"queued", "running"} for row in tasks)


def snapshot():
    result = {path: sha(STAGE / path) for path in store_before}
    result.update({path.relative_to(STAGE).as_posix(): sha(path) for directory in ("zscope", "scripts", "test", "tests", "docs/modules") for path in (STAGE / directory).rglob("*") if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"})
    return result


before = snapshot()
assert not set(before) - set(expected) - allowed
assert not (STAGE / "zscope/semantics/instance_semantics.py").exists()
incoming = {path: execution["source_before"][path] for path in paths}
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
OUT.mkdir(exist_ok=False)
write(OUT / "readonly-review.json", dict(observed_at=at, root_head=head, root_inputs_current=1065, stage_pinned_inputs_current=len(store_before), baseline_ownership_guard=True, target_paths=paths, target_owner_conflicts=[], frozen_producer_stopped=True, original_persisted_tasks=original_tasks, original_state_sha256=sha(state_path), public_visibility="unknown task at fresh official check; persisted completion is not fresh public confirmation", public_owner_restored=False, original_80748_pid_reused=True, services_started=0, old_s06_queried=False))
extension_path = HERE / "followups-r12/coordinator-instance-integration-r24-ownership-extension-05.json"
assert not extension_path.exists()
write(extension_path, dict(coordinator_authorized=True, authorized_by="Human current instruction: integrate the independently accepted consumer repair into Stage", write_paths=paths, source_sha256=incoming, actual_original_producer_task="/root/astra_design_contract_r23", actual_repair_producer_task="/root/consumer_exact_repair_r29", acceptance=accept_path.relative_to(ROOT).as_posix(), acceptance_sha256=sha(accept_path), reason="Coordinator-only Stage intake of11accepted consumer files and3matching coordinator-controlled dependency tests; no Root copy, no S01 copy or resumption."))
for path in paths:
    destination = STAGE / path
    if destination.exists():
        backup = OUT / "before" / path
        backup.parent.mkdir(parents=True, exist_ok=True)
        backup.write_bytes(destination.read_bytes())
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes((PRODUCER / path).read_bytes())
after = snapshot()
changed = sorted(path for path in set(before) | set(after) if before.get(path) != after.get(path))
assert set(changed) == set(paths)
assert all(sha(STAGE / path) == digest for path, digest in incoming.items())
assert all(before[path] == after[path] for path in before if path not in paths)
assert all(sha(ROOT / path) == digest for path, digest in root_sources.items())
assert all(sha(PRODUCER / path) == digest for path, digest in execution["source_before"].items())
proof = dict(integrated_at=dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat(), actual_coordinator_task="/root", logical_task="COORD-INSTANCE-INTEGRATION-R24", actual_consumer_repair_task="/root/consumer_exact_repair_r29", acceptance=accept_path.relative_to(ROOT).as_posix(), acceptance_sha256=sha(accept_path), ownership_extension=extension_path.relative_to(ROOT).as_posix(), copied_source_sha256=incoming, stage_source_before=before, stage_source_after=after, changed_paths=changed, other_stage_inputs_unchanged=True, producer_unchanged=True, root_bound_inputs_unchanged=1065, stage_intake=True, root_intake=False, stage_post_intake_regression_passed=False, stage_full_quality_passed=False, missing_s01_not_copied=True, original_bridge_state_unchanged=sha(state_path)=="a7b8c7bb52be3e4eb2a3a50ad7ff872abde794529f0a5682379ec5cd0bf7a4a3", whole_packages_complete=False, services_started_or_restarted=0, bridge_dispatches=0, archived_s06_operations=0, scope="Accepted consumer sources integrated toStage only. Current Stage combined tests and quality are still required; oldStore227 and producer893 are not joint acceptance of this changed Stage.")
write(OUT / "receipt.json", proof)
(OUT / "launcher.py").write_bytes(Path(__file__).read_bytes())
print(json.dumps(dict(integrated_at=proof["integrated_at"], receipt=(OUT / "receipt.json").relative_to(ROOT).as_posix(), stage_intake=True, copied_files=len(paths), root_intake=False, regression_passed=False)))
