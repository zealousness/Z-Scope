"""Create a new isolated continuation from the frozen third S01 delivery."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import shutil
import subprocess
import sys
import uuid

assert sys.platform == "linux" and not sys.flags.optimize
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
OLD = ROOT / ".coordination/20261014/workspaces/s01-instance-semantics-min-r23"
NEW = ROOT / ".coordination/20261014/workspaces/s01-origin-repair-r31"
STAGE = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
OUT = ROOT / "artifacts/coordinator-s01-replacement-r31-20261017"


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


manifest_path = HERE / "followups-r12/s01-repair-r25-readonly-dependencies.json"
readonly = {row["path"]: row["sha256"] for row in read(manifest_path)["files"]}
owned = {"zscope/semantics/instance_semantics.py": "08db6df26661da490eab42cd21f638cc661affd8cc36866da2996c39aa74e931", "tests/test_instance_semantics.py": "719339ff51e06f4be5f9ee66ff7d4b3be10d66382ddb60cad8bd47895ae4dada"}
assert len(readonly) == 1070 and not readonly.keys() & owned.keys()
old_inputs = readonly | owned
assert all(sha(OLD / path) == digest for path, digest in old_inputs.items())
root_inputs = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
assert len(root_inputs) == 1065 and all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
stage_inputs = read(ROOT / "artifacts/stage-quality-repair-r30-20261017/repair-source.json")["full_stage_source_after"]
assert len(stage_inputs) == 967 and all(sha(STAGE / path) == digest for path, digest in stage_inputs.items())
assert not (STAGE / "zscope/semantics/instance_semantics.py").exists()
head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
assert head == "010f40210b54ba0f79a088312ce5d8be3a82ace0"
assert sha(ROOT / ".coordination/20261014/bridge-route-check/state.json") == "a7b8c7bb52be3e4eb2a3a50ad7ff872abde794529f0a5682379ec5cd0bf7a4a3"
row = next(row for row in read(HERE / "tasks.json")["tasks"] if row["id"] == "S01-INSTANCE-SEMANTICS-MIN-R23")
assert row["consecutive_failed_actual_deliveries"] == 3 and len(row["glm_delivery_rounds"]) == 3
assert all(item["counted_development_failure"] for item in row["glm_delivery_rounds"])
assert not NEW.exists() and not OUT.exists()
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
NEW.mkdir(parents=True)
OUT.mkdir()
for path, digest in old_inputs.items():
    destination = NEW / path
    assert destination.resolve().is_relative_to(NEW.resolve())
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(OLD / path, destination)
    assert sha(destination) == digest
request_id = str(uuid.uuid4())
proof = dict(prepared_at=at, actual_coordinator_task="/root", logical_task="S01-INSTANCE-SEMANTICS-MIN-R23", original_task_id="task_f702313db8", original_session_id="sess_6ecde27723", continuation_actual_development_round=4, previous_actual_failed_deliveries=3, old_workspace=OLD.relative_to(ROOT).as_posix(), new_workspace=NEW.relative_to(ROOT).as_posix(), user_authorization="Bridge阻塞就新开任务继续原任务未完成的工作", new_public_task_authorized=True, old_owner_recovery_required_for_this_replacement=False, original_manifest_unchanged=True, readonly_manifest=manifest_path.relative_to(ROOT).as_posix(), readonly_manifest_sha256=sha(manifest_path), readonly_sources=readonly, owned_initial_sources=owned, old_workspace_inputs=old_inputs, root_inputs=root_inputs, stage_inputs=stage_inputs, new_source_inputs=old_inputs, write_paths=list(owned), artifact_write_paths=["DELIVERY.md", "artifacts/s01-repair-r31/**"], target_owner_conflicts=[], isolation_prevents_shared_writes=True, old_workspace_readonly=True, root_and_stage_readonly=True, request_id=request_id, agent="zcode", model="97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3", dispatched=False, actual_execution=False, artifact_available=False, independent_acceptance=False, integrated=False, joint_verification=False, services_started_or_restarted=0, archived_s06_operations=0, full_package_complete=False)
write(OUT / "preparation.json", proof)
write(OUT / "prior-failure-history.json", dict(logical_task=row["id"], consecutive_failed_actual_deliveries=3, glm_delivery_rounds=row["glm_delivery_rounds"], producer_status="third original delivery remains rejected", reset_by_new_task_id=False))
write(HERE / "followups-r12/s01-origin-repair-r31-ownership.json", {key: proof[key] for key in ("prepared_at", "logical_task", "new_workspace", "write_paths", "artifact_write_paths", "target_owner_conflicts", "old_workspace_readonly", "root_and_stage_readonly", "request_id")})
assert all(sha(OLD / path) == digest for path, digest in old_inputs.items())
print(json.dumps(dict(prepared_at=at, new_workspace=proof["new_workspace"], readonly_inputs=len(readonly), owned_inputs=len(owned), request_id=request_id, failed_count_preserved=3)))
