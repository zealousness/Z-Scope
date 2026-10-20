"""Audit persisted original-owner terminal results and live candidate bytes."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
OUT = ROOT / "artifacts/coordinator-resume-r26-20261016"
OUT.mkdir(exist_ok=True)

def read(path):
    return json.loads(path.read_text(encoding="utf-8"))

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def write_new(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(value, ensure_ascii=False, indent=2) + "\n")

root_sources = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
assert len(root_sources) == 1065 and all(sha(ROOT / path) == digest for path, digest in root_sources.items())
assert subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip() == "010f40210b54ba0f79a088312ce5d8be3a82ace0"
state_path = ROOT / ".coordination/20261014/bridge-route-check/state.json"
state_sha = sha(state_path)
state = read(state_path)
public = read(OUT / "public-bridge-observation.json")
assert public["original_queue_owner_alive"] is False and public["service_restarted"] is False
ledger = read(HERE / "tasks.json")
summaries = []
for short, actual, session, name, artifact_name, failed_candidate in (
    ("s01", "task_f702313db8", "sess_6ecde27723", "s01-instance-semantics-min-r23", "instance-semantics-r23", "s01-origin-probe-r25-20261016"),
    ("s08", "task_0d7256802a", "sess_d9cfbf4113", "s08-instance-recovery-min-r23", "instance-recovery-r23", "s08-consumer-probe-r25-20261016"),
):
    records = [record for record in state["tasks"] if record.get("task_id") == actual]
    assert len(records) == 1
    terminal = records[0]
    expected_model = "97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3"
    assert terminal["status"] == "completed" and terminal["session_id"] == session
    assert terminal["model"] == terminal["observed_model"] == expected_model
    assert not terminal.get("error") and not terminal.get("failure") and not terminal.get("warnings")
    result_path = state_path.parent / "results" / (actual + ".txt")
    result_text = result_path.read_text(encoding="utf-8")
    # Official registry._tail retains the last 6000 UTF-8 bytes in state;
    # get_result reads the complete artifact, not that bounded state tail.
    encoded_result = result_text.encode("utf-8")
    expected_tail = result_text if len(encoded_result) <= 6000 else encoded_result[-6000:].decode("utf-8", errors="ignore")
    assert expected_tail == terminal["result_text"] and len(result_text) == terminal["result_chars"]
    branch = ROOT / ".coordination/20261014/workspaces" / name
    logical = "S01-INSTANCE-SEMANTICS-MIN-R23" if short == "s01" else "S08-INSTANCE-RECOVERY-MIN-R23"
    row = next(row for row in ledger["tasks"] if row["id"] == logical)
    assert row["bridge_task_id"] == actual and row["bridge_session_id"] == session
    assert row["consecutive_failed_actual_deliveries"] == 2 and not row["integrated"]
    inputs = {}
    for filename in (name + "-baseline.json", name + "-dependencies.json"):
        inputs.update({item["path"]: item["sha256"] for item in read(HERE / "followups-r12" / filename)["files"]})
    assert len(inputs) == 1069
    if short == "s01":
        overlay = read(HERE / "followups-r12/s01-repair-r25-readonly-dependencies.json")
        inputs.update(overlay["new_shared_sha256"])
        assert inputs == {item["path"]: item["sha256"] for item in overlay["files"]}
    assert len(inputs) == (1070 if short == "s01" else 1069)
    assert all(sha(branch / path) == digest for path, digest in inputs.items())
    owned = {path: sha(branch / path) for path in row["write_paths"]}
    producer_review = branch / "artifacts" / artifact_name / "review.json"
    delivery = branch / "DELIVERY.md"
    assert producer_review.is_file() and delivery.is_file()
    producer = read(producer_review)
    assert producer.get("actual_task_id") is None
    old = read(ROOT / "artifacts" / failed_candidate / "failure-review.json")
    frozen = ROOT / old["frozen_candidate"]
    history = {}
    for path, digest in old["frozen_files"].items():
        assert sha(frozen / path) == digest
        if not path.startswith("artifacts/") or path == "artifacts/" + artifact_name + "/review.json":
            continue
        assert (branch / path).is_file() and sha(branch / path) == digest, (actual, path)
        history[path] = digest
    old_before = "artifacts/instance-recovery-r23/repair-r24-input-sha-before.json"
    if short == "s08":
        assert old_before in history, "The restored historical before manifest must match coordinator-frozen bytes"
    binding = dict(task_id=actual, session_id=session, persisted_owner_fields={key: terminal.get(key) for key in ("status", "model", "observed_model", "started_at", "finished_at", "owner_pid", "owner_create_time", "stop_reason", "error", "failure", "warnings")}, owner_state_path=state_path.relative_to(ROOT).as_posix(), owner_state_sha256=state_sha, result_path=result_path.relative_to(ROOT).as_posix(), result_sha256=sha(result_path), result_characters=len(result_text), result_matches_persisted_terminal_record=True, original_dispatch_receipt=row["dispatch_evidence"], original_dispatch_receipt_sha256=sha(HERE / row["dispatch_evidence"]), live_public_interface_binding_available=False, current_attached_bridge_error="unknown task", readonly_inputs=len(inputs), readonly_inputs_unchanged=True, owned_source_sha256=owned, producer_delivery_sha256=sha(delivery), producer_review_sha256=sha(producer_review), historical_artifact_files_verified=len(history), historical_artifact_sha256=history, s08_restored_before_matches_frozen=(short == "s08"), independent_acceptance=False, integrated=False, joint_verification=False)
    write_new(OUT / (short + "-persisted-result-binding.json"), binding)
    row.update(producer_status="completed", producer_status_source="original_owner_persisted_terminal_state", original_owner_public_interface_available=False, producer_completed_binding=(OUT / (short + "-persisted-result-binding.json")).relative_to(ROOT).as_posix(), worker_finished_at=terminal["finished_at"], observed_model=terminal["observed_model"], artifact_available=True, status="third_delivery_frozen_persisted_terminal_bound_independent_checks_pending_public_owner_unavailable")
    summaries.append({key: binding[key] for key in ("task_id", "session_id", "persisted_owner_fields", "readonly_inputs", "owned_source_sha256", "historical_artifact_files_verified", "s08_restored_before_matches_frozen")})
assert sha(state_path) == state_sha
assert all(sha(ROOT / path) == digest for path, digest in root_sources.items())
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
ledger["updated_at"] = at
(HERE / "tasks.json").write_text(json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
proof = dict(at=at, root_bound_inputs_unchanged=1065, head="010f40210b54ba0f79a088312ce5d8be3a82ace0", original_owner_state_unchanged=True, task_bindings=summaries, public_owner_gap_preserved=True, services_started_or_restarted=0, dispatches=0, tests_executed=0, consecutive_failed_actual_deliveries_unchanged=2, independent_acceptance=False, integrated=False, joint_verification=False)
write_new(OUT / "audit.json", proof)
print(json.dumps(proof, ensure_ascii=False))
