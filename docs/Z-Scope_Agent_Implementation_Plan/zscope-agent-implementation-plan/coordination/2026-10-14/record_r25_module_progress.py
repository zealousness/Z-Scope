"""Publish current evidence without promoting producer work to acceptance."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]

def read(path):
    return json.loads(path.read_text(encoding="utf-8"))

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

joint = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/review.json")
root_sources = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
assert joint["all_current_selected_validation_passed"] and len(root_sources) == 1065
assert all(sha(ROOT / path) == digest for path, digest in root_sources.items())
ledger = read(HERE / "tasks.json")
astra = next(row for row in ledger["tasks"] if row["id"] == "ASTRA-INSTANCE-CONSUMERS-R25")
baseline = read(HERE / "followups-r12/astra-instance-consumers-r25-baseline.json")
extension = read(HERE / "followups-r12/astra-instance-consumers-r25-ownership-extension-01.json")
assert extension["actual_task"] == astra["actual_task"] and extension["coordinator_authorized"]
owns = set(astra["write_paths"]) | set(extension["write_paths"])
astra_branch = ROOT / ".coordination/20261014/workspaces/astra-instance-consumers-r25"
readonly = {item["path"]: item["sha256"] for item in baseline["files"] if item["path"] not in owns}
assert len(readonly) == 1061 and all(sha(astra_branch / path) == digest for path, digest in readonly.items())
execution_path = astra_branch / "artifacts/instance-consumers-r25/execution.json"
execution = read(execution_path)
assert execution["actual_task"] == astra["actual_task"] and execution["logical_task"] == astra["id"]
assert execution["baseline_manifest_sha256"] == sha(HERE / "followups-r12/astra-instance-consumers-r25-baseline.json")
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
astra.update(write_paths=sorted(owns), owns=sorted(owns), dispatched=True, actual_execution_confirmed=True, actual_tool_execution_observed_at=execution["first_actual_tool_operation_at"], execution_evidence=execution_path.relative_to(ROOT).as_posix(), status="isolated_complex_consumer_development_executing", artifact_available=False, work_in_progress_artifact_present=True, readonly_inputs=1061, ownership_extension="followups-r12/astra-instance-consumers-r25-ownership-extension-01.json", checked_at=at)
coordinator = next(row for row in ledger["tasks"] if row["id"] == "COORD-INSTANCE-INTEGRATION-R24")
if astra["id"] not in coordinator["depends_on"]:
    coordinator["depends_on"].append(astra["id"])
summaries = []
for identity in ("S01-INSTANCE-SEMANTICS-MIN-R23", "S08-INSTANCE-RECOVERY-MIN-R23", "ASTRA-INSTANCE-CONSUMERS-R25"):
    row = next(row for row in ledger["tasks"] if row["id"] == identity)
    assert not row["independent_acceptance"] and not row["integrated"] and not row["joint_verification"]
    summaries.append({key: row.get(key) for key in ("id", "actual_task", "bridge_task_id", "bridge_session_id", "producer_status", "dispatched_at", "worker_process_started_at", "actual_tool_execution_observed_at", "worker_finished_at", "artifact_available", "work_in_progress_artifact_present", "independent_acceptance", "integrated", "joint_verification", "consecutive_failed_actual_deliveries", "execution_evidence", "dispatch_evidence", "write_paths")})
evidence = {
    "s01_dependency": "artifacts/coordinator-s01-module-dependency-r25-20261016/review.json",
    "s01_native_origin": "artifacts/coordinator-s01-origin-r25-20261016/review.json",
    "s01_second_failure": "artifacts/s01-origin-probe-r25-20261016/failure-review.json",
    "s08_dependency": "artifacts/coordinator-s08-module-dependency-r25-20261016/review.json",
    "s08_identity_reconciliation": "artifacts/coordinator-s08-module-dependency-r25-20261016/identity-reconciliation.json",
    "s08_live_roundtrip": "artifacts/coordinator-s08-consumer-r25-20261016/review.json",
    "s08_second_failure": "artifacts/s08-consumer-probe-r25-20261016/failure-review.json",
    "shared_overlay": "artifacts/coordinator-shared-overlay-r25-20261016/review.json",
    "s01_source_review": "artifacts/s01-module-source-review-r25-20261016/review.json",
    "s08_source_review": "artifacts/s08-module-source-review-r25-20261016/review.json",
    "consumer_precheck": "artifacts/instance-shadow-consumer-precheck-r25-20261016/review.json",
}
proof = dict(recorded_at=at, current_root_joint="artifacts/coordinator-r23-ui-projection-union-20261016/review.json", root_joint_finished_at=joint["finished_at"], root_result=dict(passed=2551, failed=0, errors=0, skipped=0, test_files=171, commands_passed=6), root_bound_inputs_unchanged=1065, root_new_intake=False, unchanged_root_rerun=False, tasks=summaries, evidence={key: dict(path=path, sha256=sha(ROOT / path)) for key, path in evidence.items()}, coordinator_stage="coordinator-instance-integration-r24", stage_acceptance=False, shared_overlay_functional_scope="18 controlled model/default tests only; full consumers remain unaccepted", stage_models_black_check="exit1: models would reformat; coordinator formatting pending, no quality acceptance", whole_packages_complete=False, clock_problem_resolved=False, archived_S06_operations=0, services_started_or_restarted=0, manual_wsl_process_inspection=False, actual_blockers=["S01 standard-root/ABI and default overlay obligations awaiting third delivery", "S08 legal live-cluster contexts and full-document publication bounds awaiting third delivery", "Astra exact-instance candidate effect consumers including literal paths not yet delivered", "Coordinator native consumer/recovery/validation/SQL wiring not functionally verified; worker candidates not admitted", "Controlled intake and a new Root union plus six quality commands are required after dependencies pass"], separate_not_executed=["Real-project/LLM effect acceptance", "Formal benchmark / portable smoke", "Complete S01/S08/U01 and remaining parent DAG nodes", "Conditional S10/Q01/Q02 extensions", "External waits and unresolved host-clock observations"])
out = ROOT / "artifacts" / ("coordinator-module-progress-r25-" + uuid.uuid4().hex[:12])
out.mkdir(exist_ok=False)
write(out / "review.json", proof)
ledger.update(updated_at=at, latest_module_progress=(out / "review.json").relative_to(ROOT).as_posix(), current_root_status="R23 exact2551/171/six current; second actual S01/S08 deliveries failed independent authority/roundtrip probes; third same-session GLM turns running; Astra complex consumers executing in exclusive isolation; coordinator stage unaccepted")
write(HERE / "tasks.json", ledger)
continuation = read(HERE / "continuation-r6.json")
continuation.update(updated_at=at, active_phase=ledger["current_root_status"], latest_handoff=ledger["latest_module_progress"], next_module_tasks=summaries, whole_packages_complete=False)
write(HERE / "continuation-r6.json", continuation)
note = f"""## {at} · R25 current Root preserved; second failures frozen; third deliveries and complex consumers parallel

Root remains R23 accepted at {joint['finished_at']}: 2551 passed across171 files, six commands0, zero failures/errors/skips; all1065 bound inputs still match. No new Root intake and no unchanged-Root rerun. Capture ENOENT was reproduced and repaired through ext4/default-fd launching; 519 pre-import tests never substitute for current validation. Timing.18 is unchanged; host-clock observations remain unresolved.

S01 second actual task_1297f2c18f completed12:38:04; independent137 cases finished12:47:02 with136pass/1shared-overlay fail and three quality commands0. Separate real native -fno-builtin/-isystem custom-header int malloc(int) probe failed1/0error/0skip at12:47:16. S08 second actual task_8886dcf232 completed12:44:35; independent307/0/0/0 and four commands0, exact seven external-probe JUnit namespace aliases reconciled without changing test names or multiplicities or rerunning tests. Separate real live CandidateLedger multi-context and full-envelope resource-bound probes failed2/0error/0skip at12:54:15. Both second candidates and full prior deliveries are frozen. Each logical task now has2 failed actual deliveries across IDs; the coordinator namespace mismatch and overly strict active-presence launcher guard are excluded. These scopes are not added into an overall acceptance count.

Third same-session fixed GLM requests: S01 task_f702313db8 / sess_6ecde27723 accepted13:02:00; S08 task_0d7256802a / sess_d9cfbf4113 accepted13:01:27. Public status is running; tool execution is confirmed only when a new actual observation arrives, and old DELIVERY files are not current artifacts. S01 has1070 readonly inputs after the exact coordinator-provided models replacement and shared test addition, original1069 baseline retained; S08 remains1069. Shared overlay18/0/0/0 and static source review apply only to that minimal seam.

Astra ASTRA-INSTANCE-CONSUMERS-R25, actual /root/astra_design_contract_r23, began actual tools13:02:33. Exclusive workspace astra-instance-consumers-r25; original1070 input manifest preserved, ownership extension01 adds5 literal-effect mixins to its original5 paths, leaving1061 readonly inputs verified unchanged. This particularly complex repair stays separate from ordinary ZCode module repairs; Kimi stays paused for new tasks under DISPATCH_POLICY. New restrict_to_semantics constructor wiring is prepared at all8 coordinator Analyzer generator sites, not yet executed or accepted. Coordinator stage remains isolated, with no worker candidates admitted; current full functional/quality checks are pending. Its shared models Black check was1 (formatting pending), so no stage quality pass is claimed.

Remaining dependency path: accepted S01/S08/Astra candidates -> coordinator native consumers, atomic Ledger/Store/Queue completion, P/R/E accounting and current all-restored Validator barrier -> independent integration tests/quality -> controlled Root intake -> new Root union/six commands. S01/S08/U01 whole packages, real-project/LLM effects, formal/portable, conditional extensions and external waits remain separate and unclaimed. No new owner/service or archived S06 action. Evidence {out.relative_to(ROOT).as_posix()}/review.json.

---

"""
for name in ("PROGRESS.md", "DAG.md"):
    path = HERE / name
    path.write_text(note + path.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
(HERE / "CURRENT_STATE_R25.md").write_text(note, encoding="utf-8", newline="\n")
print(json.dumps(dict(at=at, receipt=(out / "review.json").relative_to(ROOT).as_posix(), root_bound_inputs_unchanged=1065, astra_readonly_inputs=1061, tasks=[dict(id=row["id"], task_id=row.get("bridge_task_id") or row.get("actual_task"), actual_tool_execution_observed_at=row.get("actual_tool_execution_observed_at")) for row in summaries]), ensure_ascii=False))
