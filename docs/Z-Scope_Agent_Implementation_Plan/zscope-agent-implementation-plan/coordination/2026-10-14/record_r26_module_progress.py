"""Publish exact current receipts, keeping module/consumer/Root scopes distinct."""
from pathlib import Path
import argparse
import datetime as dt
import hashlib
import json
import sys
import uuid

if sys.platform != "linux" or sys.flags.optimize:
    raise RuntimeError("Use non-optimized Linux Python")
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
parser = argparse.ArgumentParser(__doc__)
parser.add_argument("focus_review")
args = parser.parse_args()

def read(path):
    return json.loads(path.read_text(encoding="utf-8"))

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

focus_path = (ROOT / args.focus_review).resolve(strict=True)
assert focus_path.parent.parent == ROOT / "artifacts" and focus_path.parent.name.startswith("coordinator-store-queue-r26-") and focus_path.name == "review.json"
focus = read(focus_path)
assert focus["actual_task"] == "/root" and focus["sources_unchanged"] and focus["root_unchanged"] and focus["references_unchanged"]
root_sources = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
assert len(root_sources) == 1065 and all(sha(ROOT / path) == digest for path, digest in root_sources.items())
joint_path = ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/review.json"
joint = read(joint_path)
assert joint["all_current_selected_validation_passed"]
failure_path = ROOT / "artifacts/s01-origin-forms-probe-r26-20261016/failure-review.json"
failure = read(failure_path)
assert failure["task_id"] == "task_f702313db8" and failure["round"]["counted_development_failure"]
intake_path = ROOT / "artifacts/s08-codec-stage-intake-r26-20261016/receipt.json"
intake = read(intake_path)
assert intake["stage_intake"] and not intake["root_intake"]
ledger_bytes = (HERE / "tasks.json").read_bytes()
ledger = json.loads(ledger_bytes.decode("utf-8"))
rows = {row["id"]: row for row in ledger["tasks"]}
assert rows["S01-INSTANCE-SEMANTICS-MIN-R23"]["consecutive_failed_actual_deliveries"] == 3
assert rows["S08-INSTANCE-RECOVERY-MIN-R23"]["independent_acceptance"] and not rows["S08-INSTANCE-RECOVERY-MIN-R23"]["integrated"]
astra = rows["ASTRA-INSTANCE-CONSUMERS-R25"]
astra_branch = ROOT / ".coordination/20261014/workspaces/astra-instance-consumers-r25"
baseline_path = HERE / "followups-r12/astra-instance-consumers-r25-baseline.json"
extension_path = HERE / "followups-r12/astra-instance-consumers-r25-ownership-extension-01.json"
baseline = read(baseline_path)
extension = read(extension_path)
owns = set(astra["write_paths"]) | set(extension["write_paths"])
effective_path = HERE / astra["effective_readonly_dependencies"]
assert sha(effective_path) == astra["effective_readonly_dependencies_sha256"]
effective = read(effective_path)
assert effective["coordinator_owned"] and effective["original_baseline_sha256"] == sha(baseline_path)
readonly = {entry["path"]: entry["sha256"] for entry in effective["files"] if entry["path"] not in owns}
assert len(readonly) == 1060 and all(sha(astra_branch / path) == digest for path, digest in readonly.items())
resume_path = astra_branch / "artifacts/instance-consumers-r25/resume-01.json"
resume = read(resume_path)
assert resume["logical_task"] == astra["id"] and resume["readonly_mismatches"] == []
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
astra.update(write_paths=sorted(owns), owns=sorted(owns), actual_resume_confirmed=True, resumed_tool_execution_observed_at=resume["first_actual_tool_observation_utc_plus_08"], resume_evidence=resume_path.relative_to(ROOT).as_posix(), readonly_inputs=1060, checked_at=at)
if not astra.get("artifact_available"):
    astra.update(status="same_task_resumed_complex_consumer_development_in_progress", work_in_progress_artifact_present=True, independent_acceptance=False, integrated=False, joint_verification=False)
coordinator = rows["COORD-INSTANCE-INTEGRATION-R24"]
coordinator.update(status="isolated_s08_codec_intaken_store_queue_focused_checks_recorded_s01_and_consumers_pending", focused_store_queue_review=focus_path.relative_to(ROOT).as_posix(), focused_store_queue_passed=focus["focused_checks_passed"], admitted_dependencies=["S08 isolated MIN codec only"], rejected_dependencies=["S01 third delivery"], independent_acceptance=False, integrated=False, joint_verification=False, checked_at=at)
summaries = [{key: rows[identity].get(key) for key in ("id", "actual_task", "bridge_task_id", "bridge_session_id", "status", "producer_status", "worker_finished_at", "actual_tool_execution_observed_at", "resumed_tool_execution_observed_at", "artifact_available", "work_in_progress_artifact_present", "independent_acceptance", "independent_acceptance_scope", "coordinator_stage_intake", "integrated", "joint_verification", "consecutive_failed_actual_deliveries", "write_paths")} for identity in ("S01-INSTANCE-SEMANTICS-MIN-R23", "S08-INSTANCE-RECOVERY-MIN-R23", "ASTRA-INSTANCE-CONSUMERS-R25", "COORD-INSTANCE-INTEGRATION-R24")]
evidence_paths = [joint_path, failure_path, intake_path, focus_path, resume_path, effective_path, ROOT / "artifacts/consumer-readonly-dependency-intake-r26-20261016/receipt.json", ROOT / "artifacts/coordinator-resume-r26-20261016/public-bridge-observation.json", ROOT / "artifacts/s01-module-source-review-r26-20261016/review.json", ROOT / "artifacts/s08-module-source-review-r26-20261016/review.json"]
proof = dict(recorded_at=at, current_root_joint=joint_path.relative_to(ROOT).as_posix(), root_joint_finished_at=joint["finished_at"], root_result=dict(passed=2551, failures=0, errors=0, skipped=0, test_files=171, commands_passed=6), root_bound_inputs_unchanged=1065, new_root_intake=False, root_unchanged_rerun=False, tasks=summaries, evidence={path.relative_to(ROOT).as_posix(): sha(path) for path in evidence_paths}, store_queue_junit=focus["junit"], store_queue_passed=focus["focused_checks_passed"], stage_independent_acceptance=False, whole_packages_complete=False, original_bridge_owner_available=False, original_bridge_client_pid=80748, original_registry_owner_pid=17892, old_tasks_current_public_result="unknown task", original_owner_access_resolution="Pending user/maintenance response; no service restart or alternate private worker route", new_fourth_dispatches=0, services_started_or_restarted=0, archived_S06_operations=0, manual_wsl_process_inspection=False, clock_problem_resolved=False, actual_blockers=["S01 third actual delivery failed two real native standard-origin probes; count3, no fourth dispatched", "Original owner has exited; current public Bridge cannot access old task/session", "Astra consumers still require final delivery and independent acceptance", "Coordinator full native consumer/recovery/P-R-E/current Validator checks await accepted S01 and Astra", "Controlled Root intake and new complete union/quality are required after integration acceptance"], separate_unaccepted=["Real-project/LLM effect acceptance", "Full S01/S08/U01 and remaining parent DAG packages", "S09 formal benchmark and portable smoke", "Conditional S10/Q01/Q02", "External waits and host-clock issue"])
out = ROOT / "artifacts" / ("coordinator-module-progress-r26-" + uuid.uuid4().hex[:12])
out.mkdir(exist_ok=False)
write(out / "review.json", proof)
ledger["bridge"].update(status="original_owner_exited_current_public_instance_unknown_old_tasks", original_owner_pid=80748, current_owner_pid=None, original_registry_owner_pid=17892, operational_evidence="artifacts/coordinator-resume-r26-20261016/public-bridge-observation.json", service_restarted_by_coordinator=False)
ledger.update(updated_at=at, latest_module_progress=(out / "review.json").relative_to(ROOT).as_posix(), current_root_status="R23 exact2551/171/six remains current; S01 third failed2probes/count3; S08 MINcodec321 independently accepted stage-only; Store/Queue focused receipt; Astra consumers resumed WIP; original public owner unavailable", next_module_tasks=summaries)
assert hashlib.sha256((HERE / "tasks.json").read_bytes()).hexdigest() == hashlib.sha256(ledger_bytes).hexdigest()
write(HERE / "tasks.json", ledger)
continuation = read(HERE / "continuation-r6.json")
continuation.update(updated_at=at, active_phase=ledger["current_root_status"], latest_handoff=ledger["latest_module_progress"], next_module_tasks=summaries, whole_packages_complete=False, original_bridge_owner_available=False, service_restart_forbidden=True)
write(HERE / "continuation-r6.json", continuation)
note = f"""## {at} · R26 current receipt and remaining dependency fence

Root remains the accepted R23 version, finished {joint['finished_at']}: 2551 passed /171 files /six commands0, zero failure/error/skip. All1065 bound inputs currently match. No new Root intake and no redundant unchanged-Root run. The old pytest capture ENOENT was reproduced on DrvFS and fixed with ext4/default-fd launching; the519 pre-import result is historical. The.18 timing oracle remains unchanged; host-clock observations remain unresolved.

S01 task_f702313db8 /sess_6ecde27723 completed13:30:57 in original persisted terminal records. Existing independent160 cases and four commands pass, but three new real native same-ABI origin probes have1pass/2fail: joined-isystem and relative pragma-system headers still grant standard malloc authority. Independent source review has2P1. Third candidate and old deliveries are frozen; this is one third-delivery failure, cumulative consecutive failed actual deliveries3. No S01 copy into coordinator stage orRoot; no fourth dispatch.

S08 task_0d7256802a /sess_d9cfbf4113 completed13:27:14 in original persisted terminal records. Independent321/0/0/0 and four commands0, preserved prior JUnit identities and nine external probes, plus exact-SHA source review, accept only the isolated MIN codec. The two accepted files have been copied into coordinator isolation; Root and the complete S08 recovery package remain unaccepted. Both prior failed deliveries stay recorded; the MIN-codec counter resets only after this independent acceptance. Controlled actual SQL/WorkQueue/scheduler/codec focused result: {focus['junit']}; commands {[result['returncode'] for result in focus['commands']]}; passed={focus['focused_checks_passed']}; finished {focus['finished_at']}. This is not native producer closure, full P/R/E accounting or current all-restored Validator acceptance.

Astra same actual /root/astra_design_contract_r23, logical ASTRA-INSTANCE-CONSUMERS-R25, resumed tools14:34:15 in the original workspace after quota interruption. Original manifests and partial files retained. At15:09:49, three independently reviewed shared test migrations were copied by the coordinator only into Astra's matching revision10 workspace during an acknowledged safe window; not into Stage catalog9 or Root. Ownership extension02 grants the one concrete shared_access.py atomic-string suppression seam, for eleven exclusive paths and1060 effective readonly inputs verified unchanged. Existing first broader regression415pass/8fail/5skip remains historical; fixture and native-environment failures must be rerun with all original cases and zero skips, not reclassified as passed. Work remains in progress until a final artifact and independent review; producer intermediate test counts are not added toRoot acceptance. Coordinator owns only shared isolated wiring/docs/tests and its explicitly extended paths. Kimi new work stays paused under current DISPATCH_POLICY; ordinary producer repairs remain fixed ZCode GLM, complex consumers/UI remain Astra. No routing bypass.

Original Bridge client80748 and registry owner17892 have exited. The currently attached public Bridge returned unknown-task for both current third-round IDs; full persisted terminal/result/dispatch and source hashes are reconciled, but no fresh live public confirmation is claimed. Original task public access restoration awaits user/maintenance response. No new service, private worker route, duplicate task, archived S06 operation or manual WSL process inspection.

Next dependency path: resolve original public task access and S01 authority repair; in parallel finish Astra consumers and independent Store/Queue checks -> accepted dependency intake into coordinator stage -> complete native recovery/atomic Ledger/queue/owner/current-validator verification and quality -> independent source acceptance -> controlled Root intake -> new full selected Root union/six commands. Existing S02–S07 shared/dependent work, remaining U01/U02 UX and S09 integration are not promoted from partial slices. Real-project/LLM effects, formal/portable, conditional S10/Q01/Q02 and external waits remain separate. Evidence {out.relative_to(ROOT).as_posix()}/review.json.

---

"""
for name in ("PROGRESS.md", "DAG.md"):
    path = HERE / name
    path.write_text(note + path.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
(HERE / "CURRENT_STATE_R26.md").write_text(note, encoding="utf-8", newline="\n")
assert all(sha(ROOT / path) == digest for path, digest in root_sources.items())
print(json.dumps(dict(at=at, receipt=(out / "review.json").relative_to(ROOT).as_posix(), root_bound_inputs_unchanged=1065, stage_store_queue_junit=focus["junit"], stage_store_queue_passed=focus["focused_checks_passed"]), ensure_ascii=False))
