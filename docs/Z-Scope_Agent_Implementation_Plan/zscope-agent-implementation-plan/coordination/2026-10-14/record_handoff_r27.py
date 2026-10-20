"""Administrative evidence handoff only; no product edits, tests or dispatch."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys
import xml.etree.ElementTree as ET

if sys.platform != "linux" or sys.flags.optimize:
    raise RuntimeError("Use non-optimized Linux Python for the evidence audit")
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
WORKER = ROOT / ".coordination/20261014/workspaces/astra-instance-consumers-r25"
ART = WORKER / "artifacts/instance-consumers-r25"
STAGE = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
OUT = ROOT / "artifacts/coordinator-maintenance-handoff-r27-20261016"

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def read(path):
    return json.loads(path.read_text(encoding="utf-8"))

def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

root_evidence = ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json"
root_sources = read(root_evidence)["after"]
assert len(root_sources) == 1065 and all(sha(ROOT / path) == digest for path, digest in root_sources.items())
producer_path = ART / "review.json"
assert sha(producer_path) == "5101d36e10090514e2b4dabb41536e8e555f4075701a0c9a0853fbf9ec544352"
producer = read(producer_path)
assert producer["actual_task"] == "/root/astra_design_contract_r23" and producer["candidate_complete"] and not producer["slice_accepted"]
assert all(sha(WORKER / path) == digest for path, digest in producer["source_after"].items())
assert all(sha(ART / path) == digest for path, digest in producer["artifact_sha256"].items())
suites = ET.parse(ART / "regression-05.xml").getroot().findall("testsuite")
counts = {key: sum(int(suite.get(key, "0")) for suite in suites) for key in ("tests", "failures", "errors", "skipped")}
assert counts == dict(tests=852, failures=0, errors=0, skipped=0)
effective_path = HERE / "followups-r12/astra-instance-consumers-r25-readonly-dependencies-r26.json"
effective = read(effective_path)
owned = set(producer["ownership"]["owned_paths"])
readonly = {entry["path"]: entry["sha256"] for entry in effective["files"] if entry["path"] not in owned}
assert len(owned) == 11 and len(readonly) == 1060
assert all(sha(WORKER / path) == digest for path, digest in readonly.items())
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
OUT.mkdir(exist_ok=False)
maintenance = dict(recorded_at=at, authorized_by_human=True, direct_human_answer="由维护会话恢复原任务公开访问", question_call_id="call_3bdf12a351774db4acfe4f6f03f20e66", destination_thread_id="01a1387a-0b36-750e-94ef-b034942e3017", destination_title="定位代理路由协议故障", original_bridge_home=".coordination/20261014/bridge-route-check", original_tasks=[dict(task_id="task_f702313db8", session_id="sess_6ecde27723"), dict(task_id="task_0d7256802a", session_id="sess_d9cfbf4113")], official_send_attempts=[dict(host_id="durable", result="invalid turn/start params: AbsolutePathBuf deserialized without a base path", accepted=False), dict(host_id="omitted optional hostId", result="invalid turn/start params: AbsolutePathBuf deserialized without a base path", accepted=False)], current_public_check_results={task: "KeyError: 'unknown task " + task + "'" for task in ("task_f702313db8", "task_0d7256802a")}, last_public_check_observed_plus08="2026-10-16T15:45+08:00 (minute precision)", delivered=False, public_access_restored=False, coordinator_services_started_or_restarted=0, replacement_workers_started=0, private_routes_used=0, scope="Only restore original public task/session access through supported maintenance procedures, avoiding duplicate owners. Do not resume code work blocked by platform review, dispatch worker turns or touch archived S06-R02.")
write(OUT / "maintenance-request.json", maintenance)
interruption = dict(source="Official read_thread for current chat, previous turn01a14367-0336-7ba1-ba50-9ceb93ef01a3", observed_at=at, previous_turn_status="failed", previous_turn_ended_at="2026-10-16T15:20:52+08:00", error="This content was flagged for possible cybersecurity risk.", current_turn_scope="User-authorized maintenance request and administrative preservation/model-policy sync", blocked_code_actions_retried=False, code_actions_transferred_to_other_agent=False, platform_restriction_lifted=False, worker_route_changed_to_bypass=False)
write(OUT / "platform-interruption.json", interruption)
store_path = STAGE / "zscope/orchestration/jobs/store.py"
focus_path = ROOT / "artifacts/coordinator-store-queue-r26-685a86a32485/review.json"
focus = read(focus_path)
assert focus["junit"] == dict(tests=226, failures=0, errors=0, skipped=0)
assert sha(store_path) != focus["source_before"]["zscope/orchestration/jobs/store.py"]
proof = dict(recorded_at=at, actual_task="/root", administrative_audit=True, root_bound_inputs_unchanged=1065, current_root_joint="artifacts/coordinator-r23-ui-projection-union-20261016/review.json", root_current_result=dict(passed=2551, failures=0, errors=0, skipped=0, test_files=171, six_commands_zero=True), new_root_intake=False, root_rerun=False, s01=dict(actual_task_id="task_f702313db8", source_review_blockers=2, consecutive_failed_actual_deliveries=3, fourth_dispatched=False), s08=dict(actual_task_id="task_0d7256802a", accepted_scope="isolated MIN codec only", independent_junit=dict(tests=321, failures=0, errors=0, skipped=0), coordinator_stage_intake=True, root_intake=False, complete_s08_accepted=False), astra=dict(actual_task="/root/astra_design_contract_r23", app_thread_id="01a1427c-30d0-7e72-b837-a2c399ecb982", producer_final_test_finished_at=producer["clock"]["final_test_finished_at"], producer_frozen_at=producer["clock"]["frozen_at_system_clock"], producer_junit_audited_readonly=counts, producer_review_sha256=sha(producer_path), owned_source_hashes_current=True, readonly_inputs_unchanged=1060, artifact_hashes_current=True, independent_test_execution=False, independent_acceptance=False, coordinator_stage_intake=False, root_intake=False), store=dict(last_pre_fix_passed_junit=focus["junit"], last_pre_fix_review=focus_path.relative_to(ROOT).as_posix(), new_failure_probe="artifacts/coordinator-store-receipt-bounds-probe-r26-20261016/review.json", source_finding="artifacts/store-queue-source-review-r26-20261016/initial-findings.json", current_store_source_sha256=sha(store_path), repair_written_to_isolation=True, repair_verified=False, repair_not_covered_by_previous226=True, stage_mypy_diagnostic="artifacts/coordinator-type-diagnostics-r26-45fbb8d057e7/review.json", stage_mypy_errors=20, stage_quality_accepted=False), maintenance_request=maintenance, platform_interruption=interruption, tests_executed_by_handoff=0, product_files_modified_by_handoff=0, services_started_or_restarted=0, dispatches=0, archived_S06_operations=0, whole_packages_complete=False, separate_unaccepted=["Real project / LLM effect acceptance", "Full S01/S08/U01 and dependent parent packages", "Formal benchmark / portable smoke", "Conditional S10/Q01/Q02", "External waits and host clock issue"])
write(OUT / "review.json", proof)
ledger = read(HERE / "tasks.json")
rows = {row["id"]: row for row in ledger["tasks"]}
astra = rows["ASTRA-INSTANCE-CONSUMERS-R25"]
astra.update(status="producer_candidate_frozen_852_selftests_readonly_evidence_audited_independent_acceptance_pending", producer_status="completed", artifact_available=True, work_in_progress_artifact_present=False, worker_finished_at=producer["clock"]["frozen_at_system_clock"], delivery_evidence=(WORKER / "DELIVERY.md").relative_to(ROOT).as_posix(), producer_review=producer_path.relative_to(ROOT).as_posix(), producer_review_sha256=sha(producer_path), producer_result=counts, producer_evidence_readonly_audited_at=at, readonly_inputs=1060, independent_acceptance=False, integrated=False, joint_verification=False, checked_at=at)
rows["COORD-INSTANCE-INTEGRATION-R24"].update(status="isolated_store_bounds_repair_unverified_after_platform_interruption_full_dependencies_pending", independent_acceptance=False, integrated=False, joint_verification=False, store_bounds_repair_verified=False, platform_interruption=proof["platform_interruption"], checked_at=at)
policy = ledger["current_worker_policy"]
policy.update(recorded_at=at, especially_complex_model="gpt-6.1-sol", complex_tasks_first_model="gpt-6.1-sol", complex_tasks_reasoning_effort="xhigh", complexity_alone_routes_to_astra=False, existing_tasks_not_redispatched=True, previous_glm_failure_counts_and_threshold_preserved=True, model_preference_is_not_permission_to_retry_platform_block=True, evidence="Trusted source-thread delegation conveying the human's 2026-10-16 exact preference: even particularly complex tasks first use6.1-sol, xhigh; no development continuation or blocked-action retry authorized by that preference.")
ledger.update(updated_at=at, bridge_maintenance_request=maintenance, latest_handoff=(OUT / "review.json").relative_to(ROOT).as_posix(), current_root_status="R23 exact2551/171/six remains current; S01 third rejected/count3; S08 MINcodec accepted stage-only; Store bounds repair unverified after platform interruption; Astra frozen852 selftests pending independent acceptance; maintenance request authorized but official send failed")
ledger["next_module_tasks"] = [{key: rows[identity].get(key) for key in ("id", "actual_task", "bridge_task_id", "bridge_session_id", "status", "producer_status", "worker_finished_at", "artifact_available", "independent_acceptance", "integrated", "joint_verification", "consecutive_failed_actual_deliveries")} for identity in ("S01-INSTANCE-SEMANTICS-MIN-R23", "S08-INSTANCE-RECOVERY-MIN-R23", "ASTRA-INSTANCE-CONSUMERS-R25", "COORD-INSTANCE-INTEGRATION-R24")]
write(HERE / "tasks.json", ledger)
continuation = read(HERE / "continuation-r6.json")
continuation.update(updated_at=at, active_phase=ledger["current_root_status"], latest_handoff=ledger["latest_handoff"], next_module_tasks=ledger["next_module_tasks"], bridge_maintenance_request=maintenance, platform_interruption=interruption, whole_packages_complete=False, model_preference_update=policy)
write(HERE / "continuation-r6.json", continuation)
note = f"""## {at} · R27 administrative handoff; maintenance request not delivered

Root R23 remains current:2551 passed/171 files/six commands0; all1065 bound inputs match now. No new Root intake or test rerun. Do not add worker/module counts to this result.

User directly selected maintenance restoration of original Bridge public task access. Two official send_message_to_thread attempts to existing chat 定位代理路由协议故障(01a1387a-0b36-750e-94ef-b034942e3017) both failed before message acceptance with AbsolutePathBuf deserialized without a base path; no delivery or restoration is claimed. Fresh public check_task still returns unknown task for task_f702313db8 and task_0d7256802a. Pending request and exact scope are saved in {OUT.relative_to(ROOT).as_posix()}/maintenance-request.json. Coordinator started/restarted no service, worker or private route.

The previous coordinator turn failed at15:20:52 with platform message possible cybersecurity risk. This is separate from the Bridge owner issue. This handoff performs only administrative preservation/read-only evidence audit; no affected code action is retried or transferred. The latest human model preference selects gpt-6.1-sol/xhigh first even for particularly complex permitted work. Existing results, GLM failure counts/threshold and other unchanged responsibilities are preserved; this preference does not lift platform restrictions or authorize resumption/retry.

S01 task_f702313db8 remains rejected with two origin P1 findings and three consecutive actual failed deliveries; no fourth turn dispatched. S08 task_0d7256802a remains independently accepted only as isolated321-case MIN codec, copied to coordinator isolation15:05:42; no Root or completeS08 acceptance. The coordinator's old226-case Store/Queue pass predates the real >4000-character receipt truncation failure at15:18. Store repair was written to isolation before interruption but has no post-fix verification or completed source acceptance. Full isolated mypy diagnostic retains20 errors, including unavailable producer interfaces and coordinator issues; Stage quality is not passed.

Astra actual /root/astra_design_contract_r23 /appthread01a1427c-30d0-7e72-b837-a2c399ecb982 has now frozen DELIVERY.md and review.json. Producer final test ended{producer['clock']['final_test_finished_at']}:852/0/0/0 across26files, including352new+500existing; producer compileall/mypy357/Black10 pass. This administrative read-only audit verified the actual XML, artifact hashes,11owned source hashes and1060readonly inputs. It executed no independent tests and grants no source/functional acceptance. No Astra candidate copy toStage/Root. All prior failures/observer interruption remain preserved.

Remaining: normal public-access maintenance, platform restriction resolution, S01 original authority obligation, independent Astra acceptance, Store repair verification and pending coordinator type issues, full native instance/recovery/current Validator integration, controlled Root intake and a new complete selected union plus quality. Real-project effects, parent S01/S08/U01 and downstream work, formal/portable, conditional S10/Q01/Q02 and external waits remain separate. Evidence {OUT.relative_to(ROOT).as_posix()}/review.json.

---

"""
for name in ("PROGRESS.md", "DAG.md"):
    path = HERE / name
    path.write_text(note + path.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
(HERE / "CURRENT_STATE_R27.md").write_text(note, encoding="utf-8", newline="\n")
assert all(sha(ROOT / path) == digest for path, digest in root_sources.items())
(OUT / "launcher.py").write_bytes(Path(__file__).read_bytes())
print(json.dumps(dict(at=at, receipt=(OUT / "review.json").relative_to(ROOT).as_posix(), root_bound_inputs_unchanged=1065, astra_producer_junit=counts, independent_tests_executed=0, maintenance_request_delivered=False, platform_blocked_code_retried=False)))
