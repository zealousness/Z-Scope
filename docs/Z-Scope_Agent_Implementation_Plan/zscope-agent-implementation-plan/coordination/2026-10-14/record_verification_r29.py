"""Record bounded Store acceptance, rejected consumers and public Bridge block."""
from collections import Counter
from pathlib import Path
import datetime as dt
import hashlib
import json
import sys
import xml.etree.ElementTree as ET

assert sys.platform == "linux" and not sys.flags.optimize
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
STAGE = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
OUT = ROOT / "artifacts/coordinator-current-verification-r29-20261017"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def cases(path):
    return Counter((node.get("classname", ""), node.get("name", "")) for node in ET.parse(path).getroot().iter("testcase"))


root_inputs = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
assert len(root_inputs) == 1065 and all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
store_dir = ROOT / "artifacts/coordinator-store-queue-r26-e0560b7b2e9d"
store = read(store_dir / "review.json")
assert store["focused_checks_passed"] and store["junit"] == dict(tests=227, failures=0, errors=0, skipped=0)
assert store["sources_unchanged"] and store["root_unchanged"] and store["references_unchanged"]
assert all(sha(STAGE / path) == digest for path, digest in store["source_before"].items())
review_path = ROOT / "artifacts/store-queue-source-review-r28-20261017/review.json"
assert sha(review_path) == "ea8767f3dcb3bbc59666036fa2f0031bd9007df75d1d23b5a31b4622f9d5faee"
review = read(review_path)
assert review["source_review_passed"] and not review["blocking_findings"] and review["sources_match_current_verification_source_before"]
old_cases = cases(ROOT / "artifacts/coordinator-store-queue-r26-685a86a32485/results.xml")
initial_cases = cases(ROOT / "artifacts/coordinator-store-queue-r26-37b61af05c3f/results.xml")
failed_probe_cases = cases(ROOT / "artifacts/coordinator-store-receipt-bounds-probe-r26-20261016/results.xml")
assert initial_cases == old_cases and len(old_cases) == 226 and len(failed_probe_cases) == 1
assert cases(store_dir / "results.xml") == old_cases + failed_probe_cases
astra_dir = ROOT / "artifacts/coordinator-astra-consumers-r28-20261017"
astra = read(astra_dir / "review.json")
assert astra["candidate_independent_execution_checks_passed"] and astra["junit"] == dict(tests=852, failures=0, errors=0, skipped=0)
failure_path = ROOT / "artifacts/astra-consumer-failure-freeze-r28-20261017/review.json"
failure = read(failure_path)
assert failure["actual_failed_delivery_ordinal"] == 1 and not failure["candidate_accepted"]
history_path = failure_path.parent / "history-preservation.json"
history = read(history_path)
assert history["all129_producer_artifacts_copied"] and len(history["copied_files"]) == 129
bridge_path = ROOT / "artifacts/coordinator-bridge-readonly-r29-20261017/review.json"
bridge = read(bridge_path)
assert not bridge["public_original_tasks_restored"] and len(bridge["results"]) == 5
state_path = ROOT / ".coordination/20261014/bridge-route-check/state.json"
assert sha(state_path) == "a7b8c7bb52be3e4eb2a3a50ad7ff872abde794529f0a5682379ec5cd0bf7a4a3"
manifest_path = HERE / "followups-r12/consumer-exact-repair-r29-ownership.json"
manifest = read(manifest_path)
assert len(manifest["source_baseline"]) == 1071 and len(manifest["readonly_paths"]) == 1068
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
OUT.mkdir(exist_ok=False)
store_acceptance = dict(
    accepted_at=at, actual_task="/root", producer_scope="COORD-INSTANCE-INTEGRATION-R24 isolated Store/Queue fence",
    execution_receipt=(store_dir / "review.json").relative_to(ROOT).as_posix(), execution_sha256=sha(store_dir / "review.json"),
    execution_finished_at=store["finished_at"], junit=store["junit"], commands_zero=all(row["returncode"] == 0 for row in store["commands"]),
    source_review=review_path.relative_to(ROOT).as_posix(), source_review_sha256=sha(review_path), source_review_actual_task=review["actual_task"], source_review_frozen_at=review["frozen_at"],
    original226_case_counter_preserved=True, original_long_usr_failed_probe_now_passes=True,
    resolved_finding="SQ-R26-01", independent_bounded_source_and_functional_acceptance=True,
    source_current=store["source_before"], source_guards_current=True,
    scope="Current SQL receipt bounds and Store/Queue fence only; oversize receipt rejected before queue mutation. No full native instance/PRE/current Validator authority or complete Stage/S08 acceptance.",
    prior_failures_retained=True, source_already_in_coordinator_isolation=True,
    new_root_intake=False, full_stage_mypy_accepted=False, whole_s08_accepted=False, root_joint_pass=False,
)
write(OUT / "store-bounded-acceptance.json", store_acceptance)
dispatch = dict(recorded_at=at, logical_task="CONSUMER-EXACT-REPAIR-R29", parent_logical_task="ASTRA-INSTANCE-CONSUMERS-R25", actual_task="/root/consumer_exact_repair_r29", bridge_task_id=None, route="native collaboration", model="gpt-6.1-sol", reasoning_effort="xhigh", dispatched=True, actually_started=True, start_acknowledgement="R29 已开始；唯一写工作区与3文件所有权已核对。", ownership_manifest=manifest_path.relative_to(ROOT).as_posix(), ownership_manifest_sha256=sha(manifest_path), owned_paths=manifest["owned_paths"], frozen_original_not_resumed=True, source_work_not_duplicate=True, ui_astra_ownership_unchanged=True, root_stage_readonly=True, repair_artifacts_available=False, independent_acceptance=False, integrated=False, joint_verification=False)
write(OUT / "consumer-repair-dispatch.json", dispatch)
proof = dict(recorded_at=at, actual_task="/root", root_r23=dict(junit_passed=2551, test_files=171, six_commands_zero=True, pinned_inputs_current=1065, new_intake=False, new_rerun=False), store=store_acceptance, astra=dict(actual_producer_task="/root/astra_design_contract_r23", app_thread_id="01a1427c-30d0-7e72-b837-a2c399ecb982", independent_852=astra["junit"], independent_852_finished_at=astra["finished_at"], all4_commands_zero=True, external_probes=dict(tests=3, failures=3, errors=0, skipped=0), source_blockers=["R28-F1 P1", "R28-F2 P2"], consecutive_failed_actual_deliveries=1, frozen_failure_receipt=failure_path.relative_to(ROOT).as_posix(), complete_history_receipt=history_path.relative_to(ROOT).as_posix(), independent_acceptance=False, stage_intake=False, root_intake=False), consumer_repair=dispatch, bridge_receipt=bridge_path.relative_to(ROOT).as_posix(), public_original_access_restored=False, s01=dict(task_id="task_f702313db8", session_id="sess_6ecde27723", consecutive_failed_actual_deliveries=3, two_origin_p1_unresolved=True, fourth_dispatched=False), s08=dict(task_id="task_0d7256802a", session_id="sess_d9cfbf4113", min_codec_independently_accepted=True, independent_junit=dict(tests=321, failures=0, errors=0, skipped=0), stage_only_intake=True, root_intake=False, whole_s08_accepted=False), platform=dict(prior_rejection_preserved="artifacts/coordinator-maintenance-handoff-r27-20261016/platform-interruption.json", normal_tools_current_turn_executed_store_and_consumer_checks=True, new_rejection_observed=False, universal_lifting_claimed=False, alternate_private_routes_used=False), services_started_or_restarted=0, bridge_dispatches=0, archived_s06_operations=0, tests_executed_by_this_record_script=0, whole_packages_complete=False, separate_unaccepted=["Original public Bridge owner/session recovery", "S01 fourth actual original-module repair and independent native authority acceptance", "Consumer repair and its independent acceptance", "Full Stage native instance closure, PRE/current Validator and quality", "Controlled Root intake and new joint union after changed dependencies", "Real-project/LLM effects, conditional S10/Q01/Q02, formal/portable and other external waits"])
write(OUT / "review.json", proof)
ledger = read(HERE / "tasks.json")
rows = {row["id"]: row for row in ledger["tasks"]}
assert rows["S01-INSTANCE-SEMANTICS-MIN-R23"]["consecutive_failed_actual_deliveries"] == 3
rows["ASTRA-INSTANCE-CONSUMERS-R25"].update(status="actual_frozen_delivery_rejected_two_source_findings_three_independent_probe_failures_r29_isolated_repair_running", independent_result=astra["junit"], independent_execution_receipt=(astra_dir / "review.json").relative_to(ROOT).as_posix(), consecutive_failed_actual_deliveries=1, failure_record=failure_path.relative_to(ROOT).as_posix(), failure_history=history_path.relative_to(ROOT).as_posix(), source_review="artifacts/astra-consumers-source-review-r28-20261017/review.json", external_probe_receipt="artifacts/coordinator-consumer-boundary-probes-r28-20261017/review.json", repair_task="CONSUMER-EXACT-REPAIR-R29", independent_acceptance=False, integrated=False, joint_verification=False, checked_at=at)
rows["COORD-INSTANCE-INTEGRATION-R24"].update(status="isolated_store_bounds_repair_227_and_independent_source_review_accepted_full_dependencies_pending", store_bounds_repair_verified=True, store_bounded_acceptance=(OUT / "store-bounded-acceptance.json").relative_to(ROOT).as_posix(), store_result=store["junit"], independent_acceptance=False, integrated=False, joint_verification=False, full_stage_mypy_accepted=False, checked_at=at)
assert "CONSUMER-EXACT-REPAIR-R29" not in rows
new_row = dict(id="CONSUMER-EXACT-REPAIR-R29", title="Exact consumer authority boundary incremental repair", workspace="consumer-exact-repair-r29", parent_logical_task="ASTRA-INSTANCE-CONSUMERS-R25", actual_task="/root/consumer_exact_repair_r29", requested_model="gpt-6.1-sol", reasoning_effort="xhigh", status="dispatched_actually_started_owned_three_files", producer_status="running", artifact_available=False, independent_acceptance=False, integrated=False, joint_verification=False, ownership_manifest=manifest_path.relative_to(ROOT).as_posix(), dispatch_receipt=(OUT / "consumer-repair-dispatch.json").relative_to(ROOT).as_posix(), parent_failure_count_preserved=1, created_at=at, checked_at=at)
ledger["tasks"].append(new_row)
rows[new_row["id"]] = new_row
ledger.update(updated_at=at, latest_handoff=(OUT / "review.json").relative_to(ROOT).as_posix(), bridge_public_access_observation=proof["bridge_receipt"], current_root_status="R23 exact2551/171/six current; Store227 bounded independent acceptance; original consumer852 passes but rejected by3probes/2sourcefindings, one delivery failure; isolated6.1sol/xhigh R29 repair running; original S01/S08 public unknown; S01 count3 fourth not dispatched")
ledger["next_module_tasks"] = [{key: rows[identity].get(key) for key in ("id", "actual_task", "bridge_task_id", "bridge_session_id", "status", "producer_status", "artifact_available", "independent_acceptance", "integrated", "joint_verification", "consecutive_failed_actual_deliveries")} for identity in ("S01-INSTANCE-SEMANTICS-MIN-R23", "S08-INSTANCE-RECOVERY-MIN-R23", "ASTRA-INSTANCE-CONSUMERS-R25", "CONSUMER-EXACT-REPAIR-R29", "COORD-INSTANCE-INTEGRATION-R24")]
write(HERE / "tasks.json", ledger)
continuation = read(HERE / "continuation-r6.json")
continuation.update(updated_at=at, active_phase=ledger["current_root_status"], latest_handoff=ledger["latest_handoff"], next_module_tasks=ledger["next_module_tasks"], bridge_public_access_observation=proof["bridge_receipt"], store_bounded_acceptance=rows["COORD-INSTANCE-INTEGRATION-R24"]["store_bounded_acceptance"], whole_packages_complete=False)
write(HERE / "continuation-r6.json", continuation)
note = f"""## {at} · R29 current verification and isolated consumer repair

Root R23 remains the current selected union:2551 passed/171files/sixcommands0; all1065 pinned inputs still match. No new Root intake or redundant unchanged Root rerun. Counts below have different scopes and must not be added.

Original public Bridge check_task/get_result still returned unknown task for task_f702313db8 and task_0d7256802a at{bridge['finished']} (UTC). list_sessions scope=current_instance returned empty, other_live_instances=4. Original persisted state SHA remains a7b8c7bb52be3e4eb2a3a50ad7ff872abde794529f0a5682379ec5cd0bf7a4a3. Maintenance chat 定位代理路由协议故障(01a1387a-0b36-750e-94ef-b034942e3017) had stopped before service start at its prior preflight; current targeted Windows inventory is now readable but does not prove inherited home/owner mapping. Restoration remains external; coordinator started no service, made no replacement Bridge dispatch and did not touch archivedS06-R02. Current manual Bridge policy contains the human6.1-sol/xhigh preference. Readonly receipt:{proof['bridge_receipt']}.

Store SQ-R26-01 is now independently accepted only for the isolated receipt-bounds/StoreQueue fence. Execution ended{store['finished_at']}:227/0/0/0, all3commands0, fullcompileall and focusedBlack checks; exact226case Counter plus the original long-USR failed probe preserved. Independent source reviewer /root/store_source_review_r28 froze{review['frozen_at']}, no new blocker. Receipt metadata is checked for lossless real bounded_event_data normalization before queue mutation; oversize receipts create no reusable SQL result. Acceptance:{(OUT / 'store-bounded-acceptance.json').relative_to(ROOT).as_posix()}. Old226pass and all failures remain. This does not accept fullStage/nativePRE/currentValidator/completeS08; the last full Stage mypy diagnostic still records20errors and has not been replaced by a passing full check.

Astra actual /root/astra_design_contract_r23 /appthread01a1427c-30d0-7e72-b837-a2c399ecb982 remains frozen. Independent original26file check ended{astra['finished_at']}:852/0/0/0, all4commands0. Independent public-entry boundary probes are3fail/0error/0skip, and source reviewer /root/consumer_source_review_r28 found R28-F1(P1: unverified unique_ptr/shared_ptr spelling suppresses an obligation) and R28-F2(P2: case-insensitive helper lets unregistered MALLOC borrow malloc capability). Candidate rejected; exactly one failed actual delivery recorded, not three rounds. Original11owned sources, declared release artifacts and all129history files frozen at{failure_path.parent.relative_to(ROOT).as_posix()}; no original workspace/source edits or intake.

Only permitted non-UI incremental repair /root/consumer_exact_repair_r29 is dispatched and actually started in its distinct consumer-exact-repair-r29 copy, gpt-6.1-sol/xhigh. It exclusively owns3files;1068other source inputs and Root/Stage/original remain readonly. Existing852identities and immutable3externalprobes are required; no lower standard, no UI reassignment, no Bridge fallback. Dispatch:{(OUT / 'consumer-repair-dispatch.json').relative_to(ROOT).as_posix()}. It has no frozen repaired delivery or independent acceptance yet.

S01 task_f702313db8 remains third-delivery rejected/two originP1/count3; fourth not dispatched. S08 task_0d7256802a remains321-case MINcodec accepted Stage-only, not completeS08/Root. Wait for original public access and actual dependencies before S01fourth/fullnativeStage/Rootjoint. Supported current-turn tools executed the authorized Store and consumer checks normally; the prior platform rejection is preserved separately and no global platform clearance or bypass is claimed.

Real-project effects, parentS01/S08/U01 and downstream packages, formal/portable, conditionalS10/Q01/Q02, clock and external waits remain separately unaccepted. Evidence:{(OUT / 'review.json').relative_to(ROOT).as_posix()}.

---

"""
for name in ("PROGRESS.md", "DAG.md"):
    path = HERE / name
    path.write_text(note + path.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
(HERE / "CURRENT_STATE_R29.md").write_text(note, encoding="utf-8", newline="\n")
assert all(sha(ROOT / path) == digest for path, digest in root_inputs.items())
(OUT / "launcher.py").write_bytes(Path(__file__).read_bytes())
print(json.dumps(dict(recorded_at=at, receipt=(OUT / "review.json").relative_to(ROOT).as_posix(), store_bounded_accepted=True, astra_failed_delivery_count=1, s01_failed_delivery_count=3, native_consumer_repair_started=True, root_intake=False)))
