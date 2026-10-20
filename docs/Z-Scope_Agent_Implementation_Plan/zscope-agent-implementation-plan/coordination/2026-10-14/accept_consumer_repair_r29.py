"""Accept only the independently validated consumer slice; leave Root unchanged."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import re
import subprocess
import sys

assert sys.platform == "linux" and not sys.flags.optimize
assert len(sys.argv) == 2 and re.fullmatch(r"[0-9a-f]{64}", sys.argv[1])
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
BRANCH = ROOT / ".coordination/20261014/workspaces/consumer-exact-repair-r29"
STAGE = ROOT / ".coordination/20261014/workspaces/coordinator-instance-integration-r24"
OUT = ROOT / "artifacts/coordinator-consumer-acceptance-r29-20261017"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


source_path = ROOT / "artifacts/consumer-repair-source-review-r29-20261017/review.json"
assert sha(source_path) == sys.argv[1]
source = read(source_path)
assert source["source_review_passed"] and not source.get("blocking_findings", [])
assert source["actual_task"] == "/root/consumer_source_review_r28"
execution_path = ROOT / "artifacts/coordinator-consumer-repair-r29-20261017/review.json"
assert sha(execution_path) == "17d9886ccb5405ebf27f21600678d56f9e44bdc2a58b16caadabb98b4edbbb77"
execution = read(execution_path)
assert execution["independent_execution_checks_passed"]
assert execution["junit"] == dict(tests=893, failures=0, errors=0, skipped=0)
assert all(row["returncode"] == 0 for row in execution["commands"])
for key in ("prior852_and_external3_preserved", "producer_full_case_counter_exact", "sources_unchanged", "root_unchanged", "original_failed_candidate_unchanged", "original129_history_and_failure_freeze_unchanged", "references_unchanged"):
    assert execution[key]
assert len(execution["source_before"]) == 1071 and all(sha(BRANCH / path) == digest for path, digest in execution["source_before"].items())
assert all(sha(Path(path)) == digest for path, digest in execution["references_sha256"].items())
producer_path = BRANCH / "artifacts/consumer-exact-repair-r29/review.json"
assert sha(producer_path) == "6e59aa5d3119ba21beadecebab746d66e1ed267a800956fcf4f010a36485ea13"
producer = read(producer_path)
assert all(sha(BRANCH / path) == digest for path, digest in producer["source_after"].items())
root_sources = read(ROOT / "artifacts/coordinator-r23-ui-projection-union-20261016/source-evidence.json")["after"]
assert len(root_sources) == 1065 and all(sha(ROOT / path) == digest for path, digest in root_sources.items())
head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
assert head == "010f40210b54ba0f79a088312ce5d8be3a82ace0"
store_path = ROOT / "artifacts/coordinator-current-verification-r29-20261017/store-bounded-acceptance.json"
store = read(store_path)
assert store["independent_bounded_source_and_functional_acceptance"]
assert all(sha(STAGE / path) == digest for path, digest in store["source_current"].items())
bridge_path = ROOT / "artifacts/coordinator-bridge-readonly-final-r29-20261017/review.json"
bridge = read(bridge_path)
assert not bridge["maintenance"]["original_access_restored"]
assert sha(ROOT / ".coordination/20261014/bridge-route-check/state.json") == "a7b8c7bb52be3e4eb2a3a50ad7ff872abde794529f0a5682379ec5cd0bf7a4a3"
assert not (ROOT / "zscope/semantics/instance_semantics.py").exists()
assert not (STAGE / "zscope/semantics/instance_semantics.py").exists()
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
OUT.mkdir(exist_ok=False)
references = {path.relative_to(ROOT).as_posix(): sha(path) for path in (source_path, execution_path, producer_path, store_path, bridge_path, ROOT / "artifacts/astra-consumer-failure-freeze-r28-20261017/review.json", ROOT / "artifacts/astra-consumer-failure-freeze-r28-20261017/history-preservation.json")}
proof = dict(accepted_at=at, actual_coordinator_task="/root", logical_task="CONSUMER-EXACT-REPAIR-R29", parent_logical_task="ASTRA-INSTANCE-CONSUMERS-R25", actual_producer_task="/root/consumer_exact_repair_r29", producer_model="gpt-6.1-sol", producer_reasoning_effort="xhigh", producer_frozen_at=producer["frozen_at"], actual_source_reviewer_task=source["actual_task"], independent_execution_finished_at=execution["finished_at"], independent_result=execution["junit"], four_commands_zero=True, source_review_passed=True, resolved_findings=["R28-F1", "R28-F2"], accepted_scope="Frozen exact consumer boundary slice only: two repaired literal authority seams, retained legacy behavior, original852 plus new38 and immutable3, compiler/type/style checks. Controlled semantics/public probes and existing native regressions do not accept current S01 factory, full native instance scan, PRE/current Validator, completeS08/U01, real-project effects or whole packages.", accepted_candidate_source=producer["source_after"], previous_actual_failed_deliveries=1, previous_failed_delivery_receipts_retained=True, parent_consecutive_failures_after_independent_slice_acceptance=0, original_astra_delivery_rejection_retained=True, new_test_oracle_and_metadata_failures_retained=True, independent_acceptance=True, coordinator_stage_intake=False, root_intake=False, root_joint_verification=False, root_r23_unchanged=dict(head=head, pinned_inputs=1065, selected_union_tests=2551, selected_test_files=171, six_commands_zero=True, new_rerun=False), store_bounded_acceptance=store_path.relative_to(ROOT).as_posix(), s01=dict(task_id="task_f702313db8", session_id="sess_6ecde27723", consecutive_failed_actual_deliveries=3, fourth_dispatched=False, original_public_access=False, two_origin_p1_remain=True), original_s08_task_id="task_0d7256802a", bridge_observation_finished_utc=bridge["finished"], bridge_public_access_restored=False, original_bridge_state_unchanged=True, services_started_or_restarted=0, replacement_bridge_dispatches=0, archived_s06_operations=0, private_routes_used=0, platform_bypass=False, whole_packages_complete=False, references_sha256=references)
write(OUT / "review.json", proof)
next_actions = dict(recorded_at=at, original_s01_task_id="task_f702313db8", original_s01_session_id="sess_6ecde27723", fourth_dispatched=False, same_logical_failure_count=3, threshold_and_failure_history_preserved=True, independent_store_scope_ready=True, independent_consumer_scope_ready=True, original_public_access_required_before_dispatch=True, original_owner_and_all_live_ownership_required_before_dispatch=True, archived_s06_never_resumed=True, pending_original_repair_spec="followups-r12/s01-repair-r26-pending.md", unchanged_required_source_and_probe_reviews=["artifacts/s01-module-source-review-r26-20261016/review.json", "artifacts/coordinator-s01-origin-forms-r26-20261016/review.json"], subsequent_work=["Original S01 fourth repair/independent acceptance through restored supported owner/session", "Coordinator-owned integration of accepted modules and consumer/catalog dependencies into isolated Stage", "Resolve coordinator type/currentness/collection wiring obligations and run full native instance/PRE/current Validator integration checks and quality", "Controlled shared Root intake only after exact current acceptance, then new full selected union and all required quality checks"], actual_blockers=["Original public tasks still unknown; maintenance stopped before service start and existing app message binding is unchanged", "S01 third delivery retains two native-origin authority P1 findings", "Full Stage quality and native instance/restore/current Validator integration not accepted"], separate_unaccepted=["Whole S01/S08/U01 and downstream packages", "Real-project/LLM scan effects", "ConditionalS10/Q01/Q02, formal/portable and external waits"], root_product_writes_authorized_by_this_record=False)
write(OUT / "next-actions.json", next_actions)
ledger = read(HERE / "tasks.json")
rows = {row["id"]: row for row in ledger["tasks"]}
assert rows["S01-INSTANCE-SEMANTICS-MIN-R23"]["consecutive_failed_actual_deliveries"] == 3
parent = rows["ASTRA-INSTANCE-CONSUMERS-R25"]
assert parent["consecutive_failed_actual_deliveries"] == 1
parent.update(status="repaired_exact_consumer_slice_independently_accepted_r29_original_failure_preserved_no_intake", original_delivery_independent_acceptance=False, accepted_repair_task="CONSUMER-EXACT-REPAIR-R29", prior_failed_actual_deliveries_before_acceptance=1, consecutive_failed_actual_deliveries=0, independent_acceptance=True, independent_acceptance_scope=proof["accepted_scope"], accepted_repair_receipt=(OUT / "review.json").relative_to(ROOT).as_posix(), independent_result=execution["junit"], integrated=False, coordinator_stage_intake=False, joint_verification=False, checked_at=at)
parent["actual_delivery_rounds"] = [dict(round=1, actual_task="/root/astra_design_contract_r23", source_review="artifacts/astra-consumers-source-review-r28-20261017/review.json", execution="artifacts/coordinator-astra-consumers-r28-20261017/review.json", external_probes="artifacts/coordinator-consumer-boundary-probes-r28-20261017/review.json", accepted=False, counted_development_failure=True), dict(round=2, actual_task="/root/consumer_exact_repair_r29", acceptance=(OUT / "review.json").relative_to(ROOT).as_posix(), accepted=True, counted_development_failure=False, accepted_scope="bounded exact consumer slice only")]
repair = rows["CONSUMER-EXACT-REPAIR-R29"]
repair.update(status="frozen_893_independent_execution_and_source_review_passed_slice_accepted_no_stage_or_root_intake", producer_status="completed", artifact_available=True, independent_acceptance=True, independent_acceptance_scope=proof["accepted_scope"], independent_result=execution["junit"], independent_execution_receipt=execution_path.relative_to(ROOT).as_posix(), source_review=source_path.relative_to(ROOT).as_posix(), accepted_at=at, acceptance_receipt=(OUT / "review.json").relative_to(ROOT).as_posix(), integrated=False, coordinator_stage_intake=False, joint_verification=False, checked_at=at)
ledger.update(updated_at=at, latest_handoff=(OUT / "review.json").relative_to(ROOT).as_posix(), latest_next_actions=(OUT / "next-actions.json").relative_to(ROOT).as_posix(), bridge_public_access_observation=bridge_path.relative_to(ROOT).as_posix(), current_root_status="R23 exact2551/171/six remains current; Store227 bounded accepted; consumerR29 893/fourcommands0 plus independent source review accepted only as isolated slice, original failure preserved; no new intake; original S01/S08 public unknown, S01 count3 fourth not dispatched; full Stage/native/quality pending")
ledger["next_module_tasks"] = [{key: rows[identity].get(key) for key in ("id", "actual_task", "bridge_task_id", "bridge_session_id", "status", "producer_status", "artifact_available", "independent_acceptance", "integrated", "joint_verification", "consecutive_failed_actual_deliveries")} for identity in ("S01-INSTANCE-SEMANTICS-MIN-R23", "S08-INSTANCE-RECOVERY-MIN-R23", "ASTRA-INSTANCE-CONSUMERS-R25", "CONSUMER-EXACT-REPAIR-R29", "COORD-INSTANCE-INTEGRATION-R24")]
write(HERE / "tasks.json", ledger)
continuation = read(HERE / "continuation-r6.json")
continuation.update(updated_at=at, active_phase=ledger["current_root_status"], latest_handoff=ledger["latest_handoff"], next_module_tasks=ledger["next_module_tasks"], next_actions=ledger["latest_next_actions"], bridge_public_access_observation=ledger["bridge_public_access_observation"], whole_packages_complete=False)
write(HERE / "continuation-r6.json", continuation)
note = f"""## {at} · R29 bounded consumer repair independently accepted; original Bridge still blocked

Root R23 remains current:2551passed/171files/sixcommands0, HEAD{head}, all1065pinned inputs exact. No new Root intake or unchanged-root rerun. These scopes are separate and counts must not be added.

Store isolated receipt-bounds/fence acceptance remains current:227/0/0/0,3commands0, execution00:26:32; independent reviewer /root/store_source_review_r28 froze00:33:14. SQ-R26-01 resolved before queue mutation, old226Counter and original long-USR failure preserved. Scope only Store/Queue fence; wholeStage/S08/nativePRE/currentValidator not accepted. Receipt:{store_path.relative_to(ROOT).as_posix()}.

Original Astra consumer delivery /root/astra_design_contract_r23 /appthread01a1427c-30d0-7e72-b837-a2c399ecb982 is still historically rejected:852existing-suite pass did not cover two real defects, independent3probes failed. Its11owned sources and129history files remain frozen. Different actual repair /root/consumer_exact_repair_r29 (gpt-6.1-sol/xhigh) fixed exactly2product seams and appended38tests in a distinct3-owned/1068readonly workspace, frozen{producer['frozen_at']}. Coordinator independent execution ended{execution['finished_at']}:893/0/0/0, pytest/fullcompileall/mypy357/Black10 all0; exact852+38+immutable3Counter and source/config/control/Root/original129history guards all pass. Independent source reviewer /root/consumer_source_review_r28 passed the frozen repair with no blockers. Limited consumer slice accepted{at}, no Stage or Root intake, no joint/nativefactory/fullscan effect claim. Acceptance:{(OUT / 'review.json').relative_to(ROOT).as_posix()}. One prior actual failed delivery retained; consecutive count ends only after this slice acceptance. Four new-test oracle mistakes and metadata-finalizer error retained with real baseline correction evidence, not development deliveries. No old failure receipt overwritten.

Latest public Bridge check finished{bridge['finished']}UTC:task_f702313db8/task_0d7256802a stillunknown, currentinstance sessions empty/otherliveinstances4. Existing maintenance chat 定位代理路由协议故障 remains idle at its Oct16 16:27pre-service pause; no restored public owner, no new accepted maintenance message, no service start/restart. Its existing path binding is unchanged after two earlier failed official sends; no blind retry/private fallback. S01 third delivery stilltwoP1/count3/fourthnotdispatched. S08 MINcodec321 remains accepted Stage-only, not parentS08/Root. ArchivedS06-R02 untouched.

The next permitted dependency order and actual blockers are explicit in{(OUT / 'next-actions.json').relative_to(ROOT).as_posix()}:original public owner/session recovery → original S01fourth/independent authority acceptance → coordinator-owned fullStage integration/type/currentness/nativePRE/currentValidator checks → controlledRoot intake/newcomplete selectedunion+quality. Store/Astra finite checks do not pass fullStage quality; the last fullStage mypy diagnosis has no passing replacement. Real-project/LLM effects, wholeS01/S08/U01 and downstream work, formal/portable, conditionalS10/Q01/Q02 and external/clock waits remain separately unaccepted. No platform restriction bypass or global clearance claimed.

---

"""
for name in ("PROGRESS.md", "DAG.md"):
    path = HERE / name
    path.write_text(note + path.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
(HERE / "CURRENT_STATE_R29.md").write_text(note, encoding="utf-8", newline="\n")
assert all(sha(ROOT / path) == digest for path, digest in root_sources.items())
assert all(sha(ROOT / path) == digest for path, digest in references.items())
(OUT / "launcher.py").write_bytes(Path(__file__).read_bytes())
print(json.dumps(dict(accepted_at=at, receipt=(OUT / "review.json").relative_to(ROOT).as_posix(), consumer_independent_junit=execution["junit"], root_intake=False, s01_consecutive_failed_actual_deliveries=3)))
