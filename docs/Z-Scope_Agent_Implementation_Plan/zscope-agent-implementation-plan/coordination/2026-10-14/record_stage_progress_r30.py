"""Record actual Stage intake and independent repair progress, without full acceptance."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import re

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
OUT = ROOT / "artifacts/coordinator-stage-progress-r30-20261017"


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


intake_path = ROOT / "artifacts/consumer-stage-intake-r30-20261017/receipt.json"
intake = read(intake_path)
assert intake["stage_intake"] and len(intake["changed_paths"]) == 14 and not intake["root_intake"]
probe = read(ROOT / "artifacts/coordinator-stage-quality-probe-after-r30-20261017/review.json")
assert probe["bounded_checks_passed"] and probe["junit"] == dict(tests=14, failures=0, errors=0, skipped=0)
fresh_dir = ROOT / "artifacts/coordinator-stage-mypy-fresh-after-r30-20261017"
fresh = read(fresh_dir / "review.json")
assert fresh["commands"][0]["returncode"] == 1 and not fresh["bounded_checks_passed"]
errors = [line for line in (fresh_dir / "command-0.log").read_text(encoding="utf-8").splitlines() if re.match(r"zscope/.*: error:", line)]
assert len(errors) == 4 and all("zscope.semantics.instance_semantics" in line and "[import-untyped]" in line for line in errors)
at = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).isoformat()
OUT.mkdir(exist_ok=False)
proof = dict(recorded_at=at, actual_task="/root", stage_intake_receipt=intake_path.relative_to(ROOT).as_posix(), stage_intake_at=intake["integrated_at"], accepted_consumer_files_and_controlled_tests_copied=14, root_intake=False, independent_quality_repair_source="artifacts/stage-quality-repair-r30-20261017/repair-source.json", independent_probe=probe["junit"], independent_probe_actual_finished_at=probe["finished_at"], fresh_mypy_remaining_errors=errors, fresh_mypy_returncode=1, independent_eight_diagnostics_removed=True, full_stage_quality_passed=False, stage_regression="launched33repository files plus immutable external probe; final receipt pending", compileall_black="launched; final receipt pending", source_review_actual_task="/root/store_source_review_r28", source_review_pending=True, s01_failed_delivery_count_preserved=3, s01_fourth_dispatched=False, consumer_prior_actual_failed_delivery_preserved=1, services_started_or_restarted=0, bridge_dispatches=0, archived_s06_operations=0, whole_packages_complete=False)
write(OUT / "review.json", proof)
ledger = read(HERE / "tasks.json")
rows = {row["id"]: row for row in ledger["tasks"]}
for identity in ("ASTRA-INSTANCE-CONSUMERS-R25", "CONSUMER-EXACT-REPAIR-R29"):
    row = rows[identity]
    row.update(coordinator_stage_intake=True, coordinator_stage_intake_at=intake["integrated_at"], coordinator_stage_intake_receipt=proof["stage_intake_receipt"], stage_regression_pending=True, integrated=False, joint_verification=False, checked_at=at)
    row["status"] = "accepted_consumer_repair_integrated_to_stage_r30_current_stage_regression_and_quality_pending_no_root_intake"
assert rows["ASTRA-INSTANCE-CONSUMERS-R25"]["prior_failed_actual_deliveries_before_acceptance"] == 1
assert rows["S01-INSTANCE-SEMANTICS-MIN-R23"]["consecutive_failed_actual_deliveries"] == 3
coordinator = rows["COORD-INSTANCE-INTEGRATION-R24"]
coordinator.update(status="consumer14_intaken_stage_eight_independent_quality_errors_repaired_probe14_passed_full_fresh_mypy_four_s01_errors_regression_running", consumer_stage_intake=proof["stage_intake_receipt"], stage_quality_progress=(OUT / "review.json").relative_to(ROOT).as_posix(), stage_independent_probe_result=probe["junit"], fresh_mypy_remaining_error_count=4, fresh_mypy_returncode=1, full_stage_mypy_accepted=False, independent_acceptance=False, integrated=False, joint_verification=False, current_stage_revalidation_required_after_intake=True, checked_at=at)
ledger.update(updated_at=at, latest_handoff=(OUT / "review.json").relative_to(ROOT).as_posix(), bridge_public_access_observation="artifacts/coordinator-bridge-readonly-r30-20261017/review.json", current_root_status="RootR23 exact2551/171/six/1065 remains current; accepted consumer14 Stage intake; independent8quality diagnostics repaired and same14probes pass; full fresh mypy remains4S01importerrors/359 rc1; current boundedStage regression/quality/source review pending; S01 count3 fourth not dispatched")
for entry in ledger["next_module_tasks"]:
    row = rows[entry["id"]]
    entry.update({key: row.get(key) for key in entry})
    entry.update({key: row[key] for key in ("coordinator_stage_intake", "coordinator_stage_intake_receipt", "full_stage_mypy_accepted", "fresh_mypy_remaining_error_count") if key in row})
write(HERE / "tasks.json", ledger)
continuation = read(HERE / "continuation-r6.json")
continuation.update(updated_at=at, active_phase=ledger["current_root_status"], latest_handoff=ledger["latest_handoff"], next_module_tasks=ledger["next_module_tasks"], bridge_public_access_observation=ledger["bridge_public_access_observation"], whole_packages_complete=False)
write(HERE / "continuation-r6.json", continuation)
note = f"""## {at} · R30 Stage consumer intake and independent quality repair in verification

Current RootR23 remains2551passed/171files/sixcommands0 with1065bound inputs unchanged; no new Root intake or rerun. Do not add scope counts.

Official Bridge read-only check ended2026-10-16 17:18:48UTC: task_f702313db8/task_0d7256802a check_task andget_result unknown, currentinstance sessions empty/otherliveinstances5. Windows01:19inventory shows old PID80748 reused by a Node process createdOct17 00:17:48, not the original queue client; owner17892 absent. No inherited project-home ownership or public recovery is proven. Existing maintenance chat remains pre-service paused. Coordinator starts/restarts no service, sends no replacement Bridge task, does not restore archivedS06-R02. Evidence artifacts/coordinator-bridge-readonly-r30-20261017/review.json.

Human explicitly authorized current consumer Stage integration. Frozen accepted /root/consumer_exact_repair_r29 sources, existing11consumer files and3matching coordinator-controlled dependency tests copied at{intake['integrated_at']};14targets exclusively assigned by extension05, otherStage/Root inputs unchanged. Receipt{proof['stage_intake_receipt']}. Original consumer failed delivery1 and its repaired slice acceptance remain preserved; this is Stage integration, not Root integration or whole-package completion. Old893 andStore227 do not jointly validate this changed Stage.

Current independent quality repair is coordinator-only; reviewer /root/store_source_review_r28 (6.1-sol/xhigh) froze initial analysis570b398c… before code writes. Fresh pre-repair mypy12errors/5files/359 versus incremental8 exposed4S01import diagnostics. Eight independent errors repaired in4files; shared_access real-time source fingerprint and existing native parameter added, two module docs synchronized. SevenPython files only formatted, AST unchanged;9source/test/doc paths frozen01:38:02, incoming14unchanged. Real corrected pre-repair probes14/8fail/0error/0skip, then same14/0/0/0; collection-error probe from wrong coordinator class name retained and not counted as a product delivery. No assertion or existingcase weakened.

Post-repair complete fresh mypy still4S01import-untyped errors/4files/359 rc1. Originalsettings and actual absent S01 module remain; no stubs/py.typed/ignore flags/search overrides/unchecked casts. FullStage quality is NOTpassed. Current33repo-file regression plus immutable external3cases, fullcompileall/Black20 and independent finalsource review are running/pending, not accepted. Native/context new currentness case remains unexecuted until realS01 acceptance; no weak substitute.

S01 task_f702313db8 remains rejected/twooriginP1/threeactualfailed deliveries; fourth not dispatched. Originalpublic owner/session and dependencies must be satisfied first. S08 MINcodec remains Stage-only321case accepted, completeS08/nativePRE/currentValidator/fullscan/Rootjoint remain pending. Real-project effects, fullS01/S08/U01 and downstream work, conditionalS10/Q01/Q02/formal/portable/external waits remain separate. Evidence{(OUT / 'review.json').relative_to(ROOT).as_posix()}.

---

"""
for name in ("PROGRESS.md", "DAG.md"):
    path = HERE / name
    path.write_text(note + path.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
(HERE / "CURRENT_STATE_R30.md").write_text(note, encoding="utf-8", newline="\n")
print(json.dumps(dict(recorded_at=at, receipt=(OUT / "review.json").relative_to(ROOT).as_posix(), stage_intake=True, independent_probes=14, full_fresh_quality_passed=False)))
