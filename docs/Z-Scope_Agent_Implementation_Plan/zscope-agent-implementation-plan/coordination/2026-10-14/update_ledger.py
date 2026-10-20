"""Refresh the DAG from public MCP receipts; never dispatch or infer completion."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent


def main() -> None:
    path = HERE / "tasks.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    baseline = json.loads((HERE / "baseline.json").read_text(encoding="utf-8"))
    data["updated_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
    data["source_baseline"] = {key: baseline[key] for key in ("captured_at", "source_manifest_sha256", "file_count", "snapshot")}
    data["bridge"] = {
        "status": "official_stdio_connected_persistent_hidden_background",
        "version": "0.1.0", "runtime_context": "coordinator", "dispatch_enabled": True,
        "cli_help": "formal require_escalated succeeds; CLI has no dispatch subcommand",
        "transport": "installed standard MCP ClientSession and official stdio service",
        "unavailable_requested_agents": [],
        "zcode_entry": "process-local official CLI/Node/hw/glm-5.3 bootstrap; old task_f531d6882c failure retained; authorized original S09 scope recovery via separate MCP",
        "dsh_model_mismatch": "old npm mismatch retained; user-approved bundled0.2.0-rc.2 ACP mapping independently connected exact deepseek/v4.1-flash; separate Bridge simple DOC-AUDIT",
        "current_owner_pid": 95496,
    }
    rows = {row["id"]: row for row in data["tasks"]}
    rows["BASE"]["status"] = "completed"
    rows["BASE"]["output_manifest"] = baseline["source_manifest_sha256"]
    rows["ASTRA-UI"]["status"] = "implemented_pending_real_backend_integration"
    rows["ASTRA-UI"]["evidence"] = "ASTRA_UI.md; artifacts/ui-workbench-20261014; final UI7/report44/doc6 reported separately"
    for row in rows.values():
        if row["owner"] == "zcode" and row["status"] == "ready_pending_bridge":
            row["status"] = "blocked_agent_unavailable"
    mapping = {
        "S08-OWNER": ["s08-owner", "s08-owner-qualified", "resume-s08-after-transport", "permission-reload-s08"],
        "S01-INST": ["s01-instances", "resume-s01-after-transport", "s01-minimal-checkpoint", "permission-reload-s01"],
        "DOC-AUDIT": ["doc-audit"],
        "U02-PROJECTION": ["u02-projection-kimi", "u02-projection-confirmed-kimi"],
        "U02-DISPOSITION": ["u02-disposition-kimi", "u02-disposition-confirmed-kimi"],
    }
    checks = {
        "S08-OWNER": ["check-s08-owner", "check-s08-qualified", "recover-check-s08", "current-s08", "monitor-s08", "live-s08", "review-s08", "collect-s08", "reconcile-s08", "fresh-s08-status", "fresh-s08-followup-status", "final-handoff-s08"],
        "S01-INST": ["check-s01", "recover-check-s01", "current-s01", "monitor-s01", "live-s01", "review-s01", "collect-s01", "reconcile-s01", "fresh-s01-status", "fresh-s01-followup-status", "final-handoff-s01"],
        "DOC-AUDIT": ["check-doc-audit"],
        "U02-PROJECTION": ["current-u02-projection", "monitor-u02-projection", "live-u02-projection", "review-u02-projection", "collect-projection", "projection-delivery-status", "finalize-projection", "reconcile-projection", "latest-u02-projection", "health-projection", "final-handoff-projection"],
        "U02-DISPOSITION": ["current-u02-disposition", "monitor-u02-disposition", "live-u02-disposition", "review-u02-disposition", "collect-disposition", "finalize-disposition", "reconcile-disposition", "latest-u02-disposition", "health-disposition"],
    }
    accepted = 0
    for key, names in mapping.items():
        attempts = []
        for name in names:
            result_file = HERE / f"bridge-response-{name}.json"
            if result_file.exists():
                value = json.loads(result_file.read_text(encoding="utf-8"))
                attempts.append(value)
                accepted += bool(value.get("ok") and value.get("task_id"))
        if attempts:
            row = rows[key]
            row["bridge_attempts"] = attempts
            row["bridge_task_id"] = attempts[-1].get("task_id")
            row["bridge_session_id"] = attempts[-1].get("session_id")
            row["accepted_model"] = attempts[-1].get("model")
            if key.startswith("U02-"):
                row["owner"] = "kimi"
                row["requested_model"] = "volceapi/kimi-k3"
                row["difficulty"] = "high"
                row["routing_note"] = "parent explicitly prioritized available Kimi for S08/U02; distinct files; no overlapping prior U02 sessions"
            row["status"] = "accepted_awaiting_status"
            for name in checks.get(key, []):
                result_file = HERE / f"bridge-response-{name}.json"
                if result_file.exists():
                    value = json.loads(result_file.read_text(encoding="utf-8"))
                    if value.get("task_id") != row["bridge_task_id"]:
                        continue
                    row["latest_public_status"] = value
                    row["observed_model"] = value.get("observed_model")
                    # A persisted result from another instance is not a live check.
                    row["status"] = ("persisted_status_live_execution_uncertain" if value.get("from_state") and value.get("status") == "running" else value.get("status", "unknown"))
            if key == "DOC-AUDIT":
                row["status"] = "blocked_model_mismatch"
        elif key.startswith("U02-"):
            rows[key]["status"] = "queued_request_outcome_uncertain_after_transport_loss"
            rows[key]["routing_note"] = "high evidence/storage risk eligible for user-authorized Kimi; original ZCode unavailable; no unapproved agent/model"
    data["bridge"]["accepted_dispatch_receipts"] = accepted
    zcode_result = HERE / "route-check/bridge-response-check-zcode-s09.json"
    if zcode_result.exists():
        zcode = json.loads(zcode_result.read_text(encoding="utf-8"))
        rows["S09-PREP"]["status"] = "blocked_prompt_protocol_error_outcome_uncertain_do_not_retry"
        rows["S09-PREP"]["bridge_task_id"] = zcode["task_id"]
        rows["S09-PREP"]["bridge_session_id"] = zcode["session_id"]
        rows["S09-PREP"]["requested_model"] = zcode["model"]
        rows["S09-PREP"]["latest_public_status"] = zcode
        data["bridge"]["accepted_dispatch_receipts"] += 1
    for key, folder, dispatch_name, check_name in (
        ("S09-PREP", "route-check", "zcode-s09-recovery", "zcode-final-handoff"),
        ("S09-PREP", "route-check", "zcode-s09-finish", "continue-s09"),
        ("S09-PREP", "route-check", "s09-record-integrity-fix", "s09-record-integrity-status"),
        ("S07-ORACLE", "route-check", "s07-oracle", "s07-oracle-status"),
        ("U01-CONFIG", "route-check", "u01-config-backend", "u01-config-status"),
        ("DOC-AUDIT", "dsh-native", "doc-audit-native", "doc-audit-status"),
    ):
        receipt = HERE / folder / f"bridge-response-{dispatch_name}.json"
        if receipt.exists():
            value = json.loads(receipt.read_text(encoding="utf-8"))
            if value.get("ok") and value.get("task_id"):
                row = rows[key]
                row.setdefault("recovery_receipts", []).append(value) if value not in row.get("recovery_receipts", []) else None
                row["bridge_task_id"] = value["task_id"]
                row["bridge_session_id"] = value["session_id"]
                row["accepted_model"] = value["model"]
                row["status"] = "accepted_awaiting_status"
                check = HERE / folder / f"bridge-response-{check_name}.json"
                if check.exists():
                    current = json.loads(check.read_text(encoding="utf-8"))
                    if current.get("task_id") == value["task_id"]:
                        row["latest_public_status"] = current
                        row["observed_model"] = current.get("observed_model")
                        row["status"] = current.get("status", "unknown")
                data["bridge"]["accepted_dispatch_receipts"] += 1
    for key, branch in (("U02-PROJECTION", "u02-projection"), ("U02-DISPOSITION", "u02-disposition")):
        intake = HERE / f"intake-{branch}.json"
        if intake.exists():
            rows[key]["integration_snapshot"] = json.loads(intake.read_text(encoding="utf-8"))
            rows[key]["integration_validation"] = "acceptance-integration-tests.xml: 79 passed/11.33s; overlaps worker49/24; do not sum; pending UI/context integration and final receipt"
    if (HERE / "review-repro/s09-record-integrity/review.json").exists():
        rows["S09-PREP"]["acceptance_status"] = "blocked_review_defect_frozen_record_identity_and_counts_can_be_modified_without_id_check"
        rows["S09-PREP"]["independent_tests"] = "s09-prep-tests.xml:28 passed/2.05s; no formal/LLM/native scan"
        rows["S09-PREP"]["review_evidence"] = "review-repro/s09-record-integrity/review.json; same native ZCode fix requested"
    # Immutable read-only collection snapshots supersede older named checks.
    public = HERE / "current-public"
    for key, label in (("S01-INST", "s01"), ("S08-OWNER", "s08"),
                       ("S09-PREP", "s09-fix"), ("S07-ORACLE", "s07-oracle")):
        files = sorted(public.glob(f"*/{label}-state.json"), key=lambda p: p.stat().st_mtime_ns)
        if files:
            value = json.loads(files[-1].read_text(encoding="utf-8"))
            if value.get("task_id") == rows[key].get("bridge_task_id"):
                rows[key]["latest_public_status"] = value
                rows[key]["observed_model"] = value.get("observed_model")
                rows[key]["status"] = value.get("status", "unknown")
                rows[key]["public_receipt"] = str(files[-1].relative_to(HERE))
    fixed = HERE / "s09-record-integrity-fixed-tests.xml"
    intake_s09 = HERE / "intake-s09-prep.json"
    if fixed.exists() and intake_s09.exists():
        suites = ET.parse(fixed).getroot().findall("testsuite")
        if suites and all(int(s.get("failures", "0")) == 0 and int(s.get("errors", "0")) == 0 for s in suites):
            rows["S09-PREP"]["acceptance_status"] = "development_prep_integrated_frozen_record_defect_fixed_formal_not_run"
            rows["S09-PREP"]["independent_tests"] = "s09-record-integrity-fixed-tests.xml:33 passed/2.19s; backend-s09-adapter-integration-tests.xml:118 passed/18.58s; overlap, do not sum"
            rows["S09-PREP"]["integration_snapshot"] = json.loads(intake_s09.read_text(encoding="utf-8"))
    if (HERE / "backend-s09-adapter-integration-tests.xml").exists():
        rows["HTTP-INTEGRATION"]["status"] = "u02_real_http_verified_jobs_adapter_contract_only_owner_pending"
        rows["HTTP-INTEGRATION"]["write_paths"] = list(dict.fromkeys(rows["HTTP-INTEGRATION"]["write_paths"] + ["zscope/web/scan_jobs_service.py", "tests/test_scan_jobs_http_api.py"]))
        rows["HTTP-INTEGRATION"]["validation"] = "118 passed/18.58s incl S09; six job adapter fixture tests do not verify JOB process execution"
    env_dispatch = HERE / "dsh-native/bridge-response-linux-environment-audit.json"
    if env_dispatch.exists():
        value = json.loads(env_dispatch.read_text(encoding="utf-8"))
        if value.get("ok") and value.get("task_id"):
            rows["S00-FULL"]["preflight_task"] = value
            rows["S00-FULL"]["status"] = "partial_environment_read_only_audit_dispatched_full_acceptance_pending"
            env_state = HERE / "dsh-native/bridge-response-env-audit-status.json"
            if env_state.exists():
                state = json.loads(env_state.read_text(encoding="utf-8"))
                if state.get("task_id") == value["task_id"]:
                    rows["S00-FULL"]["preflight_public_status"] = state
                    rows["S00-FULL"]["status"] = "environment_inventory_completed_real_scan_and_formal_readiness_unverified"
    if (HERE / "intake-s07-oracle.json").exists():
        rows["S07-ORACLE"]["integration_snapshot"] = json.loads((HERE / "intake-s07-oracle.json").read_text(encoding="utf-8"))
        rows["S07-ORACLE"]["acceptance_status"] = "synthetic_oracle_integrated_full_inc05_rapi10_not_measured"
        rows["S07-ORACLE"]["independent_tests"] = "s07-oracle-independent-tests.xml:77 passed/32.96s; root integration s07-root-integration-tests.xml:77 passed/32.33s; same overlapping collection, do not sum"
        rows["S07-ORACLE"]["limitations"] = "None/empty unknown-build snapshot representation normalized only in test oracle, explicit production observation; LLM/native/verdict/cost/full-scan untested"
    rows["DEV-DISPATCH-SAFETY"]["status"] = "approved_entries_and_process_routes_verified_live_services_not_restarted"
    rows["DEV-DISPATCH-SAFETY"]["current_routes"] = "Kimi qualified; ZCode original hw/glm-5.3 observed; DSH bundled deepseek/v4.1-flash observed; historical failures preserved"
    rows["DOC-AUDIT"]["acceptance_status"] = "read_only_delivery_reviewed_seven_stale_intro_findings_no_whole_package_completion"
    rows["U01-CONFIG"]["isolate"] = ".coordination/20261014/workspaces/u01-config"
    rows["U01-CONFIG"]["integration_policy"] = "new strict model/paths first; controlled existing-file patch only after review; coordinator owns shared Web/docs wiring, Astra owns all UI; complete CLI/init/MCP/template migration remains in scope"
    now_s01 = HERE / "bridge-response-now-s01.json"
    if now_s01.exists():
        state = json.loads(now_s01.read_text(encoding="utf-8"))
        if state.get("task_id") == rows["S01-INST"].get("bridge_task_id"):
            rows["S01-INST"]["latest_public_status"] = state
            rows["S01-INST"]["status"] = state["status"]
            rows["S01-INST"]["observed_model"] = state.get("observed_model")
            rows["S01-INST"]["acceptance_status"] = "not_delivered_bridge_stalled_cancelled_turn_no_redispatch"
    if (HERE / "review-repro/s08-input-cache/review.json").exists():
        rows["S08-OWNER"]["acceptance_status"] = "blocked_input_fingerprint_cache_defect_and_interim_unit_failures"
        rows["S08-OWNER"]["review_evidence"] = "S08_REVIEW_PENDING.md; review-repro/s08-input-cache/review.json; s08-partial-unit-review-tests.xml:36 pass/7 fail, test bytes changed during run; intermediate only"
    rows["ASTRA-UI"]["status"] = "u02_real_backend_verified_jobs_pending"
    rows["ASTRA-UI"]["evidence"] = "artifacts/ui-u02-real-20261014:86 passed/48.74s; no skip; final source SHA locked; S08 fixture pending; do not sum prior79/85"
    if "DEV-DISPATCH-SAFETY" not in rows:
        safety = {"id": "DEV-DISPATCH-SAFETY", "packages": ["development_coordination"], "title": "用户追加：入口/provider防误用、生命周期和重复保护", "depends_on": ["BASE", "API"], "owner": "coordinator", "requested_model": None, "difficulty": "medium", "risk": "high", "status": "implemented_tests_passed_global_config_approval_pending", "write_paths": ["coordination/2026-10-14/dispatch_safety.py", "coordination/2026-10-14/bridge_submit.py", "coordination/2026-10-14/ENTRY_BINDINGS.json", "tests/test_bridge_dispatch_safety.py"], "input": "实际官方入口/版本/配置/标准MCP回执与用户追加要求", "output": "显式拒绝旧入口/错误provider/近似模型/未知结果重发；精确外部修改方案", "acceptance": ["dispatch-safety-tests.xml", "ENTRY_FIX_PLAN.md", "非秘密字段输出", "不改外部安装/权限/凭据，不重启Kimi"], "enable_condition": "用户PATH/全局Bridge/ACPprofile改动需父任务具体批准；当前dsh/zcode binding均禁止新派发"}
        data["tasks"].append(safety)
        rows[safety["id"]] = safety
    if (HERE / "entry-fix-receipt.json").exists():
        rows["DEV-DISPATCH-SAFETY"]["status"] = "user_path_and_bridge_settings_applied_preflight_passed_provider_followup_blocked"
        rows["DEV-DISPATCH-SAFETY"]["validation"] = "19 passed/0 failed/0 skipped, dispatch-safety-tests.xml; existing compileall/mypy330 passed; ENTRY_FIX_APPLIED.md"
        rows["DEV-DISPATCH-SAFETY"]["mutations"] = "Only explicitly approved User PATH and user agents.toml entry fields; backups retained; Machine PATH/credentials/security/running Kimi untouched"
    # Current exact receipts supersede historical running and acceptance text.
    for key, folder, dispatch, check in (
        ("S01-INST", "route-check", "s01-zcode-recovery", "s01-zcode-first-state"),
        ("U01-CONFIG", "route-check", "u01-schema-parity-repair", None),
        ("S09-PREP", "route-check", "s09-shared-report-fix", "s09-shared-report-status"),
        ("S08-OWNER", "", "s08-acceptance-repair", "s08-repair-first-state"),
        ("S08-OWNER", "route-check", "s08-zcode-api-recovery", None),
        ("S01-INST", "route-check", "s01-scope-identity-repair", "s01-scope-live"),
        ("S08-OWNER", "route-check", "s08-zcode-api-recovery", "s08-current-delivery"),
        ("U01-CONFIG", "route-check", "u01-readonly-preparation", "u01-preparation-live"),
    ):
        receipt = HERE / folder / f"bridge-response-{dispatch}.json"
        if not receipt.exists():
            continue
        value = json.loads(receipt.read_text(encoding="utf-8"))
        if not value.get("ok") or not value.get("task_id"):
            continue
        row = rows[key]
        if value not in row.setdefault("recovery_receipts", []):
            row["recovery_receipts"].append(value)
        row.update(bridge_task_id=value["task_id"], bridge_session_id=value["session_id"], accepted_model=value["model"], status="accepted_awaiting_status", observed_model=None)
        if check:
            state_file = HERE / folder / f"bridge-response-{check}.json"
            if state_file.exists():
                state = json.loads(state_file.read_text(encoding="utf-8"))
                if state.get("task_id") == value["task_id"]:
                    row.update(latest_public_status=state, status=state["status"], observed_model=state.get("observed_model"))
    rows["S01-INST"]["owner"] = "zcode"
    rows["S01-INST"]["requested_model"] = "97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3"
    rows["S01-INST"]["acceptance_status"] = "parent_authorized_api_timeout_recovery_isolated_no_delivery_yet"
    rows["S01-INST"]["recovery_evidence"] = "s01-failure-checkpoint.json:931 baseline files unchanged,4 owned bytes preserved; prior task_f709895aa3 failed/stalled,PID99896 absent; first new Bash completed06:37:15Z"
    rows["S08-OWNER"]["acceptance_status"] = "rejected_delivery_known_f1_f2_f3_f4_and_shared_report_decode_defects_original_session_fix_running"
    rows["S08-OWNER"]["limitations"] = "Original53 worker tests do not satisfy acceptance because lost/503 assertions were weakened to500; restore and fix.8 owned modules not frozen; full JOB04/JOB06 remain pending. Root owner modules not intaken."
    rows["U01-CONFIG"]["acceptance_status"] = "independent133_passed_schema_parity_review_defects_original_session_fix_pending_no_root_intake"
    rows["U01-CONFIG"]["review_evidence"] = "u01-core-independent-tests.xml:133 passed/36.74s; review-repro/u01-schema/review.json:4 parser/schema discrepancies; full CLI/init/MCP/templates/prepare migration pending"
    shared_intake = HERE / "intake-s09-shared-report.json"
    if shared_intake.exists():
        rows["S09-PREP"]["acceptance_status"] = "current_shared_storage_fix_integrated_development_prep_only_formal_unrun"
        rows["S09-PREP"]["integration_snapshot"] = json.loads(shared_intake.read_text(encoding="utf-8"))
        rows["S09-PREP"]["independent_tests"] = "s09-shared-report-independent-tests.xml:39 passed/3.19s; replaces overlapping33, do not sum"
        rows["S09-PREP"]["limitations"] = "Synthetic reports/usage only; actual16MiB path fails closed because optional ijson unavailable, streaming not tested; no LLM/native/formal/accuracy/cost evaluation"
    rows["HTTP-INTEGRATION"]["validation"] = "Latest targeted jobs-shared-report-tests.xml:8 passed/8.56s uses actual writer+corrupt graph; contract fixture engine only, not real owner; prior147 collection now superseded by pending current-root rerun"
    rows["DEV-DISPATCH-SAFETY"]["status"] = "approved_entries_and_process_routes_verified_live_services_not_restarted"
    for key, label in (("S01-INST", "s01"), ("S08-OWNER", "s08"), ("U01-CONFIG", "u01")):
        snapshots = sorted((HERE / "current-public").glob(f"*/{label}-state.json"), key=lambda p: p.stat().st_mtime_ns)
        if snapshots:
            state = json.loads(snapshots[-1].read_text(encoding="utf-8"))
            if state.get("task_id") == rows[key].get("bridge_task_id"):
                rows[key].update(latest_public_status=state, status=state["status"], observed_model=state.get("observed_model"), public_receipt=str(snapshots[-1].relative_to(HERE)))
    s08_transfer = HERE / "route-check/bridge-response-s08-zcode-api-recovery.json"
    if s08_transfer.exists():
        rows["S08-OWNER"].update(owner="zcode", requested_model="97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3", acceptance_status="ordinary_repeated_empty_api_failure_checkpointed_cancelled_then_zcode_repair_pending")
        rows["S08-OWNER"]["recovery_evidence"] = "s08-api-failure-checkpoint.json:13 files preserved; s08-post-stop-stability.json:cancelled receipt+post-stop SHA/mtime unchanged. New repair had two APIEmptyResponseError, not new APITimeoutError; no permission/content denial."
    if (HERE / "intake-u01-core.json").exists():
        rows["U01-CONFIG"]["status"] = "core_integrated_full_migration_pending"
        rows["U01-CONFIG"]["acceptance_status"] = "four_schema_discrepancies_fixed_independent142_passed_root_validation_recorded_separately"
        rows["U01-CONFIG"]["integration_snapshot"] = json.loads((HERE / "intake-u01-core.json").read_text(encoding="utf-8"))
    if (HERE / "route-check/bridge-response-u01-readonly-preparation.json").exists():
        rows["U01-CONFIG"]["status"] = "core_integrated_readonly_preparation_backend_running_full_migration_pending"
        rows["U01-CONFIG"]["write_paths"] = list(dict.fromkeys(rows["U01-CONFIG"]["write_paths"] + ["zscope/config/v3_preparation.py", "tests/test_config_v3_preparation.py"]))
        rows["U01-CONFIG"]["active_scope"] = "Only two new machine-data backend files; accepted4 core files frozen; no shared prepare/Web/CLI/init/MCP/templates/UI/UX modifications. Coordinator shared wiring/Astra UX later."
    if (HERE / "review-repro/s01-scope-boundary/review.json").exists():
        rows["S01-INST"]["acceptance_status"] = "native_minimal_slice_returned_not_intaken_foreign_identity_and_explicit_entry_file_review_defects_original_session_repair"
        rows["S01-INST"]["review_evidence"] = "S01_REVIEW_PENDING.md; stable terminal SHA9a2e254d...390b50; actual helper synthetic foreign identity/wrong-file probe. Worker15 native-controlled tests reported, no independent final collection yet; full Analyzer/Validator/CDB/current dependency/completeness pending."
    current_root = HERE.parents[4] / "artifacts/coordinator-u01-integration-20261014/source-evidence.json"
    if current_root.exists():
        evidence = json.loads(current_root.read_text(encoding="utf-8"))
        if evidence.get("direct_source_unchanged") and all(item["returncode"] == 0 for item in evidence["commands"]):
            rows["HTTP-INTEGRATION"]["validation"] = "Current same-source collection370 passed/107.84s,0skip; includes real Astra U02 Chromium/SQLite,v2/v3,S07,S09,job adapter. compileall,mypy335+S09,Black,static locks pass. No real S08 owner; don't sum prior232/147/142. artifacts/coordinator-u01-integration-20261014"
            rows["U01-CONFIG"]["root_validation"] = rows["HTTP-INTEGRATION"]["validation"]
    # Intaken follow-ups supersede earlier review defects; package scope remains open.
    for key, branch, evidence in (
        ("S01-INST", "s01-instances", "s01-scope-fixed-independent-tests.xml:66 passed/52.14s with real existing native; foreign identity/wrong file rejected; full per-instance Analyzer/Validator/CDB reconciliation pending"),
        ("U01-CONFIG", "u01-config", "u01-preparation-independent-tests.xml:87 passed/11.79s; actual GET prepare preserves multiple targets, start disabled; full CLI/init/MCP/templates/editing and execution consumers pending"),
    ):
        receipt = HERE / f"intake-{branch}-followup.json"
        if receipt.exists():
            rows[key]["integration_snapshot"] = json.loads(receipt.read_text(encoding="utf-8"))
            rows[key]["status"] = "accepted_slice_integrated_full_package_pending"
            rows[key]["acceptance_status"] = "identified_review_defects_fixed_independently_verified_and_intaken"
            rows[key]["independent_tests"] = evidence
    if (HERE / "intake-s08-fixed.json").exists():
        rows["S08-OWNER"].update(
            integration_snapshot=json.loads((HERE / "intake-s08-fixed.json").read_text(encoding="utf-8")),
            status="accepted_owner_store_input_report_slice_integrated",
            acceptance_status="f1_f2_f3_f4_shared_report_defects_fixed_independently_verified_and_intaken",
            limitations="JOB04 cooperative stop-new-work/bounded finish and JOB06 fair remaining queue are not wired into scan_session. No actual model/native full scan or whole S08 acceptance.",
            independent_tests="s08-fixed-explicit-path-tests.xml:69 passed/33.64s,0skip; absolute isolate PYTHONPATH. Earlier ambiguous PYTHONPATH failed collection retained, not counted.",
        )
    if (HERE / "actual-backend-http-final-tests.xml").exists():
        rows["HTTP-INTEGRATION"].update(
            status="actual_jobs_owner_sqlite_http_and_v3_preparation_basic_verified_ui_in_progress",
            validation="actual-backend-http-final-tests.xml:3 passed/5.34s; real detached owner/SQLite/HTTP, controlled scanner with actual shared writer; no jobs/DB/HTTP mock; combined current version validation pending",
        )
    rows["ASTRA-UI"]["status"] = "u02_verified_s01_u01_s08_real_backend_browser_integration_active"
    rows["ASTRA-UI"]["active_scope"] = "Astra exclusive static/UI test ownership; v3 readonly targets/start capability; real HTTP+DB+owner with explicitly controlled scanner; old86 collection is historical, final new bytes pending"
    data["reserved_branch"] = {
        "observation_thread": "01a12e4c-0efe-7180-91c4-d642b3b0a571",
        "state": "user_confirmed_delivered_and_archived_observation_thread",
        "independent_acceptance": "not_performed",
        "policy": "not a pending user-action blocker; do not resume/redispatch/operate old blocked rounds; inspect only existing permitted artifacts for dependencies without implementation authorization",
    }
    for key, label, isolate, prerequisite, paths in (
        ("S01-CDB-COVERAGE", "s01-cdb-coverage", "s01-coverage", "S01-INST", ["zscope/orchestration/entry_instance_coverage.py", "tests/test_entry_instance_coverage.py"]),
        ("S08-QUEUE-CORE", "s08-fair-queue", "s08-scheduling", "S08-OWNER", ["zscope/orchestration/jobs/work_queue.py", "tests/test_scan_job_work_queue.py"]),
    ):
        if key not in rows:
            row = {"id": key, "packages": ["S01" if key.startswith("S01") else "S08"],
                   "title": label, "depends_on": ["BASE", "API"],
                   "prerequisite_slice": prerequisite, "enable_condition": "accepted prerequisite slice intake exists; whole prerequisite package not implied",
                   "owner": "zcode", "requested_model": "97ad75c3-e785-4369-9730-55a5ee47c71c/glm-5.3",
                   "difficulty": "high", "risk": "high", "status": "queued_outcome_pending",
                   "write_paths": paths, "isolate": f".coordination/20261014/workspaces/{isolate}",
                   "input": f"baseline-{isolate}.json:965 current accepted input files; NEXT_BACKEND_CONTRACT.md",
                   "output": "independent backend module, real bounded tests, stable byte/JUnit delivery",
                   "acceptance": ["actual identity/currentness/SQLite positive and negative cases", "no shared-file write", "no full scan/whole package claim", "independent review before intake"],
                   "full_scope_dependencies": "Original package dependencies preserved; this partial producer does not unlock later full-scope consumers"}
            data["tasks"].append(row)
            rows[key] = row
        receipt = HERE / "route-check" / f"bridge-response-{label}.json"
        if receipt.exists():
            value = json.loads(receipt.read_text(encoding="utf-8"))
            rows[key].update(bridge_task_id=value.get("task_id"), bridge_session_id=value.get("session_id"), accepted_model=value.get("model"), status="accepted_awaiting_live_status")
            rows[key]["bridge_attempts"] = [value]
            state_file = HERE / "route-check" / f"bridge-response-{label}-state.json"
            if state_file.exists():
                state = json.loads(state_file.read_text(encoding="utf-8"))
                if state.get("task_id") == value.get("task_id"):
                    rows[key].update(latest_public_status=state, status=state["status"], observed_model=state.get("observed_model"))
    accepted_ids = set()
    for row in rows.values():
        for receipt in row.get("bridge_attempts", []) + row.get("recovery_receipts", []):
            if receipt.get("ok") and receipt.get("task_id"):
                accepted_ids.add(receipt["task_id"])
        if row.get("preflight_task", {}).get("ok"):
            accepted_ids.add(row["preflight_task"]["task_id"])
    data["bridge"]["accepted_dispatch_receipts"] = len(accepted_ids)
    if (HERE / "post-update-recovery-checkpoint.json").exists():
        data["bridge"].update(current_owner_pid=80748, status="post_app_update_normal_official_stdio_recovered_exact_sessions",
                             recovery="Original main95496/route94576/dsh89400 and registered native processes absent. Readonly normal MCP confirmed failed/bridge_restarted, complete permission/messages,965 unchanged inputs. Closed only owned readonly monitor86572/67932; no old worker or configuration restarted.")
        for key, label in (("S01-CDB-COVERAGE", "s01-cdb-coverage"), ("S08-QUEUE-CORE", "s08-fair-queue")):
            receipt = HERE / "route-check" / f"bridge-response-{label}-post-update-resume.json"
            if receipt.exists():
                value = json.loads(receipt.read_text(encoding="utf-8"))
                row = rows[key]
                if value not in row.setdefault("recovery_receipts", []):
                    row["recovery_receipts"].append(value)
                row.update(bridge_task_id=value.get("task_id"), bridge_session_id=value.get("session_id"), accepted_model=value.get("model"), observed_model=None, status="accepted_original_session_transport_recovery_awaiting_status")
                row["recovery_evidence"] = "post-update-recovery-checkpoint.json; current-public/c725deddeaf7; readonly-rejected-unsent-recovery.json retains known local monitor-unsent requests with same idempotency key; original failure preserved"
                accepted_ids.add(value["task_id"])
                snapshots = sorted((HERE / "current-public").glob(f"*/{label}-state.json"), key=lambda p: p.stat().st_mtime_ns)
                if snapshots:
                    state = json.loads(snapshots[-1].read_text(encoding="utf-8"))
                    if state.get("task_id") == value.get("task_id"):
                        row.update(latest_public_status=state, status=state["status"], observed_model=state.get("observed_model"), public_receipt=str(snapshots[-1].relative_to(HERE)))
        data["bridge"]["accepted_dispatch_receipts"] = len(accepted_ids)
    backend_root = HERE.parents[4] / "artifacts/coordinator-jobs-backend-20261014/source-evidence.json"
    if backend_root.exists():
        evidence = json.loads(backend_root.read_text(encoding="utf-8"))
        if evidence.get("direct_source_unchanged") and all(item["returncode"] == 0 for item in evidence["commands"]):
            rows["HTTP-INTEGRATION"]["validation"] = "Current backend same-source493 passed/174.03s,0skip; real Linux owner/SQLite/HTTP controlled scanner,existing actual native variants. compileall,mypy347+S09,Black passed. Current changing Astra UI excluded; JOB04/06/full S01/model/formal pending. artifacts/coordinator-jobs-backend-20261014; not summed with370/86/69."
            rows["HTTP-INTEGRATION"]["source_evidence"] = "artifacts/coordinator-jobs-backend-20261014/source-evidence.json"
    final_root = HERE.parents[4] / "artifacts/coordinator-jobs-final-20261014/source-evidence.json"
    if final_root.exists():
        evidence = json.loads(final_root.read_text(encoding="utf-8"))
        if evidence.get("direct_source_unchanged") and all(item["returncode"] == 0 for item in evidence["commands"]):
            rows["HTTP-INTEGRATION"].update(
                status="same_source_actual_jobs_u02_ui_owner_and_backend_stage_verified_full_packages_pending",
                validation="One final same-source519 passed/226.83s,0skip; real serial Chromium/jobs/U02 HTTP/SQLite/detached owner over controlled synthetic scanner/reports plus actual existing native variants. compileall,mypy347+S09,Black,static locks passed. Full S01/JOB04/JOB06/config migration/model/formal not accepted; do not sum prior97/493/370.",
                source_evidence="artifacts/coordinator-jobs-final-20261014/source-evidence.json",
            )
            rows["ASTRA-UI"].update(status="actual_jobs_u01_readonly_and_u02_ui_stage_verified_full_ux_migration_pending",
                                  evidence="artifacts/ui-jobs-real-20261014/DELIVERY.md and final97 own collection; current coordinator same-source519 includes it,not summed. static-lock-real-jobs.json; no remaining jobs fixture in actual owner chain; old labeled contract cases preserved.")
    atomic_proof = HERE / "review-repro/job-request-atomicity/review.json"
    if atomic_proof.exists():
        rows["S08-OWNER"].update(status="integrated_slice_blocked_new_r5_atomic_request_review_defect",
                                  acceptance_status="actual_same_key_two_scanners_reproduced_fix_pending",
                                  review_evidence="review-repro/job-request-atomicity/review.json:real HTTP/DB/owner; same request_id2completedjobs/scanners; first409/second202. 519 passing collection preserved but insufficient for final owner acceptance.")
        rows["HTTP-INTEGRATION"]["status"] = "same_source519_passed_but_new_atomic_request_defect_blocks_final_acceptance"
        receipt = HERE / "route-check/bridge-response-s08-atomic-request-fix.json"
        if receipt.exists():
            value = json.loads(receipt.read_text(encoding="utf-8"))
            row = rows["S08-OWNER"]
            if value not in row.setdefault("recovery_receipts", []):
                row["recovery_receipts"].append(value)
            row.update(bridge_task_id=value.get("task_id"), bridge_session_id=value.get("session_id"), accepted_model=value.get("model"), observed_model=None)
            accepted_ids.add(value["task_id"])
            data["bridge"]["accepted_dispatch_receipts"] = len(accepted_ids)
            state_file = HERE / "route-check/bridge-response-s08-atomic-request-state.json"
            if state_file.exists():
                state = json.loads(state_file.read_text(encoding="utf-8"))
                if state.get("task_id") == value.get("task_id"):
                    row.update(latest_public_status=state, observed_model=state.get("observed_model"), bridge_task_status=state["status"])
    for key, label in (("S01-CDB-COVERAGE", "s01-cdb-coverage"), ("S08-QUEUE-CORE", "s08-fair-queue")):
        receipt = HERE / "route-check" / f"bridge-response-{label}-identity-fix.json"
        if receipt.exists():
            value = json.loads(receipt.read_text(encoding="utf-8"))
            row = rows[key]
            if value not in row.setdefault("recovery_receipts", []):
                row["recovery_receipts"].append(value)
            row.update(bridge_task_id=value["task_id"], bridge_session_id=value["session_id"], accepted_model=value["model"], observed_model=None,
                       status="producer_returned_but_rejected_identity_defect_original_session_repair",
                       review_evidence="NEXT_PRODUCER_REVIEW.md; stable readonly synthetic BuildContext or actual SQLite identity probes; no root intake")
            accepted_ids.add(value["task_id"])
        candidates = list((HERE / "current-public").glob(f"*/{label}-state.json")) + [HERE / "route-check" / f"bridge-response-{label}-state.json"]
        candidates = sorted((file for file in candidates if file.exists()), key=lambda p: p.stat().st_mtime_ns)
        if candidates:
            state = json.loads(candidates[-1].read_text(encoding="utf-8"))
            if state.get("task_id") == rows[key]["bridge_task_id"]:
                rows[key].update(latest_public_status=state, observed_model=state.get("observed_model"), bridge_task_status=state["status"])
    data["bridge"]["accepted_dispatch_receipts"] = len(accepted_ids)
    ids = set(rows)
    layers, done = [], set()
    while len(done) < len(ids):
        layer = [key for key, row in rows.items() if key not in done and set(row["depends_on"]) <= done]
        if not layer:
            raise ValueError("dependency cycle or missing task")
        layers.append(layer)
        done.update(layer)
    data["topological_layers"] = layers
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"nodes": len(rows), "layers": len(layers), "accepted_dispatch_receipts": data["bridge"]["accepted_dispatch_receipts"], "statuses": {key: rows[key]["status"] for key in mapping}}, ensure_ascii=False))


if __name__ == "__main__":
    main()
