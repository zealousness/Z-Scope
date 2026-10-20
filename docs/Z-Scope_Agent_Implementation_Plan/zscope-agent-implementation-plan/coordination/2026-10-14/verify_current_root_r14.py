"""Run one current-root collection with real Astra browser tests and byte evidence."""

from pathlib import Path
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import tempfile

assert sys.platform == "linux", "quality conclusions require Linux"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
OUT = ROOT / "artifacts" / (sys.argv[1] if len(sys.argv) > 1 else "coordinator-current-integration-20261014")
OUT.mkdir(exist_ok=False)
(OUT / "launcher.py").write_bytes(Path(__file__).read_bytes())
BACKEND_ONLY = "--backend-only" in sys.argv[2:]
TESTS = [
    "tests/test_agent_workbench_ui.py", "tests/test_protocol_review_ui.py",
    "tests/test_project_preparation.py", "tests/test_acceptance_projection.py",
    "tests/test_acceptance_feedback.py", "tests/test_acceptance_http_api.py",
    "tests/test_scan_jobs_http_api.py", "tests/test_agent_plan_evaluation.py",
    "tests/test_agent_docs.py", "tests/test_portable_release.py",
    "tests/test_scan_demand_equivalence.py", "tests/test_semantic_demand.py",
    "tests/test_incremental_semantic_modeling.py",
    "tests/test_config_v3.py", "tests/test_config_v2.py", "tests/test_cli_config_v2.py",
    "tests/test_config_migration.py", "tests/test_reference_configs.py", "tests/test_concurrency_config.py",
    "tests/test_config_v3_preparation.py", "tests/test_all_variant_scan.py",
    "tests/test_compilation_symbols.py", "tests/test_build_context.py",
    "tests/test_scan_session_resume_svf.py", "tests/test_wiki_workflow.py",
    "tests/test_scan_jobs.py", "tests/test_scan_job_execution.py",
    "tests/test_agent_integration_boundaries.py",
    "tests/test_entry_instance_coverage.py", "tests/test_scan_job_work_queue.py",
    "tests/test_config_v3_entrypoints.py", "tests/test_config_editor_http.py",
    "tests/test_portable_runtime.py", "tests/test_web_dashboard_server.py",
]
TESTS += [
    "tests/test_instance_analysis.py",
    "tests/test_job_session_scheduler.py",
    "docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/coordination/2026-10-14/followups-r6/test_instance_consumer_guard.py",
    "docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/coordination/2026-10-14/followups-r6/test_instance_navigation_consumers.py",
    "docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/coordination/2026-10-14/followups-r6/test_instance_validation_scope.py",
    "docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/coordination/2026-10-14/followups-r6/test_instance_native_body.py",
    "docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/coordination/2026-10-14/followups-r6/test_scheduler_guard_probes.py",
    "docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/coordination/2026-10-14/followups-r6/test_scheduler_discovery_durability.py",
    "docs/Z-Scope_Agent_Implementation_Plan/zscope-agent-implementation-plan/coordination/2026-10-14/followups-r6/test_scheduler_settlement_edges.py"
]
WITH_S01 = (ROOT / "zscope/retrieval/instance_index.py").is_file()
WITH_S08 = (ROOT / "zscope/orchestration/jobs/session_scheduler.py").is_file()
WITH_SYMBOLS = (ROOT / "tests/test_full_symbol_build_scope.py").is_file()
WITH_MCP = (ROOT / "zscope/mcp/jobs_adapter.py").is_file()
assert WITH_SYMBOLS == (ROOT / "tests/test_instance_symbol_native.py").is_file()
assert WITH_MCP == (ROOT / "tests/test_mcp_jobs.py").is_file()
TESTS += ["tests/test_function_info_tool.py", "tests/test_tool_registry.py"]
if WITH_SYMBOLS:
    TESTS += [f"tests/{name}.py" for name in (
        "test_full_symbol_build_scope", "test_instance_symbol_native", "test_function_lookup_index",
        "test_code_index_cache", "test_candidate_build_identity", "test_candidate_ledger",
        "test_lifecycle_paths", "test_native_model_cache", "test_parallel_entry_budget",
        "test_parallel_shared_semantics", "test_protocol_incremental_equivalence",
        "test_report_assembler", "test_retained_slot_teardown", "test_validation_runner")]
    TESTS += [f"tests/{name}.py" for name in (
        "test_contract_symbol_ambiguity", "test_graph_candidates", "test_candidate_pipeline",
        "test_callers_tool", "test_type_info_tool")]
    TESTS += [str((HERE / "followups-r10/test_symbol_consumer_receipts.py").relative_to(ROOT))]
if WITH_MCP:
    TESTS += [f"tests/{name}.py" for name in (
        "test_mcp_http_server", "test_mcp_policy", "test_mcp_read_only", "test_mcp_security", "test_mcp_jobs")]
    TESTS += [str((HERE / "followups-r10/test_mcp_strict_boundary.py").relative_to(ROOT))]
TESTS = list(dict.fromkeys(TESTS))
TESTS += ["tests/test_job_remaining.py", "tests/test_native_source_roots.py"]
ledger = json.loads((HERE / "tasks.json").read_text(encoding="utf-8"))
integrated = {row["id"] for row in ledger["tasks"] if row.get("integrated")}
ROUND_TESTS = {
    "CONTRACT-VALIDATION-R12": ["test_contract_usr_scope", "test_validation_build_scope"],
    "MCP-FINDINGS-R12": ["test_job_result_projection", "test_frozen_report_reader", "test_report_json_io", "test_shared_report_storage", "test_report_views"],
    "SCAN-SESSION-R12": ["test_scan_session_instances", "test_scan_session_jobs"],
    "COORD-QUEUE-RECEIPTS-R14": ["test_job_queue_receipts"],
}
ROUND_PROBES = {
    "CONTRACT-VALIDATION-R12": ["test_validation_thread_context", "test_contract_usr_boundary"],
    "MCP-FINDINGS-R12": ["test_mcp_findings_boundaries"],
    "SCAN-SESSION-R12": ["test_scan_session_native_boundary", "test_scan_session_crash_resume"],
}
for identifier, names in ROUND_TESTS.items():
    if identifier in integrated:
        TESTS += [f"tests/{name}.py" for name in names]
        TESTS += [str((HERE / "followups-r12" / (name+".py")).relative_to(ROOT)) for name in ROUND_PROBES.get(identifier, [])]
TESTS = list(dict.fromkeys(TESTS))
assert all((ROOT/name).is_file() for name in TESTS), "accepted current-root test missing"

assert WITH_S01 == (ROOT / "tests/test_instance_analysis.py").is_file()
assert WITH_S08 == (ROOT / "tests/test_job_session_scheduler.py").is_file()
if not WITH_S01:
    TESTS = [name for name in TESTS if name != "tests/test_instance_analysis.py" and not (
        "/followups-r6/test_instance_" in name)]
if not WITH_S08:
    TESTS = [name for name in TESTS if name != "tests/test_job_session_scheduler.py" and not (
        "/followups-r6/test_scheduler_" in name)]
if BACKEND_ONLY:
    TESTS = [name for name in TESTS if name not in {
        "tests/test_agent_workbench_ui.py", "tests/test_protocol_review_ui.py",
        "tests/test_agent_docs.py", "tests/test_portable_release.py",
    }]
SOURCES = TESTS + (["zscope/reporting/job_result_projection.py"] if "MCP-FINDINGS-R12" in integrated else []) + [

    "tests/fixtures/agent_workbench_ui.cjs", "tests/fixtures/protocol_review_ui.cjs",
    "zscope/web/static/index.html", "zscope/web/static/dashboard_workbench.js",
    "zscope/web/static/dashboard_workbench.css", "zscope/web/static/dashboard_reports.js",
    "zscope/web/static/report_view.js", "zscope/web/server.py", "zscope/web/services.py",
    "zscope/web/review_reports.py", "zscope/web/scan_jobs_service.py",
    "zscope/web/acceptance_service.py", "zscope/reporting/acceptance.py",
    "zscope/config/acceptance_feedback.py", "scripts/agent_plan_evaluation.py",
    "scripts/portable/web_assets.py", "requirements/portable/web-assets.lock.json",
    "tests/fixtures/scan_demand_equivalence/scenarios.json",
    "tests/fixtures/scan_demand_equivalence/stale_serialized_plan.json",
    "zscope/orchestration/semantic_demand.py", "zscope/orchestration/semantic_modeling.py",
    "zscope/orchestration/global_modeler.py",
    "zscope/config/v2.py", "zscope/config/v3.py", "zscope/config/config.py",
    "README.md", "docs/modules/configuration-state.md", "docs/modules/benchmarking.md",
    "zscope/config/v3_preparation.py", "zscope/orchestration/entry_instances.py",
    "zscope/orchestration/scan_session.py", "zscope/retrieval/code_index.py",
    "zscope/orchestration/entry_instance_coverage.py",
    "zscope/retrieval/instance_index.py", "zscope/core/analysis/analyzer.py",
    "zscope/orchestration/parallel_analyzer.py",
    "zscope/config/editor.py", "zscope/cli/config_cli.py", "zscope/cli/init.py",
    "zscope.c_cpp.yaml", "zscope.java.yaml", "AGENTS.md",
    "zscope/web/static/dashboard_config.js", "docs/modules/interfaces-reporting.md",
]
SOURCES += [str(path.relative_to(ROOT)) for path in sorted(
    (ROOT / "zscope/orchestration/jobs").glob("*.py"))]
if WITH_MCP:
    SOURCES += ["zscope/mcp/provider.py", "zscope/mcp/jobs_adapter.py"]
if not WITH_S01:
    SOURCES = [name for name in SOURCES if name != "zscope/retrieval/instance_index.py"]
# Bind the full prepared product/plan input inventory, including metadata and
# license inputs that extension-based inventories previously omitted.
baseline = json.loads((HERE / "followups-r6/u01-entrypoints-r6-baseline.json").read_text(encoding="utf-8"))
dependencies = json.loads((HERE / "followups-r6/u01-entrypoints-r6-dependencies.json").read_text(encoding="utf-8"))
SOURCES = sorted(set(SOURCES) | {row["path"] for row in baseline["files"] + dependencies["files"]})
if BACKEND_ONLY:
    SOURCES = [name for name in SOURCES if not (
        name.startswith("zscope/web/static/") or name.startswith("tests/fixtures/")
        or name.startswith("docs/") or name == "README.md"
        or name in {"scripts/portable/web_assets.py", "requirements/portable/web-assets.lock.json"}
    )]

def capture():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCES}

before = capture()
env = os.environ.copy()
env["PYTHONPATH"] = str(ROOT)
env["Z_SCOPE_TEST_CLANG_INDEXER"] = "/home/zeal/.cache/zscope-build-context/install/bin/zscope-clang-indexer"
# pytest fd capture truncates an open, unlinked TemporaryFile.  On this WSL
# host that operation fails with ENOENT on /mnt/c (DrvFS), before tests run.
# Keep each collection's temporary files on the Linux filesystem; durable
# logs, JUnit and browser evidence still belong to OUT.  Preserve the temporary
# directory for diagnosis rather than deleting a failed collection's evidence.
temporary_directory = tempfile.mkdtemp(prefix="zscope-root-validation-", dir="/tmp")
for temporary_variable in ("TMPDIR", "TEMP", "TMP"):
    env[temporary_variable] = temporary_directory
env["ZSCOPE_UI_PLAYWRIGHT_MODULE"] = "/mnt/c/Users/10273/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright"
env["ZSCOPE_UI_CHROMIUM"] = "/home/zeal/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome"
env["ZSCOPE_UI_EVIDENCE"] = str(OUT / "browser")
env["ZSCOPE_UI_CONFIG_EVIDENCE"] = str(OUT / "config")
env["ZSCOPE_UI_JOB_EVIDENCE"] = str(OUT / "owner")
env["ZSCOPE_UI_MULTI_TARGET_EDITING"] = "1"
results = []
commands = [
    [sys.executable, "-m", "pytest", "-q", *TESTS, f"--junitxml={OUT / 'results.xml'}"],
    [sys.executable, "-m", "compileall", "-f", "-q", "zscope", "scripts", "test", "tests"],
    [sys.executable, "-m", "mypy", "zscope"],
    [sys.executable, "-m", "mypy", "scripts/agent_plan_evaluation.py"],
    [sys.executable, "-m", "black", "--check", "zscope/web/scan_jobs_service.py", "tests/test_scan_jobs_http_api.py", "scripts/agent_plan_evaluation.py", "tests/test_agent_plan_evaluation.py", "zscope/config/v3.py", "tests/test_config_v3.py"],
    [sys.executable, "scripts/portable/web_assets.py"],
]
if BACKEND_ONLY:
    commands.pop()  # Astra owns changing static bytes; verify their final lock later.
commands[-1 if BACKEND_ONLY else -2] += [
    "zscope/config/v3_preparation.py", "tests/test_config_v3_preparation.py",
    "zscope/orchestration/entry_instances.py", "zscope/orchestration/jobs",
    "tests/test_scan_jobs.py", "tests/test_scan_job_execution.py",
    "tests/test_all_variant_scan.py", "tests/test_agent_integration_boundaries.py",
    "zscope/reporting/acceptance.py",
    "zscope/orchestration/entry_instance_coverage.py", "tests/test_entry_instance_coverage.py",
    "tests/test_scan_job_work_queue.py",
    "zscope/config/editor.py", "zscope/cli/config_cli.py", "zscope/cli/init.py",
    "tests/test_config_v3_entrypoints.py", "tests/test_config_editor_http.py",
    "tests/test_cli_config_v2.py", "tests/test_reference_configs.py",
    "zscope/retrieval/instance_index.py", "tests/test_instance_analysis.py",
    "tests/test_job_session_scheduler.py",
]
for index, command in enumerate(commands):
    if "black" in command:
        command += ["tests/test_job_remaining.py", "tests/test_native_source_roots.py", "zscope/retrieval/code_index.py"]
        if "CONTRACT-VALIDATION-R12" in integrated:
            command += ["zscope/semantics/contracts.py", "zscope/semantics/build_scope.py", "zscope/semantics/call_context.py", "zscope/semantics/contract_compiler.py", "zscope/core/validation/runner.py", "tests/test_contract_usr_scope.py", "tests/test_validation_build_scope.py"]
        if "MCP-FINDINGS-R12" in integrated:
            command += ["zscope/reporting/job_result_projection.py", "tests/test_job_result_projection.py"]
        if "SCAN-SESSION-R12" in integrated:
            command += ["zscope/orchestration/scan_session.py", "zscope/orchestration/parallel_analyzer.py", "tests/test_scan_session_instances.py", "tests/test_scan_session_jobs.py"]
        if "COORD-QUEUE-RECEIPTS-R14" in integrated:
            command += ["tests/test_job_queue_receipts.py"]
        command += ["tests/test_function_info_tool.py"]
        if WITH_SYMBOLS:
            command += ["tests/test_full_symbol_build_scope.py", "tests/test_instance_symbol_native.py"]
        if WITH_MCP:
            command += ["zscope/mcp/provider.py", "zscope/mcp/jobs_adapter.py", "tests/test_mcp_policy.py", "tests/test_mcp_jobs.py"]
        if not WITH_S01:
            command = [name for name in command if name not in {
                "zscope/retrieval/instance_index.py", "tests/test_instance_analysis.py"}]
        if not WITH_S08:
            command = [name for name in command if name != "tests/test_job_session_scheduler.py"]
    started = dt.datetime.now(dt.timezone.utc).isoformat()
    result = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True)
    log = OUT / f"command-{index}.log"
    log.write_text(result.stdout + result.stderr, encoding="utf-8")
    results.append({"command": command, "started_at": started, "returncode": result.returncode, "log": str(log.relative_to(ROOT))})
    print(json.dumps(results[-1]), flush=True)
    if result.returncode:
        break
after = capture()
proof = {
    "captured_at": dt.datetime.now(dt.timezone.utc).isoformat(), "before": before, "after": after,
    "direct_source_unchanged": before == after, "commands": results,
    "temporary_directory": temporary_directory,
    "launcher_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    "pytest_capture": "fd (unchanged default)",
    "r12_integrated_tasks": sorted(integrated & set(ROUND_TESTS)),
    "intaken_features": {"s01_instance_api": WITH_S01, "s08_session_consumer": WITH_S08,
                         "s01_symbol_consumers": WITH_SYMBOLS, "mcp_persistent_jobs": WITH_MCP,
                         "astra_ux_r10": "!!businessReview?.stale" in (ROOT / "zscope/web/static/index.html").read_text(encoding="utf-8")},
    "test_file_count": len(TESTS),
    "limits": "Backend-only" if BACKEND_ONLY else "Includes Astra browser tests",
    "scope": "Real v3 CLI/initializer/all-target HTTP/browser editing and business answer/withdrawal/real409/offline draft; S01 actual native instance/reference consumers, precise USR/overload and dependency-cache invalidation over controlled model responses; real Linux SQLite/HTTP/MCP/owner over controlled scanners and synthetic reports/assumptions; S07 controlled shadow. R12 features are included only for their recorded accepted intake, with their independent boundary probes. Bounded queue/checkpoint/identity/UI slices do not establish whole packages; remaining graph/link/modeling and full per-instance durable recovery remain separate. No actual LLM/real-project effect, formal benchmark or portable smoke. Counts are not added to prior collections.",
}
(OUT / "source-evidence.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
if before != after:
    raise SystemExit("tested source bytes changed during collection; result is intermediate")
raise SystemExit(results[-1]["returncode"])
