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
if BACKEND_ONLY:
    TESTS = [name for name in TESTS if name not in {
        "tests/test_agent_workbench_ui.py", "tests/test_protocol_review_ui.py",
        "tests/test_agent_docs.py", "tests/test_portable_release.py",
    }]
SOURCES = TESTS + [
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
    "zscope/config/editor.py", "zscope/cli/config_cli.py", "zscope/cli/init.py",
    "zscope.c_cpp.yaml", "zscope.java.yaml", "AGENTS.md",
    "zscope/web/static/dashboard_config.js", "docs/modules/interfaces-reporting.md",
]
SOURCES += [str(path.relative_to(ROOT)) for path in sorted(
    (ROOT / "zscope/orchestration/jobs").glob("*.py"))]
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
]
for index, command in enumerate(commands):
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
    "limits": "Backend-only" if BACKEND_ONLY else "Includes Astra browser tests",
    "scope": "Real v3 CLI/initializer and all-target HTTP/browser editing; real S08 Linux detached owner/SQLite/HTTP over controlled scanner and synthetic reports; S01 existing native compile variants. S07 controlled model shadow. No actual LLM/full-scan/formal/portable smoke; S01/S08 R1 consumers not intaken and JOB04/JOB06/full instance analysis pending. Counts are not added to prior collections.",
}
(OUT / "source-evidence.json").write_text(json.dumps(proof, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
if before != after:
    raise SystemExit("tested source bytes changed during collection; result is intermediate")
raise SystemExit(results[-1]["returncode"])
