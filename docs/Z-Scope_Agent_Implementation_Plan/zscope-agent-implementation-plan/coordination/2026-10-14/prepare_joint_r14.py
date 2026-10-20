"""Prepare a strict current-root launcher that includes each accepted R12 intake."""
from pathlib import Path

HERE=Path(__file__).resolve().parent
source=(HERE/"verify_current_root_r12.py").read_text(encoding="utf-8")
source=source.replace('TESTS += ["tests/test_job_remaining.py"]','''TESTS += ["tests/test_job_remaining.py", "tests/test_native_source_roots.py"]
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
''')
source=source.replace('SOURCES = TESTS + [','''SOURCES = TESTS + (["zscope/reporting/job_result_projection.py"] if "MCP-FINDINGS-R12" in integrated else []) + [
''')
source=source.replace('command += ["tests/test_job_remaining.py"]','''command += ["tests/test_job_remaining.py", "tests/test_native_source_roots.py", "zscope/retrieval/code_index.py"]
        if "CONTRACT-VALIDATION-R12" in integrated:
            command += ["zscope/semantics/contracts.py", "zscope/semantics/build_scope.py", "zscope/semantics/call_context.py", "zscope/semantics/contract_compiler.py", "zscope/core/validation/runner.py", "tests/test_contract_usr_scope.py", "tests/test_validation_build_scope.py"]
        if "MCP-FINDINGS-R12" in integrated:
            command += ["zscope/reporting/job_result_projection.py", "tests/test_job_result_projection.py"]
        if "SCAN-SESSION-R12" in integrated:
            command += ["zscope/orchestration/scan_session.py", "zscope/orchestration/parallel_analyzer.py", "tests/test_scan_session_instances.py", "tests/test_scan_session_jobs.py"]
        if "COORD-QUEUE-RECEIPTS-R14" in integrated:
            command += ["tests/test_job_queue_receipts.py"]''')
source=source.replace('"intaken_features": {','"r12_integrated_tasks": sorted(integrated & set(ROUND_TESTS)),\n    "intaken_features": {')
old='Complete ScanSession scheduling, scanner queue/checkpoint/remaining wiring, contract-USR propagation, broader graph/link consumers and MCP findings projection remain pending.'
source=source.replace(old,'R12 features are included only for their recorded accepted intake, with their independent boundary probes. Bounded queue/checkpoint/identity/UI slices do not establish whole packages; remaining graph/link/modeling and full per-instance durable recovery remain separate.')
target=HERE/"verify_current_root_r14.py"
assert not target.exists()
target.write_text(source,encoding="utf-8",newline="\n")
print(target)
