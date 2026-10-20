"""Immutable next launcher: add accepted Web queue coverage, preserve all checks."""
from pathlib import Path

HERE=Path(__file__).resolve().parent
target=HERE/"verify_current_root_r15.py"
assert not target.exists()
source=(HERE/"verify_current_root_r14.py").read_text(encoding="utf-8")
source=source.replace('"COORD-QUEUE-RECEIPTS-R14": ["test_job_queue_receipts"]','"COORD-QUEUE-RECEIPTS-R14": ["test_job_queue_receipts", "test_job_result_http_binding"]')
source=source.replace('command += ["tests/test_job_queue_receipts.py"]','command += ["tests/test_job_queue_receipts.py", "tests/test_job_result_http_binding.py"]')
source=source.replace('"CONTRACT-VALIDATION-R12": ["test_contract_usr_scope", "test_validation_build_scope"]','"CONTRACT-VALIDATION-R12": ["test_contract_usr_scope", "test_validation_build_scope", "test_native_wrapper_inference", "test_refcount_integration", "test_handle_integration", "test_lock_modes", "test_pool_protocol_modeling", "test_conditional_ownership_contracts", "test_semantic_contract_schema", "test_semantic_contract_chain", "test_wrapper_contract_compiler", "test_contract_only_publication", "test_source_contract_boundaries"]')
source=source.replace('"test_file_count": len(TESTS),','"test_file_count": len(TESTS),\n    "environment_evidence": "artifacts/coordinator-runtime-r14-20261015.json",')
target.write_text(source,encoding="utf-8",newline="\n")
print(target)
