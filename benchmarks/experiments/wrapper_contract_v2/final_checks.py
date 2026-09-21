"""Run the final Linux checks after hash-guarded refinement integration."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys


def main() -> None:
    root = Path(__file__).resolve().parents[3]
    artifacts = root / "benchmark-artifacts/pool-protocol-v3"
    assert sys.platform == "linux", "Checks require the WSL/Linux Python environment"
    assert (artifacts / "integration-result.json").is_file(), "Integrate before root checks"
    output = artifacts / "final-checks"
    output.mkdir(exist_ok=True)
    env = os.environ.copy()
    for name in ("Z_SCOPE_API_KEY", "Z_SCOPE_LLM_BASE_URL", "Z_SCOPE_LLM_MODEL"):
        env.pop(name, None)
    env["PYTHONPATH"] = str(root)
    env["Z_SCOPE_TEST_CLANG_INDEXER"] = (
        "/home/zeal/.cache/zscope-wrapper-v2/install/bin/zscope-clang-indexer"
    )
    names = """
        wrapper_contract_compiler wrapper_failure_guards wrapper_error_cleanup
        wrapper_pointer_casts acquisition_carrier_consumers pair_evidence_authority
        contract_only_publication security_map_contracts pool_protocol_modeling
        semantic_contract_schema semantic_modeling_usage semantic_model_retry
        semantic_model_input semantic_contract_chain incremental_semantic_modeling
        parallel_shared_semantics semantic_inference analyzer_semantics semantics_defaults
        risk_api_semantics security_semantic_map security_semantics_tool
        clang_ast_cfg_candidates clang_cfg_custom_apis regex_candidates graph_candidates
        cpp_candidate_domains source_lifecycle_provider candidate_ledger candidate_pipeline
        candidate_rule_policy candidate_evidence candidate_decision_context
        validation_pipeline validator_agent_parsing validator_evidence_slice
        user_config_workbook user_config_overlay_new_kinds user_config_inference_new_roles
        snapshot_store snapshot_tool rule_catalog rule_implementation rule_qualification
        rule_runtime_governance agent_docs user_config_workbook_readme
    """.split()
    tests = [f"tests/test_{name}.py" for name in names]
    assert all((root / path).is_file() for path in tests)
    commands = {
        "pytest": [sys.executable, "-m", "pytest", "-vv", *tests],
        "compileall": [
            sys.executable,
            "-m",
            "compileall",
            "-f",
            "-q",
            "zscope",
            "scripts",
            "test",
            "tests",
            "benchmarks/experiments/wrapper_contract_v2",
        ],
        "mypy": [sys.executable, "-m", "mypy", "zscope"],
    }
    records = {}
    for label, command in commands.items():
        started = datetime.now(timezone.utc).isoformat()
        with (output / f"{label}.log").open("w", encoding="utf-8") as log:
            result = subprocess.run(
                command, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT
            )
        records[label] = {
            "command": command,
            "started_at": started,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "exit_code": result.returncode,
        }
        (output / "results.json").write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
        print(label, result.returncode, flush=True)
    if any(record["exit_code"] for record in records.values()):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
