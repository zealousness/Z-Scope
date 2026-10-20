"""Executable business-protocol cases, separate from the scanner's inputs."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
from zscope.core.candidates.regex import RegexCandidateGenerator
from zscope.retrieval.clang_backend import ClangBackend
from zscope.retrieval.code_index import CodeIndex


@pytest.fixture
def protocol_project(tmp_path):
    if sys.platform != "linux":
        pytest.skip("protocol execution requires Linux")
    compiler = shutil.which("clang")
    if not compiler:
        pytest.skip("protocol execution requires clang")
    source = tmp_path / "pool_queue.c"
    shutil.copyfile(Path(__file__).parent / "fixtures/resource_protocols/pool_queue.c", source)
    binary = tmp_path / "protocol"
    command = [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-O0", "-g", str(source)]
    subprocess.run([*command, "-o", str(binary)], check=True, capture_output=True, timeout=30)
    database = tmp_path / "compile_commands.json"
    database.write_text(
        json.dumps(
            [
                {
                    "directory": str(tmp_path),
                    "file": str(source),
                    "arguments": [*command, "-c", "-o", "pool_queue.o"],
                }
            ]
        )
    )
    return tmp_path, source, binary, database


@pytest.mark.parametrize(
    "case,live,duplicate", [(0, 0, 1), (1, 0, 0), (2, 1, 0), (3, 0, 0), (4, 0, 1), (5, 0, 0)]
)
def test_pool_queue_execution(protocol_project, case, live, duplicate):
    _, _, binary, _ = protocol_project
    run = subprocess.run(
        [str(binary), str(case)], check=True, capture_output=True, text=True, timeout=5
    )
    assert json.loads(run.stdout) == {"live": live, "duplicate_returns": duplicate}


def test_record_native_candidate_baseline_without_loading_answers(protocol_project, monkeypatch):
    executable = os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER")
    if not executable:
        pytest.skip("native baseline requires Z_SCOPE_TEST_CLANG_INDEXER")
    root, source, _, database = protocol_project
    monkeypatch.setattr(
        ClangBackend, "_ensure_extractor", lambda self: pytest.fail("unexpected LSP")
    )
    backend = ClangBackend(frontend="batch", clang_indexer_path=executable, max_threads=1)
    try:
        assert backend.initialize(str(root), compile_commands_path=str(database))
        index = CodeIndex(
            root, database, backend=backend, indexing_config=SimpleNamespace(backend="clang")
        )
        builds = index.get_build_contexts(str(source))
        assert len(builds) == 1
        result = {
            "schema": "zscope.protocol-baseline.v1",
            "build_context_id": builds[0]["build_context_id"],
            "validator_executed": False,
            "llm_executed": False,
            "functions": [],
        }
        for name in ("submit_a", "submit_b", "submit_c", "cancel_a", "cancel_b", "queue_complete"):
            facts = index.get_function_program_facts(
                name, str(source), build_context_id=builds[0]["build_context_id"]
            )
            assert facts["complete"] and facts["events"]
            implementation = index.get_function_impl(
                name, file_path=str(source), include_context=False
            )
            assert implementation and implementation["code"]
            row = {"function": name, "events": len(facts["events"]), "candidates": {}}
            for kind, generator_type in (
                ("regex", RegexCandidateGenerator),
                ("clang", ClangAstCfgCandidateGenerator),
            ):
                generator = generator_type(program_facts_provider=lambda *_: facts)
                row["candidates"][kind] = generator.generate_issues(
                    name, implementation["code"], str(source)
                )
            result["functions"].append(row)
        (root / "protocol-baseline.json").write_text(
            json.dumps(result, indent=2, ensure_ascii=False)
        )
        assert all(row["events"] for row in result["functions"])
    finally:
        backend.close()
