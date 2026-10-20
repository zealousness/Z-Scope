"""Native function identities must select one body in one compilation instance."""

import json
import os
from types import SimpleNamespace

import pytest

from zscope.retrieval.clang_backend import ClangBackend
from zscope.retrieval.code_index import CodeIndex
from zscope.tools.semantic_context import SemanticContextTool
from zscope.tools.symbols import SymbolCatalog


def test_function_receipt_changes_do_not_destroy_semantic_reuse():
    from copy import deepcopy
    from zscope.semantics.compiler_fingerprint import compiler_structure

    facts = {
        "build_context_id": "old",
        "build_context": {"build_context_id": "old", "command_id": "same"},
        "function_identity": {"key": "old-key", "build_context_id": "old", "usr": "c:@F@f#I#"},
    }
    updated = deepcopy(facts)
    updated["build_context_id"] = "new"
    updated["build_context"]["build_context_id"] = "new"
    updated["function_identity"].update(key="new-key", build_context_id="new")
    assert compiler_structure(updated) == compiler_structure(facts)
    updated["function_identity"]["usr"] = "c:@F@f#C#"
    assert compiler_structure(updated) != compiler_structure(facts)


@pytest.fixture
def symbols(tmp_path, monkeypatch):
    executable = os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER")
    if not executable:
        pytest.skip("real native indexer required")
    monkeypatch.setenv("Z_SCOPE_CLANG_BATCH_MEMORY_MB", "512")
    (tmp_path / "shared.h").write_text(
        "static int local(int *p) {\n#if OFFSET\nreturn p[1];\n#else\nreturn p[0];\n#endif\n}\n",
        encoding="utf-8",
    )
    (tmp_path / "a.cpp").write_text(
        '#include "shared.h"\n'
        "int value;\n"
        "int f(int *p) { value = 1; return p[0]; }\n"
        "int f(char *p) { value = 2; return p[1]; }\n"
        "int first(int *p) { return local(p); }\n",
        encoding="utf-8",
    )
    (tmp_path / "b.cpp").write_text(
        '#include "shared.h"\nint second(int *p) { return local(p); }\n',
        encoding="utf-8",
    )
    cdb = tmp_path / "compile_commands.json"
    cdb.write_text(
        json.dumps(
            [
                dict(
                    file=str(tmp_path / name),
                    directory=str(tmp_path),
                    arguments=["clang++", "-c", str(tmp_path / name), f"-DOFFSET={offset}"],
                )
                for name, offset in (("a.cpp", 0), ("b.cpp", 1))
            ]
        ),
        encoding="utf-8",
    )
    backend = ClangBackend(frontend="batch", clang_indexer_path=executable, max_threads=1)
    try:
        assert backend.initialize(str(tmp_path), compile_commands_path=str(cdb))
        index = CodeIndex(
            tmp_path, cdb, backend=backend, indexing_config=SimpleNamespace(backend="clang")
        )
        yield index, tmp_path
    finally:
        backend.close()


def test_overloads_expose_choices_without_mixing_proof_events(symbols):
    index, _ = symbols
    context = index.get_build_contexts("a.cpp")[0]["build_context_id"]
    facts = index.get_function_program_facts("f", build_context_id=context)
    assert facts["reason"] == "ambiguous_function_identity"
    assert not facts["complete"]
    assert facts["functions"] == facts["events"] == facts["accesses"] == []
    choices = facts["function_choices"]
    assert len(choices) == 2
    assert len({choice["usr"] for choice in choices}) == 2
    for choice in choices:
        exact = index.get_function_program_facts(choice["usr"], build_context_id=context)
        assert exact["complete"]
        assert exact["functions"][0]["owner"]["usr"] == choice["usr"]
        assert {row["owner"]["usr"] for row in exact["accesses"]} == {choice["usr"]}
        assert exact["function_identity"]["build_context_id"] == context
        assert exact["function_identity"]["usr"] == choice["usr"]
    unknown = index.get_function_program_facts("c:@F@missing#", build_context_id=context)
    assert not unknown["complete"] and not unknown["events"]
    assert unknown["reason"] == "function_identity_not_found"


def test_static_header_usr_stays_separate_between_translation_units(symbols):
    index, _ = symbols
    bodies = [
        index.get_function_program_facts("local", build_context_id=ctx["build_context_id"])
        for ctx in index.get_build_contexts()
    ]
    assert all(body["complete"] for body in bodies)
    assert len({body["function_identity"]["usr"] for body in bodies}) == 1
    assert len({body["function_identity"]["key"] for body in bodies}) == 2
    expressions = [{event["expression"] for event in body["events"]} for body in bodies]
    assert expressions[0] != expressions[1]
    ambiguous = index.get_function_program_facts(bodies[0]["function_identity"]["usr"])
    assert ambiguous["reason"] == "ambiguous_build_context"
    assert not ambiguous["events"]


def test_semantic_tool_can_select_native_usr_and_reject_stale_inputs(symbols):
    index, root = symbols
    context = index.get_build_contexts("a.cpp")[0]["build_context_id"]
    tool = SemanticContextTool(
        SimpleNamespace(snapshot_dir=root / "snapshots"),
        index,
        SymbolCatalog(index),
        resolver=lambda *_: pytest.fail("must not request modeling"),
        cache_only=True,
    )
    ambiguous = tool.execute(
        {"kind": "program_facts", "query": "f", "build_context_id": context, "limit": 1}
    )
    assert ambiguous["status"] == "partial"
    assert ambiguous["page"]["total"] == 2 and ambiguous["page"]["has_more"]
    assert ambiguous["data"]["records"][0]["kind"] == "function_choice"
    usr = ambiguous["data"]["records"][0]["usr"]
    exact = tool.execute({"kind": "program_facts", "query": usr, "build_context_id": context})
    assert exact["status"] == "ok"
    assert exact["data"]["summary"]["function_identity"]["usr"] == usr
    (root / "shared.h").write_text("static int local(int *p) { return p[2]; }\n", encoding="utf-8")
    stale = tool.execute({"kind": "program_facts", "query": usr, "build_context_id": context})
    assert stale["status"] == "partial" and stale["data"]["records"] == []
