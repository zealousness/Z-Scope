"""Actual native facts use source_root paths; navigation keeps project paths."""

import json
import os

import pytest

from zscope.config.function_entry import FunctionEntry
from zscope.orchestration.entry_instances import plan_entry_instances
from zscope.orchestration.parallel_analyzer import ParallelAnalyzer
from zscope.retrieval.code_index import CodeIndex
from zscope.retrieval.instance_index import InstanceScope, ScopedCodeIndex
from test_instance_analysis import _native_config, _semantic_stub


@pytest.fixture
def indexed_source_subdir(tmp_path):
    tool = os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER")
    assert tool, "actual native indexer required"
    source = tmp_path / "src"
    source.mkdir()
    (source / "flags.h").write_text(
        "#include <stdlib.h>\n#ifdef ALT\n#define RELEASE(p) do { free(p); free(p); } while(0)\n#else\n#define RELEASE(p) free(p)\n#endif\n",
        encoding="utf-8",
    )
    (source / "unit.c").write_text(
        '#include "flags.h"\nvoid f(void){char *p=malloc(4); if(!p)return; RELEASE(p);}\n',
        encoding="utf-8",
    )
    (tmp_path / "unit.c").write_text("void f(void) {}\n", encoding="utf-8")
    cdb = tmp_path / "compile_commands.json"
    cdb.write_text(
        json.dumps(
            [
                {
                    "directory": str(tmp_path),
                    "file": str(source / "unit.c"),
                    "arguments": ["clang", "-c", str(source / "unit.c"), *flags],
                }
                for flags in ([], ["-DALT=1"])
            ]
        ),
        encoding="utf-8",
    )
    config = _native_config(tmp_path, cdb, source)
    config.indexing.clang_frontend = "batch"
    config.indexing.clang_indexer_path = tool
    config.project.include_paths = [str(source)]
    index = CodeIndex(
        tmp_path, cdb, source_root=source, indexing_config=config.indexing, include_paths=[source]
    )
    try:
        yield tmp_path, source, config, index
    finally:
        index.close()


@pytest.mark.parametrize("path_form", ["source_relative", "project_relative", "absolute"])
def test_actual_native_source_subdir_preserves_precise_query_identity(
    indexed_source_subdir, path_form
):
    root, source, config, index = indexed_source_subdir
    path = {
        "source_relative": "unit.c",
        "project_relative": "src/unit.c",
        "absolute": str(source / "unit.c"),
    }[path_form]
    contexts = index.get_build_contexts(path)
    assert len(contexts) == 2
    assert {row["source"] for row in contexts} == {"unit.c"}
    assert {row["build_context_id"] for row in index.get_function_build_contexts("f", path)} == {
        row["build_context_id"] for row in contexts
    }
    plan = plan_entry_instances(index, [FunctionEntry("f", file_path=path)])
    assert len(plan.instances) == 2, plan.to_payload()
    for instance in plan.instances:
        facts = index.get_function_program_facts(
            instance.usr, path, build_context_id=instance.build_context_id
        )
        assert facts["complete"] is True, facts
        assert facts["function_identity"]["usr"] == instance.usr
        rows = index.get_compilation_facts(
            instance.build_context_id,
            symbol=instance.usr,
            file_path=path,
            kinds=("program_function",),
        )
        assert rows
        scoped = ScopedCodeIndex(index, InstanceScope.from_entry_instance(instance))
        assert scoped.get_function_program_facts("f", path)["complete"] is True
    # The same basename in the project root is another real file, outside
    # the indexed compilation. Exact queries cannot silently select src/unit.c.
    assert index.get_build_contexts(str(root / "unit.c")) == []
    assert index.get_function_build_contexts("f", str(root / "unit.c")) == []
    assert not index.get_function_program_facts(
        "f", str(root / "unit.c"), build_context_id=contexts[0]["build_context_id"]
    )["complete"]


def test_actual_analysis_of_source_subdir_keeps_variant_candidates_separate(indexed_source_subdir):
    root, source, config, index = indexed_source_subdir
    plan = plan_entry_instances(index, [FunctionEntry("f", file_path="src/unit.c")])
    assert len(plan.instances) == 2
    parallel = ParallelAnalyzer(config, code_index=index, semantic_result=_semantic_stub())
    report = parallel.analyze_entry_instances(plan)
    assert report.analyzed_instances == 2
    assert report.instance_scope_complete is True, report.to_payload()
    assert sorted(
        len([c for c in row.issues if c["defect_class"] == "double_free"])
        for row in report.outcomes
    ) == [0, 1]
    assert all(
        c["build_context_id"] == row.build_context_id for row in report.outcomes for c in row.issues
    )
