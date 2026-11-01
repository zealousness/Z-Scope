"""Per-instance symbol/type/macro/graph consumers read exact native receipts.

The navigation projection answers these from one file-level index; the scoped
facade must instead serve the member facts that the native producer stored
under the pinned content-bound ``BuildContext`` and whose compiler ``owner``
is the pinned entry itself.  Everything here runs the real batch indexer,
``CodeIndex`` and ``ScopedCodeIndex``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest

from zscope.config.config import IndexingConfig
from zscope.config.function_entry import FunctionEntry
from zscope.orchestration.entry_instances import plan_entry_instances
from zscope.retrieval.clang_backend import ClangBackend
from zscope.retrieval.code_index import CodeIndex
from zscope.retrieval.instance_index import InstanceScope, ScopedCodeIndex


def _build(tmp_path: Path, source_text: str, *, header: str = ""):
    executable = os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER")
    if not executable:
        pytest.skip("instance symbol tests require Z_SCOPE_TEST_CLANG_INDEXER")
    if header:
        (tmp_path / "flags.h").write_text(header, encoding="utf-8")
    source = tmp_path / "unit.c"
    source.write_text(source_text, encoding="utf-8")
    cdb = tmp_path / "compile_commands.json"
    cdb.write_text(
        json.dumps(
            [
                {
                    "directory": str(tmp_path),
                    "file": str(source),
                    "arguments": ["clang", "-c", str(source), *flags],
                }
                for flags in ([], ["-DALT=1"])
            ]
        ),
        encoding="utf-8",
    )
    backend = ClangBackend(frontend="batch", clang_indexer_path=executable, max_threads=2)
    assert backend.initialize(str(tmp_path), compile_commands_path=str(cdb))
    index = CodeIndex(
        tmp_path, cdb, backend=backend, indexing_config=IndexingConfig(backend="clang")
    )
    return backend, index, cdb


def _views(index: Any, cdb: Path) -> List[Tuple[bool, ScopedCodeIndex]]:
    plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])
    assert plan.status == "planned" and len(plan.instances) == 2
    contexts = {row["build_context_id"]: row for row in index.get_build_contexts("unit.c")}
    views: List[Tuple[bool, ScopedCodeIndex]] = []
    for instance in plan.instances:
        scope = InstanceScope.from_entry_instance(instance)
        alt = "-DALT=1" in contexts[scope.build_context_id]["command"]["arguments"]
        views.append((alt, ScopedCodeIndex(index, scope)))
    return views


CALLEE_SOURCE = (
    "extern void alt_helper(void);\n"
    "extern void base_helper(void);\n"
    "void f(void) {\n"
    "#ifdef ALT\n"
    "  alt_helper();\n"
    "#else\n"
    "  base_helper();\n"
    "#endif\n"
    "}\n"
)


def test_callees_are_the_current_conditional_variant(tmp_path: Path) -> None:
    backend, index, cdb = _build(tmp_path, CALLEE_SOURCE)
    try:
        for alt, view in _views(index, cdb):
            expected = "alt_helper" if alt else "base_helper"
            other = "base_helper" if alt else "alt_helper"
            callees = view.get_callees("f")
            names = [record["name"] for record in callees]
            assert names == [expected], names
            assert other not in names
            record = callees[0]
            assert record["usr"] == f"c:@F@{expected}"
            assert record["build_context_id"] == view.scope.build_context_id
            assert record["owner_usr"] == view.scope.usr
            assert view.scope_report()["served_consumers"].get("get_callees", 0) >= 1
    finally:
        backend.close()


def test_callers_are_scoped_to_the_current_instance(tmp_path: Path) -> None:
    backend, index, cdb = _build(tmp_path, CALLEE_SOURCE)
    try:
        for alt, view in _views(index, cdb):
            own = "alt_helper" if alt else "base_helper"
            other = "base_helper" if alt else "alt_helper"
            callers = view.get_callers(own)
            assert [record["name"] for record in callers] == ["f"], callers
            assert callers[0]["usr"] == view.scope.usr
            assert callers[0]["build_context_id"] == view.scope.build_context_id
            # The other variant's helper is not called in this instance.
            assert view.get_callers(other) == []
    finally:
        backend.close()


MACRO_SOURCE = (
    "#ifdef ALT\n"
    "#define MARK_ALT 11\n"
    "#else\n"
    "#define MARK_BASE 22\n"
    "#endif\n"
    "void f(void) {\n"
    "#ifdef ALT\n"
    "  (void)MARK_ALT;\n"
    "#else\n"
    "  (void)MARK_BASE;\n"
    "#endif\n"
    "}\n"
)


def test_macro_context_is_the_current_conditional_variant(tmp_path: Path) -> None:
    backend, index, cdb = _build(tmp_path, MACRO_SOURCE)
    try:
        for alt, view in _views(index, cdb):
            expected = "MARK_ALT" if alt else "MARK_BASE"
            other = "MARK_BASE" if alt else "MARK_ALT"
            macros = view.get_function_symbol_context("f")["referenced_macros"]
            names = [member["name"] for member in macros]
            assert expected in names, names
            assert other not in names, names
            member = next(item for item in macros if item["name"] == expected)
            # The member carries its own receipt naming the pinned entry + build.
            assert member["function_identity"]["usr"] == view.scope.usr
            assert member["function_identity"]["build_context_id"] == view.scope.build_context_id
            assert (
                view.scope_report()["served_consumers"].get("get_function_symbol_context", 0) >= 1
            )
    finally:
        backend.close()


TYPE_SOURCE = (
    "#ifdef ALT\n"
    "struct AltThing { int a; };\n"
    "#else\n"
    "struct BaseThing { int b; };\n"
    "#endif\n"
    "void f(void) {\n"
    "#ifdef ALT\n"
    "  struct AltThing local;\n"
    "#else\n"
    "  struct BaseThing local;\n"
    "#endif\n"
    "  (void)local;\n"
    "}\n"
)


def test_type_context_is_the_current_conditional_variant(tmp_path: Path) -> None:
    backend, index, cdb = _build(tmp_path, TYPE_SOURCE)
    try:
        for alt, view in _views(index, cdb):
            expected = "AltThing" if alt else "BaseThing"
            other = "BaseThing" if alt else "AltThing"
            types = view.get_function_type_context("f")["referenced_types"]
            names = [item["type_index_name"] for item in types]
            assert expected in names, names
            assert other not in names, names
            assert view.scope_report()["served_consumers"].get("get_function_type_context", 0) >= 1
    finally:
        backend.close()


DOUBLE_FREE_SOURCE = (
    '#include "flags.h"\n'
    "void f(void) {\n"
    "  char *p = malloc(4);\n"
    "  if (!p) { return; }\n"
    "  RELEASE(p);\n"
    "}\n"
)
DOUBLE_FREE_HEADER = (
    "#include <stdlib.h>\n"
    "#ifdef ALT\n"
    "#define RELEASE(p) do { free(p); free(p); } while (0)\n"
    "#else\n"
    "#define RELEASE(p) do { free(p); } while (0)\n"
    "#endif\n"
)


def _config(tmp_path: Path, cdb: Path):
    from zscope.config.config import (
        AgentConfig,
        AnalysisConfig,
        ConcurrencyConfig,
        IndexingConfig,
        LLMConfig,
        ProjectConfig,
        RulesConfig,
        ZScopeConfig,
    )

    return ZScopeConfig(
        llm=LLMConfig(),
        llms={},
        indexing=IndexingConfig(backend="clang"),
        analysis=AnalysisConfig(
            snapshot_dir=str(tmp_path / ".zscope_snapshots"),
            user_config_db=str(tmp_path / ".zscope_user_config"),
        ),
        project=ProjectConfig(
            project_root=tmp_path,
            language="c_cpp",
            compile_commands_path=cdb,
            agents=[AgentConfig(name="vulnerability_analyzer", task="audit")],
        ),
        concurrency=ConcurrencyConfig(entry_workers=2),
        rules=RulesConfig(enabled_ids=["clang_cfg_same_object_released_twice"]),
    )


def _semantic_stub():
    from zscope.orchestration.global_modeler import GlobalModelStats
    from zscope.orchestration.semantic_modeling import SessionSemanticResult
    from zscope.semantics.models import LocalPatternSemantics

    return SessionSemanticResult(
        GlobalModelStats(), local_semantics=LocalPatternSemantics(), overlay={}
    )


def test_stale_header_withdraws_served_symbol_receipts(tmp_path: Path) -> None:
    """A real header edit must withdraw every migrated consumer's cache."""

    executable = os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER")
    if not executable:
        pytest.skip("instance symbol tests require Z_SCOPE_TEST_CLANG_INDEXER")
    header = tmp_path / "flags.h"
    header.write_text("#define FLAG 1\n", encoding="utf-8")
    source = tmp_path / "unit.c"
    source.write_text(
        '#include "flags.h"\nextern void helper(void);\nvoid f(void){ if(FLAG) helper(); }\n',
        encoding="utf-8",
    )
    cdb = tmp_path / "compile_commands.json"
    cdb.write_text(
        json.dumps(
            [
                {
                    "directory": str(tmp_path),
                    "file": str(source),
                    "arguments": ["clang", "-c", str(source)],
                }
            ]
        ),
        encoding="utf-8",
    )
    backend = ClangBackend(frontend="batch", clang_indexer_path=executable, max_threads=1)
    try:
        assert backend.initialize(str(tmp_path), compile_commands_path=str(cdb))
        index = CodeIndex(
            tmp_path, cdb, backend=backend, indexing_config=IndexingConfig(backend="clang")
        )
        context = index.get_build_contexts("unit.c")[0]["build_context_id"]
        facts = index.get_function_program_facts("f", "unit.c", build_context_id=context)
        assert facts["complete"]
        scope = InstanceScope(
            context, facts["function_identity"]["usr"], f"{context}:f", "unit.c", ("f",)
        )
        view = ScopedCodeIndex(index, scope)

        assert [row["name"] for row in view.get_callees("f")] == ["helper"]
        assert {"f", "helper"} <= set(view.list_functions())

        header.write_text("#define FLAG 0\n", encoding="utf-8")
        assert view.dependencies_current_status() == "stale_build_context"
        # Every migrated consumer must withdraw, not serve the pre-edit cache.
        assert view.get_callees("f") == []
        assert view.get_callers("helper") == []
        assert view.list_functions() == []
        assert view.get_function_symbol_context("f")["referenced_macros"] == []
        assert view.get_function_type_context("f")["referenced_types"] == []
    finally:
        backend.close()


def test_analyzer_and_validation_read_per_instance_symbols(tmp_path: Path, monkeypatch) -> None:
    """The real Analyzer path consumes the migrated consumers, not a fake list."""

    from zscope.orchestration import parallel_analyzer as parallel_module
    from zscope.orchestration.parallel_analyzer import ParallelAnalyzer

    backend, index, cdb = _build(tmp_path, DOUBLE_FREE_SOURCE, header=DOUBLE_FREE_HEADER)
    try:
        plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])
        assert plan.status == "planned" and len(plan.instances) == 2

        facades: List[ScopedCodeIndex] = []
        original = parallel_module.wrap_scoped_code_index

        def recording(base: Any, scope: InstanceScope) -> Any:
            scoped = original(base, scope)
            if isinstance(scoped, ScopedCodeIndex):
                facades.append(scoped)
            return scoped

        monkeypatch.setattr(parallel_module, "wrap_scoped_code_index", recording)

        # The entry-level façade is constructed directly (not through the
        # factory above), so record it too: it is the object the Analyzer
        # actually queries for per-instance symbols.
        lookup_base = parallel_module._InstanceEntryLookupIndex

        class RecordingLookup(lookup_base):  # type: ignore[misc, valid-type]
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                super().__init__(*args, **kwargs)
                facades.append(self)

        monkeypatch.setattr(parallel_module, "_InstanceEntryLookupIndex", RecordingLookup)
        parallel = ParallelAnalyzer(
            _config(tmp_path, cdb), code_index=index, semantic_result=_semantic_stub()
        )
        try:
            report = parallel.analyze_entry_instances(plan)
            assert report.analyzed_instances == 2
            assert facades, "scoped facades must be built for the scheduled instances"
            served: Dict[str, int] = {}
            for facade in facades:
                for name, count in facade.scope_report()["served_consumers"].items():
                    served[name] = served.get(name, 0) + count
            assert served.get("get_callees", 0) >= 1, served
            assert served.get("list_functions", 0) >= 1, served
            # The exact data is variant-correct for the double-free fixture.
            for facade in facades:
                names = {record["name"] for record in facade.get_callees("f")}
                assert {"malloc", "free"} <= names, names
        finally:
            parallel.close()
    finally:
        backend.close()
