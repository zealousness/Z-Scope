"""A status return is not the resource written to a global or output slot."""

import re

import pytest

from test_wrapper_contract_compiler import context, compile_all, publish
from zscope.semantics.contracts import expand_api_pattern
from zscope.semantics.defaults import default_local_pattern_semantics
from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
from zscope.core.candidates.regex import RegexCandidateGenerator
from zscope.core.candidates.graph import GraphCandidateGenerator


@pytest.mark.parametrize(
    "kind,body,args,object_name",
    [
        ("global", "slot=malloc(n);", "8", "slot"),
        ("output", "*out=malloc(n);", "8,&p", "p"),
    ],
)
def test_actual_workbook_preserves_carrier_and_does_not_classify_status_as_pointer(
    tmp_path, kind, body, args, object_name
):
    params = "size_t n,void **out" if kind == "output" else "size_t n"
    ctx = context("prepare", f"int prepare({params}) {{ {body} return 0; }}")
    ctx["referenced_globals"] = [{"name": "slot"}]
    _, custom, overlay = publish(tmp_path, compile_all([ctx]))
    semantics = default_local_pattern_semantics()
    semantics.merge(custom)
    statement = f"int status=prepare({args});"
    pattern = expand_api_pattern(r"\bmalloc\s*\(", semantics)
    assert not re.search(pattern, statement)
    for cls in (ClangAstCfgCandidateGenerator, RegexCandidateGenerator):
        engine = cls(semantics)
        code = "void entry(void) {\nvoid *p;\n" + statement + "\nreturn;\n}"
        issues = engine.generate_issues("entry", code, "entry.c")
        events = [e for e in engine.last_semantic_events if e["symbol"]["name"] == "prepare"]
        assert events and {e["object"] for e in events} == {object_name}
        assert not any(
            i["defect_class"] == "memory_leak" and "status" in str(i.get("evidence", ""))
            for i in issues
        )
        call_pattern = (
            engine._alloc_call_re if cls is ClangAstCfgCandidateGenerator else engine._alloc_re
        )
        assert not call_pattern.search(statement)
    graph = GraphCandidateGenerator(object(), semantics, overlay)
    assert not graph._alloc_assign_re.search(statement)
    events = graph.semantics.contracts.trace_calls(
        {"code": "void entry(void) { " + statement + " }", "func_name": "entry"}
    )
    assert {e["object"] for e in events if e["symbol"]["name"] == "prepare"} == {object_name}


def test_return_allocator_still_matches_after_reload(tmp_path):
    _, custom, _ = publish(
        tmp_path, compile_all([context("obtain", "void *obtain(size_t n) { return malloc(n); }")])
    )
    semantics = default_local_pattern_semantics()
    semantics.merge(custom)
    for cls in (ClangAstCfgCandidateGenerator, RegexCandidateGenerator):
        engine = cls(semantics)
        issues = engine.generate_issues(
            "entry",
            "void entry(void) {\nvoid *p=obtain(8);\nif (!p) return;\nreturn;\n}",
            "entry.c",
        )
        assert any(i["defect_class"] == "memory_leak" for i in issues)
    graph = GraphCandidateGenerator(object(), semantics)
    assert graph._alloc_assign_re.search("void *p=obtain(8);")
