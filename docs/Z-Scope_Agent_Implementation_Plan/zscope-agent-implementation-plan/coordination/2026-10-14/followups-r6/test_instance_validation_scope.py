"""Actual native candidate/validation dispatch plus synthetic receipt boundaries."""
from pathlib import Path
import sys

from zscope.orchestration import parallel_analyzer as parallel_module
from zscope.retrieval.instance_index import ScopedCodeIndex

sys.path.insert(0, str(Path(parallel_module.__file__).resolve().parents[2] / "tests"))
from test_instance_analysis import (  # noqa: E402
    native_variants, _native_config, _native_index, _semantic_stub,
    _ScopedIndex, _context, _facts, _scope, _write,
)


def test_real_native_candidate_validation_keeps_instance_index(native_variants, monkeypatch):
    from zscope.config.function_entry import FunctionEntry
    from zscope.orchestration.entry_instances import plan_entry_instances

    backend, root, cdb = native_variants
    index = _native_index(backend, root, cdb)
    plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])
    seen = []
    original = parallel_module.Analyzer.__init__

    def observe(self, *args, **kwargs):
        if kwargs.get("defer_validation_to_scan") is False:
            seen.append({"index": kwargs.get("code_index"), "semantics": kwargs.get("semantic_result")})
        original(self, *args, **kwargs)

    monkeypatch.setattr(parallel_module.Analyzer, "__init__", observe)
    parallel = parallel_module.ParallelAnalyzer(
        _native_config(root, cdb, root), code_index=index, semantic_result=_semantic_stub()
    )
    try:
        report = parallel.analyze_entry_instances(plan)
        assert report.analyzed_instances == 2
        assert any(outcome.issues for outcome in report.outcomes), "native candidate must reach validation"
        assert seen, "actual shared validation helper must run"
        assert all(isinstance(row["index"], ScopedCodeIndex) for row in seen), (
            "post-discovery validation reopened the unscoped index"
        )
        assert all(row["semantics"] is None for row in seen), "global semantic_result cannot authorize an instance verdict"
    finally:
        parallel.close()


def receipt_view(tmp_path, method, payload):
    from zscope.retrieval.indexing_identity import file_digest
    source = _write(tmp_path, "unit.c", "int f(void){return 0;}\n")
    context = _context("ctx-a", str(source), dependencies={str(source): file_digest(source)})
    base = _ScopedIndex([context], {"ctx-a": [_facts("c:@F@f", "f", str(source))]})
    setattr(base, method, lambda *args, **kwargs: payload)
    return ScopedCodeIndex(base, _scope("ctx-a", "c:@F@f", str(source)))


def test_same_build_foreign_usr_does_not_authorize_type_context(tmp_path):
    scoped = receipt_view(tmp_path, "get_function_type_context", {"referenced_types": [{
        "name": "OtherOverloadType", "build_context_id": "ctx-a",
        "function_identity": {"usr": "c:@F@other", "build_context_id": "ctx-a"},
    }]})
    assert scoped.get_function_type_context("f")["referenced_types"] == []


def test_outer_build_tag_does_not_authorize_unreceipted_macro(tmp_path):
    scoped = receipt_view(tmp_path, "get_function_symbol_context", {
        "build_context_id": "ctx-a", "referenced_globals": [],
        "referenced_macros": [{"name": "ALT", "replacement_text": "1"}],
    })
    assert scoped.get_function_symbol_context("f")["referenced_macros"] == []
