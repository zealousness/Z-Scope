"""Synthetic scope probes through real metadata and SymbolCatalog consumers."""
import threading
from types import SimpleNamespace

from zscope.retrieval.instance_index import InstanceScope, ScopedCodeIndex
from zscope.tools.symbols import SymbolCatalog


def view(base):
    return ScopedCodeIndex(base, InstanceScope("current", "usr-current", "exact", "unit.c", ("f",)))


def test_symbol_catalog_cannot_consume_unscoped_function_cache():
    base = SimpleNamespace(
        language="c_cpp", backend_name="clang", _cache_lock=threading.RLock(),
        _function_index={"foreign": {"name": "other_variant", "file": "unit.c", "start_line": 9}},
    )
    scoped = view(base)
    assert SymbolCatalog(scoped)._function_records() == [], (
        "real SymbolCatalog bypasses blocked list_functions via the plain _function_index cache"
    )


def test_explicit_foreign_file_cannot_return_entry_metadata():
    base = SimpleNamespace(find_function_infos=lambda *a, **k: [
        {"name": "f", "file": "unit.c", "start_line": 1}
    ])
    assert view(base).find_function_metadata("f", file_path="other.c") == []


def test_ambiguous_metadata_is_rejected_at_consumption():
    base = SimpleNamespace(find_function_infos=lambda *a, **k: [
        {"name": "f", "file": "unit.c", "start_line": 1},
        {"name": "f", "file": "unit.c", "start_line": 9},
    ])
    assert view(base).find_function_metadata("f") == [], "a gap label does not authorize both overloads"


def test_entry_type_context_cannot_reuse_foreign_projection():
    base = SimpleNamespace(get_function_type_context=lambda *a, **k: {
        "referenced_types": [{"name": "OtherVariantType", "build_context_id": "foreign"}]
    })
    assert not view(base).get_function_type_context("f").get("referenced_types")


def test_entry_macro_context_cannot_reuse_foreign_projection():
    base = SimpleNamespace(get_function_symbol_context=lambda *a, **k: {
        "referenced_macros": [{"name": "ALT", "replacement_text": "1", "build_context_id": "foreign"}],
        "referenced_globals": [],
    })
    assert not view(base).get_function_symbol_context("f").get("referenced_macros")
