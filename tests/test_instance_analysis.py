"""Real per-instance analysis: exact ``(BuildContext, native USR)`` scope.

The scan boundary enumerates entry compile instances, but entry analysis used
to consume the file navigation projection.  These tests cover the execution
path that actually feeds one exact instance to the real Analyzer: program facts
are pinned to the instance's build context, a foreign or missing identity stays
an explicit scope gap, and a candidate that only exists in one macro variant is
produced only for that variant with its own build identity.

The synthetic tests exercise the scoped facade and report shapes directly; the
native-gated tests run the real ClangBatch index, real ``CodeIndex`` facade and
real ``ParallelAnalyzer`` end to end.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest

from zscope.config.function_entry import FunctionEntry
from zscope.orchestration.entry_instances import (
    EntryInstance,
    EntryInstancePlan,
)
from zscope.retrieval.build_context import program_facts_result
from zscope.retrieval.indexing_identity import file_digest
from zscope.retrieval.instance_index import (
    GAP_FOREIGN_BUILD_CONTEXT,
    GAP_IDENTITY_CONTEXT_MISMATCH,
    GAP_IDENTITY_CONTEXT_UNVERIFIED,
    GAP_UNKNOWN_BUILD_CONTEXT,
    InstanceAnalysisOutcome,
    InstanceAnalysisReport,
    InstanceScope,
    ScopedCodeIndex,
    run_instance_analysis,
    wrap_scoped_code_index,
)

# ── Synthetic doubles (native facts are not faked by these) ──


def _write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def _context(
    context_id: str,
    source: str,
    *,
    dependencies: Optional[Dict[str, str]] = None,
    status: str = "indexed",
    dependencies_complete: bool = True,
) -> Dict[str, Any]:
    return {
        "build_context_id": context_id,
        "source": source,
        "status": status,
        "dependencies_complete": dependencies_complete,
        "dependencies": dict(dependencies or {}),
        "command": {
            "source": source,
            "directory": str(Path(source).parent),
            "arguments": ["clang", "-c", source],
        },
    }


def _facts(
    usr: str, name: str, file_path: str, events: Optional[List[str]] = None, line: int = 1
) -> Dict[str, Any]:
    return {
        "kind": "program_function",
        "complete": True,
        "owner": {"usr": usr, "name": name, "file": file_path, "line": line},
        "location": {"file": file_path, "line": line},
        "events": list(events or []),
    }


def _scope(
    context_id: str, usr: str, source: str, names: Tuple[str, ...] = ("f",)
) -> InstanceScope:
    return InstanceScope(
        build_context_id=context_id,
        usr=usr,
        identity=f"{context_id}:{usr}",
        source=source,
        function_names=names,
    )


class _ScopedIndex:
    """Minimal index double: exact-context program facts only."""

    language = "c_cpp"
    backend_name = "clang"

    def __init__(self, contexts: List[Dict[str, Any]], rows: Dict[str, List[Dict[str, Any]]]):
        self.contexts = [dict(context) for context in contexts]
        self.rows = {key: [dict(row) for row in value] for key, value in rows.items()}
        self.queries: List[Tuple[str, str, str]] = []

    def get_build_contexts(self, file_path: str = "") -> List[Dict[str, Any]]:
        if not file_path:
            return [dict(context) for context in self.contexts]
        return [dict(context) for context in self.contexts if context["source"] == file_path]

    def _source(self) -> str:
        return str(self.contexts[0]["source"]) if self.contexts else ""

    def _entry_identity(self, func_name: str) -> str:
        return f"{func_name}@{self._source()}:1-1"

    def find_function_identities(self, func_name: str, file_path: str = "") -> List[Dict[str, Any]]:
        for rows in self.rows.values():
            for row in rows:
                if row["owner"]["name"] == func_name:
                    return [
                        {
                            "function_name": func_name,
                            "file_path": file_path or str(row["owner"]["file"]),
                            "index_name": self._entry_identity(func_name),
                            "start_line": 1,
                            "end_line": 1,
                        }
                    ]
        return []

    def get_function_impl(
        self,
        func_name: str,
        max_lines: Any = 500,
        warn_missing: bool = True,
        include_context: bool = True,
        file_path: str = "",
    ) -> Dict[str, Any]:
        return {
            "func_name": str(func_name),
            "file": file_path or self._source(),
            "index_name": self._entry_identity(str(func_name).split("@", 1)[0]),
            "start_line": 1,
            "end_line": 1,
            "signature": "",
            "code": "int f(void){return 0;}\n",
        }

    def get_compilation_facts(
        self,
        context_id: str,
        *,
        kinds: Tuple[str, ...] = (),
        symbol: str = "",
        file_path: str = "",
    ) -> List[Dict[str, Any]]:
        rows = [dict(row) for row in self.rows.get(context_id, [])]
        if kinds:
            rows = [row for row in rows if row.get("kind") in kinds]
        if symbol:
            rows = [row for row in rows if (row.get("owner") or {}).get("name") == symbol]
        if file_path:
            rows = [
                row
                for row in rows
                if not (row.get("owner") or {}).get("file")
                or (row.get("owner") or {}).get("file") == file_path
            ]
        return rows

    def get_function_program_facts(
        self, name: str, file_path: str = "", *, build_context_id: str = ""
    ) -> Dict[str, Any]:
        self.queries.append((name, file_path, build_context_id))
        if not build_context_id:
            return {"complete": False, "events": [], "accesses": [], "reason": "unscoped_query"}
        context = next(
            (c for c in self.contexts if c["build_context_id"] == build_context_id), None
        )
        if context is None:
            return {
                "complete": False,
                "events": [],
                "accesses": [],
                "functions": [],
                "reason": "build_context_not_found",
                "build_context_id": build_context_id,
            }
        rows = list(self.rows.get(build_context_id, []))
        if name.startswith("c:"):
            rows = [row for row in rows if row["owner"]["usr"] == name]
        else:
            rows = [row for row in rows if row["owner"]["name"] == name]
        if not rows:
            return {
                "complete": False,
                "events": [],
                "accesses": [],
                "functions": [],
                "reason": "function_identity_not_found",
                "build_context_id": build_context_id,
            }
        return program_facts_result(rows, context=context)

    def get_callees(self, func_name: str, limit: int = 30) -> List[Dict[str, Any]]:
        return []

    def find_function_infos(
        self, func_name: str, file_path: str = "", **_: Any
    ) -> List[Dict[str, Any]]:
        return []


class _CannedIndex(_ScopedIndex):
    """Serves canned program-facts responses to model inconsistent getters."""

    def __init__(self, contexts: List[Dict[str, Any]], responses: Dict[Tuple[str, str, str], Any]):
        super().__init__(contexts, {})
        self.responses = dict(responses)

    def get_function_program_facts(
        self, name: str, file_path: str = "", *, build_context_id: str = ""
    ) -> Dict[str, Any]:
        self.queries.append((name, file_path, build_context_id))
        return self.responses.get(
            (build_context_id, name, file_path),
            {
                "complete": False,
                "events": [],
                "accesses": [],
                "reason": "function_identity_not_found",
            },
        )


# ── Scoped facade: identity is never a wildcard ──


def test_foreign_build_context_query_is_rejected_without_base_query(tmp_path: Path) -> None:
    source = _write(tmp_path, "unit.c", "int f(void){return 0;}\n")
    context = _context("ctx-a", str(source), dependencies={str(source): file_digest(source)})
    index = _ScopedIndex([context], {"ctx-a": [_facts("c:@F@f", "f", str(source))]})
    scoped = ScopedCodeIndex(index, _scope("ctx-a", "c:@F@f", str(source)))

    facts = scoped.get_function_program_facts("f", str(source), build_context_id="ctx-b")

    assert facts["complete"] is False
    assert facts["reason"] == GAP_FOREIGN_BUILD_CONTEXT
    # No foreign identity may leak back into a consumer.
    assert "build_context_id" not in facts
    assert index.queries == []
    gaps = scoped.scope_report()["scope_gaps"]
    assert [gap["reason"] for gap in gaps] == [GAP_FOREIGN_BUILD_CONTEXT]


def test_entry_query_is_rewritten_to_the_pinned_usr(tmp_path: Path) -> None:
    source = _write(tmp_path, "unit.c", "int f(int); int f(short);\n")
    context = _context("ctx-a", str(source), dependencies={str(source): file_digest(source)})
    index = _ScopedIndex(
        [context],
        {
            "ctx-a": [
                _facts("c:@F@f#I#", "f", str(source)),
                _facts("c:@F@f#S#", "f", str(source)),
            ]
        },
    )
    scoped = ScopedCodeIndex(index, _scope("ctx-a", "c:@F@f#S#", str(source)))

    facts = scoped.get_function_program_facts("f", str(source))

    assert facts["complete"] is True
    # The bare name was resolved through the pinned USR, never a first overload.
    assert index.queries == [("c:@F@f#S#", str(source), "ctx-a")]
    assert facts["function_identity"]["usr"] == "c:@F@f#S#"
    assert scoped.scope_report()["facts_complete"] is True


def test_returned_identity_naming_another_context_is_a_gap(tmp_path: Path) -> None:
    source = _write(tmp_path, "unit.c", "int f(void){return 0;}\n")
    digest = file_digest(source)
    context_a = _context("bc-a", str(source), dependencies={str(source): digest})
    context_b = _context("bc-b", str(source), dependencies={str(source): digest})
    foreign = program_facts_result([_facts("usr-main", "f", str(source))], context=context_b)
    index = _CannedIndex(
        [context_a],
        {
            ("bc-a", "c:@F@f", str(source)): foreign,
            ("bc-a", "f", str(source)): foreign,
        },
    )
    scoped = ScopedCodeIndex(index, _scope("bc-a", "c:@F@f", str(source)))

    facts = scoped.get_function_program_facts("f", str(source))

    assert facts["complete"] is False
    assert facts["reason"] == GAP_IDENTITY_CONTEXT_MISMATCH
    assert facts.get("build_context_id") is None
    assert facts["observed_build_context_id"] == "bc-b"


def test_complete_entry_facts_without_identity_are_not_a_wildcard(tmp_path: Path) -> None:
    source = _write(tmp_path, "unit.c", "int f(void){return 0;}\n")
    context = _context("bc-a", str(source), dependencies={str(source): file_digest(source)})
    unverified = {
        "complete": True,
        "functions": [_facts("usr-main", "f", str(source))],
        "events": [],
        "accesses": [],
    }
    index = _CannedIndex(
        [context],
        {("bc-a", "c:@F@f", str(source)): unverified, ("bc-a", "f", str(source)): unverified},
    )
    scoped = ScopedCodeIndex(index, _scope("bc-a", "c:@F@f", str(source)))

    facts = scoped.get_function_program_facts("f", str(source))

    assert facts["complete"] is False
    assert facts["reason"] == GAP_IDENTITY_CONTEXT_UNVERIFIED


def test_unknown_context_is_an_explicit_gap(tmp_path: Path) -> None:
    source = _write(tmp_path, "unit.c", "int f(void){return 0;}\n")
    context = _context("ctx-a", str(source), dependencies={str(source): file_digest(source)})
    index = _ScopedIndex([context], {"ctx-a": [_facts("c:@F@f", "f", str(source))]})
    scoped = ScopedCodeIndex(index, _scope("ctx-gone", "c:@F@f", str(source)))

    facts = scoped.get_function_program_facts("f", str(source))

    assert facts["complete"] is False
    assert facts["reason"] == GAP_UNKNOWN_BUILD_CONTEXT
    assert scoped.dependencies_current_status() == GAP_UNKNOWN_BUILD_CONTEXT


def test_changed_dependency_makes_the_instance_stale(tmp_path: Path) -> None:
    source = _write(tmp_path, "unit.c", "int f(void){return 0;}\n")
    digest = file_digest(source)
    context = _context("ctx-a", str(source), dependencies={str(source): digest})
    index = _ScopedIndex([context], {"ctx-a": [_facts("c:@F@f", "f", str(source))]})
    scoped = ScopedCodeIndex(index, _scope("ctx-a", "c:@F@f", str(source)))
    assert scoped.dependencies_current_status() == "current"

    source.write_text("int f(void){return 1;}\n", encoding="utf-8")

    facts = scoped.get_function_program_facts("f", str(source))
    assert facts["complete"] is False
    assert facts["reason"] == "stale_build_context"
    assert index.queries == []  # a stale instance never queries stored facts


def test_callee_miss_is_not_a_scope_gap(tmp_path: Path) -> None:
    source = _write(tmp_path, "unit.c", "void f(void){g();}\n")
    context = _context("ctx-a", str(source), dependencies={str(source): file_digest(source)})
    index = _ScopedIndex([context], {"ctx-a": [_facts("c:@F@f", "f", str(source))]})
    scoped = ScopedCodeIndex(index, _scope("ctx-a", "c:@F@f", str(source)))

    entry = scoped.get_function_program_facts("f", str(source))
    miss = scoped.get_function_program_facts("g", str(source))

    assert entry["complete"] is True
    assert miss["complete"] is False
    assert miss["reason"] == "function_identity_not_found"
    report = scoped.scope_report()
    assert report["scope_gaps"] == []
    assert report["facts_complete"] is True


def test_same_name_across_tus_stays_separate_instances(tmp_path: Path) -> None:
    unit_a = _write(tmp_path, "a.c", "static int helper(void){return 0;}\n")
    unit_b = _write(tmp_path, "b.c", "static int helper(void){return 1;}\n")
    contexts = [
        _context("ctx-a", str(unit_a), dependencies={str(unit_a): file_digest(unit_a)}),
        _context("ctx-b", str(unit_b), dependencies={str(unit_b): file_digest(unit_b)}),
    ]
    index = _ScopedIndex(
        contexts,
        {
            "ctx-a": [_facts("c:@F@helper", "helper", str(unit_a))],
            "ctx-b": [_facts("c:@F@helper", "helper", str(unit_b))],
        },
    )
    scope_a = _scope("ctx-a", "c:@F@helper", str(unit_a), names=("helper",))
    scope_b = _scope("ctx-b", "c:@F@helper", str(unit_b), names=("helper",))

    facts_a = ScopedCodeIndex(index, scope_a).get_function_program_facts("helper", str(unit_a))
    facts_b = ScopedCodeIndex(index, scope_b).get_function_program_facts("helper", str(unit_b))

    assert facts_a["build_context_id"] == "ctx-a"
    assert facts_b["build_context_id"] == "ctx-b"
    assert index.queries == [
        ("c:@F@helper", str(unit_a), "ctx-a"),
        ("c:@F@helper", str(unit_b), "ctx-b"),
    ]


def test_blocked_consumers_return_empty_and_record_a_gap(tmp_path: Path) -> None:
    source = _write(tmp_path, "unit.c", "int f(void){return 0;}\n")
    context = _context("ctx-a", str(source), dependencies={str(source): file_digest(source)})
    index = _ScopedIndex([context], {"ctx-a": [_facts("c:@F@f", "f", str(source))]})
    scoped = ScopedCodeIndex(index, _scope("ctx-a", "c:@F@f", str(source)))

    # The exact call-receipt query is served and happens to be empty; it is not
    # a consumer gap merely because this function has no callees.
    assert scoped.get_callees("f") == []
    # A navigation consumer for a symbol that is not the pinned entry is blocked.
    assert scoped.find_function_infos("other") == []

    report = scoped.scope_report()
    assert report["blocked_consumers"] == ["find_function_infos"]
    assert report["unscoped_consumers"] == report["blocked_consumers"]
    assert report["identity_gaps"] == []
    assert all(gap["severity"] == "consumer" for gap in report["scope_gaps"])
    assert report["facts_complete"] is False  # no entry facts queried yet


def test_entry_body_is_scoped_and_other_symbols_are_blocked(tmp_path: Path) -> None:
    source = _write(tmp_path, "unit.c", "int f(void){return 0;}\n")
    context = _context("ctx-a", str(source), dependencies={str(source): file_digest(source)})
    index = _ScopedIndex([context], {"ctx-a": [_facts("c:@F@f", "f", str(source))]})
    scoped = ScopedCodeIndex(index, _scope("ctx-a", "c:@F@f", str(source)))

    entry = scoped.get_function_impl("f", file_path=str(source))
    assert entry is not None
    assert entry["index_name"] == index._entry_identity("f")
    # The entry is also resolvable through its navigation identity.
    assert scoped.get_function_impl(index._entry_identity("f"), file_path=str(source)) is not None
    # A callee body must not be served from the shared navigation projection.
    assert scoped.get_function_impl("other_callee") is None

    report = scoped.scope_report()
    assert report["identity_gaps"] == []
    assert "get_function_impl" in report["blocked_consumers"]


def test_exact_same_instance_callee_body_is_served_without_a_consumer_gap(
    tmp_path: Path,
) -> None:
    source = _write(
        tmp_path,
        "unit.c",
        "int helper(void){return 1;}\nint f(void){return helper();}\n",
    )
    context = _context("ctx-a", str(source), dependencies={str(source): file_digest(source)})
    entry = _facts("c:@F@f", "f", str(source))
    helper = _facts("c:@F@helper", "helper", str(source))
    call = {
        "kind": "call",
        "owner": dict(entry["owner"]),
        "target": {
            "usr": "c:@F@helper",
            "name": "helper",
            "qualified_name": "helper",
            "declaration": {"file": str(source), "line": 1},
        },
        "location": {"file": str(source), "line": 2},
    }
    index = _ScopedIndex([context], {"ctx-a": [entry, helper, call]})
    scoped = ScopedCodeIndex(index, _scope("ctx-a", "c:@F@f", str(source)))

    impl = scoped.get_function_impl("helper", include_context=False)

    assert impl is not None
    assert impl["index_name"] == index._entry_identity("helper")
    report = scoped.scope_report()
    assert report["identity_gaps"] == []
    assert report["blocked_consumers"] == []
    assert report["served_consumers"]["get_function_impl"] >= 1


def test_exact_same_instance_callee_metadata_is_served_for_validator_input(
    tmp_path: Path,
) -> None:
    source = _write(
        tmp_path,
        "unit.c",
        "int helper(void){return 1;}\nint f(void){return helper();}\n",
    )
    context = _context("ctx-a", str(source), dependencies={str(source): file_digest(source)})
    entry = _facts("c:@F@f", "f", str(source), line=2)
    helper = _facts("c:@F@helper", "helper", str(source), line=1)

    class _MetadataIndex(_ScopedIndex):
        def find_function_infos(
            self, func_name: str, file_path: str = "", **_: Any
        ) -> List[Dict[str, Any]]:
            name = str(func_name).split("@", 1)[0]
            if name != "helper":
                return []
            return [
                {
                    "function_name": "helper",
                    "index_name": self._entry_identity("helper"),
                    "file_path": str(source),
                    "start_line": 1,
                    "end_line": 1,
                    "signature": "int helper(void)",
                    "is_static": False,
                    "referenced_types": [],
                }
            ]

        def get_function_type_context(
            self, func_name: str, file_path: str = "", start_line: int = 0
        ) -> Dict[str, Any]:
            return {"referenced_types": []}

        def get_function_symbol_context(
            self, func_name: str, file_path: str = ""
        ) -> Dict[str, Any]:
            return {"referenced_globals": [], "referenced_macros": []}

    index = _MetadataIndex([context], {"ctx-a": [entry, helper]})
    scoped = ScopedCodeIndex(index, _scope("ctx-a", "c:@F@f", str(source)))

    infos = scoped.find_function_metadata("helper", file_path=str(source))
    types = scoped.get_function_type_context("helper", file_path=str(source), start_line=1)
    symbols = scoped.get_function_symbol_context("helper", file_path=str(source))

    assert [item["function_name"] for item in infos] == ["helper"]
    assert types == {"referenced_types": []}
    assert symbols == {"referenced_globals": [], "referenced_macros": []}
    report = scoped.scope_report()
    assert report["blocked_consumers"] == []
    assert report["served_consumers"]["find_function_infos"] >= 1
    assert report["served_consumers"]["get_function_type_context"] >= 1
    assert report["served_consumers"]["get_function_symbol_context"] >= 1


def test_entry_body_omits_unreceipted_context_without_mutating_shared_cache(tmp_path: Path) -> None:
    source = _write(tmp_path, "unit.c", "int f(void){return 0;}\n")
    context = _context("ctx-a", str(source), dependencies={str(source): file_digest(source)})
    index = _ScopedIndex([context], {"ctx-a": [_facts("c:@F@f", "f", str(source))]})
    payload = index.get_function_impl("f", file_path=str(source))
    payload.update(callees=["foreign"], comment_blocks=[{"text": "foreign declaration"}])
    requested_context = []

    def cached_impl(*args, **kwargs):
        requested_context.append(kwargs["include_context"])
        return payload

    index.get_function_impl = cached_impl  # type: ignore[method-assign]
    scoped = ScopedCodeIndex(index, _scope("ctx-a", "c:@F@f", str(source)))
    entry = scoped.get_function_impl("f", file_path=str(source))
    assert entry is not None and entry["code"] == payload["code"]
    assert entry["callees"] == [] and entry["comment_blocks"] == []
    assert requested_context == [False]
    assert payload["callees"] == ["foreign"]
    assert payload["comment_blocks"] == [{"text": "foreign declaration"}]
    assert "get_function_impl" in scoped.scope_report()["blocked_consumers"]


def test_ambiguous_entry_overloads_do_not_pick_the_first_body(tmp_path: Path) -> None:
    source = _write(tmp_path, "unit.c", "int f(int); int f(short);\n")
    context = _context("ctx-a", str(source), dependencies={str(source): file_digest(source)})
    rows = {
        "ctx-a": [
            _facts("c:@F@f#I#", "f", str(source)),
            _facts("c:@F@f#S#", "f", str(source)),
        ]
    }

    class _TwoOverloads(_ScopedIndex):
        def find_function_identities(self, func_name: str, file_path: str = ""):
            return [
                {"function_name": "f", "file_path": str(source), "index_name": "f@unit.c:1-1"},
                {"function_name": "f", "file_path": str(source), "index_name": "f@unit.c:1-2"},
            ]

    scoped = ScopedCodeIndex(
        _TwoOverloads([context], rows), _scope("ctx-a", "c:@F@f#I#", str(source))
    )

    assert scoped.get_function_impl("f") is None
    gaps = scoped.scope_report()["identity_gaps"]
    assert any(gap["reason"] == "ambiguous_function_identity" for gap in gaps)


def test_unlisted_data_attribute_is_denied_with_a_typed_empty() -> None:
    import threading
    from types import SimpleNamespace

    base = SimpleNamespace(
        language="c_cpp",
        backend_name="clang",
        _cache_lock=threading.RLock(),
        _some_symbol_cache={"foreign": 1},
        _other_miss_cache={"x"},
        _third_records=[1, 2],
        _db=object(),
    )
    scoped = ScopedCodeIndex(base, _scope("ctx-a", "usr-a", "unit.c"))

    # Raw caches/stores are denied by default and replaced with a usable empty
    # value of the right type, never None that would raise AttributeError.
    assert scoped._some_symbol_cache == {}
    assert scoped._other_miss_cache == set()
    assert scoped._third_records == []
    assert scoped._db is None
    # Scope-neutral metadata and locks still delegate.
    assert scoped.language == "c_cpp"
    assert scoped._cache_lock is base._cache_lock
    blocked = set(scoped.scope_report()["blocked_consumers"])
    assert {"_some_symbol_cache", "_other_miss_cache", "_third_records", "_db"} <= blocked


def test_real_symbol_catalog_cannot_read_unscoped_function_index() -> None:
    import threading
    from types import SimpleNamespace

    from zscope.tools.symbols import SymbolCatalog

    base = SimpleNamespace(
        language="c_cpp",
        backend_name="clang",
        _cache_lock=threading.RLock(),
        _function_index={"foreign": {"name": "other_variant", "file": "unit.c", "start_line": 9}},
    )
    scoped = ScopedCodeIndex(base, _scope("current", "usr-current", "unit.c"))

    assert SymbolCatalog(scoped)._function_records() == []
    assert "_function_index" in scoped.scope_report()["blocked_consumers"]


def test_scoped_symbol_search_reports_unavailable_without_reading_foreign_stores() -> None:
    from types import SimpleNamespace

    from zscope.tools.search_code import SearchCodeTool
    from zscope.tools.symbols import SymbolCatalog

    def foreign_macros():
        pytest.fail("Scoped search must not read the unscoped catalog")

    base = SimpleNamespace(_get_macro_definition_index=foreign_macros)
    scoped = ScopedCodeIndex(base, _scope("current", "usr-current", "unit.c"))
    tool = SearchCodeTool(SymbolCatalog(scoped))
    result = tool.execute({"scope": "symbols", "query": "f"})
    assert result["status"] == "unavailable"
    assert result["data"] is None
    assert result["coverage"]["missing"] == ["build_scoped_symbol_catalog"]
    assert "scope=text" in result["next_actions"][0]


def test_explicit_foreign_file_metadata_is_refused(tmp_path: Path) -> None:
    source = _write(tmp_path, "unit.c", "int f(void){return 0;}\n")
    context = _context("ctx-a", str(source), dependencies={str(source): file_digest(source)})
    index = _ScopedIndex([context], {"ctx-a": [_facts("c:@F@f", "f", str(source))]})
    scoped = ScopedCodeIndex(index, _scope("ctx-a", "c:@F@f", str(source)))

    assert scoped.find_function_metadata("f", file_path="other.c") == []
    assert scoped.find_function_infos("f", file_path=str(tmp_path / "other.c")) == []


def test_ambiguous_entry_metadata_is_refused_not_returned(tmp_path: Path) -> None:
    source = _write(tmp_path, "unit.c", "int f(int); int f(short);\n")
    context = _context("ctx-a", str(source), dependencies={str(source): file_digest(source)})
    rows = {
        "ctx-a": [
            _facts("c:@F@f#I#", "f", str(source)),
            _facts("c:@F@f#S#", "f", str(source)),
        ]
    }

    class _TwoInfos(_ScopedIndex):
        def find_function_infos(self, func_name, file_path="", *, include_type_context=True):
            return [
                {"name": "f", "file": str(source), "start_line": 1},
                {"name": "f", "file": str(source), "start_line": 9},
            ]

    scoped = ScopedCodeIndex(_TwoInfos([context], rows), _scope("ctx-a", "c:@F@f#I#", str(source)))

    assert scoped.find_function_metadata("f") == []
    assert any(
        gap["reason"] == "ambiguous_function_identity"
        for gap in scoped.scope_report()["identity_gaps"]
    )


def test_scoped_metadata_omits_empty_optional_member_facts(tmp_path: Path) -> None:
    source = _write(tmp_path, "unit.c", "int f(void){return 0;}\n")
    context = _context("ctx-a", str(source), dependencies={str(source): file_digest(source)})
    rows = {"ctx-a": [_facts("c:@F@f", "f", str(source))]}

    class _EmptyOptionalMembers(_ScopedIndex):
        def find_function_infos(self, func_name, file_path="", *, include_type_context=True):
            return [
                {
                    "name": "f",
                    "file": str(source),
                    "start_line": 1,
                    "referenced_types": [],
                    "unresolved_referenced_types": [],
                    "referenced_macros": [],
                    "referenced_globals": [],
                }
            ]

    scoped = ScopedCodeIndex(
        _EmptyOptionalMembers([context], rows),
        _scope("ctx-a", "c:@F@f", str(source)),
    )

    [info] = scoped.find_function_infos("f")

    assert info["referenced_types"] == []
    assert "unresolved_referenced_types" not in info
    assert "referenced_macros" not in info
    assert "referenced_globals" not in info


def _binding_receipt(usr: str, build_id: str, source: Path) -> Dict[str, Any]:
    return {"usr": usr, "build_context_id": build_id, "file": str(source)}


def test_type_context_is_served_only_with_a_member_binding_receipt(tmp_path: Path) -> None:
    source = _write(tmp_path, "unit.c", "int f(void){return 0;}\n")
    context = _context("ctx-a", str(source), dependencies={str(source): file_digest(source)})
    rows = {"ctx-a": [_facts("c:@F@f", "f", str(source))]}

    class _Types(_ScopedIndex):
        payload: Dict[str, Any] = {}

        def get_function_type_context(self, func_name, file_path="", start_line=0):
            return dict(self.payload)

    def served(payload: Dict[str, Any]) -> Dict[str, Any]:
        index = _Types([context], rows)
        index.payload = payload
        return ScopedCodeIndex(
            index, _scope("ctx-a", "c:@F@f", str(source))
        ).get_function_type_context("f")

    # A foreign build identity is refused with a typed empty.
    foreign = served(
        {
            "referenced_types": [
                {"name": "T", "function_identity": _binding_receipt("c:@F@f", "ctx-b", source)}
            ]
        }
    )
    assert foreign["referenced_types"] == []
    # Same build id but a foreign native USR is not authorization either.
    same_build_other_usr = served(
        {
            "referenced_types": [
                {
                    "name": "Other",
                    "function_identity": _binding_receipt("c:@F@other", "ctx-a", source),
                }
            ]
        }
    )
    assert same_build_other_usr["referenced_types"] == []
    # A build-id-only tag (no USR) is not a member receipt.
    assert (
        served({"referenced_types": [{"name": "T", "build_context_id": "ctx-a"}]})[
            "referenced_types"
        ]
        == []
    )
    # A receipt-less member is not a wildcard.
    assert served({"referenced_types": [{"name": "T"}]})["referenced_types"] == []
    # Only a receipt binding the member's own native USR *and* this build (and
    # source) is served.
    pinned = served(
        {
            "referenced_types": [
                {"name": "T", "function_identity": _binding_receipt("c:@F@f", "ctx-a", source)}
            ]
        }
    )
    assert pinned["referenced_types"][0]["name"] == "T"


def test_scoped_type_context_omits_empty_optional_member_facts(tmp_path: Path) -> None:
    source = _write(tmp_path, "unit.c", "int f(void){return 0;}\n")
    context = _context("ctx-a", str(source), dependencies={str(source): file_digest(source)})
    rows = {"ctx-a": [_facts("c:@F@f", "f", str(source))]}

    class _EmptyTypeContext(_ScopedIndex):
        def get_function_type_context(self, func_name, file_path="", start_line=0):
            return {
                "referenced_types": [],
                "unresolved_referenced_types": [],
                "referenced_macros": [],
                "referenced_globals": [],
            }

    scoped = ScopedCodeIndex(
        _EmptyTypeContext([context], rows),
        _scope("ctx-a", "c:@F@f", str(source)),
    )

    value = scoped.get_function_type_context("f")

    assert value == {"referenced_types": []}


def test_symbol_context_members_need_their_own_receipt(tmp_path: Path) -> None:
    source = _write(tmp_path, "unit.c", "int f(void){return 0;}\n")
    context = _context("ctx-a", str(source), dependencies={str(source): file_digest(source)})
    rows = {"ctx-a": [_facts("c:@F@f", "f", str(source))]}

    class _Symbols(_ScopedIndex):
        payload: Dict[str, Any] = {}

        def get_function_symbol_context(self, func_name, file_path=""):
            return dict(self.payload)

    def served(payload: Dict[str, Any]) -> Dict[str, Any]:
        index = _Symbols([context], rows)
        index.payload = payload
        return ScopedCodeIndex(
            index, _scope("ctx-a", "c:@F@f", str(source))
        ).get_function_symbol_context("f")

    # An outer build tag must not authorize an unreceipted member macro.
    outer_tag = served(
        {
            "build_context_id": "ctx-a",
            "referenced_globals": [],
            "referenced_macros": [{"name": "ALT", "replacement_text": "1"}],
        }
    )
    assert outer_tag["referenced_macros"] == []
    # A foreign build identity is refused entirely.
    foreign = served(
        {
            "referenced_macros": [{"name": "ALT", "build_context_id": "ctx-b"}],
            "referenced_globals": [],
        }
    )
    assert foreign["referenced_macros"] == []
    # Only a member receipt bound to this exact instance is served.
    pinned = served(
        {
            "referenced_macros": [
                {"name": "ALT", "function_identity": _binding_receipt("c:@F@f", "ctx-a", source)}
            ],
            "referenced_globals": [],
        }
    )
    assert pinned["referenced_macros"][0]["name"] == "ALT"


def test_wrap_reuses_an_identical_scope_without_double_wrapping(tmp_path: Path) -> None:
    source = _write(tmp_path, "unit.c", "int f(void){return 0;}\n")
    scope = _scope("ctx-a", "c:@F@f", str(source))
    index = _ScopedIndex([], {})

    first = wrap_scoped_code_index(index, scope)
    again = wrap_scoped_code_index(first, scope)
    other = wrap_scoped_code_index(first, _scope("ctx-b", "c:@F@f", str(source)))

    assert isinstance(first, ScopedCodeIndex)
    assert again is first
    assert isinstance(other, ScopedCodeIndex)
    assert other.scope.build_context_id == "ctx-b"


# ── Plan payload: scheduling is real, not a label ──


def _entry_instance(context_id: str, usr: str, source: str) -> EntryInstance:
    return EntryInstance(
        build_context_id=context_id,
        usr=usr,
        identity=f"{context_id}:{usr}",
        source=source,
        function_names=["f"],
    )


def test_plan_payload_defaults_to_boundary_only_then_reports_scheduling() -> None:
    plan = EntryInstancePlan(
        status="planned",
        instances=[_entry_instance("ctx-a", "c:@F@f", "unit.c")],
        entry_count=1,
    )

    default = plan.to_payload()
    assert default["scheduled_instances"] is None
    assert default["scan_coverage_complete"] is False
    assert default["scan_coverage_reasons"] == ["entry_analysis_not_instance_scoped"]

    scheduled = plan.to_payload(
        {
            "schema": "zscope.instance-analysis.v1",
            "scheduled_instances": 2,
            "scan_coverage_complete": True,
            "reasons": [],
        }
    )
    assert scheduled["scheduled_instances"] == 2
    assert scheduled["scan_coverage_complete"] is True
    assert scheduled["scan_coverage_reasons"] == []
    assert scheduled["instance_analysis"]["scheduled_instances"] == 2


def test_report_coverage_reflects_blocked_and_gapped_instances() -> None:
    analyzed = InstanceAnalysisOutcome(
        identity="ctx-a:c:@F@f",
        build_context_id="ctx-a",
        usr="c:@F@f",
        source="unit.c",
        function_name="f",
        status="analyzed",
        blocked_consumers=["get_callees"],
    )
    gapped = InstanceAnalysisOutcome(
        identity="ctx-b:c:@F@f",
        build_context_id="ctx-b",
        usr="c:@F@f",
        source="unit.c",
        function_name="f",
        status="gap",
        scope_gaps=[
            {
                "reason": GAP_UNKNOWN_BUILD_CONTEXT,
                "build_context_id": "ctx-b",
                "severity": "identity",
            }
        ],
    )
    report = InstanceAnalysisReport(
        status="analyzed", outcomes=[analyzed, gapped], planned_instances=2
    )

    assert report.scheduled_instances == 2
    assert report.analyzed_instances == 1
    # A blocked consumer is not a hard scope gap, but the instance is still not
    # fully scoped because its own status is "gap".
    assert analyzed.scope_preserved is True
    assert report.consumer_scope_complete is False
    assert report.instance_scope_complete is False
    assert report.scan_coverage_complete is False
    reasons = report.coverage_reasons()
    assert any(reason.startswith("blocked_consumers:") for reason in reasons)
    assert any("unknown_build_context" in reason for reason in reasons)


def test_run_instance_analysis_requires_the_execution_api() -> None:
    class _NoApi:
        pass

    with pytest.raises(TypeError):
        run_instance_analysis(_NoApi(), object())


def test_analyze_entry_instances_rejects_closed_and_concurrent(tmp_path: Path) -> None:
    import threading
    from types import SimpleNamespace

    from zscope.orchestration.parallel_analyzer import ParallelAnalyzer

    analyzer = ParallelAnalyzer.__new__(ParallelAnalyzer)
    analyzer.base_config = SimpleNamespace(
        project=SimpleNamespace(language="c_cpp", project_root=tmp_path)
    )
    analyzer._candidate_ledger = SimpleNamespace(lifecycle_snapshot=lambda: {})
    instance = SimpleNamespace(
        build_context_id="ctx-a",
        usr="usr-a",
        identity="ctx-a/usr-a",
        source="unit.c",
        function_names=("f",),
        selected_by="test",
    )
    plan = SimpleNamespace(instances=[instance], gaps=[], status="planned")

    analyzer._closed = True
    with pytest.raises(RuntimeError):
        analyzer.analyze_entry_instances(plan)

    analyzer._closed = False
    analyzer._active_batch_thread = threading.get_ident()
    with pytest.raises(RuntimeError):
        analyzer.analyze_entry_instances(plan)


# ── Native-gated: real index, real Analyzer, real validation chain ──

RULE = "clang_cfg_same_object_released_twice"
GRAPH_VIEW_RULE = "global_registration_slot_checked_before_lock"


def _native_config(tmp_path: Path, cdb: Path, source_root: Optional[Path] = None):
    # ``ProjectConfig`` now has one root. Keep the third argument as a test
    # helper compatibility shim for native suites that still import it.
    del source_root
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
    from zscope.config.project_semantics import render_empty_project_semantics

    semantics_path = tmp_path / "zscope.semantics.yaml"
    if not semantics_path.exists():
        semantics_path.write_text(render_empty_project_semantics(), encoding="utf-8")

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
            semantics_file=semantics_path,
            agents=[AgentConfig(name="vulnerability_analyzer", task="audit")],
        ),
        concurrency=ConcurrencyConfig(entry_workers=2),
        rules=RulesConfig(enabled_ids=[RULE, GRAPH_VIEW_RULE]),
    )


def _semantic_stub():
    from zscope.orchestration.global_modeler import GlobalModelStats
    from zscope.orchestration.semantic_modeling import SessionSemanticResult
    from zscope.semantics.models import LocalPatternSemantics

    return SessionSemanticResult(
        GlobalModelStats(), local_semantics=LocalPatternSemantics(), overlay={}
    )


@pytest.fixture
def native_variants(tmp_path, monkeypatch):
    executable = os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER")
    if not executable:
        pytest.skip("instance analysis native tests require Z_SCOPE_TEST_CLANG_INDEXER")
    from zscope.retrieval.clang_backend import ClangBackend

    monkeypatch.setenv("Z_SCOPE_CLANG_BATCH_MEMORY_MB", "512")
    monkeypatch.setattr(
        ClangBackend, "_ensure_extractor", lambda self: pytest.fail("unexpected LSP")
    )
    (tmp_path / "flags.h").write_text(
        "#include <stdlib.h>\n"
        "#ifdef ALT\n"
        "#define RELEASE(p) do { free(p); free(p); } while (0)\n"
        "#else\n"
        "#define RELEASE(p) do { free(p); } while (0)\n"
        "#endif\n",
        encoding="utf-8",
    )
    (tmp_path / "unit.c").write_text(
        '#include "flags.h"\n'
        "static void *project_alloc(size_t n) { return malloc(n); }\n"
        "static void *project_dup(size_t n) { return project_alloc(n); }\n"
        "static void project_release(void *p) { free(p); }\n"
        "static int helper(void) { return 1; }\n"
        "void g(void) { (void)helper(); }\n"
        "void wrapper_bug(void) {\n"
        "  char *p = project_alloc(4);\n"
        "  if (!p) { return; }\n"
        "  project_release(p);\n"
        "  project_release(p);\n"
        "}\n"
        "void f(void) {\n"
        "  char *p = malloc(4);\n"
        "  if (!p) { return; }\n"
        "  RELEASE(p);\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "other.c").write_text(
        "#include <pthread.h>\n"
        "#include <stdlib.h>\n"
        "static void *g_registration_slot;\n"
        "static pthread_mutex_t g_registration_lock = PTHREAD_MUTEX_INITIALIZER;\n"
        "void graph_view_bug(void *next) {\n"
        "  if (g_registration_slot != NULL) {\n"
        "    pthread_mutex_lock(&g_registration_lock);\n"
        "    g_registration_slot = next;\n"
        "    pthread_mutex_unlock(&g_registration_lock);\n"
        "  }\n"
        "}\n"
        "void outside_entry_graph(void) {\n"
        "  char *p = malloc(8);\n"
        "  if (!p) { return; }\n"
        "  free(p);\n"
        "  free(p);\n"
        "}\n",
        encoding="utf-8",
    )
    rows = [
        dict(
            directory=str(tmp_path),
            file=str(tmp_path / "unit.c"),
            arguments=["clang", "-c", str(tmp_path / "unit.c"), *flags],
        )
        for flags in ([], ["-DALT=1"])
    ]
    rows.append(
        dict(
            directory=str(tmp_path),
            file=str(tmp_path / "other.c"),
            arguments=["clang", "-c", str(tmp_path / "other.c")],
        )
    )
    # A named entry list is an ordinary project file and it lives inside the
    # include search root, so it must exist before the index snapshot: a file
    # that appears afterwards makes the stored search receipt stale and the
    # instance inputs refuse to freeze.
    (tmp_path / "entries.json").write_text(
        json.dumps({"functions": [{"function_name": "f", "file_path": "unit.c"}]}),
        encoding="utf-8",
    )
    from zscope.config.project_semantics import render_empty_project_semantics

    (tmp_path / "zscope.semantics.yaml").write_text(
        render_empty_project_semantics(), encoding="utf-8"
    )
    cdb = tmp_path / "compile_commands.json"
    cdb.write_text(json.dumps(rows), encoding="utf-8")
    backend = ClangBackend(frontend="batch", clang_indexer_path=executable, max_threads=2)
    try:
        assert backend.initialize(str(tmp_path), compile_commands_path=str(cdb))
        yield backend, tmp_path, cdb
    finally:
        backend.close()


def _native_index(backend, root: Path, cdb: Path):
    from zscope.config.config import IndexingConfig
    from zscope.retrieval.code_index import CodeIndex

    return CodeIndex(root, cdb, backend=backend, indexing_config=IndexingConfig(backend="clang"))


def test_real_two_variant_instances_analyze_with_scoped_candidates(native_variants) -> None:
    backend, root, cdb = native_variants
    from zscope.orchestration.entry_instances import plan_entry_instances
    from zscope.orchestration.parallel_analyzer import ParallelAnalyzer

    index = _native_index(backend, root, cdb)
    contexts = index.get_build_contexts("unit.c")
    assert len(contexts) == 2
    alt_id = next(
        context["build_context_id"]
        for context in contexts
        if "-DALT=1" in context["command"]["arguments"]
    )
    base_id = next(
        context["build_context_id"]
        for context in contexts
        if "-DALT=1" not in context["command"]["arguments"]
    )

    plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])
    assert plan.status == "planned"
    assert len(plan.instances) == 2

    parallel = ParallelAnalyzer(
        _native_config(root, cdb),
        code_index=index,
        semantic_result=_semantic_stub(),
    )
    report = parallel.analyze_entry_instances(plan)

    assert report.status == "analyzed"
    assert report.scheduled_instances == 2
    assert report.analyzed_instances == 2
    assert report.instance_scope_complete is True

    by_context = {outcome.build_context_id: outcome for outcome in report.outcomes}
    assert set(by_context) == {alt_id, base_id}

    alt_double_free = [
        candidate
        for candidate in by_context[alt_id].issues
        if candidate["defect_class"] == "double_free"
    ]
    assert alt_double_free, [candidate for candidate in by_context[alt_id].issues]
    base_double_free = [
        candidate
        for candidate in by_context[base_id].issues
        if candidate["defect_class"] == "double_free"
    ]
    # Fast is a project-level pass: the unconditional bug in ``wrapper_bug``
    # is reported for both variants even though ``f`` is the attribution
    # entry.  Only the ALT macro expansion adds the second, variant-specific
    # finding inside ``f`` itself.
    assert {candidate["location"] for candidate in base_double_free} == {f"{root / 'unit.c'}:11"}
    assert {candidate["location"] for candidate in alt_double_free} == {
        f"{root / 'unit.c'}:11",
        f"{root / 'unit.c'}:16",
    }

    # Every candidate carries exactly the build identity of the instance that
    # produced it; no variant borrows another variant's candidate.
    for outcome in report.outcomes:
        for candidate in outcome.issues:
            assert candidate["build_context_id"] == outcome.build_context_id

    # Exact native receipts now cover the graph, function inventory, and body
    # consumers without borrowing either macro variant's project projection.
    assert report.instance_scope_complete is True
    assert report.consumer_scope_complete is True
    assert report.scan_coverage_complete is True
    assert report.unscoped_consumers == []
    for outcome in report.outcomes:
        assert outcome.scope_gaps == []
        assert outcome.semantics == "builtin_current_automatic_native_confirmed_project.v3"

    # The project-wide semantic model / deterministic pass / active discovery
    # were never run for scoped entries.
    assert parallel._project_fact_pass_state.get("status") == "skipped"
    assert parallel._active_discovery_state.get("status") == "skipped"
    assert parallel._shared_local_pattern_semantics is None
    fast_state = parallel._fast_static_scan_state
    assert fast_state["schema"] == "zscope.fast-static-scan.v1"
    assert fast_state["activated"] is True
    assert fast_state["unique_function_instances"] >= 2
    assert fast_state["local_analysis_executions"] == fast_state["unique_function_instances"]
    assert fast_state["duplicate_local_executions"] == 0
    assert fast_state["graph_analysis_units"] == 4  # Three TU units plus the unlinked project observation.
    assert fast_state["candidate_funnel"]["raw"] >= 1
    assert fast_state["candidate_funnel"]["dedup"] >= 1
    assert fast_state["semantic_authorization"]["wrapper_contracts_authorized"] >= 2, fast_state[
        "semantic_authorization"
    ]
    authorized_wrapper_names = {
        row["function"]
        for row in fast_state["semantic_authorization"]["wrapper_authorized_identities"]
    }
    assert {"project_alloc", "project_release"} <= authorized_wrapper_names
    # The current native wrapper pass replays the bounded forwarding chain;
    # publication is backed by the exact current callee and body receipts.
    assert "project_dup" in authorized_wrapper_names
    lifecycle = parallel._candidate_ledger.freeze()
    dispositions = {
        str(item.get("terminal_disposition") or item.get("candidate_disposition") or "")
        for item in lifecycle.get("outcomes") or []
        if isinstance(item, dict)
    }
    assert dispositions
    assert dispositions <= {"confirmed", "rejected_with_proof", "needs_review"}
    fast_outcomes = [
        item.get("issue") or {}
        for item in lifecycle.get("outcomes") or []
        if isinstance(item, dict) and (item.get("issue") or {}).get("fast_static_scan_v1")
    ]
    assert fast_outcomes
    assert any(
        "other.c" in json.dumps(candidate, sort_keys=True)
        and candidate["reachability_attribution"]["reachable"] is None
        and candidate["reachability_attribution"]["status"] == "unknown"
        and candidate["reachability_attribution"]["coverage_gap"]
        for candidate in fast_outcomes
    )
    graph_view = next(
        candidate
        for candidate in fast_outcomes
        if candidate.get("rule") == GRAPH_VIEW_RULE
        and candidate.get("function") == "graph_view_bug"
    )
    assert graph_view["analysis_unit_id"]
    assert graph_view["build_context_id"]
    assert graph_view["reachability_attribution"]["status"] == "unknown"
    assert any(
        "unit.c" in json.dumps(candidate, sort_keys=True)
        and candidate["reachability_attribution"]["reachable"] is True
        for candidate in fast_outcomes
    )
    for candidate in fast_outcomes:
        assert len(candidate["analysis_unit_id"]) == 64
        assert candidate["reachability_attribution"]["reachable"] in {True, None}

    payload = report.to_payload()
    assert payload["scheduled_instances"] == 2
    assert payload["instance_scope_complete"] is True
    assert payload["consumer_scope_complete"] is True
    assert payload["blocked_consumers"] == []
    assert not any(reason.startswith("blocked_consumers:") for reason in payload["reasons"])

    combined = parallel.generate_combined_report(parallel.last_instance_results())
    telemetry = combined["metadata"]["fast_static_scan"]
    assert telemetry["schema"] == "zscope.fast-static-scan.v1"
    assert telemetry["duplicate_local_executions"] == 0
    assert telemetry["candidate_funnel"]["dedup"] >= len(lifecycle["outcomes"])
    assert combined["summary"]["fast_static_scan"] == telemetry

    # The raw per-entry results stay available for the existing report path and
    # are keyed per instance, not collapsed onto the shared function name.
    raw_results = parallel.last_instance_results()
    assert len(raw_results) == 2
    assert len(set(raw_results)) == 2
    assert all(
        result.metadata["fast_static_entry_projection"] is True for result in raw_results.values()
    )
    assert all(
        result.instance_collection["collection_closed"] is True for result in raw_results.values()
    )

    plan_payload = plan.to_payload(report)
    assert plan_payload["scheduled_instances"] == 2
    assert plan_payload["instance_analysis"]["analyzed_instances"] == 2


def test_native_validation_helper_keeps_the_instance_scope(native_variants, monkeypatch) -> None:
    backend, root, cdb = native_variants
    from zscope.orchestration import parallel_analyzer as parallel_module
    from zscope.orchestration.entry_instances import plan_entry_instances
    from zscope.orchestration.parallel_analyzer import ParallelAnalyzer

    index = _native_index(backend, root, cdb)
    plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])

    seen: List[Dict[str, Any]] = []
    original = parallel_module.Analyzer.__init__

    def observe(self, *args, **kwargs):
        if kwargs.get("defer_validation_to_scan") is False:
            seen.append(
                {"index": kwargs.get("code_index"), "semantics": kwargs.get("semantic_result")}
            )
        original(self, *args, **kwargs)

    monkeypatch.setattr(parallel_module.Analyzer, "__init__", observe)
    parallel = ParallelAnalyzer(
        _native_config(root, cdb), code_index=index, semantic_result=_semantic_stub()
    )
    try:
        report = parallel.analyze_entry_instances(plan)
        assert report.analyzed_instances == 2
        assert any(outcome.issues for outcome in report.outcomes), "candidate must reach validation"
        assert seen, "the actual shared validation helper must run"
        assert all(
            isinstance(row["index"], ScopedCodeIndex) for row in seen
        ), "post-discovery validation reopened the unscoped index"
        assert all(
            row["semantics"] is None for row in seen
        ), "the project-wide semantic result cannot authorize an instance verdict"
    finally:
        parallel.close()


def test_fast_static_pass_analyzes_shared_functions_once_per_build(native_variants) -> None:
    backend, root, cdb = native_variants
    from zscope.orchestration.entry_instances import plan_entry_instances
    from zscope.orchestration.parallel_analyzer import ParallelAnalyzer

    index = _native_index(backend, root, cdb)

    plan = plan_entry_instances(
        index,
        [
            FunctionEntry("f", file_path="unit.c"),
            FunctionEntry("g", file_path="unit.c"),
        ],
    )
    assert plan.status == "planned"
    assert len(plan.instances) == 4
    expected_units = set()
    seen_builds = set()
    for context in index.get_build_contexts():
        build_id = str(context["build_context_id"])
        seen_builds.add(build_id)
        for row in index.get_compilation_facts(build_id, kinds=("program_function",)):
            owner = row.get("owner") or {}
            source = Path(str(owner.get("file") or ""))
            try:
                source.resolve().relative_to(root.resolve())
            except ValueError:
                continue
            if owner.get("usr"):
                expected_units.add((build_id, str(owner["usr"])))

    parallel = ParallelAnalyzer(
        _native_config(root, cdb),
        code_index=index,
        semantic_result=_semantic_stub(),
    )
    try:
        report = parallel.analyze_entry_instances(plan)
        assert report.status == "analyzed"
        state = parallel._fast_static_scan_state
        assert state["activated"] is True
        assert state["unique_function_instances"] == len(expected_units)
        assert state["local_analysis_executions"] == len(expected_units)
        assert state["duplicate_local_executions"] == 0
        assert {
            (scope.build_context_id, scope.usr)
            for scopes in parallel._instance_scopes_by_build.values()
            for scope in scopes
        } == expected_units
        assert parallel._validation_semantics_snapshots
        assert (
            set(parallel._validation_semantics_snapshots)
            == set(parallel._validation_semantics_receipts)
            == set(parallel._validation_semantics_fact_receipts)
        )
        assert {
            (snapshot.scope.build_context_id, snapshot.scope.usr)
            for snapshot in parallel._validation_semantics_snapshots.values()
        }.issubset(expected_units)
        assert state["local_engine_executions"] == {
            "cpp_clang_cfg": len(expected_units),
            "cpp_regex": len(expected_units),
            "cpp_graph_view": 0,
            "cpp_clang_matcher": len(expected_units),
            "extension_provider": len(expected_units),
        }
        # The unlinked factory/member observation is a separate project unit.
        assert state["graph_analysis_units"] == len(seen_builds) + 1
        assert state["cache"]["status"] == "cold"
        assert state["cache"]["local_cold_misses"] == len(expected_units)
        assert state["cache"]["graph_cold_misses"] == len(seen_builds)
        assert state["cache"]["hot_hits"] == 0
        assert state["rule_execution"]["executed_by_rule"][RULE] == len(expected_units)
        assert state["rule_execution"]["declared_fact_prerequisites"][RULE]
        function_manifests = [row for row in state["analysis_units"] if row.get("usr")]
        assert len(function_manifests) == len(expected_units)
        assert all(
            row["semantic_contract_trace_status"] == "complete"
            and isinstance(row["semantic_contract_events"], list)
            for row in function_manifests
        )
    finally:
        parallel.close()

    # A second analyzer over byte-identical sources, exact native contexts,
    # semantics and rule revisions reuses the local summaries.  Graph/backend
    # units remain independently recomputed until their dependency frontier is
    # represented by a current link/SCC receipt.
    warm_index = _native_index(backend, root, cdb)
    warm_plan = plan_entry_instances(
        warm_index,
        [
            FunctionEntry("f", file_path="unit.c"),
            FunctionEntry("g", file_path="unit.c"),
        ],
    )
    warm = ParallelAnalyzer(
        _native_config(root, cdb),
        code_index=warm_index,
        semantic_result=_semantic_stub(),
    )
    try:
        warm_report = warm.analyze_entry_instances(warm_plan)
        assert warm_report.status == "analyzed"
        warm_state = warm._fast_static_scan_state
        assert warm_state["unique_function_instances"] == len(expected_units)
        assert warm_state["local_analysis_executions"] == 0
        assert warm_state["duplicate_local_executions"] == 0
        assert warm_state["local_engine_executions"] == {
            "cpp_clang_cfg": 0,
            "cpp_regex": 0,
            "cpp_graph_view": 0,
            "cpp_clang_matcher": 0,
            "extension_provider": 0,
        }
        assert warm_state["cache"]["status"] == "hot"
        assert warm_state["cache"]["local_hot_hits"] == len(expected_units)
        assert warm_state["cache"]["graph_hot_hits"] == len(seen_builds)
        assert warm_state["cache"]["cold_misses"] == 0
        assert warm_state["rule_execution"]["cache_reused_by_rule"][RULE] == len(expected_units)
        assert RULE not in warm_state["rule_execution"]["executed_by_rule"]
        assert warm_state["unique_graph_units"] == len(seen_builds) + 1
        assert warm_state["graph_analysis_units"] == 1
        warm_function_manifests = [row for row in warm_state["analysis_units"] if row.get("usr")]
        assert len(warm_function_manifests) == len(expected_units)
        assert all(
            row["semantic_contract_trace_status"] == "complete"
            and isinstance(row["semantic_contract_events"], list)
            for row in warm_function_manifests
        )
    finally:
        warm.close()


def test_link_group_semantics_projects_only_member_contracts_with_exact_usr() -> None:
    from zscope.orchestration.parallel_analyzer import ParallelAnalyzer
    from zscope.semantics.contracts import ApiContract, ObjectBinding, SymbolIdentity
    from zscope.semantics.models import LocalPatternSemantics

    member = LocalPatternSemantics()
    member.contracts.add(
        ApiContract(
            symbol=SymbolIdentity(
                "project_lock",
                "src/locks.c",
                "void ( pthread_mutex_t * )",
                "function",
                "ctx-locks",
                "c:@F@project_lock",
            ),
            role="lock",
            carrier=ObjectBinding("argument", 0),
            source="native_test_receipt",
        )
    )
    unknown = LocalPatternSemantics()
    unknown.contracts.add(
        ApiContract(
            symbol=SymbolIdentity(
                "unknown_lock",
                "src/unknown.c",
                "void ( pthread_mutex_t * )",
                "function",
                "ctx-locks",
                "",
            ),
            role="lock",
            carrier=ObjectBinding("argument", 0),
            source="native_test_receipt",
        )
    )
    outsider = LocalPatternSemantics()
    outsider.contracts.add(
        ApiContract(
            symbol=SymbolIdentity(
                "other_lock",
                "src/other.c",
                "void ( pthread_mutex_t * )",
                "function",
                "ctx-other",
                "c:@F@other_lock",
            ),
            role="lock",
            carrier=ObjectBinding("argument", 0),
            source="native_test_receipt",
        )
    )

    projected, records = ParallelAnalyzer._project_link_group_semantics(
        target_id="app",
        member_build_context_ids=["ctx-caller", "ctx-locks"],
        base_semantics=member,
        semantics_by_build=[member, unknown, outsider],
    )

    exact = projected.contracts.find(
        "project_lock", usr="c:@F@project_lock", build_context_id="ctx-caller"
    )
    assert len(exact) == 1
    assert exact[0].symbol.build_context_id == ""
    assert exact[0].symbol.usr == "c:@F@project_lock"
    assert projected.contracts.find("project_lock", usr="c:@F@different") == []
    assert projected.contracts.find("unknown_lock") == []
    assert projected.contracts.find("other_lock") == []
    assert records == [
        {
            "link_group_id": "app",
            "definition_build_context_id": "ctx-locks",
            "name": "project_lock",
            "usr": "c:@F@project_lock",
            "role": "lock",
        }
    ]


def test_navigation_body_must_match_the_native_source_range(tmp_path: Path) -> None:
    source = _write(tmp_path, "unit.c", "int f(void){return 0;}\n")
    context = _context("ctx-a", str(source), dependencies={str(source): file_digest(source)})
    rows = {"ctx-a": [_facts("c:@F@f", "f", str(source), line=2)]}

    class _WrongRange(_ScopedIndex):
        def get_function_impl(
            self,
            func_name,
            max_lines=500,
            warn_missing=True,
            include_context=True,
            file_path="",
        ):
            result = super().get_function_impl(
                func_name, max_lines, warn_missing, include_context, file_path
            )
            result["start_line"] = 9
            return result

        def find_function_infos(self, func_name, file_path="", *, include_type_context=True):
            return [{"name": "f", "file": str(source), "start_line": 9}]

    scoped = ScopedCodeIndex(_WrongRange([context], rows), _scope("ctx-a", "c:@F@f", str(source)))

    # A navigation body/record whose source range is not the current native
    # owner range may not be served, even for the same file and USR.
    assert scoped.get_function_impl("f", file_path=str(source)) is None
    assert scoped.find_function_metadata("f") == []
    assert any(
        gap["reason"] == "identity_context_mismatch"
        for gap in scoped.scope_report()["identity_gaps"]
    )


def test_conditional_native_body_never_borrows_the_other_variant(tmp_path) -> None:
    executable = os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER")
    if not executable:
        pytest.skip("instance analysis native tests require Z_SCOPE_TEST_CLANG_INDEXER")
    from zscope.config.config import IndexingConfig
    from zscope.orchestration.entry_instances import plan_entry_instances
    from zscope.retrieval.clang_backend import ClangBackend
    from zscope.retrieval.code_index import CodeIndex

    source = tmp_path / "unit.c"
    source.write_text(
        "#ifdef ALT\nvoid f(void) { int ALT_MARKER = 1; }\n"
        "#else\nvoid f(void) { int BASE_MARKER = 2; }\n#endif\n",
        encoding="utf-8",
    )
    cdb = tmp_path / "compile_commands.json"
    cdb.write_text(
        json.dumps(
            [
                dict(
                    directory=str(tmp_path),
                    file=str(source),
                    arguments=["clang", "-c", str(source), *flags],
                )
                for flags in ([], ["-DALT=1"])
            ]
        ),
        encoding="utf-8",
    )
    backend = ClangBackend(frontend="batch", clang_indexer_path=executable, max_threads=2)
    try:
        assert backend.initialize(str(tmp_path), compile_commands_path=str(cdb))
        index = CodeIndex(
            tmp_path, cdb, backend=backend, indexing_config=IndexingConfig(backend="clang")
        )
        contexts = {row["build_context_id"]: row for row in index.get_build_contexts("unit.c")}
        plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])
        assert plan.status == "planned" and len(plan.instances) == 2

        served = 0
        for instance in plan.instances:
            scope = InstanceScope.from_entry_instance(instance)
            view = ScopedCodeIndex(index, scope)
            facts = view.get_function_program_facts("f", "unit.c")
            assert facts["complete"] and facts["function_identity"]["usr"] == scope.usr
            impl = view.get_function_impl("f", file_path="unit.c", include_context=False)
            alt = "-DALT=1" in contexts[scope.build_context_id]["command"]["arguments"]
            marker, other = ("ALT_MARKER", "BASE_MARKER") if alt else ("BASE_MARKER", "ALT_MARKER")
            if impl is None:
                # Two conditional definitions of one USR: the navigation body
                # cannot be bound to this instance, so it must be a gap.
                assert view.scope_report()["identity_gaps"]
                continue
            served += 1
            assert (
                marker in impl["code"] and other not in impl["code"]
            ), f"body for {scope.build_context_id} borrowed the other variant: {impl['code']}"
        # Only the instance whose native range matches the navigation record is
        # served; the concurrent conditional definition is refused, not borrowed.
        assert served == 1
    finally:
        backend.close()


def test_retired_instance_after_header_change_is_not_reanalyzed(native_variants) -> None:
    backend, root, cdb = native_variants
    from zscope.orchestration.entry_instances import plan_entry_instances

    index = _native_index(backend, root, cdb)
    plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])
    assert plan.status == "planned" and plan.instances

    # A header change is a new content-bound instance: the old identity must not
    # silently reuse the new variant's facts.
    (root / "flags.h").write_text(
        "#include <stdlib.h>\n" "#define RELEASE(p) do { free(p); free(p); } while (0)\n",
        encoding="utf-8",
    )
    assert backend.initialize(str(root), compile_commands_path=str(cdb))
    new_contexts = index.get_build_contexts("unit.c")
    assert new_contexts
    new_ids = {context["build_context_id"] for context in new_contexts}
    assert new_ids.isdisjoint({instance.build_context_id for instance in plan.instances})

    retired = plan.instances[0]
    facts = index.get_function_program_facts(
        retired.function_names[0] if retired.function_names else "f",
        "unit.c",
        build_context_id=retired.build_context_id,
    )
    assert facts["complete"] is False
    assert facts["reason"] == "build_context_not_found"


def test_scoped_context_enumeration_stays_single_instance(tmp_path: Path) -> None:
    """R2: coverage must not widen the scoped enumeration to see siblings."""

    from zscope.retrieval.build_context import scan_build_coverage

    source = _write(tmp_path, "unit.c", "int f(void) { return 0; }\n")
    index = _ScopedIndex([_context("ctx-a", str(source)), _context("ctx-b", str(source))], {})
    scoped = ScopedCodeIndex(index, _scope("ctx-b", "c:@F@f", str(source)))

    # Instance semantics need exactly one current context; the sibling is only
    # visible through the coverage accessor.
    assert [context["build_context_id"] for context in scoped.get_build_contexts(str(source))] == [
        "ctx-b"
    ]
    coverage = scan_build_coverage(scoped)
    assert coverage["view"] == "instance"
    assert coverage["pinned_build_context_id"] == "ctx-b"
    assert coverage["instances"] == 2
    assert coverage["variant_sources"] == {str(source): 2}
    assert coverage["scan_complete"] is False
    # The scan-level view of the same index still sees the same two instances.
    assert scan_build_coverage(index)["instances"] == 2
    assert scan_build_coverage(index)["view"] == "scan"


class _ArtifactReuseTransport:
    """Fixed model responses; the real client still records each physical attempt."""

    def __init__(self):
        self.calls = []

    def __call__(self, _url, payload):
        prompt = payload["messages"][-1]["content"]
        tools = {tool["function"]["name"] for tool in payload.get("tools", [])}
        if "emit_contract_summary" in tools:
            request = json.loads(prompt)
            unit = request["unit"]
            value = {
                key: []
                for key in (
                    "preconditions", "postconditions", "actual_effects",
                    "state_transitions", "obligations", "hypotheses", "unknowns",
                )
            }
            if unit["level"] == "function":
                ref = f"{unit['id']}:{unit['start_line']}"
                value["actual_effects"] = [{
                    "text": f"已读取当前函数 {unit['function']}",
                    "basis": "observed", "refs": [ref], "assumptions": [],
                }]
                if unit["function"] == "model_gap" and "free(p);" not in unit["source"]:
                    value["hypotheses"] = [{
                        "defect_class": "resource_leak",
                        "description": "当前函数分配后退出但未释放资源",
                        "violated_condition": "本次分配在退出前需要释放或转移",
                        "source_ref": f"{unit['id']}:{unit['start_line'] + 1}",
                        "sink_ref": f"{unit['id']}:{unit['end_line'] - 1}",
                        "counter_explanation": "调用方可能承接资源所有权",
                        "assumptions": [], "required_facts": [],
                        "positive_example": "allocate; return",
                        "negative_example": "allocate; release; return",
                        "object": "p", "generation": "allocation",
                        "applicability": "分配成功路径", "exclusions": "所有权已转移",
                        "proposal_kind": "fact_gap",
                    }]
            self.calls.append({"kind": "summary", "unit": unit})
            message = {"role": "assistant", "content": "", "tool_calls": [{
                "id": "emit_summary", "type": "function", "function": {
                    "name": "emit_contract_summary", "arguments": json.dumps(value),
                },
            }]}
            finish = "tool_calls"
        else:
            from zscope.core.validation.evidence import VALIDATOR_EVIDENCE_SLICE_V3

            evidence = json.loads(prompt.split("\n\nEvidence:\n", 1)[1])
            assert evidence["schema_version"] == VALIDATOR_EVIDENCE_SLICE_V3
            obligation = evidence["obligation"]
            refs = list(evidence["evidence_ref_catalog"])[:32]
            assert refs, evidence
            value = {
                "schema_version": "zscope.validator-result.v3",
                "candidate_uid": obligation["candidate_uid"],
                "validation_cluster_uid": obligation["validation_cluster_uid"],
                "pass": evidence["validation_pass"], "verdict": "verified",
                "reasoning": "当前证据支持该资源触发路径",
                "positive_evidence": ["当前函数存在资源获取及未释放退出路径"],
                "negative_evidence": [], "evidence_refs": refs,
                "blocking_negative_evidence": False,
                "missing_fact_request": None, "stop_reason": "decision_complete",
            }
            self.calls.append({"kind": evidence["validation_pass"], "evidence": evidence})
            message = {"role": "assistant", "content": json.dumps(value)}
            finish = "stop"
        # These are fixture units for verifying accounting, not measured API costs.
        return message, finish, {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}


def _native_artifact_config(root, cdb, snapshot_dir, user_config_db):
    from zscope.config.config import AgentConfig

    config = _native_config(root, cdb)
    config.scan.depth = "deep"
    config.project.agents.append(AgentConfig(name="validator_agent", task="validate"))
    config.analysis.validation_v3_reattempt = False
    config.analysis.snapshot_dir = str(snapshot_dir)
    config.analysis.user_config_db = str(user_config_db)
    return config


def _run_native_artifact_scan(backend, root, cdb, config, client, *, reuse, require_candidates=True):
    """Real instance pipeline shared by the fixed-response and small provider controls."""
    from copy import deepcopy

    from zscope.framework.llm_usage import ensure_scan_token_usage_ledger
    from zscope.orchestration.entry_instances import plan_entry_instances
    from zscope.orchestration.parallel_analyzer import ParallelAnalyzer

    index = _native_index(backend, root, cdb)
    plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])
    assert plan.status == "planned" and len(plan.instances) == 2
    parallel = ParallelAnalyzer(
        config, code_index=index, semantic_result=_semantic_stub(),
        llm_clients={"default": client}, artifact_reuse_enabled=reuse,
    )
    try:
        report = parallel.analyze_entry_instances(plan)
        assert report.status == "analyzed" and report.instance_scope_complete
        combined = parallel.generate_combined_report(parallel.last_instance_results())
        ledger = parallel._candidate_ledger.freeze()
        discovery = deepcopy(parallel._hierarchical_discovery_result)
        rows = [row["issue"] for row in ledger["outcomes"]]
        if require_candidates:
            assert rows
        keys = (
            "candidate_uid", "validation_cluster_uid", "build_context_id", "function",
            "defect_class", "candidate_disposition", "validation_status", "validator_verdict",
            "missing_fact_kinds", "evidence_gate",
        )

        def project(row):
            facts = row.get("decision_fact_slice") or {}
            refs = {
                ref
                for event in row.get("validator_audit_trail") or []
                for ref in (event.get("raw_response") or {}).get("evidence_refs") or []
            }
            return json.dumps({
                **{key: row.get(key) for key in keys},
                "evidence_refs": sorted(refs),
                "fact_uids": sorted(facts.get("fact_uids") or []),
                "edge_uids": sorted(facts.get("edge_uids") or []),
            }, sort_keys=True)
        usage = ensure_scan_token_usage_ledger(config).snapshot(include_events=True)
        return {
            "candidates": sorted(project(row) for row in rows),
            "findings": sorted(project(row) for row in combined.get("issues", [])),
            "summaries": discovery["summaries"], "discovery": discovery,
            "usage": usage, "tokens": usage["consumed_tokens"],
            "metadata": combined["metadata"], "report": combined,
        }
    finally:
        parallel.close()


def test_native_summary_and_initial_reuse_matches_fresh_after_edit_and_repair(
    native_variants, tmp_path_factory, monkeypatch,
) -> None:
    from zscope.framework.llm_client import LLMClient
    from zscope.framework.llm_usage import ensure_scan_token_usage_ledger

    backend, root, cdb = native_variants
    cache_home = tmp_path_factory.mktemp("artifact-reuse")
    source = root / "unit.c"
    original = source.read_text(encoding="utf-8")
    gap = (
        "void model_gap(size_t n) {\n"
        "  char *p = malloc(n);\n"
        "  if (!p) return;\n"
        "  p[0] = VALUE;\n"
        "  CLEANUP\n"
        "}\n"
    )

    def run(label, *, reuse):
        config = _native_artifact_config(
            root, cdb, cache_home / ("incremental" if reuse else label), cache_home / "user-config",
        )
        usage = ensure_scan_token_usage_ledger(config)
        client = LLMClient(
            api_key="fixture", base_url="https://fixture.invalid/v1", models=["fixture-model"],
            max_retries=0, supports_structured_output=True, token_usage_ledger=usage,
        )
        client._transport = "curl"
        transport = _ArtifactReuseTransport()
        monkeypatch.setattr(client, "_curl_chat_completion", transport)
        try:
            result = _run_native_artifact_scan(backend, root, cdb, config, client, reuse=reuse)
            snapshot = usage.snapshot(include_events=True)
            assert snapshot["event_count"] == len(transport.calls)
            assert snapshot["consumed_tokens"] == 18 * len(transport.calls)
            assert sum(event["total_tokens"] for event in snapshot["events"]) == snapshot["consumed_tokens"]
            assert result["report"]["summary"]["total_cumulative_total_tokens"] == snapshot["consumed_tokens"]
            result["calls"] = transport.calls
            return result
        finally:
            client.close()

    for stage, value, cleanup in (
        ("cold", "0", ""), ("hot", "0", ""),
        ("changed", "1", ""), ("repaired", "1", "free(p);"),
    ):
        source.write_text(original + gap.replace("VALUE", value).replace("CLEANUP", cleanup), encoding="utf-8")
        assert backend.initialize(str(root), compile_commands_path=str(cdb))
        current = run(stage, reuse=True)
        if stage == "cold":
            assert any(call["kind"] == "summary" for call in current["calls"])
            assert any(call["kind"] == "initial" for call in current["calls"])
            baseline = current
        elif stage == "hot":
            assert current["calls"] == []
            assert current["tokens"] == 0
            for key in ("candidates", "findings", "summaries"):
                assert current[key] == baseline[key], (stage, key)
        else:
            fresh = run("fresh-" + stage, reuse=False)
            for key in ("candidates", "findings", "summaries"):
                assert current[key] == fresh[key], (stage, key)
            assert current["tokens"] < fresh["tokens"], stage
            if stage == "changed":
                assert any(call["kind"] == "initial" for call in fresh["calls"])
                assert any(
                    call["kind"] == "summary" and call["unit"].get("function") == "model_gap"
                    for call in current["calls"]
                )
        if stage == "repaired":
            assert not any("model_gap" in row for row in current["candidates"])
