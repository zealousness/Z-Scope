"""Every migrated symbol consumer must stay bound to one exact build instance.

The scoped facade now serves callee/caller/type/macro/graph members from the
native receipts stored under a content-bound ``BuildContext``.  These tests lock
the invariant that made the migration safe: a member is served only when its
receipt names the pinned instance, and another variant's receipts (or an unknown
build identity) never leak through the same query.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List

import pytest

from zscope.config.config import IndexingConfig
from zscope.config.function_entry import FunctionEntry
from zscope.orchestration.entry_instances import plan_entry_instances
from zscope.retrieval.clang_backend import ClangBackend
from zscope.retrieval.code_index import CodeIndex
from zscope.retrieval.instance_index import InstanceScope, ScopedCodeIndex, wrap_scoped_code_index


def _receipt(kind: str, owner: Dict[str, Any], target: Dict[str, Any], line: int) -> Dict[str, Any]:
    return {
        "kind": kind,
        "owner": dict(owner),
        "target": dict(target),
        "location": {"file": owner.get("file", ""), "line": line},
    }


class _ReceiptIndex:
    """Serves exact-context receipts only; other identities stay empty."""

    language = "c_cpp"
    backend_name = "clang"

    def __init__(self, rows: Dict[str, List[Dict[str, Any]]]):
        self.rows = {key: [dict(row) for row in value] for key, value in rows.items()}
        self.queries: List[str] = []

    def get_function_program_facts(
        self, name: str, file_path: str = "", *, build_context_id: str = ""
    ) -> Dict[str, Any]:
        rows = self.rows.get(build_context_id, [])
        bodies = [
            row for row in rows if row.get("kind") == "program_function" and row.get("complete")
        ]
        if not bodies:
            return {"complete": False, "events": [], "accesses": [], "functions": []}
        return {
            "complete": True,
            "build_context_id": build_context_id,
            "functions": bodies,
            "events": [],
            "accesses": [],
            "function_identity": {
                "build_context_id": build_context_id,
                "usr": bodies[0]["owner"]["usr"],
            },
        }

    def get_build_contexts(self, file_path: str = "") -> List[Dict[str, Any]]:
        return [
            {
                "build_context_id": key,
                "source": "unit.c",
                "status": "indexed",
                "dependencies_complete": True,
            }
            for key in self.rows
        ]

    def get_compilation_facts(
        self, context_id: str, *, kinds=(), symbol: str = "", file_path: str = ""
    ) -> List[Dict[str, Any]]:
        self.queries.append(context_id)
        rows = self.rows.get(context_id, [])
        if kinds:
            rows = [row for row in rows if row.get("kind") in kinds]
        if symbol:
            rows = [row for row in rows if row["owner"].get("name") == symbol]
        return [dict(row) for row in rows]


def _function_row(context: str, usr: str, line: int) -> Dict[str, Any]:
    owner = {"name": "f", "usr": usr, "file": "unit.c", "line": line}
    return {
        "kind": "program_function",
        "complete": True,
        "owner": owner,
        "location": {"file": "unit.c", "line": line},
        "events": [],
    }


def _scope(context_id: str, usr: str = "c:@F@f", source: str = "unit.c") -> InstanceScope:
    return InstanceScope(
        build_context_id=context_id,
        usr=usr,
        identity=f"{context_id}:{usr}",
        source=source,
        function_names=("f",),
    )


def _view(index: Any, context_id: str = "ctx-alt", usr: str = "c:@F@f") -> ScopedCodeIndex:
    """A scoped view with dependency preflight held current.

    These are receipt-shape unit probes over synthetic rows; the real native
    header-edit withdrawal is covered by the native tests below.
    """

    view = ScopedCodeIndex(index, _scope(context_id, usr))
    view.dependencies_current_status = lambda: "current"  # type: ignore[method-assign]
    return view


def _two_contexts() -> _ReceiptIndex:
    alt_owner = {"name": "f", "usr": "c:@F@f", "file": "unit.c", "line": 2}
    base_owner = {"name": "f", "usr": "c:@F@f", "file": "unit.c", "line": 4}
    return _ReceiptIndex(
        {
            "ctx-alt": [
                _function_row("ctx-alt", "c:@F@f", 2),
                _receipt(
                    "call",
                    alt_owner,
                    {
                        "usr": "c:@F@alt_helper",
                        "name": "alt_helper",
                        "qualified_name": "alt_helper",
                    },
                    5,
                ),
            ],
            "ctx-base": [
                _function_row("ctx-base", "c:@F@f", 4),
                _receipt(
                    "call",
                    base_owner,
                    {
                        "usr": "c:@F@base_helper",
                        "name": "base_helper",
                        "qualified_name": "base_helper",
                    },
                    7,
                ),
            ],
        }
    )


def test_callees_never_cross_the_pinned_build_context() -> None:
    index = _two_contexts()
    alt = _view(index, "ctx-alt")
    base = _view(index, "ctx-base")

    alt_names = [record["name"] for record in alt.get_callees("f")]
    base_names = [record["name"] for record in base.get_callees("f")]

    assert alt_names == ["alt_helper"], alt_names
    assert base_names == ["base_helper"], base_names
    assert alt.get_callees("f")[0]["build_context_id"] == "ctx-alt"
    assert base.get_callees("f")[0]["build_context_id"] == "ctx-base"
    # Only the pinned context was ever queried.
    assert set(index.queries) == {"ctx-alt", "ctx-base"}


def test_callers_and_macros_stay_inside_the_pinned_context() -> None:
    index = _two_contexts()
    alt = _view(index, "ctx-alt")

    assert [record["name"] for record in alt.get_callers("alt_helper")] == ["f"]
    assert alt.get_callers("base_helper") == []
    # A member from the other variant is not visible here.
    assert alt.get_callers("alt_helper")[0]["build_context_id"] == "ctx-alt"


def test_unknown_build_context_yields_no_symbol_receipts() -> None:
    index = _two_contexts()
    view = _view(index, "ctx-absent")

    assert view.get_callees("f") == []
    assert view.get_callers("f") == []
    assert view.list_functions() == []
    assert view.get_function_symbol_context("f")["referenced_macros"] == []
    assert view.get_function_type_context("f")["referenced_types"] == []


def test_same_usr_different_owner_line_is_not_served() -> None:
    # A call receipt owned by the same USR but a different native line is a
    # different conditional definition and must not answer for this instance.
    owner = {"name": "f", "usr": "c:@F@f", "file": "unit.c", "line": 9}
    index = _ReceiptIndex(
        {
            "ctx-alt": [
                _function_row("ctx-alt", "c:@F@f", 2),
                _receipt(
                    "call",
                    owner,
                    {"usr": "c:@F@wrong", "name": "wrong", "qualified_name": "wrong"},
                    9,
                ),
            ]
        }
    )
    view = _view(index, "ctx-alt")

    assert view.get_callees("f") == []


def test_list_functions_uses_the_instance_receipts() -> None:
    index = _two_contexts()
    view = _view(index, "ctx-alt")

    assert view.list_functions() == ["f"]


def _native_two_macro(tmp_path: Path):
    executable = os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER")
    if not executable:
        pytest.skip("instance symbol tests require Z_SCOPE_TEST_CLANG_INDEXER")
    (tmp_path / "flags.h").write_text(
        "#ifdef ALT\n#define MARK 1\n#else\n#define MARK 2\n#endif\n", encoding="utf-8"
    )
    source = tmp_path / "unit.c"
    source.write_text('#include "flags.h"\nvoid f(void) { (void)MARK; }\n', encoding="utf-8")
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
    return backend, index


def test_native_cross_variant_isolation_for_served_symbol_receipts(tmp_path: Path) -> None:
    backend, index = _native_two_macro(tmp_path)
    try:
        plan = plan_entry_instances(index, [FunctionEntry("f", file_path="unit.c")])
        assert plan.status == "planned" and len(plan.instances) == 2
        contexts = {row["build_context_id"]: row for row in index.get_build_contexts("unit.c")}
        contexts_seen = set()
        for instance in plan.instances:
            scope = InstanceScope.from_entry_instance(instance)
            view = ScopedCodeIndex(index, scope)
            contexts_seen.add(scope.build_context_id)
            records = view.get_callees("f")
            assert all(
                record["build_context_id"] == scope.build_context_id for record in records
            ), records
            macros = view.get_function_symbol_context("f")["referenced_macros"]
            for member in macros:
                assert member["function_identity"]["usr"] == scope.usr
                assert member["function_identity"]["build_context_id"] == scope.build_context_id
        assert len(contexts_seen) == 2
        assert set(contexts_seen) <= set(contexts)
    finally:
        backend.close()


def test_native_usr_and_alias_queries_resolve_one_instance_owner() -> None:
    index = _two_contexts()
    view = _view(index, "ctx-alt")

    # The pinned native USR resolves to this instance's own owner.
    assert [record["name"] for record in view.get_callees("c:@F@f")] == ["alt_helper"]
    # A navigation alias of another condition's range is not the pinned identity.
    assert view.get_callees("f@unit.c:9-9") == []
    # And the plain name still resolves to the pinned entry only.
    assert [record["name"] for record in view.get_callees("f")] == ["alt_helper"]


def test_explicit_foreign_callee_file_is_refused() -> None:
    index = _two_contexts()
    view = _view(index, "ctx-alt")

    assert [record["name"] for record in view.get_callers("alt_helper")] == ["f"]
    assert view.get_callers("alt_helper", callee_file="foreign.c") == []


def test_wrap_keeps_single_facade_per_identity() -> None:
    index = _two_contexts()
    scope = _scope("ctx-alt")
    first = wrap_scoped_code_index(index, scope)
    again = wrap_scoped_code_index(first, scope)
    other = wrap_scoped_code_index(first, _scope("ctx-base"))

    assert again is first
    assert isinstance(other, ScopedCodeIndex)
    assert other.scope.build_context_id == "ctx-base"
