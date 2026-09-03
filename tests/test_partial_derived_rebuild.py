"""Partial (include-closure scoped) derived index rebuild tests (P1-M5)."""

from __future__ import annotations

import inspect
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

import pytest

from zscope.retrieval.clang_backend import ClangBackend
from zscope.retrieval.clang_extractor import ClangExtractor
from zscope.retrieval.clang_extractor_pool import ClangExtractorPool
from zscope.retrieval.knowledge_db import KnowledgeDB


def make_db(tmp_path: Path) -> KnowledgeDB:
    db = KnowledgeDB(str(tmp_path / "code_knowledge.db"))
    return db


def seed_functions(db: KnowledgeDB) -> None:
    db.insert_functions_batch(
        [
            ("fn_a", "src/a.c", 1, 10, "int fn_a(void)", 0, 0, 0, 1),
            ("fn_b", "src/b.c", 1, 10, "int fn_b(void)", 0, 0, 0, 2),
        ]
    )


def test_compute_derived_affected_files_uses_closure(tmp_path: Path) -> None:
    db = make_db(tmp_path)
    db.insert_include_edges_batch(
        [
            ("src/main.c", "src/util.h", 3, 0),
            ("src/util.h", "src/deep.h", 1, 0),
        ]
    )

    # Absolute changed path bridged through marker-relative variants
    changed_header = str(tmp_path / "src" / "deep.h")
    affected = db.compute_derived_affected_files(
        [changed_header], ["src/main.c", "src/other.c"]
    )
    assert affected == {"src/main.c"}

    affected = db.compute_derived_affected_files(
        [str(tmp_path / "src" / "util.h")], ["src/main.c", "src/other.c"]
    )
    assert affected == {"src/main.c"}

    # Directly changed candidate matches by basename
    affected = db.compute_derived_affected_files(
        ["src/main.c"], ["src/main.c", "src/other.c"]
    )
    assert affected == {"src/main.c"}

    # Unrelated change affects nothing (empty set, not None)
    affected = db.compute_derived_affected_files(
        ["src/unrelated.h"], ["src/main.c", "src/other.c"]
    )
    assert affected == set()


def test_compute_derived_affected_files_ratio_guard(tmp_path: Path) -> None:
    db = make_db(tmp_path)
    candidates = ["src/a.c", "src/b.c"]
    # Both candidates affected at the default 0.5 ratio -> full rebuild
    assert (
        db.compute_derived_affected_files(["src/a.c", "src/b.c"], candidates) is None
    )


def test_finalize_merge_replaces_only_affected_files(tmp_path: Path) -> None:
    db = make_db(tmp_path)
    seed_functions(db)
    db.insert_function_symbol_refs_batch(
        [
            ("fn_a", "src/a.c", "g_old", "variable", "src/g.c", 5, "read"),
            ("fn_b", "src/b.c", "g_keep", "variable", "src/g.c", 6, "read"),
        ]
    )

    version = "test-v1"
    db.begin_derived_index_rebuild("function_symbol_context", version)
    db.prepare_derived_index_staging("function_symbol_context")
    db.stage_function_symbol_refs_batch(
        [
            ("fn_a", "src/a.c", "g_new", "variable", "src/g.c", 7, "read_write"),
        ]
    )
    db.finalize_derived_index_rebuild(
        "function_symbol_context",
        version,
        {"rows": 1},
        merge_files=["src/a.c"],
    )

    rows = db._conn.execute(
        "SELECT function_name, symbol_name, access_kind FROM function_symbol_refs "
        "ORDER BY function_name"
    ).fetchall()
    payload = {(row["function_name"], row["symbol_name"]): row["access_kind"] for row in rows}
    assert payload == {
        ("fn_a", "g_new"): "read_write",
        ("fn_b", "g_keep"): "read",
    }
    state = db.get_derived_index_state("function_symbol_context")
    assert state["status"] == "current"
    assert state["applied_version"] == version


def test_finalize_merge_type_refs_keeps_other_files(tmp_path: Path) -> None:
    db = make_db(tmp_path)
    seed_functions(db)
    db.replace_function_type_refs(
        [
            (1, None, "", "OldType", "src/a.c", 2, "usage", ""),
            (2, None, "", "KeepType", "src/b.c", 3, "usage", ""),
        ]
    )

    version = "test-v1"
    db.begin_derived_index_rebuild("function_type_refs", version)
    db.prepare_derived_index_staging("function_type_refs")
    db.stage_function_type_refs_batch(
        [(1, None, "", "NewType", "src/a.c", 4, "usage", "direct")]
    )
    db.finalize_derived_index_rebuild(
        "function_type_refs",
        version,
        {"rows": 1},
        merge_files=["src/a.c"],
    )

    rows = db._conn.execute(
        "SELECT function_id, referenced_name FROM function_type_refs ORDER BY function_id"
    ).fetchall()
    assert [(row["function_id"], row["referenced_name"]) for row in rows] == [
        (1, "NewType"),
        (2, "KeepType"),
    ]


def test_finalize_without_merge_files_still_full_replace(tmp_path: Path) -> None:
    db = make_db(tmp_path)
    seed_functions(db)
    db.insert_function_symbol_refs_batch(
        [("fn_b", "src/b.c", "g_keep", "variable", "src/g.c", 6, "read")]
    )
    version = "test-v2"
    db.begin_derived_index_rebuild("function_symbol_context", version)
    db.prepare_derived_index_staging("function_symbol_context")
    db.finalize_derived_index_rebuild("function_symbol_context", version, {"rows": 0})
    rows = db._conn.execute("SELECT COUNT(*) AS n FROM function_symbol_refs").fetchone()
    assert rows["n"] == 0


class FakePlanningDB:
    """Duck-typed KnowledgeDB for backend planning tests."""

    def __init__(
        self,
        *,
        dirty_reason: str = "base_facts_changed",
        affected: Optional[Set[str]] = None,
        with_compute: bool = True,
        candidates: Optional[Sequence[str]] = None,
    ) -> None:
        self._dirty_reason = dirty_reason
        self._affected = affected
        self._candidates = list(candidates or ["src/a.c", "src/b.c"])
        self.compute_calls: List[Tuple[List[str], List[str]]] = []
        if with_compute:
            self.compute_derived_affected_files = self._compute  # type: ignore[attr-defined]

    def _compute(
        self,
        changed_files: Sequence[str],
        deleted_files: Sequence[str],
        candidate_files: Sequence[str],
        *,
        max_affected_ratio: float = 0.5,
    ) -> Optional[Set[str]]:
        self.compute_calls.append((list(changed_files), list(deleted_files)))
        return self._affected

    def get_derived_index_state(self, index_name: str) -> Dict[str, Any]:
        return {"status": "dirty", "dirty_reason": self._dirty_reason}

    def get_function_records(self) -> List[Dict[str, Any]]:
        return [{"file_path": name} for name in self._candidates]


def make_backend() -> ClangBackend:
    return ClangBackend(clangd_path="clangd", db_path=":memory:")


def work() -> List[Tuple[str, str, Any]]:
    return [("function_symbol_context", "v1", lambda *a, **k: 0)]


def test_backend_partial_plan_allowed_on_base_facts_change() -> None:
    backend = make_backend()
    db = FakePlanningDB(affected={"src/a.c"})
    plan = backend._plan_partial_derived_rebuild(
        db, work(), changed_paths=["C:/proj/src/deep.h"], deleted_paths=[]
    )
    assert plan == {"src/a.c"}
    assert db.compute_calls == [(["C:/proj/src/deep.h"], [])]


def test_backend_partial_plan_rejects_version_invalidation() -> None:
    backend = make_backend()
    db = FakePlanningDB(dirty_reason="extractor_version_changed", affected={"src/a.c"})
    assert (
        backend._plan_partial_derived_rebuild(
            db, work(), changed_paths=["src/deep.h"], deleted_paths=[]
        )
        is None
    )


def test_backend_partial_plan_rejects_wide_affected_set() -> None:
    backend = make_backend()
    db = FakePlanningDB(affected=None)  # None -> compute says full rebuild is cheaper
    assert (
        backend._plan_partial_derived_rebuild(
            db, work(), changed_paths=["src/deep.h"], deleted_paths=[]
        )
        is None
    )


def test_backend_partial_plan_rejects_when_no_base_changes() -> None:
    backend = make_backend()
    db = FakePlanningDB(affected={"src/a.c"})
    assert (
        backend._plan_partial_derived_rebuild(
            db, work(), changed_paths=[], deleted_paths=[]
        )
        is None
    )


def test_backend_partial_plan_rejects_without_compute_support() -> None:
    backend = make_backend()
    db = FakePlanningDB(with_compute=False)
    assert (
        backend._plan_partial_derived_rebuild(
            db, work(), changed_paths=["src/deep.h"], deleted_paths=[]
        )
        is None
    )


def test_rebuild_methods_accept_only_files() -> None:
    for extractor_type in (ClangExtractor, ClangExtractorPool):
        for method_name in (
            "rebuild_function_symbol_refs",
            "rebuild_function_type_refs",
            "rebuild_function_derived_refs",
        ):
            params = inspect.signature(getattr(extractor_type, method_name)).parameters
            assert "only_files" in params, (extractor_type.__name__, method_name)


def test_deleted_paths_flow_into_planning() -> None:
    backend = make_backend()
    db = FakePlanningDB(affected={"src/main.c"})
    backend._plan_partial_derived_rebuild(
        db, work(), changed_paths=[], deleted_paths=["src/deleted.h"]
    )
    assert db.compute_calls == [([], ["src/deleted.h"])]
