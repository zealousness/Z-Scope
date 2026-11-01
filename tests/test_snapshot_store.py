import hashlib
import json
import sqlite3
import threading
from types import SimpleNamespace

import pytest

from zscope.common.utils import compute_code_hash, compute_semantic_fingerprint
from zscope.snapshots.store import (
    SnapshotLockManager,
    SnapshotStore,
    compute_callee_summary_hash,
    compute_symbol_context_hash,
    compute_type_context_hash,
)
from zscope.snapshots.policy import build_trivial_snapshot


def _snapshot(
    index_name="handle_request@src/server.c:10-20",
    *,
    summary="snapshot",
    file_path="src/server.c",
    start_line=10,
    end_line=20,
):
    return {
        "type": "function_snapshot",
        "func_name": "handle_request",
        "index_name": index_name,
        "file_path": file_path,
        "start_line": start_line,
        "end_line": end_line,
        "signature": "int handle_request(void)",
        "snapshot_kind": "LLM-modeled",
        "is_static": False,
        "is_macro": False,
        "referenced_globals": [],
        "referenced_macros": [],
        "referenced_types": [],
        "summary": summary,
    }


@pytest.mark.parametrize("owner", [None, [], "invalid", 42])
def test_final_report_rejects_non_object_snapshot_owner(tmp_path, owner) -> None:
    store = SnapshotStore(tmp_path / "snapshots")
    snapshot = _snapshot()
    index_name = snapshot["index_name"]
    generation = store.save_snapshot(
        index_name, snapshot, "int handle_request(void) { return 0; }"
    )
    assert store.save_final_report(index_name, {"issues": []}, expected_generation=generation)
    (store.snapshot_dir / generation).write_text(json.dumps(owner), encoding="utf-8")

    assert store.load_final_report(index_name) is None


def test_snapshot_lock_uses_index_name() -> None:
    lock_manager = SnapshotLockManager()
    left = "handle_request@src/a/server.c:10-20"
    right = "handle_request@src/b/server.c:10-20"

    assert lock_manager.acquire(left) == "acquired"
    assert lock_manager.acquire(left, timeout=0.01) == "timeout"
    assert lock_manager.acquire(right) == "acquired"

    lock_manager.release(left)
    lock_manager.release(right)

    assert lock_manager.acquire(left) == "done"
    assert lock_manager.acquire(right) == "done"


def test_deleting_snapshot_invalidates_completed_build_lock(tmp_path) -> None:
    store = SnapshotStore(tmp_path / "snapshots")
    index_name = "handle_request@src/server.c:10-20"
    store.save_snapshot(
        index_name,
        _snapshot(),
        "int handle_request(void) { return 0; }",
    )
    assert store.lock_manager.acquire(index_name) == "acquired"
    store.lock_manager.release(index_name, success=True)
    assert store.lock_manager.acquire(index_name) == "done"

    store.delete_snapshot(index_name)

    assert store.lock_manager.acquire(index_name) == "acquired"
    store.lock_manager.release(index_name, success=False)


def test_snapshot_load_cache_returns_independent_copies(tmp_path) -> None:
    store = SnapshotStore(tmp_path / "snapshots")
    index_name = "handle_request@src/server.c:10-20"
    snapshot = _snapshot(index_name, summary="first")
    snapshot["items"] = [{"name": "a"}]
    store.save_snapshot(index_name, snapshot, "int handle_request(void) { return 0; }")

    loaded = store.load_snapshot(index_name)
    assert loaded is not None
    loaded["summary"] = "mutated"
    loaded["items"][0]["name"] = "mutated"

    assert store.load_snapshot(index_name) == snapshot


def test_snapshot_and_report_cache_share_a_byte_bounded_lru(tmp_path) -> None:
    snapshot = _snapshot(summary="x" * 80)
    report = {"entry_function": "handle_request", "notes": ["y" * 80]}
    encode = lambda value: json.dumps(  # noqa: E731
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    cache_limit = max(len(encode(snapshot)), len(encode(report)))
    store = SnapshotStore(
        tmp_path / "snapshots",
        cache_max_bytes=cache_limit,
    )

    store._cache_snapshot("snapshot-key", snapshot)
    assert store._cached_snapshot("snapshot-key") == snapshot
    store._cache_final_report("report-key", report)

    assert store._cached_snapshot("snapshot-key") is None
    assert store._cached_final_report("report-key") == report
    assert store.cache_stats()["bytes"] <= cache_limit
    assert store.cache_stats()["entries"] == 1


def test_snapshot_save_refreshes_cache_and_fingerprints(tmp_path) -> None:
    store = SnapshotStore(tmp_path / "snapshots")
    index_name = "handle_request@src/server.c:10-20"
    first_code = "int handle_request(void) { return 0; }"
    second_code = "int handle_request(void) { return 1; }"
    store.save_snapshot(index_name, _snapshot(summary="first"), first_code)
    store.save_snapshot(index_name, _snapshot(summary="second"), second_code)

    assert store.load_snapshot(index_name)["summary"] == "second"
    assert store.get_fingerprints(index_name) == {
        "code_hash": compute_code_hash(second_code),
        "semantic_hash": compute_semantic_fingerprint(second_code),
        "symbol_context_hash": compute_symbol_context_hash(_snapshot(summary="second")),
        "callee_summary_hash": compute_callee_summary_hash(_snapshot(summary="second")),
        "type_context_hash": compute_type_context_hash(_snapshot(summary="second")),
        "effective_rules_sha256": "",
        "snapshot_generation": store.observed_generation(index_name),
    }
    assert store.needs_refresh(index_name, second_code, _snapshot()) == (False, None)


def test_symbol_context_change_requires_snapshot_refresh(tmp_path) -> None:
    store = SnapshotStore(tmp_path / "snapshots")
    index_name = "handle_request@src/server.c:10-20"
    code = "int handle_request(void) { return LIMIT; }"
    snapshot = _snapshot()
    snapshot["referenced_macros"] = [
        {
            "macro_index_name": "LIMIT@include/limits.h:4-4",
            "definition": "4 | #define LIMIT 8\n",
            "is_function_like": False,
            "reference_lines": [10],
        }
    ]
    store.save_snapshot(index_name, snapshot, code)

    changed_context = _snapshot()
    changed_context["referenced_macros"] = [
        {
            **snapshot["referenced_macros"][0],
            "definition": "4 | #define LIMIT 16\n",
        }
    ]

    assert store.needs_refresh(index_name, code, snapshot) == (False, None)
    assert store.needs_refresh(index_name, code, changed_context) == (
        True,
        "symbol_context_changed",
    )


def test_legacy_macro_item_requires_snapshot_shape_refresh(tmp_path) -> None:
    store = SnapshotStore(tmp_path / "snapshots")
    index_name = "handle_request@src/server.c:10-20"
    code = "int handle_request(void) { return LIMIT; }"
    snapshot = _snapshot()
    snapshot["referenced_macros"] = [
        {
            "name": "LIMIT",
            "file_path": "include/limits.h",
            "line": 4,
            "definition": "#define LIMIT 8",
            "is_function_like": False,
            "reference_lines": [10],
        }
    ]
    store.save_snapshot(index_name, snapshot, code)

    current = _snapshot()
    current["referenced_macros"] = [
        {
            "macro_index_name": "LIMIT@include/limits.h:4-4",
            "definition": "4 | #define LIMIT 8\n",
            "is_function_like": False,
            "reference_lines": [10],
        }
    ]

    assert store.needs_refresh(index_name, code, current) == (
        True,
        "snapshot_shape_changed",
    )


def test_type_context_hash_normalizes_order_and_definition_line_endings() -> None:
    first = _snapshot()
    first["referenced_types"] = [
        {
            "type_index_name": "Plugin@include/types.h:90-98",
            "kind": "struct",
            "full_definition": "90 | typedef struct {\r\n91 |     int id;   \r\n92 | } Plugin;\r\n",
            "reference_kinds": ["sizeof", "local"],
            "reference_lines": [14, 12],
        }
    ]
    reordered = _snapshot()
    reordered["referenced_types"] = [
        {
            **first["referenced_types"][0],
            "full_definition": "90 | typedef struct {\n91 |     int id;\n92 | } Plugin;",
            "reference_kinds": ["local", "sizeof"],
            "reference_lines": [12, 14],
        }
    ]

    assert compute_type_context_hash(first) == compute_type_context_hash(reordered)

    reordered["referenced_types"][0][
        "full_definition"
    ] = "90 | typedef struct {\n91 |     long id;\n92 | } Plugin;"
    assert compute_type_context_hash(first) != compute_type_context_hash(reordered)


def test_type_definition_or_direct_reference_change_requires_semantic_refresh(
    tmp_path,
) -> None:
    store = SnapshotStore(tmp_path / "snapshots")
    index_name = "handle_request@src/server.c:10-20"
    code = "int handle_request(void) { return 0; }"
    snapshot = _snapshot()
    snapshot["referenced_types"] = [
        {
            "type_index_name": "Context@include/context.h:1-3",
            "kind": "struct",
            "full_definition": "1 | typedef struct { int value; } Context;\n",
            "reference_kinds": ["parameter"],
            "reference_lines": [10],
        }
    ]
    store.save_snapshot(index_name, snapshot, code)

    definition_changed = json.loads(json.dumps(snapshot))
    definition_changed["referenced_types"][0][
        "full_definition"
    ] = "1 | typedef struct { long value; } Context;\n"
    assert store.needs_refresh(index_name, code, definition_changed) == (
        True,
        "type_context_changed",
    )

    reference_changed = json.loads(json.dumps(snapshot))
    reference_changed["referenced_types"][0]["reference_kinds"] = [
        "parameter",
        "member_access",
    ]
    assert store.needs_refresh(index_name, code, reference_changed) == (
        True,
        "type_context_changed",
    )

    cosmetic = json.loads(json.dumps(snapshot))
    cosmetic["referenced_types"][0][
        "full_definition"
    ] = "1 | typedef struct { int value; } Context;   \r\n"
    assert store.needs_refresh(index_name, code, cosmetic) == (False, None)


def test_old_snapshot_without_referenced_types_requires_shape_rebuild(tmp_path) -> None:
    store = SnapshotStore(tmp_path / "snapshots")
    index_name = "handle_request@src/server.c:10-20"
    code = "int handle_request(void) { return 0; }"
    current = _snapshot()
    store.save_snapshot(index_name, current, code)
    snapshot_path = store.snapshot_dir / str(store.observed_generation(index_name))
    persisted = json.loads(snapshot_path.read_text(encoding="utf-8"))
    persisted.pop("referenced_types")
    snapshot_path.write_text(json.dumps(persisted), encoding="utf-8")
    store._invalidate_snapshot_cache(index_name)

    assert store.needs_refresh(index_name, code, current) == (
        True,
        "snapshot_shape_changed",
    )


def test_callee_context_hash_uses_only_canonical_backend_fields() -> None:
    snapshot_context = {
        "referenced_globals": [],
        "referenced_macros": [],
        "project_callees": [
            {
                "callee_index_name": "decode@src/decode.c:10-20",
                "callsite_lines": [14, 12],
                "call_type": ["indirect", "direct"],
                "callee_behavior": "LLM-generated behavior",
            }
        ],
    }
    backend_context = {
        "referenced_globals": [],
        "referenced_macros": [],
        "project_callees": [
            {
                "callee_index_name": "decode@src/decode.c:10-20",
                "callsite_lines": [12],
                "call_type": ["direct"],
                "callee_summary": "unknown",
            },
            {
                "callee_index_name": "decode@src/decode.c:10-20",
                "callsite_lines": [14],
                "call_type": ["indirect"],
            },
        ],
    }

    assert compute_symbol_context_hash(snapshot_context) == compute_symbol_context_hash(
        backend_context
    )


def test_backend_callee_change_requires_snapshot_refresh(tmp_path) -> None:
    store = SnapshotStore(tmp_path / "snapshots")
    index_name = "handle_request@src/server.c:10-20"
    code = "int handle_request(void) { return decode(); }"
    backend_context = {
        "referenced_globals": [],
        "referenced_macros": [],
        "project_callees": [
            {
                "callee_index_name": "decode@src/decode.c:10-20",
                "callsite_lines": [10],
                "call_type": ["direct"],
                "is_static": False,
            }
        ],
    }
    snapshot = _snapshot()
    snapshot["index_name"] = index_name
    snapshot["project_callees"] = [
        {
            **backend_context["project_callees"][0],
            "is_static": False,
            "callee_summary": "unknown",
        },
        {
            "callee_index_name": "llm_only@src/other.c:1-2",
            "callsite_lines": [],
            "call_type": ["direct"],
            "callee_summary": "unknown",
        },
    ]
    store.save_snapshot(
        index_name,
        snapshot,
        code,
        dependency_context=backend_context,
    )

    assert store.needs_refresh(index_name, code, backend_context) == (False, None)

    changed_indirect_callsite = {
        **backend_context,
        "project_callees": [
            {
                **backend_context["project_callees"][0],
                "indirect_callsites": [
                    {
                        "callsite_line": 11,
                        "function_pointer": "Ops.decode",
                        "function_pointer_kind": "field",
                        "function_pointer_type": "DecodeFn",
                        "function_pointer_signature": "int (*)(void)",
                        "callsite_expression": "ops->decode",
                    }
                ],
            }
        ],
    }
    assert store.needs_refresh(index_name, code, changed_indirect_callsite) == (
        True,
        "symbol_context_changed",
    )

    changed_summary = {
        **backend_context,
        "project_callees": [
            {
                **backend_context["project_callees"][0],
                "callee_summary": "updated canonical summary",
            }
        ],
    }
    assert store.needs_refresh(index_name, code, changed_summary) == (
        False,
        "callee_summary_changed",
    )
    assert store.reconcile_project_callee_summaries(index_name, changed_summary) == "refreshed"
    refreshed = store.load_snapshot(index_name)
    assert refreshed["summary"] == snapshot["summary"]
    assert refreshed["project_callees"] == changed_summary["project_callees"]
    assert store.needs_refresh(index_name, code, changed_summary) == (False, None)

    changed_truncation = {
        **backend_context,
        "project_callees_truncation": {"truncated": True, "returned": 30, "total": 31},
    }
    assert store.needs_refresh(index_name, code, changed_truncation) == (
        True,
        "symbol_context_changed",
    )


def test_concurrent_program_only_reconciliation_is_serialized(tmp_path) -> None:
    store = SnapshotStore(tmp_path / "snapshots")
    index_name = "caller@src/caller.c:1-3"
    code = "int caller(void) { return child(); }"
    context = {
        "referenced_globals": [],
        "referenced_macros": [],
        "project_callees": [
            {
                "callee_index_name": "child@src/child.c:1-3",
                "callsite_lines": [2],
                "call_type": ["direct"],
                "is_static": False,
                "callee_summary": "unknown",
            }
        ],
        "external_callees": [],
    }
    snapshot = _snapshot(index_name=index_name)
    snapshot["project_callees"] = context["project_callees"]
    snapshot["external_callees"] = []
    store.save_snapshot(index_name, snapshot, code, dependency_context=context)
    desired = {
        **context,
        "project_callees": [{**context["project_callees"][0], "callee_summary": "child summary"}],
    }
    barrier = threading.Barrier(2)
    statuses = []

    def reconcile():
        barrier.wait()
        statuses.append(store.reconcile_project_callee_summaries(index_name, desired))

    threads = [threading.Thread(target=reconcile) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(statuses) == ["refreshed", "unchanged"]
    assert store.load_snapshot(index_name)["project_callees"] == desired["project_callees"]


def test_legacy_callee_behavior_requires_snapshot_shape_refresh(tmp_path) -> None:
    store = SnapshotStore(tmp_path / "snapshots")
    index_name = "caller@src/caller.c:1-3"
    code = "int caller(void) { return child(); }"
    context = {
        "referenced_globals": [],
        "referenced_macros": [],
        "project_callees": [
            {
                "callee_index_name": "child@src/child.c:1-2",
                "callsite_lines": [1],
                "call_type": ["direct"],
                "is_static": False,
                "is_macro": False,
                "callee_summary": "unknown",
            }
        ],
        "external_callees": [],
    }
    snapshot = _snapshot()
    snapshot["index_name"] = index_name
    snapshot["project_callees"] = [
        {
            **context["project_callees"][0],
            "callee_behavior": "legacy",
        }
    ]
    snapshot["project_callees"][0].pop("callee_summary")
    store.save_snapshot(index_name, snapshot, code, dependency_context=context)

    assert store.needs_refresh(index_name, code, context) == (
        True,
        "snapshot_shape_changed",
    )


def test_legacy_deterministic_shape_requires_snapshot_refresh(tmp_path) -> None:
    store = SnapshotStore(tmp_path / "snapshots")
    index_name = "tiny@src/tiny.c:1-3"
    code = "1 | int tiny(void) {\n2 | return 0;\n3 | }"
    legacy = {
        **_snapshot(
            index_name,
            file_path="src/tiny.c",
            start_line=1,
            end_line=3,
        ),
        "snapshot_kind": "syntactic",
        "code": code,
        "inputs": [],
        "outputs": [],
        "resources": {},
        "error_handling": {},
        "concurrency": {},
        "key_semantics": [],
        "suspicious_points": [],
        "callees": [],
    }
    store.save_snapshot(index_name, legacy, code)
    store.save_final_report(index_name, {"issues": [{"id": "legacy"}]})

    assert store.needs_refresh(index_name, code, legacy) == (
        True,
        "snapshot_shape_changed",
    )
    assert store.load_final_report(index_name) == {"issues": [{"id": "legacy"}]}

    current = build_trivial_snapshot(
        "tiny",
        {
            "index_name": index_name,
            "file_path": "src/tiny.c",
            "start_line": 1,
            "end_line": 3,
            "signature": "int tiny(void)",
            "is_static": False,
            "is_macro": False,
            "referenced_globals": [],
            "referenced_macros": [],
            "callees": [],
            "code": code,
        },
    )
    store.save_snapshot(index_name, current, code)

    assert store.needs_refresh(index_name, code, current) == (False, None)
    assert store.load_final_report(index_name) is None


def test_deterministic_snapshot_accepts_unresolved_callees() -> None:
    snapshot = build_trivial_snapshot(
        "tiny",
        {
            "index_name": "tiny@src/tiny.c:1-3",
            "file_path": "src/tiny.c",
            "start_line": 1,
            "end_line": 3,
            "signature": "int tiny(void)",
            "is_static": False,
            "is_macro": False,
            "referenced_globals": [],
            "referenced_macros": [],
            "unresolved_callees": [
                {
                    "callee_name": "memcpy",
                    "direct_callsite_lines": [2],
                    "indirect_callsites": [],
                }
            ],
            "code": "1 | int tiny(void) {\n2 | return memcpy(0, 0, 0);\n3 | }",
        },
    )

    assert snapshot["unresolved_callees"] == [
        {
            "callee_name": "memcpy",
            "direct_callsite_lines": [2],
            "indirect_callsites": [],
        }
    ]


def test_same_name_snapshots_are_independent_by_index_name(tmp_path) -> None:
    store = SnapshotStore(tmp_path / "snapshots")
    left = "handle_request@src/a/server.c:10-20"
    right = "handle_request@src/b/server.c:10-20"
    store.save_snapshot(
        left,
        _snapshot(left, summary="left", file_path="src/a/server.c"),
        "int handle_request(void) { return 1; }",
    )
    store.save_snapshot(
        right,
        _snapshot(right, summary="right", file_path="src/b/server.c"),
        "int handle_request(void) { return 2; }",
    )

    assert store.load_snapshot(left)["summary"] == "left"
    assert store.load_snapshot(right)["summary"] == "right"
    assert store.list_snapshots() == [left, right]


def test_final_report_uses_same_index_name_and_cache_isolated(tmp_path) -> None:
    snapshot_dir = tmp_path / "snapshots"
    index_name = "handle_request@src/server.c:10-20"
    store = SnapshotStore(snapshot_dir)
    store.save_snapshot(index_name, _snapshot(), "int handle_request(void) { return 0; }")
    store.save_final_report(index_name, {"issues": [{"id": "first"}]})

    reloaded = SnapshotStore(snapshot_dir)
    report = reloaded.load_final_report(index_name)
    assert report is not None
    report["issues"][0]["id"] = "mutated"
    assert reloaded.load_final_report(index_name) == {"issues": [{"id": "first"}]}

    reloaded.save_final_report(index_name, {"issues": [{"id": "second"}]})
    assert reloaded.load_final_report(index_name) == {"issues": [{"id": "second"}]}


def test_missing_final_report_file_is_not_cached_as_permanent_miss(tmp_path) -> None:
    snapshot_dir = tmp_path / "snapshots"
    index_name = "handle_request@src/server.c:10-20"
    store = SnapshotStore(snapshot_dir)
    store.save_snapshot(index_name, _snapshot(), "int handle_request(void) { return 0; }")
    store.save_final_report(index_name, {"issues": [{"id": "first"}]})
    final_path = next(snapshot_dir.glob("*_final.json"))
    final_path.unlink()

    reloaded = SnapshotStore(snapshot_dir)
    assert reloaded.load_final_report(index_name) is None
    final_path.write_text(json.dumps({"issues": [{"id": "restored"}]}), encoding="utf-8")
    assert reloaded.load_final_report(index_name) == {"issues": [{"id": "restored"}]}


def test_snapshot_filename_and_sqlite_primary_key_derive_from_index_name(tmp_path) -> None:
    snapshot_dir = tmp_path / "snapshots"
    index_name = "Widget::run<int>@src/widget.cpp:10-40"
    snapshot = _snapshot(
        index_name,
        file_path="src/widget.cpp",
        start_line=10,
        end_line=40,
    )
    store = SnapshotStore(snapshot_dir)
    store.save_snapshot(index_name, snapshot, "int Widget::run<int>() { return 0; }")

    expected_file = str(store.observed_generation(index_name))
    assert (snapshot_dir / expected_file).exists()
    with sqlite3.connect(snapshot_dir / "snapshots.db") as conn:
        columns = {row[1]: row for row in conn.execute("PRAGMA table_info(snapshots)")}
        row = conn.execute("SELECT index_name, snapshot_file FROM snapshots").fetchone()
    assert columns["index_name"][5] == 1
    assert "location" not in columns
    assert "symbol_context_hash" in columns
    assert "type_context_hash" in columns
    assert row == (index_name, expected_file)


def test_snapshot_filename_keeps_readable_prefix_and_uses_index_digest() -> None:
    index_name = "Widget::run<int>@src/widget.cpp:10-40"
    encoded = SnapshotStore._encoded_index_name(index_name)

    assert encoded.startswith("Widget_run_int_src_widget.cpp_10-40-")
    assert encoded.endswith(hashlib.sha256(index_name.encode("utf-8")).hexdigest()[:16])


def test_punctuation_collisions_remain_isolated_after_process_reload(tmp_path) -> None:
    snapshot_dir = tmp_path / "snapshots"
    index_names = [
        "a::b@src/x.c:1-2",
        "a/b@src/x.c:1-2",
        "a:b@src/x.c:1-2",
    ]
    store = SnapshotStore(snapshot_dir)
    for position, index_name in enumerate(index_names):
        store.save_snapshot(
            index_name,
            _snapshot(
                index_name,
                summary=f"snapshot-{position}",
                file_path="src/x.c",
                start_line=1,
                end_line=2,
            ),
            f"int collision_{position}(void) {{ return {position}; }}",
        )
        store.save_final_report(index_name, {"owner": position})

    assert len({store._snapshot_filename(name) for name in index_names}) == 3
    assert len({store._final_report_filename(name) for name in index_names}) == 3

    reloaded = SnapshotStore(snapshot_dir)
    for position, index_name in enumerate(index_names):
        assert reloaded.load_snapshot(index_name)["summary"] == f"snapshot-{position}"
        assert reloaded.load_final_report(index_name) == {"owner": position}


def test_long_index_names_with_same_readable_prefix_remain_distinct(tmp_path) -> None:
    snapshot_dir = tmp_path / "snapshots"
    common_prefix = "Namespace::" + ("VeryLongTemplateArgument" * 10)
    left = f"{common_prefix}::left@src/long.cpp:1-2"
    right = f"{common_prefix}::right@src/long.cpp:1-2"
    store = SnapshotStore(snapshot_dir)

    store.save_snapshot(
        left,
        _snapshot(
            left,
            summary="left",
            file_path="src/long.cpp",
            start_line=1,
            end_line=2,
        ),
        "int left(void) { return 1; }",
    )
    store.save_snapshot(
        right,
        _snapshot(
            right,
            summary="right",
            file_path="src/long.cpp",
            start_line=1,
            end_line=2,
        ),
        "int right(void) { return 2; }",
    )

    left_file = store._snapshot_filename(left)
    right_file = store._snapshot_filename(right)
    assert left_file.rsplit("-", 1)[0] == right_file.rsplit("-", 1)[0]
    assert left_file != right_file

    reloaded = SnapshotStore(snapshot_dir)
    assert reloaded.load_snapshot(left)["summary"] == "left"
    assert reloaded.load_snapshot(right)["summary"] == "right"


def test_legacy_filename_collision_invalidates_ambiguous_data_without_deleting_files(
    tmp_path,
) -> None:
    snapshot_dir = tmp_path / "snapshots"
    left = "a::b@src/x.c:1-2"
    right = "a/b@src/x.c:1-2"
    store = SnapshotStore(snapshot_dir)
    for index_name, summary in ((left, "left"), (right, "right")):
        store.save_snapshot(
            index_name,
            _snapshot(
                index_name,
                summary=summary,
                file_path="src/x.c",
                start_line=1,
                end_line=2,
            ),
            f"int {summary}(void) {{ return 0; }}",
        )
        store.save_final_report(index_name, {"owner": summary})

    legacy_snapshot_file = "a_b_src_x.c_1-2.json"
    legacy_final_file = "a_b_src_x.c_1-2_final.json"
    legacy_snapshot_path = snapshot_dir / legacy_snapshot_file
    legacy_final_path = snapshot_dir / legacy_final_file
    legacy_snapshot_path.write_text(
        json.dumps(
            _snapshot(
                right,
                summary="last-writer",
                file_path="src/x.c",
                start_line=1,
                end_line=2,
            )
        ),
        encoding="utf-8",
    )
    legacy_final_path.write_text(
        json.dumps({"owner": "cannot-be-attributed"}),
        encoding="utf-8",
    )
    with sqlite3.connect(snapshot_dir / "snapshots.db") as conn:
        conn.execute(
            "UPDATE snapshots SET snapshot_file = ?, final_report_file = ? "
            "WHERE index_name IN (?, ?)",
            (legacy_snapshot_file, legacy_final_file, left, right),
        )
        conn.commit()

    reloaded = SnapshotStore(snapshot_dir)

    assert reloaded.load_snapshot(left) is None
    assert reloaded.needs_refresh(
        left,
        "int left(void) { return 0; }",
        _snapshot(
            left,
            file_path="src/x.c",
            start_line=1,
            end_line=2,
        ),
    ) == (True, "no_snapshot")
    assert reloaded.load_snapshot(right)["summary"] == "last-writer"
    assert reloaded.load_final_report(left) is None
    assert reloaded.load_final_report(right) is None
    assert legacy_snapshot_path.exists()
    assert legacy_final_path.exists()
    with sqlite3.connect(snapshot_dir / "snapshots.db") as conn:
        final_links = conn.execute(
            "SELECT final_report_file FROM snapshots ORDER BY index_name"
        ).fetchall()
    assert final_links == [(None,), (None,)]

    reloaded.delete_snapshot(left)
    assert legacy_snapshot_path.exists()
    assert legacy_final_path.exists()


def test_save_rejects_index_name_mismatch(tmp_path) -> None:
    store = SnapshotStore(tmp_path / "snapshots")
    with pytest.raises(ValueError, match="does not match"):
        store.save_snapshot(
            "other@src/server.c:10-20",
            _snapshot(),
            "int handle_request(void) { return 0; }",
        )


def _create_legacy_store(snapshot_dir, snapshot, *, include_identity=True):
    snapshot_dir.mkdir(parents=True)
    snapshot_file = "legacy.json"
    payload = dict(snapshot)
    if not include_identity:
        for key in ("index_name", "file_path", "start_line", "end_line"):
            payload.pop(key, None)
    (snapshot_dir / snapshot_file).write_text(json.dumps(payload), encoding="utf-8")
    with sqlite3.connect(snapshot_dir / "snapshots.db") as conn:
        conn.execute(
            """
            CREATE TABLE snapshots (
                func_name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                code_hash TEXT NOT NULL,
                semantic_hash TEXT NOT NULL,
                location TEXT NOT NULL,
                snapshot_file TEXT NOT NULL,
                final_report_file TEXT,
                PRIMARY KEY (func_name, file_path)
            )
            """
        )
        conn.execute(
            "INSERT INTO snapshots VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                "handle_request",
                "src/server.c",
                "old-code",
                "old-semantic",
                "src/server.c:10-20",
                snapshot_file,
                None,
            ),
        )
        conn.commit()


def test_legacy_database_migrates_to_index_name_without_deleting_old_table(tmp_path) -> None:
    snapshot_dir = tmp_path / "snapshots"
    snapshot = _snapshot(summary="legacy")
    _create_legacy_store(snapshot_dir, snapshot)

    store = SnapshotStore(snapshot_dir)

    assert store.load_snapshot(snapshot["index_name"])["summary"] == "legacy"
    with sqlite3.connect(snapshot_dir / "snapshots.db") as conn:
        tables = {
            row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        columns = {row[1] for row in conn.execute("PRAGMA table_info(snapshots)")}
    assert "snapshots" in tables
    assert any(name.startswith("snapshots_legacy") for name in tables)
    assert "index_name" in columns
    assert "symbol_context_hash" in columns
    assert "callee_summary_hash" in columns
    assert "type_context_hash" in columns
    assert "effective_rules_sha256" in columns
    assert "location" not in columns


def test_effective_rule_identity_invalidates_snapshot_without_hiding_history(tmp_path) -> None:
    snapshot_dir = tmp_path / "snapshots"
    index_name = "handle_request@src/server.c:10-20"
    code = "int handle_request(void) { return 0; }"
    snapshot = _snapshot(index_name)
    first = SnapshotStore(snapshot_dir, effective_rules_sha256="rules-a")
    first.save_snapshot(index_name, snapshot, code)

    same = SnapshotStore(snapshot_dir, effective_rules_sha256="rules-a")
    assert same.needs_refresh(index_name, code, snapshot) == (False, None)
    assert same.get_fingerprints(index_name)["effective_rules_sha256"] == "rules-a"

    changed = SnapshotStore(snapshot_dir, effective_rules_sha256="rules-b")
    # Historical data remains available for diagnostics/report migration, but
    # cannot be selected as a reusable semantic snapshot.
    assert changed.load_snapshot(index_name) == snapshot
    assert changed.needs_refresh(index_name, code, snapshot) == (
        True,
        "effective_rules_changed",
    )


def test_historical_snapshot_without_rule_identity_is_readable_but_not_reusable(
    tmp_path,
) -> None:
    snapshot_dir = tmp_path / "snapshots"
    index_name = "handle_request@src/server.c:10-20"
    code = "int handle_request(void) { return 0; }"
    snapshot = _snapshot(index_name)
    legacy = SnapshotStore(snapshot_dir)
    legacy.save_snapshot(index_name, snapshot, code)

    governed = SnapshotStore(snapshot_dir, effective_rules_sha256="rules-current")
    assert governed.load_snapshot(index_name) == snapshot
    assert governed.needs_refresh(index_name, code, snapshot) == (
        True,
        "effective_rules_identity_missing",
    )


def test_snapshot_store_from_config_binds_effective_rule_identity(tmp_path) -> None:
    config = SimpleNamespace(
        analysis=SimpleNamespace(snapshot_dir=tmp_path / "snapshots"),
        rule_catalog_provenance=SimpleNamespace(effective_sha256="rules-config"),
    )

    store = SnapshotStore.from_config(config)

    assert store.effective_rules_sha256 == "rules-config"


def test_failed_legacy_migration_preserves_old_table_and_json(tmp_path) -> None:
    snapshot_dir = tmp_path / "snapshots"
    snapshot = _snapshot(summary="legacy")
    _create_legacy_store(snapshot_dir, snapshot, include_identity=False)

    with pytest.raises(RuntimeError, match="migration failed"):
        SnapshotStore(snapshot_dir)

    assert (snapshot_dir / "legacy.json").exists()
    with sqlite3.connect(snapshot_dir / "snapshots.db") as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(snapshots)")}
    assert "location" in columns
    assert "index_name" not in columns


def test_index_name_database_backfills_split_context_hash_columns(tmp_path) -> None:
    snapshot_dir = tmp_path / "snapshots"
    snapshot_dir.mkdir(parents=True)
    snapshot = _snapshot(summary="pre-symbol-context")
    snapshot["referenced_globals"] = [
        {
            "name": "g_state",
            "storage_class": "static",
            "qualifiers": "volatile,const",
        }
    ]
    snapshot.pop("referenced_macros")
    snapshot_file = "existing.json"
    (snapshot_dir / snapshot_file).write_text(
        json.dumps(snapshot),
        encoding="utf-8",
    )
    with sqlite3.connect(snapshot_dir / "snapshots.db") as conn:
        conn.execute(
            """
            CREATE TABLE snapshots (
                index_name TEXT PRIMARY KEY,
                func_name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                start_line INTEGER NOT NULL,
                end_line INTEGER NOT NULL,
                code_hash TEXT NOT NULL,
                semantic_hash TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                snapshot_file TEXT NOT NULL,
                final_report_file TEXT
            )
            """
        )
        conn.execute(
            "INSERT INTO snapshots VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, NULL)",
            (
                snapshot["index_name"],
                snapshot["func_name"],
                snapshot["file_path"],
                snapshot["start_line"],
                snapshot["end_line"],
                "old-code",
                "old-semantic",
                snapshot_file,
            ),
        )
        conn.commit()

    store = SnapshotStore(snapshot_dir)
    loaded = store.load_snapshot(snapshot["index_name"])

    assert loaded["referenced_globals"][0]["storage_class"] == "static"
    assert loaded["referenced_globals"][0]["qualifiers"] == [
        "const",
        "volatile",
    ]
    assert loaded["referenced_macros"] == []
    with sqlite3.connect(snapshot_dir / "snapshots.db") as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(snapshots)")}
        symbol_hash, callee_hash, type_hash = conn.execute(
            "SELECT symbol_context_hash, callee_summary_hash, type_context_hash "
            "FROM snapshots WHERE index_name = ?",
            (snapshot["index_name"],),
        ).fetchone()
    assert "symbol_context_hash" in columns
    assert "callee_summary_hash" in columns
    assert "type_context_hash" in columns
    assert symbol_hash == compute_symbol_context_hash(loaded)
    assert callee_hash == compute_callee_summary_hash(loaded)
    assert type_hash == compute_type_context_hash({"referenced_types": []})


def test_validation_cache_requires_exact_v3_environment(tmp_path) -> None:
    store = SnapshotStore(tmp_path / "snapshots")
    store.save_validation_result(
        "CACHE_KEY",
        {"verdict": "verified"},
        protocol="zscope.validator-cache.v3",
        candidate_schema_version="zscope.candidate.v3",
        environment_fingerprint="ENV_A",
        max_entries=8,
    )

    assert store.load_validation_result(
        "CACHE_KEY",
        protocol="zscope.validator-cache.v3",
        candidate_schema_version="zscope.candidate.v3",
        environment_fingerprint="ENV_A",
    ) == {"verdict": "verified"}
    assert (
        store.load_validation_result(
            "CACHE_KEY",
            protocol="zscope.validator-cache.v2",
            candidate_schema_version="zscope.candidate.v2",
            environment_fingerprint="ENV_A",
        )
        is None
    )
    store.save_validation_result(
        "CACHE_KEY",
        {"verdict": "rejected"},
        protocol="zscope.validator-cache.v3",
        candidate_schema_version="zscope.candidate.v3",
        environment_fingerprint="ENV_A",
        max_entries=8,
    )
    assert store.load_validation_result(
        "CACHE_KEY",
        protocol="zscope.validator-cache.v3",
        candidate_schema_version="zscope.candidate.v3",
        environment_fingerprint="ENV_A",
    ) == {"verdict": "rejected"}
    assert (
        store.load_validation_result(
            "CACHE_KEY",
            protocol="zscope.validator-cache.v3",
            candidate_schema_version="zscope.candidate.v3",
            environment_fingerprint="ENV_B",
        )
        is None
    )
