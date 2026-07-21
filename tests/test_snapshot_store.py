import json
import sqlite3

import pytest

from zscope.common.utils import compute_code_hash, compute_semantic_fingerprint
from zscope.snapshots.store import (
    SnapshotLockManager,
    SnapshotStore,
    compute_symbol_context_hash,
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
        "summary": summary,
    }


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
    }
    assert store.needs_refresh(index_name, second_code, _snapshot()) == (False, None)


def test_symbol_context_change_requires_snapshot_refresh(tmp_path) -> None:
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

    changed_context = _snapshot()
    changed_context["referenced_macros"] = [
        {
            **snapshot["referenced_macros"][0],
            "definition": "#define LIMIT 16",
        }
    ]

    assert store.needs_refresh(index_name, code, snapshot) == (False, None)
    assert store.needs_refresh(index_name, code, changed_context) == (
        True,
        "symbol_context_changed",
    )


def test_callee_context_hash_uses_only_canonical_backend_fields() -> None:
    snapshot_context = {
        "referenced_globals": [],
        "referenced_macros": [],
        "callees": [
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
        "callees": [
            {
                "callee_index_name": "decode@src/decode.c:10-20",
                "callsite_lines": [12],
                "call_type": ["direct"],
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
        "callees": [
            {
                "callee_index_name": "decode@src/decode.c:10-20",
                "callsite_lines": [10],
                "call_type": ["direct"],
            }
        ],
    }
    snapshot = _snapshot()
    snapshot["callees"] = [
        {
            **backend_context["callees"][0],
            "callee_behavior": "Decodes the request.",
        },
        {
            "callee_index_name": "llm_only@src/other.c:1-2",
            "callsite_lines": [],
            "call_type": ["direct"],
            "callee_behavior": "Model-only observation.",
        },
    ]
    store.save_snapshot(
        index_name,
        snapshot,
        code,
        dependency_context=backend_context,
    )

    assert store.needs_refresh(index_name, code, backend_context) == (False, None)

    changed_call_type = {
        **backend_context,
        "callees": [
            {
                **backend_context["callees"][0],
                "call_type": ["direct", "indirect"],
            }
        ],
    }
    assert store.needs_refresh(index_name, code, changed_call_type) == (
        True,
        "symbol_context_changed",
    )

    changed_truncation = {
        **backend_context,
        "callees_truncation": {"truncated": True, "returned": 30, "total": 31},
    }
    assert store.needs_refresh(index_name, code, changed_truncation) == (
        True,
        "symbol_context_changed",
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

    expected_file = store._snapshot_filename(index_name)
    assert (snapshot_dir / expected_file).exists()
    with sqlite3.connect(snapshot_dir / "snapshots.db") as conn:
        columns = {row[1]: row for row in conn.execute("PRAGMA table_info(snapshots)")}
        row = conn.execute(
            "SELECT index_name, snapshot_file FROM snapshots"
        ).fetchone()
    assert columns["index_name"][5] == 1
    assert "location" not in columns
    assert "symbol_context_hash" in columns
    assert row == (index_name, expected_file)


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
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        columns = {row[1] for row in conn.execute("PRAGMA table_info(snapshots)")}
    assert "snapshots" in tables
    assert any(name.startswith("snapshots_legacy") for name in tables)
    assert "index_name" in columns
    assert "location" not in columns


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


def test_index_name_database_backfills_symbol_context_column(tmp_path) -> None:
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
        symbol_hash = conn.execute(
            "SELECT symbol_context_hash FROM snapshots WHERE index_name = ?",
            (snapshot["index_name"],),
        ).fetchone()[0]
    assert "symbol_context_hash" in columns
    assert symbol_hash == compute_symbol_context_hash(loaded)
