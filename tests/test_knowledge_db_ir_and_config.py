from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sqlite3

import pytest

from zscope.config.user_config_store import UserConfigStore
from zscope.retrieval.knowledge_db import KnowledgeDB
from zscope.web import server as web_server
from zscope.web.services import ReportFeedbackService


def _publish_empty_derived_index(
    db: KnowledgeDB,
    index_name: str,
    version: str = "1",
) -> None:
    db.begin_derived_index_rebuild(index_name, version)
    db.prepare_derived_index_staging(index_name)
    db.finalize_derived_index_rebuild(index_name, version, {"rows": 0})


def test_knowledge_db_missing_and_corrupt_derived_state_are_dirty(tmp_path: Path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        missing = db.get_derived_index_state("function_symbol_context")
        assert missing == {
            "applied_version": "",
            "target_version": "",
            "status": "dirty",
            "dirty_reason": "missing_state",
            "last_error": "",
            "last_stats": {},
            "updated_at": 0.0,
        }
        assert db.derived_index_needs_rebuild("function_symbol_refs", "2") is True

        db.set_metadata("derived_index_state:function_type_refs", "{not-json")
        corrupt = db.get_derived_index_state("function_type_refs")
        assert corrupt["status"] == "dirty"
        assert corrupt["dirty_reason"] == "invalid_state"

        db.set_metadata(
            "derived_index_state:function_type_refs",
            '{"status":"current","applied_version":"2"}',
        )
        malformed = db.get_derived_index_state("function_type_refs")
        assert malformed["status"] == "dirty"
        assert malformed["dirty_reason"] == "invalid_state"
        with pytest.raises(ValueError, match="unsupported derived index"):
            db.get_derived_index_state("unknown")
    finally:
        db.close()


def test_knowledge_db_atomically_finalizes_staged_symbol_context(tmp_path: Path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        db.insert_function("entry", "src/entry.c", 10, 20)
        db.insert_global_variable("g_old", "int", "src/old.c", 1)
        db.insert_global_variable("g_new", "int", "src/new.c", 2)
        db.insert_macro_definitions_batch(
            [("NEW_MACRO", "include/new.h", 3, "#define NEW_MACRO 1\n", 0)]
        )
        db.commit()
        function_id = db.get_function("entry", "src/entry.c")["id"]
        macro_id = db.get_macro_definitions("NEW_MACRO")[0]["id"]
        db.insert_function_symbol_refs_batch(
            [("entry", "src/entry.c", "g_old", "global", "src/old.c", 12, "read")]
        )
        db.commit()

        started = db.begin_derived_index_rebuild("function_symbol_context", "7")
        assert started["status"] == "in_progress"
        db.prepare_derived_index_staging("function_symbol_context")
        db.stage_function_symbol_refs_batch(
            [("entry", "src/entry.c", "g_new", "global", "src/new.c", 13, "read")]
        )
        db.stage_function_symbol_refs_batch(
            [("entry", "src/entry.c", "g_new", "global", "src/new.c", 13, "write")]
        )
        db.stage_function_macro_refs_batch(
            [(function_id, macro_id, 14), (function_id, macro_id, 14)]
        )

        # Staged rows are invisible until the atomic publish.
        before = db.get_function_symbol_context("entry", "src/entry.c")
        assert [item["name"] for item in before["referenced_globals"]] == ["g_old"]
        assert before["referenced_macros"] == []

        state = db.finalize_derived_index_rebuild(
            "function_symbol_context",
            "7",
            {"symbol_rows": 1, "macro_rows": 1},
        )
        after = db.get_function_symbol_context("entry", "src/entry.c")
        assert [item["name"] for item in after["referenced_globals"]] == ["g_new"]
        assert after["referenced_globals"][0]["access"] == "read_write"
        assert after["referenced_macros"][0]["macro_index_name"].startswith("NEW_MACRO@")
        assert len(after["referenced_macros"]) == 1
        assert state["status"] == "current"
        assert state["applied_version"] == "7"
        assert state["last_stats"] == {"symbol_rows": 1, "macro_rows": 1}
        assert db.derived_index_needs_rebuild("function_symbol_context", "7") is False
    finally:
        db.close()


def test_knowledge_db_atomically_finalizes_staged_function_type_refs(tmp_path: Path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        db.insert_function("entry", "src/entry.c", 10, 20)
        old_type_id = db.insert_type("OldType", "struct", "include/old.h", 1, 3)
        new_type_id = db.insert_type("NewType", "struct", "include/new.h", 4, 8)
        db.commit()
        function_id = db.get_function("entry", "src/entry.c")["id"]
        old_type = next(item for item in db.get_all_type_definitions() if item["id"] == old_type_id)
        new_type = next(item for item in db.get_all_type_definitions() if item["id"] == new_type_id)
        db.replace_function_type_refs(
            [
                (
                    function_id,
                    old_type_id,
                    db.type_index_name(old_type),
                    "OldType",
                    "src/entry.c",
                    11,
                    "local",
                    "",
                )
            ]
        )
        db.commit()

        db.begin_derived_index_rebuild("function_type_refs", "4")
        db.prepare_derived_index_staging("function_type_refs")
        db.stage_function_type_refs_batch(
            [
                (
                    function_id,
                    new_type_id,
                    db.type_index_name(new_type),
                    "NewType",
                    "src/entry.c",
                    12,
                    "parameter",
                    "",
                )
            ]
        )
        db.stage_function_type_refs_batch(
            [
                (
                    function_id,
                    new_type_id,
                    db.type_index_name(new_type),
                    "NewType",
                    "src/entry.c",
                    12,
                    "parameter",
                    "",
                )
            ]
        )
        before = db.get_function_type_context("entry", "src/entry.c", 10)
        assert [item["name"] for item in before["referenced_types"]] == ["OldType"]

        db.finalize_derived_index_rebuild(
            "function_type_refs",
            "4",
            {"type_rows": 1},
        )
        after = db.get_function_type_context("entry", "src/entry.c", 10)
        assert [item["name"] for item in after["referenced_types"]] == ["NewType"]
        state = db.get_derived_index_state("function_type_refs")
        assert state["status"] == "current"
        assert state["last_stats"] == {"type_rows": 1}
    finally:
        db.close()


def test_knowledge_db_finalize_rollback_preserves_old_symbol_context(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        db.insert_function("entry", "src/entry.c", 10, 20)
        db.insert_global_variable("g_old", "int", "src/old.c", 1)
        db.insert_global_variable("g_new", "int", "src/new.c", 2)
        db.insert_function_symbol_refs_batch(
            [("entry", "src/entry.c", "g_old", "global", "src/old.c", 12, "read")]
        )
        db.commit()
        db.begin_derived_index_rebuild("function_symbol_context", "8")
        db.prepare_derived_index_staging("function_symbol_context")
        db.stage_function_symbol_refs_batch(
            [("entry", "src/entry.c", "g_new", "global", "src/new.c", 13, "write")]
        )

        def fail_state_write(_index_name, _state):
            raise RuntimeError("injected finalize failure")

        monkeypatch.setattr(db, "_write_derived_index_state_uncommitted", fail_state_write)
        with pytest.raises(RuntimeError, match="injected finalize failure"):
            db.finalize_derived_index_rebuild("function_symbol_context", "8")

        context = db.get_function_symbol_context("entry", "src/entry.c")
        assert [item["name"] for item in context["referenced_globals"]] == ["g_old"]
        state = db.get_derived_index_state("function_symbol_context")
        assert state["status"] == "in_progress"
        assert state["target_version"] == "8"
    finally:
        db.close()


def test_knowledge_db_finalize_interrupt_rolls_back_before_close(
    tmp_path: Path,
    monkeypatch,
) -> None:
    db_path = tmp_path / "knowledge.db"
    db = KnowledgeDB(str(db_path))
    db.insert_function("entry", "src/entry.c", 10, 20)
    db.insert_global_variable("g_old", "int", "src/old.c", 1)
    db.insert_global_variable("g_new", "int", "src/new.c", 2)
    db.insert_function_symbol_refs_batch(
        [("entry", "src/entry.c", "g_old", "global", "src/old.c", 12, "read")]
    )
    db.commit()
    db.begin_derived_index_rebuild("function_symbol_context", "8")
    db.prepare_derived_index_staging("function_symbol_context")
    db.stage_function_symbol_refs_batch(
        [("entry", "src/entry.c", "g_new", "global", "src/new.c", 13, "write")]
    )

    def interrupt_state_write(_index_name, _state):
        raise KeyboardInterrupt

    monkeypatch.setattr(db, "_write_derived_index_state_uncommitted", interrupt_state_write)
    with pytest.raises(KeyboardInterrupt):
        db.finalize_derived_index_rebuild("function_symbol_context", "8")
    db.close()

    reopened = KnowledgeDB(str(db_path))
    try:
        context = reopened.get_function_symbol_context("entry", "src/entry.c")
        assert [item["name"] for item in context["referenced_globals"]] == ["g_old"]
        state = reopened.get_derived_index_state("function_symbol_context")
        assert state["status"] == "in_progress"
        assert state["target_version"] == "8"
    finally:
        reopened.close()


def test_knowledge_db_in_progress_state_survives_reopen_without_staging(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "knowledge.db"
    db = KnowledgeDB(str(db_path))
    db.begin_derived_index_rebuild("function_type_refs", "5")
    db.prepare_derived_index_staging("function_type_refs")
    db.close()

    reopened = KnowledgeDB(str(db_path))
    try:
        state = reopened.get_derived_index_state("function_type_refs")
        assert state["status"] == "in_progress"
        assert state["target_version"] == "5"
        assert reopened.derived_index_needs_rebuild("function_type_refs", "5") is True
        assert (
            reopened._conn.execute(
                "SELECT COUNT(*) AS count FROM sqlite_temp_master "
                "WHERE name LIKE 'zscope_stage_%'"
            ).fetchone()["count"]
            == 0
        )
        assert (
            reopened._conn.execute(
                "SELECT COUNT(*) AS count FROM sqlite_master " "WHERE name LIKE 'zscope_stage_%'"
            ).fetchone()["count"]
            == 0
        )
        failed = reopened.fail_derived_index_rebuild(
            "function_type_refs",
            "5",
            RuntimeError("interrupted"),
            {"files": 12},
        )
        assert failed["status"] == "failed"
        assert failed["last_error"] == "interrupted"
        assert failed["last_stats"] == {"files": 12}
    finally:
        reopened.close()


def test_knowledge_db_tu_hash_invalidation_only_dirties_changed_base_facts(
    tmp_path: Path,
) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        tu_id, changed = db.register_tu_hash("src/entry.c", "hash-1")
        assert changed is True
        assert db.get_derived_index_state("function_symbol_context")["status"] == "dirty"
        assert db.get_derived_index_state("function_type_refs")["status"] == "dirty"
        db.mark_tu_indexed(tu_id)

        _publish_empty_derived_index(db, "function_symbol_context", "2")
        _publish_empty_derived_index(db, "function_type_refs", "3")
        symbol_state_before = db.get_derived_index_state("function_symbol_context")
        type_state_before = db.get_derived_index_state("function_type_refs")
        same_id, changed = db.register_tu_hash("src/entry.c", "hash-1")
        assert same_id == tu_id
        assert changed is False
        assert db.get_derived_index_state("function_symbol_context") == symbol_state_before
        assert db.get_derived_index_state("function_type_refs") == type_state_before

        same_id, changed = db.register_tu_hash("src/entry.c", "hash-2")
        assert same_id == tu_id
        assert changed is True
        assert db.get_derived_index_state("function_symbol_context")["dirty_reason"] == (
            "translation_unit_hash_changed"
        )
        assert db.get_derived_index_state("function_type_refs")["dirty_reason"] == (
            "translation_unit_hash_changed"
        )
    finally:
        db.close()


def test_knowledge_db_macro_clear_and_tu_purge_dirty_derived_state(tmp_path: Path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        tu_id = db.register_tu("src/entry.c", 1.0)
        db.mark_tu_indexed(tu_id)
        _publish_empty_derived_index(db, "function_symbol_context", "2")
        _publish_empty_derived_index(db, "function_type_refs", "3")

        db.clear_macro_definitions()
        assert db.get_derived_index_state("function_symbol_context")["dirty_reason"] == (
            "macro_definitions_cleared"
        )
        assert db.get_derived_index_state("function_type_refs")["status"] == "current"

        _publish_empty_derived_index(db, "function_symbol_context", "2")
        db.purge_tu_data(tu_id)
        assert db.get_derived_index_state("function_symbol_context")["dirty_reason"] == (
            "translation_unit_purged"
        )
        assert db.get_derived_index_state("function_type_refs")["dirty_reason"] == (
            "translation_unit_purged"
        )
    finally:
        db.close()


def test_knowledge_db_migrates_legacy_macro_identity_and_range(tmp_path: Path) -> None:
    db_path = tmp_path / "legacy.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "CREATE TABLE macro_definitions ("
            "id INTEGER PRIMARY KEY, name TEXT NOT NULL, file_path TEXT NOT NULL, "
            "line INTEGER NOT NULL, definition TEXT, is_function_like INTEGER DEFAULT 0, "
            "UNIQUE(name, file_path, line))"
        )
        conn.execute(
            "INSERT INTO macro_definitions "
            "(name, file_path, line, definition, is_function_like) VALUES (?, ?, ?, ?, ?)",
            (
                "WRAP",
                "include/wrap.h",
                10,
                "#define WRAP(x) \\\n    helper(x)\n",
                1,
            ),
        )
        conn.commit()

    db = KnowledgeDB(str(db_path))
    try:
        macro = db.get_macro_definitions("WRAP")[0]
        assert macro["macro_index_name"] == "WRAP@include/wrap.h:10-11"
        assert macro["start_line"] == 10
        assert macro["end_line"] == 11
        assert db.get_metadata("schema_version") == "14"
    finally:
        db.close()


@pytest.mark.parametrize("legacy_schema_version", ["10", "11", "13"])
def test_knowledge_db_migrates_complete_taint_identity_and_forces_reindex(
    tmp_path: Path,
    legacy_schema_version: str,
) -> None:
    db_path = tmp_path / "legacy-taint.db"
    with sqlite3.connect(db_path) as conn:
        conn.executescript(
            """
            CREATE TABLE metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            );
            CREATE TABLE taint_signatures (
                id          INTEGER PRIMARY KEY,
                source_func TEXT,
                sink_func   TEXT,
                bug_type    TEXT NOT NULL,
                file_path   TEXT,
                line        INTEGER DEFAULT 0,
                tool        TEXT DEFAULT 'saber',
                svf_group   TEXT DEFAULT 'default',
                UNIQUE(bug_type, file_path, line, svf_group)
            );
            INSERT INTO taint_signatures
                (source_func, sink_func, bug_type, file_path, line, tool, svf_group)
            VALUES
                ('unreachable', 'sink_a', 'Double Free', 'src/shared.c', 42, 'saber', 'g1');
            INSERT INTO metadata (key, value) VALUES
                ('svf_source_hash', 'legacy-source'),
                ('svf_artifact_hash', 'legacy-artifact'),
                ('svf_tool_status:saber:g1', '{"status": "success"}'),
                ('svf_db_import:saber:g1', '{"generation": 7}'),
                ('svf_db_generation', '7');
            """
        )
        conn.execute(
            "INSERT INTO metadata (key, value) VALUES (?, ?)",
            ("schema_version", legacy_schema_version),
        )

    db = KnowledgeDB(str(db_path))
    try:
        assert db.get_metadata("schema_version") == "14"
        assert db.get_svf_hash() == ""
        assert db.get_metadata("svf_artifact_hash") == ""
        assert db.get_metadata("svf_tool_status:saber:g1") == ""
        assert db.get_metadata("svf_db_import:saber:g1") == ""
        assert db.get_svf_db_generation() == 7
        assert db.get_metadata(KnowledgeDB.TAINT_REINDEX_REQUIRED_KEY) == "1"

        db.insert_taint_signature(
            "entry",
            "sink_b",
            "Double Free",
            file_path="src/shared.c",
            line=42,
            tool="saber",
            svf_group="g1",
        )
        db.insert_taint_signature(
            "entry",
            "sink_b",
            "Double Free",
            file_path="src/shared.c",
            line=42,
            tool="saber",
            svf_group="g1",
        )
        db.commit()

        rows = db.get_taint_bugs("Double Free")
        assert {
            (row["source_func"], row["sink_func"])
            for row in rows
        } == {
            ("entry", "sink_b"),
            ("unreachable", "sink_a"),
        }
        assert db.stats()["taint_signatures"] == 2

        unique_identities = []
        for index_row in db._conn.execute(
            "PRAGMA index_list(taint_signatures)"
        ).fetchall():
            if not index_row["unique"]:
                continue
            index_name = str(index_row["name"]).replace('"', '""')
            unique_identities.append(
                tuple(
                    row["name"]
                    for row in db._conn.execute(
                        f'PRAGMA index_info("{index_name}")'
                    ).fetchall()
                )
            )
        assert KnowledgeDB.TAINT_SIGNATURE_IDENTITY in unique_identities

        db.set_svf_hash("fresh-source")
        assert db.get_svf_hash() == "fresh-source"
        assert db.get_metadata(KnowledgeDB.TAINT_REINDEX_REQUIRED_KEY) == ""
        assert db.get_metadata(KnowledgeDB.TAINT_REINDEX_REASON_KEY) == ""
    finally:
        db.close()


def test_knowledge_db_ir_tables_round_trip(tmp_path: Path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    source_stmt = db.upsert_ir_statement(
        "src/demo.c",
        10,
        "demo",
        kind="candidate_source",
        normalized_code="n * sizeof(*p)",
    )
    sink_stmt = db.upsert_ir_statement(
        "src/demo.c",
        11,
        "demo",
        kind="candidate_sink",
        normalized_code="malloc(n * sizeof(*p))",
    )
    db.insert_ir_resource_event(
        "CAND_1",
        "n",
        "integer_overflow",
        "malloc",
        "src/demo.c",
        11,
        "demo",
        confidence=0.9,
    )
    path_id = db.upsert_ir_path_slice(
        "CAND_1",
        "demo",
        source_stmt=source_stmt,
        sink_stmt=sink_stmt,
        path_summary='{"complete": true}',
    )
    db.commit()

    assert path_id > 0
    assert db.get_ir_path_slice("CAND_1")["function"] == "demo"
    assert db.stats()["ir_resource_events"] == 1
    db.close()


def test_header_functions_match_absolute_db_paths_by_source_relative_path(tmp_path: Path) -> None:
    source_root = tmp_path / "project"
    header = source_root / "include" / "task_dispatcher.h"
    header.parent.mkdir(parents=True)
    header.write_text("int td_init(void);\n", encoding="utf-8")

    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    db.insert_function(
        "td_init",
        str(header),
        1,
        1,
        signature="int (void) td_init",
        is_declaration=True,
    )
    db.commit()

    rows = db.get_header_functions(["include/task_dispatcher.h"], source_root=source_root)

    assert rows == [
        {
            "name": "td_init",
            "filename": "include/task_dispatcher.h",
            "lineNumber": 1,
        }
    ]
    db.close()


def test_knowledge_db_uses_thread_local_connections_for_parallel_access(tmp_path: Path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        db.insert_function("entry", "src/demo.c", 1, 10)
        db.insert_call_edge("entry", "src/demo.c", "helper", "src/demo.c", 5)
        db.commit()

        def worker(worker_id: int) -> int:
            conn_id = id(db._conn)
            for _ in range(5):
                assert db.get_function("entry")["name"] == "entry"
                assert db.get_callees("entry")[0]["name"] == "helper"
            db.upsert_function_contract(f"worker_{worker_id}", locks='["m"]')
            db.commit()
            return conn_id

        with ThreadPoolExecutor(max_workers=6) as executor:
            connection_ids = set(executor.map(worker, range(12)))

        assert len(connection_ids) > 1
        assert db.stats()["function_contracts"] == 12
    finally:
        db.close()


def test_knowledge_db_function_index_preserves_is_static(tmp_path: Path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        db.insert_function(
            "hidden",
            "src/demo.c",
            1,
            3,
            signature="static int hidden(void)",
            is_static=True,
        )
        db.insert_function(
            "visible",
            "src/demo.c",
            5,
            7,
            signature="int visible(void)",
            is_static=False,
        )
        db.commit()

        index = db.get_all_functions()
        records = db.get_function_records()

        assert index["hidden"]["is_static"] is True
        assert index["visible"]["is_static"] is False
        assert {row["name"]: row["is_static"] for row in records} == {
            "hidden": 1,
            "visible": 0,
        }
    finally:
        db.close()


def test_knowledge_db_function_type_context_round_trip_and_optional_unresolved(
    tmp_path: Path,
) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        db.insert_function(
            "register_plugin",
            "src/plugin.c",
            10,
            20,
            signature="int register_plugin(PluginRegistry *registry)",
        )
        type_id = db.insert_type(
            "PluginRegistry",
            "struct",
            "include/types.h",
            90,
            98,
            full_definition="typedef struct { void *plugins; } PluginRegistry;",
        )
        db.commit()
        function_id = next(
            row["id"] for row in db.get_function_records()
            if row["name"] == "register_plugin"
        )
        type_info = next(
            row for row in db.get_all_type_definitions()
            if row["name"] == "PluginRegistry"
        )
        type_index_name = db.type_index_name(type_info)
        db.replace_function_type_refs(
            [
                (
                    function_id,
                    type_id,
                    type_index_name,
                    "PluginRegistry",
                    "src/plugin.c",
                    10,
                    "parameter",
                    "",
                ),
                (
                    function_id,
                    type_id,
                    type_index_name,
                    "PluginRegistry",
                    "src/plugin.c",
                    15,
                    "member_access",
                    "",
                ),
                (
                    function_id,
                    None,
                    "",
                    "MissingType",
                    "src/plugin.c",
                    16,
                    "cast",
                    "type_definition_not_found",
                ),
            ]
        )
        db.commit()

        context = db.get_function_type_context(
            "register_plugin",
            "src/plugin.c",
            10,
        )

        assert context["referenced_types"] == [
            {
                "type_index_name": "PluginRegistry@include/types.h:90-98",
                "name": "PluginRegistry",
                "kind": "struct",
                "file_path": "include/types.h",
                "start_line": 90,
                "end_line": 98,
                "full_definition": "typedef struct { void *plugins; } PluginRegistry;",
                "reference_kinds": ["parameter", "member_access"],
                "reference_lines": [10, 15],
            }
        ]
        assert context["unresolved_referenced_types"] == [
            {
                "name": "MissingType",
                "reference_kinds": ["cast"],
                "reference_lines": [16],
                "reason": "type_definition_not_found",
            }
        ]
        assert db.stats()["function_type_refs"] == 3
    finally:
        db.close()


def test_knowledge_db_batches_transitive_include_closures(tmp_path: Path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        db._conn.executemany(
            "INSERT INTO include_edges (source_file, included_file, line, is_system) "
            "VALUES (?, ?, ?, ?)",
            [
                ("src/a.c", "include/shared.h", 1, 0),
                ("src/b.c", "include/b.h", 1, 0),
                ("include/b.h", "include/shared.h", 2, 0),
                ("src/a.c", "stdint.h", 2, 1),
            ],
        )
        db.commit()

        closures = db.get_transitive_include_closures(["src/a.c", "src/b.c", "src/solo.c"])
        assert closures == {
            "src/a.c": ["include/shared.h", "src/a.c"],
            "src/b.c": ["include/b.h", "include/shared.h", "src/b.c"],
            "src/solo.c": ["src/solo.c"],
        }
        assert db.get_transitive_include_closure("src/b.c") == closures["src/b.c"]
    finally:
        db.close()


def test_knowledge_db_purge_tu_removes_owned_and_incoming_type_refs(
    tmp_path: Path,
) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        source_tu = db.register_tu("src/plugin.c", 1.0)
        header_tu = db.register_tu("include/types.h", 1.0)
        db.insert_function("register_plugin", "src/plugin.c", 10, 20, tu_id=source_tu)
        type_id = db.insert_type(
            "PluginRegistry",
            "struct",
            "include/types.h",
            90,
            98,
            tu_id=header_tu,
        )
        db.commit()
        function_id = db.get_function_records()[0]["id"]
        type_info = db.get_all_type_definitions()[0]
        db.replace_function_type_refs(
            [
                (
                    function_id,
                    type_id,
                    db.type_index_name(type_info),
                    "PluginRegistry",
                    "src/plugin.c",
                    10,
                    "parameter",
                    "",
                )
            ]
        )
        db.commit()

        impact = db.get_tu_delete_impact(header_tu)
        assert "src/plugin.c" in impact["related_files"]

        db.purge_tu_data(header_tu, purge_incoming_refs=True)
        assert db.stats()["function_type_refs"] == 0
    finally:
        db.close()


def test_knowledge_db_caches_direct_callee_queries_and_invalidates_on_write(tmp_path: Path) -> None:
    db_path = tmp_path / "knowledge.db"
    db = KnowledgeDB(str(db_path))
    try:
        db.insert_call_edge("entry", "src/demo.c", "helper", "src/helper.c", 5)
        db.commit()

        first = db.get_callees("entry", limit=30)
        second = db.get_callees("entry", limit=30)
        second[0]["name"] = "mutated"

        stats = db.callgraph_cache_stats()
        assert stats["callee_misses"] == 1
        assert stats["callee_hits"] == 1
        assert db.get_callees("entry", limit=30)[0]["name"] == "helper"

        db.get_callees("entry", limit=1)
        assert db.callgraph_cache_stats()["callee_misses"] == 2

        db.insert_call_edge("entry", "src/demo.c", "later", "src/later.c", 6)
        db.commit()

        assert {row["name"] for row in db.get_callees("entry", limit=30)} == {"helper", "later"}
    finally:
        db.close()

    db2 = KnowledgeDB(str(db_path))
    try:
        assert db2.callgraph_cache_stats()["callee_hits"] == 0
        assert {row["name"] for row in db2.get_callees("entry", limit=30)} == {"helper", "later"}
    finally:
        db2.close()


def test_knowledge_db_caches_indirect_callee_queries_and_invalidates_on_write(tmp_path: Path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        db.insert_indirect_call("caller", "target", confidence=0.8, svf_group="entry_cluster_1")
        db.commit()

        first = db.get_indirect_callees("caller", limit=30)
        second = db.get_indirect_callees("caller", limit=30)
        first[0]["name"] = "mutated"

        stats = db.callgraph_cache_stats()
        assert stats["indirect_callee_misses"] == 1
        assert stats["indirect_callee_hits"] == 1
        assert second[0]["name"] == "target"
        assert db.get_indirect_callees("caller", limit=1)[0]["name"] == "target"
        assert db.callgraph_cache_stats()["indirect_callee_misses"] == 2

        db.insert_indirect_call("caller", "later", confidence=0.7, svf_group="entry_cluster_2")
        db.commit()

        assert {row["name"] for row in db.get_indirect_callees("caller", limit=30)} == {"target", "later"}
    finally:
        db.close()


def test_knowledge_db_preserves_llvm_intrinsic_indirect_call_facts(tmp_path: Path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        db.insert_indirect_call(
            "entry",
            "llvm.memset.p0.i64",
            call_file="src/entry.c",
            call_line=0,
            source="svf-ander",
        )
        db.commit()

        assert db.get_indirect_callees("entry") == [
            {
                "name": "llvm.memset.p0.i64",
                "source": "svf-ander",
                "confidence": 1.0,
                "svf_group": "default",
                "svf_groups": ["default"],
                "call_file": "src/entry.c",
                "call_line": 0,
            }
        ]
    finally:
        db.close()


def test_knowledge_db_get_macro_definitions_batch(
    tmp_path: Path,
) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        db.insert_global_variable(
            "g_lock",
            "pthread_mutex_t",
            "src/demo.c",
            7,
            storage_class="static",
            initializer="PTHREAD_MUTEX_INITIALIZER",
        )
        db.insert_macro_definitions_batch(
            [
                (
                    "UNLOCK",
                    "include/common.h",
                    34,
                    "#define UNLOCK(mutex) unlock_impl(mutex)\n",
                    1,
                )
            ]
        )
        db.commit()

        result = db.get_macro_definitions_batch(
            ["UNLOCK", "g_lock", "UNLOCK", "missing"]
        )

        assert result == [
            {
                "id": 1,
                "macro_index_name": "UNLOCK@include/common.h:34-34",
                "name": "UNLOCK",
                "file_path": "include/common.h",
                "line": 34,
                "start_line": 34,
                "end_line": 34,
                "definition": "#define UNLOCK(mutex) unlock_impl(mutex)\n",
                "is_function_like": 1,
            }
        ]
        assert db.get_macro_definitions_batch([]) == []
    finally:
        db.close()


def test_get_callers_filters_duplicate_callee_names_by_file(tmp_path: Path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        db.insert_call_edge("ApiReal", "src/api.c", "B", "src/real_b.c", 5)
        db.insert_call_edge("A", "src/a.c", "B", "src/decoy_b.c", 7)
        db.commit()

        callers = db.get_callers("B", callee_file="src/real_b.c")

        assert callers == [
            {
                "name": "ApiReal",
                "filename": "src/api.c",
                "callee_filename": "src/real_b.c",
                "lineNumber": 5,
            }
        ]
    finally:
        db.close()


def test_get_all_callees_filters_duplicate_caller_names_by_file(tmp_path: Path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        db.insert_call_edge("shared", "src/left.c", "left_target", "src/left_target.c", 5)
        db.insert_call_edge("shared", "src/right.c", "right_target", "src/right_target.c", 7)
        db.commit()

        rows = db.get_all_callees("shared", caller_file="src/right.c")

        assert [row["name"] for row in rows] == ["right_target"]
    finally:
        db.close()


def test_knowledge_db_macro_definitions_round_trip_and_clear(tmp_path: Path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        db.insert_macro_definitions_batch(
            [
                ("Z_ALLOC", "include/z_b.h", 9, "#define Z_ALLOC 1\n", 0),
                ("Z_ALLOC", "include/z_a.h", 3, "#define Z_ALLOC(sz) alloc(sz)\n", 1),
                ("OTHER", "include/other.h", 1, "#define OTHER 0\n", 0),
            ]
        )
        db.commit()

        rows = db.get_macro_definitions("Z_ALLOC")

        assert [row["file_path"] for row in rows] == ["include/z_a.h", "include/z_b.h"]
        assert rows[0]["is_function_like"] == 1
        assert rows[0]["definition"] == "#define Z_ALLOC(sz) alloc(sz)\n"

        db.clear_macro_definitions()

        assert db.get_macro_definitions("Z_ALLOC") == []
        assert db.stats()["macro_definitions"] == 0
    finally:
        db.close()


def test_knowledge_db_function_symbol_context_round_trip(tmp_path: Path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        db.insert_global_variable(
            "g_state",
            "volatile int",
            "src/state.c",
            4,
            storage_class="static",
            qualifiers="volatile",
            initializer="0",
            definition_kind="definition",
        )
        db.insert_macro_definitions_batch(
            [("STATE_SET", "include/state.h", 8, "#define STATE_SET(v) ((v) != 0)\n", 1)]
        )
        db.insert_function("update", "src/update.c", 18, 26)
        db.insert_function_symbol_refs_batch(
            [
                ("update", "src/update.c", "g_state", "global", "src/state.c", 20, "read"),
                ("update", "src/update.c", "g_state", "global", "src/state.c", 24, "write"),
            ]
        )
        function_id = db.get_function("update", "src/update.c")["id"]
        macro_id = db.get_macro_definitions("STATE_SET")[0]["id"]
        db.insert_function_macro_refs_batch([(function_id, macro_id, 23)])
        db.commit()

        context = db.get_function_symbol_context("update", "src/update.c")

        assert context["referenced_globals"] == [
            {
                "name": "g_state",
                "type": "volatile int",
                "file_path": "src/state.c",
                "line": 4,
                "is_extern": False,
                "storage_class": "static",
                "qualifiers": "volatile",
                "initializer": "0",
                "definition_kind": "definition",
                "access": "read_write",
                "reference_lines": [20, 24],
            }
        ]
        assert context["referenced_macros"] == [
            {
                "macro_index_name": "STATE_SET@include/state.h:8-8",
                "is_function_like": True,
                "reference_lines": [23],
            }
        ]
        assert db.stats()["function_symbol_refs"] == 2
        assert db.stats()["function_macro_refs"] == 1
    finally:
        db.close()


def test_call_edges_persist_and_query_callee_kind(tmp_path: Path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        db.insert_call_edge(
            "entry",
            "src/demo.c",
            "callback",
            "src/types.h",
            12,
            "indirect",
            "function_pointer_field",
            "void (*)(void*)",
        )
        # Existing callers that still provide six-tuples retain a safe unknown kind.
        db.insert_call_edges_batch(
            [("entry", "src/demo.c", "legacy", "", 13, "direct")]
        )
        db.commit()

        rows = db.get_all_callees("entry", caller_file="src/demo.c")

        assert rows == [
            {
                "name": "callback",
                "filename": "src/types.h",
                "lineNumber": 12,
                "call_type": "indirect",
                "callee_kind": "function_pointer_field",
                "callee_signature": "void (*)(void*)",
            },
            {
                "name": "legacy",
                "filename": "",
                "lineNumber": 13,
                "call_type": "direct",
                "callee_kind": "unknown",
                "callee_signature": "",
            },
        ]
    finally:
        db.close()


def test_indirect_call_records_preserve_distinct_callsites(tmp_path: Path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        for callsite_id, line, symbol in (
            ("svf:s0", 30, "Ops.callback_a"),
            ("svf:s1", 40, "Ops.callback_b"),
        ):
            db.insert_indirect_call(
                "entry",
                "target",
                call_file="src/entry.c",
                call_line=line,
                callsite_id=callsite_id,
                pointer_symbol=symbol,
                pointer_kind="field",
                pointer_type="Callback",
                pointer_signature="void (*)(void*)",
                callsite_expression=symbol.rsplit(".", 1)[-1],
                guard="enabled != 0",
            )
        db.commit()

        assert db.get_indirect_call_records("entry", caller_file="src/entry.c") == [
            {
                "name": "target",
                "call_file": "src/entry.c",
                "call_line": 30,
                "callsite_id": "svf:s0",
                "pointer_symbol": "Ops.callback_a",
                "pointer_kind": "field",
                "pointer_type": "Callback",
                "pointer_signature": "void (*)(void*)",
                "callsite_expression": "callback_a",
                "guard": "enabled != 0",
                "source": "svf-ander",
                "confidence": 1.0,
                "svf_group": "default",
                "call_type": "indirect",
            },
            {
                "name": "target",
                "call_file": "src/entry.c",
                "call_line": 40,
                "callsite_id": "svf:s1",
                "pointer_symbol": "Ops.callback_b",
                "pointer_kind": "field",
                "pointer_type": "Callback",
                "pointer_signature": "void (*)(void*)",
                "callsite_expression": "callback_b",
                "guard": "enabled != 0",
                "source": "svf-ander",
                "confidence": 1.0,
                "svf_group": "default",
                "call_type": "indirect",
            },
        ]
    finally:
        db.close()


def test_indirect_call_schema_migration_preserves_legacy_rows(tmp_path: Path) -> None:
    db_path = tmp_path / "legacy-indirect.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "CREATE TABLE indirect_calls ("
            "id INTEGER PRIMARY KEY, caller_name TEXT NOT NULL, callee_name TEXT NOT NULL, "
            "call_file TEXT DEFAULT '', call_line INTEGER DEFAULT 0, "
            "source TEXT DEFAULT 'svf-ander', confidence REAL DEFAULT 1.0, "
            "svf_group TEXT DEFAULT 'default', "
            "UNIQUE(caller_name, callee_name, source, svf_group))"
        )
        conn.execute(
            "INSERT INTO indirect_calls "
            "(caller_name, callee_name, call_file, call_line, source, confidence, svf_group) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("legacy_caller", "legacy_target", "src/legacy.c", 9, "svf-ander", 0.8, "default"),
        )
        conn.commit()

    db = KnowledgeDB(str(db_path))
    try:
        columns = {row["name"] for row in db._conn.execute("PRAGMA table_info(indirect_calls)")}
        assert {"callsite_id", "pointer_symbol", "call_guard"}.issubset(columns)
        assert db.get_indirect_call_records("legacy_caller") == [
            {
                "name": "legacy_target",
                "call_file": "src/legacy.c",
                "call_line": 9,
                "callsite_id": "",
                "pointer_symbol": "",
                "pointer_kind": "unknown",
                "pointer_type": "",
                "pointer_signature": "",
                "callsite_expression": "",
                "guard": "",
                "source": "svf-ander",
                "confidence": 0.8,
                "svf_group": "default",
                "call_type": "indirect",
            }
        ]
    finally:
        db.close()


def test_delete_tu_removes_file_owned_facts_and_related_call_edges(tmp_path: Path) -> None:
    project = tmp_path / "project"
    deleted = project / "include" / "deleted.h"
    deleted.parent.mkdir(parents=True)
    deleted.write_text("int gone(void);\n", encoding="utf-8")

    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        deleted_tu, _ = db.register_tu_hash(str(deleted), "old")
        other_tu, _ = db.register_tu_hash(str(project / "src" / "other.c"), "other")
        db.mark_tu_indexed(deleted_tu)
        db.mark_tu_indexed(other_tu)

        db.insert_function("gone", "include/deleted.h", 1, 1, tu_id=deleted_tu)
        db.insert_function("keep", "src/keep.c", 1, 3, tu_id=other_tu)
        type_id = db.insert_type("GoneType", "struct", "include/deleted.h", 1, 4, tu_id=deleted_tu)
        db.insert_type_member(type_id, "field", "int", 0)
        db.insert_call_edge("gone", "include/deleted.h", "helper", "src/helper.c", 1)
        db.insert_call_edge("caller", "src/caller.c", "gone", "include/deleted.h", 9)
        db.insert_call_edge("keep", "src/keep.c", "helper", "src/helper.c", 2)
        db._conn.execute(
            "INSERT INTO include_edges (source_file, included_file, line, is_system) "
            "VALUES (?, ?, ?, ?)",
            ("include/deleted.h", "stdint.h", 1, 1),
        )
        db._conn.execute(
            "INSERT INTO include_edges (source_file, included_file, line, is_system) "
            "VALUES (?, ?, ?, ?)",
            ("src/caller.c", "deleted.h", 2, 0),
        )
        db._conn.execute(
            "INSERT INTO macro_definitions (name, file_path, line, definition) "
            "VALUES (?, ?, ?, ?)",
            ("GONE_MACRO", "include/deleted.h", 3, "1"),
        )
        db._conn.execute(
            "INSERT INTO global_variables (name, type_str, file_path, line) "
            "VALUES (?, ?, ?, ?)",
            ("gone_global", "int", "include/deleted.h", 4),
        )
        db.insert_function_symbol_refs_batch(
            [
                (
                    "gone",
                    "include/deleted.h",
                    "gone_global",
                    "global",
                    "include/deleted.h",
                    5,
                    "read",
                )
            ]
        )
        stmt = db.upsert_ir_statement("include/deleted.h", 5, "gone", normalized_code="x = 1")
        other_stmt = db.upsert_ir_statement("src/keep.c", 2, "keep", normalized_code="y = 1")
        db._conn.execute(
            "INSERT INTO ir_cfg_edges (function, from_stmt, to_stmt) VALUES (?, ?, ?)",
            ("gone", stmt, other_stmt),
        )
        db._conn.execute(
            "INSERT INTO ir_def_use_edges (variable, def_stmt, use_stmt) VALUES (?, ?, ?)",
            ("x", stmt, other_stmt),
        )
        db.upsert_ir_path_slice("CAND_GONE", "gone", source_stmt=stmt, sink_stmt=other_stmt)
        db.insert_ir_resource_event("CAND_GONE", "x", "release", "free", "include/deleted.h", 5, "gone")
        db.insert_ir_lock_event("CAND_GONE", "m", "lock", "include/deleted.h", 6, "gone")
        db.insert_ir_shared_access("CAND_GONE", "obj", "", "read", "include/deleted.h", 7, "gone")
        db.insert_indirect_call("gone", "target", call_file="include/deleted.h")
        db.insert_taint_signature("", "", "Leak", file_path="include/deleted.h", line=8)
        db.upsert_function_contract("gone", releases='["free"]')
        db.commit()

        impact = db.delete_tu(deleted_tu)

        assert "gone" in impact["deleted_symbols"]
        assert "src/caller.c" in impact["related_files"]
        assert db.get_function("gone") is None
        assert db.get_function("keep")["name"] == "keep"
        assert db.get_callers("gone") == []
        assert db.get_callees("keep")[0]["name"] == "helper"
        assert db.get_type_info("GoneType") is None
        assert db.stats()["function_contracts"] == 1
        assert db.stats()["translation_units"] == 1

        for table in (
            "macro_definitions",
            "global_variables",
            "function_symbol_refs",
            "function_macro_refs",
            "ir_resource_events",
            "ir_lock_events",
            "ir_shared_accesses",
            "indirect_calls",
            "taint_signatures",
            "ir_cfg_edges",
            "ir_def_use_edges",
            "ir_path_slices",
        ):
            assert db._conn.execute(f"SELECT COUNT(*) AS cnt FROM {table}").fetchone()["cnt"] == 0
        assert db._conn.execute(
            "SELECT COUNT(*) AS cnt FROM ir_statements WHERE file_path = ?",
            ("include/deleted.h",),
        ).fetchone()["cnt"] == 0
        assert db._conn.execute(
            "SELECT COUNT(*) AS cnt FROM ir_statements WHERE file_path = ?",
            ("src/keep.c",),
        ).fetchone()["cnt"] == 1
        assert db._conn.execute("SELECT COUNT(*) AS cnt FROM include_edges").fetchone()["cnt"] == 1
    finally:
        db.close()


def test_knowledge_db_finds_configured_acquire_without_release(tmp_path: Path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        db.insert_call_edge("api_open", "src/demo.c", "SHM_FileOpen", "src/fs.c", 12)
        db.insert_call_edge("api_close", "src/demo.c", "SHM_FileOpen", "src/fs.c", 22)
        db.insert_call_edge("api_close", "src/demo.c", "SHM_FileClose", "src/fs.c", 24)
        db.commit()

        rows = db.find_callers_without_callee("SHM_FileOpen", "SHM_FileClose")

        assert rows == [
            {
                "function": "api_open",
                "file_path": "src/demo.c",
                "line": 12,
                "acquire_func": "SHM_FileOpen",
                "release_func": "SHM_FileClose",
            }
        ]
    finally:
        db.close()


def test_svf_queries_dedupe_across_groups_with_provenance(tmp_path: Path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        db.insert_indirect_call(
            "caller",
            "target",
            source="svf-ander",
            confidence=0.8,
            call_file="src/a.c",
            svf_group="entry_cluster_1",
        )
        db.insert_indirect_call(
            "caller",
            "target",
            source="svf-ander",
            confidence=1.0,
            call_file="src/a.c",
            svf_group="entry_cluster_2",
        )
        db.insert_taint_signature(
            "",
            "",
            "Double Free",
            file_path="src/a.c",
            line=42,
            tool="saber",
            svf_group="entry_cluster_1",
        )
        db.insert_taint_signature(
            "",
            "",
            "Double Free",
            file_path="src/a.c",
            line=42,
            tool="saber",
            svf_group="saber_full",
        )
        db.commit()

        callees = db.get_indirect_callees("caller")
        bugs = db.get_taint_bugs("Double Free")

        assert len(callees) == 1
        assert callees[0]["name"] == "target"
        assert callees[0]["confidence"] == 1.0
        assert callees[0]["svf_groups"] == ["entry_cluster_1", "entry_cluster_2"]
        assert len(bugs) == 1
        assert bugs[0]["svf_groups"] == ["entry_cluster_1", "saber_full"]
    finally:
        db.close()


def test_enriched_taint_bugs_can_filter_by_reachable_function_names(tmp_path: Path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        db.insert_function("entry", "src/entry.c", 1, 20)
        db.insert_function("callee", "src/callee.c", 10, 30)
        db.insert_function("unreachable", "src/unreachable.c", 10, 30)
        db.insert_taint_signature(
            "",
            "",
            "Double Free",
            file_path="src/callee.c",
            line=12,
            tool="saber",
            svf_group="saber:default",
        )
        db.insert_taint_signature(
            "",
            "",
            "Memory Leak",
            file_path="src/unreachable.c",
            line=14,
            tool="saber",
            svf_group="saber:default",
        )
        db.commit()

        assert db.get_enriched_taint_bugs(func_name="entry", limit=10) == []

        bugs = db.get_enriched_taint_bugs(
            func_names=["entry", "callee"],
            limit=10,
        )

        assert len(bugs) == 1
        assert bugs[0]["bug_type"] == "Double Free"
        assert bugs[0]["func_name"] == "callee"
        assert bugs[0]["svf_groups"] == ["saber:default"]
    finally:
        db.close()


def test_enriched_taint_bugs_preserve_distinct_source_sink_identities(
    tmp_path: Path,
) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        db.insert_taint_signature(
            "unreachable",
            "sink_a",
            "Double Free",
            file_path="src/shared.c",
            line=42,
            tool="saber",
            svf_group="g1",
        )
        db.insert_taint_signature(
            "entry",
            "sink_b",
            "Double Free",
            file_path="src/shared.c",
            line=42,
            tool="saber",
            svf_group="g1",
        )
        db.commit()

        all_rows = db.get_enriched_taint_bugs(limit=10)
        reachable_rows = db.get_enriched_taint_bugs(
            func_names=["entry"],
            limit=10,
        )

        assert {
            (row["source_func"], row["sink_func"])
            for row in all_rows
        } == {
            ("entry", "sink_b"),
            ("unreachable", "sink_a"),
        }
        assert len(reachable_rows) == 1
        assert reachable_rows[0]["source_func"] == "entry"
        assert reachable_rows[0]["sink_func"] == "sink_b"
        assert reachable_rows[0]["svf_groups"] == ["g1"]
    finally:
        db.close()


def test_enriched_taint_reachability_filter_uses_one_sql_parameter(
    tmp_path: Path,
) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        db.insert_taint_signature(
            "reachable_10999",
            "sink",
            "Memory Leak",
            file_path="src/large.c",
            line=7,
            tool="saber",
            svf_group="full",
        )
        db.commit()

        rows = db.get_enriched_taint_bugs(
            func_names=[f"reachable_{index}" for index in range(11_000)],
            limit=10,
        )

        assert len(rows) == 1
        assert rows[0]["source_func"] == "reachable_10999"
    finally:
        db.close()


def test_user_config_suppression_and_baseline(tmp_path: Path) -> None:
    store = UserConfigStore(tmp_path)
    store.add_false_positive_suppression(
        func_name="demo",
        location="src/demo.c:10",
        category="integer_overflow",
        rule="unit_test",
        reason="covered by fixed bound",
    )
    assert store.is_false_positive("demo", "src/demo.c:10", "integer_overflow")
    assert not store.is_false_positive("other", "src/demo.c:10", "integer_overflow")

    store.upsert_finding_baseline("dedup-1", "false_positive", {"id": "ISSUE_1"})
    assert store.get_finding_baseline("dedup-1")["status"] == "false_positive"


def test_finding_baseline_matches_after_line_shift(tmp_path: Path) -> None:
    store = UserConfigStore(tmp_path)
    store.upsert_finding_baseline(
        "double_free|entry|src/demo.c:42",
        "false_positive",
        {
            "id": "ISSUE_1",
            "function": "entry",
            "location": "src/demo.c:42",
            "defect_class": "double_free",
            "rule": "resource_automaton",
            "validation_status": "rejected",
            "validation_reasoning": "ownership transferred before this free",
        },
    )

    shifted_issue = {
        "id": "ISSUE_2",
        "function": "entry",
        "location": "src/demo.c:57",
        "defect_class": "double_free",
        "rule": "resource_automaton",
        "dedup_key": "double_free|entry|src/demo.c:57",
    }

    baseline = store.get_finding_baseline_for_issue(
        shifted_issue,
        shifted_issue["dedup_key"],
    )

    assert baseline is not None
    assert baseline["status"] == "false_positive"
    assert baseline["match_strategy"] == "stable_fingerprint"


def test_web_validation_feedback_persists_suppression_and_baseline(tmp_path: Path) -> None:
    store = UserConfigStore(tmp_path)
    original_service = web_server._report_feedback_service
    web_server._report_feedback_service = ReportFeedbackService(store)
    try:
        web_server.persist_validation_feedback([
            {
                "id": "ISSUE_1",
                "function": "entry",
                "location": "src/demo.c:42",
                "defect_class": "double_free",
                "validation_status": "rejected",
                "validation_reasoning": "ownership transferred before this free",
                "dedup_key": "double_free|entry|src/demo.c:42",
                "rule": "resource_automaton",
            }
        ])
    finally:
        web_server._report_feedback_service = original_service

    assert store.is_false_positive("entry", "src/demo.c:42", "double_free")
    baseline = store.get_finding_baseline("double_free|entry|src/demo.c:42")
    assert baseline is not None
    assert baseline["status"] == "false_positive"
