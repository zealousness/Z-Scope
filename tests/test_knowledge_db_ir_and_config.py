from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from zscope.config.user_config_store import UserConfigStore
from zscope.retrieval.knowledge_db import KnowledgeDB
from zscope.web import server as web_server


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


def test_web_validation_feedback_persists_suppression_and_baseline(tmp_path: Path) -> None:
    store = UserConfigStore(tmp_path)
    original_store = web_server._user_config_store
    web_server._user_config_store = store
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
        web_server._user_config_store = original_store

    assert store.is_false_positive("entry", "src/demo.c:42", "double_free")
    baseline = store.get_finding_baseline("double_free|entry|src/demo.c:42")
    assert baseline is not None
    assert baseline["status"] == "false_positive"
