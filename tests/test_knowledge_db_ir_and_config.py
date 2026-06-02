from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from zscope.config.user_config_store import UserConfigStore
from zscope.retrieval.knowledge_db import KnowledgeDB
from zscope.web import server as web_server
from zscope.web.services import ReportFeedbackService


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
