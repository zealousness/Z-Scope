import threading
from pathlib import Path

from zscope.retrieval.clang_backend import ClangBackend
from zscope.retrieval.clang_extractor import ClangExtractor
from zscope.retrieval.knowledge_db import KnowledgeDB


def _index_file(db: KnowledgeDB, source: Path) -> int:
    file_hash = ClangExtractor._compute_file_hash(source)
    tu_id, _changed = db.register_tu_hash(str(source.resolve()), file_hash)
    db.mark_tu_indexed(tu_id)
    return int(tu_id)


def _mark_base_indexes_current(backend: ClangBackend, db: KnowledgeDB) -> None:
    backend._mark_macro_index_current(db)
    backend._mark_type_index_current(db)


def test_clang_runtime_acknowledges_work_done_progress_request(tmp_path, monkeypatch) -> None:
    extractor = ClangExtractor(project_root=tmp_path)
    written = []
    monkeypatch.setattr(extractor, "_write_message", written.append)

    extractor._dispatch_message(
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "window/workDoneProgress/create",
            "params": {"token": "background-index"},
        }
    )

    assert written == [{"jsonrpc": "2.0", "id": 7, "result": None}]
    assert 7 not in extractor._responses


def test_clang_runtime_wakes_request_waiter_on_response(tmp_path, monkeypatch) -> None:
    extractor = ClangExtractor(project_root=tmp_path)
    timers = []

    def fake_write(message):
        timer = threading.Timer(
            0.01,
            lambda: extractor._dispatch_message(
                {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}
            ),
        )
        timers.append(timer)
        timer.start()

    monkeypatch.setattr(extractor, "_write_message", fake_write)
    result = extractor.send_request("test/ping", {}, timeout=1)

    for timer in timers:
        timer.join(timeout=1)
    assert result == {"ok": True}
    assert extractor._responses == {}
    assert extractor._pending_request_ids == set()


def test_derived_symbol_index_resumes_without_tu_reextraction(tmp_path) -> None:
    source = tmp_path / "state.c"
    source.write_text("int state(void) { return 0; }\n", encoding="utf-8")
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    backend = ClangBackend()

    class FakeExtractor:
        def __init__(self):
            self.symbol_rebuilds = 0
            self.type_rebuilds = 0

        def wait_for_indexing(self, timeout=120, idle_threshold=3.0):
            return True

        def rebuild_function_symbol_refs(self, _db):
            self.symbol_rebuilds += 1
            return 3

        def rebuild_function_type_refs(self, _db):
            self.type_rebuilds += 1
            return 4

    fake = FakeExtractor()
    try:
        _index_file(db, source)
        _mark_base_indexes_current(backend, db)
        backend._mark_function_type_ref_index_current(db)
        db.set_metadata("symbol_context_extractor_version", "2")
        db.set_metadata("symbol_context_index_dirty", "0")

        backend._source_path = tmp_path
        backend._include_paths = []
        backend._exclude_paths = []
        backend._db = db
        backend._extractor = fake
        backend._status = "building"

        assert backend._run_full_extraction() is True
        assert fake.symbol_rebuilds == 1
        assert fake.type_rebuilds == 0
        assert db.get_metadata("symbol_context_extractor_version") == "3"
        assert db.get_metadata("symbol_context_index_dirty") == "0"

        _tu_id, changed = db.register_tu_hash(
            str(source.resolve()), ClangExtractor._compute_file_hash(source)
        )
        assert changed is False
    finally:
        backend._db = None
        db.close()


def test_dirty_derived_index_resumes_even_when_version_is_current(tmp_path) -> None:
    source = tmp_path / "state.c"
    source.write_text("int state(void) { return 0; }\n", encoding="utf-8")
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    backend = ClangBackend()

    class FakeExtractor:
        def __init__(self):
            self.symbol_rebuilds = 0

        def wait_for_indexing(self, timeout=120, idle_threshold=3.0):
            return True

        def rebuild_function_symbol_refs(self, _db):
            self.symbol_rebuilds += 1
            return 1

        def rebuild_function_type_refs(self, _db):
            raise AssertionError("type refs should already be current")

    fake = FakeExtractor()
    try:
        _index_file(db, source)
        _mark_base_indexes_current(backend, db)
        backend._mark_symbol_context_index_current(db)
        backend._mark_function_type_ref_index_current(db)
        db.set_metadata("symbol_context_index_dirty", "1")

        backend._source_path = tmp_path
        backend._include_paths = []
        backend._exclude_paths = []
        backend._db = db
        backend._extractor = fake
        backend._status = "building"

        assert backend._run_full_extraction() is True
        assert fake.symbol_rebuilds == 1
        assert db.get_metadata("symbol_context_index_dirty") == "0"
    finally:
        backend._db = None
        db.close()


def test_derived_version_change_does_not_force_unchanged_tus_pending(tmp_path) -> None:
    source_a = tmp_path / "a.c"
    source_b = tmp_path / "b.c"
    source_a.write_text("int a(void) { return 1; }\n", encoding="utf-8")
    source_b.write_text("int b(void) { return 2; }\n", encoding="utf-8")
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    backend = ClangBackend()

    class FakeExtractor:
        def __init__(self):
            self.prescanned_tus = None

        def wait_for_indexing(self, timeout=120, idle_threshold=3.0):
            return True

        def run_batch_extraction(
            self,
            file_list,
            database,
            batch_size=50,
            progress_cb=None,
            prescanned_tus=None,
        ):
            self.prescanned_tus = dict(prescanned_tus or {})
            success = 0
            skipped = 0
            for _path, (tu_id, changed) in self.prescanned_tus.items():
                if changed:
                    database.mark_tu_indexed(tu_id)
                    success += 1
                else:
                    skipped += 1
            return {"total": len(file_list), "success": success, "failed": 0, "skipped": skipped}

    fake = FakeExtractor()
    try:
        _index_file(db, source_a)
        _index_file(db, source_b)
        _mark_base_indexes_current(backend, db)
        backend._mark_function_type_ref_index_current(db)
        db.set_metadata("symbol_context_extractor_version", "2")
        db.set_metadata("symbol_context_index_dirty", "0")

        # Only A changes.  The stale derived-index version must not turn B into
        # extraction work.
        source_a.write_text("int a(void) { return 3; }\n", encoding="utf-8")

        backend._source_path = tmp_path
        backend._include_paths = []
        backend._exclude_paths = []
        backend._db = db
        backend._extractor = fake
        backend._status = "building"

        assert backend._run_full_extraction() is True
        assert fake.prescanned_tus is not None
        assert fake.prescanned_tus[str(source_a.resolve())][1] is True
        assert fake.prescanned_tus[str(source_b.resolve())][1] is False
    finally:
        backend._db = None
        db.close()


def test_unique_symbol_candidates_do_not_call_clangd_definition(tmp_path, monkeypatch) -> None:
    source = tmp_path / "state.c"
    source.write_text(
        "#define STATE_SET(v) ((v) != 0)\n"
        "int g_state = 0;\n"
        "int update(int value) {\n"
        "    int g_state = value;\n"
        "    return STATE_SET(g_state);\n"
        "}\n"
        "int use_global(void) {\n"
        "    if (g_state) {\n"
        "        g_state = STATE_SET(1);\n"
        "    }\n"
        "    return g_state;\n"
        "}\n",
        encoding="utf-8",
    )
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        db.insert_function("update", "state.c", 3, 6, signature="int update(int value)")
        db.insert_function("use_global", "state.c", 7, 12, signature="int use_global(void)")
        db.insert_global_variable(
            "g_state",
            "int",
            "state.c",
            2,
            initializer="0",
            definition_kind="definition",
        )
        db.insert_macro_definitions_batch(
            [("STATE_SET", "state.c", 1, "#define STATE_SET(v) ((v) != 0)\n", 1)]
        )
        db.commit()

        extractor = ClangExtractor(project_root=tmp_path)
        monkeypatch.setattr(extractor, "open_document", lambda _path: False)
        monkeypatch.setattr(extractor, "close_document", lambda _path: None)

        def unexpected_definition(*_args, **_kwargs):
            raise AssertionError("unique visible symbols should not require clangd definition")

        monkeypatch.setattr(extractor, "_definition_locations", unexpected_definition)

        assert extractor.rebuild_function_symbol_refs(db) == 5
        assert extractor._symbol_ref_definition_requests == 0
        assert extractor._symbol_ref_fast_resolved >= 5
    finally:
        db.close()
