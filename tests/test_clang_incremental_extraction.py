from pathlib import Path

from zscope.retrieval.clang_backend import ClangBackend
from zscope.retrieval.clang_extractor import ClangExtractor


class _FakeDB:
    def __init__(self):
        self.register_calls = 0
        self.purged = []
        self.commits = 0
        self.pending = []

    def register_tu_hash(self, file_path: str, file_hash: str):
        self.register_calls += 1
        raise AssertionError("register_tu_hash should not be called with prescanned_tus")

    def purge_tu_data(self, tu_id: int):
        self.purged.append(tu_id)

    def commit(self):
        self.commits += 1

    def get_all_tus(self):
        return []

    def mark_tu_pending(self, tu_id: int):
        self.pending.append(tu_id)


class _SymbolDB:
    def insert_type(self, *args, **kwargs):
        return 1

    def insert_type_member(self, *args, **kwargs):
        return None


def test_clang_extractor_qualifies_class_scoped_cpp_symbols(tmp_path, monkeypatch) -> None:
    extractor = ClangExtractor(project_root=tmp_path)
    monkeypatch.setattr(extractor, "_extract_call_edges", lambda *args, **kwargs: None)
    func_rows = []
    call_rows = []

    extractor._process_symbol(
        {
            "kind": extractor.SK_CLASS,
            "name": "Widget",
            "range": {"start": {"line": 0}, "end": {"line": 5}},
            "children": [
                {
                    "kind": extractor.SK_CONSTRUCTOR,
                    "name": "Widget",
                    "range": {"start": {"line": 1}, "end": {"line": 1}},
                },
                {
                    "kind": extractor.SK_METHOD,
                    "name": "~Widget",
                    "range": {"start": {"line": 2}, "end": {"line": 2}},
                },
                {
                    "kind": extractor.SK_METHOD,
                    "name": "reset",
                    "range": {"start": {"line": 3}, "end": {"line": 4}},
                },
            ],
        },
        tmp_path / "widget.cpp",
        "widget.cpp",
        1,
        _SymbolDB(),
        func_rows,
        call_rows,
    )

    assert [row[0] for row in func_rows] == [
        "Widget::Widget",
        "Widget::~Widget",
        "Widget::reset",
    ]


def test_clang_extractor_marks_ph_prototype_as_declaration(tmp_path, monkeypatch) -> None:
    header = tmp_path / "plugin.ph"
    header.write_text(
        "extern int _plugin_register(\n"
        "    PluginRegistry* registry,\n"
        "    const char* name\n"
        ");\n",
        encoding="utf-8",
    )
    extractor = ClangExtractor(project_root=tmp_path)
    monkeypatch.setattr(extractor, "_extract_call_edges", lambda *args, **kwargs: None)
    func_rows = []

    extractor._process_symbol(
        {
            "kind": extractor.SK_FUNCTION,
            "name": "_plugin_register",
            "detail": "extern int",
            "range": {"start": {"line": 0}, "end": {"line": 3}},
        },
        header,
        "plugin.ph",
        1,
        _SymbolDB(),
        func_rows,
        [],
    )

    assert func_rows[0][0] == "_plugin_register"
    assert func_rows[0][7] == 1


def test_clang_extractor_keeps_header_inline_body_as_implementation(
    tmp_path, monkeypatch
) -> None:
    header = tmp_path / "helpers.h"
    header.write_text(
        "static inline int helper(void) {\n"
        "    return 1;\n"
        "}\n",
        encoding="utf-8",
    )
    extractor = ClangExtractor(project_root=tmp_path)
    monkeypatch.setattr(extractor, "_extract_call_edges", lambda *args, **kwargs: None)
    func_rows = []

    extractor._process_symbol(
        {
            "kind": extractor.SK_FUNCTION,
            "name": "helper",
            "detail": "static inline int",
            "range": {"start": {"line": 0}, "end": {"line": 2}},
        },
        header,
        "helpers.h",
        1,
        _SymbolDB(),
        func_rows,
        [],
    )

    assert func_rows[0][0] == "helper"
    assert func_rows[0][7] == 0


def test_run_batch_extraction_uses_prescanned_tus_without_rehashing(
    tmp_path, monkeypatch
) -> None:
    changed_file = tmp_path / "changed.c"
    unchanged_file = tmp_path / "unchanged.c"
    changed_file.write_text("int changed(void) { return 1; }\n", encoding="utf-8")
    unchanged_file.write_text("int unchanged(void) { return 0; }\n", encoding="utf-8")

    def fail_hash(_path: Path) -> str:
        raise AssertionError("_compute_file_hash should not be called with prescanned_tus")

    monkeypatch.setattr(ClangExtractor, "_compute_file_hash", staticmethod(fail_hash))

    extracted = []

    def fake_extract_tu(self, file_path, db, tu_id, progress_cb=None):
        extracted.append((Path(file_path), tu_id))
        return True

    monkeypatch.setattr(ClangExtractor, "extract_tu", fake_extract_tu)

    extractor = ClangExtractor(project_root=tmp_path)
    db = _FakeDB()
    stats = extractor.run_batch_extraction(
        [changed_file, unchanged_file],
        db,
        batch_size=10,
        prescanned_tus={
            str(changed_file.resolve()): (11, True),
            str(unchanged_file.resolve()): (12, False),
        },
    )

    assert stats == {"total": 2, "success": 1, "failed": 0, "skipped": 1}
    assert extracted == [(changed_file.resolve(), 11)]
    assert db.purged == [11]
    assert db.commits == 1
    assert db.register_calls == 0


def test_run_batch_extraction_keeps_legacy_hash_register_path(tmp_path, monkeypatch) -> None:
    source = tmp_path / "legacy.c"
    source.write_text("int legacy(void) { return 0; }\n", encoding="utf-8")

    class LegacyDB(_FakeDB):
        def register_tu_hash(self, file_path: str, file_hash: str):
            self.register_calls += 1
            assert file_path == str(source.resolve())
            assert file_hash == "hash"
            return (21, False)

    monkeypatch.setattr(ClangExtractor, "_compute_file_hash", staticmethod(lambda _path: "hash"))
    extractor = ClangExtractor(project_root=tmp_path)
    db = LegacyDB()

    stats = extractor.run_batch_extraction([source], db, batch_size=10)

    assert stats == {"total": 1, "success": 0, "failed": 0, "skipped": 1}
    assert db.register_calls == 1
    assert db.commits == 1


def test_clang_backend_passes_prescanned_tus_to_batch_extraction(
    tmp_path, monkeypatch
) -> None:
    source = tmp_path / "demo.c"
    source.write_text("int demo(void) { return 0; }\n", encoding="utf-8")

    class BackendDB(_FakeDB):
        def register_tu_hash(self, file_path: str, file_hash: str):
            self.register_calls += 1
            assert file_path == str(source.resolve())
            assert file_hash == "hash"
            return (31, True)

    class FakeExtractor:
        def __init__(self):
            self.received_prescanned_tus = None

        def wait_for_indexing(self, timeout: int, idle_threshold: float) -> bool:
            return True

        def run_batch_extraction(
            self,
            file_list,
            db,
            batch_size=50,
            progress_cb=None,
            prescanned_tus=None,
        ):
            self.received_prescanned_tus = prescanned_tus
            return {"total": len(file_list), "success": 1, "failed": 0, "skipped": 0}

    backend = ClangBackend(batch_size=7)
    backend._source_path = tmp_path
    backend._db = BackendDB()
    backend._extractor = FakeExtractor()

    monkeypatch.setattr(backend, "_collect_source_files", lambda: [source])
    monkeypatch.setattr(backend, "_ensure_extractor", lambda: True)
    monkeypatch.setattr(ClangExtractor, "_compute_file_hash", staticmethod(lambda _path: "hash"))

    assert backend._run_full_extraction() is True

    assert backend._extractor.received_prescanned_tus == {str(source.resolve()): (31, True)}
    assert backend._status == "ready"


def test_clang_backend_deletes_missing_tu_without_starting_clangd(
    tmp_path, monkeypatch
) -> None:
    deleted = tmp_path / "deleted.c"

    class DeleteOnlyDB(_FakeDB):
        def __init__(self):
            super().__init__()
            self.deleted = []

        def get_all_tus(self):
            return [{"id": 41, "file_path": str(deleted)}]

        def get_tu_delete_impact(self, tu_id: int):
            assert tu_id == 41
            return {
                "deleted_paths": [str(deleted)],
                "deleted_symbols": ["deleted"],
                "related_files": [],
            }

        def delete_tu(self, tu_id: int):
            self.deleted.append(tu_id)
            return self.get_tu_delete_impact(tu_id)

    backend = ClangBackend()
    backend._source_path = tmp_path
    backend._db = DeleteOnlyDB()
    monkeypatch.setattr(backend, "_collect_source_files", lambda: [])

    def fail_start():
        raise AssertionError("clangd should not start when only stale TUs are removed")

    monkeypatch.setattr(backend, "_ensure_extractor", fail_start)

    assert backend._run_full_extraction() is True
    assert backend._db.deleted == [41]
    assert backend._status == "ready"


def test_clang_backend_force_refreshes_callers_of_deleted_tu(
    tmp_path, monkeypatch
) -> None:
    caller = tmp_path / "caller.c"
    deleted = tmp_path / "deleted.c"
    caller.write_text("int caller(void) { return deleted(); }\n", encoding="utf-8")

    class ImpactDB(_FakeDB):
        def __init__(self):
            super().__init__()
            self.deleted = []

        def get_all_tus(self):
            return [
                {"id": 51, "file_path": str(caller.resolve())},
                {"id": 52, "file_path": str(deleted.resolve())},
            ]

        def get_tu_delete_impact(self, tu_id: int):
            assert tu_id == 52
            return {
                "deleted_paths": [str(deleted.resolve())],
                "deleted_symbols": ["deleted"],
                "related_files": [str(caller.resolve())],
            }

        def delete_tu(self, tu_id: int):
            self.deleted.append(tu_id)
            return self.get_tu_delete_impact(tu_id)

        def register_tu_hash(self, file_path: str, file_hash: str):
            self.register_calls += 1
            assert file_path == str(caller.resolve())
            assert file_hash == "hash"
            return (51, False)

    class FakeExtractor:
        def __init__(self):
            self.deleted_notifications = []
            self.received_prescanned_tus = None

        def notify_files_deleted(self, file_paths):
            self.deleted_notifications.extend(Path(p).resolve() for p in file_paths)

        def wait_for_indexing(self, timeout: int, idle_threshold: float) -> bool:
            return True

        def run_batch_extraction(
            self,
            file_list,
            db,
            batch_size=50,
            progress_cb=None,
            prescanned_tus=None,
        ):
            self.received_prescanned_tus = prescanned_tus
            return {"total": len(file_list), "success": 1, "failed": 0, "skipped": 0}

    backend = ClangBackend(batch_size=3)
    backend._source_path = tmp_path
    backend._db = ImpactDB()
    backend._extractor = FakeExtractor()

    monkeypatch.setattr(backend, "_collect_source_files", lambda: [caller])
    monkeypatch.setattr(backend, "_ensure_extractor", lambda: True)
    monkeypatch.setattr(ClangExtractor, "_compute_file_hash", staticmethod(lambda _path: "hash"))

    assert backend._run_full_extraction() is True

    assert backend._db.deleted == [52]
    assert backend._db.pending == [51]
    assert backend._extractor.received_prescanned_tus == {str(caller.resolve()): (51, True)}
    assert backend._extractor.deleted_notifications == [deleted.resolve()]
    assert backend._status == "ready"
