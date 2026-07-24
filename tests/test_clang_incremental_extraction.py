from pathlib import Path

from zscope.retrieval.clang_backend import ClangBackend
from zscope.retrieval.clang_extractor import ClangExtractor
from zscope.retrieval.knowledge_db import KnowledgeDB


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
            "detail": "",
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
    assert func_rows[0][5] == 1
    assert func_rows[0][7] == 0


def test_clang_backend_preserves_is_static_in_index_and_method(tmp_path) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    backend = ClangBackend()
    try:
        db.insert_function(
            "hidden",
            "src/hidden.c",
            1,
            3,
            signature="static int hidden(void)",
            is_static=True,
        )
        db.commit()
        backend._db = db

        index = backend.build_function_index()
        method = backend.get_method("hidden")

        assert index["hidden"]["is_static"] is True
        assert method is not None and method["is_static"] is True
    finally:
        backend._db = None
        db.close()


def test_clang_extractor_rebuilds_direct_function_type_references(
    tmp_path, monkeypatch
) -> None:
    source = tmp_path / "src" / "plugin.c"
    source.parent.mkdir(parents=True)
    source.write_text(
        "int register_plugin(PluginRegistry *registry) {\n"
        "    Plugin *plugin = (Plugin *)0;\n"
        "    int bytes = sizeof(Plugin);\n"
        "    return registry->plugins != plugin;\n"
        "}\n",
        encoding="utf-8",
    )
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        db.insert_function(
            "register_plugin",
            "src/plugin.c",
            1,
            5,
            signature="int register_plugin(PluginRegistry *registry)",
        )
        db.insert_type(
            "Plugin",
            "struct",
            "include/types.h",
            90,
            98,
            full_definition="typedef struct Plugin Plugin;",
        )
        db.insert_type(
            "PluginRegistry",
            "struct",
            "include/types.h",
            110,
            115,
            full_definition="typedef struct { Plugin *plugins; } PluginRegistry;",
        )
        db.commit()
        extractor = ClangExtractor(project_root=tmp_path)

        def definition_for_token(file_path, line, character):
            token = source.read_text(encoding="utf-8").splitlines()[line - 1][character:]
            if token.startswith("PluginRegistry"):
                return [("include/types.h", 110)]
            if token.startswith("Plugin"):
                return [("include/types.h", 90)]
            return []

        monkeypatch.setattr(extractor, "open_document", lambda path: True)
        monkeypatch.setattr(extractor, "close_document", lambda path: None)
        monkeypatch.setattr(extractor, "_definition_locations", definition_for_token)

        count = extractor.rebuild_function_type_refs(db)
        context = db.get_function_type_context("register_plugin", "src/plugin.c", 1)

        assert count >= 5
        assert [item["name"] for item in context["referenced_types"]] == [
            "Plugin",
            "PluginRegistry",
        ]
        by_name = {item["name"]: item for item in context["referenced_types"]}
        assert by_name["Plugin"]["reference_kinds"] == ["local", "cast", "sizeof"]
        assert by_name["PluginRegistry"]["reference_kinds"] == [
            "parameter",
            "member_access",
        ]
        assert "unresolved_referenced_types" not in context
    finally:
        db.close()


def test_clang_extractor_include_edges_store_canonical_project_paths(tmp_path) -> None:
    source = tmp_path / "src" / "plugin.c"
    header = tmp_path / "include" / "types.h"
    source.parent.mkdir(parents=True)
    header.parent.mkdir(parents=True)
    source.write_text('#include "../include/types.h"\n', encoding="utf-8")
    header.write_text("typedef int Plugin;\n", encoding="utf-8")
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        extractor = ClangExtractor(project_root=tmp_path)
        extractor._extract_includes(source, "src/plugin.c", db)
        db.commit()

        assert db.get_transitive_include_closure("src/plugin.c") == [
            "include/types.h",
            "src/plugin.c",
        ]
    finally:
        db.close()


def test_direct_type_candidates_exclude_parenthesized_values_and_builtin_typedefs(
    tmp_path,
) -> None:
    source = tmp_path / "runtime.c"
    source.write_text(
        "int run(const char *path, uint32_t count) {\n"
        "    RuntimeEvent *event = (RuntimeEvent *)0;\n"
        "    if (_file_exists(path)) { count = sizeof(path); }\n"
        "    count += helper(PLATFORM_WINDOWS);\n"
        "    count = (uint32_t)_hash_string(path);\n"
        "    SAFE_FREE(event);\n"
        "    return (int)count;\n"
        "}\n",
        encoding="utf-8",
    )
    extractor = ClangExtractor(project_root=tmp_path)
    lines = source.read_text(encoding="utf-8").splitlines(True)

    candidates = extractor._direct_function_type_candidates(
        {
            "name": "run",
            "start_line": 1,
            "end_line": 8,
            "signature": "int run(const char *path, uint32_t count)",
        },
        lines,
        {"RuntimeEvent"},
    )

    assert {item["name"] for item in candidates} == {"RuntimeEvent"}
    assert {item["kind"] for item in candidates} == {"local", "cast"}


def test_clang_extractor_stores_source_signature_in_function_rows(
    tmp_path, monkeypatch
) -> None:
    source = tmp_path / "executor.c"
    source.write_text(
        "int _executor_validate_command(const char* command) {\n"
        "    return command ? 0 : -1;\n"
        "}\n",
        encoding="utf-8",
    )
    extractor = ClangExtractor(project_root=tmp_path)
    monkeypatch.setattr(extractor, "_extract_call_edges", lambda *args, **kwargs: None)
    func_rows = []

    extractor._process_symbol(
        {
            "kind": extractor.SK_FUNCTION,
            "name": "_executor_validate_command",
            "detail": "int (const char *)",
            "range": {"start": {"line": 0}, "end": {"line": 2}},
        },
        source,
        "executor.c",
        1,
        _SymbolDB(),
        func_rows,
        [],
    )

    assert func_rows[0][0] == "_executor_validate_command"
    assert func_rows[0][4] == "int _executor_validate_command(const char* command)"


def test_clang_extractor_only_stores_file_scope_globals(tmp_path, monkeypatch) -> None:
    source = tmp_path / "state.c"
    source.write_text(
        "\n" * 7
        + "static volatile int g_state = 1;\n"
        + "int update(void) {\n"
        + "    int local_state = 0;\n"
        + "    return local_state;\n"
        + "}\n",
        encoding="utf-8",
    )

    class GlobalDB(_SymbolDB):
        def __init__(self):
            self.globals = []

        def insert_global_variable(self, *args, **kwargs):
            self.globals.append((args, kwargs))

    extractor = ClangExtractor(project_root=tmp_path)
    monkeypatch.setattr(extractor, "_extract_call_edges", lambda *args, **kwargs: None)
    db = GlobalDB()

    extractor._process_symbol(
        {
            "kind": extractor.SK_VARIABLE,
            "name": "g_state",
            "detail": "static volatile int",
            "range": {"start": {"line": 7}, "end": {"line": 7}},
        },
        source,
        "state.c",
        1,
        db,
        [],
        [],
    )
    extractor._process_symbol(
        {
            "kind": extractor.SK_FUNCTION,
            "name": "update",
            "detail": "int",
            "range": {"start": {"line": 8}, "end": {"line": 11}},
            "children": [
                {
                    "kind": extractor.SK_VARIABLE,
                    "name": "local_state",
                    "detail": "int",
                    "range": {"start": {"line": 9}, "end": {"line": 9}},
                }
            ],
        },
        source,
        "state.c",
        1,
        db,
        [],
        [],
    )

    assert len(db.globals) == 1
    args, metadata = db.globals[0]
    assert args[:4] == ("g_state", "static volatile int", "state.c", 8)
    assert metadata == {
        "is_extern": False,
        "storage_class": "static",
        "qualifiers": "volatile",
        "initializer": "1",
        "definition_kind": "definition",
    }


def test_clang_extractor_rebuilds_function_global_and_macro_refs(tmp_path, monkeypatch) -> None:
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
        db.insert_function(
            "update",
            "state.c",
            3,
            6,
            signature="int update(int value)",
        )
        db.insert_function(
            "use_global",
            "state.c",
            7,
            12,
            signature="int use_global(void)",
        )
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
        monkeypatch.setattr(extractor, "get_definition", lambda *args, **kwargs: [])

        assert extractor.rebuild_function_symbol_refs(db) == 5

        update_context = db.get_function_symbol_context("update", "state.c")
        use_context = db.get_function_symbol_context("use_global", "state.c")
        assert update_context["referenced_globals"] == []
        assert update_context["referenced_macros"][0]["reference_lines"] == [5]
        assert use_context["referenced_globals"][0]["access"] == "read_write"
        assert use_context["referenced_globals"][0]["reference_lines"] == [8, 9, 11]
        assert use_context["referenced_macros"][0]["reference_lines"] == [9]
    finally:
        db.close()


def test_clang_extractor_writes_macro_definitions_for_tu(tmp_path, monkeypatch) -> None:
    source = tmp_path / "macros.h"
    source.write_text(
        "#define ZIP_ALLOC(sz) alloc(sz)\n"
        "#define ZIP_LIMIT 64\n"
        "#define ZIP_WRAP(x) \\\n"
        "    helper(x)\n",
        encoding="utf-8",
    )

    class MacroDB:
        def __init__(self):
            self.macro_rows = []
            self.indexed = []

        def insert_macro_definitions_batch(self, rows):
            self.macro_rows.extend(rows)

        def mark_tu_indexed(self, tu_id: int):
            self.indexed.append(tu_id)

    extractor = ClangExtractor(project_root=tmp_path)
    monkeypatch.setattr(extractor, "open_document", lambda _path: True)
    monkeypatch.setattr(extractor, "close_document", lambda _path: None)
    monkeypatch.setattr(extractor, "get_document_symbols", lambda _path: [])

    db = MacroDB()

    assert extractor.extract_tu(source, db, 7) is True

    assert db.indexed == [7]
    assert db.macro_rows == [
        (
            "ZIP_ALLOC",
            "macros.h",
            1,
            1,
            "ZIP_ALLOC@macros.h:1-1",
            "#define ZIP_ALLOC(sz) alloc(sz)\n",
            1,
        ),
        (
            "ZIP_LIMIT",
            "macros.h",
            2,
            2,
            "ZIP_LIMIT@macros.h:2-2",
            "#define ZIP_LIMIT 64\n",
            0,
        ),
        (
            "ZIP_WRAP",
            "macros.h",
            3,
            4,
            "ZIP_WRAP@macros.h:3-4",
            "#define ZIP_WRAP(x) \\\n    helper(x)\n",
            1,
        ),
    ]


def test_clang_extractor_reuses_source_text_cache_across_helpers(
    tmp_path,
    monkeypatch,
) -> None:
    source = tmp_path / "demo.c"
    source.write_text(
        "#define ZIP_WRAP(x) helper(x)\n"
        "int helper(void) { return 1; }\n"
        "int entry(void) {\n"
        "    return helper();\n"
        "}\n",
        encoding="utf-8",
    )
    extractor = ClangExtractor(project_root=tmp_path)
    monkeypatch.setattr(extractor, "get_definition", lambda *args, **kwargs: [])

    original_read_text = Path.read_text
    read_count = 0
    source_resolved = source.resolve()

    def counted_read_text(self, *args, **kwargs):
        nonlocal read_count
        if Path(self).resolve() == source_resolved:
            read_count += 1
        return original_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", counted_read_text)

    assert extractor._read_source_text(source) is not None
    assert extractor._extract_macros(source, "demo.c") == [
        (
            "ZIP_WRAP",
            "demo.c",
            1,
            1,
            "ZIP_WRAP@demo.c:1-1",
            "#define ZIP_WRAP(x) helper(x)\n",
            1,
        )
    ]
    assert extractor._symbol_range_has_function_body(source, 3, 5) is True
    call_rows = []
    extractor._extract_call_edges_by_regex(source, "entry", "demo.c", 3, 5, call_rows)

    assert read_count == 1
    assert any(row[2] == "helper" for row in call_rows)

    source.write_text(
        "#define ZIP_WRAP(x) helper(x)\n"
        "int helper(void) { return 1; }\n"
        "int entry(void) {\n"
        "    return helper();\n"
        "}\n"
        "int after(void) { return entry(); }\n",
        encoding="utf-8",
    )

    assert "after" in (extractor._read_source_text(source) or "")
    assert read_count == 2


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


def test_clang_backend_collect_source_files_scans_each_root_once_and_filters(
    tmp_path,
    monkeypatch,
) -> None:
    src_dir = tmp_path / "src"
    nested_dir = src_dir / "nested"
    excluded_dir = src_dir / "excluded"
    nested_dir.mkdir(parents=True)
    excluded_dir.mkdir()
    allowed_source = src_dir / "allowed.c"
    allowed_header = nested_dir / "allowed.hpp"
    allowed_inline = nested_dir / "allowed.inl"
    ignored_text = nested_dir / "ignored.txt"
    hidden_source = excluded_dir / "hidden.c"
    for path in [allowed_source, allowed_header, allowed_inline, ignored_text, hidden_source]:
        path.write_text("int x;\n", encoding="utf-8")

    backend = ClangBackend()
    backend._source_path = tmp_path
    backend._include_paths = [src_dir.absolute(), tmp_path.absolute()]
    backend._exclude_paths = [excluded_dir.absolute()]

    path_type = type(tmp_path)
    original_rglob = path_type.rglob
    calls = []

    def counting_rglob(self, pattern):
        calls.append((Path(self).resolve(), pattern))
        yield from original_rglob(self, pattern)

    monkeypatch.setattr(path_type, "rglob", counting_rglob)

    files = {path.resolve() for path in backend._collect_source_files()}

    assert files == {
        allowed_source.resolve(),
        allowed_header.resolve(),
        allowed_inline.resolve(),
    }
    assert [pattern for _, pattern in calls] == ["*", "*"]


def test_clang_backend_refreshes_unchanged_files_when_macro_metadata_missing(
    tmp_path, monkeypatch
) -> None:
    source = tmp_path / "macros.h"
    source.write_text("#define ZIP_ALLOC(sz) alloc(sz)\n", encoding="utf-8")

    class LegacyMacroDB(_FakeDB):
        def __init__(self):
            super().__init__()
            self.cleared_macros = 0
            self.metadata = {}

        def register_tu_hash(self, file_path: str, file_hash: str):
            self.register_calls += 1
            assert file_path == str(source.resolve())
            assert file_hash == "hash"
            return (61, False)

        def get_metadata(self, key: str) -> str:
            return self.metadata.get(key, "")

        def set_metadata(self, key: str, value: str):
            self.metadata[key] = value

        def clear_macro_definitions(self):
            self.cleared_macros += 1

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

    backend = ClangBackend(batch_size=5)
    backend._source_path = tmp_path
    backend._db = LegacyMacroDB()
    backend._extractor = FakeExtractor()

    monkeypatch.setattr(backend, "_collect_source_files", lambda: [source])
    monkeypatch.setattr(backend, "_ensure_extractor", lambda: True)
    monkeypatch.setattr(ClangExtractor, "_compute_file_hash", staticmethod(lambda _path: "hash"))

    assert backend._run_full_extraction() is True

    assert backend._db.cleared_macros == 1
    assert backend._db.pending == [61]
    assert backend._extractor.received_prescanned_tus == {str(source.resolve()): (61, True)}
    assert backend._db.metadata["macro_extractor_version"] == "2"
    assert backend._db.metadata["symbol_context_extractor_version"] == "2"
    assert backend._db.metadata["type_extractor_version"] == "1"
    assert backend._db.metadata["function_type_ref_extractor_version"] == "2"
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
