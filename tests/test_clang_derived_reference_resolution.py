import re
import threading
import time
from collections import OrderedDict
from pathlib import Path

from zscope.retrieval.clang_extractor import ClangExtractor
from zscope.retrieval.knowledge_db import KnowledgeDB


def _semantic_data(line: int, starts: list[int], token_type: int = 0, modifiers: int = 0):
    data: list[int] = []
    previous_line = 0
    previous_start = 0
    for index, start in enumerate(starts):
        delta_line = line - previous_line if index == 0 else 0
        delta_start = start if delta_line else start - previous_start
        data.extend([delta_line, delta_start, 1, token_type, modifiers])
        previous_line = line
        previous_start = start
    return data


def _semantic_records(line: int, records: list[tuple[int, int, int]]):
    data: list[int] = []
    previous_line = 0
    previous_start = 0
    for index, (start, token_type, modifiers) in enumerate(sorted(records)):
        delta_line = line - previous_line if index == 0 else 0
        delta_start = start if delta_line else start - previous_start
        data.extend([delta_line, delta_start, 1, token_type, modifiers])
        previous_line = line
        previous_start = start
    return data


def _semantic_multiline_records(records: list[tuple[int, int, int, int]]):
    data: list[int] = []
    previous_line = 0
    previous_start = 0
    for line, start, token_type, modifiers in sorted(records):
        delta_line = line - previous_line
        delta_start = start if delta_line else start - previous_start
        data.extend([delta_line, delta_start, 1, token_type, modifiers])
        previous_line = line
        previous_start = start
    return data


def _configure_semantics(
    extractor: ClangExtractor,
    monkeypatch,
    data: list[int],
    *,
    token_types: list[str],
    modifiers: list[str],
):
    calls = {"semantic": 0, "definition": 0}
    extractor._semantic_token_types = token_types
    extractor._semantic_token_modifiers = modifiers
    monkeypatch.setattr(extractor, "open_document", lambda _path: True)
    monkeypatch.setattr(extractor, "close_document", lambda _path: None)

    def semantic_tokens(_path):
        calls["semantic"] += 1
        return {"data": data}

    def definition(*_args, **_kwargs):
        calls["definition"] += 1
        raise AssertionError("definition must not be queried")

    monkeypatch.setattr(extractor, "get_semantic_tokens", semantic_tokens, raising=False)
    monkeypatch.setattr(extractor, "get_definition", definition)
    return calls


def test_symbol_filters_run_before_definition(tmp_path, monkeypatch) -> None:
    source = tmp_path / "filters.c"
    source.write_text(
        "#define FN(x) (x)\n"
        "int g;\n"
        "struct Obj { int g; };\n"
        "int f(struct Obj *obj) {\n"
        "    int g = 1;\n"
        "    int a = g;\n"
        "    int b = obj->g;\n"
        "    return a + b + FN;\n"
        "}\n",
        encoding="utf-8",
    )
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        db.insert_function("f", "filters.c", 4, 9, signature="int f(struct Obj *obj)")
        db.insert_global_variable("g", "int", "filters.c", 2)
        db.insert_macro_definitions_batch([("FN", "filters.c", 1, "#define FN(x) (x)\n", 1)])
        db.commit()
        extractor = ClangExtractor(project_root=tmp_path)
        monkeypatch.setattr(extractor, "open_document", lambda _path: False)
        monkeypatch.setattr(
            extractor,
            "get_definition",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError("lexically filtered occurrences must not query definition")
            ),
        )

        assert extractor.rebuild_function_symbol_refs(db) == 0
        stats = extractor.get_last_derived_stats("function_symbol_context")
        assert stats["definition_requests"] == 0
        assert stats["filtered_local_shadow"] >= 2
        assert stats["filtered_field"] >= 1
        assert stats["filtered_non_call_macro"] == 1
    finally:
        db.close()


def test_one_hundred_thousand_semantic_unique_refs_issue_no_definition(
    tmp_path,
    monkeypatch,
) -> None:
    occurrence_count = 100_000
    prefix = "int f(void) { return "
    expression = "+".join("g" for _ in range(occurrence_count))
    source = tmp_path / "scale.c"
    source.write_text(
        "int g = 1;\n" + prefix + expression + "; }\n",
        encoding="utf-8",
    )
    starts = [len(prefix) + index * 2 for index in range(occurrence_count)]
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        db.insert_function("f", "scale.c", 2, 2, signature="int f(void)")
        db.insert_global_variable("g", "int", "scale.c", 1)
        db.commit()
        extractor = ClangExtractor(project_root=tmp_path)
        calls = _configure_semantics(
            extractor,
            monkeypatch,
            _semantic_data(1, starts, modifiers=1),
            token_types=["variable"],
            modifiers=["globalScope"],
        )
        monkeypatch.setattr(
            extractor,
            "get_references",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError("semantic unique binding must not query references")
            ),
            raising=False,
        )

        assert extractor.rebuild_function_symbol_refs(db) == 1
        stats = extractor.get_last_derived_stats("function_symbol_context")
        assert calls == {"semantic": 1, "definition": 0}
        assert stats["candidates"] == occurrence_count
        assert stats["semantic_resolved"] == occurrence_count
        assert stats["definition_requests"] == 0
    finally:
        db.close()


def test_reverse_references_resolve_after_use_site_definition_fails(
    tmp_path,
    monkeypatch,
) -> None:
    source = tmp_path / "use.c"
    first = tmp_path / "first.h"
    second = tmp_path / "second.h"
    source_text = "int f(void) { return shared; }\n"
    source.write_text(source_text, encoding="utf-8")
    first.write_text("extern int shared;\n", encoding="utf-8")
    second.write_text("extern int shared;\n", encoding="utf-8")
    occurrence_start = source_text.index("shared")
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        db.insert_function("f", "use.c", 1, 1, signature="int f(void)")
        db.insert_global_variable("shared", "int", "first.h", 1, is_extern=True)
        db.insert_global_variable("shared", "int", "second.h", 1, is_extern=True)
        db.commit()
        extractor = ClangExtractor(project_root=tmp_path)
        calls = _configure_semantics(
            extractor,
            monkeypatch,
            _semantic_data(0, [occurrence_start]),
            token_types=["variable"],
            modifiers=[],
        )
        reference_calls: list[Path] = []

        def references(file_path, *_args, **_kwargs):
            reference_calls.append(Path(file_path))
            if Path(file_path).name != "second.h":
                return []
            return [
                {
                    "uri": source.as_uri(),
                    "range": {
                        "start": {"line": 0, "character": occurrence_start},
                        "end": {"line": 0, "character": occurrence_start + 6},
                    },
                }
            ]

        monkeypatch.setattr(extractor, "get_references", references, raising=False)

        assert extractor.rebuild_function_symbol_refs(db) == 1
        context = db.get_function_symbol_context("f", "use.c")
        assert context["referenced_globals"][0]["file_path"] == "second.h"
        assert sorted(path.name for path in reference_calls) == ["first.h", "second.h"]
        assert calls == {"semantic": 1, "definition": 1}
    finally:
        db.close()


def test_semantic_local_custom_type_shadow_is_not_bound_to_global(
    tmp_path,
    monkeypatch,
) -> None:
    source = tmp_path / "shadow.cpp"
    text = "int f() { CustomType g; return g; }\n"
    source.write_text(text, encoding="utf-8")
    (tmp_path / "globals.h").write_text("extern int g;\n", encoding="utf-8")
    starts = [text.index("g;"), text.rindex("g;")]
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        db.insert_function("f", "shadow.cpp", 1, 1, signature="int f()")
        db.insert_global_variable("g", "int", "globals.h", 1, is_extern=True)
        db.commit()
        extractor = ClangExtractor(project_root=tmp_path)
        calls = _configure_semantics(
            extractor,
            monkeypatch,
            _semantic_data(0, starts, modifiers=1),
            token_types=["variable"],
            modifiers=["functionScope"],
        )

        assert extractor.rebuild_function_symbol_refs(db) == 0
        assert calls == {"semantic": 1, "definition": 0}
        assert db.get_function_symbol_context("f", "shadow.cpp")["referenced_globals"] == []
    finally:
        db.close()


def test_definition_fallback_runs_once_for_one_ambiguous_coordinate(
    tmp_path,
    monkeypatch,
) -> None:
    source = tmp_path / "use.c"
    first = tmp_path / "first.h"
    second = tmp_path / "second.h"
    text = "int f(void) { return shared; }\n"
    source.write_text(text, encoding="utf-8")
    first.write_text("extern int shared;\n", encoding="utf-8")
    second.write_text("extern int shared;\n", encoding="utf-8")
    occurrence_start = text.index("shared")
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        db.insert_function("f", "use.c", 1, 1, signature="int f(void)")
        db.insert_global_variable("shared", "int", "first.h", 1, is_extern=True)
        db.insert_global_variable("shared", "int", "second.h", 1, is_extern=True)
        db.commit()
        extractor = ClangExtractor(project_root=tmp_path)
        extractor._semantic_token_types = ["variable"]
        extractor._semantic_token_modifiers = []
        monkeypatch.setattr(extractor, "open_document", lambda _path: True)
        monkeypatch.setattr(extractor, "close_document", lambda _path: None)
        monkeypatch.setattr(
            extractor,
            "get_semantic_tokens",
            lambda _path: {"data": _semantic_data(0, [occurrence_start])},
            raising=False,
        )
        monkeypatch.setattr(
            extractor, "get_references", lambda *_args, **_kwargs: [], raising=False
        )
        definition_calls = []

        def definition(*args, **_kwargs):
            definition_calls.append(args)
            return [
                {
                    "uri": second.as_uri(),
                    "range": {
                        "start": {"line": 0, "character": 11},
                        "end": {"line": 0, "character": 17},
                    },
                }
            ]

        monkeypatch.setattr(extractor, "get_definition", definition)

        assert extractor.rebuild_function_symbol_refs(db) == 1
        assert len(definition_calls) == 1
        context = db.get_function_symbol_context("f", "use.c")
        assert context["referenced_globals"][0]["file_path"] == "second.h"
    finally:
        db.close()


def test_symbol_and_type_rebuild_share_one_semantic_request_per_file(
    tmp_path,
    monkeypatch,
) -> None:
    source = tmp_path / "shared.cpp"
    text = "int f(T *value) { return g + sizeof(T); }\n"
    source.write_text("struct T {};\nint g;\n" + text, encoding="utf-8")
    type_starts = [text.index("T"), text.rindex("T")]
    global_start = text.index("g")
    data = _semantic_records(
        2,
        [(start, 1, 1) for start in type_starts] + [(global_start, 0, 1)],
    )
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        db.insert_function("f", "shared.cpp", 3, 3, signature="int f(T *value)")
        db.insert_global_variable("g", "int", "shared.cpp", 2)

        db.insert_type("T", "struct", "shared.cpp", 1, 1, full_definition="struct T;")
        db.commit()
        extractor = ClangExtractor(project_root=tmp_path)
        calls = _configure_semantics(
            extractor,
            monkeypatch,
            data,
            token_types=["variable", "type"],
            modifiers=["globalScope"],
        )
        def symbol_details(_path, _line, char):
            name = "g" if text[char:].startswith("g") else "T"
            target_line, target_char = (1, 4) if name == "g" else (0, 7)
            return [
                {
                    "usr": "c:@" + name,
                    "name": name,
                    "declarationRange": {
                        "uri": source.as_uri(),
                        "range": {
                            "start": {"line": target_line, "character": target_char},
                            "end": {"line": target_line, "character": target_char + 1},
                        },
                    },
                }
            ]

        monkeypatch.setattr(extractor, "get_symbol_details", symbol_details)
        monkeypatch.setattr(
            extractor,
            "get_references",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError("semantic unique binding must not query references")
            ),
            raising=False,
        )

        assert extractor.rebuild_function_symbol_refs(db) == 1
        assert extractor.rebuild_function_type_refs(db) >= 1
        assert calls == {"semantic": 1, "definition": 0}
        assert (
            db.get_function_type_context("f", "shared.cpp", 3)["referenced_types"][0]["name"] == "T"
        )
    finally:
        db.close()


def test_derived_semantic_cache_evicts_by_file_count_and_byte_budget(
    tmp_path,
    monkeypatch,
) -> None:
    sources = []
    for index in range(3):
        source = tmp_path / f"cache_{index}.c"
        source.write_text(f"int value_{index};\n", encoding="utf-8")
        sources.append(source)
    extractor = ClangExtractor(project_root=tmp_path)
    extractor._semantic_token_types = ["variable"]
    monkeypatch.setattr(
        extractor,
        "get_semantic_tokens",
        lambda _path: {"data": _semantic_data(0, [4])},
        raising=False,
    )
    monkeypatch.setattr(ClangExtractor, "_DERIVED_SEMANTIC_CACHE_MAX_FILES", 2)
    monkeypatch.setattr(
        ClangExtractor,
        "_DERIVED_SEMANTIC_CACHE_MAX_BYTES",
        128 * 1024 * 1024,
    )
    extractor.begin_derived_rebuild_session()
    for source in sources:
        extractor._get_file_semantic_context(
            source,
            source.read_text(encoding="utf-8").splitlines(True),
        )
    cache = extractor._semantic_context_cache
    assert len(cache) == 2
    assert all(str(sources[0].resolve()) != key[0] for key in cache)

    cache.clear()
    monkeypatch.setattr(ClangExtractor, "_DERIVED_SEMANTIC_CACHE_MAX_FILES", 64)
    monkeypatch.setattr(ClangExtractor, "_DERIVED_SEMANTIC_CACHE_MAX_BYTES", 1536)
    for source in sources[:2]:
        extractor._get_file_semantic_context(
            source,
            source.read_text(encoding="utf-8").splitlines(True),
        )
    assert len(cache) == 1
    assert next(iter(cache))[0] == str(sources[1].resolve())


def test_local_type_semantic_scope_never_falls_back_to_global_type(
    tmp_path,
    monkeypatch,
) -> None:
    source = tmp_path / "local_type.cpp"
    text = (
        "int f() {\n" "    struct T { int x; };\n" "    T value;\n" "    return sizeof(T);\n" "}\n"
    )
    source.write_text(text, encoding="utf-8")
    (tmp_path / "global.h").write_text("struct T;\n", encoding="utf-8")
    token_records = [
        (line_index, match.start(), 0, 1)
        for line_index, line in enumerate(text.splitlines())
        for match in re.finditer(r"\bT\b", line)
    ]
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        db.insert_function("f", "local_type.cpp", 1, 5, signature="int f()")
        db.insert_type("T", "struct", "global.h", 1, 1, full_definition="struct T;")
        db.commit()
        extractor = ClangExtractor(project_root=tmp_path)
        calls = _configure_semantics(
            extractor,
            monkeypatch,
            _semantic_multiline_records(token_records),
            token_types=["type"],
            modifiers=["functionScope"],
        )

        assert extractor.rebuild_function_type_refs(db) >= 1
        context = db.get_function_type_context("f", "local_type.cpp", 1)
        assert context.get("referenced_types", []) == []
        assert context["unresolved_referenced_types"][0]["reason"] == "local_type_shadow"
        assert calls == {"semantic": 1, "definition": 0}
    finally:
        db.close()


def test_reverse_reference_locations_use_negotiated_position_encoding(
    tmp_path,
    monkeypatch,
) -> None:
    source = tmp_path / "unicode.c"
    declaration = tmp_path / "globals.h"
    source_text = "int f(void) { return 名称 + shared; }\n"
    source.write_text(source_text, encoding="utf-8")
    declaration.write_text("extern int shared;\n", encoding="utf-8")
    python_character = source_text.index("shared")
    lsp_character = len(source_text[:python_character].encode("utf-8"))
    extractor = ClangExtractor(project_root=tmp_path)
    extractor._position_encoding = "utf-8"
    monkeypatch.setattr(
        extractor,
        "get_references",
        lambda *_args, **_kwargs: [
            {
                "uri": source.as_uri(),
                "range": {
                    "start": {"line": 0, "character": lsp_character},
                    "end": {"line": 0, "character": lsp_character + 6},
                },
            }
        ],
        raising=False,
    )
    semantic_context = {
        "available": True,
        "reference_cache": {},
        "declaration_char_cache": {},
    }
    stats = {"references_requests": 0}

    locations = extractor._candidate_reference_locations(
        {"name": "shared", "file_path": "globals.h", "line": 1},
        kind="global",
        semantic_context=semantic_context,
        stats=stats,
    )

    assert locations == {("unicode.c", 1, python_character)}


def test_type_name_set_is_reused_across_functions(tmp_path, monkeypatch) -> None:
    source = tmp_path / "types.c"
    source.write_text(
        "ProjectType first(void) { return value; }\n"
        "ProjectType second(void) { return value; }\n",
        encoding="utf-8",
    )
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        db.insert_function("first", "types.c", 1, 1, signature="int first(void)")
        db.insert_function("second", "types.c", 2, 2, signature="int second(void)")
        db.insert_type("ProjectType", "struct", "types.c", 1, 1)
        db.commit()
        extractor = ClangExtractor(project_root=tmp_path)
        monkeypatch.setattr(extractor, "open_document", lambda _path: False)
        observed_sets: list[set[str]] = []

        def candidates(_function, _lines, indexed_type_names):
            observed_sets.append(indexed_type_names)
            return []

        monkeypatch.setattr(extractor, "_direct_function_type_candidates", candidates)

        assert extractor.rebuild_function_type_refs(db) == 0
        assert len(observed_sets) == 2
        assert observed_sets[0] is observed_sets[1]
        assert observed_sets[0] == {"ProjectType"}
    finally:
        db.close()


def test_derived_rebuild_skips_semantic_tokens_when_functions_have_no_candidates(
    tmp_path,
    monkeypatch,
) -> None:
    source = tmp_path / "quiet.c"
    source.write_text("int quiet(void) { return 0; }\n", encoding="utf-8")
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        db.insert_function("quiet", "quiet.c", 1, 1, signature="int quiet(void)")
        db.insert_global_variable("unused_global", "int", "quiet.c", 1)
        db.commit()
        extractor = ClangExtractor(project_root=tmp_path)
        monkeypatch.setattr(
            extractor,
            "open_document",
            lambda _path: (_ for _ in ()).throw(
                AssertionError("candidate-free files must not be opened in clangd")
            ),
        )

        assert extractor.rebuild_function_symbol_refs(db) == 0

        stats = extractor.get_last_derived_stats("function_symbol_context")
        assert stats["files_skipped_no_candidates"] == 1
        assert stats["semantic_requests"] == 0
    finally:
        db.close()


def test_combined_derived_rebuild_uses_one_semantic_request_per_file(
    tmp_path,
    monkeypatch,
) -> None:
    source = tmp_path / "combined.c"
    source.write_text(
        "struct ProjectType { int value; };\n"
        "int shared;\n"
        "void entry(ProjectType *item) { shared = item->value; }\n",
        encoding="utf-8",
    )
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        db.insert_function(
            "entry",
            "combined.c",
            3,
            3,
            signature="void entry(ProjectType *item)",
        )
        db.insert_global_variable("shared", "int", "combined.c", 2)
        db.insert_type("ProjectType", "struct", "combined.c", 1, 1)
        db.commit()
        db.begin_derived_index_rebuild("function_symbol_context", "test")
        db.prepare_derived_index_staging("function_symbol_context")
        db.begin_derived_index_rebuild("function_type_refs", "test")
        db.prepare_derived_index_staging("function_type_refs")

        extractor = ClangExtractor(project_root=tmp_path)
        semantic_calls = 0

        def semantic_tokens(_path):
            nonlocal semantic_calls
            semantic_calls += 1
            return {"data": []}

        monkeypatch.setattr(extractor, "open_document", lambda _path: True)
        monkeypatch.setattr(extractor, "close_document", lambda _path: None)
        monkeypatch.setattr(extractor, "get_semantic_tokens", semantic_tokens)
        monkeypatch.setattr(extractor, "get_definition", lambda *_args: None)

        result = extractor.rebuild_function_derived_refs(db, use_staging=True)

        assert result["errors"] == {}
        assert semantic_calls == 1
        assert extractor.get_last_derived_stats("function_symbol_context")[
            "semantic_requests"
        ] == 1
        assert extractor.get_last_derived_stats("function_type_refs")[
            "semantic_requests"
        ] == 1
    finally:
        db.close()


def test_type_declaration_scan_avoids_whitespace_backtracking(tmp_path) -> None:
    source = tmp_path / "adversarial.c"
    source.write_text(
        "int f(void) {\n"
        "    RuntimeEvent *event = 0;\n"
        "    RuntimeEvent*compact = event;\n"
        "    RuntimeEvent const * volatile &qualified = event;\n"
        "    Type" + (" " * 24) + "value)\n"
        "    return event != 0;\n"
        "}\n",
        encoding="utf-8",
    )
    extractor = ClangExtractor(project_root=tmp_path)
    lines = source.read_text(encoding="utf-8").splitlines(True)

    started = time.monotonic()
    candidates = extractor._direct_function_type_candidates(
        {"name": "f", "start_line": 1, "end_line": 7, "signature": "int f(void)"},
        lines,
        {"RuntimeEvent", "Type"},
    )
    elapsed = time.monotonic() - started

    assert {item["name"] for item in candidates} == {"RuntimeEvent"}
    assert sum(item["kind"] == "local" for item in candidates) == 3
    assert elapsed < 0.5


def test_reference_cache_returns_same_set_and_uses_coordinate_index(
    tmp_path,
    monkeypatch,
) -> None:
    source = tmp_path / "use.c"
    declaration = tmp_path / "globals.h"
    text = "int f(void) { return shared; }\n"
    source.write_text(text, encoding="utf-8")
    declaration.write_text("extern int shared;\n", encoding="utf-8")
    character = text.index("shared")
    candidate = {"name": "shared", "file_path": "globals.h", "line": 1}
    extractor = ClangExtractor(project_root=tmp_path)
    monkeypatch.setattr(
        extractor,
        "get_references",
        lambda *_args, **_kwargs: [
            {
                "uri": source.as_uri(),
                "range": {
                    "start": {"line": 0, "character": character},
                    "end": {"line": 0, "character": character + 6},
                },
            }
        ],
        raising=False,
    )
    context = extractor._new_derived_resolution_caches()
    stats = {"references_requests": 0}

    first = extractor._candidate_reference_locations(
        candidate,
        kind="global",
        semantic_context=context,
        stats=stats,
    )
    second = extractor._candidate_reference_locations(
        candidate,
        kind="global",
        semantic_context=context,
        stats=stats,
    )

    assert second is first
    assert stats["references_requests"] == 1
    assert (
        extractor._resolve_candidate_by_references(
            [candidate],
            kind="global",
            source_path=source,
            line=1,
            character=character,
            semantic_context=context,
            stats=stats,
        )
        is candidate
    )
    assert stats["references_requests"] == 1


def test_reference_cache_eviction_removes_stale_reverse_coordinates(
    tmp_path,
    monkeypatch,
) -> None:
    extractor = ClangExtractor(project_root=tmp_path)
    monkeypatch.setattr(extractor, "_DERIVED_REFERENCE_CACHE_MAX_ENTRIES", 1)
    first_key = ("global", ("usr", "global", "first"))
    second_key = ("global", ("usr", "global", "second"))
    first_location = ("first.c", 1, 0)
    second_location = ("second.c", 2, 1)
    first_coordinate = extractor._reference_coordinate("global", *first_location)
    second_coordinate = extractor._reference_coordinate("global", *second_location)
    semantic_context = {
        "reference_cache": OrderedDict(
            [(first_key, {first_location}), (second_key, {second_location})]
        ),
        "reference_coordinate_index": {
            first_coordinate: {first_key[1]},
            second_coordinate: {second_key[1]},
        },
        "reference_indexed_keys": {first_key, second_key},
    }
    stats = {"reference_cache_evictions": 0}

    extractor._trim_reference_resolution_cache(semantic_context, stats)

    assert list(semantic_context["reference_cache"]) == [second_key]
    assert first_coordinate not in semantic_context["reference_coordinate_index"]
    assert semantic_context["reference_coordinate_index"][second_coordinate] == {
        second_key[1]
    }
    assert stats["reference_cache_evictions"] == 1


def test_reference_location_conversion_reads_each_target_file_once(
    tmp_path,
    monkeypatch,
) -> None:
    source = tmp_path / "use.c"
    declaration = tmp_path / "globals.h"
    source.write_text("int f(void) { return shared; }\n", encoding="utf-8")
    declaration.write_text("extern int shared;\n", encoding="utf-8")
    extractor = ClangExtractor(project_root=tmp_path)
    raw_locations = [
        {
            "uri": source.as_uri(),
            "range": {
                "start": {"line": 0, "character": 21},
                "end": {"line": 0, "character": 27},
            },
        }
        for _ in range(100)
    ]
    monkeypatch.setattr(
        extractor,
        "get_references",
        lambda *_args, **_kwargs: raw_locations,
        raising=False,
    )
    original_read_lines = extractor._read_source_lines
    target_reads = 0

    def counted_read_lines(path):
        nonlocal target_reads
        if Path(path).resolve() == source.resolve():
            target_reads += 1
        return original_read_lines(path)

    monkeypatch.setattr(extractor, "_read_source_lines", counted_read_lines)

    extractor._candidate_reference_locations(
        {"name": "shared", "file_path": "globals.h", "line": 1},
        kind="global",
        semantic_context=extractor._new_derived_resolution_caches(),
        stats={"references_requests": 0},
    )

    assert target_reads == 1


def test_usr_groups_only_positive_redeclarations_after_reverse_reference_lookup(
    tmp_path,
    monkeypatch,
) -> None:
    source = tmp_path / "use.c"
    declaration = tmp_path / "shared.h"
    definition = tmp_path / "shared.c"
    text = "int f(void) { return shared; }\n"
    source.write_text(text, encoding="utf-8")
    declaration.write_text("extern int shared;\n", encoding="utf-8")
    definition.write_text("int shared = 1;\n", encoding="utf-8")
    character = text.index("shared")
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        db.insert_function("f", "use.c", 1, 1, signature="int f(void)")
        db.insert_global_variable("shared", "int", "shared.h", 1, is_extern=True)
        db.insert_global_variable(
            "shared",
            "int",
            "shared.c",
            1,
            initializer="1",
            definition_kind="definition",
        )
        db.commit()
        extractor = ClangExtractor(project_root=tmp_path)
        calls = _configure_semantics(
            extractor,
            monkeypatch,
            _semantic_data(0, [character]),
            token_types=["variable"],
            modifiers=[],
        )
        symbol_info_calls: list[Path] = []
        reference_calls: list[Path] = []

        def symbol_info(path, *_args, **_kwargs):
            symbol_info_calls.append(Path(path))
            return {"name": "shared", "usr": "c:@shared"}

        def references(path, *_args, **_kwargs):
            reference_calls.append(Path(path))
            return [
                {
                    "uri": source.as_uri(),
                    "range": {
                        "start": {"line": 0, "character": character},
                        "end": {"line": 0, "character": character + 6},
                    },
                }
            ]

        monkeypatch.setattr(extractor, "get_symbol_info", symbol_info, raising=False)
        monkeypatch.setattr(extractor, "get_references", references, raising=False)

        assert extractor.rebuild_function_symbol_refs(db) == 1
        context = db.get_function_symbol_context("f", "use.c")
        assert context["referenced_globals"][0]["file_path"] == "shared.c"
        assert sorted(path.name for path in symbol_info_calls) == ["shared.c", "shared.h", "use.c"]
        assert sorted(path.name for path in reference_calls) == ["shared.c", "shared.h", "use.c"]
        assert calls == {"semantic": 1, "definition": 1}
        assert all(
            not semantic_context["reference_cache"]
            and not semantic_context["reference_coordinate_index"]
            for semantic_context in extractor._semantic_context_cache.values()
        )
    finally:
        db.close()


def test_usr_groups_redeclarations_across_many_occurrences(
    tmp_path,
    monkeypatch,
) -> None:
    source = tmp_path / "many.c"
    declaration = tmp_path / "shared.h"
    definition = tmp_path / "shared.c"
    text = "int f(void) { return shared + shared + shared; }\n"
    source.write_text(text, encoding="utf-8")
    declaration.write_text("extern int shared;\n", encoding="utf-8")
    definition.write_text("int shared = 1;\n", encoding="utf-8")
    starts = [match.start() for match in re.finditer(r"\bshared\b", text)]
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        db.insert_function("f", "many.c", 1, 1, signature="int f(void)")
        db.insert_global_variable("shared", "int", "shared.h", 1, is_extern=True)
        db.insert_global_variable(
            "shared",
            "int",
            "shared.c",
            1,
            initializer="1",
            definition_kind="definition",
        )
        db.commit()
        extractor = ClangExtractor(project_root=tmp_path)
        _configure_semantics(
            extractor,
            monkeypatch,
            _semantic_data(0, starts),
            token_types=["variable"],
            modifiers=[],
        )
        symbol_info_calls: list[Path] = []
        reference_calls: list[Path] = []

        def symbol_info(path, *_args, **_kwargs):
            symbol_info_calls.append(Path(path))
            return {"usr": "c:@shared"}

        def references(path, *_args, **_kwargs):
            reference_calls.append(Path(path))
            return [
                {
                    "uri": source.as_uri(),
                    "range": {
                        "start": {"line": 0, "character": start},
                        "end": {"line": 0, "character": start + 6},
                    },
                }
                for start in starts
            ]

        monkeypatch.setattr(extractor, "get_symbol_info", symbol_info, raising=False)
        monkeypatch.setattr(extractor, "get_references", references, raising=False)

        assert extractor.rebuild_function_symbol_refs(db) == 1
        stats = extractor.get_last_derived_stats("function_symbol_context")
        assert len(symbol_info_calls) == 5
        # One forward query per USR/TU, then one query per declaration. Only
        # the two positive declarations need symbolInfo for alias equivalence.
        assert len(reference_calls) == 3
        assert stats["usr_resolved"] == 3
        assert stats["definition_requests"] == 3
    finally:
        db.close()


def test_visibility_results_are_cached_per_source_and_candidate_list(
    tmp_path,
    monkeypatch,
) -> None:
    extractor = ClangExtractor(project_root=tmp_path)
    candidates = [{"name": "g", "file_path": "include/shared.h", "line": 1}]
    context = extractor._new_derived_resolution_caches()
    first = extractor._visible_candidates(
        candidates,
        "src/use.c",
        ["src/use.c", "include/shared.h"],
        context,
    )
    monkeypatch.setattr(
        extractor,
        "_paths_match",
        lambda *_args: (_ for _ in ()).throw(AssertionError("visibility cache was missed")),
    )

    second = extractor._visible_candidates(
        candidates,
        "src/use.c",
        ["src/use.c", "include/shared.h"],
        context,
    )

    assert second is first


def test_type_rebuild_runs_files_concurrently_and_stages_on_caller_thread(
    tmp_path,
    monkeypatch,
) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    type_ids: dict[str, int] = {}
    try:
        for index in range(4):
            type_name = f"ProjectType{index}"
            source = tmp_path / f"unit_{index}.c"
            source.write_text(
                f"struct {type_name} {{ int value; }};\n"
                f"int f{index}({type_name} *item) {{ return item->value; }}\n",
                encoding="utf-8",
            )
            db.insert_function(
                f"f{index}",
                source.name,
                2,
                2,
                signature=f"int f{index}({type_name} *item)",
            )
            type_ids[type_name] = int(
                db.insert_type(
                    type_name,
                    "struct",
                    source.name,
                    1,
                    1,
                    full_definition=f"struct {type_name} {{ int value; }};",
                )
            )
        db.commit()
        db.begin_derived_index_rebuild("function_type_refs", "parallel-test")
        db.prepare_derived_index_staging("function_type_refs")

        extractor = ClangExtractor(project_root=tmp_path, max_threads=4)
        monkeypatch.setattr(extractor, "open_document", lambda _path: False)
        active = 0
        max_active = 0
        active_lock = threading.Lock()
        concurrent = threading.Event()

        def collect(function, function_file, _source_path, _lines, types_by_name, *_args):
            nonlocal active, max_active
            with active_lock:
                active += 1
                max_active = max(max_active, active)
                if active >= 2:
                    concurrent.set()
            assert concurrent.wait(2.0), "type files were processed serially"
            type_name = f"ProjectType{str(function['name'])[1:]}"
            record = types_by_name[type_name][0]
            row = (
                int(function["id"]),
                type_ids[type_name],
                KnowledgeDB.type_index_name(record),
                type_name,
                function_file,
                2,
                "signature",
                "",
            )
            with active_lock:
                active -= 1
            return [row]

        monkeypatch.setattr(extractor, "_collect_function_type_refs", collect)
        caller_thread = threading.get_ident()
        staged_rows: list[tuple] = []
        original_stage = db.stage_function_type_refs_batch

        def stage(rows):
            assert threading.get_ident() == caller_thread
            staged_rows.extend(rows)
            original_stage(rows)

        monkeypatch.setattr(db, "stage_function_type_refs_batch", stage)

        assert extractor.rebuild_function_type_refs(db, use_staging=True) == 4
        assert len(staged_rows) == 4
        assert 2 <= max_active <= 4
        stats = extractor.get_last_derived_stats("function_type_refs")
        assert stats["worker_count"] == 4
        assert 2 <= stats["peak_inflight_files"] <= 4
        assert ClangExtractor(project_root=tmp_path, max_threads=32)._derived_worker_count(20) == 8
    finally:
        db.close()


def test_symbol_rebuild_runs_files_concurrently(tmp_path, monkeypatch) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        for index in range(2):
            source = tmp_path / f"symbol_{index}.c"
            source.write_text(
                f"int shared_{index};\n"
                f"int f{index}(void) {{ return shared_{index}; }}\n",
                encoding="utf-8",
            )
            db.insert_function(f"f{index}", source.name, 2, 2, signature=f"int f{index}(void)")
            db.insert_global_variable(f"shared_{index}", "int", source.name, 1)
        db.commit()
        db.begin_derived_index_rebuild("function_symbol_context", "parallel-test")
        db.prepare_derived_index_staging("function_symbol_context")

        extractor = ClangExtractor(project_root=tmp_path, max_threads=2)
        monkeypatch.setattr(extractor, "open_document", lambda _path: False)
        concurrent = threading.Event()
        active = 0
        lock = threading.Lock()

        def collect(function, function_file, *_args):
            nonlocal active
            aggregated = _args[4]
            with lock:
                active += 1
                if active >= 2:
                    concurrent.set()
            assert concurrent.wait(2.0), "symbol files were processed serially"
            symbol_name = f"shared_{str(function['name'])[1:]}"
            aggregated[(function["name"], function_file, symbol_name, "global", function_file, 2)] = (
                "read"
            )
            with lock:
                active -= 1

        monkeypatch.setattr(extractor, "_collect_function_symbol_refs", collect)

        assert extractor.rebuild_function_symbol_refs(db, use_staging=True) == 2
        stats = extractor.get_last_derived_stats("function_symbol_context")
        assert stats["worker_count"] == 2
        assert stats["peak_inflight_files"] == 2
    finally:
        db.close()


def test_combined_rebuild_parallelizes_files_but_requests_semantics_once_per_file(
    tmp_path,
    monkeypatch,
) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        for index in range(2):
            source = tmp_path / f"combined_{index}.c"
            source.write_text(
                f"struct ProjectType{index} {{ int value; }};\n"
                f"int shared_{index};\n"
                f"void f{index}(ProjectType{index} *item) {{ shared_{index} = item->value; }}\n",
                encoding="utf-8",
            )
            db.insert_function(
                f"f{index}",
                source.name,
                3,
                3,
                signature=f"void f{index}(ProjectType{index} *item)",
            )
            db.insert_global_variable(f"shared_{index}", "int", source.name, 2)
            db.insert_type(f"ProjectType{index}", "struct", source.name, 1, 1)
        db.commit()
        for index_name in ("function_symbol_context", "function_type_refs"):
            db.begin_derived_index_rebuild(index_name, "parallel-test")
            db.prepare_derived_index_staging(index_name)

        extractor = ClangExtractor(project_root=tmp_path, max_threads=2)
        monkeypatch.setattr(extractor, "open_document", lambda _path: True)
        closed: list[Path] = []
        monkeypatch.setattr(extractor, "close_document", lambda path: closed.append(Path(path)))
        semantic_calls = 0
        semantic_active = 0
        semantic_lock = threading.Lock()
        concurrent = threading.Event()

        def semantic_tokens(_path):
            nonlocal semantic_calls, semantic_active
            with semantic_lock:
                semantic_calls += 1
                semantic_active += 1
                if semantic_active >= 2:
                    concurrent.set()
            assert concurrent.wait(2.0), "combined files were processed serially"
            with semantic_lock:
                semantic_active -= 1
            return {"data": []}

        monkeypatch.setattr(extractor, "get_semantic_tokens", semantic_tokens)

        def collect_symbols(function, function_file, *_args):
            aggregated = _args[4]
            symbol_name = f"shared_{str(function['name'])[1:]}"
            aggregated[(function["name"], function_file, symbol_name, "global", function_file, 3)] = (
                "write"
            )

        def collect_types(function, function_file, _source_path, _lines, types_by_name, *_args):
            type_name = f"ProjectType{str(function['name'])[1:]}"
            record = types_by_name[type_name][0]
            return [
                (
                    int(function["id"]),
                    int(record["id"]),
                    KnowledgeDB.type_index_name(record),
                    type_name,
                    function_file,
                    3,
                    "signature",
                    "",
                )
            ]

        monkeypatch.setattr(extractor, "_collect_function_symbol_refs", collect_symbols)
        monkeypatch.setattr(extractor, "_collect_function_type_refs", collect_types)

        result = extractor.rebuild_function_derived_refs(db, use_staging=True)

        assert result["errors"] == {}
        assert result["counts"] == {
            "function_symbol_context": 2,
            "function_type_refs": 2,
        }
        assert semantic_calls == 2
        assert sorted(path.name for path in closed) == ["combined_0.c", "combined_1.c"]
        for index_name in ("function_symbol_context", "function_type_refs"):
            stats = extractor.get_last_derived_stats(index_name)
            assert stats["semantic_requests"] == 2
            assert stats["worker_count"] == 2
            assert stats["peak_inflight_files"] == 2
    finally:
        db.close()


def test_shared_reference_cache_single_flights_concurrent_declaration_queries(
    tmp_path,
    monkeypatch,
) -> None:
    source = tmp_path / "use.c"
    declaration = tmp_path / "shared.h"
    source.write_text("int f(void) { return shared; }\n", encoding="utf-8")
    declaration.write_text("extern int shared;\n", encoding="utf-8")
    character = source.read_text(encoding="utf-8").index("shared")
    extractor = ClangExtractor(project_root=tmp_path)
    context = extractor._new_derived_resolution_caches()
    calls = 0
    request_started = threading.Event()
    release_request = threading.Event()

    def references(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        request_started.set()
        assert release_request.wait(2.0)
        return [
            {
                "uri": source.as_uri(),
                "range": {
                    "start": {"line": 0, "character": character},
                    "end": {"line": 0, "character": character + 6},
                },
            }
        ]

    monkeypatch.setattr(extractor, "get_references", references, raising=False)
    candidate = {"name": "shared", "file_path": "shared.h", "line": 1}
    results: list[set[tuple[str, int, int]]] = []
    errors: list[BaseException] = []

    def resolve() -> None:
        try:
            results.append(
                extractor._candidate_reference_locations(
                    candidate,
                    kind="global",
                    semantic_context=context,
                    stats={"references_requests": 0, "reference_cache_evictions": 0},
                )
            )
        except BaseException as exc:
            errors.append(exc)

    first = threading.Thread(target=resolve)
    second = threading.Thread(target=resolve)
    first.start()
    assert request_started.wait(2.0)
    second.start()
    time.sleep(0.02)
    assert calls == 1
    release_request.set()
    first.join(2.0)
    second.join(2.0)

    assert errors == []
    assert calls == 1
    assert len(results) == 2
    assert results[0] is results[1]


def test_semantic_token_decoding_uses_each_worker_source_lines(tmp_path, monkeypatch) -> None:
    sources = {
        tmp_path / "alpha.c": "α Type\n",
        tmp_path / "emoji.c": "😀😀 Type\n",
    }
    for source, text in sources.items():
        source.write_text(text, encoding="utf-8")
    extractor = ClangExtractor(project_root=tmp_path, max_threads=2)
    extractor._position_encoding = "utf-8"
    extractor._semantic_token_types = ["type"]
    simultaneous = threading.Barrier(2)

    def semantic_tokens(path):
        simultaneous.wait(timeout=2.0)
        text = sources[Path(path)]
        python_start = text.index("Type")
        byte_start = len(text[:python_start].encode("utf-8"))
        return {"data": [0, byte_start, 4, 0, 0]}

    monkeypatch.setattr(extractor, "get_semantic_tokens", semantic_tokens, raising=False)
    contexts: dict[Path, dict] = {}

    def load(source: Path) -> None:
        contexts[source] = extractor._get_file_semantic_context(
            source,
            sources[source].splitlines(True),
        )

    threads = [threading.Thread(target=load, args=(source,)) for source in sources]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(2.0)

    assert set(contexts) == set(sources)
    for source, text in sources.items():
        token = contexts[source]["tokens_by_line"][1][0]
        assert token["start"] == text.index("Type")
        assert token["end"] == text.index("Type") + len("Type")


def test_type_rebuild_parallel_and_serial_results_are_equivalent(tmp_path, monkeypatch) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        for index in range(4):
            type_name = f"ProjectType{index}"
            source = tmp_path / f"equivalent_{index}.c"
            source.write_text(
                f"struct {type_name} {{ int value; }};\n"
                f"int f{index}({type_name} *item) {{ return sizeof({type_name}); }}\n",
                encoding="utf-8",
            )
            db.insert_function(
                f"f{index}",
                source.name,
                2,
                2,
                signature=f"int f{index}({type_name} *item)",
            )
            db.insert_type(
                type_name,
                "struct",
                source.name,
                1,
                1,
                full_definition=f"struct {type_name} {{ int value; }};",
            )
        db.commit()

        def run(worker_count: int):
            extractor = ClangExtractor(project_root=tmp_path, max_threads=worker_count)
            monkeypatch.setattr(extractor, "open_document", lambda _path: False)
            monkeypatch.setattr(
                extractor,
                "get_definition",
                lambda path, *_args: [
                    {
                        "uri": Path(path).as_uri(),
                        "range": {
                            "start": {"line": 0, "character": 7},
                            "end": {"line": 0, "character": 19},
                        },
                    }
                ],
            )
            row_count = extractor.rebuild_function_type_refs(db)
            rows = [
                tuple(row)
                for row in db._conn.execute(
                    "SELECT function_id, type_id, type_index_name, referenced_name, "
                    "reference_file, reference_line, reference_kind, resolution_reason "
                    "FROM function_type_refs ORDER BY function_id, referenced_name, "
                    "reference_line, reference_kind"
                ).fetchall()
            ]
            return row_count, rows, extractor.get_last_derived_stats("function_type_refs")

        serial_count, serial_rows, serial_stats = run(1)
        parallel_count, parallel_rows, parallel_stats = run(4)

        assert parallel_count == serial_count
        assert parallel_rows == serial_rows
        for key in (
            "files_processed",
            "functions_processed",
            "candidates",
            "semantic_resolved",
            "local_resolved",
            "references_requests",
            "references_resolved",
            "definition_requests",
            "definition_timeouts",
            "unresolved_reasons",
        ):
            assert parallel_stats[key] == serial_stats[key]
        assert serial_stats["worker_count"] == 1
        assert parallel_stats["worker_count"] == 4
    finally:
        db.close()


def test_combined_parallel_failure_stops_only_failed_index(tmp_path, monkeypatch) -> None:
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        for index in range(2):
            source = tmp_path / f"partial_{index}.c"
            source.write_text(
                f"struct ProjectType{index} {{ int value; }};\n"
                f"int shared_{index};\n"
                f"void f{index}(ProjectType{index} *item) {{ shared_{index} = item->value; }}\n",
                encoding="utf-8",
            )
            db.insert_function(
                f"f{index}",
                source.name,
                3,
                3,
                signature=f"void f{index}(ProjectType{index} *item)",
            )
            db.insert_global_variable(f"shared_{index}", "int", source.name, 2)
            db.insert_type(f"ProjectType{index}", "struct", source.name, 1, 1)
        db.commit()
        for index_name in ("function_symbol_context", "function_type_refs"):
            db.begin_derived_index_rebuild(index_name, "parallel-test")
            db.prepare_derived_index_staging(index_name)

        extractor = ClangExtractor(project_root=tmp_path, max_threads=2)
        monkeypatch.setattr(extractor, "open_document", lambda _path: False)

        def collect_symbols(function, function_file, *_args):
            aggregated = _args[4]
            symbol_name = f"shared_{str(function['name'])[1:]}"
            aggregated[(function["name"], function_file, symbol_name, "global", function_file, 3)] = (
                "write"
            )

        def collect_types(function, *_args):
            if function["name"] == "f0":
                raise RuntimeError("injected type failure")
            return []

        monkeypatch.setattr(extractor, "_collect_function_symbol_refs", collect_symbols)
        monkeypatch.setattr(extractor, "_collect_function_type_refs", collect_types)

        result = extractor.rebuild_function_derived_refs(db, use_staging=True)

        assert "function_symbol_context" not in result["errors"]
        assert "injected type failure" in str(result["errors"]["function_type_refs"])
        assert result["counts"]["function_symbol_context"] == 2
        assert (
            db._conn.execute("SELECT COUNT(*) FROM zscope_stage_function_symbol_refs").fetchone()[0]
            == 2
        )
    finally:
        db.close()


def test_shared_resolution_single_flight_propagates_owner_error_to_waiter(
    tmp_path,
) -> None:
    extractor = ClangExtractor(project_root=tmp_path)
    context = extractor._new_derived_resolution_caches()
    started = threading.Event()
    release = threading.Event()
    calls = 0
    errors: list[BaseException] = []

    def compute():
        nonlocal calls
        calls += 1
        started.set()
        assert release.wait(2.0)
        raise RuntimeError("single-flight failure")

    def resolve() -> None:
        try:
            extractor._shared_resolution_cache_get_or_compute(
                context,
                "visibility_cache",
                "shared-key",
                compute,
            )
        except BaseException as exc:
            errors.append(exc)

    owner = threading.Thread(target=resolve)
    waiter = threading.Thread(target=resolve)
    owner.start()
    assert started.wait(2.0)
    waiter.start()
    time.sleep(0.02)
    assert calls == 1
    release.set()
    owner.join(2.0)
    waiter.join(2.0)

    assert calls == 1
    assert len(errors) == 2
    assert all("single-flight failure" in str(error) for error in errors)


def test_definition_timeout_outcomes_are_worker_local(tmp_path, monkeypatch) -> None:
    source = tmp_path / "timeouts.c"
    source.write_text("int f(void) { return value; }\n", encoding="utf-8")
    extractor = ClangExtractor(project_root=tmp_path)
    barrier = threading.Barrier(2)

    def definitions(*_args):
        barrier.wait(timeout=2.0)
        extractor._record_thread_request_outcome(
            "textDocument/definition",
            timed_out=True,
        )
        return []

    monkeypatch.setattr(extractor, "_definition_locations", definitions)
    worker_stats = [extractor._new_derived_worker_stats("function_type_refs") for _ in range(2)]

    def resolve(index: int) -> None:
        extractor._definition_locations_cached(
            source,
            1,
            index,
            {"definition_cache": {}},
            worker_stats[index],
        )

    threads = [threading.Thread(target=resolve, args=(index,)) for index in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(2.0)

    merged = extractor._new_derived_stats("function_type_refs", 0, 0)
    for stats in worker_stats:
        extractor._merge_derived_stats(merged, stats)
    assert merged["definition_requests"] == 2
    assert merged["definition_timeouts"] == 2
