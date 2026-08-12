import re
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


def test_reverse_references_resolve_ambiguous_declaration_without_definition(
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
        assert calls == {"semantic": 1, "definition": 0}
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
    source.write_text(text, encoding="utf-8")
    type_starts = [text.index("T"), text.rindex("T")]
    global_start = text.index("g")
    data = _semantic_records(
        0,
        [(start, 1, 1) for start in type_starts] + [(global_start, 0, 1)],
    )
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    try:
        db.insert_function("f", "shared.cpp", 1, 1, signature="int f(T *value)")
        db.insert_global_variable("g", "int", "shared.cpp", 1)
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
            db.get_function_type_context("f", "shared.cpp", 1)["referenced_types"][0]["name"] == "T"
        )
    finally:
        db.close()


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
