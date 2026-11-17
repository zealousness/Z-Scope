"""Source-tool review regressions using actual Linux files and symlinks."""

from types import SimpleNamespace
import time

import pytest

from zscope.tools.read_code import ReadCodeTool
from zscope.tools.registry import build_tool_registry
from zscope.tools.search_code import SearchCodeTool
from zscope.tools.source_access import ProjectSourceAccess, SourceAccessError, source_lines
from zscope.tools.symbols import SymbolCatalog, macro_metadata
from zscope.tools import symbols


def index(root, **overrides):
    return SimpleNamespace(project_root=root, _index_epoch=1, _function_index={}, **overrides)


def test_relative_exclusions_are_bound_to_project_not_process_directory(tmp_path, monkeypatch):
    root = tmp_path / "project"
    (root / "private").mkdir(parents=True)
    (root / "private" / "secret.c").write_text("hidden needle\n")
    monkeypatch.chdir(tmp_path)
    access = ProjectSourceAccess(root, excluded=["private"])
    assert not access.allowed("private/secret.c")
    with pytest.raises(SourceAccessError, match="corpus_denied"):
        access.read("private/secret.c")
    assert access.search({"scope": "text", "query": "needle"})["data"]["matches"] == []


def test_text_search_prefix_matches_a_path_component_and_dot_means_root(tmp_path):
    for name in ("src", "src-other"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "unit.c").write_text("needle\n")
    access = ProjectSourceAccess(tmp_path)
    result = access.search({"scope": "text", "query": "needle", "path_prefix": "./src/"})
    assert [hit["file"] for hit in result["data"]["matches"]] == ["src/unit.c"]
    result = access.search({"scope": "text", "query": "needle", "path_prefix": "."})
    assert len(result["data"]["matches"]) == 2


@pytest.mark.parametrize("separator", ["\u2028", "\v", "\f"])
def test_source_coordinates_only_count_physical_newlines(tmp_path, separator):
    text = f'const char *s = "a{separator}b";\r\nint sink;\n'
    (tmp_path / "unit.c").write_bytes(text.encode("utf-8"))
    access = ProjectSourceAccess(tmp_path)
    result = access.search({"scope": "text", "query": "sink"})
    assert result["data"]["matches"][0]["line"] == 2
    snippet = access.snippet("unit.c", 2, 2, 10)
    assert snippet["code"] == "2 | int sink;\n"
    assert snippet["total_lines"] == 2
    assert source_lines(text) == [text[: text.index("\n") + 1], "int sink;\n"]


@pytest.mark.parametrize(
    "text,expected",
    [("", []), ("\n", ["\n"]), ("a\rb\r\nc\nlast", ["a\r", "b\r\n", "c\n", "last"])],
)
def test_source_lines_retains_terminators_and_does_not_add_an_eof_line(text, expected):
    assert source_lines(text) == expected


def test_replaced_project_parent_cannot_redirect_reads_outside_the_original_root(tmp_path):
    parent = tmp_path / "parent"
    root = parent / "project"
    root.mkdir(parents=True)
    (root / "unit.c").write_text("safe\n")
    outside = tmp_path / "outside"
    (outside / "project").mkdir(parents=True)
    (outside / "project" / "unit.c").write_text("OUTSIDE_CONTENT\n")
    access = ProjectSourceAccess(root)
    assert access.read("unit.c")[0] == "safe\n"
    parent.rename(tmp_path / "original")
    parent.symlink_to(outside, target_is_directory=True)
    with pytest.raises(SourceAccessError, match="project_root_changed"):
        access.read("unit.c")
    result = access.search({"scope": "text", "query": "OUTSIDE_CONTENT"})
    assert result["status"] == "partial"
    assert result["data"]["matches"] == []


def test_cached_symbols_recheck_the_current_corpus_permission(tmp_path):
    catalog = SymbolCatalog(index(tmp_path))
    catalog.code_index._function_index["f"] = {
        "name": "f",
        "file": "unit.c",
        "start_line": 1,
        "end_line": 1,
    }
    allowed = [True]
    catalog.permitted_source = lambda path: allowed[0]
    symbol = catalog.search("f", ["function"], "exact", None)[0]
    allowed[0] = False
    assert catalog.search("f", ["function"], "exact", None) == []
    assert catalog.resolve(symbol["symbol_id"]) is None
    assert catalog.resolve_cached(symbol["symbol_id"]) is None
    allowed[0] = True
    assert catalog.resolve(symbol["symbol_id"])["name"] == "f"


@pytest.mark.parametrize("profile", ["default", "read_only", "candidate_blind"])
def test_all_symbol_profiles_hide_private_macros_and_preserve_only_permitted_external_contracts(
    tmp_path, profile
):
    (tmp_path / ".env.h").write_text('#define HIDDEN "DO_NOT_EXPOSE"\n')
    code_index = index(
        tmp_path,
        _get_macro_definition_index=lambda: {
            "HIDDEN": [
                {
                    "name": "HIDDEN",
                    "file_path": ".env.h",
                    "start_line": 1,
                    "definition": '#define HIDDEN "DO_NOT_EXPOSE"',
                }
            ]
        },
    )
    config = SimpleNamespace(
        list_external_functions=lambda: [{"function_name": "external_api", "ownership": "caller"}]
    )
    tools = build_tool_registry(
        code_index,
        SimpleNamespace(snapshot_dir=tmp_path),
        user_config=config,
        access_profile=profile,
    )
    private = tools["search_code"].execute({"query": "HIDDEN", "kinds": ["macro"]})
    assert private["status"] == "not_found"
    assert "DO_NOT_EXPOSE" not in str(private)
    external = tools["search_code"].execute({"query": "external_api", "kinds": ["function"]})
    if profile == "default":
        symbol = external["data"]["symbols"][0]
        read = tools["read_code"].execute({"symbol_id": symbol["symbol_id"]})
        assert read["data"]["definition"]["contract"]["ownership"] == "caller"
    else:
        assert external["data"]["symbols"] == []


def test_symbol_prefix_uses_the_same_normalized_components_as_source_search(tmp_path):
    code_index = index(tmp_path)
    code_index._function_index["f"] = {
        "name": "f",
        "file": "src/unit.c",
        "start_line": 1,
        "end_line": 1,
    }
    symbols = SymbolCatalog(code_index).search("f", ["function"], "exact", "./src//")
    assert len(symbols) == 1


@pytest.mark.parametrize("mode,query", [("substring", "TAIL_TOKEN"), ("regex", "TAIL_TOKEN$")])
def test_symbol_search_matches_the_tail_of_a_long_template_signature(tmp_path, mode, query):
    code_index = index(tmp_path)
    signature = "template<" + "X," * 2500 + "> TAIL_TOKEN"
    code_index._function_index["f"] = {"name": "f", "file": "unit.c", "signature": signature}
    tool = SearchCodeTool(SymbolCatalog(code_index))
    result = tool.execute({"query": query, "match_mode": mode})
    assert result["status"] == "ok"
    assert result["data"]["symbols"][0]["signature"] == signature


def test_drive_relative_paths_are_rejected_at_the_public_tool_boundary(tmp_path):
    code_index = index(tmp_path)
    read = ReadCodeTool(code_index, SymbolCatalog(code_index))
    assert (
        read.validate_arguments({"file_path": "C:outside.c", "start_line": 1})["error"]["code"]
        == "invalid_project_path"
    )


def test_oversized_regex_repeat_is_an_argument_error_instead_of_an_execution_failure(tmp_path):
    search = SearchCodeTool(SymbolCatalog(index(tmp_path)))
    result = search.validate_arguments({"query": "a{4294967296}", "match_mode": "regex"})
    assert result["status"] == "invalid_request"
    assert result["error"]["code"] == "invalid_regex"


def test_ambiguous_regex_cannot_block_the_symbol_query(tmp_path, monkeypatch):
    code_index = index(tmp_path)
    code_index._function_index["long"] = {"name": "a" * 200 + "!", "file": "unit.c"}
    tool = SearchCodeTool(SymbolCatalog(code_index))
    args = {"query": "(a|aa)+$", "match_mode": "regex"}
    assert tool.validate_arguments(args) is None
    monkeypatch.setattr(symbols, "_REGEX_QUERY_SECONDS", 0.01)
    started = time.monotonic()
    result = tool.execute(args)
    assert time.monotonic() - started < 1
    assert result["status"] == "invalid_request"
    assert result["error"]["code"] == "regex_query_timeout"
    assert result["data"] is None


def test_regex_deadline_covers_the_whole_query_instead_of_resetting_per_field(
    tmp_path, monkeypatch
):
    clock = [0.0]

    class Pattern:
        def search(self, field, *, timeout):
            clock[0] += 0.4
            return True

    code_index = index(tmp_path)
    code_index._function_index["f"] = {"name": "f", "file": "unit.c"}
    tool = SearchCodeTool(SymbolCatalog(code_index))
    monkeypatch.setattr(symbols.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(symbols.regex, "compile", lambda *args: Pattern())
    result = tool.execute({"query": "f", "match_mode": "regex"})
    assert result["error"]["code"] == "regex_query_timeout"


def test_symbol_end_before_the_resolved_start_is_a_clear_argument_error(tmp_path):
    (tmp_path / "unit.c").write_text("// header\n// header\nint f(void) { return 0; }\n")
    code_index = index(tmp_path)
    code_index._function_index["f"] = {
        "name": "f",
        "file": "unit.c",
        "start_line": 3,
        "end_line": 3,
    }
    catalog = SymbolCatalog(code_index)
    symbol = catalog.search("f", ["function"], "exact", None)[0]
    tool = ReadCodeTool(code_index, catalog)
    args = {"symbol_id": symbol["symbol_id"], "end_line": 1}
    assert tool.validate_arguments(args) is None
    result = tool.execute(args)
    assert result["status"] == "invalid_request"
    assert result["error"]["path"] == "end_line"
    assert tool.validate_result(result) is None


def test_reading_only_the_tail_of_a_symbol_does_not_claim_its_complete_definition(tmp_path):
    (tmp_path / "unit.c").write_text("int f(void) {\n return 0;\n}\n")
    code_index = index(tmp_path)
    code_index._function_index["f"] = {
        "name": "f",
        "file": "unit.c",
        "start_line": 1,
        "end_line": 3,
    }
    catalog = SymbolCatalog(code_index)
    symbol = catalog.search("f", ["function"], "exact", None)[0]
    tool = ReadCodeTool(code_index, catalog)
    full = tool.execute({"symbol_id": symbol["symbol_id"]})
    tail = tool.execute({"symbol_id": symbol["symbol_id"], "start_line": 2})
    assert full["data"]["definition"]["complete"] is True
    assert tail["status"] == "ok"
    assert tail["data"]["source"]["truncated"] is False
    assert tail["data"]["definition"]["complete"] is False


@pytest.mark.parametrize(
    "source,end",
    [
        ("auto VALUE = [] {\n  int local = 1;\n  return local;\n}();\nint after;\n", 4),
        ("struct {\n  int member;\n} VALUE;\nint after;\n", 3),
        ('const char *VALUE =\n  "text; // ; /* ; */";\nint after;\n', 2),
        ('const char *VALUE = R"tag(\n  payload"; still raw\n)tag";\nint after;\n', 3),
    ],
)
def test_global_definition_ends_at_the_outer_declaration_semicolon(tmp_path, source, end):
    (tmp_path / "unit.cpp").write_text(source)
    code_index = index(
        tmp_path,
        _get_global_definition_index=lambda: {
            "VALUE": [
                {
                    "name": "VALUE",
                    "file_path": "unit.cpp",
                    "start_line": 1,
                }
            ]
        },
    )
    catalog = SymbolCatalog(code_index)
    symbol = catalog.search("VALUE", ["global"], "exact", None)[0]
    tool = ReadCodeTool(code_index, catalog)
    result = tool.execute({"symbol_id": symbol["symbol_id"]})
    assert result["status"] == "ok"
    assert result["data"]["source"]["end_line"] == end
    assert "int after" not in result["data"]["source"]["code"]
    assert tool.validate_result(result) is None


def test_ambiguous_scoped_type_details_do_not_fall_back_to_a_different_type(tmp_path):
    (tmp_path / "unit.c").write_text("struct T { int own; };\n")
    details = {"name": "T", "file_path": "unit.c", "start_line": 1, "end_line": 1}
    code_index = index(
        tmp_path,
        _get_regex_type_definition_index=lambda: {"T": [details]},
        find_type_infos=lambda *args, **kwargs: [details, details],
        get_type_info=lambda *args: pytest.fail("ambiguous type replaced by global name lookup"),
    )
    catalog = SymbolCatalog(code_index)
    symbol = catalog.search("T", ["type"], "exact", None)[0]
    result = ReadCodeTool(code_index, catalog).execute({"symbol_id": symbol["symbol_id"]})
    assert result["status"] == "ok"
    assert "members" not in result["data"]


@pytest.mark.parametrize("literal", ["9" * 5000, '"' + "x" * 5000 + '"'])
def test_large_macro_literals_keep_metadata_bounded_without_partial_classification(literal):
    result = macro_metadata("LARGE", "#define LARGE " + literal, False)
    assert result["definition_truncated"]
    assert result["literal"] is None
    assert len(result["definition"]) == len(result["replacement_text"]) == 2000
