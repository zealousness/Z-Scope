"""Exact matching and operation-count regressions for large header API scans."""

import logging
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from zscope.retrieval.code_index import CodeIndex


def make_index(tmp_path, records):
    backend = SimpleNamespace(build_function_index=lambda: records, close=lambda: None)
    return CodeIndex(tmp_path, source_root=tmp_path, backend=backend)


def function(name, file, line=1, params="void"):
    return dict(
        name=name, file=file, start_line=line, end_line=line + 2, signature=f"int {name}({params})"
    )


def scan_match(index, query, file=""):
    """The former scan algorithm is an independent equivalence oracle."""
    variants = index._function_query_variants(query)
    if not file:
        for variant in variants:
            if variant in index._function_index:
                return [(variant, dict(index._function_index[variant]))]
        for variant in variants:
            alias = index._function_alias_index.get(variant)
            if alias in index._function_index:
                return [(alias, dict(index._function_index[alias]))]
    matches = [
        (key, dict(row))
        for key, row in index._function_index.items()
        if (not file or index._record_matches_file_hint(row, file))
        and set(variants) & index._function_record_query_variants(key, row)
    ]
    matches.sort(
        key=lambda item: (
            index._function_info_match_rank(set(variants), *item),
            item[1]["file"],
            item[1]["start_line"],
            item[0],
        )
    )
    return matches


def test_postings_preserve_scan_matching_and_ambiguity(tmp_path):
    records = {
        "a": function("Run", "left/same.c", params="int value"),
        "b": function("Run", "right/same.c", params="char *value"),
        "c": function("app::Box<int>::run", "box.cpp", params="int *value"),
        "d": function("app::Box<float>::run", "other.cpp", params="int *value"),
        "e": function("app::Box<int>::Box", "box.cpp", line=8),
        "f": function("app::Box<int>::~Box", "box.cpp", line=12),
        "g": function("app::Nest<std::vector<int>>::read", "nested.cpp"),
        "h": dict(function("UserApi", "api.c"), aliases=["ExternalAlias"]),
    }
    index = make_index(tmp_path, records)
    try:
        queries = [
            "Run",
            "Run(int value)",
            "Run(char *value)",
            "Run(double)",
            "run",
            "Box::run",
            "app::Box::run",
            "app::Box<int>::run",
            "~Box",
            "app::Box<int>::Box",
            "read",
            "ExternalAlias",
            "missing",
        ]
        queries.extend(index._function_index)
        for query in queries:
            for file in (
                "",
                "same.c",
                "left/same.c",
                "box.cpp",
                str(tmp_path / "right/same.c"),
                "not_indexed.h",
            ):
                assert index._find_function_matches(query, file_path=file) == scan_match(
                    index, query, file
                )
            assert index._has_indexed_function(query) == bool(scan_match(index, query))
        assert len(index._find_function_matches("Run")) == 2
    finally:
        index.close()


def test_missing_and_ambiguous_queries_never_recompute_all_record_variants(tmp_path, monkeypatch):
    records = {str(i): function(f"scope_{i}::work", f"src/{i}.cpp") for i in range(1000)}
    index = make_index(tmp_path, records)
    initial_keys = set(index._function_query_index)
    try:
        monkeypatch.setattr(
            index,
            "_function_record_query_variants",
            lambda *_: pytest.fail("query traversed the function catalogue"),
        )
        for number in range(500):
            assert index._find_function_matches(f"external_{number}") == []
            assert not index._has_indexed_function(f"external_{number}")
        assert len(index._find_function_matches("work")) == 1000
        assert len(index._find_function_matches("work", file_path="src/7.cpp")) == 1
        assert index._function_query_index.keys() == initial_keys  # no growing negative-name cache
    finally:
        index.close()


def test_insert_replace_and_rebuild_invalidate_lookup_forms(tmp_path):
    records = {"one": function("Target", "a.c", params="int value")}
    index = make_index(tmp_path, records)
    try:
        assert not index._has_indexed_function("Later")
        index._add_function_index_entry("Later", function("Later", "b.c"))
        assert index._has_indexed_function("Later")
        assert index._find_function_matches("Later", file_path="b.c")
        index._add_function_index_entry("Target", function("Target", "a.c", params="char *value"))
        assert index._find_function_matches("Target(int value)") == []
        assert index._find_function_matches("Target(char *value)")
        records.clear()
        records["two"] = function("Replacement", "new.c")
        index._build_index()
        assert not index._has_indexed_function("Later")
        assert not index._has_indexed_function("Target")
        assert index._has_indexed_function("Replacement")
    finally:
        index.close()


def test_header_scan_uses_one_scope_pass_and_existence_without_resolving(tmp_path, monkeypatch):
    header = tmp_path / "api.hpp"
    text = "class Box {\npublic:\n  Box();\n  ~Box();\n  int member(int x);\n};\n"
    text += "int public_api(\n  int value);\n"
    text += "\n".join(f"int external_{i}(void);" for i in range(1500))
    header.write_text(text, encoding="utf-8")
    records = {
        str(i): function(name, "api.cpp", line=i * 10 + 1)
        for i, name in enumerate(("Box::Box", "Box::~Box", "Box::member", "public_api"))
    }
    index = make_index(tmp_path, records)
    original_scopes = index._cpp_type_scopes
    counted = []

    def scopes(lines):
        counted.append(len(lines))
        return original_scopes(lines)

    try:
        monkeypatch.setattr(index, "_cpp_type_scopes", scopes)
        monkeypatch.setattr(
            index,
            "_enclosing_cpp_type_name",
            lambda *_: pytest.fail("declaration rescanned its file prefix"),
        )
        monkeypatch.setattr(
            index,
            "_resolve_function_name",
            lambda *_: pytest.fail("existence query attempted full resolution"),
        )
        result = index.get_header_declared_functions(["*.hpp", "api.hpp"])
        assert {row["name"] for row in result} == {
            "Box::Box",
            "Box::~Box",
            "Box::member",
            "public_api",
        }
        assert counted == [len(text.splitlines())]
        assert {row["name"]: row["lineNumber"] for row in result}["public_api"] == 7
    finally:
        index.close()


def test_scope_prefixes_keep_nested_types_and_comment_braces(tmp_path):
    index = make_index(tmp_path, {"x": function("x", "a.c")})
    lines = [
        "class Outer {",
        "/* } class Fake {",
        "still a comment",
        "*/",
        'const char *text = "}";',
        "struct Inner {",
        "int method();",
        "};",
        "int outer();",
        "};",
        "int top();",
    ]
    try:
        scopes = index._cpp_type_scopes(lines)
        assert scopes == [
            "",
            "Outer",
            "Outer",
            "Outer",
            "Outer",
            "Outer",
            "Outer::Inner",
            "Outer::Inner",
            "Outer",
            "Outer",
            "",
            "",
        ]
    finally:
        index.close()


def test_header_heartbeat_runs_while_file_read_is_blocked(tmp_path, monkeypatch, caplog):
    from zscope.retrieval import indexing_runtime

    index = make_index(tmp_path, {"x": function("x", "a.c")})
    (tmp_path / "api.h").write_text("int x(void);\n", encoding="utf-8")
    original = indexing_runtime.heartbeat
    monkeypatch.setattr(
        indexing_runtime, "heartbeat", lambda phase, state: original(phase, state, interval=0.01)
    )
    logged = threading.Event()

    class Observer(logging.Handler):
        def emit(self, record):
            if "indexing-heartbeat" in record.getMessage():
                logged.set()

    handler = Observer()
    log = logging.getLogger(indexing_runtime.__name__)
    log.addHandler(handler)

    def blocked_read(path):
        assert logged.wait(3)
        return "int x(void);\n"

    monkeypatch.setattr(index, "_read_file_text", blocked_read)
    try:
        with caplog.at_level(logging.INFO):
            assert index.get_header_declared_functions()
        assert "phase=entry-headers" in caplog.text
        assert "[entry-headers] completed" in caplog.text
    finally:
        log.removeHandler(handler)
        index.close()
