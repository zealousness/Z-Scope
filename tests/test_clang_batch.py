"""Native compiler integration; set Z_SCOPE_TEST_CLANG_INDEXER to the built tool."""

import json
import os
from pathlib import Path

import pytest

from zscope.retrieval.clang_backend import ClangBackend
from zscope.retrieval.clang_batch import BatchIndexer, find_indexer


def test_import_cleanup_retains_reusable_facts_and_failure_diagnostics(tmp_path):
    indexer = BatchIndexer.__new__(BatchIndexer)
    indexer.cache = tmp_path
    retained = ("tu.jsonl", "tu.json", "tu.stderr.log", "failed.job.json", "failed.stderr.log")
    disposable = ("tu.job.json", "tu.stdout.log", "tu.partial.jsonl")
    for name in (*retained, *disposable):
        (tmp_path / name).write_text(name, encoding="utf-8")
    indexer._trim_package_cache("tu")
    for name in retained:
        assert (tmp_path / name).read_text(encoding="utf-8") == name
    assert not any((tmp_path / name).exists() for name in disposable)


@pytest.fixture
def project(tmp_path, monkeypatch):
    executable = os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER")
    if not executable:
        pytest.skip("native indexer integration requires Z_SCOPE_TEST_CLANG_INDEXER")
    monkeypatch.setenv("Z_SCOPE_CLANG_BATCH_MEMORY_MB", "512")
    monkeypatch.setattr(
        ClangBackend, "_ensure_extractor", lambda self: pytest.fail("unexpected LSP")
    )
    (tmp_path / "shared.h").write_text(
        "#pragma once\ntypedef struct Item { int value; } Item;\nextern int global;\n"
        "#define PLUS(x) ((x) + global)\nint other(Item *p);\n",
        encoding="utf-8",
    )
    (tmp_path / "a.c").write_text(
        '#include "shared.h"\nint global = 1;\nint use(Item *p) {\n'
        "  global++;\n  Item local = (Item){0};\n  return PLUS(p->value) + other(&local);\n}\n",
        encoding="utf-8",
    )
    (tmp_path / "b.c").write_text(
        '#include "shared.h"\nint other(Item *p) { return global + p->value; }\n', encoding="utf-8"
    )
    commands = [
        {
            "file": str(tmp_path / name),
            "directory": str(tmp_path),
            "arguments": ["clang", "-I", str(tmp_path), "-c", str(tmp_path / name)],
        }
        for name in ("a.c", "b.c")
    ]
    cdb = tmp_path / "compile_commands.json"
    cdb.write_text(json.dumps(commands), encoding="utf-8")
    backend = ClangBackend(frontend="batch", clang_indexer_path=executable, max_threads=2)
    try:
        yield backend, tmp_path, cdb
    finally:
        backend.close()


def build(project):
    backend, root, cdb = project
    if backend.db:
        return backend._run_full_extraction()
    return backend.initialize(str(root), compile_commands_path=str(cdb))


def test_program_events_include_cfg_and_compiler_object_identity(tmp_path):
    executable = os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER")
    if not executable:
        pytest.skip("native indexer integration requires Z_SCOPE_TEST_CLANG_INDEXER")
    source = tmp_path / "events.cpp"
    source.write_text(
        "int shared_value; thread_local int private_value;\n"
        "struct State { int total; };\n"
        "void demo(State *s) { shared_value++; s->total++; private_value++; "
        "int *p = new int[4]; delete[] p; }\n"
        "extern void free(void*);\n"
        "#define TWICE(p) do { free(p); free(p); } while (0)\n"
        "void macro_release(int *p) { TWICE(p); }\n"
        "void comma_release(int *p) { free(p), free(p); }\n"
        "void private_fields() { State local; local.total++; thread_local State tls; tls.total++; }\n"
        "struct Guard { ~Guard(); };\nvoid cleanup() { Guard guard; }\n",
        encoding="utf-8",
    )
    cdb = tmp_path / "compile_commands.json"
    cdb.write_text(json.dumps([{"file": str(source), "directory": str(tmp_path),
                                "arguments": ["clang++", "-std=c++17", "-c", str(source)]}]), encoding="utf-8")
    backend = ClangBackend(frontend="batch", clang_indexer_path=executable)
    try:
        assert backend.initialize(str(tmp_path), compile_commands_path=str(cdb))
        facts = backend.get_function_program_facts("demo", "events.cpp")
        assert facts["complete"]
        assert facts["functions"][0]["cfg_edges"]
        assert {row["resource_family"] for row in facts["events"]} >= {"new_array"}
        releases = [row for row in facts["events"] if row["event_kind"] == "release"]
        assert releases and releases[0]["location"]["column"] > 1
        assert releases[0]["object"]["usr"]
        acquisitions = [row for row in facts["events"] if row["event_kind"] == "acquire"]
        assert acquisitions[0]["object"]["usr"] == releases[0]["object"]["usr"]
        accesses = {row["target"]["name"]: row for row in facts["accesses"]}
        assert {"shared_value", "total"} <= set(accesses)
        assert "private_value" not in accesses
        assert accesses["total"]["target"]["usr"]
        assert accesses["shared_value"]["access_kind"] == "read_write"
        assert not backend.get_function_program_facts("private_fields", "events.cpp")["accesses"]
        cleanup = backend.get_function_program_facts("cleanup", "events.cpp")
        assert any(event["event_kind"] == "implicit_release" and event["object"]["usr"] for event in cleanup["events"])
        from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
        generator = ClangAstCfgCandidateGenerator(program_facts_provider=backend.get_function_program_facts)
        for name, line in (("macro_release", 6), ("comma_release", 7)):
            code = f"{line} | {source.read_text().splitlines()[line - 1]}"
            issues = generator.generate_issues(name, code, "events.cpp")
            double = [issue for issue in issues if issue["defect_class"] == "double_free"]
            assert double and double[0]["validation_required"]
            assert not double[0]["evidence_pack"]["path"]["complete_in_function"]
    finally:
        backend.close()


def test_native_facts_warm_cache_and_header_invalidation(project, caplog):
    caplog.set_level("INFO")
    assert build(project)
    backend, root, _ = project
    db = backend.db
    assert {r[0] for r in db._conn.execute("SELECT name FROM functions")} >= {"use", "other"}
    assert db._conn.execute("SELECT COUNT(*) FROM function_symbol_refs").fetchone()[0] >= 3
    assert db._conn.execute("SELECT COUNT(*) FROM function_macro_refs").fetchone()[0] == 1
    kinds = {r[0] for r in db._conn.execute("SELECT reference_kind FROM function_type_refs")}
    assert {"parameter", "local", "member_access", "compound_literal"} <= kinds
    assert (
        db._conn.execute("SELECT COUNT(*) FROM call_edges WHERE callee_name='other'").fetchone()[0]
        == 1
    )
    assert build(project)
    stats = json.loads(db.get_metadata("clang_batch_stats"))
    assert stats["compiled_tus"] == 0
    assert stats["reused_tus"] == 2
    assert stats["complete"]
    assert stats["completed_tus"] == 2 and stats["remaining_tus"] == 0
    assert "finished complete=True" in caplog.text
    assert "[indexing-process]" not in caplog.text
    assert "[clang-batch] done=" not in caplog.text
    header = root / "shared.h"
    header.write_text(header.read_text() + "\n#define SECOND 2\n")
    assert build(project)
    assert json.loads(db.get_metadata("clang_batch_stats"))["compiled_tus"] == 2


def test_macro_contexts_are_not_bound_to_another_tus_type_layout(project):
    backend, root, cdb = project
    (root / "shared.h").write_text(
        "struct Layout {\n#ifdef WIDE\nlong wide;\n#else\nint narrow;\n#endif\n};\n"
    )
    (root / "a.c").write_text(
        '#include "shared.h"\nint a(struct Layout *p) { return p->narrow; }\n'
    )
    (root / "b.c").write_text('#include "shared.h"\nint b(struct Layout *p) { return p->wide; }\n')
    commands = json.loads(cdb.read_text())
    commands[1]["arguments"].insert(1, "-DWIDE")
    cdb.write_text(json.dumps(commands))
    assert build(project)
    rows = list(
        backend.db._conn.execute(
            "SELECT r.type_id,r.resolution_reason FROM function_type_refs r JOIN functions f ON f.id=r.function_id WHERE f.name='b'"
        )
    )
    assert rows and all(row[0] is None and row[1] == "type_context_not_projected" for row in rows)


def test_auto_falls_back_only_for_failed_tu(project, monkeypatch, caplog):
    assert build(project)
    backend, root, _ = project
    backend._frontend = "auto"
    calls = []
    original = BatchIndexer._extract

    def extract(indexer, job):
        if Path(job["source"]).name == "b.c":
            raise RuntimeError("injected native TU failure")
        return original(indexer, job)

    class Fallback:
        def stop(self):
            pass

        def seed_project_file_index(self, paths):
            calls.append(("seed", sorted(path.name for path in paths)))

        def run_batch_extraction(self, paths, db, **kwargs):
            calls.append(("base", [path.name for path in paths]))
            return {"failed": 0}

        def rebuild_function_symbol_refs(self, db, **kwargs):
            calls.append(("derived", sorted(kwargs["only_files"])))
            return {"errors": []}

    def ensure(self):
        report = json.loads(
            (Path(self.db._db_path).parent / "clang_batch_cache" / "latest_run.json").read_text()
        )
        assert report["failed_tus"][0]["reason"] == "injected native TU failure"
        assert not report["complete"]
        assert "[clang-batch-failed]" in caplog.text
        self._extractor = Fallback()
        return True

    monkeypatch.setattr(BatchIndexer, "_extract", extract)
    monkeypatch.setattr(ClangBackend, "_ensure_extractor", ensure)
    assert build(project)
    assert calls == [
        ("seed", ["a.c", "b.c", "shared.h"]),
        ("base", ["b.c"]),
        ("derived", ["b.c"]),
    ]
    stats = json.loads(backend.db.get_metadata("clang_batch_stats"))
    assert stats["ready_for_queries"] and stats["rpc_requests_native"] == 0
    assert not stats["type_refs_complete"]
    assert stats["fallback_files"] == [str(root / "b.c")]


def test_deleted_tu_is_removed_and_compile_context_change_invalidates_package(project):
    assert build(project)
    backend, root, cdb = project
    (root / "b.c").unlink()
    commands = json.loads(cdb.read_text())[:1]
    commands[0]["arguments"].insert(1, "-DNEW_CONTEXT=1")
    cdb.write_text(json.dumps(commands))
    assert build(project)
    assert not backend.db._conn.execute(
        "SELECT 1 FROM functions WHERE name='other' AND is_declaration=0"
    ).fetchone()
    stats = json.loads(backend.db.get_metadata("clang_batch_stats"))
    assert stats["compiled_tus"] == 1


def test_strict_failure_keeps_published_facts(project, caplog):
    assert build(project)
    backend, root, _ = project
    before = list(backend.db._conn.execute("SELECT name,file_path,start_line FROM functions"))
    (root / "a.c").write_text("this is not C;\n")
    assert not build(project)
    after = list(backend.db._conn.execute("SELECT name,file_path,start_line FROM functions"))
    assert [tuple(r) for r in before] == [tuple(r) for r in after]
    assert "reason=process_exit" in caplog.text and "error:" in caplog.text


def test_build_directory_outside_scanned_root_preserves_relative_includes(project):
    backend, root, cdb = project
    build_dir = root.parent / (root.name + "-external-build")
    generated = build_dir / "generated"
    generated.mkdir(parents=True)
    (generated / "generated.h").write_text("#define GENERATED 42\n", encoding="utf-8")
    source = root / "a.c"
    source.write_text(
        source.read_text()
        + '#include "generated.h"\nint generated_value(void) { return GENERATED; }\n',
        encoding="utf-8",
    )
    commands = json.loads(cdb.read_text())
    for command in commands:
        command["directory"] = str(build_dir)
        command["arguments"][1:1] = ["-Igenerated"]
    cdb.write_text(json.dumps(commands), encoding="utf-8")
    assert build(project)
    assert backend.db.get_function("generated_value") is not None
    stats = json.loads(backend.db.get_metadata("clang_batch_stats"))
    assert stats["compiled_tus"] == 2 and not stats["failed_tus"]


def test_frontend_transition_rebuilds_in_isolation_and_preserves_on_failure(project, monkeypatch):
    assert build(project)
    backend, root, _ = project
    published = backend.db
    before = published.get_metadata("clang_batch_input")
    seen = []

    def attempt():
        assert backend.db is not published
        assert backend._frontend == "lsp"
        assert all(row["status"] == "pending" for row in backend.db.get_all_tus())
        assert backend.db.get_metadata("clang_batch_input") == ""
        seen.append(backend.db.get_metadata("clang_fact_frontend"))
        return False

    monkeypatch.setattr(backend, "_run_full_extraction", attempt)
    assert not backend._transition_to_lsp(published)
    assert backend.db is published and backend._frontend == "batch"
    assert published.get_metadata("clang_batch_input") == before
    assert published.get_metadata("clang_fact_frontend") == "batch"
    assert seen == ["lsp"]


def test_publish_exception_rolls_back(project, monkeypatch):
    assert build(project)
    backend, root, _ = project
    before = backend.db.get_metadata("clang_batch_input")
    (root / "a.c").write_text((root / "a.c").read_text() + "\nint extra(void) { return 2; }\n")

    def fail(*args):
        raise RuntimeError("publication injected failure")

    monkeypatch.setattr(BatchIndexer, "_commit", fail)
    assert not build(project)
    assert backend.db.get_metadata("clang_batch_input") == before
    assert not backend.db._conn.execute("SELECT 1 FROM functions WHERE name='extra'").fetchone()


def test_compiler_binding_shadow_macro_redefinition_and_utf_columns(project):
    backend, root, _ = project
    (root / "a.c").write_text(
        '#include "shared.h"\nint global = 1;\n'
        "#define SWITCH 1\nint first(void) { return SWITCH; }\n"
        "#undef SWITCH\n#define SWITCH 2\nint second(void) { return SWITCH; }\n"
        "int utf(void) { /* 中文 */ global = global + 1; { int global = 9; return global; } }\n",
        encoding="utf-8",
    )
    assert build(project)
    db = backend.db
    definitions = {
        row[0]: row[1]
        for row in db._conn.execute(
            "SELECT f.name,m.start_line FROM function_macro_refs r JOIN functions f ON f.id=r.function_id JOIN macro_definitions m ON m.id=r.macro_id WHERE m.name='SWITCH'"
        )
    }
    assert definitions == {"first": 3, "second": 6}
    refs = list(
        db._conn.execute(
            "SELECT reference_line,access_kind,symbol_file FROM function_symbol_refs WHERE function_name='utf' AND symbol_name='global'"
        )
    )
    assert [tuple(row) for row in refs] == [(8, "read_write", "a.c")]
    from zscope.retrieval.clang_batch import records

    uses = [
        row
        for path in (Path(db._db_path).parent / "clang_batch_cache").glob("*.jsonl")
        for row in records(path)
        if row.get("kind") == "symbol_reference" and row["owner"]["name"] == "utf"
    ]
    assert len(uses) == 2
    assert {use["location"]["column"] for use in uses} == {30, 39}


@pytest.mark.parametrize("count", [255, 256, 257, 512, 4096])
def test_many_homonyms_use_compiler_identity(project, count):
    backend, root, cdb = project
    source = root / "names.cpp"
    source.write_text(
        "\n".join(f"namespace n{i} {{ int same = {i}; }}" for i in range(count))
        + f"\nint selected() {{ return n{count - 1}::same; }}\n"
    )
    commands = json.loads(cdb.read_text())
    commands.append(
        {"file": str(source), "directory": str(root), "arguments": ["clang++", "-c", str(source)]}
    )
    cdb.write_text(json.dumps(commands))
    assert build(project)
    rows = list(
        backend.db._conn.execute(
            "SELECT symbol_name FROM function_symbol_refs WHERE function_name='selected'"
        )
    )
    assert [row[0] for row in rows] == [f"n{count - 1}::same"]


def test_missing_tool_handshake():
    assert find_indexer("zscope-indexer-does-not-exist-48323") is None
