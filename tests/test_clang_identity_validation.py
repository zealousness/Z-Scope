"""Derived input identities must not depend on mutable include-lookup caches."""

import json
import os

import pytest

from zscope.retrieval.clang_extractor import ClangExtractor
from zscope.retrieval.clang_resolution import _identity_changes, build_identity, derived_session
from zscope.retrieval.knowledge_db import KnowledgeDB


@pytest.fixture
def project(tmp_path):
    source = tmp_path / "main.c"
    source.write_text("int f(void) { return 1; }\n", encoding="utf-8")
    (tmp_path / "compile_commands.json").write_text(
        json.dumps(
            [
                {
                    "directory": str(tmp_path),
                    "file": str(source),
                    "arguments": ["clang", "-c", str(source)],
                }
            ]
        ),
        encoding="utf-8",
    )
    ex = ClangExtractor(tmp_path, compile_commands_dir=tmp_path)
    ex._server_info = {"name": "clangd", "version": "fixture"}
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    db.insert_function("f", "main.c", 1, 1, signature="int f(void)")
    db.commit()
    try:
        yield ex, db, source
    finally:
        db.close()


def test_fallback_file_lookup_does_not_hash_scanner_outputs(project):
    ex, db, source = project
    log = source.parent / "scan.log"
    log.write_text("before\n", encoding="utf-8")
    # Base fallback resolves a quoted include through the whole-project lookup.
    ex._canonical_included_file(source, "not-installed/header.h")
    assert log in ex._project_file_index[log.name]

    @derived_session
    def collect(extractor, database):
        log.write_text("progress\n", encoding="utf-8")
        database.set_metadata("derived-progress", "1")
        return 42

    assert collect(ex, db) == 42


def test_lazy_file_lookup_warming_does_not_change_identity(project):
    ex, db, source = project
    before = build_identity(ex, db)[0]
    ex._canonical_included_file(source, "not-installed/header.h")
    assert build_identity(ex, db)[0] == before


@pytest.mark.parametrize(
    "change", ["source", "delete", "dependency", "compilation", "base", "config"]
)
def test_true_input_changes_still_reject_publication_with_diagnostics(project, caplog, change):
    ex, db, source = project
    # A real input in a cache-like directory must not be excluded by name/suffix.
    dependency = source.parent / "clang_batch_cache" / "generated.txt"
    dependency.parent.mkdir()
    dependency.write_text("#define VALUE 1\n", encoding="utf-8")
    db.insert_include_edges_batch([("main.c", "clang_batch_cache/generated.txt", 1, 0)])
    db.commit()

    @derived_session
    def collect(extractor, database):
        if change == "source":
            previous = source.stat()
            source.write_text("int f(void) { return 2; }\n", encoding="utf-8")
            os.utime(source, ns=(previous.st_atime_ns, previous.st_mtime_ns))
        elif change == "delete":
            source.unlink()
        elif change == "dependency":
            dependency.write_text("#define VALUE 2\n", encoding="utf-8")
        elif change == "compilation":
            compilation = source.parent / "compile_commands.json"
            commands = json.loads(compilation.read_text(encoding="utf-8"))
            commands[0]["arguments"].insert(1, "-DPRIVATE_VALUE=not-for-logs")
            compilation.write_text(json.dumps(commands), encoding="utf-8")
        elif change == "base":
            database.insert_function("g", "main.c", 2, 2)
            database.commit()
        else:
            (source.parent / ".clangd").write_text(
                "CompileFlags:\n  Add: -DNEW\n", encoding="utf-8"
            )

    expected = {
        "source": "main.c",
        "delete": "main.c",
        "dependency": "generated.txt",
        "compilation": "compile_commands.json",
        "base": "base:functions",
        "config": ".clangd",
    }[change]
    with pytest.raises(RuntimeError, match="changed during derived rebuild") as error:
        collect(ex, db)
    assert expected in str(error.value)
    assert "[derived-inputs-changed]" in caplog.text
    assert "not-for-logs" not in caplog.text
    assert ex._last_resolution_cache_stats["identity_changes"]["count"] > 0
    assert ex._derived_resolver is None


def test_selected_files_and_symlink_targets_remain_inputs(project):
    ex, db, source = project
    one, two = source.parent / "one.h", source.parent / "two.h"
    one.write_text("int value;\n", encoding="utf-8")
    two.write_text("int value;\n", encoding="utf-8")
    alias = source.parent / "selected.h"
    alias.symlink_to(one)
    ex.seed_project_file_index([source, alias])
    before = build_identity(ex, db)[0]
    alias.unlink()
    alias.symlink_to(two)
    assert build_identity(ex, db)[0] != before
    # The independent selection includes headers without base records or uses.
    before = build_identity(ex, db)[0]
    two.write_text("int changed;\n", encoding="utf-8")
    assert build_identity(ex, db)[0] != before


def test_dependency_manifest_is_authoritative_even_for_log_named_inputs(project):
    ex, db, source = project
    dependency = source.parent / "definitions.log"
    dependency.write_text("#define VALUE 1\n", encoding="utf-8")
    compilation = source.parent / "compile_commands.json"
    commands = json.loads(compilation.read_text(encoding="utf-8"))
    commands[0]["arguments"] += ["-MD", "-MF", "main.d"]
    compilation.write_text(json.dumps(commands), encoding="utf-8")
    (source.parent / "main.d").write_text("main.o: main.c definitions.log\n", encoding="utf-8")
    db.insert_include_edges_batch([("main.c", "stdio.h", 1, 1)])
    db.commit()
    before, reusable, _ = build_identity(ex, db)
    assert reusable
    dependency.write_text("#define VALUE 2\n", encoding="utf-8")
    assert build_identity(ex, db)[0] != before


def test_diagnostics_count_all_changes_but_bound_examples():
    before = {f"file:{index:02d}.h": "old" for index in range(20)}
    after = {f"file:{index:02d}.h": "new" for index in range(1, 21)}
    count, examples = _identity_changes(before, after)
    assert count == 21 and len(examples) == 8
    assert examples[0] == "removed file:00.h"
