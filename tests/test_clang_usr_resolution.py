"""Scale, identity, failure and durable-resume contracts for the derived resolver."""

import json
import os
import threading
import shutil
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from zscope.retrieval.clang_derived_cache import DerivedCache, cache_key
from zscope.retrieval.clang_extractor import ClangExtractor
from zscope.retrieval.clang_resolution import DerivedResolver, build_identity
from zscope.retrieval.knowledge_db import KnowledgeDB


def location(path, line=0, char=0, length=1):
    return {
        "uri": path.as_uri(),
        "range": {
            "start": {"line": line, "character": char},
            "end": {"line": line, "character": char + length},
        },
    }


def mocks(ex, monkeypatch):
    opened = set()
    monkeypatch.setattr(ex, "open_document", lambda path: opened.add(path.resolve()) or True)
    monkeypatch.setattr(ex, "close_document", lambda path: opened.discard(path.resolve()))
    monkeypatch.setattr(ex, "get_definition", lambda *args: [])
    monkeypatch.setattr(ex, "get_symbol_details", lambda *args: [])
    return opened


@pytest.mark.parametrize("groups", [255, 256, 257, 512, 4096])
@pytest.mark.parametrize("workers,max_bytes", [(1, 1), (4, 4096)])
def test_grouped_fallback_requests_once_despite_eviction(
    tmp_path, monkeypatch, groups, workers, max_bytes
):
    source, header = tmp_path / "use.c", tmp_path / "defs.h"
    source.write_text("COMMON + COMMON\n", encoding="utf-8")
    header.write_text("#define COMMON 1\n" * groups, encoding="utf-8")
    ex = ClangExtractor(tmp_path)
    opened = mocks(ex, monkeypatch)
    requests = []
    lease_counts = {}
    lease_lock = threading.Lock()

    def open_document(path):
        with lease_lock:
            key = path.resolve()
            lease_counts[key] = lease_counts.get(key, 0) + 1
            opened.add(key)
        return True

    def close_document(path):
        with lease_lock:
            key = path.resolve()
            lease_counts[key] -= 1
            if not lease_counts[key]:
                opened.discard(key)

    monkeypatch.setattr(ex, "open_document", open_document)
    monkeypatch.setattr(ex, "close_document", close_document)

    def references(path, line, char, **kwargs):
        assert path.resolve() in opened
        requests.append(line)
        return [location(source), location(source, char=9)] if line == 0 else []

    monkeypatch.setattr(ex, "get_references", references)
    candidates = [
        {"name": "COMMON", "file_path": "defs.h", "line": i + 1, "id": i + 1} for i in range(groups)
    ]
    cache = DerivedCache(max_bytes=max_bytes)
    resolver = ex._derived_resolver = DerivedResolver(ex, cache)
    stats = ex._new_derived_stats("function_symbol_context", 1, 1)

    def run():
        for ordered in (candidates, list(reversed(candidates))):
            with resolver.file(source) as state:
                context = ex._new_derived_resolution_caches()
                for char in (0, 9):
                    resolver.resolve(ordered, "macro", source, 1, char, context, stats)
                resolver.flush(state)
                for char in (0, 9):
                    result, reason = resolver.resolve(
                        ordered, "macro", source, 1, char, context, stats
                    )
                    assert result["id"] == 1
                    assert reason == ""

    try:
        if workers == 1:
            run()
        else:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = [pool.submit(run) for _ in range(workers)]
                while not all(f.done() for f in futures):
                    cache.wakeup.clear()
                    cache.pump()
                    cache.wakeup.wait(0.001)
                for future in futures:
                    future.result()
        assert len(requests) == groups
        assert stats["symbol_info_requests"] == 2
        assert stats["definition_requests"] == 2
        assert cache.stats["disk_hits"] > 0
        assert cache.stats["peak_hot_bytes"] <= max_bytes
        assert not opened
    finally:
        ex._derived_resolver = None
        cache.close()


@pytest.mark.parametrize("failure", ["ambiguous", "rpc_error", "truncated"])
def test_reference_completeness_and_eviction_never_invent_unique_binding(
    tmp_path, monkeypatch, failure
):
    source, header = tmp_path / "use.c", tmp_path / "defs.h"
    source.write_text("COMMON\n", encoding="utf-8")
    header.write_text("#define COMMON 1\n" * 257, encoding="utf-8")
    ex = ClangExtractor(tmp_path)
    mocks(ex, monkeypatch)

    def references(path, line, char, **kwargs):
        if line == 0:
            if failure == "rpc_error":
                ex._record_rpc_outcome("textDocument/references", "rpc_error", {"code": -32602})
                return None
            if failure == "truncated":
                return [location(source, 0, 30)] * 1000
            return [location(source)]
        return [location(source)] if line == 256 else []

    monkeypatch.setattr(ex, "get_references", references)
    candidates = [
        {"name": "COMMON", "file_path": "defs.h", "line": i + 1, "id": i + 1} for i in range(257)
    ]
    cache = DerivedCache(max_bytes=1)
    resolver = ex._derived_resolver = DerivedResolver(ex, cache)
    try:
        with resolver.file(source) as state:
            context = ex._new_derived_resolution_caches()
            stats = ex._new_derived_stats("function_symbol_context", 1, 1)
            resolver.resolve(candidates, "macro", source, 1, 0, context, stats)
            resolver.flush(state)
            result, reason = resolver.resolve(candidates, "macro", source, 1, 0, context, stats)
            assert result is None
            assert reason == (
                "reference_ambiguous" if failure == "ambiguous" else "reference_incomplete"
            )
    finally:
        ex._derived_resolver = None
        cache.close()


def test_same_file_name_has_distinct_usr_bindings_and_shared_coordinate_rpc(tmp_path, monkeypatch):
    source = tmp_path / "scope.cpp"
    source.write_text(
        "namespace A { int value; }\nnamespace B { int value; }\nvalue + value\n", encoding="utf-8"
    )
    ex = ClangExtractor(tmp_path)
    mocks(ex, monkeypatch)
    queried = []

    def details(path, line, char):
        queried.append((line, char))
        target = 0 if char == 0 else 1
        return [
            {"usr": f"c:@N@{target}@value", "declarationRange": location(source, target, 18, 5)}
        ]

    monkeypatch.setattr(ex, "get_symbol_details", details)
    candidates = [
        {"name": "value", "file_path": "scope.cpp", "line": i + 1, "id": i + 1} for i in range(2)
    ]
    cache = DerivedCache(max_bytes=1)
    resolver = ex._derived_resolver = DerivedResolver(ex, cache)
    try:
        with resolver.file(source):
            stats = ex._new_derived_stats("function_symbol_context", 1, 1)
            context = ex._new_derived_resolution_caches()
            for _ in range(2):
                assert (
                    resolver.resolve(candidates, "global", source, 3, 0, context, stats)[0]["id"]
                    == 1
                )
                assert (
                    resolver.resolve(candidates, "global", source, 3, 8, context, stats)[0]["id"]
                    == 2
                )
            assert queried == [(2, 0), (2, 8)]
            assert stats["definition_requests"] == 0
    finally:
        ex._derived_resolver = None
        cache.close()


def test_multiple_symbol_results_are_not_collapsed(tmp_path, monkeypatch):
    ex = ClangExtractor(tmp_path)
    monkeypatch.setattr(
        ex, "send_request", lambda *args, **kwargs: [{"usr": "one"}, {"usr": "two"}]
    )
    assert len(ex.get_symbol_details(tmp_path / "use.c", 0, 0)) == 2
    assert ex.get_symbol_info(tmp_path / "use.c", 0, 0) is None


def test_method_not_found_disables_only_symbol_info(tmp_path, monkeypatch):
    ex = ClangExtractor(tmp_path)
    count = 0

    def send(method, *args, **kwargs):
        nonlocal count
        count += 1
        ex._record_rpc_outcome(method, "rpc_error", {"code": -32601})
        return None

    monkeypatch.setattr(ex, "send_request", send)
    ex.get_symbol_details(tmp_path / "use.c", 0, 0)
    ex.get_symbol_details(tmp_path / "use.c", 0, 1)
    assert count == 1
    assert ex.get_request_metrics("textDocument/symbolInfo")["count"] == 0
    ex._symbol_info_supported = None
    ex.get_symbol_details(tmp_path / "use.c", 0, 0)
    assert count == 2


def test_cache_broker_single_writer_singleflight_and_error_recovery(tmp_path):
    cache = DerivedCache(tmp_path / "cache.sqlite3", epoch="one", max_bytes=1)
    owner = threading.get_ident()
    writes = []
    cache.db.set_trace_callback(lambda sql: writes.append(threading.get_ident()))
    attempts = []

    def compute():
        attempts.append(1)
        return {"value": 42}

    try:
        with ThreadPoolExecutor(max_workers=8) as pool:
            tasks = [pool.submit(cache.compute, "probe", "same", compute) for _ in range(8)]
            while not all(t.done() for t in tasks):
                cache.wakeup.clear()
                cache.pump()
                cache.wakeup.wait(0.001)
            assert [t.result() for t in tasks] == [{"value": 42}] * 8
        assert len(attempts) == 1
        assert set(writes) == {owner}
        with pytest.raises(ValueError):
            cache.compute("probe", "error", lambda: (_ for _ in ()).throw(ValueError("bad")))
        assert cache.compute("probe", "error", lambda: {"ok": 1}) == {"ok": 1}
        cache.put("probe", "negative", {"_volatile": True, "status": "timeout"})
        cache.checkpoint()
    finally:
        cache.close()
    cache = DerivedCache(tmp_path / "cache.sqlite3", epoch="one", max_bytes=1)
    try:
        assert cache.get("probe", "same") == {"value": 42}
        assert cache.get("probe", "negative") is None
    finally:
        cache.close()


def prepared_project(tmp_path, monkeypatch):
    source = tmp_path / "use.cpp"
    source.write_text("int shared;\nint f() { return shared; }\n", encoding="utf-8")
    depfile = tmp_path / "use.d"
    command = {
        "directory": str(tmp_path),
        "file": str(source),
        "arguments": ["clang++", "-MD", "-MF", str(depfile), "-c", str(source)],
    }
    compilation = tmp_path / "compile_commands.json"
    compilation.write_text(json.dumps([command]), encoding="utf-8")
    depfile.write_text("use.o: " + source.as_posix() + "\n", encoding="utf-8")
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    db.insert_function("f", "use.cpp", 2, 2, signature="int f()")
    db.insert_global_variable("shared", "int", "use.cpp", 1)
    db.commit()
    queried = []

    def extractor():
        ex = ClangExtractor(tmp_path, compile_commands_dir=tmp_path, max_threads=1)
        ex._server_info = {"name": "clangd", "version": "fixture"}
        mocks(ex, monkeypatch)
        monkeypatch.setattr(ex, "get_semantic_tokens", lambda path: {"data": []})

        def details(path, line, char):
            queried.append((line, char))
            return [{"usr": "c:@shared", "declarationRange": location(source, 0, 4, 6)}]

        monkeypatch.setattr(ex, "get_symbol_details", details)
        return ex

    return source, compilation, depfile, db, extractor, queried


def test_file_checkpoint_replays_facts_with_identical_manifest(tmp_path, monkeypatch):
    source, compilation, depfile, db, extractor, queried = prepared_project(tmp_path, monkeypatch)
    try:
        ex = extractor()
        assert build_identity(ex, db)[1]
        assert ex.rebuild_function_symbol_refs(db) == 1
        original = db.get_function_symbol_context("f", "use.cpp")
        assert len(queried) == 1
        ex = extractor()
        assert ex.rebuild_function_symbol_refs(db) == 1
        assert len(queried) == 1
        assert db.get_function_symbol_context("f", "use.cpp") == original
        assert ex.get_last_derived_stats("function_symbol_context")["files_reused"] == 1
        source.write_text(source.read_text(encoding="utf-8") + "// changed\n", encoding="utf-8")
        ex = extractor()
        assert ex.rebuild_function_symbol_refs(db) == 1
        assert len(queried) == 2
    finally:
        db.close()


def test_manifest_rejects_missing_depfile_and_changes_with_configuration(tmp_path, monkeypatch):
    source, compilation, depfile, db, extractor, _ = prepared_project(tmp_path, monkeypatch)
    try:
        before = build_identity(extractor(), db)
        compilation.write_text(
            compilation.read_text(encoding="utf-8").replace("-MD", "-MMD"), encoding="utf-8"
        )
        after = build_identity(extractor(), db)
        assert before[0] != after[0]
        assert not after[1]
        depfile.unlink()
        assert not build_identity(extractor(), db)[1]
    finally:
        db.close()


def test_content_epoch_invalidates_source_cache_even_with_preserved_mtime(tmp_path, monkeypatch):
    source, _, _, db, extractor, _ = prepared_project(tmp_path, monkeypatch)
    try:
        ex = extractor()
        assert ex.rebuild_function_symbol_refs(db) == 1
        before = source.stat()
        source.write_text(
            source.read_text(encoding="utf-8").replace("shared", "absent"), encoding="utf-8"
        )
        os.utime(source, ns=(before.st_atime_ns, before.st_mtime_ns))
        assert source.stat().st_size == before.st_size
        assert ex.rebuild_function_symbol_refs(db) == 0
    finally:
        db.close()


def test_cache_epochs_do_not_mix_concurrent_builds(tmp_path):
    path = tmp_path / "cache.sqlite3"
    first = DerivedCache(path, epoch="first", max_bytes=0)
    second = DerivedCache(path, epoch="second", max_bytes=0)
    try:
        first.put("identity", "symbol", {"value": "first"})
        first.checkpoint()
        second.put("identity", "symbol", {"value": "second"})
        second.checkpoint()
        assert first.get("identity", "symbol") == {"value": "first"}
        assert second.get("identity", "symbol") == {"value": "second"}
    finally:
        first.close()
        second.close()


def test_file_change_before_publication_preserves_old_facts(tmp_path, monkeypatch):
    source, _, _, db, extractor, _ = prepared_project(tmp_path, monkeypatch)
    try:
        ex = extractor()
        assert ex.rebuild_function_symbol_refs(db) == 1
        old = db.get_function_symbol_context("f", "use.cpp")
        # Force a new manifest, then change input during the use-site request.
        source.write_text(
            source.read_text(encoding="utf-8") + "// first change\n", encoding="utf-8"
        )
        ex = extractor()
        original = ex.get_symbol_details

        def mutate(*args):
            source.write_text(
                source.read_text(encoding="utf-8") + "// concurrent change\n", encoding="utf-8"
            )
            return original(*args)

        monkeypatch.setattr(ex, "get_symbol_details", mutate)
        with pytest.raises(RuntimeError, match="Inputs changed"):
            ex.rebuild_function_symbol_refs(db)
        assert db.get_function_symbol_context("f", "use.cpp") == old
    finally:
        db.close()


def add_second_file(tmp_path, source, compilation, depfile, db):
    second = tmp_path / "z.cpp"
    second.write_text("int g() { return shared; }\n", encoding="utf-8")
    second_dep = tmp_path / "z.d"
    commands = json.loads(compilation.read_text(encoding="utf-8"))
    commands.append(
        {
            "directory": str(tmp_path),
            "file": str(second),
            "arguments": ["clang++", "-MD", "-MF", str(second_dep), "-c", str(second)],
        }
    )
    compilation.write_text(json.dumps(commands), encoding="utf-8")
    depfile.write_text("use.o: " + source.as_posix() + "\n", encoding="utf-8")
    second_dep.write_text(
        "z.o: " + second.as_posix() + " " + source.as_posix() + "\n", encoding="utf-8"
    )
    db.insert_function("g", "z.cpp", 1, 1, signature="int g()")
    db.commit()


def test_interruption_resumes_only_unfinished_files(tmp_path, monkeypatch):
    source, compilation, depfile, db, extractor, queried = prepared_project(tmp_path, monkeypatch)
    add_second_file(tmp_path, source, compilation, depfile, db)
    try:
        ex = extractor()
        collect = ex._collect_function_symbol_refs

        def interrupt(function, file, *args):
            if file == "z.cpp":
                raise KeyboardInterrupt("fixture interruption")
            return collect(function, file, *args)

        monkeypatch.setattr(ex, "_collect_function_symbol_refs", interrupt)
        with pytest.raises(KeyboardInterrupt):
            ex.rebuild_function_symbol_refs(db)
        assert len(queried) == 1
        ex = extractor()
        assert ex.rebuild_function_symbol_refs(db) == 2
        assert len(queried) == 2
        assert ex.get_last_derived_stats("function_symbol_context")["files_reused"] == 1
        assert (
            db.get_function_symbol_context("g", "z.cpp")["referenced_globals"][0]["name"]
            == "shared"
        )
    finally:
        db.close()


def test_staging_failure_does_not_checkpoint_cancelled_files(tmp_path, monkeypatch):
    source, compilation, depfile, db, extractor, queried = prepared_project(tmp_path, monkeypatch)
    add_second_file(tmp_path, source, compilation, depfile, db)
    stage = db.stage_function_symbol_refs_batch
    try:
        for name in ("function_symbol_context", "function_type_refs"):
            db.prepare_derived_index_staging(name)

        def fail(_rows):
            raise RuntimeError("fixture staging failure")

        monkeypatch.setattr(db, "stage_function_symbol_refs_batch", fail)
        assert (
            "function_symbol_context"
            in extractor().rebuild_function_derived_refs(db, use_staging=True)["errors"]
        )
        assert len(queried) == 1
        monkeypatch.setattr(db, "stage_function_symbol_refs_batch", stage)
        for name in ("function_symbol_context", "function_type_refs"):
            db.prepare_derived_index_staging(name)
        ex = extractor()
        result = ex.rebuild_function_derived_refs(db, use_staging=True)
        assert not result["errors"]
        assert ex.get_last_derived_stats("function_symbol_context")["files_reused"] == 1
        assert len(queried) == 2
        assert ex.get_last_derived_stats("function_symbol_context")["rows"] == 2
    finally:
        db.close()


def test_per_index_checkpoints_survive_combined_and_separate_rebuilds(tmp_path, monkeypatch):
    _, _, _, db, extractor, queried = prepared_project(tmp_path, monkeypatch)
    try:
        assert extractor().rebuild_function_symbol_refs(db) == 1
        for name in ("function_symbol_context", "function_type_refs"):
            db.prepare_derived_index_staging(name)
        ex = extractor()
        assert not ex.rebuild_function_derived_refs(db, use_staging=True)["errors"]
        assert ex.get_last_derived_stats("function_symbol_context")["files_reused"] == 1
        assert ex.get_last_derived_stats("function_type_refs")["files_reused"] == 0
        assert len(queried) == 1
        ex = extractor()
        assert ex.rebuild_function_type_refs(db) == 0
        assert ex.get_last_derived_stats("function_type_refs")["files_reused"] == 1
        assert extractor().rebuild_function_symbol_refs(db) == 1
        assert len(queried) == 1
    finally:
        db.close()


def test_missing_source_does_not_publish_empty_replacement(tmp_path, monkeypatch):
    source, _, _, db, extractor, _ = prepared_project(tmp_path, monkeypatch)
    try:
        assert extractor().rebuild_function_symbol_refs(db) == 1
        before = db.get_function_symbol_context("f", "use.cpp")
        source.unlink()
        with pytest.raises(OSError, match="Cannot read indexed source"):
            extractor().rebuild_function_symbol_refs(db)
        assert db.get_function_symbol_context("f", "use.cpp") == before
    finally:
        db.close()


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-32"])
def test_selection_columns_disambiguate_same_line_and_multiline_declarations(
    tmp_path, monkeypatch, encoding
):
    source = tmp_path / "use.cpp"
    header = tmp_path / "scope.h"
    source.write_text("value\n", encoding="utf-8")
    header.write_text("/* 😀 */ int unrelated; int value;\nstruct\nMulti\n{};\n", encoding="utf-8")
    ex = ClangExtractor(tmp_path)
    ex._position_encoding = encoding
    mocks(ex, monkeypatch)
    line = header.read_text(encoding="utf-8").splitlines()[0]
    char = line.index("value")
    encoded = len(line[:char].encode(encoding.replace("16", "16-le").replace("32", "32-le"))) // (
        2 if encoding == "utf-16" else 4 if encoding == "utf-32" else 1
    )
    cache = DerivedCache(max_bytes=1)
    resolver = ex._derived_resolver = DerivedResolver(ex, cache)
    try:
        with resolver.file(source):
            context = ex._new_derived_resolution_caches()
            wrong = {"name": "unrelated", "file_path": "scope.h", "line": 1, "id": 1}
            right = {"name": "value", "file_path": "scope.h", "line": 1, "id": 2}
            assert (
                resolver.match([wrong, right], [location(header, 0, encoded, 5)], context) == right
            )
            multi = {
                "name": "Multi",
                "file_path": "scope.h",
                "start_line": 2,
                "end_line": 4,
                "id": 3,
            }
            assert resolver.match([multi], [location(header, 2, 0, 5)], context) == multi
    finally:
        ex._derived_resolver = None
        cache.close()


def test_cross_kind_reference_failure_cannot_prove_unique_binding(tmp_path, monkeypatch):
    source = tmp_path / "use.c"
    header = tmp_path / "defs.h"
    source.write_text("COMMON\n", encoding="utf-8")
    header.write_text("int COMMON;\n#define COMMON 1\n", encoding="utf-8")
    ex = ClangExtractor(tmp_path)
    mocks(ex, monkeypatch)

    def references(path, line, *args, **kwargs):
        if line == 0:
            return [location(source)]
        ex._record_rpc_outcome("textDocument/references", "rpc_error", {"code": -32602})
        return None

    monkeypatch.setattr(ex, "get_references", references)
    cache = DerivedCache(max_bytes=1)
    resolver = ex._derived_resolver = DerivedResolver(ex, cache)
    try:
        with resolver.file(source) as state:
            context = ex._new_derived_resolution_caches()
            stats = ex._new_derived_worker_stats("function_symbol_context")
            kwargs = dict(
                function_file="use.c",
                source_path=source,
                line=1,
                character=0,
                global_candidates=[{"name": "COMMON", "file_path": "defs.h", "line": 1, "id": 1}],
                macro_candidates=[{"name": "COMMON", "file_path": "defs.h", "line": 2, "id": 2}],
                include_closure=[],
                semantic_context=context,
                semantic_token=None,
                stats=stats,
            )
            ex._resolve_cross_kind_occurrence(**kwargs)
            resolver.flush(state)
            assert ex._resolve_cross_kind_occurrence(**kwargs) == ("", None)
            assert state["transient"]
    finally:
        ex._derived_resolver = None
        cache.close()


def test_enclosing_record_range_is_not_a_member_identity(tmp_path, monkeypatch):
    source = tmp_path / "type.cpp"
    source.write_text("struct T { int T; };\n", encoding="utf-8")
    ex = ClangExtractor(tmp_path)
    cache = DerivedCache()
    resolver = ex._derived_resolver = DerivedResolver(ex, cache)
    try:
        with resolver.file(source):
            context = ex._new_derived_resolution_caches()
            record = {"name": "T", "file_path": "type.cpp", "start_line": 1, "end_line": 1, "id": 1}
            assert resolver.match([record], [location(source, 0, 15)], context) is None
            assert resolver.match([record], [location(source, 0, 7)], context) == record
    finally:
        ex._derived_resolver = None
        cache.close()


@pytest.mark.skipif(shutil.which("clangd") is None, reason="clangd is not installed")
def test_real_clangd_macro_redefinition_binds_each_use_independently(tmp_path):
    source = tmp_path / "macros.cpp"
    source.write_text(
        "#define VALUE 1\nint first() { return VALUE; }\n#undef VALUE\n"
        "#define VALUE 2\nint second() { return VALUE; }\n",
        encoding="utf-8",
    )
    (tmp_path / "compile_commands.json").write_text(
        json.dumps(
            [
                {
                    "directory": str(tmp_path),
                    "file": str(source),
                    "arguments": ["clang++", "-c", str(source)],
                }
            ]
        ),
        encoding="utf-8",
    )
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    ex = ClangExtractor(tmp_path, compile_commands_dir=tmp_path)
    try:
        db.insert_function("first", "macros.cpp", 2, 2, signature="int first()")
        db.insert_function("second", "macros.cpp", 5, 5, signature="int second()")
        db.insert_macro_definitions_batch(
            [
                ("VALUE", "macros.cpp", 1, "#define VALUE 1\n", 0),
                ("VALUE", "macros.cpp", 4, "#define VALUE 2\n", 0),
            ]
        )
        db.commit()
        assert ex.start()
        assert ex.rebuild_function_symbol_refs(db) == 2
        first = db.get_function_symbol_context("first", "macros.cpp")["referenced_macros"][0]
        second = db.get_function_symbol_context("second", "macros.cpp")["referenced_macros"][0]
        definitions = {
            record["line"]: record["macro_index_name"]
            for record in db.get_macro_definition_records()
        }
        assert first["macro_index_name"] == definitions[1]
        assert second["macro_index_name"] == definitions[4]
        assert first["macro_index_name"] != second["macro_index_name"]
    finally:
        ex.stop()
        db.close()


@pytest.mark.skipif(shutil.which("clangd") is None, reason="clangd is not installed")
def test_real_clangd_resolves_forced_and_angle_headers_without_include_closure(tmp_path):
    include = tmp_path / "include"
    include.mkdir()
    source = tmp_path / "use.cpp"
    types = include / "types.h"
    forced = include / "forced.h"
    (include / "extra.h").write_text("struct Extra {};\n", encoding="utf-8")
    types.write_text("struct T { int value; };\n#define FLAG 7\n", encoding="utf-8")
    forced.write_text("extern int shared;\n", encoding="utf-8")
    source.write_text(
        "#include <types.h>\n#define EXTRA_HEADER <extra.h>\n#include EXTRA_HEADER\n"
        "int f(T *value, Extra *other) { return shared + FLAG; }\n",
        encoding="utf-8",
    )
    compilation = [
        {
            "directory": str(tmp_path),
            "file": str(source),
            "arguments": [
                "clang++",
                "-std=c++17",
                "-I" + str(include),
                "-include",
                str(forced),
                "-c",
                str(source),
            ],
        }
    ]
    (tmp_path / "compile_commands.json").write_text(json.dumps(compilation), encoding="utf-8")
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    ex = ClangExtractor(tmp_path, compile_commands_dir=tmp_path, max_threads=2)
    try:
        db.insert_function("f", "use.cpp", 4, 4, signature="int f(T *value, Extra *other)")
        db.insert_type(
            "T", "struct", "include/types.h", 1, 1, full_definition="struct T { int value; };"
        )
        db.insert_type(
            "Extra", "struct", "include/extra.h", 1, 1, full_definition="struct Extra {};"
        )
        db.insert_global_variable("shared", "int", "include/forced.h", 1, is_extern=True)
        db.insert_macro_definitions_batch([("FLAG", "include/types.h", 2, "#define FLAG 7\n", 0)])
        db.commit()
        assert ex.start()
        for name in ("function_symbol_context", "function_type_refs"):
            db.begin_derived_index_rebuild(name, "5")
            db.prepare_derived_index_staging(name)
        result = ex.rebuild_function_derived_refs(db, use_staging=True)
        assert not result["errors"]
        for name in ("function_symbol_context", "function_type_refs"):
            db.finalize_derived_index_rebuild(name, "5", ex.get_last_derived_stats(name))
        symbols = db.get_function_symbol_context("f", "use.cpp")
        assert [g["name"] for g in symbols["referenced_globals"]] == ["shared"]
        assert [m["macro_index_name"] for m in symbols["referenced_macros"]] == [
            db.get_macro_definition_records()[0]["macro_index_name"]
        ]
        assert {
            t["name"] for t in db.get_function_type_context("f", "use.cpp", 4)["referenced_types"]
        } == {"T", "Extra"}
        metrics = ex.get_last_derived_stats("function_symbol_context")["rpc_methods"]
        assert metrics["textDocument/symbolInfo"]["sent"] >= 2
        assert not metrics["textDocument/symbolInfo"].get("rpc_error")
        assert ex.get_request_metrics("textDocument/references")["count"] == 0
    finally:
        ex.stop()
        db.close()
