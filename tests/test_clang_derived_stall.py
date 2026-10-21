"""Regression for the clangd 20 use-site fallback / 6508-declaration stall."""

import logging
import json
import shutil
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from zscope.retrieval.clang_derived_cache import DerivedCache
from zscope.retrieval.clang_extractor import ClangExtractor, _DerivedFileResult
from zscope.retrieval.clang_resolution import DerivedResolver
from zscope.retrieval.knowledge_db import KnowledgeDB


def location(path, line=0, char=0):
    return {
        "uri": path.as_uri(),
        "range": {
            "start": {"line": line, "character": char},
            "end": {"line": line, "character": char + 6},
        },
    }


def document_mocks(ex, monkeypatch):
    leases, opened = {}, []
    lock = threading.Lock()

    def acquire(path):
        with lock:
            opened.append(path)
            leases[path] = leases.get(path, 0) + 1
        return True

    def release(path):
        with lock:
            leases[path] -= 1
            assert leases[path] >= 0

    monkeypatch.setattr(ex, "open_document", acquire)
    monkeypatch.setattr(ex, "close_document", release)
    return leases, opened


def run_workers(cache, workers, work):
    if workers == 1:
        work(0)
        return
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(work, i) for i in range(workers)]
        while not all(f.done() for f in futures):
            cache.wakeup.clear()
            cache.pump()
            cache.wakeup.wait(0.001)
        for future in futures:
            future.result()


@pytest.mark.parametrize("kind", ["global", "type"])
@pytest.mark.parametrize("route", ["declaration", "use_references"])
@pytest.mark.parametrize("workers,max_bytes", [(1, 1), (8, 4096)])
def test_6508_candidates_resolve_without_candidate_document_queries(
    tmp_path, monkeypatch, kind, route, workers, max_bytes
):
    header = tmp_path / "all.h"
    header.write_text(("int shared;\n" if kind == "global" else "struct shared {};\n") * 6508)
    column = 4 if kind == "global" else 7
    sources = [tmp_path / f"use{i}.cpp" for i in range(workers)]
    for source in sources:
        source.write_text("shared + shared\n")
    candidates = [
        {"name": "shared", "file_path": "all.h", "line": i + 1, "id": i + 1} for i in range(6508)
    ]
    ex = ClangExtractor(tmp_path)
    leases, opened = document_mocks(ex, monkeypatch)
    calls = {"symbolInfo": [], "definition": [], "declaration": [], "references": []}

    def query(method, path, line, char):
        assert path in sources, "must not open/query all 6508 candidate declarations"
        assert leases[path] > 0
        calls[method].append((path, line, char))
        if method == "symbolInfo":
            # clangd 20 shape: valid USR, no optional definition/declaration ranges.
            return [{"usr": "c:@shared", "name": "shared"}]
        if method == "declaration" and route == "declaration":
            return [location(header, 6507, column)]
        return []

    monkeypatch.setattr(ex, "get_symbol_details", lambda *a: query("symbolInfo", *a))
    monkeypatch.setattr(ex, "get_definition", lambda *a: query("definition", *a))
    monkeypatch.setattr(ex, "get_declaration", lambda *a: query("declaration", *a))

    def references(path, line, char, include_declaration=False):
        query("references", path, line, char)
        assert include_declaration
        return [location(header, 6507, column), location(path, 0, 0), location(path, 0, 9)]

    monkeypatch.setattr(ex, "get_references", references)
    cache = DerivedCache(max_bytes=max_bytes)
    resolver = ex._derived_resolver = DerivedResolver(ex, cache)

    def work(i):
        for ordered in (candidates, list(reversed(candidates))):
            with resolver.file(sources[i]) as state:
                stats, context = {}, ex._new_derived_resolution_caches()
                for char in (0, 9):
                    resolver.resolve(ordered, kind, sources[i], 1, char, context, stats, [])
                resolver.flush(state)
                for char in (0, 9):
                    result, reason = resolver.resolve(
                        ordered, kind, sources[i], 1, char, context, stats
                    )
                    assert result["id"] == 6508
                    assert not reason

    try:
        run_workers(cache, workers, work)
        assert len(calls["symbolInfo"]) == workers * 2
        assert len(calls["definition"]) <= workers * 2
        assert len(calls["declaration"]) <= workers * 2
        assert len(calls["references"]) == (workers if route == "use_references" else 0)
        assert header not in opened
        assert not any(leases.values())
        assert cache.stats["peak_hot_bytes"] <= max_bytes
    finally:
        cache.close()


def test_reverse_fallback_only_checks_identities_of_positive_declarations(tmp_path, monkeypatch):
    source, header = tmp_path / "use.cpp", tmp_path / "all.h"
    source.write_text("shared\n")
    header.write_text("int shared;\n" * 512)
    ex = ClangExtractor(tmp_path)
    document_mocks(ex, monkeypatch)
    info, references_sent = [], []

    def details(path, line, char):
        info.append((path, line))
        return [] if path == source else [{"usr": "c:@shared"}]

    def references(path, line, char, **kwargs):
        references_sent.append(line)
        return [location(source)] if line in {0, 511} else []

    monkeypatch.setattr(ex, "get_symbol_details", details)
    monkeypatch.setattr(ex, "get_definition", lambda *a: [])
    monkeypatch.setattr(ex, "get_references", references)
    candidates = [
        {"name": "shared", "file_path": "all.h", "line": i + 1, "id": i + 1} for i in range(512)
    ]
    cache = DerivedCache(max_bytes=1)
    resolver = ex._derived_resolver = DerivedResolver(ex, cache)
    try:
        with resolver.file(source) as state:
            stats, context = {}, ex._new_derived_resolution_caches()
            resolver.resolve(candidates, "global", source, 1, 0, context, stats)
            resolver.flush(state)
            result, reason = resolver.resolve(candidates, "global", source, 1, 0, context, stats)
            assert result["id"] == 1
            assert not reason
        assert info == [(source, 0), (header, 0), (header, 511)]
        assert len(references_sent) == 512
    finally:
        cache.close()


@pytest.mark.parametrize("forward_status", ["empty", "error", "truncated"])
def test_insufficient_forward_evidence_keeps_all_reverse_candidates(
    tmp_path, monkeypatch, forward_status
):
    source, header = tmp_path / "use.cpp", tmp_path / "all.h"
    source.write_text("shared\n")
    header.write_text("int shared;\nint shared;\n")
    ex = ClangExtractor(tmp_path)
    document_mocks(ex, monkeypatch)
    queries = []
    monkeypatch.setattr(ex, "get_symbol_details", lambda *a: [{"usr": "c:@shared"}])
    monkeypatch.setattr(ex, "get_definition", lambda *a: [])

    def references(path, line, char, include_declaration=False):
        queries.append((path, line))
        if path == source:
            if forward_status == "error":
                ex._record_rpc_outcome("textDocument/references", "rpc_error", {"code": -32603})
                return None
            return [location(source)] * 1000 if forward_status == "truncated" else []
        return [location(source)] if line == 1 else []

    monkeypatch.setattr(ex, "get_references", references)
    candidates = [
        {"name": "shared", "file_path": "all.h", "line": i + 1, "id": i + 1} for i in range(2)
    ]
    cache = DerivedCache()
    resolver = ex._derived_resolver = DerivedResolver(ex, cache)
    try:
        with resolver.file(source) as state:
            stats, context = {}, ex._new_derived_resolution_caches()
            resolver.resolve(candidates, "global", source, 1, 0, context, stats)
            resolver.flush(state)
            result, reason = resolver.resolve(candidates, "global", source, 1, 0, context, stats)
            assert result["id"] == 2
            assert not reason
        assert queries == [(source, 0), (header, 0), (header, 1)]
    finally:
        cache.close()


@pytest.mark.parametrize("workers", [1, 8])
def test_heartbeat_reports_while_every_file_is_waiting_for_rpc(tmp_path, monkeypatch, workers):
    ex = ClangExtractor(tmp_path, max_threads=workers)
    document_mocks(ex, monkeypatch)
    cache = DerivedCache()
    resolver = ex._derived_resolver = DerivedResolver(ex, cache)
    resolver.scope = "rebuild_function_symbol_refs"
    monkeypatch.setattr(resolver, "HEARTBEAT_SECONDS", 0.02)
    release = threading.Event()
    records = []
    statements = []
    owner = threading.get_ident()
    cache.db.set_trace_callback(lambda sql: statements.append(threading.get_ident()))

    def details(*args):
        assert release.wait(5), "heartbeat did not report while file workers were blocked"
        return []

    monkeypatch.setattr(ex, "get_symbol_details", details)

    class Handler(logging.Handler):
        def emit(self, record):
            if "[derived-heartbeat]" in record.getMessage():
                snapshot = record.args[0]
                if len(snapshot["active"]) == workers and all(
                    v.get("method") for v in snapshot["active"]
                ):
                    records.append(snapshot)
                    release.set()

    log = logging.getLogger("zscope.retrieval.clang_resolution")
    handler, old_level = Handler(), log.level
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    items = []
    for i in range(workers):
        source = tmp_path / f"use{i}.cpp"
        source.write_text("shared\n")
        items.append((source.name, []))

    def worker(item):
        resolver._rpc("symbolInfo", tmp_path / item[0], 1, 0, {})
        return _DerivedFileResult()

    try:
        with resolver.heartbeat():
            ex._run_derived_file_jobs(items, worker, lambda result: None, {})
        assert records
        assert records[0]["files_completed"] == 0
        assert records[0]["files_total"] == workers
        assert resolver.progress_snapshot()["files_completed"] == workers
        assert resolver.progress_snapshot()["active"] == []
        assert set(statements) == {owner}
        assert not any(t.name == "ClangDerivedHeartbeat" for t in threading.enumerate())
    finally:
        release.set()
        cache.close()
        log.removeHandler(handler)
        log.setLevel(old_level)


@pytest.mark.skipif(shutil.which("clangd") is None, reason="clangd is not installed")
@pytest.mark.parametrize("route", ["declaration", "use_references"])
def test_real_clangd_maps_usr_without_optional_symbol_info_coordinates(
    tmp_path, monkeypatch, route
):
    source = tmp_path / "use.cpp"
    source.write_text('#include "h63.h"\nint f() { return shared; }\n')
    db = KnowledgeDB(str(tmp_path / "knowledge.db"))
    ex = ClangExtractor(tmp_path, compile_commands_dir=tmp_path, clangd_path=shutil.which("clangd"))
    for i in range(64):
        header = tmp_path / f"h{i}.h"
        header.write_text(f"static int shared = {i};\n")
        db.insert_global_variable("shared", "int", header.name, 1, storage_class="static")
    db.insert_function("f", source.name, 2, 2, signature="int f()")
    db.commit()
    (tmp_path / "compile_commands.json").write_text(
        json.dumps(
            [
                {
                    "directory": str(tmp_path),
                    "file": str(source),
                    "arguments": ["clang++", "-c", str(source)],
                }
            ]
        )
    )
    info_calls = []
    try:
        assert ex.start()
        original_details = ex.get_symbol_details

        def details(path, line, char):
            info_calls.append(path)
            return [
                {k: v for k, v in item.items() if k not in {"definitionRange", "declarationRange"}}
                for item in original_details(path, line, char) or []
            ]

        monkeypatch.setattr(ex, "get_symbol_details", details)
        monkeypatch.setattr(ex, "get_definition", lambda *args: [])
        if route == "use_references":
            ex._declaration_supported = False
        assert ex.rebuild_function_symbol_refs(db) == 1
        result = db.get_function_symbol_context("f", source.name)["referenced_globals"]
        assert result[0]["file_path"] == "h63.h"
        assert info_calls == [source]
        stats = ex.get_last_derived_stats("function_symbol_context")
        assert stats.get("references_requests", 0) == (1 if route == "use_references" else 0)
    finally:
        ex.stop()
        db.close()
