import json
import os
import shutil
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest

from zscope.retrieval import clang_type_state as state
from zscope.retrieval.clang_type_worker import FunctionTypeCollector, TypeCollectionCancelled
from zscope.retrieval.knowledge_db import KnowledgeDB


@pytest.fixture
def compiler_project(tmp_path):
    clangd = shutil.which("clangd")
    clang = shutil.which("clang")
    if not clangd or not clang:
        pytest.skip("real clang/clangd required")
    source = tmp_path / "a.c"
    source.write_text(
        "struct Item { int value; };\n"
        "int first(struct Item *p) {\n"
        "  struct Item local;\n"
        "  return sizeof(struct Item) + p->value;\n"
        "}\n"
        "int second(struct Item *p) {\n"
        "  return p->value;\n"
        "}\n",
        encoding="utf-8",
    )
    cdb = tmp_path / "compile_commands.json"
    cdb.write_text(
        json.dumps(
            [
                {
                    "file": str(source),
                    "directory": str(tmp_path),
                    "arguments": [
                        clang,
                        "-x",
                        "c",
                        "-std=c11",
                        "-c",
                        str(source),
                        "-MD",
                        "-MF",
                        str(tmp_path / "a.d"),
                    ],
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "a.d").write_text("a.o: " + str(source) + "\n", encoding="utf-8")
    db = KnowledgeDB(str(tmp_path / "facts.db"))
    for name, begin, end in [("first", 2, 5), ("second", 6, 8)]:
        db._conn.execute(
            "INSERT INTO functions(name,file_path,start_line,end_line,signature) VALUES (?,?,?,?,?)",
            (name, "a.c", begin, end, "int " + name + "(struct Item *p)"),
        )
    db._conn.execute(
        "INSERT INTO type_definitions(name,kind,file_path,start_line,end_line,full_definition) "
        "VALUES ('Item','struct','a.c',1,1,'struct Item { int value; };')"
    )
    db.commit()
    state.initialize_states(db, "generation", {"a.c": "command"})
    backend = SimpleNamespace(
        _db=db,
        _source_path=tmp_path,
        _compile_commands_path=str(cdb),
        _clangd_path=clangd,
        _max_threads=2,
        _type_ref_cache_nonce="test-run",
    )
    yield backend
    db.close()


def test_real_clangd_collects_one_function_and_reuses_checkpoint(compiler_project):
    backend = compiler_project
    collector = FunctionTypeCollector(backend)
    try:
        collector.prepare()
        assert collector.ex.wait_for_indexing(timeout=30, idle_threshold=0.2)
        first = state.function_record(backend._db, "first", "a.c", 2)
        uses = []
        original = collector.ex.get_symbol_details

        def track(path, line, character=0):
            uses.append((path, line + 1))
            return original(path, line, character)

        collector.ex.get_symbol_details = track
        rows = collector.collect(first, lambda: None)
        assert rows
        assert all(row[0] == first["id"] and row[1] is not None for row in rows)
        assert {row[6] for row in rows} >= {"parameter", "local", "sizeof", "member_access"}
        assert all(line <= 5 for _, line in uses)
        count = len(uses)
        assert collector.collect(first, lambda: None) == rows
        assert len(uses) == count
        # The checkpoint is function scoped, never a completed file checkpoint.
        assert collector.cache.get("file", "a.c") is None
        assert (
            backend._db._conn.execute("SELECT COUNT(*) FROM function_type_refs").fetchone()[0] == 0
        )
    finally:
        collector.close()


def test_real_collector_rejects_source_change_before_publication(compiler_project):
    collector = FunctionTypeCollector(compiler_project)
    try:
        collector.prepare()
        source = Path(compiler_project._source_path) / "a.c"
        source.write_text(source.read_text() + "\n#define CHANGED 1\n")
        with pytest.raises(state.TypeContextUnavailable, match="changed"):
            collector.check_inputs(state.function_record(compiler_project._db, "first", "a.c", 2))
    finally:
        collector.close()


def test_real_resume_reuses_successful_rpc_evidence_after_interruption(compiler_project):
    first = state.function_record(compiler_project._db, "first", "a.c", 2)
    collector = FunctionTypeCollector(compiler_project)
    sent_before, sent_after = [], []

    def track(ex, sent):
        send = ex.send_request

        def request(method, params=None, **kwargs):
            result = send(method, params, **kwargs)
            if method.startswith("textDocument/") and result is not None:
                sent.append((method, json.dumps(params, sort_keys=True)))
            return result

        ex.send_request = request

    steps = 0

    def interrupt():
        nonlocal steps
        steps += 1
        if steps == 3:
            raise TypeCollectionCancelled()

    try:
        collector.prepare()
        assert collector.reusable
        assert collector.ex.wait_for_indexing(timeout=30, idle_threshold=0.2)
        track(collector.ex, sent_before)
        with pytest.raises(TypeCollectionCancelled):
            collector.collect(first, interrupt)
        assert sent_before
    finally:
        collector.close()
    resumed = FunctionTypeCollector(compiler_project)
    try:
        resumed.prepare()
        # Cooperative indexing observes readiness without a blocking full-index wait.
        with resumed.ex._condition:
            resumed.ex._progress_tokens.clear()
            resumed.ex._last_progress_time -= 6
            resumed.ex._derived_index_ready = False
        assert resumed.resolver.index_ready()
        track(resumed.ex, sent_after)
        rows = resumed.collect(first, lambda: None)
        assert rows and all(row[0] == first["id"] for row in rows)
        assert not set(sent_before) & set(sent_after)
        assert resumed.cache.snapshot()["disk_hits"] > 0
    finally:
        resumed.close()


@pytest.mark.parametrize("shards", ["1", "2"])
@pytest.mark.parametrize("all_failed", [False, True])
def test_auto_real_fallback_returns_before_types_and_consumes_one_function(
    compiler_project,
    monkeypatch,
    shards,
    all_failed,
):
    from zscope.retrieval.clang_backend import ClangBackend
    from zscope.retrieval.clang_batch import BatchIndexer

    native = os.environ.get("Z_SCOPE_TEST_CLANG_INDEXER")
    if not native:
        pytest.skip("native tool required to exercise auto fallback")
    project = compiler_project
    monkeypatch.setenv("Z_SCOPE_CLANGD_SHARDS", shards)
    from zscope.retrieval.clang_extractor import ClangExtractor

    def forbidden(*args, **kwargs):
        pytest.fail("auto fallback synchronously rebuilt type references")

    monkeypatch.setattr(ClangExtractor, "rebuild_function_type_refs", forbidden)
    monkeypatch.setattr(ClangExtractor, "rebuild_function_derived_refs", forbidden)
    other = project._source_path / "b.c"
    other.write_text("int batch_only(void) { return 0; }\n", encoding="utf-8")
    cdb = Path(project._compile_commands_path)
    commands = json.loads(cdb.read_text())
    commands.append(
        {
            "directory": str(project._source_path),
            "file": str(other),
            "arguments": [shutil.which("clang"), "-c", str(other)],
        }
    )
    cdb.write_text(json.dumps(commands))
    gate = threading.Event()
    original_collect = FunctionTypeCollector.collect

    def collect(self, function, checkpoint):
        assert gate.wait(10)
        return original_collect(self, function, checkpoint)

    original_extract = BatchIndexer._extract

    def fail_native(self, job):
        if all_failed or Path(job["source"]).name == "a.c":
            raise RuntimeError("injected TU batch failure")
        return original_extract(self, job)

    monkeypatch.setattr(BatchIndexer, "_extract", fail_native)
    monkeypatch.setattr(FunctionTypeCollector, "collect", collect)
    backend = ClangBackend(
        clangd_path=project._clangd_path,
        frontend="auto",
        clang_indexer_path=native,
        db_path="auto.db",
        max_threads=2,
    )
    try:
        assert backend.initialize(
            str(project._source_path), compile_commands_path=project._compile_commands_path
        )
        assert backend.status() == "ready"
        assert not backend._derived_indexes_are_current(backend.db)
        assert backend._derived_indexes_ready_for_queries(backend.db)
        assert backend.db.get_derived_index_state("function_symbol_context")["status"] == "current"
        with ThreadPoolExecutor(1) as pool:
            result = pool.submit(backend.get_function_type_context, "first", "a.c", 2)
            gate.set()
            context = result.result(30)
        assert context["referenced_types"]
        assert not context.get("unresolved_referenced_types")
        # An unchanged batch failure does not force base/symbol extraction again.
        monkeypatch.setattr(
            backend, "_ensure_extractor", lambda: pytest.fail("base was re-extracted")
        )
        assert backend._run_full_extraction()
    finally:
        gate.set()
        backend.close()
