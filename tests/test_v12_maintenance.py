"""Regression coverage for independent v1.2 maintenance changes."""

import json
import os
import shutil
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from zscope.common.joern_client import JoernClient, _scala_string
from zscope.retrieval.clang_extractor import ClangExtractor
from zscope.retrieval.clang_extractor_pool import ClangExtractorPool, _CollectedFacts
from zscope.retrieval.code_index import CodeIndex
from zscope.retrieval.knowledge_db import KnowledgeDB


def make_index(tmp_path, cache_bytes=1024 * 1024):
    source = tmp_path / "sample.c"
    source.write_text("int sample(void) { return 1; }\n", encoding="utf-8")
    rows = {"sample": dict(name="sample", file=str(source), start_line=1, end_line=1)}
    backend = SimpleNamespace(build_function_index=lambda: rows, close=lambda: None)
    return (
        CodeIndex(
            tmp_path,
            source_root=tmp_path,
            backend=backend,
            indexing_config=SimpleNamespace(backend="clang", shared_cache_max_bytes=cache_bytes),
        ),
        source,
    )


def test_replaced_source_refreshes_both_function_and_snippet(tmp_path):
    index, source = make_index(tmp_path)
    try:
        assert "return 1" in index.get_function_impl("sample", include_context=False)["code"]
        stat = source.stat()
        replacement = tmp_path / "replacement.c"
        replacement.write_text("int sample(void) { return 2; }\n", encoding="utf-8")
        os.utime(replacement, ns=(stat.st_atime_ns, stat.st_mtime_ns))
        replacement.replace(source)
        assert source.stat().st_size == stat.st_size
        assert "return 2" in index.get_function_impl("sample", include_context=False)["code"]
        assert "return 2" in index.get_file_snippet(str(source), 1, 1)["code"]
    finally:
        index.close()


def test_tiny_cache_budget_returns_results_without_retaining_them(tmp_path):
    index, source = make_index(tmp_path, cache_bytes=8)
    try:
        assert "return 1" in index.get_function_impl("sample", include_context=False)["code"]
        assert index._shared_cache_bytes <= 8
        assert not index._function_impl_cache
        assert not index._file_lines_cache
    finally:
        index.close()


def test_missing_scoped_queries_do_not_scan_unrelated_functions(tmp_path, monkeypatch):
    rows = {
        str(i): dict(name=f"api_{i}", file=f"src/{i}.c", start_line=1, end_line=2)
        for i in range(1000)
    }
    backend = SimpleNamespace(build_function_index=lambda: rows, close=lambda: None)
    index = CodeIndex(tmp_path, backend=backend)
    try:
        monkeypatch.setattr(index, "_record_matches_file_hint", lambda *_: pytest.fail("full scan"))
        for i in range(10):
            assert index._resolve_function_name_by_file(f"external_{i}", "unknown.h") == ""
        index._add_function_index_entry(
            "new_api", dict(name="new_api", file="new.c", start_line=1, end_line=2)
        )
        monkeypatch.undo()
        assert index._resolve_function_name_by_file("new_api", "new.c") == "new_api"
        rows.clear()
        rows["replacement"] = dict(name="replacement", file="replace.c", start_line=1, end_line=2)
        index._build_index()
        assert not index._function_query_index.get("new_api")
    finally:
        index.close()


def test_headers_use_one_scope_scan_per_file(tmp_path, monkeypatch):
    index, _ = make_index(tmp_path)
    (tmp_path / "sample.h").write_text("int sample(void);\nint missing(void);\n", encoding="utf-8")
    calls = []
    original = index._cpp_type_scopes

    def scopes(lines):
        calls.append(len(lines))
        return original(lines)

    monkeypatch.setattr(index, "_cpp_type_scopes", scopes)
    monkeypatch.setattr(index, "_enclosing_cpp_type_name", lambda *_: pytest.fail("prefix rescan"))
    try:
        assert [
            row["name"] for row in index.get_header_declared_functions(["*.h", "sample.h"])
        ] == ["sample"]
        assert calls == [2]
    finally:
        index.close()


@pytest.mark.parametrize("name", ['foo"bar\\baz', "line\nbreak", "中文名称", "\\d+\\.c"])
def test_joern_parameters_are_single_scala_literals(name):
    captured = []
    client = object.__new__(JoernClient)
    client.query = lambda query: captured.append(query) or []
    client.get_method(name)
    assert _scala_string(name) in captured[0]
    assert json.loads(_scala_string(name)) == name


def test_joern_file_suffix_is_encoded_with_the_leading_slash():
    captured = []
    client = object.__new__(JoernClient)
    client.query = lambda query: captured.append(query) or []
    path = 'src/quoted"file.c'
    client.get_method_callers("api", callee_file=path)
    assert "m.filename.endsWith(" + _scala_string("/" + path) + ")" in captured[0]


def test_lsp_progress_request_is_answered_and_not_stored_as_response(tmp_path):
    extractor = ClangExtractor(tmp_path)
    extractor._dispatch_message(
        dict(id=42, method="window/workDoneProgress/create", params=dict(token="job"))
    )
    frame, _, _ = extractor._write_queue.get_nowait()
    assert json.loads(frame.split(b"\r\n\r\n", 1)[1]) == dict(jsonrpc="2.0", id=42, result=None)
    assert extractor._responses == {}
    assert extractor._progress_tokens["job"][0] == "created"


def test_lsp_fixed_timeout_ignores_progress_and_discards_late_response(tmp_path):
    extractor = ClangExtractor(tmp_path)
    stop = threading.Event()

    def progress():
        while not stop.wait(0.003):
            extractor._dispatch_message(
                dict(method="$/progress", params=dict(token="job", value=dict(kind="report")))
            )

    thread = threading.Thread(target=progress)
    thread.start()
    try:
        started = time.monotonic()
        assert extractor.send_request("textDocument/documentSymbol", {}, timeout=0.04) is None
        assert time.monotonic() - started < 0.3
        extractor._dispatch_message(dict(id=1, result="late"))
        assert not extractor._responses
        assert not extractor._pending_requests
    finally:
        stop.set()
        thread.join()


def test_lsp_response_and_transport_close_wake_requests(tmp_path):
    extractor = ClangExtractor(tmp_path)

    def write(message):
        extractor._dispatch_message(dict(id=message["id"], result={"ok": True}))

    extractor._write_message = write
    assert extractor.send_request("test", {}, timeout=0.1) == {"ok": True}
    extractor._write_message = lambda _: extractor._close_transport()
    assert extractor.send_request("test", {}, timeout=5) is None


def test_old_transport_generation_cannot_close_or_populate_replacement(tmp_path):
    extractor = ClangExtractor(tmp_path)
    extractor._generation = 2
    extractor._pending_requests.add(1)
    extractor._dispatch_message(dict(id=1, result="old"), generation=1)
    extractor._close_transport(generation=1)
    assert not extractor._responses
    assert not extractor._transport_closed


def test_reader_eof_wakes_pending_request(tmp_path):
    extractor = ClangExtractor(tmp_path)
    read_fd, write_fd = os.pipe()
    stdout = os.fdopen(read_fd, "rb", buffering=0)
    extractor.process = SimpleNamespace(stdout=stdout, poll=lambda: 1)
    extractor._running = True
    sent = threading.Event()
    extractor._write_message = lambda message: sent.set()
    results = []
    request = threading.Thread(
        target=lambda: results.append(extractor.send_request("test", {}, timeout=5))
    )
    reader = threading.Thread(target=extractor._read_loop)
    try:
        request.start()
        assert sent.wait(1)
        reader.start()
        os.close(write_fd)
        request.join(timeout=1)
        reader.join(timeout=1)
        assert not request.is_alive() and not reader.is_alive()
        assert results == [None]
    finally:
        extractor._running = False
        extractor._close_transport()
        stdout.close()


def test_loop_guard_keeps_other_tools_and_revalidates_results(monkeypatch):
    from zscope.framework.llm_client import LLMClient

    client = LLMClient(api_key="test", base_url="http://example.invalid", models=["test"])
    calls = []
    executed = []
    schemas = [
        dict(type="function", function=dict(name=name, parameters={}))
        for name in ("lookup", "other")
    ]

    def completion(messages, **kwargs):
        calls.append(kwargs)
        if len(calls) == 4:
            message = dict(role="assistant", content="done")
            reason = "stop"
        else:
            name = "other" if len(calls) == 3 else "lookup"
            if len(calls) == 3:
                assert [row["function"]["name"] for row in kwargs["tools"]] == ["other"]
            message = dict(
                role="assistant",
                content="",
                tool_calls=[
                    dict(
                        id=str(len(calls)),
                        type="function",
                        function=dict(name=name, arguments="{}"),
                    )
                ],
            )
            reason = "tool_calls"
        return dict(choices=[dict(finish_reason=reason, message=message)], usage={})

    monkeypatch.setattr(client, "chat_completion", completion)
    result = client.run_conversation_with_tools(
        [dict(role="user", content="start")],
        schemas,
        lambda name, args: executed.append(name) or {"value": name},
        max_identical_tool_calls=1,
        max_iterations=5,
    )
    assert result["content"] == "done"
    assert executed == ["lookup", "lookup", "other"]


def test_blocked_pipe_write_stays_inside_request_deadline(tmp_path):
    extractor = ClangExtractor(tmp_path)
    release = threading.Event()
    entered = threading.Event()

    class Pipe:
        def write(self, _):
            entered.set()
            release.wait(2)

        def flush(self):
            pass

    extractor.process = SimpleNamespace(stdin=Pipe())
    extractor._running = True
    worker = threading.Thread(target=extractor._writer_loop)
    worker.start()
    try:
        started = time.monotonic()
        assert extractor.send_request("test", {}, timeout=0.04) is None
        assert entered.is_set()
        assert time.monotonic() - started < 0.3
    finally:
        release.set()
        extractor._running = False
        extractor._write_queue.put(None)
        worker.join(timeout=2)
        assert not worker.is_alive()


def test_collected_type_ids_are_rebound_on_publication():
    facts = _CollectedFacts()
    token = facts.insert_type("Record", "struct", "a.c", 1, 3, tu_id=1)
    facts.insert_type_member(token, "field", "int", 0)
    members = []
    facts.publish(
        SimpleNamespace(
            insert_type=lambda *a, **kw: 123, insert_type_member=lambda *args: members.append(args)
        )
    )
    assert members == [(123, "field", "int", 0)]


def test_shards_extract_concurrently_and_publish_on_owner_thread(tmp_path):
    owner = threading.get_ident()
    barrier = threading.Barrier(2)
    pool = object.__new__(ClangExtractorPool)

    class Shard:
        def extract_tu(self, path, db, tu_id):
            assert threading.get_ident() != owner
            barrier.wait(timeout=2)
            db.insert_functions_batch([(path.stem, tu_id)])
            return True

        def close_document(self, _):
            pass

    pool._shards = [Shard(), Shard()]
    paths = [tmp_path / "a" / "one.c", tmp_path / "b" / "two.c"]
    for path in paths:
        path.parent.mkdir()
        path.write_text("int api(void);", encoding="utf-8")

    def published(*args):
        assert threading.get_ident() == owner

    db = SimpleNamespace(
        purge_tu_data=published, insert_functions_batch=published, commit=published
    )
    prescan = {str(path): (i, True) for i, path in enumerate(paths)}
    assert pool.run_batch_extraction(paths, db, prescanned_tus=prescan) == dict(
        total=2, success=2, failed=0, skipped=0
    )


def test_lazy_planning_is_used_by_the_actual_svf_entrypoint(tmp_path, monkeypatch):
    from zscope.retrieval import svf_analyzer as module
    from zscope.retrieval.svf_runner import SvfResult

    source = tmp_path / "main.c"
    source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    commands = tmp_path / "compile_commands.json"
    commands.write_text(
        json.dumps(
            [dict(directory=str(tmp_path), file=str(source), arguments=["cc", "-c", str(source)])]
        ),
        encoding="utf-8",
    )
    bitcode = tmp_path / "all.bc"
    bitcode.write_bytes(b"bitcode")
    calls = []

    class Builder:
        def __init__(self, **kwargs):
            pass

        def plan_required_sources(self, **kwargs):
            calls.append("plan")
            return {str(source)}

        def build(self, groups, **kwargs):
            calls.append(kwargs["only_sources"])
            return {"default": bitcode}

    class Runner:
        def __init__(self, **kwargs):
            pass

        def run_ander(self, path, output):
            output.mkdir(parents=True, exist_ok=True)
            dot = output / "callgraph_final.dot"
            dot.write_text("digraph {}\n", encoding="utf-8")
            return SvfResult(tool="ander", success=True, output_file=dot)

    monkeypatch.setenv("Z_SCOPE_SVF_LAZY_BITCODE", "1")
    monkeypatch.setattr(module, "BitcodeBuilder", Builder)
    monkeypatch.setattr(module, "SvfRunner", Runner)
    db = KnowledgeDB(str(tmp_path / "facts.db"))
    try:
        assert module.SvfAnalyzer(db).run(tmp_path, tmp_path, commands, entry_functions=["main"])
        assert calls == ["plan", {str(source)}]
    finally:
        db.close()


@pytest.mark.skipif(shutil.which("clangd") is None, reason="clangd is not installed")
def test_real_clangd_two_shard_extraction(tmp_path):
    paths = [tmp_path / "left" / "one.c", tmp_path / "right" / "two.c"]
    for i, path in enumerate(paths):
        path.parent.mkdir()
        path.write_text(f"int api_{i}(void) {{ return {i}; }}\n", encoding="utf-8")
    (tmp_path / "compile_commands.json").write_text(
        json.dumps(
            [
                dict(directory=str(tmp_path), file=str(path), arguments=["clang", "-c", str(path)])
                for path in paths
            ]
        ),
        encoding="utf-8",
    )
    db = KnowledgeDB(str(tmp_path / "facts.db"))
    pool = ClangExtractorPool(tmp_path, compile_commands_dir=tmp_path, max_threads=2, shard_count=2)
    try:
        assert pool.start()
        stats = pool.run_batch_extraction(paths, db)
        assert stats["success"] == 2, stats
        assert set(db.get_all_functions()) == {"api_0", "api_1"}
        assert pool.run_batch_extraction(paths, db)["skipped"] == 2
    finally:
        pool.stop()
        db.close()
