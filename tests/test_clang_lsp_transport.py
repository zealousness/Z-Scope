import json
import os
import queue
import threading
import time
from pathlib import Path

from zscope.retrieval.clang_extractor import ClangExtractor


def test_start_cleans_up_process_that_exits_immediately(tmp_path, monkeypatch) -> None:
    extractor = ClangExtractor(tmp_path)

    class DeadProcess:
        stdin = None
        stdout = None
        stderr = None

        def __init__(self):
            self.terminated = False

        @staticmethod
        def poll():
            return 1

        def terminate(self):
            self.terminated = True

        @staticmethod
        def wait(timeout):
            return 1

    class NoopThread:
        def __init__(self, **_kwargs):
            pass

        @staticmethod
        def start():
            pass

    dead_process = DeadProcess()
    monkeypatch.setattr(
        "zscope.retrieval.clang_extractor.subprocess.Popen", lambda *_args, **_kwargs: dead_process
    )
    monkeypatch.setattr("zscope.retrieval.clang_extractor.threading.Thread", NoopThread)
    monkeypatch.setattr("zscope.retrieval.clang_extractor.time.sleep", lambda _seconds: None)

    assert extractor.start() is False
    assert dead_process.terminated is True
    assert extractor.process is None
    assert extractor._transport_closed is True


def test_send_request_is_condition_driven_and_records_latency(tmp_path, monkeypatch) -> None:
    extractor = ClangExtractor(tmp_path)
    written = []

    def write_message(message):
        written.append(message)
        if message.get("method") == "probe":
            threading.Timer(
                0.01,
                lambda: extractor._dispatch_message(
                    {"jsonrpc": "2.0", "id": message["id"], "result": {"ready": True}}
                ),
            ).start()

    monkeypatch.setattr(extractor, "_write_message", write_message)
    monkeypatch.setattr(
        "zscope.retrieval.clang_extractor.time.sleep",
        lambda _seconds: (_ for _ in ()).throw(AssertionError("send_request must not poll")),
    )

    assert extractor.send_request("probe", {}, timeout=1) == {"ready": True}
    assert written[0]["method"] == "probe"
    assert extractor._pending_requests == {}
    metrics = extractor.get_request_metrics("probe")
    assert metrics["count"] == 1
    assert metrics["timeouts"] == 0
    assert metrics["average_latency_ms"] > 0
    assert metrics["p95_latency_ms"] > 0


def test_send_request_hard_timeout_cancels_and_discards_late_response(
    tmp_path, monkeypatch
) -> None:
    extractor = ClangExtractor(tmp_path)
    written = []
    monkeypatch.setattr(extractor, "_write_message", lambda message: written.append(message))

    started_at = time.monotonic()
    assert extractor.send_request("slow", {}, timeout=0.02) is None
    elapsed = time.monotonic() - started_at

    request = written[0]
    assert elapsed < 0.25
    assert written[1] == {
        "jsonrpc": "2.0",
        "method": "$/cancelRequest",
        "params": {"id": request["id"]},
    }
    assert request["id"] not in extractor._pending_requests

    extractor._dispatch_message({"jsonrpc": "2.0", "id": request["id"], "result": "too late"})
    assert request["id"] not in extractor._pending_requests
    assert extractor.get_request_metrics("slow")["timeouts"] == 1


def test_server_request_is_not_mistaken_for_response(tmp_path, monkeypatch) -> None:
    extractor = ClangExtractor(tmp_path)
    written = []
    request_written = threading.Event()
    result = {}

    def write_message(message):
        written.append(message)
        if message.get("method") == "probe":
            request_written.set()

    monkeypatch.setattr(extractor, "_write_message", write_message)
    thread = threading.Thread(
        target=lambda: result.setdefault("value", extractor.send_request("probe", {}, timeout=1))
    )
    thread.start()
    assert request_written.wait(0.5)
    request_id = written[0]["id"]

    extractor._dispatch_message(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "window/workDoneProgress/create",
            "params": {"token": "index"},
        }
    )
    assert thread.is_alive()
    assert written[1] == {"jsonrpc": "2.0", "id": request_id, "result": None}

    extractor._dispatch_message({"jsonrpc": "2.0", "id": request_id, "result": "done"})
    thread.join(0.5)
    assert not thread.is_alive()
    assert result["value"] == "done"


def test_unknown_server_request_gets_method_not_found(tmp_path, monkeypatch) -> None:
    extractor = ClangExtractor(tmp_path)
    written = []
    monkeypatch.setattr(extractor, "_write_message", lambda message: written.append(message))

    extractor._dispatch_message(
        {"jsonrpc": "2.0", "id": "server-1", "method": "custom/unsupported", "params": {}}
    )

    assert written == [
        {
            "jsonrpc": "2.0",
            "id": "server-1",
            "error": {"code": -32601, "message": "Method not found: custom/unsupported"},
        }
    ]


def test_work_done_progress_tracks_each_token_through_end(tmp_path, monkeypatch) -> None:
    extractor = ClangExtractor(tmp_path)
    written = []
    monkeypatch.setattr(extractor, "_write_message", lambda message: written.append(message))

    extractor._dispatch_message(
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "window/workDoneProgress/create",
            "params": {"token": "background-index"},
        }
    )
    assert extractor._progress_tokens == {"background-index": "created"}
    assert written == [{"jsonrpc": "2.0", "id": 7, "result": None}]

    extractor._dispatch_message(
        {
            "jsonrpc": "2.0",
            "method": "$/progress",
            "params": {"token": "background-index", "value": {"kind": "begin"}},
        }
    )
    assert extractor._progress_tokens == {"background-index": "begin"}
    extractor._dispatch_message(
        {
            "jsonrpc": "2.0",
            "method": "$/progress",
            "params": {"token": "background-index", "value": {"kind": "report"}},
        }
    )
    assert extractor._progress_tokens == {"background-index": "report"}
    extractor._dispatch_message(
        {
            "jsonrpc": "2.0",
            "method": "$/progress",
            "params": {"token": "background-index", "value": {"kind": "end"}},
        }
    )
    assert extractor._progress_tokens == {}


def test_created_progress_token_is_not_active_indexing(tmp_path, monkeypatch) -> None:
    extractor = ClangExtractor(tmp_path)
    extractor._initialized = True
    written = []
    monkeypatch.setattr(extractor, "_write_message", lambda message: written.append(message))
    extractor._dispatch_message(
        {
            "jsonrpc": "2.0",
            "id": 8,
            "method": "window/workDoneProgress/create",
            "params": {"token": "reserved-token"},
        }
    )

    assert extractor.wait_for_indexing(timeout=0.2, idle_threshold=0.01) is True
    assert extractor._progress_tokens == {"reserved-token": "created"}


def test_wait_for_indexing_observes_progress_end_and_idle_threshold(tmp_path) -> None:
    extractor = ClangExtractor(tmp_path)
    extractor._initialized = True
    extractor._dispatch_message(
        {
            "jsonrpc": "2.0",
            "method": "$/progress",
            "params": {"token": "index", "value": {"kind": "begin"}},
        }
    )
    timer = threading.Timer(
        0.02,
        lambda: extractor._dispatch_message(
            {
                "jsonrpc": "2.0",
                "method": "$/progress",
                "params": {"token": "index", "value": {"kind": "end"}},
            }
        ),
    )
    timer.start()

    assert extractor.wait_for_indexing(timeout=0.5, idle_threshold=0.01) is True
    timer.join(0.5)


def test_wait_for_indexing_progress_cannot_extend_hard_deadline(tmp_path) -> None:
    extractor = ClangExtractor(tmp_path)
    extractor._initialized = True
    extractor._dispatch_message(
        {
            "jsonrpc": "2.0",
            "method": "$/progress",
            "params": {"token": "index", "value": {"kind": "begin"}},
        }
    )
    stopped = threading.Event()

    def report_progress() -> None:
        while not stopped.wait(0.005):
            extractor._dispatch_message(
                {
                    "jsonrpc": "2.0",
                    "method": "$/progress",
                    "params": {"token": "index", "value": {"kind": "report"}},
                }
            )

    reporter = threading.Thread(target=report_progress)
    reporter.start()
    started_at = time.monotonic()
    try:
        assert extractor.wait_for_indexing(timeout=0.04, idle_threshold=0.01) is False
    finally:
        stopped.set()
        reporter.join(0.5)
    assert time.monotonic() - started_at < 0.25
    assert extractor._MAX_INDEXING_WAIT_SECONDS == 120.0


def test_stop_wakes_pending_request(tmp_path, monkeypatch) -> None:
    extractor = ClangExtractor(tmp_path)
    request_written = threading.Event()
    result = {}
    monkeypatch.setattr(extractor, "_write_message", lambda _message: request_written.set())
    thread = threading.Thread(
        target=lambda: result.setdefault("value", extractor.send_request("probe", {}, timeout=5))
    )
    thread.start()
    assert request_written.wait(0.5)

    extractor.stop()

    thread.join(0.5)
    assert not thread.is_alive()
    assert result["value"] is None
    assert extractor._pending_requests == {}


def test_reader_eof_wakes_pending_request(tmp_path, monkeypatch) -> None:
    extractor = ClangExtractor(tmp_path)
    request_written = threading.Event()
    result = {}

    class FakeStdout:
        @staticmethod
        def fileno() -> int:
            return 99

    class FakeProcess:
        stdout = FakeStdout()

    extractor.process = FakeProcess()
    extractor._running = True
    monkeypatch.setattr(extractor, "_write_message", lambda _message: request_written.set())
    monkeypatch.setattr(os, "read", lambda _fd, _size: b"")
    thread = threading.Thread(
        target=lambda: result.setdefault("value", extractor.send_request("probe", {}, timeout=5))
    )
    thread.start()
    assert request_written.wait(0.5)

    extractor._read_loop()

    thread.join(0.5)
    assert not thread.is_alive()
    assert result["value"] is None
    assert extractor._transport_closed is True


def test_semantic_capabilities_and_server_legend_are_preserved(tmp_path) -> None:
    extractor = ClangExtractor(tmp_path)
    capabilities = extractor._client_capabilities()

    assert capabilities["general"]["positionEncodings"] == ["utf-8"]
    semantic = capabilities["textDocument"]["semanticTokens"]
    assert semantic["requests"] == {"full": True}
    assert semantic["formats"] == ["relative"]
    assert "function" in semantic["tokenTypes"]
    assert "declaration" in semantic["tokenModifiers"]
    assert "functionScope" in semantic["tokenModifiers"]
    assert "globalScope" in semantic["tokenModifiers"]
    assert "localScope" in semantic["tokenModifiers"]

    extractor._apply_server_capabilities(
        {
            "positionEncoding": "utf-8",
            "semanticTokensProvider": {
                "legend": {
                    "tokenTypes": ["variable", "macro"],
                    "tokenModifiers": ["declaration", "readonly", "static"],
                }
            },
        }
    )
    assert extractor._position_encoding == "utf-8"
    assert extractor._semantic_token_types == ["variable", "macro"]
    assert extractor._semantic_token_modifiers == ["declaration", "readonly", "static"]


def test_reference_and_semantic_token_wrappers_preserve_lsp_coordinates(
    tmp_path, monkeypatch
) -> None:
    extractor = ClangExtractor(tmp_path)
    source = tmp_path / "source.c"
    calls = []

    def send_request(method, params, timeout=120):
        calls.append((method, params, timeout))
        if method == "textDocument/references":
            return [{"uri": source.as_uri()}]
        return {"data": [0, 1, 2, 3, 4]}

    monkeypatch.setattr(extractor, "send_request", send_request)

    assert extractor.get_references(source, 4, 9, include_declaration=True) == [
        {"uri": source.as_uri()}
    ]
    assert extractor.get_semantic_tokens(source) == {"data": [0, 1, 2, 3, 4]}
    assert calls == [
        (
            "textDocument/references",
            {
                "textDocument": {"uri": source.as_uri()},
                "position": {"line": 4, "character": 9},
                "context": {"includeDeclaration": True},
            },
            30,
        ),
        (
            "textDocument/semanticTokens/full",
            {"textDocument": {"uri": source.as_uri()}},
            60,
        ),
    ]


def test_lsp_position_encoding_converts_python_offsets(tmp_path, monkeypatch) -> None:
    extractor = ClangExtractor(tmp_path)
    source = tmp_path / "unicode.c"
    source.write_text("int 名称 = value;\n", encoding="utf-8")
    calls = []
    monkeypatch.setattr(
        extractor,
        "send_request",
        lambda method, params, timeout=120: calls.append((method, params, timeout)) or [],
    )

    extractor._position_encoding = "utf-8"
    extractor.get_definition(source, 0, 6)
    assert calls[-1][1]["position"]["character"] == len("int 名称".encode("utf-8"))

    extractor._position_encoding = "utf-16"
    extractor.get_references(source, 0, 6)
    assert calls[-1][1]["position"]["character"] == len("int 名称".encode("utf-16-le")) // 2


class _LiveProcess:
    def __init__(self, stdin, *, stdout=None, stderr=None) -> None:
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.alive = True

    def poll(self):
        return None if self.alive else 0

    def terminate(self) -> None:
        self.alive = False

    def wait(self, timeout):
        self.alive = False
        return 0


def _install_writer(extractor, process):
    outbound = queue.Queue()
    extractor.process = process
    extractor._generation = 1
    extractor._writer_queue = outbound
    extractor._running = True
    extractor._transport_closed = False
    writer = threading.Thread(target=extractor._writer_loop, args=(process, 1, outbound))
    writer.start()
    return outbound, writer


def test_writer_queue_keeps_blocked_pipe_inside_request_deadline(tmp_path) -> None:
    extractor = ClangExtractor(tmp_path)
    entered = threading.Event()
    release = threading.Event()
    recorded = bytearray()

    class BlockingStdin:
        def write(self, payload):
            entered.set()
            assert release.wait(1)
            recorded.extend(payload)
            return len(payload)

        @staticmethod
        def flush() -> None:
            pass

    outbound, writer = _install_writer(extractor, _LiveProcess(BlockingStdin()))
    try:
        assert extractor.send_notification("hold", {"名字": "值"}) is True
        assert entered.wait(0.2)
        started_at = time.monotonic()
        assert extractor.send_request("blocked", {}, timeout=0.03) is None
        assert time.monotonic() - started_at < 0.25
    finally:
        release.set()
        outbound.put(None)
        writer.join(1)

    assert not writer.is_alive()
    metrics = extractor.get_transport_metrics()
    assert metrics["messages_enqueued"] >= 1
    assert metrics["messages_written"] >= 1
    assert metrics["payload_bytes_enqueued"] > 0
    assert metrics["payload_bytes_written"] > 0
    assert metrics["wire_bytes_enqueued"] > metrics["payload_bytes_enqueued"]
    assert metrics["average_write_latency_ms"] >= 0
    assert metrics["expired_before_write"] == 1

    decoded = []
    wire = bytes(recorded)
    while wire:
        header_end = wire.index(b"\r\n\r\n")
        declared = int(wire[:header_end].split(b":", 1)[1].strip())
        body_start = header_end + 4
        body = wire[body_start : body_start + declared]
        assert len(body) == declared
        decoded.append(json.loads(body))
        wire = wire[body_start + declared :]
    assert [message["method"] for message in decoded] == ["hold", "$/cancelRequest"]


def test_writer_failure_wakes_pending_request(tmp_path) -> None:
    extractor = ClangExtractor(tmp_path)

    class BrokenStdin:
        @staticmethod
        def write(_payload):
            raise BrokenPipeError

        @staticmethod
        def flush() -> None:
            pass

    _outbound, writer = _install_writer(extractor, _LiveProcess(BrokenStdin()))
    started_at = time.monotonic()
    assert extractor.send_request("probe", {}, timeout=5) is None
    writer.join(1)

    assert time.monotonic() - started_at < 0.5
    assert extractor._transport_closed is True
    assert extractor.get_transport_metrics()["write_failures"] == 1


def test_reader_frames_fragmented_large_utf8_payload_with_bytearray(tmp_path, monkeypatch) -> None:
    extractor = ClangExtractor(tmp_path)
    result = {"名字": "值", "blob": "x" * 100_000}
    body = json.dumps({"jsonrpc": "2.0", "id": 41, "result": result}, ensure_ascii=False).encode(
        "utf-8"
    )
    wire = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body
    chunks = iter(wire[index : index + 997] for index in range(0, len(wire), 997))

    class FakeStdout:
        @staticmethod
        def fileno() -> int:
            return 77

    process = _LiveProcess(None, stdout=FakeStdout())
    extractor.process = process
    extractor._generation = 4
    extractor._running = True
    extractor._transport_closed = False
    extractor._pending_requests[41] = None
    monkeypatch.setattr(os, "read", lambda _fd, _size: next(chunks, b""))

    extractor._read_loop(process, 4)

    assert extractor._pending_requests[41]["result"] == result
    metrics = extractor.get_transport_metrics()
    assert metrics["reader_bytes"] == len(wire)
    assert metrics["reader_messages"] == 1
    assert metrics["reader_payload_bytes"] == len(body)
    assert metrics["reader_max_payload_bytes"] == len(body)


def test_stale_reader_eof_cannot_close_new_process_generation(tmp_path) -> None:
    extractor = ClangExtractor(tmp_path)

    class FakeStdout:
        @staticmethod
        def fileno() -> int:
            return 88

    current = _LiveProcess(None)
    stale = _LiveProcess(None, stdout=FakeStdout())
    extractor.process = current
    extractor._generation = 2
    extractor._running = True
    extractor._transport_closed = False

    extractor._read_loop(stale, 1)

    assert extractor._running is True
    assert extractor._transport_closed is False
    assert extractor.process is current


def test_health_checks_process_liveness_and_stop_joins_threads(tmp_path) -> None:
    extractor = ClangExtractor(tmp_path)
    process = _LiveProcess(None)
    extractor.process = process
    extractor._initialized = True
    extractor._running = True
    extractor._transport_closed = False
    assert extractor.is_healthy() is True
    process.alive = False
    assert extractor.is_healthy() is False

    joined = []

    class Joinable:
        def join(self, timeout):
            joined.append(timeout)

    extractor._writer_thread = Joinable()
    extractor._reader_thread = Joinable()
    extractor._stderr_thread = Joinable()
    extractor.stop()
    assert len(joined) == 3


def test_start_replaces_dead_process_with_new_generation(tmp_path, monkeypatch) -> None:
    extractor = ClangExtractor(tmp_path)
    stale = _LiveProcess(None)
    stale.alive = False
    replacement = _LiveProcess(object(), stdout=object(), stderr=object())
    extractor.process = stale
    extractor._generation = 7
    extractor._running = True
    extractor._initialized = True

    class NoopThread:
        def __init__(self, **_kwargs):
            pass

        @staticmethod
        def start() -> None:
            pass

        @staticmethod
        def join(timeout) -> None:
            pass

    monkeypatch.setattr(
        "zscope.retrieval.clang_extractor.subprocess.Popen",
        lambda *_args, **_kwargs: replacement,
    )
    monkeypatch.setattr("zscope.retrieval.clang_extractor.threading.Thread", NoopThread)
    monkeypatch.setattr("zscope.retrieval.clang_extractor.time.sleep", lambda _seconds: None)
    monkeypatch.setattr(
        extractor,
        "send_request",
        lambda method, _params, timeout=120: (
            {"capabilities": {}} if method == "initialize" else None
        ),
    )
    monkeypatch.setattr(extractor, "send_notification", lambda _method, _params: True)

    assert extractor.start() is True
    assert extractor.process is replacement
    assert extractor._generation == 8
    assert extractor.is_healthy() is True


def test_document_leases_are_thread_safe_and_emit_only_edge_notifications(
    tmp_path, monkeypatch
) -> None:
    extractor = ClangExtractor(tmp_path)
    source = tmp_path / "lease.c"
    source.write_text("int value;\n", encoding="utf-8")
    notifications = []
    notifications_lock = threading.Lock()

    def notify(method, params):
        with notifications_lock:
            notifications.append((method, params))
        return True

    monkeypatch.setattr(extractor, "send_notification", notify)
    open_results = []
    open_threads = [
        threading.Thread(target=lambda: open_results.append(extractor.open_document(source)))
        for _ in range(8)
    ]
    for thread in open_threads:
        thread.start()
    for thread in open_threads:
        thread.join(1)

    assert open_results == [True] * 8
    assert extractor._opened_documents[source.resolve().as_uri()] == 8
    assert [item[0] for item in notifications] == ["textDocument/didOpen"]

    close_threads = [
        threading.Thread(target=lambda: extractor.close_document(source)) for _ in range(8)
    ]
    for thread in close_threads:
        thread.start()
    for thread in close_threads:
        thread.join(1)

    assert extractor._opened_documents == {}
    assert [item[0] for item in notifications] == [
        "textDocument/didOpen",
        "textDocument/didClose",
    ]


def test_source_lines_cache_reuses_split_result_and_invalidates_on_change(tmp_path) -> None:
    extractor = ClangExtractor(tmp_path)
    source = tmp_path / "cached.c"
    source.write_text("first\nsecond\n", encoding="utf-8")

    first = extractor._read_source_lines(source)
    second = extractor._read_source_lines(source)
    assert first is second

    source.write_text("first\nsecond changed\n", encoding="utf-8")
    third = extractor._read_source_lines(source)
    assert third is not first
    assert third == ["first\n", "second changed\n"]


def test_file_status_wait_is_optional_and_tracks_building_to_idle(tmp_path) -> None:
    extractor = ClangExtractor(tmp_path)
    source = tmp_path / "status.c"
    uri = source.resolve().as_uri()

    assert extractor.wait_for_file_idle(source, timeout=0.01) is True
    assert extractor.wait_for_file_idle(source, timeout=0.01, require_notification=True) is False

    extractor._dispatch_message(
        {
            "jsonrpc": "2.0",
            "method": "textDocument/clangd.fileStatus",
            "params": {"uri": uri, "state": "building"},
        }
    )
    timer = threading.Timer(
        0.02,
        lambda: extractor._dispatch_message(
            {
                "jsonrpc": "2.0",
                "method": "textDocument/clangd.fileStatus",
                "params": {"uri": uri, "state": "idle"},
            }
        ),
    )
    timer.start()
    assert extractor.wait_for_file_idle(source, timeout=0.5) is True
    timer.join(1)
    assert extractor.get_file_status(source) == "idle"


def test_symbol_info_ast_and_range_helpers(tmp_path, monkeypatch) -> None:
    extractor = ClangExtractor(tmp_path)
    source = tmp_path / "extensions.c"
    source.write_text("int 名称;\n", encoding="utf-8")
    extractor._position_encoding = "utf-8"
    calls = []

    def request(method, params, timeout=120):
        calls.append((method, params, timeout))
        if method == "textDocument/symbolInfo":
            return [{"usr": "c:@名称"}]
        return {"kind": "TranslationUnit"}

    monkeypatch.setattr(extractor, "send_request", request)
    assert extractor.get_symbol_info(source, 0, 6) == {"usr": "c:@名称"}
    requested_range = {
        "start": {"line": 0, "character": len("int ".encode("utf-8"))},
        "end": {"line": 0, "character": len("int 名称".encode("utf-8"))},
    }
    assert extractor.get_ast(source, requested_range) == {"kind": "TranslationUnit"}
    assert extractor._lsp_range_to_python(source, requested_range) == {
        "start": {"line": 0, "character": 4},
        "end": {"line": 0, "character": 6},
    }
    assert calls[0][0] == "textDocument/symbolInfo"
    assert calls[0][1]["position"]["character"] == len("int 名称".encode("utf-8"))
    assert calls[1] == (
        "textDocument/ast",
        {"textDocument": {"uri": source.resolve().as_uri()}, "range": requested_range},
        60,
    )
    capabilities = extractor._client_capabilities()["textDocument"]
    assert capabilities["symbolInfo"] == {}
    assert capabilities["ast"] == {}
