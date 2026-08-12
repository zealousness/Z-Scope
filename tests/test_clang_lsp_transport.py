import os
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
