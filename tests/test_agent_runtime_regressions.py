"""The ten runtime audit reproducers, plus adjacent cancellation/protocol boundaries.

All network fixtures are local. No provider keys, tokenizer downloads or external
model calls are needed; real requests exercise the production transport boundary.
"""

from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import random
import threading
from types import SimpleNamespace

import pytest

from zscope.common.cancellation import CancellationError, CancellationToken, bind_cancellation_token
from zscope.framework.context_window import ContextWindowExceeded
from zscope.framework.conversation_recorder import (
    disable_conversation_recording,
    enable_conversation_recording,
)
from zscope.framework.llm_client import LLMClient
from zscope.framework.chat_protocol import ChatChunkDecoder
from zscope.tools.runtime import ToolsRuntime


def call(name="finish", identifier="call_1", arguments=None):
    return {
        "index": 0,
        "id": identifier,
        "type": "function",
        "function": {"name": name, "arguments": json.dumps(arguments or {})},
    }


def frame(delta, finish=None):
    return {"choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}


def schema(name):
    return {
        "type": "function",
        "function": {
            "name": name,
            "parameters": {"type": "object", "properties": {}},
        },
    }


MESSAGES = [{"role": "user", "content": "Synthetic runtime protocol regression"}]


@pytest.fixture
def server_factory(monkeypatch):
    monkeypatch.setenv("Z_SCOPE_LLM_TRANSPORT", "requests")
    resources = []

    def create(responder, *, stall=None):
        requests = []
        ready = threading.Event()
        release = threading.Event()

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                requests.append(request)
                try:
                    if stall == "headers":
                        ready.set()
                        release.wait(5)
                    status, chunks = responder(len(requests), request)
                    body = "".join(
                        "data: " + json.dumps(chunk) + "\n\n" for chunk in chunks
                    ).encode()
                    self.send_response(status)
                    self.send_header("Content-Type", "text/event-stream")
                    if stall not in {"stream", "after_done"}:
                        self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    if stall == "stream":
                        self.wfile.write(
                            (
                                "data: "
                                + json.dumps(frame({"content": "working"}))
                                + "\n\n:"
                                + "x" * 700
                                + "\n\n"
                            ).encode()
                        )
                        self.wfile.flush()
                        ready.set()
                        release.wait(5)
                    self.wfile.write(body)
                    if stall == "after_done":
                        self.wfile.write(b"data: [DONE]\n\n")
                        self.wfile.flush()
                        ready.set()
                        release.wait(5)
                except (BrokenPipeError, ConnectionResetError):
                    pass  # A cancelled client must have closed this connection.

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        client = LLMClient(
            api_key="synthetic",
            base_url=f"http://127.0.0.1:{server.server_port}/v1",
            models=["audit-model"],
            max_retries=0,
            timeout=10,
        )
        client.session.trust_env = False
        resource = SimpleNamespace(client=client, requests=requests, ready=ready, release=release)
        resources.append((resource, server, thread))
        return resource

    yield create
    for resource, server, thread in resources:
        resource.release.set()
        resource.client.close()
        server.shutdown()
        server.server_close()
        thread.join(2)


def test_partial_stream_cannot_accept_terminal(server_factory):
    server = server_factory(lambda *_: (200, [frame({"tool_calls": [call()]})]))
    accepted = []
    with pytest.raises(Exception, match="finish_reason"):
        server.client.run_conversation_with_tools(
            MESSAGES,
            [schema("finish")],
            lambda *_: {},
            max_iterations=3,
            terminal_tool_name="finish",
            terminal_tool_required=True,
            terminal_tool_handler=lambda args: accepted.append(args) or {"valid": True},
        )
    assert accepted == []
    assert len(server.requests) == 1


def test_inband_error_cannot_turn_partial_content_into_success(server_factory):
    server = server_factory(
        lambda *_: (
            200,
            [
                frame({"content": '{"verdict":"safe"}'}),
                {"error": {"message": "synthetic provider failure"}},
            ],
        )
    )
    with pytest.raises(Exception, match="Provider stream returned an error"):
        server.client.chat_completion(MESSAGES)


@pytest.mark.parametrize("data", ["{broken", "[]"])
def test_damaged_stream_frame_is_not_silently_skipped(data):
    decoder = ChatChunkDecoder()
    with pytest.raises(Exception, match="stream frame"):
        decoder.feed("data: " + data)
        decoder.feed("")


def test_multiline_sse_frame_preserves_protocol_fields():
    decoder = ChatChunkDecoder()
    assert decoder.feed('data: {"choices":') is None
    chunk = decoder.feed('data: [{"delta":{"content":"ok"},"finish_reason":"stop"}]}')
    assert chunk == {"choices": [{"delta": {"content": "ok"}, "finish_reason": "stop"}]}


def test_protocol_failures_do_not_use_unbounded_availability_retries(server_factory):
    server = server_factory(
        lambda *_: (200, [frame({"tool_calls": [call(identifier="")]}, "tool_calls")])
    )
    server.client.retry_until_available = True
    token = CancellationToken(timeout_seconds=2)
    with bind_cancellation_token(token), pytest.raises(Exception, match="All models failed"):
        server.client.chat_completion(MESSAGES)
    assert len(server.requests) == 1


def test_content_after_finish_cannot_change_accepted_result(server_factory):
    server = server_factory(
        lambda *_: (
            200,
            [
                frame({"content": "first"}, "stop"),
                frame({"content": "second"}),
            ],
        )
    )
    with pytest.raises(Exception, match="completed turn"):
        server.client.chat_completion(MESSAGES)


def test_quoted_xml_is_text_not_a_tool_call(server_factory):
    text = 'Example only; do not execute:\n```xml\n<invoke name="read_code"><parameter name="file_path">a.c</parameter></invoke>\n```'
    server = server_factory(lambda *_: (200, [frame({"content": text}, "stop")]))
    executed = []
    result = server.client.run_conversation_with_tools(
        MESSAGES,
        [schema("read_code")],
        lambda *args: executed.append(args),
        max_iterations=3,
    )
    assert result["content"] == text
    assert executed == []
    assert len(server.requests) == 1


def test_default_reasoning_metadata_survives_tool_round_trip(server_factory):
    server = server_factory(
        lambda n, _: (
            200,
            [
                (
                    frame(
                        {
                            "reasoning_content": "opaque-provider-state",
                            "tool_calls": [call("read_code")],
                        },
                        "tool_calls",
                    )
                    if n == 1
                    else frame({"content": "done"}, "stop")
                )
            ],
        )
    )
    server.client.run_conversation_with_tools(
        MESSAGES,
        [schema("read_code")],
        lambda *_: {"success": True},
        max_iterations=3,
    )
    previous = next(m for m in server.requests[1]["messages"] if m["role"] == "assistant")
    assert previous["reasoning_content"] == "opaque-provider-state"


@pytest.mark.parametrize("stall", ["stream", "headers"])
@pytest.mark.parametrize("cancel_kind", ["cancel", "deadline"])
def test_cancel_stalled_http_releases_request_and_capacity(server_factory, stall, cancel_kind):
    server = server_factory(lambda *_: (200, [frame({"content": "done"}, "stop")]), stall=stall)
    token = CancellationToken()
    outcomes = []

    def worker():
        with bind_cancellation_token(token):
            try:
                server.client.chat_completion(MESSAGES)
            except BaseException as exc:
                outcomes.append(exc)

    thread = threading.Thread(target=worker)
    thread.start()
    try:
        assert server.ready.wait(3)
        if cancel_kind == "cancel":
            token.cancel("regression cancellation")
        else:
            import time

            token.tighten_deadline(time.monotonic() + 0.05)
        thread.join(1.5)
        assert not thread.is_alive(), "Cancelled HTTP must not wait for the peer or read timeout"
        assert len(outcomes) == 1 and isinstance(outcomes[0], CancellationError)
        assert server.client._owned_in_flight == 0
        # The same client can immediately obtain its capacity for another request.
    finally:
        server.release.set()
        thread.join(5)


def test_done_marker_closes_owned_stream_without_waiting_for_peer(server_factory):
    server = server_factory(
        lambda *_: (200, [frame({"content": "done"}, "stop")]), stall="after_done"
    )
    outcomes = []

    def worker():
        with bind_cancellation_token(CancellationToken()):
            try:
                outcomes.append(server.client.chat_completion(MESSAGES))
            except BaseException as exc:
                outcomes.append(exc)

    thread = threading.Thread(target=worker)
    thread.start()
    try:
        assert server.ready.wait(3)
        thread.join(1.5)
        assert not thread.is_alive()
        assert len(outcomes) == 1 and isinstance(outcomes[0], dict)
        assert outcomes[0]["choices"][0]["finish_reason"] == "stop"
        assert server.client._owned_in_flight == 0
    finally:
        server.release.set()
        thread.join(5)


@pytest.mark.parametrize("direct", [True, False])
def test_failed_sessions_have_exactly_one_end_and_index(server_factory, tmp_path, direct):
    recorder = enable_conversation_recording(tmp_path)
    server = server_factory(lambda *_: (400, [{"error": "synthetic request rejected"}]))
    try:
        with pytest.raises(Exception, match="All models failed"):
            if direct:
                server.client.chat_completion(MESSAGES)
            else:
                server.client.run_conversation_with_tools(
                    MESSAGES, [], lambda *_: {}, max_iterations=3
                )
        events = [
            json.loads(line)
            for p in recorder.run_dir.glob("*.jsonl")
            if p.name != "index.jsonl"
            for line in p.read_text().splitlines()
        ]
        ends = [event for event in events if event["event"] == "session_end"]
        assert len(ends) == 1 and ends[0]["finish_reason"] == "error"
        assert ends[0]["truncated"] is True
        assert len((recorder.run_dir / "index.jsonl").read_text().splitlines()) == 1
    finally:
        disable_conversation_recording()


def test_context_rejection_ends_session_without_sending_contracts_truncated(
    server_factory, tmp_path
):
    recorder = enable_conversation_recording(tmp_path)
    server = server_factory(
        lambda *_: (400, [{"error": {"message": "maximum context length exceeded"}}])
    )
    history = [{"role": "system", "content": "Required contract. " * 20000}]
    original = deepcopy(history)
    try:
        with pytest.raises(ContextWindowExceeded):
            server.client.chat_completion(history)
        assert len(server.requests) == 1 and server.requests[0]["messages"] == history
        assert history == original
        events = [
            json.loads(line)
            for path in recorder.run_dir.glob("*.jsonl")
            if path.name != "index.jsonl"
            for line in path.read_text().splitlines()
        ]
        ends = [event for event in events if event["event"] == "session_end"]
        assert len(ends) == 1 and ends[0]["finish_reason"] == "context_window_exceeded"
        assert len((recorder.run_dir / "index.jsonl").read_text().splitlines()) == 1
    finally:
        disable_conversation_recording()


def test_cancellation_stops_remaining_tool_batch_and_ends_session(server_factory, tmp_path):
    second = call("second", "second")
    second["index"] = 1
    server = server_factory(
        lambda *_: (200, [frame({"tool_calls": [call("first"), second]}, "tool_calls")])
    )
    token = CancellationToken()
    executed = []
    recorder = enable_conversation_recording(tmp_path)

    def execute(name, _args):
        executed.append(name)
        token.cancel("tool interrupted")
        raise CancellationError("tool interrupted")

    try:
        with bind_cancellation_token(token), pytest.raises(CancellationError):
            server.client.run_conversation_with_tools(
                MESSAGES,
                [schema("first"), schema("second")],
                execute,
                max_iterations=3,
            )
        assert executed == ["first"]
        events = [
            json.loads(line)
            for p in recorder.run_dir.glob("*.jsonl")
            if p.name != "index.jsonl"
            for line in p.read_text().splitlines()
        ]
        ends = [event for event in events if event["event"] == "session_end"]
        assert len(ends) == 1 and ends[0]["finish_reason"] == "cancelled"
        assert not any(e.get("event") == "tool_result" for e in events)
    finally:
        disable_conversation_recording()


@pytest.mark.parametrize("identity", [None, "", "duplicate"])
def test_invalid_tool_identity_is_rejected_before_execution(server_factory, identity):
    calls = [call("read_code")]
    if identity is None:
        calls[0].pop("id")
    elif identity == "duplicate":
        calls.append({**call("read_code"), "index": 1})
    else:
        calls[0]["id"] = identity
    server = server_factory(lambda *_: (200, [frame({"tool_calls": calls}, "tool_calls")]))
    executed = []
    with pytest.raises(Exception, match="tool call identity"):
        server.client.run_conversation_with_tools(
            MESSAGES,
            [schema("read_code")],
            lambda *args: executed.append(args),
            max_iterations=3,
        )
    assert executed == []
    assert len(server.requests) == 1


def hex_history():
    rng = random.Random(42)
    history = [{"role": "system", "content": "Preserve identities, evidence and gaps."}]
    for n in range(40):
        invocation = call(
            "read_code", f"call_{n}", {"file_path": f"generated_{n}.c", "start_line": 1}
        )
        invocation.pop("index")
        history.append({"role": "assistant", "content": "", "tool_calls": [invocation]})
        payload = {
            "success": True,
            "data": {
                "code": 'static const char data[] = "'
                + "".join(rng.choices("0123456789abcdef", k=12500))
                + '";',
                "build_context_id": f"build_{n % 2}",
                "symbol_id": f"symbol_{n}",
                "evidence_refs": [f"ref_{n}"],
            },
            "coverage": {"level": "partial", "gaps": ["native_receipt_missing"]},
        }
        history.append(
            {"role": "tool", "tool_call_id": f"call_{n}", "content": json.dumps(payload)}
        )
    return history


def assert_metadata_preserved(before, after):
    assert len(before) == len(after)
    for old, new in zip(before, after):
        if old["role"] != "tool":
            assert old == new
            continue
        assert old["tool_call_id"] == new["tool_call_id"]
        expected = json.loads(old["content"])
        actual = json.loads(new["content"])
        if actual.get("compacted_tool_result"):
            actual = actual["summary"]
            import hashlib

            code = expected["data"]["code"]
            assert actual["data"]["code"] == {
                "context_omitted": True,
                "original_chars": len(code),
                "sha256": hashlib.sha256(code.encode()).hexdigest(),
            }
            expected["data"]["code"] = actual["data"]["code"]
        assert actual == expected


def test_provider_rejection_compacts_hex_without_treating_bytes_as_tokens(server_factory):
    def respond(index, _payload):
        if index == 1:
            return 400, [{"error": {"message": "maximum context length exceeded"}}]
        return 200, [frame({"content": "done"}, "stop")]

    server = server_factory(respond)
    history = hex_history()
    original = deepcopy(history)
    client = server.client
    # Heuristics can undercount hex. Let the provider reject, then re-project
    # once; never silently discard identities or claim this is a token count.
    client.chat_completion(history)
    assert server.requests[0]["messages"] == history
    wire = server.requests[1]
    assert client.context_window == 192000 and wire["max_tokens"] == 8192
    assert wire["messages"] != history
    assert (
        client._estimate_request_prompt_tokens(wire["messages"], tools=None, response_format=None)
        <= 174208
    )
    assert_metadata_preserved(history, wire["messages"])
    assert history == original
    assert wire["messages"][-1] == history[-1]


def test_tool_loop_revalidates_source_before_reusing_identical_arguments(
    server_factory, tmp_path, monkeypatch
):
    source = tmp_path / "sample.c"
    source.write_text("old\n")
    runtime = ToolsRuntime(
        SimpleNamespace(project_root=tmp_path, exclude_paths=[], _index_epoch=0),
        SimpleNamespace(snapshot_dir=tmp_path / ".snapshots"),
    )
    arguments = {"file_path": "sample.c", "start_line": 1}
    requests = []

    def complete(messages, **kwargs):
        requests.append(messages)
        n = len(requests)
        if n == 3:
            source.write_text("changed_source\n")
        message = {"role": "assistant", "content": "done"}
        if n <= 3:
            message["tool_calls"] = [call("read_code", f"call_{n}", arguments)]
        return {
            "choices": [{"message": message, "finish_reason": "tool_calls" if n <= 3 else "stop"}]
        }

    client = server_factory(lambda *_: (200, [])).client
    monkeypatch.setattr(client, "chat_completion", complete)
    result = client.run_conversation_with_tools(
        MESSAGES, runtime.get_tools_schema(), runtime.execute_tool, max_iterations=6
    )
    outputs = [json.loads(m["content"]) for m in result["conversation"] if m["role"] == "tool"]
    assert outputs[0]["data"]["source"]["code"] == "1 | old\n"
    assert outputs[2]["data"]["source"]["code"] == "1 | changed_source\n"
    assert not outputs[2].get("cached_tool_result")


@pytest.mark.parametrize("always_reject", [False, True])
def test_provider_context_repair_is_bounded_and_preserves_metadata(server_factory, always_reject):
    def respond(n, _request):
        if n == 1 or always_reject:
            return 400, [{"error": {"code": "context_length_exceeded"}}]
        return 200, [frame({"content": "done"}, "stop")]

    server = server_factory(respond)
    history = hex_history()[:9]
    if always_reject:
        with pytest.raises(ContextWindowExceeded):
            server.client.chat_completion(history)
    else:
        server.client.chat_completion(history)
    assert len(server.requests) == 2
    assert_metadata_preserved(history, server.requests[1]["messages"])
    assert server.requests[1]["max_tokens"] == 8192
