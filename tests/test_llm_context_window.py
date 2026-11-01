"""Model capacity is a request boundary, never authority to discard evidence."""

from copy import deepcopy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import shutil
from threading import Thread

import pytest

from zscope.config.config import ConfigLoader, LLMConfig
from zscope.framework.context_window import ContextWindowExceeded, compact_tool_result
from zscope.framework.llm_client import LLMClient


@pytest.fixture
def client():
    instance = LLMClient(api_key="test", base_url="http://example.invalid", models=["unit-model"])
    yield instance
    instance.close()


def _history(rounds=1, chars=20000):
    messages = [
        {
            "role": "system",
            "content": "Full Agent and Skill contracts: never infer safety from gaps.",
        },
        {"role": "user", "content": "Investigate the exact build and cite its evidence."},
    ]
    for index in range(rounds):
        payload = {
            "success": True,
            "status": "partial",
            "data": {
                "build_context_id": f"build-{index % 2}",
                "usr": f"c:@F@function_{index}",
                "symbol_id": f"symbol-{index}",
                "evidence_ref": f"tool:{index}",
                "code": "x" * chars,
            },
            "coverage": {
                "level": "partial",
                "providers": ["clang"],
                "missing": ["cross_tu", f"gap-{index}"],
                "details": {"current": False, "text": "missing receipt " * 20},
            },
            "page": {"next_offset": index + 1, "has_more": True},
            "warnings": ["This does not prove safety."],
            "next_actions": ["Read the next evidence page."],
        }
        messages.extend(
            [
                {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "id": f"call-{index}",
                            "type": "function",
                            "function": {
                                "name": "read_code",
                                "arguments": json.dumps({"symbol_id": f"symbol-{index}"}),
                            },
                        }
                    ],
                },
                {"role": "tool", "tool_call_id": f"call-{index}", "content": json.dumps(payload)},
            ]
        )
    return messages


def _fits(
    client, messages, *, model="unit-model", tools=None, response_format=None, max_tokens=None
):
    window = client.model_context_windows.get(model, client.context_window)
    prompt = client._estimate_request_prompt_tokens(
        messages, tools=tools, response_format=response_format
    )
    return prompt + (max_tokens or client.max_tokens) + max(256, (window + 19) // 20) <= window


def _assert_metadata(original, projected):
    assert len(projected) == len(original)
    for before, after in zip(original, projected):
        if before["role"] != "tool":
            assert after == before
            continue
        assert after["tool_call_id"] == before["tool_call_id"]
        expected = json.loads(before["content"])
        actual = json.loads(after["content"])
        if actual.get("compacted_tool_result"):
            assert actual["original_chars"] == len(before["content"])
            assert actual["tool_call_id"] == before["tool_call_id"]
            actual = actual["summary"]
            actual_source = actual["data"].get("source", actual["data"])
            expected_source = expected["data"].get("source", expected["data"])
            code = expected_source["code"]
            assert actual_source["code"] == {
                "context_omitted": True,
                "original_chars": len(code),
                "sha256": hashlib.sha256(code.encode("utf-8")).hexdigest(),
            }
            expected_source["code"] = actual_source["code"]
        assert actual == expected


def test_default_window_compacts_before_default_fifty_turn_limit(client):
    assert client.context_window == LLMConfig().context_window == 192000
    assert client.max_tokens == LLMConfig().max_tokens == 8192
    messages = _history(45)
    original = deepcopy(messages)
    projected = client._prepare_messages_for_model(messages)
    assert any('"compacted_tool_result":true' in m.get("content", "") for m in projected)
    assert _fits(client, projected)
    _assert_metadata(messages, projected)
    assert messages == original


def test_under_window_preserves_tool_results_even_after_fifty_rounds(client):
    messages = _history(60, chars=300)
    # Keep this history small; the default regression above retains large gaps.
    for message in messages:
        if message["role"] == "tool":
            payload = json.loads(message["content"])
            payload["coverage"]["details"]["text"] = "Missing receipt."
            message["content"] = json.dumps(payload)
    assert _fits(client, messages)
    assert client._prepare_messages_for_model(messages) == messages


def test_single_oversized_latest_result_is_compacted(client):
    messages = _history(chars=800000)
    projected = client._prepare_messages_for_model(messages)
    assert "compacted_tool_result" in projected[-1]["content"]
    assert _fits(client, projected)
    _assert_metadata(messages, projected)


def test_default_tool_loop_compacts_and_preserves_complete_transcript(client, monkeypatch):
    history = _history(45)
    tool_inputs = [message for message in history if message["role"] == "assistant"]
    tool_results = [
        json.loads(message["content"]) for message in history if message["role"] == "tool"
    ]
    sent = []

    def transport(_url, payload):
        sent.append(deepcopy(payload))
        assert _fits(client, payload["messages"], tools=payload.get("tools"))
        index = len(sent) - 1
        if index < len(tool_inputs):
            return tool_inputs[index], "tool_calls", {"prompt_tokens": 10, "completion_tokens": 5}
        return (
            {"role": "assistant", "content": "done"},
            "stop",
            {"prompt_tokens": 10, "completion_tokens": 5},
        )

    def execute(_name, args):
        return tool_results[int(args["symbol_id"].split("-")[1])]

    client._transport = "curl"
    monkeypatch.setattr(client, "_curl_chat_completion", transport)
    # All loop/window settings are the production defaults, including 50 turns.
    result = client.run_conversation_with_tools(history[:2], [], execute)
    assert result["finish_reason"] == "stop"
    assert result["api_call_count"] == 46
    assert result["tool_call_count"] == 45
    final_tools = [m for m in sent[-1]["messages"] if m["role"] == "tool"]
    assert any("compacted_tool_result" in m["content"] for m in final_tools)
    original_tools = [m for m in result["conversation"] if m["role"] == "tool"]
    assert [json.loads(m["content"]) for m in original_tools] == tool_results
    _assert_metadata(original_tools, final_tools)


def test_window_failure_returns_incomplete_loop_with_all_evidence(client, monkeypatch):
    from zscope.framework.llm_client import ProviderContextError

    history = _history(chars=20000)
    payload = json.loads(history[-1]["content"])
    payload["coverage"]["missing"] = [f"gap-{index}" for index in range(100000)]
    calls = []

    def transport(_url, _payload):
        calls.append(1)
        if len(calls) > 1:
            raise ProviderContextError("provider context limit exceeded")
        return history[-2], "tool_calls", {"prompt_tokens": 10, "completion_tokens": 5}

    client._transport = "curl"
    monkeypatch.setattr(client, "_curl_chat_completion", transport)
    result = client.run_conversation_with_tools(history[:2], [], lambda *_: payload)
    assert len(calls) == 2  # No guessed local refusal before the real rejection.
    assert result["finish_reason"] == "context_window_exceeded"
    assert result["truncated"] is True
    assert result["terminal_tool_valid"] is False
    assert result["cumulative_total_tokens"] == 15
    assert json.loads(result["conversation"][-1]["content"]) == payload


def test_json_agent_does_not_repair_or_accept_partial_text_after_window_failure(
    client, monkeypatch
):
    from zscope.agents.base import JsonToolAgent

    class Agent(JsonToolAgent):
        def run(self, input_data):
            raise NotImplementedError

    agent = Agent(name="test", description="test", llm_client=client)
    monkeypatch.setattr(
        agent,
        "_run_tool_conversation",
        lambda *_args, **_kwargs: {
            "content": '{"verdict":"safe"}',
            "finish_reason": "context_window_exceeded",
            "context_window_error": "context_window_exceeded",
            "truncated": True,
        },
    )
    monkeypatch.setattr(
        client, "chat_completion", lambda *_args, **_kwargs: pytest.fail("unexpected repair")
    )
    result = agent._run_json_conversation(
        [],
        extractor=lambda *_: {"verdict": "safe"},
        trace_label="test",
        parse_label="test",
        retry_prompt="retry",
    )
    assert result.success is False
    assert result.data == {}
    assert result.metadata["reason"] == "context_window_exceeded"


def test_nested_identity_and_gaps_survive_without_count_or_depth_caps():
    records = []
    for index in range(25):
        records.append(
            {
                **{f"field_{n}": f"unknown-{n}" for n in range(25)},
                "nested": {
                    "a": {
                        "b": {
                            "c": {
                                "build_context_id": f"build-{index}",
                                "usr": f"usr-{index}",
                                "evidence_refs": [f"ref-{index}-{n}" for n in range(12)],
                                "dependency_hash": "h" * 1000,
                                "coverage": {
                                    "level": "unavailable",
                                    "details": {"text": "gap " * 1000},
                                },
                                "status": "unavailable",
                                "source": "src/example.c",
                                "code": "x" * 10000,
                            }
                        }
                    }
                },
            }
        )
    payload = {"data": {"records": records}, "warnings": ["warning " * 1000]}
    original = deepcopy(payload)
    projected = json.loads(compact_tool_result(json.dumps(payload), "call-1"))["summary"]
    for record in projected["data"]["records"]:
        assert record["nested"]["a"]["b"]["c"]["code"]["context_omitted"]
        record["nested"]["a"]["b"]["c"]["code"] = "x" * 10000
    assert projected == original
    assert payload == original


@pytest.mark.parametrize("kind", ["system", "user", "coverage", "unstructured", "reasoning"])
def test_required_context_cannot_be_silently_dropped(client, kind):
    messages = _history(chars=200000)
    if kind in {"system", "user"}:
        messages[0 if kind == "system" else 1]["content"] = "required " * 100000
    elif kind == "coverage":
        payload = json.loads(messages[-1]["content"])
        payload["coverage"]["missing"] = [f"missing-{i}" for i in range(100000)]
        messages[-1]["content"] = json.dumps(payload)
    elif kind == "unstructured":
        messages[-1]["content"] = "unknown format containing build/evidence/gaps " * 20000
    else:
        messages[-2]["reasoning_content"] = "provider-required " * 50000
    original = deepcopy(messages)
    projected = client._prepare_messages_for_model(messages, preserve_reasoning_metadata=True)
    _assert_metadata(messages, projected) if kind == "coverage" else None
    # Only a real provider rejection gives an enforced re-projection limit.
    with pytest.raises(ContextWindowExceeded, match="context_window_exceeded"):
        client._prepare_messages_for_model(
            messages, preserve_reasoning_metadata=True, input_limit=1000
        )
    assert messages == original


def _install_transport(client, monkeypatch, transport, responses=None):
    sent = []
    client._transport = transport
    client.max_retries = 0
    responses = iter(responses or [200])

    class Response:
        text = "request rejected"

        def __init__(self, status):
            self.status_code = status

        def close(self):
            pass

    def response():
        return {"role": "assistant", "content": "done"}, "stop", None

    def curl(_url, payload):
        sent.append(deepcopy(payload))
        return response()

    def post(_url, **kwargs):
        sent.append(deepcopy(kwargs["json"]))
        return Response(next(responses))

    monkeypatch.setattr(client, "_curl_chat_completion", curl)
    monkeypatch.setattr(client.session, "post", post)
    monkeypatch.setattr(client, "_assemble_chat_response_with_usage", lambda _: response())
    return sent


@pytest.mark.parametrize("transport", ["requests", "curl"])
def test_wire_schema_output_override_and_usage_share_projected_request(
    client, monkeypatch, transport
):
    client.context_window = 10000
    client.supports_structured_output = True
    messages = _history(chars=20000)
    original = deepcopy(messages)
    tools = [
        {
            "type": "function",
            "function": {
                "name": "read_code",
                "description": "工具说明" * 1000,
                "parameters": {"type": "object", "properties": {"symbol_id": {"type": "string"}}},
            },
        }
    ]
    response_format = {
        "type": "json_schema",
        "json_schema": {
            "name": "result",
            "schema": {
                "type": "object",
                "description": "d" * 2000,
                "properties": {},
            },
        },
    }
    sent = _install_transport(client, monkeypatch, transport)
    response = client.chat_completion(
        messages, tools=tools, response_format=response_format, max_tokens=2000
    )
    assert len(sent) == 1
    wire = sent[0]
    assert wire["tools"][0]["function"]["strict"] is True
    assert wire["max_tokens"] == 2000
    assert _fits(
        client,
        wire["messages"],
        tools=wire["tools"],
        response_format=response_format,
        max_tokens=2000,
    )
    assert "compacted_tool_result" in wire["messages"][-1]["content"]
    assert response["usage"]["prompt_tokens"] == client._estimate_request_prompt_tokens(
        wire["messages"], tools=wire["tools"], response_format=response_format
    )
    _assert_metadata(messages, wire["messages"])
    assert messages == original


def test_fallback_reprojects_original_history_for_smaller_model(client, monkeypatch):
    client.models = ["large", "small"]
    client.model_context_windows = {"large": 32768, "small": 12000}
    messages = _history(chars=20000)
    sent = _install_transport(client, monkeypatch, "requests", [400, 200])
    client.chat_completion(messages)
    assert [payload["model"] for payload in sent] == ["large", "small"]
    assert sent[0]["messages"] == messages
    assert "compacted_tool_result" in sent[1]["messages"][-1]["content"]
    assert _fits(client, sent[1]["messages"], model="small")
    _assert_metadata(messages, sent[1]["messages"])


def test_larger_fallback_can_fit_required_context_without_requesting_small_model(
    client, monkeypatch
):
    client.models = ["small", "large"]
    client.model_context_windows = {"small": 4096, "large": 65536}
    sent = _install_transport(client, monkeypatch, "requests")
    client.chat_completion([{"role": "system", "content": "contract " * 3000}])
    assert [payload["model"] for payload in sent] == ["large"]


@pytest.mark.parametrize("transport", ["requests", "curl"])
def test_uncertain_estimate_never_refuses_contract_or_schema_before_http(
    client, monkeypatch, transport
):
    sent = _install_transport(client, monkeypatch, transport, [200, 200])
    client.chat_completion([{"role": "system", "content": "contract " * 100000}])
    client.chat_completion(
        [{"role": "user", "content": "start"}], response_format={"schema": "x" * 800000}
    )
    assert len(sent) == 2
    assert sent[0]["messages"][0]["content"] == "contract " * 100000
    assert client.usage_snapshot()["successful_calls"] == 2


@pytest.mark.parametrize("version", [2, 3])
@pytest.mark.parametrize(
    "windows", [{}, {"context_window": 65536, "model_context_windows": {"small": 16384}}]
)
def test_public_config_capacities_and_shared_client_factory(tmp_path, version, windows):
    from zscope.orchestration.parallel_analyzer import ParallelAnalyzer

    document = {
        "config_version": version,
        "llms": {
            "default": {
                "base_urls": ["http://example.invalid"],
                "models": ["large", "small"],
                "api_key": "test",
                **windows,
            }
        },
        "project": {"language": "java"},
        "scan": {"depth": "fast"} if version == 2 else {"preset": "fast"},
    }
    if version == 2:
        document["indexing"] = {"backend": "java_source"}
        document["concurrency"] = {
            "entry_workers": 1,
            "validator_workers": 1,
            "investigator_workers": 1,
            "evidence_completion_workers": 1,
            "index_workers": 1,
            "llm_max_inflight": 1,
        }
    else:
        document["project"].update(platform="linux_user", targets=[{"id": "default"}])
    path = tmp_path / "zscope.yaml"
    path.write_text(json.dumps(document))
    config = ConfigLoader.load(str(path))
    # Use the same factory as parallel production scans, including default settings.
    clients = ParallelAnalyzer._build_shared_llm_clients(config)
    try:
        instance = clients["default"]
        assert instance.context_window == windows.get("context_window", 192000)
        assert instance.max_tokens == 8192
        assert instance.model_context_windows == windows.get("model_context_windows", {})
    finally:
        for instance in clients.values():
            instance.close()


@pytest.mark.parametrize(
    "field,value",
    [
        ("context_window", 0),
        ("context_window", True),
        ("context_window", "32768"),
        ("model_context_windows", None),
        ("model_context_windows", []),
        ("model_context_windows", {"": 10000}),
        ("model_context_windows", {"model": False}),
        ("model_context_windows", {"model": -1}),
    ],
)
def test_capacity_config_rejects_invalid_values(field, value):
    from zscope.config.v2 import _parse_llms

    with pytest.raises(ValueError, match=field):
        _parse_llms(
            {
                "default": {
                    "base_urls": ["http://example.invalid"],
                    "models": ["model"],
                    "api_key": "test",
                    field: value,
                }
            }
        )


def test_public_schema_advertises_the_runtime_defaults():
    from zscope.config.v3 import public_json_schema

    fields = public_json_schema()["properties"]["llms"]["additionalProperties"]["properties"]
    assert fields["context_window"]["default"] == 192000
    assert fields["max_tokens"]["default"] == 8192


@pytest.fixture
def http_receiver():
    """Receive real POST bytes; neither transport nor request serialization is mocked."""
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            raw = self.rfile.read(int(self.headers["Content-Length"]))
            payload = json.loads(raw)
            received.append((self.path, raw, payload))
            response = {
                "choices": [
                    {
                        "message": {"role": "assistant", "content": '{"received":true}'},
                        "finish_reason": "stop",
                    }
                ]
            }
            body = json.dumps(response).encode("utf-8")
            if payload["stream"]:
                body = b"data: " + body + b"\n\ndata: [DONE]\n\n"
            self.send_response(200)
            self.send_header(
                "Content-Type", "text/event-stream" if payload["stream"] else "application/json"
            )
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/v1", received
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _read_code_wire_history():
    from zscope.framework.base import validate_function_arguments
    from zscope.tools.contracts import tool_result
    from zscope.tools.read_code import READ_CONTRACT

    root = Path(__file__).resolve().parents[1]
    messages = _history(45)
    # Use the full product contracts, never a shortened test-only system prompt.
    messages[0]["content"] = "\n\n".join(
        (root / path).read_text(encoding="utf-8")
        for path in (
            "zscope/agents/validator_agent/AGENT.md",
            "zscope/skills/resource_lifecycle/SKILL.md",
        )
    )
    for index in range(45):
        call, result = messages[2 + index * 2 : 4 + index * 2]
        arguments = {"file_path": f"src/unit_{index}.c", "start_line": 1, "end_line": 300}
        call["tool_calls"][0]["function"]["arguments"] = json.dumps(arguments)
        call["content"] = "Retain this analysis and verify the missing build receipt. " * 6
        code = "\n".join(
            f"{line}:     if (ctx->slot_{line} != NULL) consume(ctx->slot_{line}); /* 核对所有权 */"
            for line in range(1, 301)
        )
        identity = json.loads(result["content"])["data"]
        identity.pop("code")
        payload = tool_result(
            status="partial",
            data={
                "symbol": None,
                "definition": {"complete": False, "origin": "source_range"},
                "source": {
                    "file": arguments["file_path"],
                    "start_line": 1,
                    "end_line": 300,
                    "code": code,
                    "revision": hashlib.sha256(code.encode("utf-8")).hexdigest(),
                    "definition_end_line": None,
                    "total_file_lines": 500,
                    "truncated": True,
                    "next_start_line": 301,
                },
            },
            providers=["clang"],
            missing=["cross_tu", f"gap-{index}"],
            coverage_details={
                "identity": identity,
                "current": False,
                "text": "Missing build receipt; do not infer safety. " * 10,
                "evidence_ref_catalog": [{"ref": f"tool:{index}", "body": code[:400]}],
            },
            warnings=["This partial source page does not prove safety."],
            next_actions=["Read from source.next_start_line and verify the build receipt."],
        )
        assert validate_function_arguments(READ_CONTRACT.input_schema, arguments) is None
        assert validate_function_arguments(READ_CONTRACT.output_schema, payload) is None
        result["content"] = json.dumps(payload, ensure_ascii=False)
    return messages


@pytest.mark.parametrize("transport", ["requests", "curl"])
def test_default_window_real_http_preserves_all_but_expected_old_source(
    http_receiver, transport, monkeypatch
):
    from zscope.tools.read_code import READ_CONTRACT

    endpoint, received = http_receiver
    # Test traffic must stay in the Linux loopback namespace, even in proxied WSL setups.
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setenv("no_proxy", "127.0.0.1")
    client = LLMClient(api_key="local-test", base_url=endpoint, models=["unit-model"])
    client._transport = transport
    if transport == "curl":
        client._curl_bin = shutil.which("curl")
        assert client._curl_bin, "The real curl transport regression requires Linux curl"
    messages = _read_code_wire_history()
    original = deepcopy(messages)
    tools = [READ_CONTRACT.openai_schema()]
    response_format = {"type": "json_object"}
    before = client._estimate_request_prompt_tokens(
        messages, tools=tools, response_format=response_format
    )
    assert not _fits(client, messages, tools=tools, response_format=response_format)
    try:
        for history in (messages[:4], messages):
            response = client.chat_completion(history, tools=tools, response_format=response_format)
            assert response["choices"][0]["message"]["content"] == '{"received":true}'
            assert response["choices"][0]["finish_reason"] == "stop"
        assert len(received) == 2
        assert received[0][2]["messages"] == messages[:4]
        path, raw, wire = received[1]
        assert path == "/v1/chat/completions"
        assert client.context_window == 192000
        assert wire["max_tokens"] == 8192
        assert wire["tools"] == tools
        assert wire["response_format"] == response_format
        assert wire["stream"] is (transport == "requests")
        assert _fits(client, wire["messages"], tools=tools, response_format=response_format)
        _assert_metadata(messages, wire["messages"])
        assert messages == original
        compacted = [
            i
            for i, row in enumerate(wire["messages"])
            if row["role"] == "tool" and json.loads(row["content"]).get("compacted_tool_result")
        ]
        assert compacted and compacted == list(range(3, compacted[-1] + 1, 2))
        assert wire["messages"][-1] == messages[-1]
        # Restoring the last omitted result must exceed the threshold: compression
        # stopped as soon as the request fit, without consuming a newer result.
        one_less = deepcopy(wire["messages"])
        one_less[compacted[-1]] = messages[compacted[-1]]
        assert not _fits(client, one_less, tools=tools, response_format=response_format)
        after = client._estimate_request_prompt_tokens(
            wire["messages"], tools=tools, response_format=response_format
        )
        print(
            json.dumps(
                {
                    "transport": transport,
                    "window": client.context_window,
                    "max_tokens": wire["max_tokens"],
                    "prompt_before": before,
                    "prompt_after": after,
                    "input_limit": 174208,
                    "messages_preserved": len(messages),
                    "compacted_source_fields": len(compacted),
                    "received_bytes": len(raw),
                    "other_fields_unchanged": True,
                }
            )
        )
    finally:
        client.close()
