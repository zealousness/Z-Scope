import json

import pytest

from zscope.framework.conversation_recorder import (
    disable_conversation_recording,
    enable_conversation_recording,
)
from zscope.framework.llm_client import LLMClient


class _CompletedResponse:
    status_code = 200
    text = "ok"

    def close(self):
        pass


@pytest.mark.parametrize("transport", ["requests", "curl"])
def test_direct_chat_records_length_finish_as_truncated(monkeypatch, tmp_path, transport) -> None:
    recorder = enable_conversation_recording(tmp_path)
    client = LLMClient(
        api_key="test",
        base_url="http://example.invalid/v1",
        models=["unit-model"],
        max_retries=0,
    )
    message = {"role": "assistant", "content": "partial"}

    if transport == "curl":
        monkeypatch.setattr(
            client,
            "_curl_chat_completion",
            lambda _url, _payload: (message, "length", None),
        )
        monkeypatch.setenv("Z_SCOPE_LLM_TRANSPORT", "curl")
        client._transport = "curl"
    else:
        monkeypatch.setattr(
            client,
            "_assemble_chat_response_with_usage",
            lambda _response: (message, "length", None),
        )
        monkeypatch.setattr(
            client,
            "_session_for_thread",
            lambda: type("Session", (), {"post": lambda self, *args, **kwargs: _CompletedResponse()})(),
        )

    try:
        result = client.chat_completion([{"role": "user", "content": "hello"}])
        assert result["choices"][0]["finish_reason"] == "length"
        session_files = list(recorder.run_dir.glob("*.md"))
        assert len(session_files) == 1
        assert "- Truncated: `true`" in session_files[0].read_text(encoding="utf-8")
    finally:
        disable_conversation_recording()


def test_run_conversation_with_tools_accumulates_api_tokens(monkeypatch) -> None:
    client = LLMClient(
        api_key="test",
        base_url="http://example.invalid",
        models=["unit-model"],
    )
    calls = []

    def fake_chat_completion(messages, **kwargs):
        calls.append(list(messages))
        if len(calls) == 1:
            return {
                "choices": [
                    {
                        "finish_reason": "tool_calls",
                        "message": {
                            "role": "assistant",
                            "content": "",
                            "tool_calls": [
                                {
                                    "id": "call_1",
                                    "type": "function",
                                    "function": {
                                        "name": "lookup",
                                        "arguments": json.dumps({"name": "demo"}),
                                    },
                                }
                            ],
                        },
                    }
                ],
                "usage": {
                    "prompt_tokens": 110,
                    "completion_tokens": 30,
                    "total_tokens": 140,
                },
            }
        return {
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": "done"},
                }
            ],
            "usage": {
                "prompt_tokens": 190,
                "completion_tokens": 50,
                "total_tokens": 240,
            },
        }

    monkeypatch.setattr(client, "chat_completion", fake_chat_completion)

    result = client.run_conversation_with_tools(
        messages=[{"role": "user", "content": "start"}],
        tools_schema=[],
        tool_executor=lambda name, args: {"success": True, "name": name, "args": args},
        max_iterations=4,
    )

    assert result["iterations"] == 2
    assert result["tool_call_count"] == 1
    assert result["cumulative_prompt_tokens"] == 300
    assert result["cumulative_completion_tokens"] == 80
    assert result["cumulative_total_tokens"] == 380
    assert result["context_tokens"] < result["cumulative_total_tokens"]


def test_run_conversation_stops_on_valid_terminal_tool(monkeypatch) -> None:
    client = LLMClient(
        api_key="test",
        base_url="http://example.invalid",
        models=["unit-model"],
    )
    calls = []
    executed = []

    def fake_chat_completion(messages, **kwargs):
        calls.append((list(messages), kwargs))
        if len(calls) == 1:
            tool_name = "lookup"
            arguments = {"name": "demo"}
        else:
            tool_name = "emit_result"
            arguments = {"type": "result", "value": 7}
        return {
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {
                                "id": f"call_{len(calls)}",
                                "type": "function",
                                "function": {
                                    "name": tool_name,
                                    "arguments": json.dumps(arguments),
                                },
                            }
                        ],
                    },
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 4},
        }

    monkeypatch.setattr(client, "chat_completion", fake_chat_completion)
    result = client.run_conversation_with_tools(
        messages=[{"role": "user", "content": "start"}],
        tools_schema=[
            {"type": "function", "function": {"name": "lookup", "parameters": {}}},
            {"type": "function", "function": {"name": "emit_result", "parameters": {}}},
        ],
        tool_executor=lambda name, args: executed.append((name, args)) or {"success": True},
        terminal_tool_name="emit_result",
        terminal_tool_handler=lambda payload: {
            "valid": payload.get("type") == "result",
            "payload": payload,
        },
        terminal_tool_required=True,
        max_iterations=4,
    )

    assert executed == [("lookup", {"name": "demo"})]
    assert result["terminal_tool_payload"] == {"type": "result", "value": 7}
    assert result["terminal_tool_valid"] is True
    assert result["tool_call_count"] == 1
    assert result["terminal_tool_call_count"] == 1
    assert result["final_tool_call_count"] == 1
    assert result["api_call_count"] == 2
    assert result["cumulative_total_tokens"] == 28


def test_invalid_terminal_tool_repairs_in_same_conversation(monkeypatch) -> None:
    client = LLMClient(
        api_key="test",
        base_url="http://example.invalid",
        models=["unit-model"],
    )
    calls = []

    def fake_chat_completion(messages, **kwargs):
        calls.append((list(messages), kwargs))
        payload = {"value": 1} if len(calls) == 1 else {"type": "result", "value": 1}
        return {
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {
                                "id": f"call_{len(calls)}",
                                "type": "function",
                                "function": {
                                    "name": "emit_result",
                                    "arguments": json.dumps(payload),
                                },
                            }
                        ],
                    },
                }
            ],
            "usage": {"prompt_tokens": 5, "completion_tokens": 2},
        }

    monkeypatch.setattr(client, "chat_completion", fake_chat_completion)
    result = client.run_conversation_with_tools(
        messages=[{"role": "user", "content": "start"}],
        tools_schema=[
            {"type": "function", "function": {"name": "emit_result", "parameters": {}}},
        ],
        tool_executor=lambda name, args: (_ for _ in ()).throw(
            AssertionError(f"terminal tool executed as normal tool: {name} {args}")
        ),
        terminal_tool_name="emit_result",
        terminal_tool_handler=lambda payload: {
            "valid": payload.get("type") == "result",
            "payload": payload,
            "error": "missing type",
        },
        terminal_tool_required=True,
        max_iterations=3,
    )

    second_messages = calls[1][0]
    terminal_errors = [
        message
        for message in second_messages
        if message.get("role") == "tool" and message.get("terminal_tool_result")
    ]
    assert len(terminal_errors) == 1
    assert "missing type" in terminal_errors[0]["content"]
    assert result["terminal_tool_valid"] is True
    assert result["terminal_tool_call_count"] == 2
    assert result["tool_call_count"] == 0


def test_identical_invalid_terminal_calls_trigger_guard_on_third_call(monkeypatch) -> None:
    client = LLMClient(
        api_key="test",
        base_url="http://example.invalid",
        models=["unit-model"],
    )
    calls = []

    def fake_chat_completion(messages, **kwargs):
        calls.append(list(messages))
        return {
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {
                                "id": f"call_{len(calls)}",
                                "type": "function",
                                "function": {
                                    "name": "emit_result",
                                    "arguments": json.dumps({"value": 1}),
                                },
                            }
                        ],
                    },
                }
            ],
            "usage": {"prompt_tokens": 5, "completion_tokens": 2},
        }

    monkeypatch.setattr(client, "chat_completion", fake_chat_completion)
    result = client.run_conversation_with_tools(
        messages=[{"role": "user", "content": "start"}],
        tools_schema=[
            {"type": "function", "function": {"name": "emit_result", "parameters": {}}},
        ],
        tool_executor=lambda name, args: {"success": True},
        terminal_tool_name="emit_result",
        terminal_tool_handler=lambda payload: {
            "valid": False,
            "error": "invalid payload",
        },
        terminal_tool_required=True,
        max_iterations=10,
    )

    assert len(calls) == 3
    assert result["terminal_loop_guard_triggered"] is True
    assert result["terminal_loop_guard_reason"] == "identical_invalid_terminal_call_limit"
    assert result["terminal_invalid_call_count"] == 3
    assert result["terminal_tool_call_count"] == 3
    assert result["repeated_terminal_tool_call"]["repeat_count"] == 3
    assert result["truncated"] is False
    assert "loop_guard_triggered" not in result


def test_distinct_invalid_terminal_calls_trigger_total_guard_on_fifth_call(monkeypatch) -> None:
    client = LLMClient(
        api_key="test",
        base_url="http://example.invalid",
        models=["unit-model"],
    )
    calls = []

    def fake_chat_completion(messages, **kwargs):
        calls.append(list(messages))
        return {
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {
                                "id": f"call_{len(calls)}",
                                "type": "function",
                                "function": {
                                    "name": "emit_result",
                                    "arguments": json.dumps({"value": len(calls)}),
                                },
                            }
                        ],
                    },
                }
            ],
            "usage": {"prompt_tokens": 5, "completion_tokens": 2},
        }

    monkeypatch.setattr(client, "chat_completion", fake_chat_completion)
    result = client.run_conversation_with_tools(
        messages=[{"role": "user", "content": "start"}],
        tools_schema=[
            {"type": "function", "function": {"name": "emit_result", "parameters": {}}},
        ],
        tool_executor=lambda name, args: {"success": True},
        terminal_tool_name="emit_result",
        terminal_tool_handler=lambda payload: {
            "valid": False,
            "error": "invalid payload",
        },
        terminal_tool_required=True,
        max_iterations=10,
    )

    assert len(calls) == 5
    assert result["terminal_loop_guard_triggered"] is True
    assert result["terminal_loop_guard_reason"] == "invalid_terminal_call_limit"
    assert result["terminal_invalid_call_count"] == 5
    assert "repeated_terminal_tool_call" not in result


def test_two_invalid_terminal_calls_can_repair_before_guard(monkeypatch) -> None:
    client = LLMClient(
        api_key="test",
        base_url="http://example.invalid",
        models=["unit-model"],
    )
    calls = []

    def fake_chat_completion(messages, **kwargs):
        calls.append(list(messages))
        payload = {"value": len(calls)}
        if len(calls) == 3:
            payload["type"] = "result"
        return {
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {
                                "id": f"call_{len(calls)}",
                                "type": "function",
                                "function": {
                                    "name": "emit_result",
                                    "arguments": json.dumps(payload),
                                },
                            }
                        ],
                    },
                }
            ],
            "usage": {"prompt_tokens": 5, "completion_tokens": 2},
        }

    monkeypatch.setattr(client, "chat_completion", fake_chat_completion)
    result = client.run_conversation_with_tools(
        messages=[{"role": "user", "content": "start"}],
        tools_schema=[
            {"type": "function", "function": {"name": "emit_result", "parameters": {}}},
        ],
        tool_executor=lambda name, args: {"success": True},
        terminal_tool_name="emit_result",
        terminal_tool_handler=lambda payload: {
            "valid": payload.get("type") == "result",
            "payload": payload,
            "error": "missing type",
        },
        terminal_tool_required=True,
        max_iterations=10,
    )

    assert len(calls) == 3
    assert result["terminal_tool_valid"] is True
    assert result["terminal_invalid_call_count"] == 2
    assert result["terminal_tool_call_count"] == 3
    assert "terminal_loop_guard_triggered" not in result


def test_terminal_tool_required_reprompts_prose_until_budget(monkeypatch) -> None:
    client = LLMClient(api_key="test", base_url="http://example.invalid", models=["unit-model"])
    calls = []

    def fake_chat_completion(messages, **kwargs):
        calls.append(list(messages))
        return {
            "choices": [
                {"finish_reason": "stop", "message": {"role": "assistant", "content": "draft"}}
            ],
            "usage": {"prompt_tokens": 2, "completion_tokens": 1},
        }

    monkeypatch.setattr(client, "chat_completion", fake_chat_completion)
    result = client.run_conversation_with_tools(
        messages=[{"role": "user", "content": "start"}],
        tools_schema=[{"type": "function", "function": {"name": "emit_result", "parameters": {}}}],
        tool_executor=lambda name, args: {"success": True},
        terminal_tool_name="emit_result",
        terminal_tool_required=True,
        max_iterations=3,
    )

    assert len(calls) == 3
    assert result["terminal_tool_valid"] is False
    assert result.get("truncated", False) is False
    assert result["terminal_tool_call_count"] == 0


def test_xml_terminal_invoke_uses_terminal_handler(monkeypatch) -> None:
    client = LLMClient(api_key="test", base_url="http://example.invalid", models=["unit-model"])

    def fake_chat_completion(messages, **kwargs):
        return {
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {
                        "role": "assistant",
                        "content": '<invoke name="emit_result"><parameter name="value">7</parameter></invoke>',
                    },
                }
            ],
            "usage": {"prompt_tokens": 2, "completion_tokens": 1},
        }

    monkeypatch.setattr(client, "chat_completion", fake_chat_completion)
    result = client.run_conversation_with_tools(
        messages=[{"role": "user", "content": "start"}],
        tools_schema=[{"type": "function", "function": {"name": "emit_result", "parameters": {}}}],
        tool_executor=lambda name, args: (_ for _ in ()).throw(AssertionError("not normal")),
        terminal_tool_name="emit_result",
        terminal_tool_handler=lambda payload: {
            "valid": payload == {"value": 7},
            "payload": payload,
        },
        terminal_tool_required=True,
        max_iterations=3,
    )

    assert result["terminal_tool_payload"] == {"value": 7}
    assert result["terminal_tool_valid"] is True
    assert result["terminal_tool_call_count"] == 1


def test_mixed_terminal_and_regular_calls_reject_terminal_then_continue(monkeypatch) -> None:
    client = LLMClient(api_key="test", base_url="http://example.invalid", models=["unit-model"])
    calls = []
    executed = []

    def fake_chat_completion(messages, **kwargs):
        calls.append(list(messages))
        if len(calls) == 1:
            tool_calls = [
                {
                    "id": "lookup",
                    "type": "function",
                    "function": {"name": "lookup", "arguments": "{}"},
                },
                {
                    "id": "emit",
                    "type": "function",
                    "function": {"name": "emit_result", "arguments": json.dumps({"value": 7})},
                },
            ]
        else:
            tool_calls = [
                {
                    "id": "emit2",
                    "type": "function",
                    "function": {"name": "emit_result", "arguments": json.dumps({"value": 7})},
                }
            ]
        return {
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "message": {"role": "assistant", "content": "", "tool_calls": tool_calls},
                }
            ],
            "usage": {"prompt_tokens": 2, "completion_tokens": 1},
        }

    monkeypatch.setattr(client, "chat_completion", fake_chat_completion)
    result = client.run_conversation_with_tools(
        messages=[{"role": "user", "content": "start"}],
        tools_schema=[
            {"type": "function", "function": {"name": "lookup", "parameters": {}}},
            {"type": "function", "function": {"name": "emit_result", "parameters": {}}},
        ],
        tool_executor=lambda name, args: executed.append(name) or {"success": True},
        terminal_tool_name="emit_result",
        terminal_tool_handler=lambda payload: {
            "valid": payload == {"value": 7},
            "payload": payload,
        },
        terminal_tool_required=True,
        max_iterations=3,
    )

    assert executed == ["lookup"]
    assert result["terminal_tool_valid"] is True
    assert result["tool_call_count"] == 1
    assert any(
        message.get("terminal_tool_result") for message in calls[1] if message.get("role") == "tool"
    )


def test_duplicate_terminal_calls_are_rejected_before_single_retry(monkeypatch) -> None:
    client = LLMClient(api_key="test", base_url="http://example.invalid", models=["unit-model"])
    calls = []

    def fake_chat_completion(messages, **kwargs):
        calls.append(list(messages))
        count = 2 if len(calls) == 1 else 1
        tool_calls = [
            {
                "id": f"emit_{len(calls)}_{index}",
                "type": "function",
                "function": {"name": "emit_result", "arguments": json.dumps({"value": 7})},
            }
            for index in range(count)
        ]
        return {
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "message": {"role": "assistant", "content": "", "tool_calls": tool_calls},
                }
            ],
            "usage": {"prompt_tokens": 2, "completion_tokens": 1},
        }

    monkeypatch.setattr(client, "chat_completion", fake_chat_completion)
    result = client.run_conversation_with_tools(
        messages=[{"role": "user", "content": "start"}],
        tools_schema=[{"type": "function", "function": {"name": "emit_result", "parameters": {}}}],
        tool_executor=lambda name, args: (_ for _ in ()).throw(AssertionError("not normal")),
        terminal_tool_name="emit_result",
        terminal_tool_handler=lambda payload: {"valid": True, "payload": payload},
        terminal_tool_required=True,
        max_iterations=3,
    )

    assert result["terminal_tool_valid"] is True
    assert result["terminal_tool_call_count"] == 3
    assert sum(1 for message in calls[1] if message.get("terminal_tool_result")) == 2


def test_run_conversation_with_tools_compacts_old_tool_results(monkeypatch) -> None:
    client = LLMClient(
        api_key="test",
        base_url="http://example.invalid",
        models=["unit-model"],
    )
    calls = []
    huge_one = "A" * 6000
    huge_two = "B" * 6000

    def fake_chat_completion(messages, **kwargs):
        calls.append(list(messages))
        if len(calls) == 1:
            return {
                "choices": [
                    {
                        "finish_reason": "tool_calls",
                        "message": {
                            "role": "assistant",
                            "content": "",
                            "reasoning_content": "hidden reasoning" * 200,
                            "tool_calls": [
                                {
                                    "id": "call_1",
                                    "type": "function",
                                    "function": {
                                        "name": "lookup",
                                        "arguments": json.dumps({"name": "one"}),
                                    },
                                }
                            ],
                        },
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            }
        if len(calls) == 2:
            return {
                "choices": [
                    {
                        "finish_reason": "tool_calls",
                        "message": {
                            "role": "assistant",
                            "content": "",
                            "tool_calls": [
                                {
                                    "id": "call_2",
                                    "type": "function",
                                    "function": {
                                        "name": "lookup",
                                        "arguments": json.dumps({"name": "two"}),
                                    },
                                }
                            ],
                        },
                    }
                ],
                "usage": {"prompt_tokens": 20, "completion_tokens": 5},
            }
        return {
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": "done"},
                }
            ],
            "usage": {"prompt_tokens": 30, "completion_tokens": 5},
        }

    def fake_tool_executor(name, args):
        payload = huge_one if args["name"] == "one" else huge_two
        return {
            "success": True,
            "data": {
                "func_name": args["name"],
                "file": "src/demo.c",
                "start_line": 10,
                "end_line": 20,
                "code": payload,
            },
        }

    monkeypatch.setattr(client, "chat_completion", fake_chat_completion)

    result = client.run_conversation_with_tools(
        messages=[{"role": "user", "content": "start"}],
        tools_schema=[],
        tool_executor=fake_tool_executor,
        max_iterations=4,
    )

    third_prompt = calls[2]
    tool_messages = [msg for msg in third_prompt if msg.get("role") == "tool"]
    assert len(tool_messages) == 2
    old_tool = next(msg for msg in tool_messages if msg["tool_call_id"] == "call_1")
    latest_tool = next(msg for msg in tool_messages if msg["tool_call_id"] == "call_2")

    assert "compacted_tool_result" in old_tool["content"]
    assert huge_one not in old_tool["content"]
    assert len(old_tool["content"]) < 2200
    assert huge_two in latest_tool["content"]
    assert all("reasoning_content" not in msg for msg in third_prompt)

    full_transcript = json.dumps(result["conversation"], ensure_ascii=False)
    assert huge_one in full_transcript
    assert huge_two in full_transcript


def test_bounded_conversation_can_replay_provider_reasoning_metadata(monkeypatch) -> None:
    client = LLMClient(
        api_key="test",
        base_url="http://example.invalid",
        models=["unit-model"],
    )
    calls = []

    def fake_chat_completion(messages, **kwargs):
        calls.append(list(messages))
        if len(calls) == 1:
            return {
                "choices": [
                    {
                        "finish_reason": "tool_calls",
                        "message": {
                            "role": "assistant",
                            "content": "",
                            "reasoning_content": "provider-chain-state",
                            "tool_calls": [
                                {
                                    "id": "call_1",
                                    "type": "function",
                                    "function": {
                                        "name": "lookup",
                                        "arguments": "{}",
                                    },
                                }
                            ],
                        },
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            }
        return {
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": "done"},
                }
            ],
            "usage": {"prompt_tokens": 20, "completion_tokens": 3},
        }

    monkeypatch.setattr(client, "chat_completion", fake_chat_completion)
    client.run_conversation_with_tools(
        messages=[{"role": "user", "content": "start"}],
        tools_schema=[],
        tool_executor=lambda name, args: {"success": True, "data": {"fact": 1}},
        max_iterations=2,
        preserve_reasoning_metadata=True,
    )

    assert any(message.get("reasoning_content") == "provider-chain-state" for message in calls[1])


def test_run_conversation_forces_final_answer_after_repeated_identical_tool_call(
    monkeypatch,
) -> None:
    client = LLMClient(
        api_key="test",
        base_url="http://example.invalid",
        models=["unit-model"],
    )
    chat_calls = []
    tool_calls = []

    def fake_chat_completion(messages, **kwargs):
        chat_calls.append(list(messages))
        if len(chat_calls) == 4:
            assert kwargs.get("tools") is None
            assert "Tool use is now disabled" in messages[-1]["content"]
            return {
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": "done"},
                    }
                ],
                "usage": {"prompt_tokens": 20, "completion_tokens": 4},
            }
        return {
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {
                                "id": f"call_{len(chat_calls)}",
                                "type": "function",
                                "function": {
                                    "name": "get_file_snippet",
                                    "arguments": json.dumps(
                                        {
                                            "file_path": "src/demo.c",
                                            "start_line": 1,
                                            "end_line": 10,
                                        }
                                    ),
                                },
                            }
                        ],
                    },
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 2},
        }

    def fake_tool_executor(name, args):
        tool_calls.append((name, args))
        return {"success": True, "data": "snippet"}

    monkeypatch.setattr(client, "chat_completion", fake_chat_completion)

    result = client.run_conversation_with_tools(
        messages=[{"role": "user", "content": "start"}],
        tools_schema=[],
        tool_executor=fake_tool_executor,
        max_iterations=10,
        max_identical_tool_calls=1,
    )

    assert result["loop_guard_triggered"] is True
    assert result["loop_guard_recovered"] is True
    assert "truncated" not in result
    assert result["iterations"] == 4
    assert len(chat_calls) == 4
    assert len(tool_calls) == 1
    assert result["content"].endswith("done")
    assert result["repeated_tool_call"]["tool"] == "get_file_snippet"
    assert result["repeated_tool_call"]["repeat_count"] == 3
    cached_tool_messages = [
        msg
        for msg in result["conversation"]
        if msg.get("role") == "tool" and "cached_tool_result" in str(msg.get("content", ""))
    ]
    assert cached_tool_messages


def test_get_file_snippet_covered_range_reuses_cached_result(monkeypatch) -> None:
    client = LLMClient(
        api_key="test",
        base_url="http://example.invalid",
        models=["unit-model"],
    )
    chat_calls = []
    tool_calls = []

    def snippet_call(call_id: str, start: int, end: int):
        return {
            "id": call_id,
            "type": "function",
            "function": {
                "name": "get_file_snippet",
                "arguments": json.dumps(
                    {
                        "file_path": "src/demo.c",
                        "start_line": start,
                        "end_line": end,
                    }
                ),
            },
        }

    def fake_chat_completion(messages, **kwargs):
        chat_calls.append(list(messages))
        if len(chat_calls) == 1:
            tool_call = snippet_call("call_wide", 1, 20)
        elif len(chat_calls) == 2:
            tool_call = snippet_call("call_covered", 5, 10)
        else:
            return {
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": "done"},
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 2},
            }
        return {
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [tool_call],
                    },
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 2},
        }

    def fake_tool_executor(name, args):
        tool_calls.append((name, args))
        code = "".join(
            f"{line} | int demo_{line}(void) {{ return {line}; }}\n"
            for line in range(1, 21)
        )
        return {
            "success": True,
            "data": {
                "file": args["file_path"],
                "start_line": args["start_line"],
                "end_line": args["end_line"],
                "code": code,
            },
        }

    monkeypatch.setattr(client, "chat_completion", fake_chat_completion)

    result = client.run_conversation_with_tools(
        messages=[{"role": "user", "content": "start"}],
        tools_schema=[],
        tool_executor=fake_tool_executor,
        max_iterations=5,
    )

    assert result["iterations"] == 3
    assert result["tool_call_count"] == 2
    assert len(tool_calls) == 1
    covered_tool_messages = [
        msg
        for msg in result["conversation"]
        if msg.get("role") == "tool"
        and "covered_file_snippet_replay" in str(msg.get("content", ""))
    ]
    assert covered_tool_messages
    assert "cached_tool_result" in covered_tool_messages[0]["content"]
    covered_payload = json.loads(covered_tool_messages[0]["content"])
    assert covered_payload["data"]["start_line"] == 5
    assert covered_payload["data"]["end_line"] == 10
    assert covered_payload["data"]["code"].splitlines()[0].startswith("5 |")
    assert len(covered_payload["data"]["code"].splitlines()) == 6


def test_run_conversation_reports_final_tool_call_after_tools_disabled(monkeypatch) -> None:
    client = LLMClient(
        api_key="test",
        base_url="http://example.invalid",
        models=["unit-model"],
    )

    def fake_chat_completion(messages, **kwargs):
        assert kwargs.get("tools") is None
        return {
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {
                                "id": "call_1",
                                "type": "function",
                                "function": {
                                    "name": "lookup",
                                    "arguments": json.dumps({"name": "demo"}),
                                },
                            }
                        ],
                    },
                }
            ],
            "model": "unit-model",
            "usage": {"prompt_tokens": 10, "completion_tokens": 2},
        }

    def fail_tool_executor(name, args):
        raise AssertionError("final disabled tool calls must not be executed")

    monkeypatch.setattr(client, "chat_completion", fake_chat_completion)

    result = client.run_conversation_with_tools(
        messages=[{"role": "user", "content": "start"}],
        tools_schema=[],
        tool_executor=fail_tool_executor,
        max_iterations=1,
    )

    assert result["final_tool_call_without_json"] is True
    assert result["final_tool_call_after_tools_disabled"] is True
    assert result["final_tool_call_count"] == 1
    assert result["finish_reason"] == "tool_calls"
    assert result["provider_model"] == "unit-model"
    assert result["truncated"] is True
    assert result["tool_call_count"] == 0
    assert "lookup" in result["last_assistant_preview"]
