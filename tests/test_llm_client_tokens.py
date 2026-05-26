import json

from zscope.framework.llm_client import LLMClient


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


def test_run_conversation_stops_on_repeated_identical_tool_call(monkeypatch) -> None:
    client = LLMClient(
        api_key="test",
        base_url="http://example.invalid",
        models=["unit-model"],
    )
    chat_calls = []
    tool_calls = []

    def fake_chat_completion(messages, **kwargs):
        chat_calls.append(list(messages))
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
    assert result["truncated"] is True
    assert result["iterations"] == 3
    assert len(chat_calls) == 3
    assert len(tool_calls) == 1
    assert result["repeated_tool_call"]["tool"] == "get_file_snippet"
    assert result["repeated_tool_call"]["repeat_count"] == 3
    cached_tool_messages = [
        msg
        for msg in result["conversation"]
        if msg.get("role") == "tool"
        and "cached_tool_result" in str(msg.get("content", ""))
    ]
    assert cached_tool_messages
