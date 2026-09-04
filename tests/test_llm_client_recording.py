"""Integration tests for llm_client conversation-recording instrumentation."""

import json

import pytest
import requests

from zscope.framework.conversation_recorder import (
    disable_conversation_recording,
    enable_conversation_recording,
)
from zscope.framework.llm_client import LLMClient


@pytest.fixture()
def recorder(tmp_path):
    rec = enable_conversation_recording(tmp_path)
    yield rec
    disable_conversation_recording()


def _jsonl_events(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _events_by_type(recorder):
    events = []
    for path in sorted(recorder.run_dir.glob("*.jsonl")):
        if path.name == "index.jsonl":
            continue
        events.extend(_jsonl_events(path))
    return events


class _CompletedResponse:
    status_code = 200
    text = "ok"

    def close(self):
        pass


class _ErrorResponse:
    def __init__(self, status_code, text="error"):
        self.status_code = status_code
        self.text = text

    def close(self):
        pass


class _ScriptedSession:
    """Returns scripted items in order: responses or raised exceptions."""

    def __init__(self, script):
        self.script = list(script)

    def post(self, *args, **kwargs):
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def test_timeout_attempt_then_success_records_attempt_and_exchange(recorder, monkeypatch):
    client = LLMClient(
        api_key="test",
        base_url="http://example.invalid/v1",
        models=["unit-model"],
        max_retries=1,
    )
    message = {"role": "assistant", "content": "done"}
    scripted = _ScriptedSession(
        [requests.exceptions.Timeout("read timed out"), _CompletedResponse()]
    )
    monkeypatch.setattr(client, "_session_for_thread", lambda: scripted)
    monkeypatch.setattr(
        client,
        "_assemble_chat_response_with_usage",
        lambda _response: (message, "stop", None),
    )

    result = client.chat_completion([{"role": "user", "content": "hello"}])
    assert result["choices"][0]["finish_reason"] == "stop"

    events = _events_by_type(recorder)
    types = [event["event"] for event in events]
    assert types == ["session_start", "attempt", "exchange", "session_end"]
    attempt = events[1]
    assert attempt["outcome"] == "timeout"
    assert attempt["model"] == "unit-model"
    assert attempt["base_url"] == "http://example.invalid/v1"
    assert attempt["attempt"] == 1
    assert attempt["delay_ms"] >= 0
    exchange = events[2]
    assert exchange["attempt_count"] == 2
    assert exchange["duration_ms"] >= 0
    assert exchange["base_url"] == "http://example.invalid/v1"
    assert exchange["finish_reason"] == "stop"
    session_end = events[3]
    assert session_end["cumulative_prompt_tokens"] > 0
    assert session_end["finish_reason"] == "stop"


def test_model_fallback_records_http_and_fallback_attempts(recorder, monkeypatch):
    client = LLMClient(
        api_key="test",
        base_url="http://example.invalid/v1",
        models=["model-a", "model-b"],
        max_retries=0,
    )
    message = {"role": "assistant", "content": "done"}
    scripted = _ScriptedSession([_ErrorResponse(400, "bad request"), _CompletedResponse()])
    monkeypatch.setattr(client, "_session_for_thread", lambda: scripted)
    monkeypatch.setattr(
        client,
        "_assemble_chat_response_with_usage",
        lambda _response: (message, "stop", None),
    )

    result = client.chat_completion([{"role": "user", "content": "hello"}])
    assert result["model"] == "model-b"

    events = _events_by_type(recorder)
    attempts = [event for event in events if event["event"] == "attempt"]
    assert [attempt["outcome"] for attempt in attempts] == ["http_400", "model_fallback"]
    assert attempts[0]["model"] == "model-a"
    assert attempts[1]["model"] == "model-a"
    assert "bad request" in attempts[1]["error"]
    exchanges = [event for event in events if event["event"] == "exchange"]
    assert len(exchanges) == 1
    assert exchanges[0]["model"] == "model-b"
    assert exchanges[0]["attempt_count"] == 1


def test_tool_exception_records_parsed_args_and_duration(recorder, monkeypatch):
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
                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            }
        return {
            "choices": [
                {"finish_reason": "stop", "message": {"role": "assistant", "content": "done"}}
            ],
            "usage": {"prompt_tokens": 20, "completion_tokens": 5},
        }

    monkeypatch.setattr(client, "chat_completion", fake_chat_completion)

    def failing_executor(name, args):
        raise RuntimeError("executor boom")

    result = client.run_conversation_with_tools(
        messages=[{"role": "user", "content": "start"}],
        tools_schema=[{"type": "function", "function": {"name": "lookup", "parameters": {}}}],
        tool_executor=failing_executor,
        max_iterations=2,
    )
    assert result["iterations"] == 2

    events = _events_by_type(recorder)
    tool_calls = [event for event in events if event["event"] == "tool_call"]
    tool_results = [event for event in events if event["event"] == "tool_result"]
    assert len(tool_calls) == 1
    assert tool_calls[0]["tool_call_id"] == "call_1"
    assert tool_calls[0]["args"] == {"name": "demo"}
    assert len(tool_results) == 1
    assert tool_results[0]["status"] == "error"
    assert "executor boom" in tool_results[0]["error"]
    assert tool_results[0]["args"] == {"name": "demo"}
    assert tool_results[0]["duration_ms"] >= 0
    session_start = events[0]
    assert session_start["tools_schema_hash"]


def test_unparseable_tool_args_record_raw_arguments(recorder, monkeypatch):
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
                                    "id": "call_bad",
                                    "type": "function",
                                    "function": {
                                        "name": "lookup",
                                        "arguments": "{not json",
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
                {"finish_reason": "stop", "message": {"role": "assistant", "content": "done"}}
            ],
            "usage": {"prompt_tokens": 20, "completion_tokens": 5},
        }

    monkeypatch.setattr(client, "chat_completion", fake_chat_completion)
    client.run_conversation_with_tools(
        messages=[{"role": "user", "content": "start"}],
        tools_schema=[],
        tool_executor=lambda name, args: {"success": True},
        max_iterations=2,
    )

    events = _events_by_type(recorder)
    tool_results = [event for event in events if event["event"] == "tool_result"]
    assert len(tool_results) == 1
    assert tool_results[0]["status"] == "error"
    assert tool_results[0]["args_raw"] == "{not json"
    assert tool_results[0]["tool_call_id"] == "call_bad"


def test_length_continuation_records_control_event(recorder, monkeypatch):
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
                        "finish_reason": "length",
                        "message": {"role": "assistant", "content": ""},
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            }
        return {
            "choices": [
                {"finish_reason": "stop", "message": {"role": "assistant", "content": "done"}}
            ],
            "usage": {"prompt_tokens": 20, "completion_tokens": 5},
        }

    monkeypatch.setattr(client, "chat_completion", fake_chat_completion)
    client.run_conversation_with_tools(
        messages=[{"role": "user", "content": "start"}],
        tools_schema=[],
        tool_executor=lambda name, args: {"success": True},
        max_iterations=3,
    )

    events = _events_by_type(recorder)
    controls = [event for event in events if event["event"] == "iteration_control"]
    assert any(control["kind"] == "length_continuation" for control in controls)


def test_final_iteration_records_instruction_and_truncated_end(recorder, monkeypatch):
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
            "usage": {"prompt_tokens": 10, "completion_tokens": 2},
        }

    monkeypatch.setattr(client, "chat_completion", fake_chat_completion)
    result = client.run_conversation_with_tools(
        messages=[{"role": "user", "content": "start"}],
        tools_schema=[],
        tool_executor=lambda name, args: {"success": True},
        max_iterations=1,
    )
    assert result["truncated"] is True

    events = _events_by_type(recorder)
    controls = [event for event in events if event["event"] == "iteration_control"]
    assert any(control["kind"] == "final_instruction" for control in controls)
    rejected = [
        event
        for event in controls
        if event["kind"] == "final_iteration_tool_calls_rejected"
    ]
    assert len(rejected) == 1
    session_end = next(event for event in events if event["event"] == "session_end")
    assert session_end["truncated"] is True
    assert session_end["iterations"] == 1


def test_loop_guard_records_guard_event(recorder, monkeypatch):
    client = LLMClient(
        api_key="test",
        base_url="http://example.invalid",
        models=["unit-model"],
    )
    chat_calls = []

    def fake_chat_completion(messages, **kwargs):
        chat_calls.append(list(messages))
        if len(chat_calls) == 4:
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

    monkeypatch.setattr(client, "chat_completion", fake_chat_completion)
    client.run_conversation_with_tools(
        messages=[{"role": "user", "content": "start"}],
        tools_schema=[
            {"type": "function", "function": {"name": "get_file_snippet", "parameters": {}}},
            {"type": "function", "function": {"name": "lookup", "parameters": {}}},
        ],
        tool_executor=lambda name, args: {"success": True, "data": "snippet"},
        max_iterations=10,
        max_identical_tool_calls=1,
    )

    events = _events_by_type(recorder)
    guards = [event for event in events if event["event"] == "loop_guard"]
    assert len(guards) == 1
    assert guards[0]["tool"] == "get_file_snippet"
    assert guards[0]["repeat_count"] == 3
    assert guards[0]["disabled_tools"] == ["get_file_snippet"]
    blocked_results = [
        event
        for event in events
        if event["event"] == "tool_result" and event.get("blocked")
    ]
    assert len(blocked_results) == 1
    session_end = next(event for event in events if event["event"] == "session_end")
    assert session_end["loop_guard_triggered"] is True


def test_terminal_tool_submissions_record_call_ids(recorder, monkeypatch):
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
                                "id": f"emit_{len(calls)}",
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
            "error": "missing type" if payload.get("type") != "result" else None,
        },
        terminal_tool_required=True,
        max_iterations=3,
    )
    assert result["terminal_tool_valid"] is True

    events = _events_by_type(recorder)
    terminal_events = [event for event in events if event["event"] == "terminal_tool"]
    assert [event["valid"] for event in terminal_events] == [False, True]
    assert [event["tool_call_id"] for event in terminal_events] == ["emit_1", "emit_2"]
    assert "missing type" in terminal_events[0]["error"]
    session_end = next(event for event in events if event["event"] == "session_end")
    assert session_end["terminal_tool_valid"] is True
