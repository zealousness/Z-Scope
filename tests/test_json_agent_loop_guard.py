import json

from zscope.agents.base import JsonOutputSpec, JsonToolAgent
from zscope.framework.base import AgentResponse
from zscope.framework.llm_client import LLMClient


class LoopGuardAgent(JsonToolAgent):
    def __init__(self, llm_client: LLMClient):
        super().__init__(
            name="loop_guard_agent",
            description="loop guard test agent",
            llm_client=llm_client,
            tools=[],
        )

    def run(self, input_data):
        return AgentResponse(success=True, data={})


def test_json_tool_agent_does_not_retry_after_tool_loop_guard(monkeypatch) -> None:
    client = LLMClient(
        api_key="test",
        base_url="http://example.invalid",
        models=["unit-model"],
    )
    agent = LoopGuardAgent(client)

    def fake_run_tool_conversation(*args, **kwargs):
        return {
            "content": "",
            "conversation": [],
            "iterations": 2,
            "truncated": True,
            "loop_guard_triggered": True,
            "repeated_tool_call": {
                "tool": "get_file_snippet",
                "arguments": {"file_path": "src/demo.c"},
                "repeat_count": 2,
            },
            "context_tokens": 100,
            "cumulative_prompt_tokens": 90,
            "cumulative_completion_tokens": 10,
            "cumulative_total_tokens": 100,
        }

    def fail_retry(*args, **kwargs):
        raise AssertionError("JSON retry should not run after loop guard")

    monkeypatch.setattr(agent, "_run_tool_conversation", fake_run_tool_conversation)
    monkeypatch.setattr(client, "chat_completion", fail_retry)

    response = agent._run_json_conversation(
        [{"role": "user", "content": "start"}],
        extractor=lambda content, result, conversation: None,
        trace_label="loop",
        parse_label="payload",
        retry_prompt="retry",
    )

    assert response.success is False
    assert response.error == "Stopped after repeated identical tool calls."
    assert response.metadata["loop_guard_triggered"] is True
    assert response.metadata["repeated_tool_call"]["tool"] == "get_file_snippet"


def _payload_spec() -> JsonOutputSpec:
    return JsonOutputSpec(
        type_name="unit_payload",
        schema={
            "type": "object",
            "properties": {
                "type": {"type": "string", "enum": ["unit_payload"]},
                "value": {"type": "string"},
            },
            "required": ["type", "value"],
            "additionalProperties": True,
        },
        final_tool_name="emit_unit_payload",
        final_tool_description="Emit the final unit payload.",
        validator=lambda data: isinstance(data, dict) and data.get("type") == "unit_payload",
        metadata_prefix="unit",
    )


def test_json_tool_agent_repairs_prose_with_final_tool(monkeypatch) -> None:
    client = LLMClient(
        api_key="test",
        base_url="http://example.invalid",
        models=["unit-model"],
    )
    agent = LoopGuardAgent(client)
    spec = _payload_spec()

    def fake_run_tool_conversation(*args, **kwargs):
        return {
            "content": "I can answer now.",
            "conversation": [{"role": "assistant", "content": "I can answer now."}],
            "finish_reason": "stop",
            "provider_model": "unit-model",
            "iterations": 1,
            "tool_call_count": 0,
        }

    def fake_chat_completion(messages, **kwargs):
        assert kwargs["tools"][0]["function"]["name"] == "emit_unit_payload"
        return {
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {
                                "id": "call_emit",
                                "type": "function",
                                "function": {
                                    "name": "emit_unit_payload",
                                    "arguments": json.dumps(
                                        {"type": "unit_payload", "value": "ok"}
                                    ),
                                },
                            }
                        ],
                    },
                }
            ],
            "model": "unit-model",
            "usage": {"prompt_tokens": 10, "completion_tokens": 3},
        }

    monkeypatch.setattr(agent, "_run_tool_conversation", fake_run_tool_conversation)
    monkeypatch.setattr(client, "chat_completion", fake_chat_completion)

    response = agent._run_json_conversation(
        [{"role": "user", "content": "start"}],
        extractor=lambda content, result, conversation: agent._extract_structured_json_payload(
            content,
            result,
            conversation,
            spec,
        ),
        trace_label="unit",
        parse_label="unit_payload JSON",
        retry_prompt="retry",
        json_output_spec=spec,
    )

    assert response.success is True
    assert response.data["value"] == "ok"
    assert response.data["unit_json_repaired"] is True
    assert response.metadata["unit_repair_attempted"] == 1
    assert response.metadata["unit_repair_accepted"] == 1
    assert response.metadata["unit_final_tool_call_count"] == 1


def test_json_tool_agent_repairs_after_tool_loop_guard(monkeypatch) -> None:
    client = LLMClient(
        api_key="test",
        base_url="http://example.invalid",
        models=["unit-model"],
    )
    agent = LoopGuardAgent(client)
    spec = _payload_spec()

    monkeypatch.setattr(
        agent,
        "_run_tool_conversation",
        lambda *args, **kwargs: {
            "content": "",
            "conversation": [],
            "iterations": 2,
            "truncated": True,
            "loop_guard_triggered": True,
            "repeated_tool_call": {
                "tool": "get_file_snippet",
                "arguments": {"file_path": "src/demo.c"},
                "repeat_count": 2,
            },
            "context_tokens": 100,
            "cumulative_prompt_tokens": 90,
            "cumulative_completion_tokens": 10,
            "cumulative_total_tokens": 100,
        },
    )

    def fake_chat_completion(messages, **kwargs):
        assert kwargs["tools"][0]["function"]["name"] == "emit_unit_payload"
        return {
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {
                                "id": "call_emit",
                                "type": "function",
                                "function": {
                                    "name": "emit_unit_payload",
                                    "arguments": json.dumps(
                                        {"type": "unit_payload", "value": "recovered"}
                                    ),
                                },
                            }
                        ],
                    },
                }
            ],
            "model": "unit-model",
            "usage": {"prompt_tokens": 10, "completion_tokens": 3},
        }

    monkeypatch.setattr(client, "chat_completion", fake_chat_completion)

    response = agent._run_json_conversation(
        [{"role": "user", "content": "start"}],
        extractor=lambda content, result, conversation: None,
        trace_label="unit",
        parse_label="unit_payload JSON",
        retry_prompt="retry",
        json_output_spec=spec,
    )

    assert response.success is True
    assert response.data["value"] == "recovered"
    assert response.data["unit_json_repaired"] is True
    assert response.metadata["loop_guard_triggered"] is True
    assert response.metadata["repeated_tool_call"]["tool"] == "get_file_snippet"
    assert response.metadata["unit_repair_attempted"] == 1
    assert response.metadata["unit_repair_accepted"] == 1


def test_json_tool_agent_structured_output_falls_back_to_final_tool(monkeypatch) -> None:
    client = LLMClient(
        api_key="test",
        base_url="http://example.invalid",
        models=["unit-model"],
        supports_structured_output=True,
    )
    agent = LoopGuardAgent(client)
    spec = _payload_spec()
    calls = []

    monkeypatch.setattr(
        agent,
        "_run_tool_conversation",
        lambda *args, **kwargs: {
            "content": "",
            "conversation": [],
            "finish_reason": "stop",
            "iterations": 1,
        },
    )

    def fake_chat_completion(messages, **kwargs):
        calls.append(kwargs)
        if len(calls) == 1:
            assert kwargs.get("response_format")
            raise RuntimeError("provider rejected response_format")
        assert kwargs["tools"][0]["function"]["name"] == "emit_unit_payload"
        return {
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {
                                "id": "call_emit",
                                "type": "function",
                                "function": {
                                    "name": "emit_unit_payload",
                                    "arguments": json.dumps(
                                        {"type": "unit_payload", "value": "fallback"}
                                    ),
                                },
                            }
                        ],
                    },
                }
            ],
            "model": "unit-model",
            "usage": {"prompt_tokens": 10, "completion_tokens": 3},
        }

    monkeypatch.setattr(client, "chat_completion", fake_chat_completion)

    response = agent._run_json_conversation(
        [{"role": "user", "content": "start"}],
        extractor=lambda content, result, conversation: None,
        trace_label="unit",
        parse_label="unit_payload JSON",
        retry_prompt="retry",
        json_output_spec=spec,
    )

    assert response.success is True
    assert response.data["value"] == "fallback"
    assert len(calls) == 2
