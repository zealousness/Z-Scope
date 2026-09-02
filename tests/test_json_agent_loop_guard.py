import json

import pytest

from zscope.agents.base import JsonOutputSpec, JsonToolAgent
from zscope.framework.base import AgentResponse
from zscope.framework.llm_client import LLMClient
from zscope.framework.llm_usage import (
    P6BalancedTokenAdmissionError,
    ScanTokenUsageLedger,
)


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


def _p6_client(*, supports_structured_output: bool = False) -> LLMClient:
    ledger = ScanTokenUsageLedger(depth="balanced")
    ledger.enable_p6_balanced_admission()
    return LLMClient(
        api_key="test",
        base_url="http://example.invalid",
        models=["unit-model"],
        supports_structured_output=supports_structured_output,
        token_usage_ledger=ledger,
    )


def test_json_tool_agent_propagates_p6_token_admission(monkeypatch) -> None:
    client = LLMClient(
        api_key="test",
        base_url="http://example.invalid",
        models=["unit-model"],
    )
    agent = LoopGuardAgent(client)

    def deny(*_args, **_kwargs):
        raise P6BalancedTokenAdmissionError("p6_token_hard_limit")

    monkeypatch.setattr(agent, "_run_tool_conversation", deny)

    with pytest.raises(P6BalancedTokenAdmissionError) as raised:
        agent._run_json_conversation(
            [{"role": "user", "content": "start"}],
            extractor=lambda content, result, conversation: None,
            trace_label="unit",
            parse_label="unit payload",
            retry_prompt="retry",
        )

    assert raised.value.failure_class == "p6_token_hard_limit"


def test_json_tool_agent_sanitizes_broad_p6_failure(monkeypatch, caplog) -> None:
    canary = "PRIVATE_EXCEPTION_BODY_MUST_NOT_LEAK"
    agent = LoopGuardAgent(_p6_client())

    def fail(*_args, **_kwargs):
        raise RuntimeError(canary)

    monkeypatch.setattr(agent, "_run_tool_conversation", fail)
    response = agent._run_json_conversation(
        [{"role": "user", "content": "start"}],
        extractor=lambda content, result, conversation: None,
        trace_label="unit",
        parse_label="unit payload",
        retry_prompt="retry",
    )

    assert response.success is False
    assert response.error == "class=internal_failure; count=1"
    assert response.metadata == {"failure_class": "internal_failure", "failure_count": 1}
    assert canary not in caplog.text
    assert "class=internal_failure; count=1" in caplog.text


def test_json_tool_agent_preserves_non_p6_broad_failure_detail(monkeypatch) -> None:
    canary = "ordinary-debug-detail"
    client = LLMClient(
        api_key="test",
        base_url="http://example.invalid",
        models=["unit-model"],
    )
    agent = LoopGuardAgent(client)

    def fail(*_args, **_kwargs):
        raise RuntimeError(canary)

    monkeypatch.setattr(agent, "_run_tool_conversation", fail)
    response = agent._run_json_conversation(
        [{"role": "user", "content": "start"}],
        extractor=lambda content, result, conversation: None,
        trace_label="unit",
        parse_label="unit payload",
        retry_prompt="retry",
    )

    assert response.error == canary


def test_json_repair_sanitizes_initial_and_fallback_p6_failures(caplog) -> None:
    canary = "PRIVATE_REPAIR_EXCEPTION_BODY_MUST_NOT_LEAK"
    agent = LoopGuardAgent(_p6_client(supports_structured_output=True))
    calls = []

    def fail(*_args, **kwargs):
        calls.append(kwargs)
        raise RuntimeError(canary)

    result = agent._call_json_repair_completion(
        fail,
        [{"role": "user", "content": "repair"}],
        final_tool_schema=agent._final_json_tool_schema(_payload_spec()),
        json_output_spec=_payload_spec(),
        trace_label="unit",
        trace_iteration=1,
    )

    assert result is None
    assert len(calls) == 2
    assert canary not in caplog.text
    assert "class=internal_failure; count=1" in caplog.text


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


def test_final_tool_payload_is_enumerated_once_when_message_is_in_conversation() -> None:
    agent = LoopGuardAgent(object())
    spec = _payload_spec()
    message = {
        "role": "assistant",
        "content": "",
        "tool_calls": [
            {
                "id": "call_emit",
                "type": "function",
                "function": {
                    "name": "emit_unit_payload",
                    "arguments": json.dumps({"type": "unit_payload", "value": "ok"}),
                },
            }
        ],
    }

    payloads = list(agent._final_tool_payloads({"message": message}, [message], spec))

    assert payloads == [{"type": "unit_payload", "value": "ok"}]


@pytest.mark.parametrize("second_name", ["emit_unit_payload", "inspect_more"])
def test_final_tool_payload_rejects_duplicate_or_mixed_calls(second_name: str) -> None:
    agent = LoopGuardAgent(object())
    spec = _payload_spec()
    message = {
        "role": "assistant",
        "content": "",
        "tool_calls": [
            {
                "id": "call_emit",
                "type": "function",
                "function": {
                    "name": "emit_unit_payload",
                    "arguments": json.dumps({"type": "unit_payload", "value": "ok"}),
                },
            },
            {
                "id": "call_second",
                "type": "function",
                "function": {"name": second_name, "arguments": "{}"},
            },
        ],
    }

    assert list(agent._final_tool_payloads({"message": message}, [message], spec)) == []


@pytest.mark.parametrize("second_name", ["emit_unit_payload", "inspect_more"])
def test_final_tool_contract_never_falls_back_to_prose_for_invalid_batch(
    second_name: str,
) -> None:
    agent = LoopGuardAgent(object())
    spec = _payload_spec()
    content = json.dumps({"type": "unit_payload", "value": "prose-bypass"})
    message = {
        "role": "assistant",
        "content": content,
        "tool_calls": [
            {
                "id": "call_emit",
                "type": "function",
                "function": {
                    "name": "emit_unit_payload",
                    "arguments": json.dumps({"type": "unit_payload", "value": "tool"}),
                },
            },
            {
                "id": "call_second",
                "type": "function",
                "function": {"name": second_name, "arguments": "{}"},
            },
        ],
    }
    result = {"message": message}

    assert agent._extract_structured_json_payload(content, result, [message], spec) is None
    assert (
        agent._extract_json_output(
            content,
            result,
            [message],
            extractor=lambda *_args: {"type": "unit_payload", "value": "caller-bypass"},
            json_output_spec=spec,
        )
        is None
    )


def test_missing_forced_final_tool_never_falls_back_to_prose() -> None:
    agent = LoopGuardAgent(object())
    spec = _payload_spec()
    content = json.dumps({"type": "unit_payload", "value": "prose-bypass"})
    message = {"role": "assistant", "content": content}
    result = {
        "message": message,
        "_zscope_final_tool_contract_required": True,
    }

    assert agent._extract_structured_json_payload(content, result, [message], spec) is None


def test_result_message_cannot_hide_conversation_final_tool_contract() -> None:
    agent = LoopGuardAgent(object())
    spec = _payload_spec()
    content = json.dumps({"type": "unit_payload", "value": "prose-bypass"})
    result_message = {"role": "assistant", "content": content}
    earlier_final = {
        "role": "assistant",
        "content": "",
        "tool_calls": [
            {
                "id": "call_bad",
                "type": "function",
                "function": {"name": "emit_unit_payload", "arguments": "not-json"},
            }
        ],
    }

    assert (
        agent._extract_structured_json_payload(
            content,
            {"message": result_message},
            [earlier_final, result_message],
            spec,
        )
        is None
    )


def test_structured_output_without_final_tool_contract_keeps_json_path() -> None:
    agent = LoopGuardAgent(object())
    spec = _payload_spec()
    payload = {"type": "unit_payload", "value": "structured"}
    content = json.dumps(payload)
    message = {"role": "assistant", "content": content}

    assert (
        agent._extract_structured_json_payload(
            content,
            {"message": message},
            [message],
            spec,
        )
        == payload
    )


def test_ordinary_tool_history_does_not_disable_later_structured_output() -> None:
    agent = LoopGuardAgent(object())
    spec = _payload_spec()
    payload = {"type": "unit_payload", "value": "structured"}
    content = json.dumps(payload)
    ordinary_action = {
        "role": "assistant",
        "content": "",
        "tool_calls": [
            {
                "id": "call_inspect",
                "type": "function",
                "function": {"name": "inspect_more", "arguments": "{}"},
            }
        ],
    }
    message = {"role": "assistant", "content": content}

    assert (
        agent._extract_structured_json_payload(
            content,
            {"message": message},
            [ordinary_action, message],
            spec,
        )
        == payload
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
