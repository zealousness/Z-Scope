"""HTTP 4xx wire-shape diagnostics for LLMClient.

Customer gateways (e.g. DeepSeek-style OpenAI-compatible validators) reject
requests with HTTP 400 on fields the local benchmark replay never exercises.
These tests pin the ``[LLM-4xx-DIAG]`` summary that must be emitted on every
4xx so the offending protocol field is identifiable from logs alone.
"""

import json

import pytest

from zscope.common.validator_protocol import validator_result_schema_v3
from zscope.framework.llm_client import LLMClient


class _RejectedResponse:
    status_code = 400
    text = (
        '{"error":{"message":"Input validation error: max_tokens must be positive",'
        '"type":"invalid_request_error"}}'
    )

    def close(self):
        pass


def _client() -> LLMClient:
    return LLMClient(
        api_key="test",
        base_url="http://example.invalid/v1",
        models=["unit-model"],
        max_retries=0,
    )


def _v3_terminal_tool() -> dict:
    return {
        "type": "function",
        "function": {
            "name": "emit_validator_result_v3",
            "description": "Emit the strict Z-Scope ValidatorResult v3 object.",
            "parameters": validator_result_schema_v3(),
        },
    }


def test_400_logs_wire_shape_diagnostics(monkeypatch, caplog) -> None:
    client = _client()
    session = type(
        "Session",
        (),
        {"post": lambda self, *args, **kwargs: _RejectedResponse()},
    )()
    monkeypatch.setattr(client, "_session_for_thread", lambda: session)
    messages = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "hello"},
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [],
            "reasoning_content": "scratchpad that must not be replayed",
        },
        {"role": "tool", "tool_call_id": "t1", "content": "{}"},
    ]
    tool_choice = {
        "type": "function",
        "function": {"name": "emit_validator_result_v3"},
    }
    with caplog.at_level("WARNING", logger="zscope.framework.llm_client"):
        with pytest.raises(Exception, match="All models failed"):
            client.chat_completion(
                messages,
                tools=[_v3_terminal_tool()],
                tool_choice=tool_choice,
                max_tokens=8192,
            )

    diag_lines = [line for line in caplog.text.splitlines() if "[LLM-4xx-DIAG]" in line]
    assert len(diag_lines) >= 2
    summary = json.loads(diag_lines[0].split("[LLM-4xx-DIAG]", 1)[1])
    assert summary["status"] == 400
    assert "stream_options" in summary["payload_fields"]
    assert summary["stream_options"] == {"include_usage": True}
    assert summary["max_tokens"] == 8192
    assert summary["tool_choice"] == tool_choice
    assert summary["response_format"] is None
    assert summary["message_count"] == 4
    assert summary["role_counts"] == {"system": 1, "user": 1, "assistant": 1, "tool": 1}
    assert summary["assistant_with_reasoning_content"] == 1
    assert summary["message_extra_keys"] == []
    assert summary["tool_names"] == ["emit_validator_result_v3"]
    assert summary["tools_schema_hash"]
    assert summary["tool_schema_flags"]["type_union"] >= 1
    assert summary["tool_schema_flags"]["additionalProperties_false"] >= 1
    assert "provider_error" in caplog.text
    assert "max_tokens rejected" in caplog.text
    assert "max_tokens must be positive" not in caplog.text


def test_http_error_never_persists_provider_echoed_secrets(monkeypatch, caplog) -> None:
    client = _client()
    response = _RejectedResponse()
    response.text = '{"error":"invalid schema; Authorization: Bearer SECRET_KEY; PRIVATE_SOURCE"}'
    monkeypatch.setattr(
        client,
        "_session_for_thread",
        lambda: type("Session", (), {"post": lambda self, *args, **kwargs: response})(),
    )
    with caplog.at_level("WARNING", logger="zscope.framework.llm_client"):
        with pytest.raises(Exception, match="HTTP 400: tool schema rejected") as failure:
            client.chat_completion([{"role": "user", "content": "hello"}])
    for text in (caplog.text, str(failure.value)):
        assert "SECRET_KEY" not in text
        assert "PRIVATE_SOURCE" not in text


def test_400_diag_reports_json_schema_response_format(monkeypatch, caplog) -> None:
    client = _client()
    session = type(
        "Session",
        (),
        {"post": lambda self, *args, **kwargs: _RejectedResponse()},
    )()
    monkeypatch.setattr(client, "_session_for_thread", lambda: session)
    response_format = {
        "type": "json_schema",
        "json_schema": {
            "name": "validator_result_v3",
            "strict": True,
            "schema": validator_result_schema_v3(),
        },
    }
    with caplog.at_level("WARNING", logger="zscope.framework.llm_client"):
        with pytest.raises(Exception, match="All models failed"):
            client.chat_completion(
                [{"role": "user", "content": "hello"}],
                response_format=response_format,
            )
    diag_lines = [line for line in caplog.text.splitlines() if "[LLM-4xx-DIAG]" in line]
    summary = json.loads(diag_lines[0].split("[LLM-4xx-DIAG]", 1)[1])
    assert summary["response_format"] == {
        "type": "json_schema",
        "json_schema.name": "validator_result_v3",
        "json_schema.strict": True,
    }
    assert "tools" not in summary["payload_fields"]
    assert summary["tool_names"] == []


def test_schema_flags_detect_validator_v3_union_type() -> None:
    flags: dict = {}
    LLMClient._collect_json_schema_flags(validator_result_schema_v3(), flags)
    # missing_fact_request uses the "type": ["object", "null"] union form that
    # strict providers are known to reject.
    assert flags["type_union"] == 1
    assert flags["maxLength"] >= 1
    assert flags["maxItems"] >= 1
    assert flags["additionalProperties_false"] >= 1
