import json

import pytest

from zscope.framework.llm_client import LLMClient


@pytest.fixture
def client():
    value = LLMClient(api_key="test", base_url="http://example.invalid", models=["unit-model"])
    try:
        yield value
    finally:
        value.close()


def _response(arguments, *, name="lookup", finish_reason="tool_calls"):
    return {
        "choices": [
            {
                "finish_reason": finish_reason,
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {"name": name, "arguments": arguments},
                        }
                    ],
                },
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
    }


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (
            '{query: "literal,} and {kind: null true false", enabled: true,}',
            {"query": "literal,} and {kind: null true false", "enabled": True},
        ),
        (
            "{'query': 'null true false', 'enabled': true}",
            {"query": "null true false", "enabled": True},
        ),
    ],
)
def test_syntax_repairs_preserve_quoted_argument_values(client, raw, expected):
    assert client._parse_tool_args(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "[]",
        "null",
        "42",
        42,
        '{"source":{"query":"x"},"limit":BROKEN}',
        '{"query":"x"',
        '{"file_path":"src/a.c","start_line":line20,"extra":true}',
        '{"confidence":NaN}',
        {"extra": {"confidence": float("inf")}},
    ],
)
def test_invalid_arguments_are_not_reconstructed_or_replaced_by_nested_objects(client, raw):
    with pytest.raises(ValueError):
        client._parse_tool_args(raw)


def test_terminal_tool_restores_strict_optional_nulls_before_validation(client, monkeypatch):
    schema = {
        "type": "function",
        "function": {
            "name": "emit_result",
            "parameters": {
                "type": "object",
                "properties": {"answer": {"type": "string"}, "note": {"type": "string"}},
                "required": ["answer"],
                "additionalProperties": False,
            },
        },
    }
    monkeypatch.setattr(
        client,
        "chat_completion",
        lambda *_args, **_kwargs: _response('{"answer":"done","note":null}', name="emit_result"),
    )
    seen = []

    def handle(payload):
        seen.append(payload)
        return {"valid": payload == {"answer": "done"}, "payload": payload}

    result = client.run_conversation_with_tools(
        messages=[{"role": "user", "content": "start"}],
        tools_schema=[schema],
        tool_executor=lambda *_: pytest.fail("terminal tool dispatched"),
        terminal_tool_name="emit_result",
        terminal_tool_handler=handle,
        terminal_tool_required=True,
        max_iterations=2,
    )

    assert seen == [{"answer": "done"}]
    assert result["terminal_tool_valid"] is True


def test_truncated_tool_call_is_not_executed_or_replayed_to_provider(client, monkeypatch):
    calls = []

    def complete(*_args, **_kwargs):
        calls.append(1)
        return _response('{"query":"unfinished', finish_reason="length")

    monkeypatch.setattr(client, "chat_completion", complete)
    result = client.run_conversation_with_tools(
        messages=[{"role": "user", "content": "start"}],
        tools_schema=[],
        tool_executor=lambda *_: pytest.fail("truncated call executed"),
        max_iterations=5,
    )

    assert len(calls) == 1
    assert result["truncated"] is True
    assert result["finish_reason"] == "length"
    assert result["tool_call_count"] == 0
    assert result["cumulative_total_tokens"] == 15


def test_oversized_context_summary_remains_json_and_preserves_partial_status(client):
    payload = {
        "success": True,
        "status": "partial",
        "coverage": {"level": "partial", "missing": ["native_cfg"]},
        "data": {"code": "x" * 20000, **{f"field_{index}": "x" * 1000 for index in range(18)}},
    }
    rendered = client._compact_tool_result_content(json.dumps(payload), "call_1")
    compacted = json.loads(rendered)

    assert len(rendered) < len(json.dumps(payload))
    assert compacted["tool_call_id"] == "call_1"
    assert compacted["summary"]["status"] == "partial"
    assert compacted["summary"]["coverage"]["level"] == "partial"
    assert compacted["summary"]["coverage"] == payload["coverage"]
    assert compacted["summary"]["data"]["code"]["context_omitted"] is True
    # Unknown metadata must not disappear just to meet an arbitrary summary cap.
    for index in range(18):
        assert compacted["summary"]["data"][f"field_{index}"] == "x" * 1000
    assert payload["data"]["field_0"] == "x" * 1000


def test_compaction_does_not_duplicate_unbounded_provider_tool_id(client):
    rendered = client._compact_tool_result_content(
        json.dumps({"success": True, "code": "x" * 10000}), "call_" + "x" * 10000
    )
    assert len(rendered) < 1800
    assert json.loads(rendered)["tool_call_id_omitted"] is True
