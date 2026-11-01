from __future__ import annotations

import pytest

from zscope.framework.base import validate_function_arguments
from zscope.agents.semantic_modeler.validation import schema_errors
from zscope.framework.llm_client import LLMClient
from zscope.tools.registry import build_tool_registry

TOOL = {
    "type": "function",
    "function": {
        "name": "lookup",
        "description": "Look up one item.",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "mode": {"type": "string", "enum": ["exact", "prefix"]},
            },
            "required": [],
            "additionalProperties": False,
        },
    },
}


class _Response:
    def __init__(self, status_code: int, text: str):
        self.status_code = status_code
        self.text = text

    def close(self) -> None:
        pass


def _client() -> LLMClient:
    return LLMClient(
        api_key="test",
        base_url="http://example.invalid/v1",
        models=["unit-model"],
        max_retries=0,
        supports_structured_output=True,
    )


def test_strict_schema_makes_optional_fields_nullable_and_required() -> None:
    schema = LLMClient._strict_tool_schemas([TOOL])[0]["function"]

    assert schema["strict"] is True
    assert schema["parameters"]["required"] == ["query", "mode"]
    assert schema["parameters"]["properties"]["query"]["type"] == ["string", "null"]
    assert schema["parameters"]["properties"]["mode"]["enum"] == [
        "exact",
        "prefix",
        None,
    ]
    assert schema["parameters"]["additionalProperties"] is False


def test_optional_union_and_const_preserve_original_non_null_constraints():
    tool = {"type": "function", "function": {
        "name": "select", "parameters": {
            "type": "object", "required": [], "additionalProperties": False,
            "properties": {
                "selection": {"anyOf": [{"type": "string"}, {"type": "integer"}]},
                "fixed": {"type": "string", "const": "fixed"},
            },
        },
    }}
    strict = LLMClient._strict_tool_schemas([tool])[0]
    for selection in ("entry", 3, None):
        assert validate_function_arguments(strict, {"selection": selection, "fixed": None}) is None
    for selection in (True, [], {}, 1.5):
        assert validate_function_arguments(strict, {"selection": selection, "fixed": None})
    assert validate_function_arguments(strict, {"selection": None, "fixed": "wrong"})
    assert validate_function_arguments(strict, {"selection": None, "fixed": "fixed"}) is None
    assert LLMClient._restore_portable_tool_args(
        "select", {"selection": None, "fixed": None}, [tool]
    ) == {}
    # Adapting a schema never modifies its portable source.
    assert tool["function"]["parameters"]["required"] == []


@pytest.mark.parametrize("keyword", ["anyOf", "oneOf"])
def test_nested_union_object_is_strict_and_restores_only_artificial_nulls(keyword):
    object_branch = {
        "type": "object", "required": ["kind"], "additionalProperties": False,
        "properties": {
            "kind": {"type": "string", "const": "entry"},
            "note": {"type": "string"},
            "keep": {"type": ["string", "null"]},
        },
    }
    tool = {"type": "function", "function": {
        "name": "select", "parameters": {
            "type": "object", "required": ["choice"], "additionalProperties": False,
            "properties": {"choice": {keyword: [object_branch, {"type": "string"}]}},
        },
    }}
    strict = LLMClient._strict_tool_schemas([tool])[0]
    branch = strict["function"]["parameters"]["properties"]["choice"][keyword][0]
    assert branch["required"] == ["kind", "note", "keep"]
    assert branch["additionalProperties"] is False
    arguments = {"choice": {"kind": "entry", "note": None, "keep": None}}
    assert validate_function_arguments(strict, arguments) is None
    restored = LLMClient._restore_portable_tool_args("select", arguments, [tool])
    assert restored == {"choice": {"kind": "entry", "keep": None}}
    assert validate_function_arguments(tool, restored) is None
    assert validate_function_arguments(strict, {"choice": "entry"}) is None
    assert validate_function_arguments(strict, {"choice": {"kind": "entry"}})
    assert validate_function_arguments(strict, {"choice": {
        "kind": "entry", "note": 7, "keep": None,
    }})


def test_restoration_respects_enum_that_excludes_explicit_null():
    tool = {"type": "function", "function": {
        "name": "select", "parameters": {
            "type": "object", "required": [],
            "properties": {"choice": {"type": ["string", "null"], "enum": ["entry"]}},
        },
    }}
    assert LLMClient._restore_portable_tool_args("select", {"choice": None}, [tool]) == {}


def test_recursive_local_defs_keep_root_scope_during_strict_restoration():
    predicate = {
        "type": "object", "required": ["kind"], "additionalProperties": False,
        "properties": {
            "kind": {"enum": ["and", "atom"]},
            "note": {"type": "string"},
            "items": {"type": "array", "items": {"$ref": "#/$defs/predicate"}},
            "nullable": {"type": ["string", "null"]},
        },
    }
    tool = {"type": "function", "function": {
        "name": "select", "parameters": {
            "type": "object", "required": ["choice"], "additionalProperties": False,
            "$defs": {"predicate": predicate},
            "properties": {"choice": {"anyOf": [
                {"$ref": "#/$defs/predicate"}, {"type": "string"},
            ]}},
        },
    }}
    arguments = {"choice": {
        "kind": "and", "note": None, "nullable": None,
        "items": [{"kind": "atom", "note": None, "items": None, "nullable": None}],
    }}
    strict = LLMClient._strict_tool_schemas([tool])[0]["function"]["parameters"]
    definition = strict["$defs"]["predicate"]
    assert definition["required"] == ["kind", "note", "items", "nullable"]
    assert definition["additionalProperties"] is False
    assert schema_errors(arguments, strict) == []
    restored = LLMClient._restore_portable_tool_args("select", arguments, [tool])
    assert restored == {"choice": {
        "kind": "and", "nullable": None,
        "items": [{"kind": "atom", "nullable": None}],
    }}
    assert schema_errors(restored, tool["function"]["parameters"]) == []
    assert predicate["required"] == ["kind"]


def test_tool_argument_normalization_applies_defaults_only_at_the_root() -> None:
    normalized = LLMClient._normalize_tool_args(
        "trace_data_flow",
        {
            "symbol_id": "zs1:function:111111111111111111111111",
            "source": {"kind": "parameter", "name": "input"},
            "sink": {"kind": "call", "query": "sink"},
        },
    )

    assert normalized["max_call_depth"] == 3
    assert "max_call_depth" not in normalized["source"]
    assert normalized["source"]["file_path"] is None
    assert normalized["sink"]["match_mode"] == "exact"


def test_strict_nullable_required_arguments_restore_portable_optionality() -> None:
    restored = LLMClient._restore_portable_tool_args(
        "lookup",
        {"query": None, "mode": None},
        [TOOL],
    )

    assert restored == {}

    nullable_tool = {
        "type": "function",
        "function": {
            "name": "nullable_lookup",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": ["string", "null"]},
                    "limit": {"type": "integer"},
                },
                "required": [],
                "additionalProperties": False,
            },
        },
    }
    restored_nullable = LLMClient._restore_portable_tool_args(
        "nullable_lookup",
        {"query": None, "limit": None},
        [nullable_tool],
    )
    assert restored_nullable == {"query": None}

    search_tool = build_tool_registry(None, None)["search_code"]
    search_schema = search_tool.get_schema()
    restored_search = LLMClient._restore_portable_tool_args(
        "search_code",
        {
            "query": "parse",
            "kinds": None,
            "match_mode": None,
            "path_prefix": None,
            "limit": None,
            "offset": None,
        },
        [search_schema],
    )
    assert restored_search == {"query": "parse", "path_prefix": None}
    assert search_tool.validate_arguments(restored_search) is None


def test_http_400_strict_schema_rejection_retries_once_with_portable_schema(
    monkeypatch,
) -> None:
    client = _client()
    responses = [
        _Response(400, '{"error":"invalid strict tool schema"}'),
        _Response(200, "ok"),
    ]
    payloads = []

    class _Session:
        def post(self, _url, *, json, timeout, stream):
            del timeout, stream
            payloads.append(json)
            return responses.pop(0)

    monkeypatch.setattr(client, "_session_for_thread", lambda: _Session())
    monkeypatch.setattr(
        client,
        "_assemble_chat_response_with_usage",
        lambda _response: ({"role": "assistant", "content": "done"}, "stop", {}),
    )

    result = client.chat_completion(
        [{"role": "user", "content": "hello"}],
        tools=[TOOL],
    )

    assert result["choices"][0]["message"]["content"] == "done"
    assert len(payloads) == 2
    assert payloads[0]["tools"][0]["function"]["strict"] is True
    assert "strict" not in payloads[1]["tools"][0]["function"]
    assert payloads[1]["tools"] == [TOOL]

    responses.append(_Response(200, "ok"))
    client.chat_completion([{"role": "user", "content": "again"}], tools=[TOOL])
    assert len(payloads) == 3
    assert "strict" not in payloads[2]["tools"][0]["function"]


def test_curl_http_400_strict_schema_rejection_also_falls_back_once(
    monkeypatch,
) -> None:
    client = _client()
    client._transport = "curl"
    payloads = []

    def fake_curl(_url, payload):
        payloads.append(payload)
        if len(payloads) == 1:
            raise RuntimeError("HTTP 400: invalid strict function schema")
        return {"role": "assistant", "content": "done"}, "stop", {}

    monkeypatch.setattr(client, "_curl_chat_completion", fake_curl)

    result = client.chat_completion(
        [{"role": "user", "content": "hello"}],
        tools=[TOOL],
    )

    assert result["choices"][0]["message"]["content"] == "done"
    assert len(payloads) == 2
    assert payloads[0]["tools"][0]["function"]["strict"] is True
    assert payloads[1]["tools"] == [TOOL]
