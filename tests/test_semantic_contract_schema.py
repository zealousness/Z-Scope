"""The finalizer accepts canonical optional fields but rejects missing bindings."""

import json

import pytest

from test_json_output_agents import _semantic_model_input, _snapshot_payload
from zscope.agents.semantic_modeler.agent import SemanticModeler
from zscope.agents.semantic_modeler.schema import DEFAULT_FUNCTION_SNAPSHOT_SCHEMA
from zscope.agents.semantic_modeler.validation import schema_errors
from zscope.framework.llm_client import LLMClient
from zscope.semantics.contract_compiler import compile_snapshot
from zscope.semantics.contracts import ApiContract
from zscope.semantics.defaults import default_local_pattern_semantics


def contract(protocol=None):
    return {
        "role": "allocator",
        "carrier": {
            "kind": "return",
            "argument_index": None,
            "member_path": "",
            "global_name": "",
            "address_of": False,
        },
        "resource_domain": None,
        "protocol": protocol,
        "preconditions": {"op": "true"},
        "effect_cases": [{"when": {"op": "unknown"}, "effect": "applies"}],
        "pairs": [],
        "confidence": 0.8,
        "evidence": [{"lines": "1", "description": "Returns the allocation."}],
    }


def errors(raw):
    schema = DEFAULT_FUNCTION_SNAPSHOT_SCHEMA
    return schema_errors(raw, schema["properties"]["interface_contracts"]["items"], root=schema)


@pytest.mark.parametrize("protocol", [None, {}])
@pytest.mark.parametrize("envelope", [None, "payload", "function_snapshot"])
def test_nullable_optionals_finalize_once_then_compile_from_source(monkeypatch, protocol, envelope):
    payload = _snapshot_payload()
    payload["interface_contracts"] = [contract(protocol)]
    payload["return_values"]["return_type"] = "void *"
    calls = []
    client = LLMClient(api_key="test", base_url="http://example.invalid", models=["unit-model"])

    def respond(messages, **kwargs):
        calls.append(messages)
        return {
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {
                                "id": "emit",
                                "type": "function",
                                "function": {
                                    "name": "emit_function_snapshot",
                                    "arguments": json.dumps(
                                        {envelope: payload} if envelope else payload
                                    ),
                                },
                            }
                        ],
                    },
                }
            ],
            "model": "unit-model",
            "usage": {"prompt_tokens": 10, "completion_tokens": 10},
        }

    monkeypatch.setattr(client, "chat_completion", respond)
    context = _semantic_model_input(
        signature="void *api_entry(void)",
        code="void *api_entry(void) { return malloc(8); }",
    )
    result = SemanticModeler(client, []).run(context)
    assert result.success, result.error
    assert len(calls) == 1
    assert len(result.metadata["terminal_submissions"]) == 1
    assert result.metadata["terminal_submissions"][-1]["validation_errors"] == []
    assert result.metadata["terminal_invalid_call_count"] == 0
    assert not compile_snapshot(result.data, context, default_local_pattern_semantics().contracts)
    published = ApiContract.from_row({"contract": result.data["interface_contracts"][0]})
    assert published.effects_trusted
    assert published.verification["method"] == "source_composition"


@pytest.mark.parametrize("index", [None, True, -1, "0"])
def test_argument_binding_still_requires_an_actual_index(index):
    raw = contract()
    raw["carrier"] = {"kind": "argument", "argument_index": index}
    assert errors(raw)


def test_missing_argument_index_and_nonempty_untyped_protocol_are_rejected():
    raw = contract()
    raw["carrier"] = {"kind": "output_argument"}
    assert errors(raw)
    for protocol in ({"head_path": "->nodes"}, {"kind": ""}, "intrusive_freelist"):
        assert errors(contract(protocol))


def test_null_index_is_valid_for_global_but_not_for_argument_domain():
    raw = contract()
    raw["carrier"] = {"kind": "global", "global_name": "state", "argument_index": None}
    assert not errors(raw)
    raw["resource_domain"] = {"kind": "argument", "argument_index": None}
    assert errors(raw)
