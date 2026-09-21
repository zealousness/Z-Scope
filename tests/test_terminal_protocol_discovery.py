"""Schema repair cannot erase a protocol that the current source proves."""

from copy import deepcopy
import json

import pytest

from test_json_output_agents import _snapshot_payload, _semantic_model_input
from test_pool_protocol_modeling import TAKE, proposal
from zscope.agents.semantic_modeler.agent import SemanticModeler
from zscope.agents.semantic_modeler.retry import run_semantic_model_with_retries
from zscope.framework.llm_client import LLMClient
from zscope.semantics.contract_compiler import compile_snapshot
from zscope.semantics.defaults import default_local_pattern_semantics


@pytest.mark.parametrize("supported", [True, False])
def test_real_terminal_repair_retains_only_source_verified_protocol(monkeypatch, supported):
    first = _snapshot_payload()
    first["summary"] = None  # An unrelated malformed field causes schema repair.
    first["interface_contracts"] = [proposal("allocator", "omega")]
    final = _snapshot_payload()
    final["interface_contracts"] = []  # Observed destructive repair behavior.
    payloads = [first, final]
    calls = []
    llm = LLMClient(api_key="test", base_url="http://example.invalid", models=["unit-model"])

    def respond(messages, **kwargs):
        payload = payloads[len(calls)]
        calls.append(deepcopy(messages))
        return {
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {
                                "id": f"emit-{len(calls)}",
                                "type": "function",
                                "function": {
                                    "name": "emit_function_snapshot",
                                    "arguments": json.dumps(payload),
                                },
                            }
                        ],
                    },
                }
            ],
            "model": "unit-model",
            "usage": {"prompt_tokens": 10, "completion_tokens": 10},
        }

    monkeypatch.setattr(llm, "chat_completion", respond)
    code = (
        TAKE
        if supported
        else TAKE.replace("pool->available = node->link", "pool->available = node")
    )
    context = _semantic_model_input(
        func_name="alpha",
        index_name="alpha@pool.c:1-1",
        file_path="pool.c",
        start_line=1,
        end_line=1,
        signature="Node *alpha(Pool *pool)",
        code=code,
    )

    def validate(response, model_context):
        return compile_snapshot(
            response.data,
            model_context,
            default_local_pattern_semantics().contracts,
            terminal_submissions=response.metadata["terminal_submissions"],
        )

    result = run_semantic_model_with_retries(
        lambda: SemanticModeler(llm, []),
        context,
        response_validator=validate,
    )
    assert result.success
    assert len(calls) == 2
    attempts = result.metadata["semantic_model_attempts"]
    assert len(attempts) == 1
    submissions = attempts[0]["terminal_submissions"]
    assert len(submissions) == 2
    assert submissions[0]["validation_errors"]
    assert submissions[-1]["validation_errors"] == []
    published = result.data["interface_contracts"]
    assert bool(published) is supported
    if supported:
        assert published[0]["verification"]["method"] == "source_protocol"
        assert result.data["contract_diagnostics"][-1]["action"] == "source_protocol_recovered"
    else:
        assert result.data["protocol_discovery_audit"][0]["status"] == "unverified"
    assert first["interface_contracts"][0]["confidence"] == 0.8


def test_empty_snapshot_without_protocol_discovery_stays_empty():
    context = _semantic_model_input(
        code=TAKE, func_name="alpha", signature="Node *alpha(Pool *pool)"
    )
    snapshot = {"interface_contracts": []}
    assert not compile_snapshot(snapshot, context, default_local_pattern_semantics().contracts)
    assert snapshot["interface_contracts"] == []


@pytest.mark.parametrize(
    "binding",
    [
        {"kind": "return", "member_path": "->link"},
        {"kind": "return", "address_of": True},
    ],
)
def test_repair_cannot_publish_a_different_object_than_source_returns(binding):
    from zscope.semantics.pool_protocols import verify_pool_contract

    context = _semantic_model_input(
        code=TAKE, func_name="alpha", signature="Node *alpha(Pool *pool)"
    )
    raw = proposal("allocator", "omega")
    raw["carrier"] = binding
    assert verify_pool_contract(raw, context) is None
