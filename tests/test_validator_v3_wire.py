"""Gateway-safe wire contract for Validator v3 and JSON repair calls.

Strict OpenAI-compatible gateways in customer environments (e.g. InferHub
serving GLM, error InferHub.001001005.400) answer HTTP 400 unless
``tool_choice`` is ``"auto"`` / ``"none"`` / ``"required"``: the
named-function object form is rejected.  These tests pin the wire shape so
no call site regresses to the object form, and keep the direct v3
``max_tokens`` inside the deployment-configured budget.
"""

from typing import Any, Dict, List

from zscope.agents.base import JsonOutputSpec, JsonToolAgent
from zscope.agents.validator_agent.agent import ValidatorAgent


class _RecordingClient:
    supports_structured_output = False

    def __init__(self, max_tokens: int = 4096):
        self.max_tokens = max_tokens
        self.calls: List[Dict[str, Any]] = []

    def chat_completion(self, messages, **kwargs):
        self.calls.append({"messages": messages, **kwargs})
        return {
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": ""},
                }
            ],
            "model": "unit-model",
            "usage": {},
        }


def _agent(client: _RecordingClient) -> ValidatorAgent:
    return ValidatorAgent(client, [])


class _ConcreteJsonAgent(JsonToolAgent):
    """JsonToolAgent is abstract; only the shared repair helper is exercised."""

    def run(self, input_data, max_retries: int = 2):  # pragma: no cover
        raise NotImplementedError


def test_v3_direct_completion_uses_gateway_safe_tool_choice() -> None:
    client = _RecordingClient(max_tokens=4096)
    agent = _agent(client)
    response, result = agent._direct_v3_completion(
        [{"role": "user", "content": "validate"}],
        trace_label="unit",
        max_tokens=8192,
    )
    kwargs = client.calls[0]
    assert kwargs["tool_choice"] == "required"
    assert kwargs.get("response_format") is None
    assert kwargs["tools"] and (
        kwargs["tools"][0]["function"]["name"] == "emit_validator_result_v3"
    )
    # Clamped to the deployment-configured budget the provider already accepts.
    assert kwargs["max_tokens"] == 4096
    assert response["choices"][0]["finish_reason"] == "stop"
    assert result is not None


def test_v3_direct_completion_keeps_budget_within_client_limit() -> None:
    client = _RecordingClient(max_tokens=16384)
    agent = _agent(client)
    agent._direct_v3_completion(
        [{"role": "user", "content": "validate"}],
        trace_label="unit",
        max_tokens=8192,
    )
    assert client.calls[0]["max_tokens"] == 8192


def test_json_repair_uses_gateway_safe_tool_choice() -> None:
    client = _RecordingClient()
    agent = _ConcreteJsonAgent(
        name="unit_json_agent",
        description="unit",
        llm_client=client,
        tools=[],
    )
    spec = JsonOutputSpec(
        type_name="unit_result",
        schema={"type": "object"},
        final_tool_name="emit_unit_result",
        final_tool_description="emit",
        validator=lambda data: True,
    )
    agent._call_json_repair_completion(
        client.chat_completion,
        [{"role": "user", "content": "repair"}],
        final_tool_schema={
            "type": "function",
            "function": {
                "name": "emit_unit_result",
                "description": "emit",
                "parameters": {"type": "object"},
            },
        },
        json_output_spec=spec,
        trace_label="unit",
        trace_iteration=1,
        force_final_tool=True,
    )
    assert client.calls[0]["tool_choice"] == "required"
