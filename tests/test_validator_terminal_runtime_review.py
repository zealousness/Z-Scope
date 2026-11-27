"""Exercise strict Validator terminal admission through the real tool loop."""

import json

import pytest

from test_validator_compact_runtime import _decision
from test_validator_v3_protocol import _result, _slice
from zscope.agents.validator_agent import agent as agent_module
from zscope.agents.validator_agent.agent import ValidatorAgent
from zscope.common.cancellation import CancellationError
from zscope.common.validator_protocol import decode_validator_json
from zscope.framework.llm_client import LLMClient


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr("zscope.framework.llm_client.get_conversation_recorder", lambda: None)
    instance = LLMClient("offline-test", "https://example.test/v1", ["offline-model"])
    yield instance
    instance.close()


def terminal_reply(arguments, name="emit_validator_result_v3"):
    return {
        "choices": [
            {
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "id": "terminal-1",
                            "type": "function",
                            "function": {"name": name, "arguments": arguments},
                        }
                    ],
                },
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
    }


@pytest.mark.parametrize("nested", [False, True])
def test_investigation_rejects_duplicate_keys_before_handler(client, monkeypatch, nested):
    decision = _decision()
    evidence = _slice()
    if nested:
        decision.update(
            verdict="uncertain",
            missing_fact_request={"fact_kind": "value_range", "reason": "Need the upper bound"},
        )
        evidence["allowed_missing_fact_kinds"] = ["value_range"]
        raw = json.dumps(decision).replace(
            '"fact_kind": "value_range"',
            '"fact_kind": "cleanup_coverage", "fact_kind": "value_range"',
        )
    else:
        raw = '{"verdict":"rejected",' + json.dumps(decision)[1:]
    monkeypatch.setattr(client, "chat_completion", lambda *a, **k: terminal_reply(raw))
    admissions = []
    accept = agent_module.InvestigationSession.accept_result

    def observed(session, payload):
        admissions.append(payload)
        return accept(session, payload)

    monkeypatch.setattr(agent_module.InvestigationSession, "accept_result", observed)
    response = ValidatorAgent(client, []).investigate(
        {"evidence_slice": evidence}, max_iterations=1
    )
    assert admissions == []
    assert response.data["verdict"] == "uncertain"
    assert response.metadata["validator_protocol_audit"]["parsed"] is False


@pytest.mark.parametrize("historical", [False, True])
def test_investigation_decodes_valid_terminal_once_and_retains_audit(
    client, monkeypatch, historical
):
    payload = _result(**{"pass": "investigation_synthesis"}) if historical else _decision()
    raw = json.dumps(payload)
    decoded = []

    def decode(value):
        decoded.append(value)
        return decode_validator_json(value)

    monkeypatch.setattr(agent_module, "decode_validator_json", decode)
    monkeypatch.setattr(client, "chat_completion", lambda *a, **k: terminal_reply(raw))
    response = ValidatorAgent(client, []).investigate(
        {"evidence_slice": _slice()}, max_iterations=1
    )
    assert decoded == [raw]
    assert response.data["verdict"] == "verified"
    assert response.metadata["validator_protocol_audit"]["raw_response"] == payload


@pytest.mark.parametrize("python_literal", [False, True])
def test_investigation_never_repairs_non_json_terminal_arguments(
    client, monkeypatch, python_literal
):
    raw = repr(_decision()) if python_literal else json.dumps(_decision())[:-1] + ",}"
    monkeypatch.setattr(client, "chat_completion", lambda *a, **k: terminal_reply(raw))
    response = ValidatorAgent(client, []).investigate(
        {"evidence_slice": _slice()}, max_iterations=1
    )
    assert response.data["verdict"] == "uncertain"
    assert response.metadata["validator_protocol_audit"]["parsed"] is False


def test_terminal_decoder_cancellation_reaches_the_caller(client, monkeypatch):
    monkeypatch.setattr(
        client, "chat_completion", lambda *a, **k: terminal_reply(json.dumps(_decision()))
    )

    def cancelled(value):
        raise CancellationError("offline cancellation")

    monkeypatch.setattr(agent_module, "decode_validator_json", cancelled)
    with pytest.raises(CancellationError):
        ValidatorAgent(client, []).investigate({"evidence_slice": _slice()}, max_iterations=1)


@pytest.mark.parametrize("strict", [False, True])
def test_strict_terminal_decoder_preserves_portable_optional_null_restoration(
    client, monkeypatch, strict
):
    arguments = {"result": {"value": "current", "annotation": None}}
    schema = {
        "type": "function",
        "function": {
            "name": "emit_result",
            "parameters": {
                "type": "object",
                "properties": {
                    "result": {
                        "type": "object",
                        "properties": {
                            "value": {"type": "string"},
                            "annotation": {"type": "integer"},
                        },
                        "required": ["value"],
                    }
                },
                "required": ["result"],
            },
        },
    }
    monkeypatch.setattr(
        client,
        "chat_completion",
        lambda *a, **k: terminal_reply(json.dumps(arguments), "emit_result"),
    )
    admitted = []

    def accept(payload):
        admitted.append(payload)
        return {"valid": True, "payload": payload}

    result = client.run_conversation_with_tools(
        messages=[{"role": "user", "content": "Return a result"}],
        tools_schema=[schema],
        tool_executor=lambda *_: pytest.fail("No repository tool should execute"),
        terminal_tool_name="emit_result",
        terminal_tool_handler=accept,
        terminal_tool_json_decoder=decode_validator_json if strict else None,
        max_iterations=1,
    )
    assert admitted == [{"result": {"value": "current"}}]
    assert result["terminal_tool_valid"] is True


def test_other_agents_keep_permissive_terminal_arguments(client, monkeypatch):
    monkeypatch.setattr(
        client,
        "chat_completion",
        lambda *a, **k: terminal_reply("{'verdict': 'first', 'verdict': 'last'}", "emit_other"),
    )
    result = client.run_conversation_with_tools(
        messages=[],
        tools_schema=[],
        tool_executor=lambda *_: pytest.fail("No repository tool should execute"),
        terminal_tool_name="emit_other",
        terminal_tool_handler=lambda payload: {"valid": True, "payload": payload},
        max_iterations=1,
    )
    assert result["terminal_tool_payload"] == {"verdict": "last"}


@pytest.mark.parametrize("structured", [False, True])
def test_failed_legacy_repair_counts_every_dispatched_request(structured):
    class FailedRepairClient:
        supports_structured_output = structured

        def __init__(self):
            self.calls = 0

        def run_conversation_with_tools(self, **kwargs):
            self.calls += 1
            return {"content": "No complete result", "iterations": 1, "api_call_count": 1}

        def chat_completion(self, *args, **kwargs):
            self.calls += 1
            raise RuntimeError("synthetic failed repair")

    llm = FailedRepairClient()
    response = ValidatorAgent(llm, []).run({"finding": {"id": "legacy"}}, max_retries=1)
    assert not response.success
    assert response.metadata["validator_api_call_count"] == llm.calls == (3 if structured else 2)
    assert response.metadata["iterations"] == 1
    assert response.metadata["validator_repair_attempted"] == 1


def test_legacy_repair_preserves_cancellation():
    class CancelledClient:
        def run_conversation_with_tools(self, **kwargs):
            return {"content": "No complete result", "iterations": 1}

        def chat_completion(self, *args, **kwargs):
            raise CancellationError("offline cancellation")

    with pytest.raises(CancellationError):
        ValidatorAgent(CancelledClient(), []).run({"finding": {}}, max_retries=1)


def test_legacy_structured_fallback_counts_requests_without_duplicating_usage():
    class FallbackClient:
        supports_structured_output = True

        def __init__(self):
            self.calls = 0

        def run_conversation_with_tools(self, **kwargs):
            self.calls += 1
            return {
                "content": "No complete result",
                "iterations": 1,
                "api_call_count": 1,
                "cumulative_prompt_tokens": 20,
                "cumulative_completion_tokens": 5,
                "cumulative_total_tokens": 25,
            }

        def chat_completion(self, *args, **kwargs):
            self.calls += 1
            if self.calls == 2:
                raise RuntimeError("synthetic unsupported structured request")
            result = terminal_reply(
                json.dumps(
                    {
                        "type": "validation_result",
                        "verdict": "uncertain",
                        "reasoning": "Missing context",
                        "blocking_negative_evidence": False,
                    }
                ),
                "emit_validation_result",
            )
            result["usage"] = {"prompt_tokens": 30, "completion_tokens": 10}
            return result

    llm = FallbackClient()
    response = ValidatorAgent(llm, []).run({"finding": {"id": "legacy"}}, max_retries=1)
    assert response.success
    assert response.metadata["validator_api_call_count"] == llm.calls == 3
    assert response.metadata["iterations"] == 2
    assert response.metadata["cumulative_prompt_tokens"] == 50
    assert response.metadata["cumulative_completion_tokens"] == 15
    assert response.metadata["cumulative_total_tokens"] == 65


@pytest.mark.parametrize("cancelled", [False, True])
def test_legacy_compatibility_retry_keeps_failure_counts_and_cancellation(cancelled):
    class LegacyClient:
        calls = 0

        def run_conversation_with_tools(self, **kwargs):
            self.calls += 1
            return {"content": "Incomplete result", "iterations": 1, "api_call_count": 1}

        def chat_completion(self, *args, **kwargs):
            self.calls += 1
            if "response_format" in kwargs:
                raise TypeError("synthetic unsupported response argument")
            if cancelled:
                raise CancellationError("offline cancellation")
            raise RuntimeError("synthetic compatibility request failure")

    llm = LegacyClient()
    agent = ValidatorAgent(llm, [])
    if cancelled:
        with pytest.raises(CancellationError):
            agent.run({"finding": {}}, max_retries=1)
    else:
        response = agent.run({"finding": {}}, max_retries=1)
        assert not response.success
        assert response.metadata["validator_api_call_count"] == llm.calls == 3
