"""The model decides; the runtime binds scope and records the decoded response."""

import json

import pytest

from test_review_experiment_protocol import envelope
from test_validator_v3_protocol import _DirectLLM, _result, _slice
from zscope.agents.validator_agent.agent import ValidatorAgent
from zscope.agents.validator_agent.investigation import InvestigationSession
from zscope.agents.validator_agent import output
from zscope.common.cancellation import CancellationError
from zscope.common.validator_protocol import parse_validator_result_v3, validator_decision_schema_v3


def _decision(**changes):
    full = _result(**changes)
    return {key: full[key] for key in validator_decision_schema_v3()["properties"]}


@pytest.mark.parametrize("stage", ["initial", "evidence_recheck"])
def test_compact_direct_decision_keeps_the_public_result_and_decodes_once(monkeypatch, stage):
    calls = []
    decode = output.decode_validator_json

    def observed(value):
        calls.append(value)
        return decode(value)

    monkeypatch.setattr(output, "decode_validator_json", observed)
    decision = _decision()
    llm = _DirectLLM([{"content": json.dumps(decision)}])
    response = ValidatorAgent(llm, []).run({"evidence_slice": _slice(), "validation_pass": stage})
    assert response.data == _result(**{"pass": stage})
    assert len(calls) == 1
    assert response.metadata["validator_protocol_audit"]["raw_response"] == decision
    assert parse_validator_result_v3(response.data) is not None
    prompt = "\n".join(message["content"] for message in llm.calls[0][0])
    assert "Legacy validation:" not in prompt
    assert "validation_result JSON" not in prompt
    assert "finding_kind" not in prompt
    assert f"Validator {stage}" in prompt


def test_compact_missing_fact_target_comes_from_the_current_obligation():
    decision = _decision(
        verdict="uncertain", missing_fact_request={"fact_kind": "value_range", "reason": "缺上限"}
    )
    evidence = _slice()
    evidence["allowed_missing_fact_kinds"] = ["value_range"]
    evidence["obligation"].update(subject_uid="current-object", function="current_function")
    llm = _DirectLLM([{"content": json.dumps(decision)}])
    response = ValidatorAgent(llm, []).run({"evidence_slice": evidence})
    assert response.data["missing_fact_request"] == {
        "fact_kind": "value_range",
        "reason": "缺上限",
        "subject_uid": "current-object",
        "function_uid": "current_function",
    }
    assert response.data["stop_reason"] == "missing_fact"


def test_old_client_adapter_preserves_terminal_state_and_usage_without_repository_tools():
    messages = [{"role": "user", "content": "current evidence"}]
    message = {"role": "assistant", "content": json.dumps(_decision())}
    legacy = {
        "content": "superseded combined content",
        "message": message,
        "conversation": [*messages, message],
        "finish_reason": "context_window_exceeded",
        "truncated": True,
        "terminal_tool_valid": False,
        "terminal_tool_name": "emit_validator_result_v3",
        "api_call_count": 0,
        "cumulative_prompt_tokens": 31,
        "cumulative_completion_tokens": 7,
    }

    class OldClient:
        def run_conversation_with_tools(self, **kwargs):
            assert kwargs["messages"] == messages
            assert kwargs["trace_label"] == "scope; compatibility_adapter=1"
            assert kwargs["max_iterations"] == 1
            assert kwargs["terminal_tool_required"] is True
            assert [schema["function"]["name"] for schema in kwargs["tools_schema"]] == [
                "emit_validator_result_v3"
            ]
            assert not kwargs["tool_executor"]("read_code", {})["success"]
            assert "max_tokens" not in kwargs and "thinking" not in kwargs
            return legacy

    response, result = ValidatorAgent(OldClient(), [])._direct_v3_completion(
        messages, trace_label="scope", max_tokens=8192, thinking={"type": "disabled"}
    )
    assert result == legacy
    assert response == {
        "choices": [{"finish_reason": "context_window_exceeded", "message": message}],
        "usage": {"prompt_tokens": 31, "completion_tokens": 7},
    }


@pytest.mark.parametrize("direct", [False, True])
@pytest.mark.parametrize("cancelled", [False, True])
def test_both_v3_transports_preserve_cancellation_and_log_only_error_categories(
    direct, cancelled, caplog
):
    marker = "SYNTHETIC_PRIVATE_TRANSPORT_BODY"

    def fail(*args, **kwargs):
        raise CancellationError(marker) if cancelled else RuntimeError(marker)

    class FailedClient:
        run_conversation_with_tools = staticmethod(fail)

    client = FailedClient()
    if direct:
        client.chat_completion = fail
    agent = ValidatorAgent(client, [])
    if cancelled:
        with pytest.raises(CancellationError):
            agent._direct_v3_completion([], trace_label="scope")
    else:
        assert agent._direct_v3_completion([], trace_label="scope") == (None, None)
        assert "RuntimeError" in caplog.text
    assert marker not in caplog.text


def test_repair_decodes_each_response_once_and_keeps_separate_audits(monkeypatch):
    calls = []
    decode = output.decode_validator_json

    def observed(value):
        calls.append(value)
        return decode(value)

    monkeypatch.setattr(output, "decode_validator_json", observed)
    mixed = {**_decision(), "candidate_uid": "WRONG"}
    llm = _DirectLLM([{"content": json.dumps(mixed)}, {"content": json.dumps(_decision())}])
    response = ValidatorAgent(llm, []).run({"evidence_slice": _slice()})
    assert len(calls) == 2
    assert response.data == _result()
    assert response.metadata["validator_first_attempt_audit"]["parsed"] is False
    assert response.metadata["validator_protocol_audit"]["parsed"] is True
    assert response.metadata["validator_first_attempt_audit"]["raw_response"] == mixed
    assert "only repair attempt" in llm.calls[1][0][-1]["content"]


@pytest.mark.parametrize("route", ["legacy", "fast", "v2", "repair"])
def test_only_old_routes_receive_the_legacy_contract(route):
    seen = []

    class LegacyLLM:
        def run_conversation_with_tools(self, **kwargs):
            seen.extend(kwargs["messages"])
            return {
                "content": (
                    "bad" if route == "repair" else '{"verdict":"uncertain","reasoning":"缺少证据"}'
                ),
                "iterations": 1,
            }

        def chat_completion(self, messages, **kwargs):
            seen.extend(messages)
            return {
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {
                            "role": "assistant",
                            "content": '{"type":"validation_result","verdict":"uncertain",'
                            '"reasoning":"缺少证据","blocking_negative_evidence":false}',
                        },
                    }
                ]
            }

    request = {"finding": "example"}
    if route == "fast":
        request["evidence_pack"] = {"source": "demo.c"}
    elif route == "v2":
        request["evidence_slice"] = {"schema_version": "v2"}
    response = ValidatorAgent(LegacyLLM(), []).run(request)
    assert response.success
    assert any("Legacy validation:" in message["content"] for message in seen)
    assert all(
        "Legacy validation:" not in message["content"]
        for message in seen
        if message["role"] == "system"
    )


@pytest.mark.parametrize(
    "failure", [{}, {"finish_reason": "length"}, {"terminal_tool_valid": False}, {"raise": True}]
)
def test_investigation_reuses_handler_decision_but_observes_final_failure(monkeypatch, failure):
    normalized = []
    normalize = output.normalize_validator_provider_payload_v3

    def observed(value):
        normalized.append(value)
        return normalize(value)

    monkeypatch.setattr(output, "normalize_validator_provider_payload_v3", observed)

    class SessionLLM:
        def run_conversation_with_tools(self, **kwargs):
            decision = _decision()
            accepted = kwargs["terminal_tool_handler"](decision)
            assert accepted["valid"]
            if failure.get("raise"):
                raise RuntimeError("after the handler")
            return {
                "content": json.dumps(decision),
                "iterations": 1,
                "terminal_tool_valid": True,
                **failure,
            }

    response = ValidatorAgent(SessionLLM(), []).investigate({"evidence_slice": _slice()})
    assert len(normalized) == 1
    assert response.data["verdict"] == ("uncertain" if failure else "verified")
    assert response.metadata["validator_protocol_audit"]["parsed"] is (not bool(failure))


def test_compatibility_investigation_does_not_trust_claimed_terminal_metadata():
    class CompatibilityLLM:
        def run_conversation_with_tools(self, **kwargs):
            return {
                "content": "not a decision",
                "terminal_tool_valid": True,
                "terminal_tool_payload": _result(**{"pass": "investigation_synthesis"}),
                "iterations": 1,
            }

    response = ValidatorAgent(CompatibilityLLM(), []).investigate({"evidence_slice": _slice()})
    assert response.data["stop_reason"] == "investigation_exhausted"


def test_compact_review_keeps_adjudication_and_the_versioned_public_envelope():
    class ReviewLLM:
        def run_conversation_with_tools(self, **kwargs):
            schema = kwargs["tools_schema"][-1]["function"]["parameters"]
            assert set(schema["required"]) == {"decision", "prior_rejection", "defect_case"}
            full = envelope(refs=["FACT_1"])
            decision = {key: full["decision"][key] for key in _decision()}
            wire = {key: value for key, value in full.items() if key != "schema_version"}
            wire["decision"] = decision
            accepted = kwargs["terminal_tool_handler"](wire)
            assert accepted["valid"]
            return {"content": "", "terminal_tool_valid": True, "iterations": 1}

    evidence = _slice()
    evidence["obligation"].update(candidate_uid="C_1", validation_cluster_uid="V_1")
    response = ValidatorAgent(ReviewLLM(), []).investigate(
        {
            "evidence_slice": evidence,
            "review_protocol_enabled": True,
            "review_rejection_expected": True,
        },
        pass_kind="v2b_adjudication",
    )
    assert response.data["verdict"] == "uncertain"
    assert response.data["stop_reason"] == "unsupported_fact"
    assert (
        response.metadata["review_adjudication"]["schema_version"]
        == "zscope.review-adjudication.v1"
    )
    assert response.metadata["review_adjudication"]["decision"]["candidate_uid"] == "C_1"
    assert response.metadata["validator_protocol_audit"]["raw_verdict"] == "verified"


@pytest.mark.parametrize("mix_catalog_into_witness", [False, True])
def test_review_witness_requires_tool_backing_even_with_valid_catalog_refs(
    mix_catalog_into_witness,
):
    evidence = _slice()
    evidence["obligation"].update(candidate_uid="C_1", validation_cluster_uid="V_1")
    session = InvestigationSession(
        {
            "evidence_slice": evidence,
            "review_protocol_enabled": True,
            "review_rejection_expected": True,
        },
        execute_tool=lambda *_: {"success": True, "data": {"code": "buffer[index] = 0;"}},
        tools_schema=[],
        pass_kind="v2b_adjudication",
    )
    ref = session("read_code", {"file_path": "unit.c"})["evidence_ref"]
    payload = envelope(complete=True, refs=[ref])
    payload["decision"]["evidence_refs"].append("FACT_1")
    if mix_catalog_into_witness:
        payload["defect_case"]["evidence_refs"].append("FACT_1")
    payload["decision"] = {key: payload["decision"][key] for key in _decision()}
    del payload["schema_version"]
    accepted = session.accept_result(payload)
    assert accepted["valid"]
    assert accepted["payload"]["verdict"] == (
        "uncertain" if mix_catalog_into_witness else "verified"
    )
