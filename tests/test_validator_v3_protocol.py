import json

import pytest

from zscope.agents.proof_engine.agent import ProofEngineAgent
from zscope.common.validator_protocol import (
    DynamicReproductionRequest,
    VALIDATOR_RESULT_VERSION,
    ValidatorResultV3,
    parse_validator_result_v3,
)


def _slice() -> dict:
    return {
        "schema_version": "zscope.validator-evidence-slice.v3",
        "protocol_version": "zscope.validator-protocol.v3",
        "validation_pass": "initial",
        "obligation": {
            "candidate_uid": "CAND_1",
            "validation_cluster_uid": "VAL_1",
            "subject_uid": "wire_len",
            "decision_region_uid": "REGION_1",
        },
        "evidence_ref_catalog": {
            "FACT_1": {"kind": "decision_fact", "summary": "entry reaches sink"}
        },
    }


def _result(**overrides) -> dict:
    result = {
        "schema_version": VALIDATOR_RESULT_VERSION,
        "candidate_uid": "CAND_1",
        "validation_cluster_uid": "VAL_1",
        "pass": "initial",
        "verdict": "verified",
        "reasoning": "FACT_1 supports the requested evidence summary.",
        "positive_evidence": ["entry reaches sink"],
        "negative_evidence": [],
        "evidence_refs": ["FACT_1"],
        "blocking_negative_evidence": False,
        "missing_fact_request": None,
        "stop_reason": "decision_complete",
    }
    result.update(overrides)
    return result


class _DirectLLM:
    models = ["unit-model"]
    supports_structured_output = True

    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    def chat_completion(self, messages, **kwargs):
        self.calls.append((messages, kwargs))
        reply = self.replies.pop(0)
        return {
            "choices": [
                {
                    "finish_reason": reply.get("finish_reason", "stop"),
                    "message": {
                        "role": "assistant",
                        "content": reply.get("content", ""),
                        "reasoning_content": reply.get("reasoning_content"),
                    },
                }
            ],
            "model": "unit-model",
            "usage": {"prompt_tokens": 100, "completion_tokens": 20},
        }


def _input(evidence_slice=None) -> dict:
    return {
        "finding_uid": "CAND_1",
        "validation_cluster_uid": "VAL_1",
        "validation_pass": "initial",
        "evidence_slice": evidence_slice or _slice(),
    }


def test_proof_engine_v3_uses_one_direct_strict_completion() -> None:
    llm = _DirectLLM([{"content": json.dumps(_result())}])
    response = ProofEngineAgent(llm, []).run(_input())

    assert response.success is True
    assert response.data["verdict"] == "verified"
    assert len(llm.calls) == 1
    assert llm.calls[0][1]["max_tokens"] == 8192
    assert llm.calls[0][1]["response_format"]["json_schema"]["strict"] is True
    assert response.metadata["validator_api_call_count"] == 1


def test_proof_engine_rejects_non_v3_and_generic_inputs_without_model_call() -> None:
    llm = _DirectLLM([])
    assert ProofEngineAgent(llm, []).run({"finding": {}}).success is False
    legacy = _slice()
    legacy["protocol_version"] = "zscope.validator-protocol.v2"
    response = ProofEngineAgent(llm, []).run(_input(legacy))
    assert response.success is False
    assert response.error == "proof_engine_rejects_legacy_validator_protocol"
    assert llm.calls == []


def test_proof_engine_v3_failure_has_no_protocol_or_tool_fallback() -> None:
    class FailingLLM(_DirectLLM):
        def chat_completion(self, messages, **kwargs):
            self.calls.append((messages, kwargs))
            raise RuntimeError("provider rejected structured output")

    llm = FailingLLM([])
    response = ProofEngineAgent(llm, []).run(_input())
    assert response.success is False
    assert len(llm.calls) == 1
    assert "response_format" in llm.calls[0][1]
    assert "tools" not in llm.calls[0][1]


@pytest.mark.parametrize(
    ("reply", "stop_reason"),
    [
        ({"content": "not-json"}, "malformed_output"),
        ({"content": "{", "finish_reason": "length"}, "output_truncated"),
        (
            {
                "content": "",
                "reasoning_content": json.dumps(_result()),
            },
            "malformed_output",
        ),
    ],
)
def test_proof_engine_v3_malformed_output_fails_closed_in_one_call(reply, stop_reason) -> None:
    llm = _DirectLLM([reply])
    response = ProofEngineAgent(llm, []).run(_input())
    assert response.success is True
    assert response.data["verdict"] == "uncertain"
    assert response.data["stop_reason"] == stop_reason
    assert len(llm.calls) == 1
    assert response.metadata["validator_repair_attempted"] == 0
    assert response.metadata["validator_length_retry_count"] == 0


def test_proof_engine_synthesis_does_not_count_input_facts_as_new_usage_facts() -> None:
    result = _result(**{"pass": "investigation_synthesis"})
    evidence_slice = _slice()
    evidence_slice["validation_pass"] = "investigation_synthesis"
    evidence_slice["evidence_delta"] = {
        "facts": [{"fact_uid": f"FACT_{index}"} for index in range(6)]
    }
    llm = _DirectLLM([{"content": json.dumps(result)}])
    payload = _input(evidence_slice)
    payload["validation_pass"] = "investigation_synthesis"
    response = ProofEngineAgent(llm, []).run(payload)
    assert response.success is True
    assert "new_fact_count=0" in llm.calls[0][1]["trace_label"]


def test_proof_engine_action_session_exposes_only_action_id_and_stops_on_closure() -> None:
    action_id = "ACTION_1"
    fact = {"fact_uid": "FACT_PROVED", "fact_kind": "source_sink_reachability"}
    calls = []

    class ActionLLM:
        models = ["unit-model"]

        def run_conversation_with_tools(self, **kwargs):
            exposed = {value["function"]["name"] for value in kwargs["tools_schema"]}
            assert exposed == {"execute_proof_evidence_action", "emit_validator_result_v3"}
            action_schema = next(
                value["function"]["parameters"]
                for value in kwargs["tools_schema"]
                if value["function"]["name"] == "execute_proof_evidence_action"
            )
            assert set(action_schema["properties"]) == {"action_id"}
            calls.append(
                kwargs["tool_executor"]("execute_proof_evidence_action", {"action_id": action_id})
            )
            programmatic = kwargs["tool_executor"]._zscope_programmatic_terminal_payload()
            assert programmatic["verdict"] == "verified"
            return {
                "terminal_tool_payload": programmatic,
                "terminal_tool_valid": True,
                "conversation": [],
                "iterations": 1,
                "tool_call_count": 1,
            }

    def execute(selected):
        assert selected == action_id
        return {
            "status": "verified_true",
            "reason_code": "checker_accepted",
            "verified_fact": fact,
            "terminal_authority": {"terminal": True, "disposition": "confirmed"},
        }

    response = ProofEngineAgent(ActionLLM(), []).investigate(
        {**_input(), "validation_pass": "investigation_synthesis"},
        evidence_actions=[{"action_id": action_id, "predicate": "system-bound"}],
        evidence_action_executor=execute,
    )
    assert response.success is True
    assert response.data["verdict"] == "verified"
    assert response.data["evidence_refs"] == ["FACT_PROVED"]
    assert response.metadata["new_fact_count"] == 1
    assert len(calls) == 1


def test_proof_engine_action_session_rejects_missing_duplicate_and_free_parameters() -> None:
    agent = ProofEngineAgent(object(), [])
    missing = agent.investigate(
        _input(), evidence_actions=[], evidence_action_executor=lambda _: {}
    )
    assert missing.success is False

    class InvalidSelectionLLM:
        models = ["unit-model"]

        def __init__(self):
            self.results = []

        def run_conversation_with_tools(self, **kwargs):
            execute = kwargs["tool_executor"]
            self.results.extend(
                [
                    execute("execute_proof_evidence_action", {"action_id": "ACTION_1", "x": 1}),
                    execute("execute_proof_evidence_action", {"action_id": "UNKNOWN"}),
                    execute("execute_proof_evidence_action", {"action_id": "ACTION_1"}),
                    execute("execute_proof_evidence_action", {"action_id": "ACTION_1"}),
                ]
            )
            uncertain = _result(
                **{
                    "pass": "investigation_synthesis",
                    "verdict": "uncertain",
                    "evidence_refs": [],
                    "stop_reason": "investigation_exhausted",
                }
            )
            return {
                "terminal_tool_payload": uncertain,
                "terminal_tool_valid": True,
                "conversation": [],
                "iterations": 1,
                "tool_call_count": 4,
            }

    llm = InvalidSelectionLLM()
    response = ProofEngineAgent(llm, []).investigate(
        {**_input(), "validation_pass": "investigation_synthesis"},
        evidence_actions=[{"action_id": "ACTION_1"}],
        evidence_action_executor=lambda _: {"status": "unknown"},
    )
    assert response.success is True
    assert llm.results[0]["error"] == "evidence_action_id_only"
    assert llm.results[1]["error"] == "unknown_evidence_action"
    assert llm.results[2]["success"] is True
    assert llm.results[3]["error"] == "duplicate_evidence_action"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("candidate_uid", 7),
        ("validation_cluster_uid", True),
        ("pass", ["initial"]),
        ("verdict", {"value": "verified"}),
        ("reasoning", 123),
        ("stop_reason", False),
        ("blocking_negative_evidence", 1),
    ],
)
def test_validator_result_v3_rejects_scalar_type_coercion(field, value) -> None:
    assert parse_validator_result_v3(_result(**{field: value})) is None


def test_validator_result_v3_rejects_extra_fields_unknown_refs_and_oversize() -> None:
    assert parse_validator_result_v3(_result(extra="not allowed")) is None
    assert (
        parse_validator_result_v3(
            _result(evidence_refs=["FACT_UNKNOWN"]),
            allowed_evidence_refs=["FACT_1"],
        )
        is None
    )
    assert parse_validator_result_v3(_result(reasoning="r" * 4001)) is None


def test_validator_v3_runtime_dataclass_self_validates() -> None:
    with pytest.raises(ValueError, match="reasoning"):
        ValidatorResultV3(
            candidate_uid="CAND_1",
            validation_cluster_uid="VAL_1",
            validation_pass="initial",
            verdict="uncertain",
            reasoning="x" * 4001,
            positive_evidence=(),
            negative_evidence=(),
            evidence_refs=(),
            blocking_negative_evidence=False,
            missing_fact_request=None,
            stop_reason="malformed_output",
        )


def test_dynamic_reproduction_v4_contract_is_reserved_but_not_dispatched() -> None:
    request = DynamicReproductionRequest(
        request_id="REPRO_1",
        candidate_uid="CAND_1",
        validation_cluster_uid="VAL_1",
        reproduction_kind="asan",
        target="unit_test_target",
        evidence_refs=("FACT_1",),
        timeout_seconds=30,
        memory_limit_mb=512,
    )
    assert request.to_dict()["decision_level"] == "V4"
    assert request.to_dict()["dispatch_status"] == "reserved_not_implemented"
