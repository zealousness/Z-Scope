import json

import pytest

from zscope.agents.proof_engine.agent import ProofEngineAgent
from zscope.common.validator_protocol import (
    DynamicReproductionRequest,
    VALIDATOR_RESULT_VERSION,
    ValidatorResultV3,
    parse_validator_result_v3,
    validator_result_schema_v3,
    validator_result_v3_failure_class,
)
from zscope.framework.llm_client import ProviderFailureError
from zscope.framework.llm_usage import (
    P6BalancedTokenAdmissionError,
    ScanTokenUsageLedger,
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


def _p6_ledger() -> ScanTokenUsageLedger:
    ledger = ScanTokenUsageLedger(depth="balanced")
    ledger.enable_p6_balanced_admission()
    return ledger


def test_validator_v3_provider_schema_encodes_missing_fact_coherence() -> None:
    schema = validator_result_schema_v3()

    assert schema["allOf"][0]["then"]["properties"] == {
        "verdict": {"const": "uncertain"},
        "stop_reason": {"const": "missing_fact"},
    }
    assert "missing_fact" not in schema["allOf"][1]["then"]["properties"]["stop_reason"]["enum"]


def test_validator_v3_provider_schema_binds_runtime_identities_and_refs() -> None:
    schema = validator_result_schema_v3(
        candidate_uid="CAND_1",
        validation_cluster_uid="VAL_1",
        expected_pass="initial",
        allowed_evidence_refs=["FACT_2", "FACT_1", "FACT_1"],
    )

    assert schema["properties"]["candidate_uid"]["const"] == "CAND_1"
    assert schema["properties"]["validation_cluster_uid"]["const"] == "VAL_1"
    assert schema["properties"]["pass"]["const"] == "initial"
    assert schema["properties"]["evidence_refs"]["items"]["enum"] == [
        "FACT_1",
        "FACT_2",
    ]
    empty = validator_result_schema_v3(allowed_evidence_refs=[])
    assert empty["properties"]["evidence_refs"]["maxItems"] == 0


def test_validator_v3_fixed_failure_classifier_never_echoes_values() -> None:
    canary = "SECRET_CANARY_MUST_NOT_LEAK"
    failure = validator_result_v3_failure_class(
        _result(candidate_uid=canary),
        candidate_uid="CAND_1",
        validation_cluster_uid="VAL_1",
        expected_pass="initial",
        allowed_evidence_refs=["FACT_1"],
    )

    assert failure == "candidate_binding_mismatch"
    assert canary not in failure
    assert (
        validator_result_v3_failure_class(
            _result(evidence_refs=[canary]),
            candidate_uid="CAND_1",
            validation_cluster_uid="VAL_1",
            expected_pass="initial",
            allowed_evidence_refs=["FACT_1"],
        )
        == "evidence_ref_binding_mismatch"
    )


def test_proof_engine_v3_uses_one_direct_strict_completion() -> None:
    llm = _DirectLLM([{"content": json.dumps(_result())}])
    response = ProofEngineAgent(llm, []).run(_input())

    assert response.success is True
    assert response.data["verdict"] == "verified"
    assert len(llm.calls) == 1
    assert llm.calls[0][1]["max_tokens"] == 8192
    assert llm.calls[0][1]["response_format"]["json_schema"]["strict"] is True
    bound = llm.calls[0][1]["response_format"]["json_schema"]["schema"]["properties"]
    assert bound["candidate_uid"]["const"] == "CAND_1"
    assert bound["validation_cluster_uid"]["const"] == "VAL_1"
    assert bound["pass"]["const"] == "initial"
    assert bound["evidence_refs"]["items"]["enum"] == ["FACT_1"]
    assert response.metadata["validator_api_call_count"] == 1
    prompt = llm.calls[0][0][-1]["content"]
    assert "missing_fact_request is an object" in prompt
    assert "verdict must be uncertain" in prompt
    assert "stop_reason must be missing_fact" in prompt


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


def test_proof_engine_propagates_typed_systemic_provider_failure() -> None:
    class FailingProvider(_DirectLLM):
        def chat_completion(self, messages, **kwargs):
            self.calls.append((messages, kwargs))
            raise ProviderFailureError("provider_protocol_incompatible")

    llm = FailingProvider([])

    with pytest.raises(ProviderFailureError) as raised:
        ProofEngineAgent(llm, []).run(_input())

    assert raised.value.failure_class == "provider_protocol_incompatible"
    assert len(llm.calls) == 1


def test_proof_engine_propagates_p6_token_admission_from_direct_completion() -> None:
    class DeniedLLM(_DirectLLM):
        def chat_completion(self, messages, **kwargs):
            self.calls.append((messages, kwargs))
            raise P6BalancedTokenAdmissionError("p6_token_hard_limit")

    llm = DeniedLLM([])

    with pytest.raises(P6BalancedTokenAdmissionError) as raised:
        ProofEngineAgent(llm, []).run(_input())

    assert raised.value.failure_class == "p6_token_hard_limit"
    assert len(llm.calls) == 1


def test_proof_engine_propagates_p6_token_admission_from_action_session() -> None:
    class DeniedActionLLM:
        models = ["unit-model"]

        @staticmethod
        def run_conversation_with_tools(**_kwargs):
            raise P6BalancedTokenAdmissionError("p6_token_hard_limit")

    with pytest.raises(P6BalancedTokenAdmissionError) as raised:
        ProofEngineAgent(DeniedActionLLM(), []).investigate(
            {**_input(), "validation_pass": "investigation_synthesis"},
            evidence_actions=[{"action_id": "ACTION_1"}],
            evidence_action_executor=lambda _action_id: {"status": "unknown"},
        )

    assert raised.value.failure_class == "p6_token_hard_limit"


def test_proof_engine_does_not_convert_action_admission_to_unknown_evidence() -> None:
    class ExecutesActionLLM:
        models = ["unit-model"]

        @staticmethod
        def run_conversation_with_tools(**kwargs):
            return kwargs["tool_executor"](
                "execute_proof_evidence_action",
                {"action_id": "ACTION_1"},
            )

    def deny(_action_id):
        raise P6BalancedTokenAdmissionError("p6_token_hard_limit")

    with pytest.raises(P6BalancedTokenAdmissionError) as raised:
        ProofEngineAgent(ExecutesActionLLM(), []).investigate(
            {**_input(), "validation_pass": "investigation_synthesis"},
            evidence_actions=[{"action_id": "ACTION_1"}],
            evidence_action_executor=deny,
        )

    assert raised.value.failure_class == "p6_token_hard_limit"


def test_proof_engine_sanitizes_p6_direct_completion_failure(caplog) -> None:
    canary = "PRIVATE_DIRECT_EXCEPTION_BODY_MUST_NOT_LEAK"

    class FailingLLM(_DirectLLM):
        def chat_completion(self, messages, **kwargs):
            self.calls.append((messages, kwargs))
            raise RuntimeError(canary)

    llm = FailingLLM([])
    llm.token_usage_ledger = _p6_ledger()
    response = ProofEngineAgent(llm, []).run(_input())

    assert response.success is False
    assert response.error == "class=internal_failure; count=1"
    assert response.metadata["failure_class"] == "internal_failure"
    assert response.metadata["failure_count"] == 1
    assert canary not in caplog.text
    assert "class=internal_failure; count=1" in caplog.text


def test_proof_engine_sanitizes_p6_action_session_failure(caplog) -> None:
    canary = "PRIVATE_SESSION_EXCEPTION_BODY_MUST_NOT_LEAK"

    class FailingActionLLM:
        models = ["unit-model"]
        token_usage_ledger = _p6_ledger()

        @staticmethod
        def run_conversation_with_tools(**_kwargs):
            raise RuntimeError(canary)

    response = ProofEngineAgent(FailingActionLLM(), []).investigate(
        {**_input(), "validation_pass": "investigation_synthesis"},
        evidence_actions=[{"action_id": "ACTION_1"}],
        evidence_action_executor=lambda _action_id: {"status": "unknown"},
    )

    assert response.success is False
    assert response.error == "class=internal_failure; count=1"
    assert response.metadata["failure_class"] == "internal_failure"
    assert response.metadata["failure_count"] == 1
    assert canary not in caplog.text
    assert "class=internal_failure; count=1" in caplog.text


def test_proof_engine_sanitizes_p6_evidence_action_failure() -> None:
    canary = "PRIVATE_ACTION_EXCEPTION_BODY_MUST_NOT_LEAK"

    class ExecutesFailingActionLLM:
        models = ["unit-model"]
        token_usage_ledger = _p6_ledger()

        def __init__(self):
            self.outcome = None

        def run_conversation_with_tools(self, **kwargs):
            self.outcome = kwargs["tool_executor"](
                "execute_proof_evidence_action",
                {"action_id": "ACTION_1"},
            )
            return {
                "terminal_tool_payload": _result(
                    **{
                        "pass": "investigation_synthesis",
                        "verdict": "uncertain",
                        "evidence_refs": [],
                        "stop_reason": "investigation_exhausted",
                    }
                ),
                "terminal_tool_valid": True,
                "conversation": [],
                "iterations": 1,
                "tool_call_count": 1,
            }

    def fail(_action_id):
        raise RuntimeError(canary)

    llm = ExecutesFailingActionLLM()
    response = ProofEngineAgent(llm, []).investigate(
        {**_input(), "validation_pass": "investigation_synthesis"},
        evidence_actions=[{"action_id": "ACTION_1"}],
        evidence_action_executor=fail,
    )

    assert response.success is True
    assert llm.outcome["status"] == "unknown"
    assert llm.outcome["reason_code"] == "evidence_action_executor_error"
    assert llm.outcome["failure_class"] == "internal_failure"
    assert llm.outcome["failure_count"] == 1
    assert canary not in json.dumps(llm.outcome)
    assert canary not in json.dumps(response.metadata)


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
def test_proof_engine_v3_malformed_output_has_one_bounded_regeneration(reply, stop_reason) -> None:
    expected_calls = 1 if stop_reason == "output_truncated" else 2
    llm = _DirectLLM([reply] * expected_calls)
    response = ProofEngineAgent(llm, []).run(_input())
    assert response.success is True
    assert response.data["verdict"] == "uncertain"
    assert response.data["stop_reason"] == stop_reason
    assert len(llm.calls) == expected_calls
    assert response.metadata["validator_repair_attempted"] == (expected_calls - 1)
    assert response.metadata["validator_length_retry_count"] == 0
    assert response.metadata["validator_contract_failure_count"] == 1
    assert response.metadata["validator_contract_failure_class"] in {
        "payload_not_object",
        "structured_payload_missing",
        "multiple_required_fields_missing",
        "additional_field_present",
        "multiple_required_fields_missing_with_additional",
    }


def test_proof_engine_v3_accepts_one_answer_free_contract_regeneration() -> None:
    llm = _DirectLLM(
        [
            {"content": json.dumps({"error": "shape"})},
            {"content": json.dumps(_result())},
        ]
    )

    response = ProofEngineAgent(llm, []).run(_input())

    assert response.success is True
    assert response.data["verdict"] == "verified"
    assert response.metadata["validator_repair_attempted"] == 1
    assert response.metadata["validator_repair_accepted"] == 1
    assert response.metadata["validator_api_call_count"] == 2
    assert response.metadata["cumulative_prompt_tokens"] == 200
    assert len(llm.calls) == 2
    repair_prompt = llm.calls[1][0][-1]["content"]
    assert "class=multiple_required_fields_missing_with_additional" in repair_prompt
    assert "Do not repeat or discuss the prior response" in repair_prompt
    assert "shape" not in repair_prompt


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
