import json

import pytest

from zscope.agents.validator_agent.agent import ValidatorAgent
from zscope.common.validator_protocol import (
    DynamicReproductionRequest,
    VALIDATOR_RESULT_VERSION,
    ValidatorResultV3,
    parse_validator_result_v3,
)
from zscope.framework.base import BaseTool
from zscope.core.validation.claim_verifier import EvidenceClaimRequest, EvidenceClaimVerifier


def _slice() -> dict:
    return {
        "schema_version": "zscope.validator-evidence-slice.v3",
        "protocol_version": "zscope.validator-protocol.v3",
        "validation_pass": "initial",
        "obligation": {
            "candidate_uid": "CAND_1",
            "validation_cluster_uid": "VAL_1",
            "subject_uid": "wire_len",
            "decision_region_uid": "",
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
        "reasoning": "FACT_1 proves the concrete trigger path.",
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
                    },
                }
            ],
            "model": "unit-model",
            "usage": {"prompt_tokens": 100, "completion_tokens": 20},
        }


class _FailingStructuredLLM(_DirectLLM):
    def __init__(self) -> None:
        super().__init__([])

    def chat_completion(self, messages, **kwargs):
        self.calls.append((messages, kwargs))
        raise RuntimeError("provider rejected the declared response format")


class _ReasoningOnlyLLM(_DirectLLM):
    def chat_completion(self, messages, **kwargs):
        self.calls.append((messages, kwargs))
        return {
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "reasoning_content": json.dumps(_result()),
                    },
                }
            ],
            "model": "unit-model",
            "usage": {"prompt_tokens": 100, "completion_tokens": 20},
        }


class _ReadOnlyEvidenceTool(BaseTool):
    def __init__(self) -> None:
        super().__init__("get_data_flow", "Read one immutable validation fact")

    def execute(self, arguments):
        query = str(arguments.get("query") or "")
        if query.startswith("empty"):
            return {"success": True, "data": {}}
        return {
            "success": True,
            "data": {
                "file_path": "src/demo.c",
                "function": "sink",
                "start_line": 10 if query == "path" else 20,
                "statement": (
                    "entry reaches sink" if query == "path" else "len may exceed capacity"
                ),
                "value_range_proved": True,
                "analysis_complete": True,
            },
        }

    def get_schema(self):
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {"query": {"type": "string"}},
                    "required": ["query"],
                },
            },
        }


class _InvestigationLLM:
    models = ["unit-model"]

    def __init__(self, *, no_gain=False, unrecorded_gain=False) -> None:
        self.no_gain = no_gain
        self.unrecorded_gain = unrecorded_gain
        self.calls = []
        self.executor_results = []

    def run_conversation_with_tools(self, **kwargs):
        self.calls.append(kwargs)
        executor = kwargs["tool_executor"]
        if self.no_gain or self.unrecorded_gain:
            assert executor._zscope_start_iteration(1) is False
            first_query = "path" if self.unrecorded_gain else "empty-one"
            second_query = "bound" if self.unrecorded_gain else "empty-two"
            first = executor("get_data_flow", {"query": first_query})
            duplicate = executor("get_data_flow", {"query": first_query})
            same_round = executor("get_data_flow", {"query": "empty-same-round"})
            assert executor._zscope_start_iteration(2) is False
            second = executor("get_data_flow", {"query": second_query})
            assert executor._zscope_start_iteration(3) is False
            assert executor._zscope_start_iteration(4) is False
            assert executor._zscope_start_iteration(5) is False
            assert executor._zscope_start_iteration(6) is True
            stopped = executor("get_data_flow", {"query": "after-stop"})
            self.executor_results = [first, same_round, second, duplicate, stopped]
            payload = _result(
                verdict="uncertain",
                reasoning="read-only providers added no new evidence",
                evidence_refs=[],
                stop_reason="investigation_exhausted",
            )
            payload["pass"] = "investigation_synthesis"
            iterations = 4
            tool_calls = 4
        else:
            assert executor._zscope_start_iteration(1) is False
            path = executor("get_data_flow", {"query": "path"})
            path_fact = executor(
                "submit_validator_evidence_claim",
                {
                    "fact_kind": "value_range",
                    "predicate": "value_range_is_proved",
                    "polarity": "supports",
                    "subject_uid": "wire_len",
                    "decision_region_uid": "",
                    "arguments": {"query": "path"},
                    "cited_evidence_refs": [
                        path["evidence_ref"],
                        "evidence:positive:0",
                    ],
                },
            )
            assert executor._zscope_start_iteration(2) is False
            bound = executor("get_data_flow", {"query": "bound"})
            fact = executor(
                "submit_validator_evidence_claim",
                {
                    "fact_kind": "value_range",
                    "predicate": "value_range_is_proved",
                    "polarity": "supports",
                    "subject_uid": "wire_len",
                    "decision_region_uid": "",
                    "arguments": {"query": "bound"},
                    "cited_evidence_refs": [bound["evidence_ref"]],
                },
            )
            assert executor._zscope_start_iteration(3) is False
            assert executor._zscope_start_iteration(4) is False
            self.executor_results = [path, path_fact, bound, fact]
            fact_uid = fact["verified_fact"]["fact_uid"]
            payload = _result(
                evidence_refs=[fact_uid],
                stop_reason="investigation_complete",
            )
            payload["pass"] = "investigation_synthesis"
            iterations = 4
            tool_calls = 4
        message = {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "id": "terminal",
                    "type": "function",
                    "function": {
                        "name": "emit_validator_result_v3",
                        "arguments": json.dumps(payload),
                    },
                }
            ],
        }
        return {
            "content": "",
            "message": message,
            "conversation": [message],
            "iterations": iterations,
            "tool_call_count": tool_calls,
            "cumulative_prompt_tokens": 400,
            "cumulative_completion_tokens": 100,
            "cumulative_total_tokens": 500,
        }


def _verify_test_claim(raw_claim, tool_catalog):
    claim = EvidenceClaimRequest.from_mapping(
        raw_claim,
        default_obligation_uid="CAND_1",
    )
    return (
        EvidenceClaimVerifier()
        .verify(
            claim,
            issue={"candidate_uid": "CAND_1"},
            tool_catalog=tool_catalog,
        )
        .to_dict()
    )


def test_validator_v3_uses_one_direct_strict_completion() -> None:
    llm = _DirectLLM([{"content": json.dumps(_result())}])
    agent = ValidatorAgent(llm, [])

    response = agent.run(
        {
            "finding_uid": "CAND_1",
            "validation_cluster_uid": "VAL_1",
            "validation_pass": "initial",
            "evidence_slice": _slice(),
        }
    )

    assert response.success
    assert response.data["verdict"] == "verified"
    assert len(llm.calls) == 1
    assert llm.calls[0][1]["max_tokens"] == 8192
    assert llm.calls[0][1]["response_format"]["json_schema"]["strict"] is True
    assert response.metadata["validator_api_call_count"] == 1


def test_v3_synthesis_does_not_count_input_facts_as_new_usage_facts() -> None:
    result = _result(**{"pass": "investigation_synthesis"})
    llm = _DirectLLM([{"content": json.dumps(result)}])
    evidence_slice = _slice()
    evidence_slice["validation_pass"] = "investigation_synthesis"
    evidence_slice["evidence_delta"] = {
        "facts": [
            {"fact_uid": f"FACT_INPUT_{index}", "fact_kind": "value_range"}
            for index in range(6)
        ]
    }

    response = ValidatorAgent(llm, []).run(
        {
            "finding_uid": "CAND_1",
            "validation_cluster_uid": "VAL_1",
            "validation_pass": "investigation_synthesis",
            "evidence_slice": evidence_slice,
        }
    )

    assert response.success is True
    trace_label = llm.calls[0][1]["trace_label"]
    assert "new_fact_count=0" in trace_label
    assert "new_fact_count=6" not in trace_label


def test_validator_v3_does_not_add_tool_fallback_after_structured_call_failure() -> None:
    llm = _FailingStructuredLLM()

    response = ValidatorAgent(llm, []).run(
        {
            "finding_uid": "CAND_1",
            "validation_cluster_uid": "VAL_1",
            "validation_pass": "initial",
            "evidence_slice": _slice(),
        }
    )

    assert response.success is False
    assert len(llm.calls) == 1
    assert "response_format" in llm.calls[0][1]
    assert "tools" not in llm.calls[0][1]


def test_validator_v3_never_accepts_reasoning_metadata_as_terminal_output() -> None:
    llm = _ReasoningOnlyLLM([])

    response = ValidatorAgent(llm, []).run(
        {
            "finding_uid": "CAND_1",
            "validation_cluster_uid": "VAL_1",
            "validation_pass": "initial",
            "evidence_slice": _slice(),
        }
    )

    assert response.success is True
    assert response.data["verdict"] == "uncertain"
    assert response.data["stop_reason"] == "malformed_output"
    assert len(llm.calls) == 1
    assert response.metadata["validator_repair_attempted"] == 0


def test_validator_v3_malformed_output_stays_single_call_for_v3_escalation() -> None:
    llm = _DirectLLM([{"content": "not-json"}])
    response = ValidatorAgent(llm, []).run(
        {
            "finding_uid": "CAND_1",
            "validation_cluster_uid": "VAL_1",
            "evidence_slice": _slice(),
        }
    )

    assert response.success
    assert response.data["verdict"] == "uncertain"
    assert response.data["stop_reason"] == "malformed_output"
    assert len(llm.calls) == 1
    assert response.metadata["validator_repair_attempted"] == 0


def test_validator_v3_length_stays_single_call_for_v3_escalation() -> None:
    llm = _DirectLLM([{"content": "{", "finish_reason": "length"}])
    response = ValidatorAgent(llm, []).run(
        {
            "finding_uid": "CAND_1",
            "validation_cluster_uid": "VAL_1",
            "evidence_slice": _slice(),
        }
    )

    assert response.success
    assert response.data["verdict"] == "uncertain"
    assert response.data["stop_reason"] == "output_truncated"
    assert len(llm.calls) == 1
    assert llm.calls[0][1]["max_tokens"] == 8192
    assert response.metadata["validator_length_retry_count"] == 0


def test_validator_v3_rejects_extra_fields_and_unknown_evidence_refs() -> None:
    with_extra = _result(extra="not allowed")
    unknown_ref = _result(evidence_refs=["FACT_UNKNOWN"])

    assert parse_validator_result_v3(with_extra) is None
    assert (
        parse_validator_result_v3(
            unknown_ref,
            candidate_uid="CAND_1",
            validation_cluster_uid="VAL_1",
            expected_pass="initial",
            allowed_evidence_refs=["FACT_1"],
        )
        is None
    )


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
def test_validator_v3_rejects_scalar_type_coercion(field, value) -> None:
    assert parse_validator_result_v3(_result(**{field: value})) is None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("reasoning", "r" * 4001),
        ("positive_evidence", ["p" * 1001]),
        ("negative_evidence", ["n" * 1001]),
        ("evidence_refs", ["E" * 513]),
    ],
)
def test_validator_v3_enforces_schema_string_lengths(field, value) -> None:
    assert parse_validator_result_v3(_result(**{field: value})) is None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("fact_kind", 1),
        ("subject_uid", "S" * 513),
        ("function_uid", "F" * 513),
        ("reason", "R" * 1001),
    ],
)
def test_validator_v3_enforces_missing_fact_request_types_and_lengths(field, value) -> None:
    request = {
        "fact_kind": "value_range",
        "subject_uid": "length",
        "function_uid": "sink",
        "reason": "need the exact range",
    }
    request[field] = value

    assert (
        parse_validator_result_v3(
            _result(
                verdict="uncertain",
                missing_fact_request=request,
                stop_reason="missing_fact",
            )
        )
        is None
    )


def test_validator_v3_missing_fact_stop_requires_request() -> None:
    assert (
        parse_validator_result_v3(
            _result(verdict="uncertain", missing_fact_request=None, stop_reason="missing_fact")
        )
        is None
    )


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


def test_validator_v3_investigation_uses_one_50_turn_session_and_records_tool_facts() -> None:
    llm = _InvestigationLLM()
    evidence_slice = _slice()
    evidence_slice["decision_facts"] = {"missing_fact_kinds": ["value_range"]}

    response = ValidatorAgent(llm, [_ReadOnlyEvidenceTool()]).investigate(
        {
            "finding_uid": "CAND_1",
            "validation_cluster_uid": "VAL_1",
            "validation_pass": "investigation_synthesis",
            "evidence_slice": evidence_slice,
        },
        max_iterations=50,
        claim_verifier=_verify_test_claim,
    )

    assert response.success is True
    assert response.data["pass"] == "investigation_synthesis"
    assert response.data["verdict"] == "verified"
    assert len(llm.calls) == 1
    assert llm.calls[0]["max_iterations"] == 50
    assert llm.calls[0]["max_identical_tool_calls"] == 1
    assert llm.calls[0]["replay_identical_tool_result"] is False
    assert llm.calls[0]["preserve_reasoning_metadata"] is True
    claim_schema = next(
        item["function"]["parameters"]
        for item in llm.calls[0]["tools_schema"]
        if item["function"]["name"] == "submit_validator_evidence_claim"
    )
    assert claim_schema["properties"]["subject_uid"]["enum"] == ["wire_len"]
    assert claim_schema["properties"]["decision_region_uid"]["enum"] == [""]
    exposed_tools = {item["function"]["name"] for item in llm.calls[0]["tools_schema"]}
    assert "get_data_flow" in exposed_tools
    assert "get_function_snapshot" not in exposed_tools
    assert len(response.metadata["validator_tool_fact_catalog"]) == 2
    assert len(response.metadata["validator_investigation_facts"]) == 2
    recorded = response.metadata["validator_investigation_facts"][-1]
    assert recorded["fact_kind"] == "value_range"
    assert recorded["fact_uid"] in response.data["evidence_refs"]
    assert len(recorded["evidence_refs"]) == 1
    assert set(recorded["evidence_refs"]).issubset(response.metadata["validator_tool_fact_catalog"])
    # Two repository reads plus two fact-recording calls exceed the old two-tool limit.
    assert response.metadata["tool_call_count"] == 4


def test_validator_v3_rejects_non_authoritative_claim_tool_with_actionable_hint() -> None:
    class WrongToolLLM:
        models = ["unit-model"]

        def run_conversation_with_tools(self, **kwargs):
            executor = kwargs["tool_executor"]
            observation = executor("get_data_flow", {"query": "path"})
            rejected = executor(
                "submit_validator_evidence_claim",
                {
                    "fact_kind": "caller_contract",
                    "predicate": "caller_contract_holds",
                    "polarity": "supports",
                    "subject_uid": "wire_len",
                    "decision_region_uid": "",
                    "arguments": {"query": "path"},
                    "cited_evidence_refs": [observation["evidence_ref"]],
                },
            )
            assert rejected["success"] is True
            assert rejected["claim_status"] == "unknown"
            assert rejected["reason_code"] == "tool_not_authoritative_for_predicate"
            assert rejected["expected_predicate"] == "caller_contract_holds"
            assert "get_callers" in rejected["allowed_tools"]
            payload = _result(
                verdict="uncertain",
                evidence_refs=[],
                stop_reason="investigation_exhausted",
            )
            payload["pass"] = "investigation_synthesis"
            accepted = kwargs["terminal_tool_handler"](payload)
            return {
                "content": "",
                "conversation": [],
                "terminal_tool_payload": accepted["payload"],
                "terminal_tool_valid": True,
                "iterations": 2,
                "tool_call_count": 2,
                "cumulative_prompt_tokens": 20,
                "cumulative_completion_tokens": 10,
                "cumulative_total_tokens": 30,
            }

    evidence_slice = _slice()
    evidence_slice["decision_facts"] = {"missing_fact_kinds": ["caller_contract"]}
    response = ValidatorAgent(WrongToolLLM(), [_ReadOnlyEvidenceTool()]).investigate(
        {
            "finding_uid": "CAND_1",
            "validation_cluster_uid": "VAL_1",
            "evidence_slice": evidence_slice,
        },
        claim_verifier=_verify_test_claim,
    )

    assert response.success is True
    assert response.metadata["validator_investigation_facts"] == []


def test_validator_v3_investigation_stops_after_two_no_gain_rounds_and_rejects_duplicate() -> None:
    llm = _InvestigationLLM(no_gain=True)

    response = ValidatorAgent(llm, [_ReadOnlyEvidenceTool()]).investigate(
        {
            "finding_uid": "CAND_1",
            "validation_cluster_uid": "VAL_1",
            "validation_pass": "investigation_synthesis",
            "evidence_slice": _slice(),
        }
    )

    assert response.success is True
    first, same_round, second, duplicate, stopped = llm.executor_results
    assert first["validator_new_evidence"] is False
    assert same_round["validator_new_evidence"] is False
    assert second["validator_new_evidence"] is False
    assert duplicate["error"] == "validator_v3_duplicate_tool_query"
    assert stopped["error"] == "validator_v3_no_new_evidence_fact_stop; emit the final result"
    assert response.metadata["validator_no_new_evidence_fact_stop"] is True
    assert response.metadata["consecutive_no_new_evidence_fact_iterations"] == 2


def test_validator_v3_tool_observations_do_not_reset_accepted_fact_progress() -> None:
    llm = _InvestigationLLM(unrecorded_gain=True)

    response = ValidatorAgent(llm, [_ReadOnlyEvidenceTool()]).investigate(
        {
            "finding_uid": "CAND_1",
            "validation_cluster_uid": "VAL_1",
            "validation_pass": "investigation_synthesis",
            "evidence_slice": _slice(),
        }
    )

    assert response.success is True
    first, _same_round, second, _duplicate, stopped = llm.executor_results
    assert first["validator_new_evidence"] is True
    assert second["validator_new_evidence"] is True
    assert response.metadata["validator_investigation_tool_fact_count"] == 2
    assert response.metadata["validator_investigation_facts"] == []
    assert stopped["error"] == "validator_v3_no_new_evidence_fact_stop; emit the final result"
    assert response.metadata["consecutive_no_new_evidence_fact_iterations"] == 2


def test_validator_v3_verified_terminal_requires_program_verified_fact() -> None:
    class VerifiedTerminalLLM:
        models = ["unit-model"]

        def __init__(self) -> None:
            self.invalid_terminal = None

        def run_conversation_with_tools(self, **kwargs):
            handler = kwargs["terminal_tool_handler"]
            executor = kwargs["tool_executor"]
            premature = _result(
                **{
                    "pass": "investigation_synthesis",
                    "evidence_refs": ["FACT_1"],
                    "stop_reason": "investigation_complete",
                }
            )
            self.invalid_terminal = handler(premature)
            assert self.invalid_terminal["valid"] is False

            tool_fact = executor("get_data_flow", {"query": "bound"})
            verified = executor(
                "submit_validator_evidence_claim",
                {
                    "fact_kind": "value_range",
                    "predicate": "value_range_is_proved",
                    "polarity": "supports",
                    "subject_uid": "wire_len",
                    "decision_region_uid": "",
                    "arguments": {"query": "bound"},
                    "cited_evidence_refs": [tool_fact["evidence_ref"]],
                },
            )
            fact_uid = verified["verified_fact"]["fact_uid"]
            terminal = _result(
                **{
                    "pass": "investigation_synthesis",
                    "evidence_refs": [fact_uid],
                    "stop_reason": "investigation_complete",
                }
            )
            accepted = handler(terminal)
            assert accepted["valid"] is True
            return {
                "content": "",
                "conversation": [],
                "terminal_tool_payload": accepted["payload"],
                "terminal_tool_valid": True,
                "iterations": 2,
                "tool_call_count": 2,
                "cumulative_prompt_tokens": 200,
                "cumulative_completion_tokens": 50,
                "cumulative_total_tokens": 250,
            }

    llm = VerifiedTerminalLLM()
    evidence_slice = _slice()
    evidence_slice["decision_facts"] = {"missing_fact_kinds": ["value_range"]}

    response = ValidatorAgent(llm, [_ReadOnlyEvidenceTool()]).investigate(
        {
            "finding_uid": "CAND_1",
            "validation_cluster_uid": "VAL_1",
            "validation_pass": "investigation_synthesis",
            "evidence_slice": evidence_slice,
        },
        claim_verifier=_verify_test_claim,
    )

    assert response.success is True
    assert response.data["verdict"] == "verified"
    assert "program-verified FACT" in llm.invalid_terminal["error"]
    assert response.metadata["new_fact_count"] == 1


def test_validator_v3_no_progress_coerces_unbacked_verified_terminal_to_uncertain() -> None:
    class NoProgressTerminalLLM:
        models = ["unit-model"]

        def run_conversation_with_tools(self, **kwargs):
            executor = kwargs["tool_executor"]
            handler = kwargs["terminal_tool_handler"]
            assert executor._zscope_start_iteration(1) is False
            assert executor._zscope_start_iteration(2) is False
            assert executor._zscope_start_iteration(3) is False
            assert executor._zscope_start_iteration(4) is False
            assert executor._zscope_start_iteration(5) is False
            assert executor._zscope_start_iteration(6) is True
            unsupported = _result(
                **{
                    "pass": "investigation_synthesis",
                    "evidence_refs": ["FACT_1"],
                    "stop_reason": "investigation_complete",
                }
            )
            terminal = handler(unsupported)
            assert terminal["valid"] is True
            assert terminal["payload"]["verdict"] == "uncertain"
            assert terminal["payload"]["stop_reason"] == "investigation_exhausted"
            return {
                "content": "",
                "conversation": [],
                "terminal_tool_payload": terminal["payload"],
                "terminal_tool_valid": True,
                "iterations": 6,
                "tool_call_count": 0,
                "cumulative_prompt_tokens": 600,
                "cumulative_completion_tokens": 100,
                "cumulative_total_tokens": 700,
            }

    response = ValidatorAgent(NoProgressTerminalLLM(), [_ReadOnlyEvidenceTool()]).investigate(
        {
            "finding_uid": "CAND_1",
            "validation_cluster_uid": "VAL_1",
            "validation_pass": "investigation_synthesis",
            "evidence_slice": _slice(),
        }
    )

    assert response.success is True
    assert response.data["verdict"] == "uncertain"
    assert response.data["stop_reason"] == "investigation_exhausted"
    assert response.metadata["validator_no_new_evidence_fact_stop"] is True
    assert response.metadata["new_fact_count"] == 0


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
