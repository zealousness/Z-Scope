import json

import pytest

from zscope.agents.validator_agent.agent import ValidatorAgent
from zscope.common.validator_protocol import (
    DynamicReproductionRequest,
    VALIDATOR_RESULT_VERSION,
    ValidatorResultV3,
    parse_validator_result_v3,
    validator_result_provider_schema_v3,
    validator_result_schema_v3,
    validator_decision_schema_v3,
)
from zscope.framework.base import BaseTool, validate_function_arguments


def _slice() -> dict:
    return {
        "schema_version": "zscope.validator-evidence-slice.v3",
        "protocol_version": "zscope.validator-protocol.v3",
        "validation_pass": "initial",
        "obligation": {
            "candidate_uid": "CAND_1",
            "validation_cluster_uid": "VAL_1",
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


@pytest.mark.parametrize("structured", [True, False])
def test_initial_reuse_descriptor_matches_actual_closed_request(structured):
    llm = _DirectLLM([{"content": json.dumps(_result())}])
    llm.supports_structured_output = structured
    agent = ValidatorAgent(llm, [])
    request = {"evidence_slice": _slice(), "agent_contract": "exact runtime skill contract"}
    descriptor = agent.initial_reuse_descriptor(request)
    response = agent.run(request)
    assert response.success
    messages, options = llm.calls[0]
    assert descriptor["messages"] == messages
    assert descriptor["request_options"] == {
        key: value for key, value in options.items() if not key.startswith("trace_")
    }
    assert response.metadata["validator_provider_model"] == "unit-model"
    if not structured:
        assert [tool["function"]["name"] for tool in options["tools"]] == [
            "emit_validator_result_v3"
        ]
    assert (
        agent.initial_reuse_descriptor(
            {"evidence_slice": {**_slice(), "validation_pass": "evidence_recheck"}}
        )
        is None
    )
    assert agent.initial_reuse_descriptor({**request, "_review_session": object()}) is None


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


class _LengthThenFailingLLM(_DirectLLM):
    """First call truncates at the provider limit; the retry call errors."""

    def __init__(self) -> None:
        super().__init__([])

    def chat_completion(self, messages, **kwargs):
        self.calls.append((messages, kwargs))
        if len(self.calls) == 1:
            return {
                "choices": [
                    {
                        "finish_reason": "length",
                        "message": {"role": "assistant", "content": "{"},
                    }
                ],
                "model": "unit-model",
                "usage": {"prompt_tokens": 100, "completion_tokens": 20},
            }
        raise RuntimeError("provider dropped the retry connection")


class _ReadOnlyEvidenceTool(BaseTool):
    def __init__(self) -> None:
        super().__init__("read_validation_fact", "Read one immutable validation fact")

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

    def __init__(self, *, no_gain=False) -> None:
        self.no_gain = no_gain
        self.calls = []
        self.executor_results = []

    def run_conversation_with_tools(self, **kwargs):
        self.calls.append(kwargs)
        executor = kwargs["tool_executor"]
        if self.no_gain:
            assert executor._zscope_start_iteration(1) is False
            first = executor("read_validation_fact", {"query": "empty-one"})
            duplicate = executor("read_validation_fact", {"query": "empty-one"})
            same_round = executor("read_validation_fact", {"query": "empty-same-round"})
            assert executor._zscope_start_iteration(2) is False
            second = executor("read_validation_fact", {"query": "empty-two"})
            assert executor._zscope_start_iteration(3) is True
            stopped = executor("read_validation_fact", {"query": "after-stop"})
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
            path = executor("read_validation_fact", {"query": "path"})
            assert executor._zscope_start_iteration(2) is False
            bound = executor("read_validation_fact", {"query": "bound"})
            assert executor._zscope_start_iteration(3) is False
            fact = executor(
                "record_validator_investigation_fact",
                {
                    "fact_kind": "value_range",
                    "evidence_refs": [path["evidence_ref"], bound["evidence_ref"]],
                    "summary": "the externally controlled length may exceed capacity",
                },
            )
            assert executor._zscope_start_iteration(4) is False
            self.executor_results = [path, bound, fact]
            fact_uid = fact["fact"]["fact_uid"]
            payload = _result(
                evidence_refs=[fact_uid],
                stop_reason="decision_complete",
            )
            payload["pass"] = "investigation_synthesis"
            iterations = 4
            tool_calls = 3
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
    assert "max_tokens" not in llm.calls[0][1]
    assert llm.calls[0][1]["response_format"]["json_schema"]["strict"] is True
    wire_schema = llm.calls[0][1]["response_format"]["json_schema"]["schema"]
    assert "oneOf" not in wire_schema
    assert set(wire_schema["required"]) == set(validator_decision_schema_v3()["required"])
    assert response.metadata["validator_api_call_count"] == 1


def test_validator_provider_schema_keeps_full_shape_without_gateway_hostile_oneof() -> None:
    contract = validator_result_schema_v3()
    provider = validator_result_provider_schema_v3()

    assert "oneOf" in contract
    assert "oneOf" not in provider
    assert provider["required"] == contract["required"]
    assert set(provider["properties"]) == set(contract["properties"])


def test_validator_provider_schema_enforces_candidate_missing_fact_policy() -> None:
    exhausted = validator_result_provider_schema_v3(allowed_missing_fact_kinds=[])
    requestable = validator_result_provider_schema_v3(
        allowed_missing_fact_kinds=["value_range", "guard_dominance", "not-a-kind"]
    )

    assert exhausted["properties"]["missing_fact_request"]["type"] == "null"
    assert "missing_fact" not in exhausted["properties"]["stop_reason"]["enum"]
    branches = requestable["properties"]["missing_fact_request"]["anyOf"]
    assert branches[0] == {"type": "null"}
    assert branches[1]["type"] == "object"
    assert branches[1]["properties"]["fact_kind"]["enum"] == [
        "guard_dominance",
        "value_range",
    ]


def test_validator_provider_schema_enumerates_candidate_evidence_refs() -> None:
    scoped = validator_result_provider_schema_v3(
        allowed_evidence_refs=["FACT_1", "path-edge:0:entry->sink", "FACT_1"]
    )
    empty = validator_result_provider_schema_v3(allowed_evidence_refs=[])

    assert scoped["properties"]["evidence_refs"]["items"]["enum"] == [
        "FACT_1",
        "path-edge:0:entry->sink",
    ]
    assert empty["properties"]["evidence_refs"]["maxItems"] == 0


def test_validator_direct_schema_and_prompt_close_exhausted_provider_requests() -> None:
    llm = _DirectLLM([{"content": json.dumps(_result())}])
    evidence_slice = _slice()
    evidence_slice["allowed_missing_fact_kinds"] = []

    response = ValidatorAgent(llm, []).run(
        {
            "finding_uid": "CAND_1",
            "validation_cluster_uid": "VAL_1",
            "validation_pass": "initial",
            "evidence_slice": evidence_slice,
        }
    )

    assert response.success
    wire_schema = llm.calls[0][1]["response_format"]["json_schema"]["schema"]
    assert wire_schema["properties"]["missing_fact_request"]["type"] == "null"
    assert wire_schema["properties"]["evidence_refs"]["items"]["enum"] == ["FACT_1"]
    prompt = llm.calls[0][0][-1]["content"]
    assert "stop_reason" not in wire_schema["properties"]
    assert "stop_reason=" not in prompt
    assert "runtime binds identities, stage and stop status" in prompt


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
    assert response.metadata["validator_api_call_count"] == 1
    assert response.metadata["validator_turn_count"] == 0


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
    assert len(llm.calls) == 2
    assert response.metadata["validator_repair_attempted"] == 1
    assert response.metadata["validator_repair_accepted"] == 0
    assert response.metadata["validator_first_attempt_audit"]["parse_status"] == "malformed"


def test_validator_v3_malformed_output_gets_one_strict_repair_attempt() -> None:
    llm = _DirectLLM([{"content": "not-json"}, {"content": "still-not-json"}])
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
    assert len(llm.calls) == 2
    assert response.metadata["validator_repair_attempted"] == 1
    assert response.metadata["validator_repair_accepted"] == 0
    assert "protocol_retry=1" in llm.calls[1][1]["trace_label"]


def test_validator_v3_malformed_output_can_be_repaired_once() -> None:
    llm = _DirectLLM(
        [
            {"content": '<DSML><invoke name="final">broken</invoke></DSML>'},
            {"content": json.dumps(_result())},
        ]
    )
    response = ValidatorAgent(llm, []).run(
        {
            "finding_uid": "CAND_1",
            "validation_cluster_uid": "VAL_1",
            "evidence_slice": _slice(),
        }
    )

    assert response.success
    assert response.data["verdict"] == "verified"
    assert len(llm.calls) == 2
    assert response.metadata["validator_repair_attempted"] == 1
    assert response.metadata["validator_repair_accepted"] == 1
    assert response.metadata["validator_first_attempt_audit"]["parse_status"] == "malformed"
    assert "protocol_retry=1" in llm.calls[1][1]["trace_label"]


def test_validator_v3_length_retries_once_with_doubled_output_ceiling() -> None:
    llm = _DirectLLM(
        [
            {"content": "{", "finish_reason": "length"},
            {"content": json.dumps(_result())},
        ]
    )
    response = ValidatorAgent(llm, []).run(
        {
            "finding_uid": "CAND_1",
            "validation_cluster_uid": "VAL_1",
            "evidence_slice": _slice(),
        }
    )

    assert response.success
    assert response.data["verdict"] == "verified"
    assert len(llm.calls) == 2
    # The first call keeps pure config semantics (no explicit max_tokens);
    # only the length retry carries the doubled output ceiling.
    assert "max_tokens" not in llm.calls[0][1]
    assert llm.calls[1][1]["max_tokens"] >= 8192
    assert llm.calls[1][1]["thinking"] == {"type": "disabled"}
    assert "length_retry=1" in llm.calls[1][1]["trace_label"]
    assert response.metadata["validator_length_retry_count"] == 1
    assert response.metadata["validator_repair_thinking_disabled"] == 1
    assert response.metadata["validator_api_call_count"] == 2
    assert response.metadata["finish_reason"] == "stop"


def test_validator_v3_length_retry_failure_still_degrades_to_uncertain() -> None:
    llm = _DirectLLM(
        [
            {"content": "{", "finish_reason": "length"},
            {"content": "{", "finish_reason": "length"},
        ]
    )
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
    assert parse_validator_result_v3(response.data) is not None
    assert len(llm.calls) == 2
    assert "max_tokens" not in llm.calls[0][1]
    assert response.metadata["validator_length_retry_count"] == 1


def test_validator_v3_length_retry_exception_keeps_first_response() -> None:
    # A retry that fails at the provider level must not lose the original
    # truncated response; the run still degrades to uncertain/output_truncated.
    llm = _LengthThenFailingLLM()
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
    assert len(llm.calls) == 2
    assert response.metadata["validator_length_retry_count"] == 1
    assert response.metadata["validator_api_call_count"] == 2
    assert response.metadata["validator_turn_count"] == 1


def test_v3_uncertain_prompt_does_not_require_legacy_fields():
    llm = _DirectLLM(
        [
            {
                "content": json.dumps(
                    _result(
                        verdict="uncertain",
                        stop_reason="no_evidence_gain",
                    )
                )
            }
        ]
    )
    response = ValidatorAgent(llm, []).run({"evidence_slice": _slice()})
    system = "\n".join(
        message["content"] for message in llm.calls[0][0] if message["role"] == "system"
    )
    shared_contract = system.split("The following object is retained only for legacy", 1)[0]
    assert "finding_kind" not in shared_contract
    assert response.data["verdict"] == "uncertain"
    assert len(llm.calls) == 1


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
        # Scalar type coercion must be rejected...
        ("candidate_uid", 7),
        ("validation_cluster_uid", True),
        ("pass", ["initial"]),
        ("verdict", {"value": "verified"}),
        ("reasoning", 123),
        ("stop_reason", False),
        ("blocking_negative_evidence", 1),
        # ...and schema string lengths must be enforced.
        ("reasoning", "r" * 4001),
        ("positive_evidence", ["p" * 1001]),
        ("negative_evidence", ["n" * 1001]),
        ("evidence_refs", ["E" * 513]),
    ],
)
def test_validator_v3_rejects_invalid_field_values(field, value) -> None:
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


@pytest.mark.parametrize(
    "verdict,reason,needs_fact,accepted",
    [
        ("uncertain", "malformed_output", False, True),
        ("uncertain", "investigation_exhausted", False, True),
        ("uncertain", "output_truncated", False, True),
        ("uncertain", "no_evidence_gain", False, True),
        ("uncertain", "missing_fact", True, True),
        ("verified", "decision_complete", False, True),
        ("rejected", "investigation_complete", False, True),
        ("verified", "investigation_exhausted", False, False),
        ("rejected", "malformed_output", False, False),
        ("uncertain", "decision_complete", False, False),
        ("uncertain", "investigation_complete", False, False),
        ("uncertain", "missing_fact", False, False),
        ("uncertain", "investigation_exhausted", True, False),
        ("verified", "decision_complete", True, False),
        ("rejected", "missing_fact", True, False),
    ],
)
def test_validator_stop_states_agree_across_wire_parser_and_runtime(
    verdict, reason, needs_fact, accepted
):
    payload = _result(
        verdict=verdict,
        stop_reason=reason,
        missing_fact_request=(
            {"fact_kind": "value_range", "reason": "Need the bound"} if needs_fact else None
        ),
    )
    payload["pass"] = "investigation_synthesis"
    assert (validate_function_arguments(validator_result_schema_v3(), payload) is None) == accepted
    assert (parse_validator_result_v3(payload) is not None) == accepted
    fields = {key: value for key, value in payload.items() if key not in {"schema_version", "pass"}}
    fields["validation_pass"] = payload["pass"]
    for name in ("positive_evidence", "negative_evidence", "evidence_refs"):
        fields[name] = tuple(fields[name])
    if accepted:
        result = ValidatorResultV3(**fields)
        assert parse_validator_result_v3(result.to_dict()) == result
    else:
        with pytest.raises(ValueError):
            ValidatorResultV3(**fields)


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
    )

    assert response.success is True
    assert response.data["pass"] == "investigation_synthesis"
    assert response.data["verdict"] == "verified"
    assert len(llm.calls) == 1
    assert llm.calls[0]["max_iterations"] == 50
    assert llm.calls[0]["preserve_reasoning_metadata"] is True
    assert len(response.metadata["validator_tool_fact_catalog"]) == 2
    assert len(response.metadata["validator_investigation_facts"]) == 1
    recorded = response.metadata["validator_investigation_facts"][0]
    assert recorded["fact_kind"] == "value_range"
    assert recorded["fact_uid"] in response.data["evidence_refs"]
    assert set(recorded["evidence_refs"]) == set(response.metadata["validator_tool_fact_catalog"])
    # Two repository reads plus a fact-recording call exceed the old two-tool limit.
    assert response.metadata["tool_call_count"] == 3


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


def test_validator_window_failure_keeps_facts_but_cannot_accept_earlier_decision() -> None:
    class WindowLimitedLLM(_InvestigationLLM):
        def run_conversation_with_tools(self, **kwargs):
            result = super().run_conversation_with_tools(**kwargs)
            # Even schema-valid, evidence-backed text from before the stop
            # cannot become a completed verdict after an incomplete session.
            result["content"] = result["message"]["tool_calls"][0]["function"]["arguments"]
            result.update(finish_reason="context_window_exceeded", truncated=True, api_call_count=3)
            return result

    evidence_slice = _slice()
    evidence_slice["decision_facts"] = {"missing_fact_kinds": ["value_range"]}
    response = ValidatorAgent(WindowLimitedLLM(), [_ReadOnlyEvidenceTool()]).investigate(
        {
            "finding_uid": "CAND_1",
            "validation_cluster_uid": "VAL_1",
            "validation_pass": "investigation_synthesis",
            "evidence_slice": evidence_slice,
        }
    )
    assert response.data["verdict"] == "uncertain"
    assert response.data["stop_reason"] == "investigation_exhausted"
    assert response.metadata["validator_context_window_exceeded"] is True
    assert response.metadata["validator_api_call_count"] == 3
    assert len(response.metadata["validator_tool_fact_catalog"]) == 2
    assert len(response.metadata["validator_investigation_facts"]) == 1
    assert parse_validator_result_v3(response.data) is not None


def test_complete_json_in_truncated_direct_response_still_requires_repair():
    llm = _DirectLLM(
        [
            {"content": json.dumps(_result()), "finish_reason": "length"},
            {"content": json.dumps(_result(verdict="uncertain", stop_reason="unsupported_fact"))},
        ]
    )
    response = ValidatorAgent(llm, []).run({"evidence_slice": _slice()})
    assert len(llm.calls) == 2
    assert response.data["verdict"] == "uncertain"
    assert response.metadata["validator_length_retry_count"] == 1


@pytest.mark.parametrize("failure", [{"terminal_tool_valid": False}, {"finish_reason": "length"}])
def test_failed_investigation_terminal_cannot_be_recovered_from_earlier_json(failure):
    class IncompleteLLM(_InvestigationLLM):
        def run_conversation_with_tools(self, **kwargs):
            result = super().run_conversation_with_tools(**kwargs)
            result["content"] = result["message"]["tool_calls"][0]["function"]["arguments"]
            return {**result, **failure}

    response = ValidatorAgent(IncompleteLLM(), [_ReadOnlyEvidenceTool()]).investigate(
        {"evidence_slice": _slice()}
    )
    assert response.data["verdict"] == "uncertain"
    assert response.data["stop_reason"] == "investigation_exhausted"
    assert len(response.metadata["validator_investigation_facts"]) == 1
    assert response.metadata["validator_protocol_audit"]["parsed"] is False


def test_investigation_failure_keeps_error_category_without_logging_provider_body(caplog):
    class FailedLLM:
        def run_conversation_with_tools(self, **kwargs):
            raise RuntimeError("private-endpoint-body-DO-NOT-LOG")

    response = ValidatorAgent(FailedLLM(), []).investigate({"evidence_slice": _slice()})
    assert response.data["verdict"] == "uncertain"
    assert response.metadata["validator_error_type"] == "RuntimeError"
    assert "RuntimeError" in caplog.text
    assert "private-endpoint-body-DO-NOT-LOG" not in caplog.text


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
