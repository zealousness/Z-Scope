"""Adversarial response and accounting cases found by the line-by-line review."""

import json

import pytest

from test_validator_v3_protocol import _DirectLLM, _result, _slice
from zscope.agents.validator_agent.agent import ValidatorAgent
from zscope.agents.validator_agent.output import DecisionOutput, terminal_payload
from zscope.core.validation.execution_context import ExecutionContext, rebound_execution_context
from zscope.core.validation import investigation_reuse


def _call(payload, name="emit_validator_result_v3"):
    return {"type": "function", "function": {"name": name, "arguments": json.dumps(payload)}}


@pytest.mark.parametrize(
    "calls",
    [
        [_call(_result()), _call({}, "read_code")],
        [_call(_result()), _call(_result(verdict="rejected"))],
    ],
)
def test_mixed_or_duplicate_direct_terminals_require_a_fresh_decision(calls):
    class MixedLLM(_DirectLLM):
        def chat_completion(self, messages, **kwargs):
            if not self.calls:
                self.calls.append((messages, kwargs))
                return {
                    "choices": [
                        {
                            "finish_reason": "tool_calls",
                            "message": {
                                "role": "assistant",
                                "tool_calls": calls,
                            },
                        }
                    ],
                    "usage": {"prompt_tokens": 31, "completion_tokens": 7},
                }
            return super().chat_completion(messages, **kwargs)

    llm = MixedLLM(
        [{"content": json.dumps(_result(verdict="uncertain", stop_reason="no_evidence_gain"))}]
    )
    response = ValidatorAgent(llm, []).run({"evidence_slice": _slice()})
    assert response.data["verdict"] == "uncertain"
    assert len(llm.calls) == response.metadata["validator_api_call_count"] == 2
    assert response.metadata["validator_final_tool_call_count"] == sum(
        call["function"]["name"] == "emit_validator_result_v3" for call in calls
    )
    assert response.metadata["cumulative_total_tokens"] == 158


def test_empty_choices_preserve_usage_and_get_only_one_repair():
    class EmptyLLM(_DirectLLM):
        def chat_completion(self, messages, **kwargs):
            self.calls.append((messages, kwargs))
            return {"choices": [], "usage": {"prompt_tokens": 31, "completion_tokens": 7}}

    llm = EmptyLLM([])
    response = ValidatorAgent(llm, []).run({"evidence_slice": _slice()})
    assert response.data["stop_reason"] == "malformed_output"
    assert response.metadata["cumulative_total_tokens"] == 76
    assert response.metadata["validator_api_call_count"] == len(llm.calls) == 2


@pytest.mark.parametrize(
    "result",
    [
        {"finish_reason": "length"},
        {"finish_reason": "context_window_exceeded"},
        {"truncated": True},
        {"terminal_tool_valid": False},
    ],
)
def test_legacy_cannot_recover_a_decision_from_an_unfinished_response(result):
    content = _public_validation_result()
    assert (
        ValidatorAgent.__new__(ValidatorAgent)._extract_validation_payload(content, result, [])
        is None
    )


def _public_validation_result():
    return json.dumps(
        {
            "type": "validation_result",
            "verdict": "verified",
            "reasoning": "current evidence",
            "blocking_negative_evidence": False,
        }
    )


def test_only_current_public_assistant_content_can_become_a_decision():
    public = _public_validation_result()
    agent = ValidatorAgent.__new__(ValidatorAgent)
    history = [
        {"role": "assistant", "content": public},
        {"role": "assistant", "content": "Still gathering evidence", "reasoning_content": public},
    ]
    assert agent._extract_validation_payload(public, {"reasoning_content": public}, history) is None
    assert terminal_payload({"reasoning_content": public}, "emit_validation_result") is None
    assert (
        agent._extract_validation_payload(
            public,
            {
                "terminal_tool_valid": False,
                "terminal_tool_name": None,
            },
            [],
        )
        is not None
    )  # No terminal was required in this legacy conversation.


@pytest.mark.parametrize(
    "text",
    [
        json.dumps(_result())[:-1],
        json.dumps(_result()) + " {",
        json.dumps(_result()) + json.dumps(_result(verdict="rejected")),
        "[" + json.dumps(_result()),
        "[" + json.dumps(_result()) + ",42]",
        '"' + json.dumps(_result()) + '"',
        '{"verdict":"verified","verdict":"rejected"}',
        '{"verdict":"verified","score":NaN}',
        '{"verdict":"verified","score":1e999}',
        '{"nested":' * 2000 + "{}",
    ],
)
def test_truncated_ambiguous_and_overdeep_json_are_not_salvaged(text):
    assert terminal_payload({"content": text}, "emit_validator_result_v3") is None


def test_complete_deep_unknown_structure_cannot_become_a_verdict():
    content = '{"nested":' * 2000 + "{}" + "}" * 2000
    llm = _DirectLLM([{"content": content}, {"content": content}])
    response = ValidatorAgent(llm, []).run({"evidence_slice": _slice()})
    assert response.data["verdict"] == "uncertain"
    assert response.data["stop_reason"] == "malformed_output"
    assert len(llm.calls) == 2


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
@pytest.mark.parametrize("header", ["```", "```json", "```JSON "])
def test_complete_json_fences_accept_both_line_endings(newline, header):
    payload = _result()
    content = newline.join([header, json.dumps(payload), "```"])
    assert terminal_payload({"content": content}, "emit_validator_result_v3") == payload


def test_bounded_raw_audit_keeps_digest_instead_of_a_large_invalid_payload():
    audit = DecisionOutput.from_result({"content": json.dumps({"reasoning": "x" * 70000})}).audit(
        False
    )
    assert audit["raw_response"]["omitted"] is True
    assert len(audit["raw_response"]["sha256"]) == 64
    assert len(json.dumps(audit)) < 1000


@pytest.mark.parametrize(
    "payload",
    [
        {"verdict": "x" * 70000},
        {"stop_reason": "x" * 70000},
        {"missing_fact_request": {"fact_kind": "x" * 70000}},
        {"verdict": {"nested": "x" * 70000}},
    ],
)
def test_audit_samples_cannot_reintroduce_an_oversized_payload(payload):
    audit = DecisionOutput.from_result({"content": json.dumps(payload)}).audit(False)
    assert audit["raw_response"]["omitted"] is True
    assert len(json.dumps(audit)) < 2000


def test_v3_compatibility_client_cannot_execute_repository_tools():
    class CompatibilityLLM:
        def run_conversation_with_tools(self, **kwargs):
            assert [tool["function"]["name"] for tool in kwargs["tools_schema"]] == [
                "emit_validator_result_v3"
            ]
            assert (
                kwargs["tool_executor"]("read_code", {"file_path": "private.c"})["success"] is False
            )
            return {"content": json.dumps(_result()), "iterations": 1}

    assert ValidatorAgent(CompatibilityLLM(), []).run({"evidence_slice": _slice()}).success


def test_zero_actual_calls_survive_a_preflight_window_failure():
    class WindowLLM:
        def run_conversation_with_tools(self, **kwargs):
            return {
                "content": "",
                "iterations": 1,
                "api_call_count": 0,
                "finish_reason": "context_window_exceeded",
                "truncated": True,
            }

        def chat_completion(self, *args, **kwargs):
            pytest.fail("An unavailable context must not be retried as a format repair")

    response = ValidatorAgent(WindowLLM(), []).run({"evidence_slice": {"schema_version": "v2"}})
    assert response.metadata["validator_api_call_count"] == 0
    assert response.metadata["validator_turn_count"] == 1


def test_legacy_result_finalizes_turn_distribution():
    class LegacyLLM:
        def run_conversation_with_tools(self, **kwargs):
            return {
                "content": json.dumps(
                    {
                        "type": "validation_result",
                        "verdict": "verified",
                        "reasoning": "current facts",
                        "blocking_negative_evidence": False,
                    }
                ),
                "iterations": 3,
                "api_call_count": 2,
            }

    response = ValidatorAgent(LegacyLLM(), []).run({"finding": "demo"})
    assert response.metadata["validator_turn_count"] == 3
    assert response.metadata["multi_turn_outlier_count"] == 1
    assert response.metadata["validator_api_call_count"] == 2


def test_fast_path_retries_a_nested_verdict_and_accepts_the_current_result():
    current = {
        "type": "validation_result",
        "verdict": "uncertain",
        "reasoning": "missing context",
        "blocking_negative_evidence": False,
    }
    messages = iter([{"result": {**current, "verdict": "verified"}}, current])

    class LegacyLLM:
        def run_conversation_with_tools(self, **kwargs):
            return {"content": json.dumps(next(messages)), "iterations": 1}

    response = ValidatorAgent(LegacyLLM(), []).run(
        {"finding": "demo", "evidence_pack": {"source": "current code"}}
    )
    assert response.success
    assert response.data["verdict"] == "uncertain"
    assert response.metadata["validator_fast_path_accepted"] == 0
    assert response.metadata["validator_api_call_count"] == 2


def test_query_replay_exception_retains_evidence_and_live_execution_identity(monkeypatch):
    class UnusedLLM:
        def run_conversation_with_tools(self, **kwargs):
            pytest.fail("Prefetch failed before model dispatch")

    agent = ValidatorAgent(UnusedLLM(), [])
    agent.tools_schema = [{"function": {"name": "read_code"}}]

    def execute(name, args):
        if args["file_path"] == "second.c":
            raise RuntimeError("SYNTHETIC_PRIVATE_READ_ERROR")
        return {"success": True, "data": {"file_path": "first.c", "code": "f();"}}

    monkeypatch.setattr(agent, "_tool_executor", execute)
    plan = {
        "schema_version": investigation_reuse.PROTOCOL,
        "queries": [
            {
                "name": "read_code",
                "arguments": {"file_path": path, "start_line": 1},
                "observation": {},
            }
            for path in ("first.c", "second.c")
        ],
    }
    with rebound_execution_context(ExecutionContext("LIVE_BUILD", ("entry", "USR_ENTRY"))):
        response = agent.investigate(
            {"evidence_slice": _slice(), "_investigation_query_plan": plan}
        )
    assert response.data["verdict"] == "uncertain"
    assert response.metadata["execution_build_context_id"] == "LIVE_BUILD"
    assert response.metadata["execution_entry_symbol"] == "entry"
    assert response.metadata["execution_entry_usr"] == "USR_ENTRY"
    assert len(response.metadata["validator_tool_fact_catalog"]) == 1
    assert response.metadata["validator_api_call_count"] == 0
    assert response.metadata["validator_query_reuse"]["model_tasks"] == 0
    assert response.metadata["validator_error_type"] == "RuntimeError"
