import json
import logging

import pytest

from zscope.agents.validator_agent.agent import ValidatorAgent
from zscope.agents.validator_agent.legacy import LegacyResult
from zscope.agents.validator_agent.investigation import _tool_result_evidence_atoms


def _agent() -> ValidatorAgent:
    return ValidatorAgent.__new__(ValidatorAgent)


def test_v3_tool_evidence_atoms_ignore_empty_and_failed_reads() -> None:
    assert not _tool_result_evidence_atoms(
        "query_code_graph", {"success": True, "data": {"edges": []}, "duration_ms": 2}
    )
    assert not _tool_result_evidence_atoms(
        "query_code_graph", {"success": False, "data": {"edges": [{"site": "demo.c:12"}]}}
    )


def _result(verdict="verified", **changes):
    return {
        "type": "validation_result",
        "verdict": verdict,
        "reasoning": "current evidence",
        "blocking_negative_evidence": False,
        **changes,
    }


def test_model_schema_requests_the_verdict_once():
    fields = LegacyResult.output_spec().schema["properties"]
    assert set(fields["verdict"]["enum"]) == {"verified", "rejected", "uncertain"}
    assert "is_valid" not in fields


@pytest.mark.parametrize("verdict", ["verified", "rejected", "uncertain"])
def test_validation_result_preserves_fields_and_derives_is_valid(verdict):
    original = _result(verdict, is_valid=verdict != "verified", issue_id="ISSUE_1")
    content = "```json\n" + json.dumps(original) + "\n```"
    assert _agent()._extract_validation_payload(content, {}, []) == {
        **original,
        "is_valid": verdict == "verified",
    }
    assert original["is_valid"] is (verdict != "verified")


@pytest.mark.parametrize(
    "verdict", ["tp", "fp", "needs_review", "confirmed", "true", "VERIFIED", None, []]
)
def test_validation_rejects_noncanonical_verdict_even_with_is_valid(verdict):
    assert LegacyResult.parse(_result(verdict, is_valid=True)) is None


@pytest.mark.parametrize(
    "body",
    [
        {"is_valid": True, "reasoning": "old representation"},
        {"validation_result": "verified"},
        {"result": _result()},
        {"validation_results": [_result()]},
        {"finding": _result()},
        _result(type="unrelated"),
        _result(reasoning="  "),
    ],
)
def test_validation_rejects_undeclared_result_shapes(body):
    assert _agent()._extract_validation_payload(json.dumps(body), {}, []) is None


def test_deep_unexpected_metadata_is_a_format_failure():
    nested = '{"item":' * 2000 + "null" + "}" * 2000
    text = json.dumps(_result())[:-1] + ',"extra":' + nested + "}"
    assert _agent()._extract_validation_payload(text, {}, []) is None


@pytest.mark.parametrize("route", ["legacy", "fast_path", "v2"])
def test_legacy_exceptions_do_not_escape_into_logs_prompts_or_results(caplog, route):
    marker = "SYNTHETIC_PRIVATE_ERROR_BODY"
    calls = []

    class FailingLLM:
        def run_conversation_with_tools(self, **kwargs):
            calls.append(kwargs["messages"])
            raise RuntimeError(marker)

    request = {"finding": "demo", "context_code": ""}
    if route == "fast_path":
        request["evidence_pack"] = {"source": "demo.c"}
    elif route == "v2":
        request["evidence_slice"] = {"schema_version": "zscope.validator-evidence-slice.v2"}
    with caplog.at_level(logging.DEBUG):
        response = ValidatorAgent(FailingLLM(), []).run(request)
    assert not response.success
    assert "RuntimeError" in response.error
    assert marker not in caplog.text + response.error + json.dumps(response.metadata)
    assert marker not in json.dumps(calls)
    assert len(calls) == {"legacy": 2, "fast_path": 3, "v2": 1}[route]


@pytest.mark.parametrize("structured", [False, True])
def test_failed_legacy_format_repair_logs_only_error_categories(caplog, structured):
    marker = "SYNTHETIC_REPAIR_ERROR_BODY"
    calls = []

    class RepairFailure:
        supports_structured_output = structured

        def run_conversation_with_tools(self, **kwargs):
            calls.append(kwargs["messages"])
            return {"content": "not-json", "iterations": 1}

        def chat_completion(self, messages, **kwargs):
            calls.append(messages)
            raise RuntimeError(marker)

    with caplog.at_level(logging.DEBUG):
        response = ValidatorAgent(RepairFailure(), []).run({"finding": "demo"})
    assert not response.success
    assert "RuntimeError" in caplog.text
    assert marker not in caplog.text + response.error + json.dumps(response.metadata)
    assert marker not in json.dumps(calls)


def test_validator_agent_run_accepts_the_declared_result_on_first_try() -> None:
    class FakeLLM:
        def __init__(self) -> None:
            self.calls = 0

        def run_conversation_with_tools(self, **kwargs):
            self.calls += 1
            return {
                "content": json.dumps(_result(issue_id="ISSUE_5")),
                "conversation": [],
                "context_tokens": 10,
                "cumulative_prompt_tokens": 20,
                "cumulative_completion_tokens": 5,
                "cumulative_total_tokens": 25,
                "iterations": 1,
                "tool_call_count": 0,
            }

    llm = FakeLLM()
    agent = ValidatorAgent(llm, [])

    response = agent.run({"finding": {"id": "ISSUE_5"}, "context_code": ""}, max_retries=2)

    assert response.success is True
    assert response.data["verdict"] == "verified"
    assert llm.calls == 1


def test_validator_agent_run_accepts_high_confidence_fast_path() -> None:
    class FakeLLM:
        def __init__(self) -> None:
            self.calls = 0
            self.max_iterations = []

        def run_conversation_with_tools(self, **kwargs):
            self.calls += 1
            self.max_iterations.append(kwargs.get("max_iterations"))
            return {
                "content": """
```json
{
  "type": "validation_result",
  "issue_id": "ISSUE_6",
  "blocking_negative_evidence": false,
  "verdict": "verified",
  "confidence_score": 0.91,
  "reasoning": "证据包已经证明 source 到 sink",
  "positive_evidence": ["source reaches sink"],
  "negative_evidence": [],
  "missing_context": [],
  "source": "caller argument",
  "sink": "memcpy length",
  "control_of_source": "caller controls it",
  "guard_analysis": "missing bound"
}
```
""",
                "conversation": [],
                "context_tokens": 10,
                "cumulative_prompt_tokens": 20,
                "cumulative_completion_tokens": 5,
                "cumulative_total_tokens": 25,
                "iterations": 1,
                "tool_call_count": 0,
            }

    llm = FakeLLM()
    agent = ValidatorAgent(llm, [])

    response = agent.run(
        {
            "finding": {"id": "ISSUE_6"},
            "context_code": "",
            "evidence_pack": {"positive_evidence": ["source reaches sink"]},
        },
        max_retries=2,
    )

    assert response.success is True
    assert response.data["validator_fast_path"] is True
    assert llm.calls == 1
    assert llm.max_iterations == [1]
    assert response.metadata["validator_fast_path_accepted"] == 1


def test_validator_agent_run_accepts_uncertain_fast_path_as_terminal_review() -> None:
    class FakeLLM:
        def __init__(self) -> None:
            self.calls = 0
            self.max_iterations = []

        def run_conversation_with_tools(self, **kwargs):
            self.calls += 1
            self.max_iterations.append(kwargs.get("max_iterations"))
            return {
                "content": json.dumps(
                    {
                        "type": "validation_result",
                        "issue_id": "ISSUE_REVIEW",
                        "blocking_negative_evidence": False,
                        "verdict": "uncertain",
                        "confidence_score": 0.62,
                        "reasoning": "The compact evidence does not prove the guard contract.",
                        "positive_evidence": ["source and sink are structurally connected"],
                        "negative_evidence": [],
                        "missing_context": ["callee guard contract"],
                    }
                ),
                "conversation": [],
                "context_tokens": 10,
                "cumulative_prompt_tokens": 20,
                "cumulative_completion_tokens": 5,
                "cumulative_total_tokens": 25,
                "iterations": 1,
                "tool_call_count": 0,
            }

    llm = FakeLLM()
    agent = ValidatorAgent(llm, [])

    response = agent.run(
        {
            "finding": {"id": "ISSUE_REVIEW"},
            "context_code": "",
            "evidence_pack": {
                "positive_evidence": ["source and sink are structurally connected"],
                "missing_context": ["callee guard contract"],
            },
        },
        max_retries=2,
    )

    assert response.success is True
    assert response.data["verdict"] == "uncertain"
    assert response.data["validator_fast_path"] is True
    assert llm.calls == 1
    assert llm.max_iterations == [1]
    assert response.metadata["validator_fast_path_attempted"] == 1
    assert response.metadata["validator_fast_path_accepted"] == 1


@pytest.mark.parametrize("verdict", ["verified", "rejected"])
def test_validator_parser_defers_confidence_policy_to_pipeline(verdict):
    assert LegacyResult.parse(_result(verdict, confidence_score=0.42))["verdict"] == verdict


def test_validator_agent_repairs_prose_without_json() -> None:
    class FakeLLM:
        models = ["repair-model"]
        supports_structured_output = False

        def __init__(self) -> None:
            self.repair_kwargs = {}

        def run_conversation_with_tools(self, **kwargs):
            return {
                "content": "Based on the evidence, I can now provide the validation result.",
                "conversation": [
                    {
                        "role": "assistant",
                        "content": "Based on the evidence, I can now provide the validation result.",
                    }
                ],
                "finish_reason": "stop",
                "provider_model": "repair-model",
                "context_tokens": 10,
                "cumulative_prompt_tokens": 20,
                "cumulative_completion_tokens": 5,
                "cumulative_total_tokens": 25,
                "iterations": 1,
                "tool_call_count": 0,
            }

        def chat_completion(self, messages, **kwargs):
            self.repair_kwargs = kwargs
            return {
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {
                            "role": "assistant",
                            "content": json.dumps(
                                {
                                    "type": "validation_result",
                                    "issue_id": "ISSUE_7",
                                    "verdict": "uncertain",
                                    "reasoning": "Evidence is incomplete.",
                                    "blocking_negative_evidence": False,
                                    "missing_context": ["callee lifetime contract"],
                                }
                            ),
                        },
                    }
                ],
                "model": "repair-model",
                "usage": {"prompt_tokens": 30, "completion_tokens": 10},
            }

    llm = FakeLLM()
    agent = ValidatorAgent(llm, [])

    response = agent.run({"finding": {"id": "ISSUE_7"}, "context_code": ""}, max_retries=1)

    assert response.success is True
    assert response.data["verdict"] == "uncertain"
    assert response.data["validator_json_repaired"] is True
    assert response.data["validator_repair_error_type"] == "prose_without_json"
    assert response.metadata["validator_repair_attempted"] == 1
    assert response.metadata["validator_repair_accepted"] == 1
    assert llm.repair_kwargs["tools"][0]["function"]["name"] == "emit_validation_result"


def test_validator_agent_repairs_with_final_emit_tool_call() -> None:
    class FakeLLM:
        models = ["repair-model"]
        supports_structured_output = False

        def run_conversation_with_tools(self, **kwargs):
            return {
                "content": "",
                "conversation": [
                    {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {
                                "id": "call_lookup",
                                "type": "function",
                                "function": {
                                    "name": "get_file_snippet",
                                    "arguments": json.dumps({"file_path": "src/demo.c"}),
                                },
                            }
                        ],
                    }
                ],
                "finish_reason": "tool_calls",
                "provider_model": "repair-model",
                "final_tool_call_without_json": True,
                "final_tool_call_count": 1,
                "iterations": 1,
                "tool_call_count": 0,
            }

        def chat_completion(self, messages, **kwargs):
            return {
                "choices": [
                    {
                        "finish_reason": "tool_calls",
                        "message": {
                            "role": "assistant",
                            "content": "",
                            "tool_calls": [
                                {
                                    "id": "call_emit",
                                    "type": "function",
                                    "function": {
                                        "name": "emit_validation_result",
                                        "arguments": json.dumps(
                                            {
                                                "type": "validation_result",
                                                "issue_id": "ISSUE_8",
                                                "verdict": "rejected",
                                                "reasoning": "Guard rejects the path.",
                                                "blocking_negative_evidence": True,
                                                "negative_evidence": ["len is checked"],
                                            }
                                        ),
                                    },
                                }
                            ],
                        },
                    }
                ],
                "model": "repair-model",
                "usage": {"prompt_tokens": 30, "completion_tokens": 10},
            }

    agent = ValidatorAgent(FakeLLM(), [])

    response = agent.run({"finding": {"id": "ISSUE_8"}, "context_code": ""}, max_retries=1)

    assert response.success is True
    assert response.data["issue_id"] == "ISSUE_8"
    assert response.data["verdict"] == "rejected"
    assert response.data["validator_repair_error_type"] == "final_tool_call_without_json"
    assert response.metadata["validator_final_tool_call_count"] >= 1
