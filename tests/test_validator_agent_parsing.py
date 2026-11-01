import json

from zscope.agents.validator_agent.agent import ValidatorAgent, _tool_result_evidence_atoms


def _agent() -> ValidatorAgent:
    return ValidatorAgent.__new__(ValidatorAgent)


def test_v3_tool_evidence_atoms_ignore_empty_and_request_echoes() -> None:
    assert (
        _tool_result_evidence_atoms(
            {"success": True, "query": "different symbol", "results": [], "duration_ms": 2}
        )
        == set()
    )
    assert (
        _tool_result_evidence_atoms(
            {"success": False, "error": "not found", "results": ["misleading"]}
        )
        == set()
    )


def test_v3_tool_evidence_atoms_detect_new_program_facts() -> None:
    first = _tool_result_evidence_atoms(
        {"success": True, "results": [{"file": "src/demo.c", "line": 12, "code": "sink(x);"}]}
    )
    rewrapped = _tool_result_evidence_atoms(
        {
            "success": True,
            "query": "another request",
            "metadata": {"timestamp": "later"},
            "results": [{"file": "src/demo.c", "line": 12, "code": "sink(x);"}],
        }
    )

    assert first
    assert rewrapped == first


def test_validator_agent_accepts_wrapped_validation_result() -> None:
    content = """```json
{
  "validation_result": {
    "issue_id": "ISSUE_1",
    "verdict": "verified",
    "confidence_score": 0.91,
    "reasoning": "evidence proves the path"
  }
}
```"""

    parsed = _agent()._extract_validation_payload(content, {}, [])

    assert parsed == {
        "type": "validation_result",
        "issue_id": "ISSUE_1",
        "verdict": "verified",
        "confidence_score": 0.91,
        "reasoning": "evidence proves the path",
        "is_valid": True,
    }


def test_validator_agent_accepts_result_wrapper_and_verdict_alias() -> None:
    content = '{"result": {"issue_id": "ISSUE_2", "verdict": "needs_review"}}'

    parsed = _agent()._extract_validation_payload(content, {}, [])

    assert parsed["type"] == "validation_result"
    assert parsed["verdict"] == "uncertain"
    assert parsed["is_valid"] is False


def test_validator_agent_normalizes_legacy_boolean_result() -> None:
    content = '{"is_valid": "false", "reasoning": "guard disproves it"}'

    parsed = _agent()._extract_validation_payload(content, {}, [])

    assert parsed["type"] == "validation_result"
    assert parsed["verdict"] == "rejected"
    assert parsed["is_valid"] is False


def test_validator_agent_does_not_accept_embedded_finding_verdict() -> None:
    content = (
        '{"finding": {"id": "ISSUE_3", "verdict": "verified"}, "notes": "not a validator result"}'
    )

    assert _agent()._extract_validation_payload(content, {}, []) is None


def test_validator_agent_accepts_validation_result_list_wrapper() -> None:
    content = '{"validation_results": [{"issue_id": "ISSUE_4", "verdict": "confirmed"}]}'

    parsed = _agent()._extract_validation_payload(content, {}, [])

    assert parsed["type"] == "validation_result"
    assert parsed["issue_id"] == "ISSUE_4"
    assert parsed["verdict"] == "verified"
    assert parsed["is_valid"] is True


def test_validator_agent_run_does_not_retry_for_recoverable_wrapper() -> None:
    class FakeLLM:
        def __init__(self) -> None:
            self.calls = 0

        def run_conversation_with_tools(self, **kwargs):
            self.calls += 1
            return {
                "content": '{"data": {"issue_id": "ISSUE_5", "verdict": "verified"}}',
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


def test_validator_agent_uncertain_fast_path_requires_reasoning() -> None:
    assert (
        ValidatorAgent._accept_fast_path_result(
            {
                "type": "validation_result",
                "verdict": "uncertain",
                "reasoning": "  ",
                "missing_context": ["callee guard contract"],
            }
        )
        is False
    )


def test_validator_agent_fast_path_defers_confidence_policy_to_pipeline() -> None:
    for verdict in ("verified", "rejected"):
        assert (
            ValidatorAgent._accept_fast_path_result(
                {
                    "type": "validation_result",
                    "verdict": verdict,
                    "confidence_score": 0.42,
                    "reasoning": "The structured evidence supports a terminal triage decision.",
                    "missing_context": ["additional contract evidence"],
                }
            )
            is True
        )


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
