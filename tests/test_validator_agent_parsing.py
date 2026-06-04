from zscope.agents.validator_agent.agent import ValidatorAgent


def _agent() -> ValidatorAgent:
    return ValidatorAgent.__new__(ValidatorAgent)


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
    content = '{"finding": {"id": "ISSUE_3", "verdict": "verified"}, "notes": "not a validator result"}'

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
