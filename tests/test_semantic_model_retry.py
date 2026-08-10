from copy import deepcopy

from zscope.agents.semantic_modeler.retry import run_semantic_model_with_retries
from zscope.framework.base import AgentResponse


def _guarded_response(attempt: int) -> AgentResponse:
    return AgentResponse(
        success=False,
        data={},
        error="terminal guard",
        metadata={
            "reason": "terminal_tool_loop_guard",
            "terminal_loop_guard_triggered": True,
            "terminal_loop_guard_reason": "identical_invalid_terminal_call_limit",
            "context_tokens": 10 * attempt,
            "cumulative_prompt_tokens": 6 * attempt,
            "cumulative_completion_tokens": 4 * attempt,
            "cumulative_total_tokens": 10 * attempt,
            "iterations": 3,
            "api_call_count": 3,
            "tool_call_count": 1,
            "terminal_tool_call_count": 3,
            "terminal_invalid_call_count": 3,
        },
    )


def test_semantic_retry_uses_fresh_agents_and_aggregates_metadata() -> None:
    original_context = {
        "index_name": "demo@demo.c:1-3",
        "nested": {"value": "original"},
    }
    contexts = []
    created_agents = []

    class FakeAgent:
        def __init__(self, attempt: int):
            self.attempt = attempt

        def run(self, context):
            contexts.append(context)
            context["nested"]["value"] = f"attempt-{self.attempt}"
            if self.attempt == 1:
                return _guarded_response(self.attempt)
            return AgentResponse(
                success=True,
                data={"type": "function_snapshot", "summary": "done"},
                metadata={
                    "context_tokens": 20,
                    "cumulative_prompt_tokens": 12,
                    "cumulative_completion_tokens": 8,
                    "cumulative_total_tokens": 20,
                    "iterations": 2,
                    "api_call_count": 2,
                    "tool_call_count": 2,
                    "terminal_tool_call_count": 1,
                    "terminal_invalid_call_count": 0,
                },
            )

    def factory():
        agent = FakeAgent(len(created_agents) + 1)
        created_agents.append(agent)
        return agent

    response = run_semantic_model_with_retries(factory, original_context)

    assert response.success is True
    assert len(created_agents) == 2
    assert contexts[0] is not contexts[1]
    assert original_context == {
        "index_name": "demo@demo.c:1-3",
        "nested": {"value": "original"},
    }
    assert response.metadata["semantic_model_attempt_count"] == 2
    assert response.metadata["semantic_model_retry_count"] == 1
    assert response.metadata["context_tokens"] == 30
    assert response.metadata["cumulative_prompt_tokens"] == 18
    assert response.metadata["cumulative_completion_tokens"] == 12
    assert response.metadata["cumulative_total_tokens"] == 30
    assert response.metadata["iterations"] == 5
    assert response.metadata["api_call_count"] == 5
    assert response.metadata["terminal_tool_call_count"] == 4
    assert response.metadata["terminal_invalid_call_count"] == 3
    assert response.metadata["terminal_loop_guard_triggered"] is False
    assert response.metadata["semantic_model_attempts"][0]["terminal_loop_guard_triggered"] is True


def test_semantic_retry_stops_after_two_retries() -> None:
    attempts = []

    class GuardedAgent:
        def run(self, context):
            attempts.append(deepcopy(context))
            return _guarded_response(len(attempts))

    response = run_semantic_model_with_retries(
        GuardedAgent,
        {"index_name": "demo@demo.c:1-3"},
    )

    assert response.success is False
    assert len(attempts) == 3
    assert response.metadata["semantic_model_attempt_count"] == 3
    assert response.metadata["semantic_model_retry_count"] == 2
    assert response.metadata["terminal_loop_guard_triggered"] is True
    assert response.metadata["context_tokens"] == 60


def test_semantic_retry_does_not_retry_non_guard_failure() -> None:
    calls = []

    class FailingAgent:
        def run(self, context):
            calls.append(context)
            return AgentResponse(
                success=False,
                data={},
                error="api unavailable",
                metadata={
                    "reason": "semantic_model_exception",
                    "context_tokens": 7,
                },
            )

    response = run_semantic_model_with_retries(
        FailingAgent,
        {"index_name": "demo@demo.c:1-3"},
    )

    assert response.success is False
    assert len(calls) == 1
    assert response.metadata["semantic_model_attempt_count"] == 1
    assert response.metadata["semantic_model_retry_count"] == 0
    assert response.metadata["context_tokens"] == 7
