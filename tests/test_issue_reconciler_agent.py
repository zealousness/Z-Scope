import json

from zscope.agents.issue_reconciler.agent import IssueReconcilerAgent
from zscope.framework.base import AgentResponse


def test_issue_reconciler_deduplicate_cluster_normalizes_valid_schema(monkeypatch) -> None:
    agent = IssueReconcilerAgent(object())  # type: ignore[arg-type]

    def fake_call(_prompt):
        return AgentResponse(
            success=True,
            data={
                "duplicate_groups": [
                    {
                        "primary_issue_id": "ISSUE_A",
                        "duplicate_issue_ids": ["ISSUE_B"],
                        "root_cause_key": "race|src/demo.c|worker|g_tasks",
                        "confidence": "0.91",
                        "reasoning": "same resource and same root cause",
                    }
                ],
                "must_keep_distinct_issue_ids": ["ISSUE_C"],
            },
        )

    monkeypatch.setattr(agent, "_call_llm", fake_call)

    response = agent.run(
        {
            "mode": "deduplicate_cluster",
            "cluster_id": "cluster",
            "issues": [
                {"id": "ISSUE_A", "category": "race", "function": "worker"},
                {"id": "ISSUE_B", "category": "shared_state_race", "function": "worker"},
                {"id": "ISSUE_C", "category": "race", "function": "worker"},
            ],
        }
    )

    assert response.success is True
    assert response.data["duplicate_groups"][0]["confidence"] == 0.91
    assert response.data["must_keep_distinct_issue_ids"] == ["ISSUE_C"]


def test_issue_reconciler_deduplicate_cluster_rejects_invalid_schema(monkeypatch) -> None:
    agent = IssueReconcilerAgent(object())  # type: ignore[arg-type]
    monkeypatch.setattr(
        agent,
        "_call_llm",
        lambda _prompt: AgentResponse(
            success=True,
            data={
                "duplicate_groups": [
                    {
                        "primary_issue_id": "ISSUE_A",
                        "duplicate_issue_ids": ["MISSING"],
                        "confidence": 0.95,
                    }
                ],
                "must_keep_distinct_issue_ids": [],
            },
        ),
    )

    response = agent.run(
        {
            "mode": "deduplicate_cluster",
            "issues": [
                {"id": "ISSUE_A", "category": "race"},
                {"id": "ISSUE_B", "category": "race"},
            ],
        }
    )

    assert response.success is False
    assert "Invalid deduplicate_cluster" in str(response.error)


def test_issue_reconciler_repairs_non_json_deduplicate_response(monkeypatch) -> None:
    class FakeLLM:
        models = ["unit-model"]
        supports_structured_output = False

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
                                        "name": "emit_deduplicate_decision",
                                        "arguments": json.dumps(
                                            {
                                                "is_duplicate": False,
                                                "matched_historical_id": None,
                                                "reasoning": "Distinct root cause.",
                                            }
                                        ),
                                    },
                                }
                            ],
                        },
                    }
                ],
                "model": "unit-model",
                "usage": {"prompt_tokens": 10, "completion_tokens": 4},
            }

    agent = IssueReconcilerAgent(FakeLLM())  # type: ignore[arg-type]

    monkeypatch.setattr(
        agent,
        "_run_tool_conversation",
        lambda *args, **kwargs: {
            "content": "They look different.",
            "conversation": [{"role": "assistant", "content": "They look different."}],
            "finish_reason": "stop",
            "iterations": 1,
        },
    )

    response = agent.run(
        {
            "mode": "deduplicate",
            "historical_issues": [{"id": "ISSUE_A", "description": "old"}],
            "new_issue": {"id": "ISSUE_B", "description": "new"},
        }
    )

    assert response.success is True
    assert response.data["is_duplicate"] is False
    assert response.metadata["issue_reconciler_repair_attempted"] == 1
    assert response.metadata["issue_reconciler_repair_accepted"] == 1
