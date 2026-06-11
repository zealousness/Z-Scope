import json

from zscope.agents.deep_worker.agent import DeepWorkerAgent
from zscope.agents.semantic_modeler.agent import SemanticModeler
from zscope.agents.vulnerability_analyzer.agent import VulnerabilityAnalyzer


class RepairLLM:
    models = ["unit-model"]
    supports_structured_output = False

    def __init__(self, tool_name: str, payload: dict):
        self.tool_name = tool_name
        self.payload = payload

    def chat_completion(self, messages, **kwargs):
        assert kwargs["tools"][0]["function"]["name"] == self.tool_name
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
                                    "name": self.tool_name,
                                    "arguments": json.dumps(self.payload),
                                },
                            }
                        ],
                    },
                }
            ],
            "model": "unit-model",
            "usage": {"prompt_tokens": 10, "completion_tokens": 4},
        }


def _prose_result(text: str = "I can provide the JSON now."):
    return {
        "content": text,
        "conversation": [{"role": "assistant", "content": text}],
        "finish_reason": "stop",
        "provider_model": "unit-model",
        "iterations": 1,
        "tool_call_count": 0,
    }


def test_semantic_modeler_repairs_function_snapshot(monkeypatch) -> None:
    agent = SemanticModeler(
        RepairLLM(
            "emit_function_snapshot",
            {
                "type": "function_snapshot",
                "func_name": "api_entry",
                "summary": "demo",
                "key_semantics": [],
                "inputs": [],
            },
        ),
        [],
    )
    monkeypatch.setattr(agent, "_run_tool_conversation", lambda *args, **kwargs: _prose_result())

    response = agent.run({"func_name": "api_entry", "code": "void api_entry(void) {}", "location": "demo.c:1"})

    assert response.success is True
    assert response.data["type"] == "function_snapshot"
    assert response.metadata["snapshot_repair_attempted"] == 1
    assert response.metadata["snapshot_repair_accepted"] == 1


def test_vulnerability_analyzer_repairs_final_report(monkeypatch) -> None:
    agent = VulnerabilityAnalyzer(
        RepairLLM(
            "emit_final_report",
            {"type": "final_report", "issues": [], "candidate_coverage": []},
        ),
        [],
    )
    monkeypatch.setattr(agent, "_run_tool_conversation", lambda *args, **kwargs: _prose_result(""))

    response = agent.run({"func_name": "api_entry", "code": "void api_entry(void) {}"}, max_iterations=1)

    assert response.success is True
    assert response.data["type"] == "final_report"
    assert response.data["issues"] == []
    assert response.metadata["report_repair_attempted"] == 1


def test_deep_worker_preserves_partial_failure_metadata(monkeypatch) -> None:
    class BadRepairLLM:
        models = ["unit-model"]
        supports_structured_output = False

        def chat_completion(self, messages, **kwargs):
            return {
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": "still no JSON"},
                    }
                ],
                "model": "unit-model",
                "usage": {"prompt_tokens": 10, "completion_tokens": 4},
            }

    agent = DeepWorkerAgent(BadRepairLLM(), [])  # type: ignore[arg-type]
    monkeypatch.setattr(
        agent,
        "_run_tool_conversation",
        lambda *args, **kwargs: {
            "content": "partial analysis text",
            "conversation": [{"role": "assistant", "content": "partial analysis text"}],
            "finish_reason": "stop",
            "truncated": True,
            "iterations": 2,
            "tool_call_count": 1,
        },
    )

    response = agent.run({"ticket": {"id": "T1"}, "context_slice": "", "max_iterations": 2})

    assert response.success is False
    assert response.data["partial_result"] == "partial analysis text"
    assert response.metadata["failure_kind"] == "partial"
    assert response.metadata["needs_human_review"] is True
