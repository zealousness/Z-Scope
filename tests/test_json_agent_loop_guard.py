from zscope.agents.base import JsonToolAgent
from zscope.framework.base import AgentResponse
from zscope.framework.llm_client import LLMClient


class LoopGuardAgent(JsonToolAgent):
    def __init__(self, llm_client: LLMClient):
        super().__init__(
            name="loop_guard_agent",
            description="loop guard test agent",
            llm_client=llm_client,
            tools=[],
        )

    def run(self, input_data):
        return AgentResponse(success=True, data={})


def test_json_tool_agent_does_not_retry_after_tool_loop_guard(monkeypatch) -> None:
    client = LLMClient(
        api_key="test",
        base_url="http://example.invalid",
        models=["unit-model"],
    )
    agent = LoopGuardAgent(client)

    def fake_run_tool_conversation(*args, **kwargs):
        return {
            "content": "",
            "conversation": [],
            "iterations": 2,
            "truncated": True,
            "loop_guard_triggered": True,
            "repeated_tool_call": {
                "tool": "get_file_snippet",
                "arguments": {"file_path": "src/demo.c"},
                "repeat_count": 2,
            },
            "context_tokens": 100,
            "cumulative_prompt_tokens": 90,
            "cumulative_completion_tokens": 10,
            "cumulative_total_tokens": 100,
        }

    def fail_retry(*args, **kwargs):
        raise AssertionError("JSON retry should not run after loop guard")

    monkeypatch.setattr(agent, "_run_tool_conversation", fake_run_tool_conversation)
    monkeypatch.setattr(client, "chat_completion", fail_retry)

    response = agent._run_json_conversation(
        [{"role": "user", "content": "start"}],
        extractor=lambda content, result, conversation: None,
        trace_label="loop",
        parse_label="payload",
        retry_prompt="retry",
    )

    assert response.success is False
    assert response.error == "Stopped after repeated identical tool calls."
    assert response.metadata["loop_guard_triggered"] is True
    assert response.metadata["repeated_tool_call"]["tool"] == "get_file_snippet"
