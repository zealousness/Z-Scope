"""Model calls and publication can be joined without guessing from timing."""

from test_json_output_agents import SinglePassLLM, _semantic_model_input, _snapshot_payload
from zscope.agents.semantic_modeler.agent import SemanticModeler
from zscope.agents.semantic_modeler.retry import run_semantic_model_with_retries
from zscope.framework.base import AgentResponse
from zscope.framework.llm_usage import LLMUsageAttribution
from zscope.semantics.contracts import semantic_model_unit_uid


def test_model_trace_identifies_symbol_and_attempt():
    context = _semantic_model_input(semantic_model_attempt=2)
    llm = SinglePassLLM(_snapshot_payload())
    assert SemanticModeler(llm, []).run(context).success
    attribution = LLMUsageAttribution.from_trace(
        trace_agent="semantic_modeler",
        trace_label=llm.calls[0]["trace_label"],
    )
    assert attribution.audit_unit_uid == semantic_model_unit_uid(context)
    assert attribution.call_kind == "semantic_modeling_attempt_2"
    assert attribution.stage == "semantic_modeling"
    assert (
        semantic_model_unit_uid(dict(context, start_line=50, end_line=51))
        == attribution.audit_unit_uid
    )
    assert semantic_model_unit_uid(dict(context, file_path="other.c")) != attribution.audit_unit_uid


def test_fresh_retries_carry_distinct_attempt_numbers():
    attempts = []

    class Agent:
        def run(self, context):
            attempts.append(context["semantic_model_attempt"])
            return AgentResponse(
                success=len(attempts) == 3,
                data={},
                metadata={"terminal_loop_guard_triggered": len(attempts) < 3},
            )

    context = {"index_name": "target@unit.c:1-1"}
    result = run_semantic_model_with_retries(Agent, context)
    assert result.success and attempts == [1, 2, 3]
    assert "semantic_model_attempt" not in context
