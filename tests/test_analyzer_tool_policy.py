from zscope.core.analysis.analyzer import Analyzer
from zscope.orchestration.agent_policy import attach_agent_contract
from zscope.orchestration.specs import SpecRegistry


def _analyzer_with_specs() -> Analyzer:
    analyzer = object.__new__(Analyzer)
    analyzer.spec_registry = SpecRegistry()
    return analyzer


def test_agent_tool_policy_uses_agent_allowlist() -> None:
    analyzer = _analyzer_with_specs()

    policy = analyzer._tool_policy_for_agent("proof_engine")

    assert policy.enforce_tool("get_function_info", {}, actor="test") is None
    assert policy.enforce_tool("get_data_flow", {}, actor="test") is None
    blocked_impl = policy.enforce_tool("get_function_impl", {}, actor="test")
    assert blocked_impl is not None
    assert blocked_impl["policy_decision"] == "deny"


def test_hypothesis_hunter_policy_is_tool_free() -> None:
    analyzer = _analyzer_with_specs()

    policy = analyzer._tool_policy_for_agent(
        "hypothesis_hunter",
        active_skill_names=["stack_escape"],
    )

    for tool_name in ("get_file_snippet", "get_data_flow"):
        blocked = policy.enforce_tool(tool_name, {}, actor="test")
        assert blocked is not None
        assert blocked["policy_decision"] == "deny"


def test_prompt_contract_lists_only_visible_tools() -> None:
    context = {}
    attach_agent_contract(
        context,
        "hypothesis_hunter",
        SpecRegistry(),
        active_skill_names=["stack_escape"],
        visible_tool_names=[],
    )

    assert "Allowed tools: none" in context["agent_contract"]
    assert "skill_contracts" not in context
