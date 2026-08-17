from zscope.config.config import AnalysisConfig
from zscope.orchestration.budget import RiskBudgetPlanner


def _planner() -> RiskBudgetPlanner:
    return RiskBudgetPlanner(
        AnalysisConfig(
            max_recursion_depth=6,
            max_premodel_depth=5,
            max_premodel_callees=80,
        )
    )


def test_adaptive_budget_keeps_low_risk_functions_below_hard_caps() -> None:
    planner = _planner()
    state = {
        "impl_result": {
            "code": "int trivial(int x) { return x + 1; }",
            "callees": [],
        },
        "agent_context": {"code": "int trivial(int x) { return x + 1; }"},
    }

    budget = planner.plan(state)

    assert budget.recursion_depth == 1
    assert budget.premodel_depth == 1
    assert budget.premodel_callees <= 8
    assert budget.recursion_depth <= budget.hard_caps["max_recursion_depth"]
    assert budget.premodel_depth <= budget.hard_caps["max_premodel_depth"]
    assert budget.premodel_callees <= budget.hard_caps["max_premodel_callees"]


def test_zero_hard_caps_disable_their_effective_budgets() -> None:
    planner = RiskBudgetPlanner(
        AnalysisConfig(
            max_recursion_depth=0,
            max_premodel_depth=0,
            max_premodel_callees=0,
        )
    )
    state = {
        "impl_result": {
            "code": "int entry(void) { return malloc(16) != 0; }",
        },
        "agent_context": {},
    }

    budget = planner.plan(
        state,
        graph_candidates=[{"candidate_source": "graph_rule", "rule_confidence": 0.9}],
    )

    assert budget.recursion_depth == 0
    assert budget.premodel_depth == 0
    assert budget.premodel_callees == 0
    assert budget.graph_depth == 0
    assert budget.graph_functions == 0


def test_adaptive_budget_uses_separate_risk_signals_per_budget_type() -> None:
    planner = _planner()
    low = planner.plan(
        {
            "impl_result": {"code": "int trivial(int x) { return x + 1; }"},
            "agent_context": {"code": "int trivial(int x) { return x + 1; }"},
        }
    )
    state = {
        "impl_result": {
            "code": """
            int dispatch_msg(struct ctx *ctx, int opcode) {
                switch (opcode) {
                case 1:
                    register_callback(ctx, on_event);
                    return alloc_session(ctx);
                case 2:
                    pthread_create(&ctx->tid, 0, worker, ctx);
                    return cleanup_session(ctx);
                default:
                    return close_session(ctx);
                }
            }
            """,
            "callees": [
                "register_callback",
                "alloc_session",
                "cleanup_session",
                "close_session",
                "pthread_create",
            ],
        },
        "agent_context": {
            "user_config_context": "[Relevant user-config pairs]\n  lifecycle: alloc_session <-> cleanup_session"
        },
        "verified_hist_issues": [{"id": "old-1"}],
    }
    graph_candidates = [
        {
            "candidate_source": "graph_rule",
            "rule_confidence": 0.9,
            "skill": "resource_lifecycle",
        }
    ]

    budget = planner.plan(state, graph_candidates=graph_candidates)

    assert budget.recursion_depth > low.recursion_depth
    assert budget.premodel_depth > low.premodel_depth
    assert budget.premodel_callees > low.premodel_callees
    assert "graph_candidate_requires_cross_function_trace" in budget.risk_reasons["recursion_depth"]
    assert "user_config_protocol_or_pair_context" in budget.risk_reasons["premodel_depth"]


def test_adaptive_budget_expands_thin_protocol_facades() -> None:
    planner = _planner()
    state = {
        "impl_result": {
            "code": "int api_schedule(int fast) { return runtime_dispatch_event_cycle(fast); }",
            "callees": ["runtime_dispatch_event_cycle"],
        },
        "agent_context": {
            "code": "int api_schedule(int fast) { return runtime_dispatch_event_cycle(fast); }"
        },
    }

    budget = planner.plan(state)

    assert budget.premodel_depth >= 2
    assert budget.graph_depth >= 2
    assert "thin_public_facade_requires_callee_context" in budget.risk_reasons["premodel_depth"]
