from __future__ import annotations

from types import SimpleNamespace
from semantic_fixtures import configured_test_semantics
from zscope.semantics.contracts import ApiContract

import pytest

from zscope.core.analysis.analyzer import Analyzer
from zscope.core.candidates.regex import (
    RegexCandidateGenerator,
    LocalPatternSemantics,
)
from zscope.core.candidates.graph import FunctionView, GraphCandidateGenerator
from zscope.core.candidates.adapters import dedupe_rule_candidates
from zscope.core.candidates.backend_signals import (
    class_from_joern_category,
    split_config_pair_names,
)
from zscope.common.issue_identity import normalize_issue_category, normalize_issue_fields
from zscope.core.validation.evidence import compact_snapshot
from zscope.orchestration.candidates import CandidateLedger
from zscope.orchestration.skill_selection import SkillSelection
from zscope.semantics.inference import add_api_from_semantic_text, snapshot_contract_text
from zscope.snapshots.policy import (
    DETERMINISTIC_SNAPSHOT_OPTIONAL_FIELDS,
    DETERMINISTIC_SNAPSHOT_REQUIRED_FIELDS,
)
from zscope.rules.engine import RuleMatch


def _graph_view(
    generator: GraphCandidateGenerator,
    name: str,
    code: str,
    *,
    signature: str | None = None,
) -> FunctionView:
    return FunctionView(
        name=name,
        file_path="src/lifecycle.c",
        signature=signature or f"int {name}(RealModelNode *node)",
        lines=tuple(generator._parse_lines(code)),
        callees=(),
    )


class NullCodeIndex:
    def get_function_impl(self, name: str, warn_missing: bool = False, max_lines=None):
        return None


def test_java_entry_lookup_keeps_the_qualified_method_identifier() -> None:
    entry_function = "demo.Controller.load:java.lang.String(java.lang.String)"
    descriptor = "java.lang.String(java.lang.String)"

    assert Analyzer._entry_lookup_query(entry_function, descriptor, "java") == entry_function
    assert Analyzer._entry_lookup_query("load", "int load(int value)", "c_cpp") == (
        "int load(int value)"
    )


def test_snapshot_semantic_text_does_not_reclassify_described_function_as_api() -> None:
    semantics = LocalPatternSemantics()
    analyzer = object.__new__(Analyzer)
    text = """
    {
      "resources": {"locks": [{"release_line": 744}]},
      "summary": "walks a global list, acquires pipe->ctrl_lock, releases it before return",
      "cleanup_on_error": "no dynamic memory allocation; no cleanup required"
    }
    """

    add_api_from_semantic_text(
        semantics,
        "_lifecycle_tick_timer_callback",
        text,
        "semantic_snapshot",
    )

    assert "_lifecycle_tick_timer_callback" not in semantics.lock_apis
    assert "_lifecycle_tick_timer_callback" not in semantics.unlock_apis
    assert "_lifecycle_tick_timer_callback" not in semantics.deallocators


def test_llm_iteration_budget_is_observed_without_hard_failure() -> None:
    analyzer = object.__new__(Analyzer)
    analyzer.config = SimpleNamespace(analysis=SimpleNamespace(max_tool_iterations=50))
    state = {"budget_observations": [], "any_failure": False}
    response = SimpleNamespace(
        success=False,
        error="Max iterations reached without finding a JSON report in history",
        metadata={"truncated": True, "iterations": 50},
    )

    reached = analyzer._record_llm_iteration_budget(
        state,
        response,
        agent_name="vulnerability_analyzer",
        outcome="incomplete",
    )

    assert reached is True
    assert state["any_failure"] is False
    assert state["budget_observations"] == [
        {
            "kind": "llm_iteration_budget",
            "agent": "vulnerability_analyzer",
            "configured_iterations": 50,
            "observed_iterations": 50,
            "budget_reached": True,
            "outcome": "incomplete",
            "hard_failure": False,
        }
    ]


def test_candidate_first_skips_entry_scoped_investigator_planning() -> None:
    analyzer = object.__new__(Analyzer)
    recorded = []
    analyzer._record_engine_capability = lambda *args, **kwargs: recorded.append((args, kwargs))
    state = {"notes": []}

    analyzer._step_focused_subagent_planning(state)

    assert "stable candidate-first" in state["notes"][0]
    assert recorded == [
        (
            ("focused_investigators",),
            {
                "status": "complete",
                "active": False,
                "reason": "stable_candidate_first_lifecycle",
            },
        )
    ]


def test_candidate_first_uses_local_skill_routing_before_fact_collection() -> None:
    batch = SimpleNamespace(
        local_candidates=[],
        graph_candidates=[],
        backend_candidates=[],
        merged_candidates=[],
        summary_increment=lambda: {},
    )
    analyzer = object.__new__(Analyzer)
    analyzer.config = SimpleNamespace(
        project=SimpleNamespace(
            agents=[
                SimpleNamespace(
                    enabled=True,
                    name="vulnerability_analyzer",
                    task="Audit memory and concurrency defects",
                    skills=[],
                )
            ]
        ),
        analysis=SimpleNamespace(semantic_snapshot_candidate_mode="off"),
    )
    analyzer.candidate_pipeline = SimpleNamespace(
        collect_signal_candidates=lambda state: batch,
        accumulate_summary=lambda state, candidate_batch: None,
        persist=lambda candidate_batch: None,
    )
    observed_configs = []
    analyzer._candidate_first_skill_selection = lambda cfg: (
        observed_configs.append(cfg) or SkillSelection(skills=[], restricted=False)
    )
    analyzer._attach_agent_contract = lambda *args, **kwargs: None
    analyzer._compact_candidate_signal_items = lambda *args, **kwargs: []
    analyzer._register_candidate_issues = lambda *args, **kwargs: None
    analyzer._deduplicate_against_history = lambda candidates, state: candidates
    analyzer._record_engine_capability = lambda *args, **kwargs: None
    state = {"agent_context": {}, "pending_new_issues": [], "notes": []}

    analyzer._step_vulnerability_mining(state)

    assert observed_configs == [analyzer.config.project.agents[0]]
    assert state["pending_new_issues"] == []


def test_candidate_first_skill_selection_keeps_every_deterministic_skill() -> None:
    analyzer = object.__new__(Analyzer)
    skills = {
        name: SimpleNamespace(name=name, languages=["c_cpp"])
        for name in (
            "bounds_and_integer",
            "resource_lifecycle",
            "shared_state_race",
        )
    }
    analyzer.config = SimpleNamespace(project=SimpleNamespace(language="c_cpp"))
    analyzer.spec_registry = SimpleNamespace(
        skills_for_agent=lambda name, extra: [
            skills["bounds_and_integer"],
            skills["resource_lifecycle"],
            skills["shared_state_race"],
        ],
        skills=skills,
        get_skill=skills.get,
    )

    selection = analyzer._candidate_first_skill_selection(SimpleNamespace(skills=[]))

    assert selection.skills == [
        "bounds_and_integer",
        "resource_lifecycle",
        "shared_state_race",
    ]
    assert selection.restricted is False
    assert selection.source == "candidate_first_complete"


def test_snapshot_contract_text_prefers_new_fields_and_keeps_legacy_fallback() -> None:
    current = snapshot_contract_text(
        {
            "summary": "checked allocation wrapper",
            "return_values": {"failure_cases": [{"value": "NULL"}]},
            "effects": [{"category": "memory", "api": "malloc"}],
            "error_handling": {"error_paths": [{"exit_action": "return NULL"}]},
        }
    )
    legacy = snapshot_contract_text(
        {
            "summary": "legacy wrapper",
            "outputs": ["pointer"],
            "resources": {"allocation": "malloc"},
            "concurrency": {},
            "key_semantics": ["caller owned"],
        }
    )

    assert "failure_cases" in current
    assert "malloc" in current
    assert "caller owned" in legacy


def test_facade_callee_candidates_recurse_into_internal_helpers() -> None:
    class FakeIndex:
        def get_function_impl(self, name: str, warn_missing: bool = False, max_lines=None):
            impls = {
                "_outer": {
                    "file": "src/demo.c",
                    "code": "1 | int _outer(size_t n) { return _inner(n); }",
                    "callees": ["_inner"],
                },
                "_inner": {
                    "file": "src/demo.c",
                    "code": """
10 | int _inner(size_t n) {
11 |     char* p = _safe_malloc(n * 64);
12 |     return p ? 0 : -1;
13 | }
""",
                    "callees": [],
                },
            }
            return impls.get(name)

    analyzer = object.__new__(Analyzer)
    analyzer.code_index = FakeIndex()
    issues = analyzer._detect_direct_callee_rule_candidates(
        {"callees": ["_outer"]},
        RegexCandidateGenerator(),
    )

    assert any(issue.get("function") == "_inner" for issue in issues)


def test_facade_callee_candidates_expand_dispatcher_siblings_at_depth_cap() -> None:
    class FakeIndex:
        def get_function_impl(self, name: str, warn_missing: bool = False, max_lines=None):
            impls = {
                "dispatch_msg": {
                    "file": "src/demo.c",
                    "code": """
1 | int dispatch_msg(int type, size_t n) {
2 |     switch (type) {
3 |     case 1: return handle_a();
4 |     case 2: return handle_b(n);
5 |     default: return handle_c();
6 |     }
7 | }
""",
                    "callees": ["handle_a", "handle_b", "handle_c"],
                },
                "handle_a": {
                    "file": "src/demo.c",
                    "code": "10 | int handle_a(void) { return 0; }",
                    "callees": [],
                },
                "handle_b": {
                    "file": "src/demo.c",
                    "code": """
20 | int handle_b(size_t n) {
21 |     char* p = _safe_malloc(n * 64);
22 |     return p ? 0 : -1;
23 | }
""",
                    "callees": [],
                },
                "handle_c": {
                    "file": "src/demo.c",
                    "code": "30 | int handle_c(void) { return 0; }",
                    "callees": [],
                },
            }
            return impls.get(name)

    analyzer = object.__new__(Analyzer)
    analyzer.code_index = FakeIndex()
    issues = analyzer._detect_direct_callee_rule_candidates(
        {"callees": ["dispatch_msg"]},
        RegexCandidateGenerator(),
        max_depth=1,
    )

    assert any(issue.get("function") == "handle_b" for issue in issues)


def test_direct_callee_fact_limit_is_reported_as_deferred_work() -> None:
    class FakeIndex:
        def get_function_impl(self, name: str, warn_missing: bool = False, max_lines=None):
            return {
                "first": {
                    "file": "src/demo.c",
                    "code": "1 | void first(void) { second(); }",
                    "callees": ["second"],
                },
                "second": {
                    "file": "src/demo.c",
                    "code": "2 | void second(void) {}",
                    "callees": [],
                },
            }.get(name)

    analyzer = object.__new__(Analyzer)
    analyzer.code_index = FakeIndex()
    analyzer.candidate_ledger = CandidateLedger(project_id="demo", revision="rev")
    state = {
        "entry_func": "entry",
        "entry_identity": "src/demo.c::entry(void)",
        "deferred_deterministic_work": [],
    }

    analyzer._detect_direct_callee_rule_candidates(
        {"callees": ["first"]},
        RegexCandidateGenerator(),
        state=state,
        entry_func="entry",
        max_depth=1,
    )

    deferred = state["deferred_deterministic_work"]
    assert [item["function_name"] for item in deferred] == ["second"]
    assert deferred[0]["candidate_disposition"] == "deferred_budget"
    assert (
        analyzer._runtime_engine_capabilities["deterministic_local_rules_callee_facts"]["status"]
        == "degraded"
    )


def test_instance_direct_callee_scan_skips_edges_without_scoped_body() -> None:
    class FakeIndex:
        def __init__(self) -> None:
            self.queries = []

        def has_scoped_function_body(self, name: str) -> bool:
            return name == "local_helper"

        def get_function_impl(self, name: str, **kwargs):
            self.queries.append(name)
            return {
                "file": "src/demo.c",
                "code": "1 | int local_helper(void) { return 0; }",
                "callees": [],
            }

    analyzer = object.__new__(Analyzer)
    analyzer.code_index = FakeIndex()
    analyzer.candidate_ledger = CandidateLedger(project_id="demo", revision="rev")
    state = {
        "entry_func": "entry",
        "entry_identity": "src/demo.c::entry(void)",
        "deferred_deterministic_work": [],
    }

    analyzer._detect_direct_callee_rule_candidates(
        {"callees": ["malloc", "foreign_tu", "local_helper"]},
        RegexCandidateGenerator(),
        state=state,
        entry_func="entry",
    )

    assert analyzer.code_index.queries == ["local_helper"]
    assert state["deferred_deterministic_work"] == []
    assert (
        analyzer._runtime_engine_capabilities["deterministic_local_rules_callee_facts"]["status"]
        == "complete"
    )


def test_direct_callee_scan_budget_expands_to_complete_indexed_project() -> None:
    class FakeIndex:
        def list_functions(self, limit=None):
            assert limit is None
            return ["entry", "first", "second", "third", "fourth"]

    analyzer = object.__new__(Analyzer)
    analyzer.code_index = FakeIndex()
    analyzer.config = type(
        "Config",
        (),
        {"analysis": type("Analysis", (), {"max_premodel_callees": 16, "max_premodel_depth": 2})()},
    )()

    budget = analyzer._direct_callee_rule_scan_budget(
        {"premodel_callees": 2, "premodel_depth": 1, "hard_caps": {}}
    )

    assert budget["max_depth"] >= 5
    assert budget["total_limit"] >= 5


def test_graph_impl_query_failure_is_exposed() -> None:
    class FailingIndex:
        def get_function_impl(self, name: str, warn_missing: bool = False, max_lines=None):
            raise RuntimeError("index offline")

    generator = GraphCandidateGenerator(FailingIndex(), LocalPatternSemantics())
    generator.generate_for_entry(
        "entry",
        {
            "file": "src/demo.c",
            "code": "1 | void entry(void) { child(); }",
            "callees": ["child"],
        },
        max_depth=2,
        max_functions=8,
    )

    assert generator.last_query_errors == [
        {
            "function_name": "child",
            "error": "RuntimeError: index offline",
        }
    ]


def test_graph_candidates_detect_free_wrapper_omitted_dynamic_payload() -> None:
    semantics = configured_test_semantics()
    for name, role, pair, carrier in (
        (
            "_real_model_alloc_node",
            "allocator",
            ["_real_model_free_node", "SAFE_FREE"],
            {"kind": "return"},
        ),
        (
            "_real_model_alloc_node",
            "allocator",
            ["SAFE_FREE"],
            {"kind": "return", "member_path": "->payload"},
        ),
        ("_real_model_free_node", "deallocator", [], {"kind": "argument", "argument_index": 0}),
        ("service_release_by_role", "deallocator", [], {"kind": "argument", "argument_index": 0}),
    ):
        semantics.contracts.add(
            ApiContract.from_row(
                {"symbol_name": name, "kind": role, "pair": pair, "contract": {"carrier": carrier}}
            )
        )
        semantics.add_api(role, name, "user_config")
    semantics.add_api("deallocator", "SAFE_FREE", "user_config")
    generator = GraphCandidateGenerator(object(), semantics)
    creator = _graph_view(
        generator,
        "_real_model_alloc_node",
        """
10 | RealModelNode* _real_model_alloc_node(const char* key) {
11 |     RealModelNode* node = SAFE_CALLOC(1, sizeof(*node));
12 |     node->payload = _str_dup(key);
13 |     return node;
14 | }
""",
    )
    cleanup = _graph_view(
        generator,
        "_real_model_free_node",
        """
20 | void _real_model_free_node(RealModelNode* node) {
21 |     if (!node) return;
22 |     SAFE_FREE(node);
23 | }
""",
    )

    issues = generator.generate_for_views([creator, cleanup])
    leak = next(
        issue for issue in issues if issue["rule"] == "paired_free_wrapper_omits_dynamic_member"
    )

    assert leak["category"] == "memory_leak"
    assert leak["function"] == "_real_model_free_node"
    assert leak["location"] == "src/lifecycle.c:22"
    assert "node->payload" in "\n".join(leak["positive_evidence"])


def test_graph_candidates_detect_helper_alloc_wrapper_member_leak_without_primitive_pair_fp() -> (
    None
):
    semantics = configured_test_semantics()
    for name, role, pair, carrier in (
        (
            "_real_model_alloc_node",
            "allocator",
            ["_real_model_free_node", "SAFE_FREE"],
            {"kind": "return"},
        ),
        (
            "_real_model_alloc_node",
            "allocator",
            ["SAFE_FREE"],
            {"kind": "return", "member_path": "->payload"},
        ),
        ("_real_model_free_node", "deallocator", [], {"kind": "argument", "argument_index": 0}),
        ("service_release_by_role", "deallocator", [], {"kind": "argument", "argument_index": 0}),
    ):
        semantics.contracts.add(
            ApiContract.from_row(
                {"symbol_name": name, "kind": role, "pair": pair, "contract": {"carrier": carrier}}
            )
        )
        semantics.add_api(role, name, "user_config")
    semantics.add_api("deallocator", "SAFE_FREE", "user_config")
    generator = GraphCandidateGenerator(NullCodeIndex(), semantics)
    unregister = _graph_view(
        generator,
        "_real_model_unregister_file_leak",
        """
100 | int _real_model_unregister_file_leak(const char* name) {
101 |     RealModelNode* node = _real_model_alloc_node(name, "/virtual/fs/node");
102 |     SAFE_FREE(node->name);
103 |     SAFE_FREE(node);
104 |     return 0;
105 | }
""",
        signature="int _real_model_unregister_file_leak(const char* name)",
    )
    primitive_release = _graph_view(
        generator,
        "_lifecycle_release_value_slice",
        """
110 | int _lifecycle_release_value_slice(char* line) {
111 |     char* value = strchr(line, '=');
112 |     free(value + 1);
113 |     return 0;
114 | }
""",
        signature="int _lifecycle_release_value_slice(char* line)",
    )

    issues = generator.generate_for_views([unregister, primitive_release])

    leak = next(
        issue
        for issue in issues
        if issue["rule"] == "same_function_helper_alloc_wrapper_member_leak"
    )
    assert leak["category"] == "memory_leak"
    assert leak["function"] == "_real_model_unregister_file_leak"
    assert "payload/path" in leak["description"]
    assert not any(
        issue.get("rule") == "paired_free_wrapper_omits_dynamic_member"
        and issue.get("function") == "_lifecycle_release_value_slice"
        for issue in issues
    )


def test_graph_candidates_detect_paired_key_truncation_before_generic_race_terms() -> None:
    generator = GraphCandidateGenerator(object(), LocalPatternSemantics())
    lookup = _graph_view(
        generator,
        "_real_model_lookup_full_key",
        """
30 | RealModelNode* _real_model_lookup_full_key(const char* full_key) {
31 |     return strcmp(g_rules_map[i].full_key, full_key) == 0 ? g_rules_map[i].node : NULL;
32 | }
""",
    )
    insert = _graph_view(
        generator,
        "_real_model_insert_key",
        """
40 | int _real_model_insert_key(RealModelNode* node, const char* key) {
41 |     strncpy(node->key, key, REAL_KEY_LIMIT);
42 |     g_rules_map[g_rules_len++] = node;
43 |     return 0;
44 | }
""",
    )

    issues = generator.generate_for_views([lookup, insert])
    truncation = next(
        issue for issue in issues if issue["rule"] == "paired_full_key_lookup_truncated_insert"
    )

    assert truncation["category"] == "key_truncation"
    assert truncation["function"] == "_real_model_insert_key"
    assert (
        normalize_issue_category("race in rules map caused by key truncation") == "key_truncation"
    )
    drifted = {
        "category": "race",
        "description": "full key lookup uses a truncated key after strncpy",
    }
    normalize_issue_fields(drifted)
    assert drifted["normalized_category"] == "key_truncation"


def test_graph_candidates_detect_self_referential_pipe_log_amplification() -> None:
    generator = GraphCandidateGenerator(object(), LocalPatternSemantics())
    close_pipe = _graph_view(
        generator,
        "_lifecycle_close_pipe",
        """
50 | int _lifecycle_close_pipe(Pipe* pipe) {
51 |     pipe->next = pipe;
52 |     return 0;
53 | }
""",
    )
    traversal = _graph_view(
        generator,
        "_lifecycle_dump_pipe_chain",
        """
60 | int _lifecycle_dump_pipe_chain(Pipe* pipe) {
61 |     while (pipe) {
62 |         LOG_ERROR("pipe state %d", pipe->state);
63 |         pipe = pipe->next;
64 |     }
65 |     return 0;
66 | }
""",
    )

    issues = generator.generate_for_views([close_pipe, traversal])
    amplification = next(
        issue
        for issue in issues
        if issue["rule"] == "paired_self_referential_traversal_log_amplification"
    )

    assert amplification["category"] == "log_amplification"
    assert amplification["function"] == "_lifecycle_dump_pipe_chain"
    assert amplification["location"] == "src/lifecycle.c:62"
    assert (
        normalize_issue_category("busy loop from log amplification resource exhaustion")
        == "log_amplification"
    )
    assert normalize_issue_category("CWE-479 signal handler shared state race") == "signal_race"
    drifted = {
        "category": "busy_loop",
        "description": "self-referential traversal causes log amplification",
    }
    normalize_issue_fields(drifted)
    assert drifted["normalized_category"] == "log_amplification"


def test_graph_candidates_expand_thin_runtime_fanout_at_depth_cap() -> None:
    class FakeIndex:
        def get_function_impl(self, name: str, warn_missing: bool = False, max_lines=None):
            impls = {
                "api_schedule": {
                    "file": "src/lifecycle.c",
                    "code": "1 | int api_schedule(int same_core) { return runtime_cycle(same_core); }",
                    "callees": ["runtime_cycle"],
                },
                "runtime_cycle": {
                    "file": "src/lifecycle.c",
                    "code": """
10 | int runtime_cycle(int same_core) {
11 |     int rc = 0;
12 |     rc |= queue_flush(same_core);
13 |     rc |= cancel_timer();
14 |     rc |= finish_event();
15 |     return rc;
16 | }
""",
                    "callees": ["queue_flush", "cancel_timer", "finish_event"],
                },
                "queue_flush": {
                    "file": "src/lifecycle.c",
                    "code": """
20 | int queue_flush(int same_core) {
21 |     RuntimeEvent ev;
22 |     memset(&ev, 0, sizeof(ev));
23 |     if (same_core) {
24 |         ev.next = g_runtime_event_base.level_trigger_list;
25 |         g_runtime_event_base.level_trigger_list = &ev;
26 |         return 0;
27 |     }
28 |     return -1;
29 | }
""",
                    "callees": [],
                },
                "cancel_timer": {
                    "file": "src/lifecycle.c",
                    "code": "30 | int cancel_timer(void) { return 0; }",
                    "callees": [],
                },
                "finish_event": {
                    "file": "src/lifecycle.c",
                    "code": "40 | int finish_event(void) { return 0; }",
                    "callees": [],
                },
            }
            return impls.get(name)

    generator = GraphCandidateGenerator(FakeIndex(), LocalPatternSemantics())
    issues = generator.generate_for_entry(
        "api_schedule",
        FakeIndex().get_function_impl("api_schedule"),
        max_depth=1,
        max_functions=16,
    )

    assert any(
        issue["category"] == "lost_wakeup" and issue["function"] == "queue_flush"
        for issue in issues
    )


def test_graph_candidates_detect_protocol_contract_variants() -> None:
    generator = GraphCandidateGenerator(object(), LocalPatternSemantics())
    bitmap = _graph_view(
        generator,
        "find_bitmap_delta",
        """
10 | size_t find_bitmap_delta(const unsigned char* input, size_t len) {
11 |     uint64_t left = 0;
12 |     uint64_t right = 0;
13 |     memcpy(&left, input + 1, sizeof(left));
14 |     memcpy(&right, input + 9, sizeof(right));
15 |     uint64_t diff = left ^ right;
16 |     return (size_t)(__builtin_ctzll(diff) >> 3);
17 | }
""",
    )
    output = _graph_view(
        generator,
        "query_usage",
        """
20 | int query_usage(UseInfo* out) {
21 |     if (!out) return -1;
22 |     UseInfo tmp;
23 |     tmp.total_size = 4096;
24 |     tmp.used_size = 1024;
25 |     *out = tmp;
26 |     return 0;
27 | }
""",
    )

    issues = generator.generate_for_views([bitmap, output])
    categories = {issue["category"] for issue in issues}

    assert "byte_order_logic" in categories
    assert "uninitialized_output" in categories


def test_graph_candidates_detect_callback_self_destroy_and_role_contract() -> None:
    semantics = configured_test_semantics()
    for name, role, pair, carrier in (
        (
            "_real_model_alloc_node",
            "allocator",
            ["_real_model_free_node", "SAFE_FREE"],
            {"kind": "return"},
        ),
        (
            "_real_model_alloc_node",
            "allocator",
            ["SAFE_FREE"],
            {"kind": "return", "member_path": "->payload"},
        ),
        ("_real_model_free_node", "deallocator", [], {"kind": "argument", "argument_index": 0}),
        ("service_release_by_role", "deallocator", [], {"kind": "argument", "argument_index": 0}),
    ):
        semantics.contracts.add(
            ApiContract.from_row(
                {"symbol_name": name, "kind": role, "pair": pair, "contract": {"carrier": carrier}}
            )
        )
        semantics.add_api(role, name, "user_config")
    generator = GraphCandidateGenerator(object(), semantics)
    callback = _graph_view(
        generator,
        "_completion_callback",
        """
10 | static int _completion_callback(void* arg, uint32_t* result) {
11 |     RuntimeEvent* event = (RuntimeEvent*)arg;
12 |     if (result) *result = 0;
13 |     SAFE_FREE(event);
14 |     return 0;
15 | }
""",
    )
    caller = _graph_view(
        generator,
        "finish_event",
        """
20 | int finish_event(int destroy) {
21 |     RuntimeEvent* event = (RuntimeEvent*)_safe_calloc(1, sizeof(RuntimeEvent));
22 |     event->callback_arg = event;
23 |     event->callback = destroy ? _completion_callback : NULL;
24 |     if (event->callback) {
25 |         event->callback(event->callback_arg, NULL);
26 |     }
27 |     event->running = 0;
28 |     SAFE_FREE(event);
29 |     return 0;
30 | }
""",
    )
    role_release = _graph_view(
        generator,
        "release_channel",
        """
40 | int release_channel(Node* node, int role) {
41 |     node->role = role;
42 |     service_release_by_role(node, 0);
43 |     SAFE_FREE(node);
44 |     return 0;
45 | }
""",
    )

    issues = generator.generate_for_views([caller, callback, role_release])
    categories = {issue["category"] for issue in issues}

    assert "callback_self_destroy_race" in categories
    assert any(issue["rule"] == "role_specific_release_uses_hardcoded_role" for issue in issues)


def test_graph_candidates_detect_fd_type_contract() -> None:
    generator = GraphCandidateGenerator(object(), LocalPatternSemantics())
    bridge = _graph_view(
        generator,
        "bridge_descriptor",
        """
10 | int bridge_descriptor(int reliable_fd) {
11 |     return lower_is_inter_fd(reliable_fd);
12 | }
""",
        signature="int bridge_descriptor(int reliable_fd)",
    )

    issues = generator.generate_for_views([bridge])

    assert any(issue["category"] == "fd_type_mismatch" for issue in issues)


def test_lifted_internal_sink_dedup_merges_entry_paths() -> None:
    first = {
        "candidate_id": "a",
        "function": "shared_helper",
        "location": "src/demo.c:42",
        "defect_class": "bounds",
        "rule": "clang_cfg_copy",
        "source": "len",
        "sink": "memcpy",
        "internal_sink_lifted": True,
        "entry_function": "api_a",
        "analyzed_from": "api_a",
        "call_path": ["api_a", "shared_helper"],
        "positive_evidence": ["api_a reaches shared_helper"],
        "evidence_pack": {
            "internal_sink_lifted": True,
            "sink_function": "shared_helper",
            "call_path_edges": [{"caller": "api_a", "callee": "shared_helper"}],
        },
    }
    second = {
        "candidate_id": "b",
        "function": "shared_helper",
        "location": "src/demo.c:42",
        "defect_class": "bounds",
        "rule": "clang_cfg_copy",
        "source": "len",
        "sink": "memcpy",
        "internal_sink_lifted": True,
        "entry_function": "api_b",
        "analyzed_from": "api_b",
        "call_path": ["api_b", "shared_helper"],
        "positive_evidence": ["api_b reaches shared_helper"],
        "evidence_pack": {
            "internal_sink_lifted": True,
            "sink_function": "shared_helper",
            "call_path_edges": [{"caller": "api_b", "callee": "shared_helper"}],
        },
    }

    deduped = dedupe_rule_candidates([first, second])

    assert len(deduped) == 1
    assert deduped[0]["call_paths"] == [
        ["api_a", "shared_helper"],
        ["api_b", "shared_helper"],
    ]
    assert deduped[0]["duplicate_sources"][0]["entry_function"] == "api_b"
    assert "api_b reaches shared_helper" in deduped[0]["positive_evidence"]


def test_premodel_callee_retrieval_failure_is_non_fatal() -> None:
    class FailingIndex:
        def get_callees(self, name: str, limit: int = 30):
            raise RuntimeError("bad parameter or other API misuse")

    analyzer = object.__new__(Analyzer)
    analyzer.code_index = FailingIndex()

    assert analyzer._premodel_callees(
        "entry",
        object(),
        max_depth=1,
        max_callees=5,
    ) == (0, 0, 0)


def test_premodel_callee_collection_uses_per_level_cap_and_light_impls() -> None:
    class FanoutIndex:
        def __init__(self):
            self.impl_context_flags: list[bool] = []
            self.callee_calls: list[str] = []

        def get_callees(self, name: str, limit: int = 30):
            self.callee_calls.append(name)
            graph = {
                "entry": ["a0", "a1", "a2", "a3"],
                "a0": ["b0", "b1", "b2"],
                "a1": ["b3", "b4", "b5"],
            }
            return [{"name": child} for child in graph.get(name, [])]

        def get_function_impl(
            self,
            name: str,
            warn_missing: bool = False,
            include_context: bool = True,
            max_lines=None,
        ):
            del warn_missing
            self.impl_context_flags.append(include_context)
            simple_name = name.split("@", 1)[0]
            return {
                "func_name": simple_name,
                "file": "src/demo.c",
                "index_name": f"{simple_name}@src/demo.c:1-4",
                "start_line": 1,
                "end_line": 4,
                "signature": f"int {simple_name}(void)",
                "is_static": False,
                "is_macro": False,
                "code": f"1 | int {simple_name}(void) {{\n2 |     return 0;\n3 | }}\n",
                "callees": [],
            }

        def find_function_infos(self, name: str, file_path: str = ""):
            del file_path
            simple_name = name.split("@", 1)[0]
            return [
                {
                    "function_name": simple_name,
                    "file_path": "src/demo.c",
                    "index_name": f"{simple_name}@src/demo.c:1-4",
                    "start_line": 1,
                    "end_line": 4,
                    "signature": f"int {simple_name}(void)",
                    "is_static": False,
                    "callees": [],
                    "referenced_globals": [],
                    "referenced_macros": [],
                    "referenced_types": [],
                }
            ]

    class SnapshotStore:
        def load_snapshot(self, func: str):
            return {"func_name": func}

        def needs_refresh(self, index_name, code, symbol_context):
            del index_name, code, symbol_context
            return False, None

    analyzer = object.__new__(Analyzer)
    analyzer.code_index = FanoutIndex()
    analyzer.snapshot_store = SnapshotStore()
    analyzer.config = SimpleNamespace(analysis=SimpleNamespace(max_function_lines=500))
    analyzer._get_tools = lambda *args, **kwargs: []
    analyzer._tool_policy_for_agent = lambda *args, **kwargs: None

    modeled, skipped, tokens = analyzer._premodel_callees(
        "entry",
        object(),
        max_depth=2,
        max_callees=2,
    )

    assert (modeled, skipped, tokens) == (0, 4, 0)
    assert analyzer.code_index.callee_calls == ["entry", "a0", "a1", "b0", "b1"]
    assert analyzer.code_index.impl_context_flags == [
        False,
        False,
        False,
        False,
        True,
        True,
        True,
        True,
    ]


def test_trivial_snapshot_keeps_security_contract_points_auditable() -> None:
    cases = [
        (
            "update_shared_state",
            "state_protocol",
            """
1461 | int update_shared_state(int fd) {
1462 |     int previous = g_service_registry.state;
1463 |     g_service_registry.state = fd;
1464 |     if (fcntl(fd, F_GETFD) < 0) {
1465 |         return -1;
1466 |     }
1467 |     previous = g_service_registry.state;
1468 |     return previous;
1469 | }
""",
        ),
        (
            "copy_record_body",
            "bounds",
            """
1354 | int copy_record_body(const unsigned char* packet, size_t packet_len,
1355 |                                         unsigned char* out, size_t out_len) {
1356 |     if (!packet || !out || packet_len < 4) {
1357 |         return -1;
1358 |     }
1359 |     uint32_t units = packet[0];
1360 |     size_t copy_len = (size_t)(units * 8);
1361 |     if (copy_len <= out_len) {
1362 |         memcpy(out, packet + 4, copy_len);
1363 |     }
1364 |     return (int)copy_len;
1365 | }
""",
        ),
    ]

    for func_name, category, code in cases:
        snapshot = Analyzer._build_trivial_snapshot(
            func_name,
            {
                "file": "src/lifecycle.c",
                "index_name": f"{func_name}@src/lifecycle.c:1700-1900",
                "start_line": 1700,
                "end_line": 1900,
                "signature": f"int {func_name}(void)",
                "is_static": False,
                "is_macro": False,
                "code": code,
                "callees": [],
            },
        )

        assert snapshot["snapshot_kind"] == "syntactic"
        assert tuple(snapshot) == DETERMINISTIC_SNAPSHOT_REQUIRED_FIELDS
        assert snapshot["parameters"] == []
        assert snapshot["return_values"]["return_type"] == "unknown"
        assert snapshot["effects"] == []
        assert snapshot["error_handling"] == {"error_paths": []}
        assert any(point["category"] == category for point in snapshot["suspicious_points"])
        assert all("confidence" not in point for point in snapshot["suspicious_points"])

    assert not Analyzer._is_trivial_function(cases[-1][2], max_lines_threshold=10)


def test_trivial_snapshot_does_not_infer_contracts_from_fixture_names() -> None:
    cases = [
        """
10 | int authorize(int detected_protocol, int auth_level) {
11 |     if (detected_protocol != 3 && auth_level != 7) {
12 |         return 0;
13 |     }
14 |     return -1;
15 | }
""",
        """
20 | int inspect(const unsigned char* report) {
21 |     uint8_t version = report[0];
22 |     (void)version;
23 |     return 0;
24 | }
""",
        """
30 | int transform(int work_fd) {
31 |     int raw_work_fd = work_fd + 1;
32 |     return project_validate_encoded_fd(raw_work_fd);
33 | }
""",
        """
40 | int bridge(int reliable_fd) {
41 |     return project_is_inter_fd(reliable_fd);
42 | }
""",
    ]

    forbidden_types = {
        "protocol_contract",
        "version_filtering_contract",
        "fd_encoding_contract",
        "fd_type_contract",
    }
    for index, code in enumerate(cases):
        snapshot = Analyzer._build_trivial_snapshot(
            f"fixture_name_case_{index}",
            {
                "file": "src/generic.c",
                "index_name": f"fixture_name_case_{index}@src/generic.c:1-50",
                "start_line": 1,
                "end_line": 50,
                "signature": f"int fixture_name_case_{index}(void)",
                "is_static": False,
                "is_macro": False,
                "code": code,
                "callees": [],
            },
        )

        assert forbidden_types.isdisjoint(point["type"] for point in snapshot["suspicious_points"])


def test_trivial_snapshot_marks_facade_forwarding_as_auditable() -> None:
    snapshot = Analyzer._build_trivial_snapshot(
        "td_runtime_apply_shared_memory_event",
        {
            "file": "src/main.c",
            "index_name": "td_runtime_apply_shared_memory_event@src/main.c:100-106",
            "start_line": 100,
            "end_line": 106,
            "signature": "int td_runtime_apply_shared_memory_event(...)",
            "is_static": False,
            "is_macro": False,
            "code": """
100 | int td_runtime_apply_shared_memory_event(int fd, const unsigned char* wire) {
101 |     return _runtime_accept_session_frame(fd, wire);
102 | }
""",
            "project_callees": [
                {
                    "callee_index_name": "_runtime_accept_session_frame",
                    "callsite_lines": [],
                    "call_type": ["direct"],
                    "is_static": False,
                }
            ],
            "external_callees": [],
        },
    )

    assert any(
        point["type"] == "facade_forwarding_contract"
        and point["category"] == "api_contract"
        and point["lines"] == "100"
        for point in snapshot["suspicious_points"]
    )
    assert all("confidence" not in point for point in snapshot["suspicious_points"])
    assert "semantic_fingerprint" not in snapshot
    assert "key_semantics" not in snapshot
    assert snapshot["project_callees"] == [
        {
            "callee_index_name": "_runtime_accept_session_frame",
            "callee_signature": "",
            "is_static": False,
            "callee_summary": "unknown",
            "direct_callsite_lines": [],
            "indirect_callsites": [],
        }
    ]


def test_allocator_wrappers_require_modeling_without_name_shortcuts() -> None:
    code = """
13 | void* _safe_malloc(size_t size) {
14 |     void* ptr = malloc(size);
15 |     if (!ptr && size > 0) {
16 |         LOG_ERROR("Memory allocation failed: %zu bytes", size);
17 |         return NULL;
18 |     }
19 |     return ptr;
20 | }
"""
    impl = {
        "file": "src/utils.c",
        "index_name": "_safe_malloc@src/utils.c:13-20",
        "start_line": 13,
        "end_line": 20,
        "signature": "void* _safe_malloc(size_t size)",
        "is_static": True,
        "is_macro": False,
        "code": code,
        "callees": ["malloc", "LOG_ERROR"],
    }

    assert not Analyzer._is_trivial_function(code, max_lines_threshold=10)
    assert not Analyzer._is_lightweight_snapshot_candidate("_safe_malloc", impl)

    snapshot = Analyzer._build_lightweight_snapshot(
        "_safe_malloc",
        impl,
    )

    assert snapshot["snapshot_kind"] == "syntactic"
    assert snapshot["interface_contracts"] == []
    assert snapshot["effects"] == []
    assert "semantic_fingerprint" not in snapshot
    assert "resources" not in snapshot
    assert "key_semantics" not in snapshot


def test_lightweight_snapshot_variants_use_unified_semantic_fields() -> None:
    cases = [
        ("LOG_INFO", "io", None),
        ("LOCK", "lock", "acquire"),
        ("UNLOCK", "lock", "release"),
        ("MIN", None, None),
        ("RETURN_IF_ERR", None, "return"),
        ("GOTO_IF_ERR", None, "goto"),
    ]

    for offset, (name, effect_category, operation) in enumerate(cases, start=1):
        snapshot = Analyzer._build_lightweight_snapshot(
            name,
            {
                "file": "include/helpers.h",
                "index_name": f"{name}@include/helpers.h:{offset}-{offset}",
                "start_line": offset,
                "end_line": offset,
                "signature": f"#define {name}(x)",
                "is_static": False,
                "is_macro": True,
                "code": f"{offset} | #define {name}(x) (x)",
                "callees": [],
                "referenced_globals": [],
                "referenced_macros": [],
            },
        )

        assert tuple(snapshot) == DETERMINISTIC_SNAPSHOT_REQUIRED_FIELDS
        assert snapshot["parameters"] == []
        assert snapshot["return_values"]["return_type"] == "unknown"
        assert snapshot["effects"] == []
        assert snapshot["interface_contracts"] == []
        assert snapshot["error_handling"] == {"error_paths": []}


def test_deterministic_snapshot_preserves_context_truncation_and_isolation() -> None:
    referenced_globals = [{"name": "g_state", "reference_lines": [2]}]
    referenced_macros = [
        {
            "macro_index_name": "LIMIT@include/limits.h:1-1",
            "definition": "1 | #define LIMIT 8\n",
            "is_function_like": False,
            "reference_lines": [2],
        }
    ]
    referenced_types = [
        {
            "type_index_name": "TinyContext@include/tiny.h:1-2",
            "kind": "struct",
            "full_definition": "1 | typedef struct { int value; } TinyContext;\n",
            "reference_kinds": ["local"],
            "reference_lines": [2],
        }
    ]
    unresolved_types = [
        {
            "name": "MissingTiny",
            "reference_kinds": ["cast"],
            "reference_lines": [2],
            "reason": "type_definition_not_found",
        }
    ]
    types_truncation = {
        "truncated": True,
        "returned": 1,
        "total": 2,
        "definition_bytes_returned": 47,
        "definition_bytes_limit": 32768,
    }
    globals_truncation = {"truncated": True, "returned": 50, "total": 51}
    macros_truncation = {"truncated": True, "returned": 50, "total": 51}
    project_callees_truncation = {"truncated": True, "returned": 30, "total": 32}
    snapshot = Analyzer._build_trivial_snapshot(
        "tiny",
        {
            "file": "src/tiny.c",
            "index_name": "tiny@src/tiny.c:1-3",
            "start_line": 1,
            "end_line": 3,
            "signature": "int tiny(void)",
            "is_static": False,
            "is_macro": False,
            "code": "1 | int tiny(void) {\n2 | return helper();\n3 | }",
            "referenced_globals": referenced_globals,
            "referenced_macros": referenced_macros,
            "referenced_types": referenced_types,
            "unresolved_referenced_types": unresolved_types,
            "referenced_types_truncation": types_truncation,
            "referenced_globals_truncation": globals_truncation,
            "referenced_macros_truncation": macros_truncation,
            "project_callees": [
                {
                    "callee_index_name": "helper@src/helper.c:10-12",
                    "callsite_lines": [2],
                    "call_type": ["direct"],
                    "is_static": False,
                },
                {
                    "callee_index_name": "dispatch@src/dispatch.c:20-24",
                    "callsite_lines": [2],
                    "call_type": ["direct", "indirect"],
                    "is_static": False,
                },
            ],
            "external_callees": [],
            "project_callees_truncation": project_callees_truncation,
        },
    )

    expected_fields = list(DETERMINISTIC_SNAPSHOT_REQUIRED_FIELDS)
    symbol_index = expected_fields.index("referenced_macros") + 1
    expected_fields[symbol_index:symbol_index] = [
        "referenced_globals_truncation",
        "referenced_macros_truncation",
    ]
    type_index = expected_fields.index("referenced_types") + 1
    expected_fields[type_index:type_index] = [
        "unresolved_referenced_types",
        "referenced_types_truncation",
    ]
    callee_index = expected_fields.index("external_callees") + 1
    expected_fields.insert(callee_index, "project_callees_truncation")
    assert list(snapshot) == expected_fields
    assert set(snapshot) <= set(DETERMINISTIC_SNAPSHOT_REQUIRED_FIELDS) | set(
        DETERMINISTIC_SNAPSHOT_OPTIONAL_FIELDS
    )
    assert snapshot["project_callees"][0]["direct_callsite_lines"] == [2]
    assert snapshot["project_callees"][0]["indirect_callsites"] == []
    assert snapshot["project_callees"][1]["direct_callsite_lines"] == [2]
    assert snapshot["project_callees"][1]["indirect_callsites"] == []
    assert snapshot["code"].endswith("3 | }")

    snapshot["referenced_globals"][0]["name"] = "changed"
    snapshot["referenced_macros"][0]["macro_index_name"] = "changed"
    snapshot["referenced_types"][0]["kind"] = "changed"
    snapshot["unresolved_referenced_types"][0]["name"] = "changed"
    snapshot["referenced_globals_truncation"]["total"] = 99
    snapshot["referenced_macros_truncation"]["total"] = 99
    snapshot["project_callees_truncation"]["total"] = 99
    snapshot["referenced_types_truncation"]["total"] = 99
    assert referenced_globals[0]["name"] == "g_state"
    assert referenced_macros[0]["macro_index_name"] == "LIMIT@include/limits.h:1-1"
    assert referenced_types[0]["kind"] == "struct"
    assert unresolved_types[0]["name"] == "MissingTiny"
    assert globals_truncation["total"] == 51
    assert macros_truncation["total"] == 51
    assert project_callees_truncation["total"] == 32
    assert types_truncation["total"] == 2


def test_validation_evidence_pack_preserves_entry_reachability_context() -> None:
    class FakeIndex:
        def find_function_infos(self, name: str, file_path: str = ""):
            return [
                {
                    "function_name": name,
                    "file_path": file_path,
                    "index_name": f"{name}@{file_path}:1241-1241",
                    "start_line": 1241,
                    "end_line": 1241,
                    "signature": f"int {name}(void)",
                    "is_static": False,
                    "is_macro": False,
                    "callees": [],
                    "referenced_globals": [],
                    "referenced_macros": [],
                }
            ]

        def get_file_snippet(self, path: str, start: int, end: int):
            return "10 | sink();"

        def get_callers(self, name: str, limit: int = 8):
            return []

        def get_callees(self, name: str, limit: int = 12):
            return []

    class FakeSnapshotStore:
        def load_snapshot(self, name: str):
            return {
                "summary": "internal sink",
                "parameters": [],
                "return_values": {
                    "return_type": "unknown",
                    "meaning": "unknown",
                    "nullable": "unknown",
                    "success_cases": [],
                    "failure_cases": [],
                },
                "effects": [
                    {
                        "category": "memory",
                        "description": "validation contract",
                        "line": 1241,
                        "object": "allocation",
                    }
                ],
                "error_handling": {"error_paths": []},
                "callees": [],
                "referenced_globals": [],
                "referenced_macros": [],
                "suspicious_points": [],
            }

    analyzer = object.__new__(Analyzer)
    analyzer.code_index = FakeIndex()
    analyzer.snapshot_store = FakeSnapshotStore()
    issue = {
        "id": "RULE_1",
        "function": "_real_model_comp_destroy_detach_leak",
        "location": "src/lifecycle.c:1241",
        "category": "memory_leak",
        "entry_function": "td_run_real_cleanup_cases",
        "analyzed_from": "td_run_real_cleanup_cases",
        "reachable_from_entry": True,
        "call_path": ["td_run_real_cleanup_cases", "_real_model_comp_destroy_detach_leak"],
        "evidence_pack": {
            "path": {
                "complete_to_entry": True,
                "call_path": ["td_run_real_cleanup_cases", "_real_model_comp_destroy_detach_leak"],
            }
        },
    }
    state = {
        "entry_func": "td_run_real_cleanup_cases",
        "agent_context": {
            "func_name": "td_run_real_cleanup_cases",
            "entry_custom_prompt": "Public API declared in a header file.",
        },
    }

    pack = analyzer._build_validation_evidence_pack(issue, state, "int sink(void) { return -1; }")

    assert pack["entry_context"]["current_analysis_entry"] == "td_run_real_cleanup_cases"
    assert pack["entry_context"]["entry_exposure"] == "api"
    assert pack["entry_context"]["entry_is_external_root"] is True
    assert pack["entry_context"]["zero_callers_is_expected_for_entry"] is True
    assert "zero repository callers" in pack["entry_context"]["public_trigger"]
    assert pack["entry_context"]["reachable_from_entry"] is True
    assert pack["entry_context"]["call_path"] == [
        "td_run_real_cleanup_cases",
        "_real_model_comp_destroy_detach_leak",
    ]
    requirements = "\n".join(pack["validation_requirements"])
    assert "Do not reject an internal callee solely" in requirements
    assert "zero repository callers" in requirements
    assert "entry_is_external_root is true" in requirements
    assert "real_model" not in requirements
    snapshot_summary = pack["function_context"]["snapshot_summary"]
    assert snapshot_summary["effects"][0]["description"] == "validation contract"
    assert "semantic_fingerprint" not in snapshot_summary


def test_validation_snapshot_type_evidence_preserves_identity_under_byte_budget() -> None:
    snapshot = {
        "referenced_types": [
            {
                "type_index_name": "Large@include/types.h:1-10",
                "kind": "struct",
                "full_definition": "x" * (16 * 1024 + 1),
                "reference_kinds": ["parameter"],
                "reference_lines": [5],
            },
            {
                "type_index_name": "Small@include/types.h:20-21",
                "kind": "typedef",
                "full_definition": "20 | typedef int Small;\n",
                "reference_kinds": ["local"],
                "reference_lines": [6],
            },
        ],
        "unresolved_referenced_types": [
            {
                "name": "Missing",
                "reference_kinds": ["cast"],
                "reference_lines": [7],
                "reason": "type_definition_not_found",
            }
        ],
        "referenced_types_truncation": {
            "truncated": True,
            "returned": 2,
            "total": 3,
            "definition_bytes_returned": 16384,
            "definition_bytes_limit": 32768,
        },
    }

    compact = compact_snapshot(snapshot)

    assert compact is not None
    assert compact["referenced_types"][0]["type_index_name"] == ("Large@include/types.h:1-10")
    assert "full_definition" not in compact["referenced_types"][0]
    assert compact["referenced_types"][0]["definition_omitted"] == (
        "validation_evidence_byte_budget"
    )
    assert compact["referenced_types"][1]["full_definition"] == "20 | typedef int Small;\n"
    assert compact["unresolved_referenced_types"] == snapshot["unresolved_referenced_types"]
    assert compact["referenced_types_truncation"] == snapshot["referenced_types_truncation"]


def test_entry_root_dead_code_rejection_is_detected() -> None:
    evidence_pack = {
        "entry_context": {
            "current_analysis_entry": "td_run_real_resource_cases",
            "entry_exposure": "api",
            "entry_is_external_root": True,
            "reachable_from_entry": True,
            "call_path": ["td_run_real_resource_cases", "_real_model_peak_stats_leak"],
        }
    }
    rejected = {
        "verdict": "rejected",
        "reasoning": "td_run_real_resource_cases没有调用者，main函数也不调用，因此是死代码。",
    }
    model_name_rejected = {
        "verdict": "rejected",
        "reasoning": "该函数属于real_model测试代码，函数名包含race，说明是故意构造的模型代码而非生产漏洞。",
    }
    guard_rejected = {
        "verdict": "rejected",
        "reasoning": "调用路径存在，但释放函数在所有失败分支都执行，因此没有泄漏。",
    }

    assert Analyzer._is_entry_root_dead_code_rejection(rejected, evidence_pack) is True
    assert Analyzer._is_entry_root_dead_code_rejection(model_name_rejected, evidence_pack) is False
    assert Analyzer._is_entry_root_dead_code_rejection(guard_rejected, evidence_pack) is False


def test_entry_root_contract_scope_rejection_is_not_rewritten() -> None:
    assert not hasattr(Analyzer, "_is_entry_root_contract_scope_rejection")


def test_validation_pack_marks_current_entry_as_reachable() -> None:
    class FakeIndex:
        def find_function_infos(self, name: str, file_path: str = ""):
            return [
                {
                    "function_name": name,
                    "file_path": file_path,
                    "index_name": f"{name}@{file_path}:210-210",
                    "start_line": 210,
                    "end_line": 210,
                    "signature": f"int {name}(void)",
                    "is_static": False,
                    "is_macro": False,
                    "callees": [],
                    "referenced_globals": [],
                    "referenced_macros": [],
                }
            ]

        def get_file_snippet(self, file_path: str, line: int, context: int = 20):
            return ""

        def get_callers(self, name: str, limit: int = 8):
            return []

        def get_callees(self, name: str, limit: int = 12):
            return []

    class FakeSnapshotStore:
        def load_snapshot(self, name: str):
            return {}

    analyzer = object.__new__(Analyzer)
    analyzer.code_index = FakeIndex()
    analyzer.snapshot_store = FakeSnapshotStore()

    pack = analyzer._build_validation_evidence_pack(
        {
            "id": "ROOT_1",
            "function": "td_run_real_resource_cases",
            "location": "src/main.c:210",
            "category": "memory_leak",
        },
        {
            "entry_func": "td_run_real_resource_cases",
            "agent_context": {
                "func_name": "td_run_real_resource_cases",
                "entry_custom_prompt": "Public API declared in a header file.",
            },
        },
        "int td_run_real_resource_cases(void) { return 0; }",
    )

    assert pack["entry_context"]["reachable_from_entry"] is True
    assert pack["entry_context"]["entry_is_external_root"] is True


def test_resolve_issue_locations_fills_observation_line_only_locations() -> None:
    class FakeIndex:
        def get_function_impl(self, name: str, warn_missing: bool = False, max_lines=None):
            assert name == "_lifecycle_recv_packet"
            return {
                "file": "src/lifecycle.c",
                "start_line": 312,
                "end_line": 323,
                "code": "",
                "callees": [],
            }

    analyzer = object.__new__(Analyzer)
    analyzer.code_index = FakeIndex()
    issues = [
        {
            "function": "_lifecycle_recv_packet",
            "location": "318-322",
            "category": "memory_safety",
            "description": "当_net_recv_data返回-1时，(size_t)received转换为SIZE_MAX，导致memcpy越界读写",
        }
    ]

    analyzer._resolve_issue_locations(issues)

    assert issues[0]["location"] == "src/lifecycle.c:318-322"
    assert issues[0]["file"] == "src/lifecycle.c"
    assert issues[0]["line"] == 318
    assert issues[0]["start_line"] == 318
    assert issues[0]["end_line"] == 322


def test_resolve_issue_locations_recovers_observation_location_from_evidence_refs() -> None:
    class FakeIndex:
        def get_function_impl(self, name: str, warn_missing: bool = False, max_lines=None):
            raise AssertionError("location should be recovered before function fallback")

    analyzer = object.__new__(Analyzer)
    analyzer.code_index = FakeIndex()
    issues = [
        {
            "function": "_issue41_missing_reference_count",
            "location": "",
            "category": "memory_safety",
            "validation_status": "uncertain",
            "evidence_pack": {
                "finding_summary": {"location": ""},
                "evidence_refs": ["candidate source at src/issue41.c:641"],
            },
        }
    ]

    analyzer._resolve_issue_locations(issues)

    assert issues[0]["location"] == "src/issue41.c:641"
    assert issues[0]["file"] == "src/issue41.c"
    assert issues[0]["line"] == 641
    assert issues[0]["start_line"] == 641


def test_validator_source_sink_contribute_to_score_components() -> None:
    class FakeUserConfig:
        def get_finding_baseline(self, _key):
            return None

    analyzer = object.__new__(Analyzer)
    analyzer.user_config = FakeUserConfig()
    issue = {
        "id": "ISSUE_1",
        "function": "_lifecycle_schedule_flush",
        "location": "src/lifecycle.c:247-260",
        "category": "stack_escape",
        "subcategory": "stack_escape",
        "confidence": 0.95,
        "rule_confidence": 0.95,
        "reasoning": "入口 api_send test reasoning",
        "validation_reasoning": "入口 api_send test reasoning",
        "source": "api_send 参数 len",
        "positive_evidence": ["pthread_create(&tid, NULL, _flush_worker, &job)"],
    }
    validator = type(
        "FakeValidator",
        (),
        {
            "input_data": {
                "evidence_pack": {
                    "validation_requirements": ["中文"],
                }
            }
        },
    )()
    val_data = {
        "confidence_score": 0.95,
        "source": "FlushJob job allocated on the stack",
        "sink": "_flush_worker reads job->path after pthread_detach",
    }

    score = analyzer._score_components(issue, val_data)

    assert score["path_completeness"] == 0.75
    assert score["contract_consistency"] == 0.8
    assert score["final_score"] >= 0.8
    assert issue["reasoning"].startswith("入口 api_send")
    assert issue["validation_reasoning"] == issue["reasoning"]
    assert issue["source"] == "api_send 参数 len"
    assert "中文" in "\n".join(validator.input_data["evidence_pack"]["validation_requirements"])


def test_validator_rejections_are_not_persisted_as_broad_baselines() -> None:
    class FakeUserConfig:
        def __init__(self):
            self.upserts = []

        def upsert_finding_baseline(self, dedup_key, status, issue):
            self.upserts.append((dedup_key, status, issue))

    analyzer = object.__new__(Analyzer)
    analyzer.user_config = FakeUserConfig()

    analyzer._remember_validation_result(
        {
            "id": "RULE_1",
            "function": "api_entry",
            "location": "src/demo.c:42",
            "category": "memory_leak",
            "dedup_key": "memory_leak|src/demo.c|42|node",
        },
        "rejected",
    )

    assert analyzer.user_config.upserts == []


def test_joern_rule_match_normalizes_to_evidence_only_candidate() -> None:
    analyzer = object.__new__(Analyzer)
    match = RuleMatch(
        rule_id="paired_SHM_FileOpen_SHM_FileClose",
        rule_name="Missing SHM_FileClose for SHM_FileOpen",
        category="resource",
        score=7.0,
        func_name="api_open",
        file_path="src/demo.c",
        line_number=42,
        code_snippet="handle = SHM_FileOpen(path);",
        evidence=[{"acquire": "SHM_FileOpen", "release": "SHM_FileClose"}],
    )

    candidate = analyzer._joern_rule_match_to_candidate(match, "entry")

    assert candidate["candidate_source"] == "joern_cpg"
    assert candidate["defect_class"] == "memory_leak"
    assert candidate["finding_kind"] == "joern_cpg_candidate"
    assert candidate["evidence_pack"]["candidate_source"] == "joern_cpg"
    assert candidate["evidence_pack"]["path"]["backend"] == "Joern CPG"
    assert "SHM_FileOpen" in "\n".join(candidate["positive_evidence"])


def test_joern_category_mapping_preserves_specific_classes() -> None:
    assert class_from_joern_category("integer_overflow") == "integer_overflow"
    assert class_from_joern_category("path_traversal") == "path_traversal"
    assert class_from_joern_category("null_pointer_dereference") == "null_pointer_dereference"
    assert class_from_joern_category("buffer_overflow") == "bounds"


def test_joern_candidate_scope_uses_entry_reachability() -> None:
    class FakeIndex:
        def get_callees(self, name: str, limit: int = 80):
            graph = {
                "entry": [{"name": "wrapper"}],
                "wrapper": [{"name": "api_open"}],
                "api_open": [],
            }
            return graph.get(name, [])

    analyzer = object.__new__(Analyzer)
    analyzer.code_index = FakeIndex()

    assert analyzer._match_reachable_from_entry("entry", "api_open")
    assert analyzer._match_reachable_from_entry("entry", "ns:api_open")
    assert not analyzer._match_reachable_from_entry("entry", "unrelated")


def test_reachable_precompute_is_cached_per_entry_depth_and_limit() -> None:
    class CountingIndex:
        def __init__(self):
            self.calls = []

        def get_callees(self, name: str, limit: int = 80):
            self.calls.append((name, limit))
            graph = {
                "entry": [{"name": "wrapper"}],
                "wrapper": [{"name": "api_open"}, {"name": "entry"}],
                "api_open": [{"name": "leaf"}],
                "leaf": [],
            }
            return graph.get(name, [])

    index = CountingIndex()
    analyzer = object.__new__(Analyzer)
    analyzer.code_index = index

    assert analyzer._match_reachable_from_entry("entry", "api_open")
    assert analyzer._match_reachable_from_entry("entry", "ns:api_open")
    assert analyzer._match_reachable_from_entry("entry", "leaf")
    assert not analyzer._match_reachable_from_entry("entry", "unrelated")
    assert index.calls == [
        ("entry", 80),
        ("wrapper", 80),
        ("api_open", 80),
        ("leaf", 80),
    ]

    assert not analyzer._match_reachable_from_entry("entry", "leaf", max_depth=2)
    assert index.calls[-2:] == [
        ("entry", 80),
        ("wrapper", 80),
    ]

    assert analyzer._match_reachable_from_entry("entry", "leaf", max_depth=3)
    assert index.calls[-3:] == [
        ("entry", 80),
        ("wrapper", 80),
        ("api_open", 80),
    ]


def test_reachable_precompute_respects_cycles_depth_and_node_limits() -> None:
    class FakeIndex:
        def get_callees(self, name: str, limit: int = 80):
            graph = {
                "entry": [{"name": "a"}, {"name": "b"}, {"name": "c"}],
                "a": [{"name": "entry"}, {"name": "deep"}],
                "b": [],
                "c": [],
                "deep": [{"name": "leaf"}],
            }
            return graph.get(name, [])

    analyzer = object.__new__(Analyzer)
    analyzer.code_index = FakeIndex()

    assert analyzer._reachable_function_names_from_entry(
        "entry",
        max_depth=1,
        max_nodes=10,
        callee_limit=80,
    ) == {"entry", "a", "b", "c"}
    assert not analyzer._match_reachable_from_entry("entry", "leaf", max_depth=2)
    assert analyzer._match_reachable_from_entry("entry", "leaf", max_depth=3)
    assert (
        len(
            analyzer._reachable_function_names_from_entry(
                "entry",
                max_depth=5,
                max_nodes=3,
                callee_limit=80,
            )
        )
        == 3
    )


def test_clang_knowledge_candidates_reuse_precomputed_reachable_set() -> None:
    class CountingIndex:
        def __init__(self):
            self.calls = []

        def get_callees(self, name: str, limit: int = 80):
            self.calls.append((name, limit))
            graph = {
                "entry": [{"name": "api_open"}],
                "api_open": [],
            }
            return graph.get(name, [])

    class FakeDB:
        def find_acquisition_calls(self, acquire: str, release: list[str], limit: int = 100):
            return [
                {"function": "api_open", "file_path": "src/api.c", "line": 7},
                {"function": "unreachable", "file_path": "src/other.c", "line": 9},
            ]

    index = CountingIndex()
    analyzer = object.__new__(Analyzer)
    analyzer.code_index = index
    analyzer._candidate_backend_profile = lambda: "clang"
    analyzer._resource_release_pairs_from_overlay = lambda: [("open", "close", "test")]
    analyzer._clang_pair_row_to_candidate = lambda row, **kwargs: {
        "function": row["function"],
        "entry": kwargs["entry_func"],
    }
    reachable = analyzer._reachable_function_names_from_entry(
        "entry",
        max_depth=4,
        max_nodes=200,
        callee_limit=80,
    )
    calls_after_precompute = list(index.calls)

    candidates = analyzer._detect_clang_knowledgedb_candidates(
        {"entry_func": "entry"},
        FakeDB(),
        reachable_funcs=reachable,
    )

    assert candidates == [{"function": "api_open", "entry": "entry"}]
    assert index.calls == calls_after_precompute


def test_deterministic_database_collectors_page_until_exhausted() -> None:
    taint_rows = [{"row": index} for index in range(5)]
    pair_rows = [{"function": f"f{index}"} for index in range(5)]
    taint_offsets = []
    pair_offsets = []

    class FakeDB:
        def get_enriched_taint_bugs(
            self,
            *,
            func_names,
            limit: int,
            offset: int,
        ):
            assert func_names == ["entry"]
            taint_offsets.append(offset)
            return taint_rows[offset : offset + limit]

    def find_missing(
        acquire: str,
        release: str,
        *,
        limit: int,
        offset: int,
    ):
        assert (acquire, release) == ("open", "close")
        pair_offsets.append(offset)
        return pair_rows[offset : offset + limit]

    bugs, legacy = Analyzer._collect_enriched_taint_bugs(
        FakeDB(),
        reachable_funcs={"entry"},
        entry_func="entry",
        page_size=2,
    )
    missing, missing_legacy = Analyzer._collect_missing_release_rows(
        find_missing,
        "open",
        "close",
        page_size=2,
    )

    assert bugs == taint_rows
    assert not legacy
    assert taint_offsets == [0, 2, 4]
    assert missing == pair_rows
    assert not missing_legacy
    assert pair_offsets == [0, 2, 4]


def test_deterministic_pagination_fails_closed_when_adapter_ignores_offset() -> None:
    class StuckDB:
        def get_enriched_taint_bugs(
            self,
            *,
            func_names,
            limit: int,
            offset: int,
        ):
            return [{"row": 1}, {"row": 2}]

    with pytest.raises(RuntimeError, match="did not advance"):
        Analyzer._collect_enriched_taint_bugs(
            StuckDB(),
            reachable_funcs={"entry"},
            entry_func="entry",
            page_size=2,
        )


def test_paged_adapter_internal_type_error_is_not_misread_as_legacy_api() -> None:
    class BrokenDB:
        def get_enriched_taint_bugs(
            self,
            *,
            func_names,
            limit: int,
            offset: int,
        ):
            raise TypeError("decoder failed inside adapter")

    with pytest.raises(TypeError, match="decoder failed"):
        Analyzer._collect_enriched_taint_bugs(
            BrokenDB(),
            reachable_funcs={"entry"},
            entry_func="entry",
            page_size=2,
        )


def test_clang_pair_row_normalizes_to_candidate() -> None:
    analyzer = object.__new__(Analyzer)
    analyzer._semantic_overlay = {}
    row = {
        "function": "api_open",
        "file_path": "src/demo.c",
        "line": 12,
        "acquire_func": "SHM_FileOpen",
        "release_func": "SHM_FileClose",
    }

    candidate = analyzer._clang_pair_row_to_candidate(
        row,
        entry_func="entry",
        pair_source="user_config",
    )

    assert candidate["candidate_source"] == "clang_knowledgedb_call_edges"
    assert candidate["finding_kind"] == "clang_callgraph_candidate"
    assert candidate["defect_class"] == "memory_leak"
    assert candidate["evidence_pack"]["resource_pair"] == {
        "acquire": "SHM_FileOpen",
        "release": "SHM_FileClose",
        "source": "user_config",
    }
    assert "ownership transfer" in "\n".join(candidate["negative_evidence"])


def test_config_pair_names_split_csv() -> None:
    assert split_config_pair_names("CloseA, CloseB") == ["CloseA", "CloseB"]


def test_candidate_ir_database_failure_marks_engine_incomplete() -> None:
    class RecordingLock:
        def __init__(self):
            self.entries = 0

        def __enter__(self):
            self.entries += 1
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

    class FailedDb:
        def upsert_ir_statement(self, *args, **kwargs):
            raise RuntimeError("database is read-only")

        def commit(self):
            raise RuntimeError("commit failed")

    analyzer = object.__new__(Analyzer)
    analyzer._get_knowledge_db = lambda: FailedDb()
    writer_lock = RecordingLock()
    analyzer._candidate_ir_persistence_lock = writer_lock

    analyzer._persist_candidate_ir_records(
        [
            {
                "id": "CANDIDATE_1",
                "function": "entry",
                "location": "src/demo.c:7",
                "defect_class": "bounds",
                "description": "candidate",
            }
        ]
    )

    capability = analyzer._runtime_engine_capabilities["candidate_ir_persistence"]
    assert capability["status"] == "failed"
    assert capability["persisted_count"] == 0
    assert capability["failure_count"] == 2
    assert writer_lock.entries == 1
