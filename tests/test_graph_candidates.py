from pathlib import Path

from zscope.core.candidates.regex import LocalPatternSemantics
from zscope.core.candidates.graph import FunctionView, GraphCandidateGenerator
from zscope.retrieval.code_index import CodeIndex


def _range_index() -> CodeIndex:
    project_root = Path(__file__).resolve().parents[1] / "test" / "range"
    return CodeIndex(project_root, source_root=project_root)


def _range_semantics() -> LocalPatternSemantics:
    semantics = LocalPatternSemantics()
    semantics.add_api("deallocator", "SAFE_FREE", "range_test:user_config")
    return semantics


def test_graph_candidates_cover_cross_function_protocols() -> None:
    index = _range_index()
    generator = GraphCandidateGenerator(index, _range_semantics())
    issues = generator.generate_for_functions(
        [
            "_plugin_unregister",
            "td_cleanup",
            "td_init",
            "_lifecycle_register_topic_subscription",
            "_lifecycle_unregister_topic_subscription",
            "_lifecycle_attach_proc_node",
            "_lifecycle_delete_os_node",
        ]
    )

    rules = {str(issue.get("rule")) for issue in issues}
    assert "cross_function_recursive_lock" in rules
    assert "cleanup_contract_type_mismatch" in rules
    assert "heap_thread_argument_not_released" in rules
    assert "paired_nested_mutex_cleanup_omitted" in rules
    assert "paired_child_list_cleanup_omitted" in rules


def test_graph_candidates_cover_open_global_registration_cleanup_pair() -> None:
    index = _range_index()
    generator = GraphCandidateGenerator(index, _range_semantics())
    issues = generator.generate_for_functions(
        [
            "_lifecycle_customize_control_message",
            "_lifecycle_customize_transport_cleanup",
        ]
    )

    pair = next(
        issue
        for issue in issues
        if issue.get("rule") == "paired_global_registration_cleanup_omitted"
    )
    assert pair["function"] == "_lifecycle_customize_control_message"
    assert "_lifecycle_customize_transport_cleanup" in pair["sink"]
    assert pair["evidence_pack"]["lifecycle_pair"] == {
        "registration_function": "_lifecycle_customize_control_message",
        "cleanup_function": "_lifecycle_customize_transport_cleanup",
    }


def test_graph_candidates_cover_liveness_and_lock_order_shapes() -> None:
    index = _range_index()
    generator = GraphCandidateGenerator(index, _range_semantics())
    issues = generator.generate_for_functions(
        [
            "_lifecycle_dispatch_pipe_tick",
            "_lifecycle_close_pipe",
            "_lifecycle_tick_timer_callback",
            "_lifecycle_avl_policy_upsert",
            "_lifecycle_avl_register_route",
        ]
    )

    rules = {str(issue.get("rule")) for issue in issues}
    assert "cross_function_lock_order_inversion" in rules
    assert "timer_callback_cascade_wait" in rules
    assert "self_referential_list_link" in rules
    assert "log_inside_poisoned_traversal" in rules
    assert "full_key_lookup_truncated_insert" in rules
    assert "insert_failure_leaves_stale_tree_node" in rules

    timer = next(
        issue
        for issue in issues
        if issue.get("rule") == "timer_callback_cascade_wait"
        and issue.get("function") == "_lifecycle_tick_timer_callback"
    )
    cascade = timer["evidence_pack"]["cascade_wait"]
    assert cascade["holder"]["function"] == "_lifecycle_close_pipe"
    assert cascade["scheduler_holder"]["function"] == "_lifecycle_dispatch_pipe_tick"


def test_graph_candidates_cover_issue41_42_system_protocol_shapes() -> None:
    index = _range_index()
    generator = GraphCandidateGenerator(index, _range_semantics())
    issues = generator.generate_for_functions(
        [
            "_peer_send_control_reply",
            "_peer_bridge_descriptor",
            "_runtime_release_packet_pool",
            "_runtime_read_timer_ticks",
            "_runtime_capture_signal_stack",
            "_runtime_rebuild_available_list",
            "_runtime_register_pool_ops",
            "_runtime_schedule_rcu_release",
            "_runtime_release_hash_node",
            "_runtime_make_shared_key",
            "_runtime_insert_policy_node",
            "_peer_route_protocol_context",
        ]
    )

    rules = {str(issue.get("rule")) for issue in issues}
    assert "peer_write_without_sigpipe_handling" in rules
    assert "encoded_or_reliable_fd_passed_to_raw_fd_contract" in rules
    assert "destroy_shared_pool_while_active_tasks_remain" in rules
    assert "unchecked_param_indexes_fixed_global_array" in rules
    assert "signal_path_mutates_shared_state_or_logs" in rules
    assert "caller_limit_indexes_fixed_local_array" in rules
    assert "global_registration_slot_checked_before_lock" in rules
    assert "mutable_global_mode_drives_callback_without_lock" in rules
    assert "callback_allocator_pair_not_enforced" in rules
    assert "path_state_checked_separately_from_key_generation" in rules
    assert "unchecked_ownership_transfer_return_loses_node" in rules
    assert "protocol_mismatch_accepted_under_non_strict_auth" in rules

    premature = next(
        issue
        for issue in issues
        if issue.get("rule") == "destroy_shared_pool_while_active_tasks_remain"
    )
    assert "published to shared/global state" in "\n".join(premature["positive_evidence"])

    bridge_rules = {
        issue.get("rule")
        for issue in issues
        if issue.get("function") == "_peer_bridge_descriptor"
    }
    assert "unchecked_param_indexes_fixed_global_array" not in bridge_rules


def test_graph_candidates_lift_callee_key_generation_race() -> None:
    index = _range_index()
    generator = GraphCandidateGenerator(index, _range_semantics())
    issues = generator.generate_for_functions(["_runtime_shutdown_local_session"])

    lifted = next(
        issue
        for issue in issues
        if issue.get("rule") == "callee_path_state_checked_separately_from_key_generation"
    )
    assert lifted["function"] == "_runtime_shutdown_local_session"
    assert "_runtime_make_shared_key" in lifted["source"]
    assert "_runtime_make_shared_key" in lifted["sink"]


def _function_view(generator: GraphCandidateGenerator, name: str, code: str) -> FunctionView:
    lines = tuple(generator._parse_lines(code))
    return FunctionView(
        name=name,
        file_path="src/demo.c",
        signature=f"int {name}(void)",
        lines=lines,
        callees=(),
    )


def test_graph_candidates_use_custom_lock_semantics() -> None:
    semantics = LocalPatternSemantics()
    semantics.add_api("lock", "VOS_SemTake", "user_config")
    semantics.add_api("unlock", "VOS_SemGive", "user_config")
    generator = GraphCandidateGenerator(object(), semantics)
    caller = _function_view(
        generator,
        "api_update",
        """
1 | int api_update(void) {
2 |     VOS_SemTake(&g_lock);
3 |     helper_update();
4 |     VOS_SemGive(&g_lock);
5 |     return 0;
6 | }
""",
    )
    helper = _function_view(
        generator,
        "helper_update",
        """
10 | int helper_update(void) {
11 |     VOS_SemTake(&g_lock);
12 |     VOS_SemGive(&g_lock);
13 |     return 0;
14 | }
""",
    )

    issues = generator.generate_for_views([caller, helper])

    recursive = next(issue for issue in issues if issue["rule"] == "cross_function_recursive_lock")
    assert recursive["source"] == "api_update:2:g_lock"
    assert recursive["sink"] == "helper_update:11:g_lock"


def test_graph_candidates_use_custom_resource_semantics() -> None:
    semantics = LocalPatternSemantics()
    semantics.add_api("allocator", "VOS_MemAlloc", "user_config")
    semantics.add_api("deallocator", "VOS_MemFree", "user_config")
    generator = GraphCandidateGenerator(object(), semantics)
    view = _function_view(
        generator,
        "start_worker",
        """
1 | int start_worker(void) {
2 |     Job *jobs = VOS_MemAlloc(sizeof(Job) * 4);
3 |     pthread_create(&tid, NULL, worker_main, &jobs[0]);
4 |     return 0;
5 | }
""",
    )

    issues = generator.generate_for_views([view])

    leak = next(issue for issue in issues if issue["rule"] == "heap_thread_argument_not_released")
    assert leak["source"] == "jobs"
    assert "VOS_MemAlloc" in leak["code_snippet"]


def test_graph_candidates_expand_configured_pointer_targets_under_lock() -> None:
    class FakeIndex:
        def get_function_impl(self, name: str, warn_missing: bool = False):
            impls = {
                "api_dispatch": {
                    "file": "src/demo.c",
                    "code": """
1 | int api_dispatch(Ops *ops) {
2 |     VOS_SemTake(&g_lock);
3 |     ops->on_msg();
4 |     VOS_SemGive(&g_lock);
5 |     return 0;
6 | }
""",
                    "callees": [],
                },
                "handler_update": {
                    "file": "src/demo.c",
                    "code": """
10 | int handler_update(void) {
11 |     VOS_SemTake(&g_lock);
12 |     VOS_SemGive(&g_lock);
13 |     return 0;
14 | }
""",
                    "callees": [],
                },
            }
            return impls.get(name)

        def get_callees(self, name: str, limit: int = 80):
            return []

    semantics = LocalPatternSemantics()
    semantics.add_api("lock", "VOS_SemTake", "user_config")
    semantics.add_api("unlock", "VOS_SemGive", "user_config")
    overlay = {
        "pointer_target_models": [
            {
                "pointer_location": "ops->on_msg",
                "scope": "api_dispatch",
                "target_functions": '["handler_update"]',
            }
        ]
    }
    generator = GraphCandidateGenerator(FakeIndex(), semantics, semantic_overlay=overlay)

    issues = generator.generate_for_entry("api_dispatch", max_depth=1, max_functions=4)

    recursive = next(issue for issue in issues if issue["rule"] == "cross_function_recursive_lock")
    assert recursive["sink"] == "handler_update:11:g_lock"
    assert recursive["evidence_pack"]["path"]["call_evidence"]["source"] == "user_config:pointer_targets"
    assert "configured target" in "\n".join(recursive["positive_evidence"])


def test_graph_candidates_expand_backend_indirect_call_line_evidence() -> None:
    class FakeIndex:
        def get_function_impl(self, name: str, warn_missing: bool = False):
            impls = {
                "api_dispatch": {
                    "file": "src/demo.c",
                    "code": """
1 | int api_dispatch(Ops *ops) {
2 |     VOS_SemTake(&g_lock);
3 |     ops->on_msg();
4 |     VOS_SemGive(&g_lock);
5 |     return 0;
6 | }
""",
                    "callees": [],
                },
                "handler_update": {
                    "file": "src/demo.c",
                    "code": """
10 | int handler_update(void) {
11 |     VOS_SemTake(&g_lock);
12 |     VOS_SemGive(&g_lock);
13 |     return 0;
14 | }
""",
                    "callees": [],
                },
            }
            return impls.get(name)

        def get_callees(self, name: str, limit: int = 80):
            if name == "api_dispatch":
                return [{"name": "handler_update", "source": "svf-ander", "call_line": 3}]
            return []

    semantics = LocalPatternSemantics()
    semantics.add_api("lock", "VOS_SemTake", "user_config")
    semantics.add_api("unlock", "VOS_SemGive", "user_config")
    generator = GraphCandidateGenerator(FakeIndex(), semantics)

    issues = generator.generate_for_entry("api_dispatch", max_depth=1, max_functions=4)

    recursive = next(issue for issue in issues if issue["rule"] == "cross_function_recursive_lock")
    assert recursive["evidence_pack"]["path"]["call_evidence"]["source"] == "svf-ander"
    assert "svf-ander call graph evidence" in "\n".join(recursive["positive_evidence"])


def test_graph_candidates_expand_configured_dispatcher_handlers() -> None:
    class FakeIndex:
        def get_function_impl(self, name: str, warn_missing: bool = False):
            impls = {
                "dispatch_msg": {
                    "file": "src/demo.c",
                    "code": """
1 | int dispatch_msg(int type) {
2 |     VOS_SemTake(&g_lock);
3 |     switch (type) { default: break; }
4 |     VOS_SemGive(&g_lock);
5 |     return 0;
6 | }
""",
                    "callees": [],
                },
                "handle_msg": {
                    "file": "src/demo.c",
                    "code": """
10 | int handle_msg(void) {
11 |     VOS_SemTake(&g_lock);
12 |     VOS_SemGive(&g_lock);
13 |     return 0;
14 | }
""",
                    "callees": [],
                },
            }
            return impls.get(name)

        def get_callees(self, name: str, limit: int = 80):
            return []

    semantics = LocalPatternSemantics()
    semantics.add_api("lock", "VOS_SemTake", "user_config")
    semantics.add_api("unlock", "VOS_SemGive", "user_config")
    overlay = {
        "dispatcher_models": [
            {
                "dispatcher_name": "dispatch_msg",
                "message_type": "MSG_UPDATE",
                "handler_name": "handle_msg",
                "handler_kind": "message_handler",
            }
        ]
    }
    generator = GraphCandidateGenerator(FakeIndex(), semantics, semantic_overlay=overlay)

    issues = generator.generate_for_entry("dispatch_msg", max_depth=1, max_functions=4)

    recursive = next(issue for issue in issues if issue["rule"] == "cross_function_recursive_lock")
    assert recursive["sink"] == "handle_msg:11:g_lock"
    assert recursive["evidence_pack"]["path"]["call_evidence"]["source"] == "user_config:dispatcher"
    assert "configured handler" in "\n".join(recursive["positive_evidence"])


def test_graph_candidates_expand_dispatcher_sibling_branches_at_depth_cap() -> None:
    class FakeIndex:
        def get_function_impl(self, name: str, warn_missing: bool = False):
            impls = {
                "api_entry": {
                    "file": "src/demo.c",
                    "code": """
1 | int api_entry(int type) {
2 |     return dispatch_msg(type);
3 | }
""",
                    "callees": ["dispatch_msg"],
                },
                "dispatch_msg": {
                    "file": "src/demo.c",
                    "code": """
10 | int dispatch_msg(int type) {
11 |     VOS_SemTake(&g_lock);
12 |     switch (type) {
13 |     case 1: return handle_a();
14 |     case 2: return handle_b();
15 |     default: return handle_c();
16 |     }
17 |     VOS_SemGive(&g_lock);
18 |     return 0;
19 | }
""",
                    "callees": ["handle_a", "handle_b", "handle_c"],
                },
                "handle_a": {
                    "file": "src/demo.c",
                    "code": "20 | int handle_a(void) { return 0; }",
                    "callees": [],
                },
                "handle_b": {
                    "file": "src/demo.c",
                    "code": """
30 | int handle_b(void) {
31 |     VOS_SemTake(&g_lock);
32 |     VOS_SemGive(&g_lock);
33 |     return 0;
34 | }
""",
                    "callees": [],
                },
                "handle_c": {
                    "file": "src/demo.c",
                    "code": "40 | int handle_c(void) { return 0; }",
                    "callees": [],
                },
            }
            return impls.get(name)

        def get_callees(self, name: str, limit: int = 80):
            return []

    semantics = LocalPatternSemantics()
    semantics.add_api("lock", "VOS_SemTake", "user_config")
    semantics.add_api("unlock", "VOS_SemGive", "user_config")
    generator = GraphCandidateGenerator(FakeIndex(), semantics)

    issues = generator.generate_for_entry("api_entry", max_depth=1, max_functions=8)

    recursive = next(issue for issue in issues if issue["rule"] == "cross_function_recursive_lock")
    assert recursive["function"] == "dispatch_msg"
    assert recursive["sink"] == "handle_b:31:g_lock"

