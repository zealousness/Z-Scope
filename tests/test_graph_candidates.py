from pathlib import Path

import pytest

from zscope.core.candidates.regex import LocalPatternSemantics
from zscope.core.candidates.graph import FunctionView, GraphCandidateGenerator
from zscope.retrieval.code_index import CodeIndex


def test_graph_keeps_pointer_and_address_lock_obligations_distinct():
    from zscope.core.candidates.cpp_domains.models import GraphLine
    from zscope.semantics.defaults import default_local_pattern_semantics

    graph = GraphCandidateGenerator(object(), default_local_pattern_semantics())
    line = GraphLine(1, "pthread_mutex_lock(p);", "pthread_mutex_lock(p);", 0)
    held = [(graph.semantics.contracts.resolve_object("pthread_mutex_lock", "lock", ["p"]), line)]
    assert not graph._release_held_lock("pthread_mutex_unlock(&p);", held)
    assert len(held) == 1
    uncertain = set()
    assert graph._release_held_lock("pthread_mutex_unlock(p);", held, uncertain)
    # A hidden return status identifies the correct object but cannot discharge it.
    assert len(held) == 1
    assert uncertain == {"p"}


@pytest.fixture(scope="module")
def range_index() -> CodeIndex:
    """Share one lazily-warmed index across the range-project tests.

    ``CodeIndex`` over ``test/range`` pays a multi-second lazy load on first
    query and is read-only for ``GraphCandidateGenerator`` (queries only fill
    internal caches), so building it once per module keeps every observation
    point while removing the repeated warm-up cost.
    """

    return _range_index()


def _range_index() -> CodeIndex:
    project_root = Path(__file__).resolve().parents[1] / "test" / "range"
    return CodeIndex(project_root, source_root=project_root)


def _range_semantics() -> LocalPatternSemantics:
    from semantic_fixtures import configured_test_semantics
    from zscope.semantics.contracts import ApiContract

    semantics = configured_test_semantics()
    pairs = {
        "_lifecycle_register_topic_subscription": "_lifecycle_unregister_topic_subscription",
        "_lifecycle_attach_proc_node": "_lifecycle_delete_os_node",
    }
    for acquire, release in pairs.items():
        semantics.contracts.add(
            ApiContract.from_row({"symbol_name": acquire, "kind": "allocator", "pair": [release]})
        )
        semantics.add_api("allocator", acquire, "test:user_config")
        semantics.add_api("deallocator", release, "test:user_config")
    for release in ("_plugin_registry_cleanup", "_executor_cleanup_resources"):
        semantics.add_api("deallocator", release, "test:user_config")
    return semantics


def test_graph_candidates_cover_cross_function_protocols(range_index) -> None:
    generator = GraphCandidateGenerator(range_index, _range_semantics())
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


def test_graph_detects_getter_backed_indexed_member_cleanup_gap(range_index) -> None:
    generator = GraphCandidateGenerator(range_index, _range_semantics())
    issues = generator.generate_for_functions(
        ["_runtime_get_thread_cache", "_runtime_close_thread_cache"]
    )

    issue = next(
        item
        for item in issues
        if item.get("rule") == "paired_free_wrapper_omits_dynamic_member"
        and item.get("function") == "_runtime_close_thread_cache"
    )
    assert issue["defect_class"] == "memory_leak"
    assert "getter-to-global owner alias" in issue["evidence_pack"]["path"]["path_constraints"]


def _view(name: str, file_path: str, start: int, source: str) -> FunctionView:
    from zscope.core.candidates.cpp_domains.models import GraphLine

    lines = tuple(
        GraphLine(start + offset, text, text, offset)
        for offset, text in enumerate(source.strip("\n").splitlines())
    )
    return FunctionView(name, file_path, "", lines, ())


def test_graph_detects_factory_returned_member_omitted_by_destructor() -> None:
    producer = _view(
        "SanitizeOptions",
        "db/db_impl.cc",
        100,
        """
Options SanitizeOptions(const Options& src) {
  Options result = src;
  if (result.block_cache == NULL) {
    result.block_cache = new LRUCache(32);
  }
  return result;
}
""",
    )
    constructor = _view(
        "Repairer::Repairer",
        "db/repair.cc",
        40,
        """
Repairer::Repairer(const Options& options)
    : options_(SanitizeOptions(options)),
      owns_info_log_(options_.info_log != options.info_log) {}
""",
    )
    destructor = _view(
        "Repairer::~Repairer",
        "db/repair.cc",
        55,
        """
Repairer::~Repairer() {
  if (owns_info_log_) {
    delete options_.info_log;
  }
}
""",
    )
    generator = GraphCandidateGenerator(object(), _range_semantics())

    issues = generator.generate_for_views([producer, constructor, destructor])
    issue = next(
        item
        for item in issues
        if item.get("rule") == "paired_free_wrapper_omits_dynamic_member"
        and item.get("function") == "Repairer::~Repairer"
    )

    assert issue["defect_class"] == "memory_leak"
    assert issue["evidence_pack"]["ownership"]["carrier"] == "return.block_cache"
    assert issue["evidence_pack"]["source"]["file"] == "db/db_impl.cc"
    assert issue["evidence_pack"]["sink"]["file"] == "db/repair.cc"


def test_graph_factory_member_cleanup_gap_accepts_explicit_destructor_release() -> None:
    producer = _view(
        "SanitizeOptions",
        "db/db_impl.cc",
        100,
        """
Options SanitizeOptions(const Options& src) {
  Options result = src;
  if (result.block_cache == NULL) {
    result.block_cache = new LRUCache(32);
  }
  return result;
}
""",
    )
    constructor = _view(
        "Repairer::Repairer",
        "db/repair.cc",
        40,
        """
Repairer::Repairer(const Options& options)
    : options_(SanitizeOptions(options)),
      owns_cache_(options_.block_cache != options.block_cache) {}
""",
    )
    destructor = _view(
        "Repairer::~Repairer",
        "db/repair.cc",
        55,
        """
Repairer::~Repairer() {
  if (owns_cache_) {
    delete options_.block_cache;
  }
}
""",
    )
    generator = GraphCandidateGenerator(object(), _range_semantics())

    issues = generator.generate_for_views([producer, constructor, destructor])

    assert not any(
        item.get("rule") == "paired_free_wrapper_omits_dynamic_member"
        and item.get("function") == "Repairer::~Repairer"
        for item in issues
    )


def test_graph_candidates_cover_open_global_registration_cleanup_pair(range_index) -> None:
    generator = GraphCandidateGenerator(range_index, _range_semantics())
    issues = generator.generate_for_functions(
        [
            "_lifecycle_customize_control_message",
            "_lifecycle_customize_transport_cleanup",
        ]
    )

    # No caller-visible resource contract was declared for the business handler.
    assert not any(
        issue.get("rule") == "paired_global_registration_cleanup_omitted" for issue in issues
    )


def test_graph_candidates_cover_liveness_and_lock_order_shapes(range_index) -> None:
    generator = GraphCandidateGenerator(range_index, _range_semantics())
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


def test_prepared_graph_view_never_reopens_unscoped_body_or_program_facts() -> None:
    class PreparedOnlyIndex:
        def get_function_impl(self, *_args, **_kwargs):
            raise AssertionError("prepared graph view reopened an unscoped body")

        def get_function_program_facts(self, *_args, **_kwargs):
            raise AssertionError("prepared graph view reopened unscoped native facts")

        def get_callees(self, *_args, **_kwargs):
            return []

    generator = GraphCandidateGenerator(PreparedOnlyIndex(), _range_semantics())
    impl = {
        "file": "src/unit.c",
        "signature": "int exact_view(void)",
        "code": "10 | int exact_view(void) {\n11 |     return 0;\n12 | }",
        "callees": [],
    }
    facts = {"functions": [{"owner": {"usr": "c:@F@exact_view"}, "events": []}]}

    view = generator.prepare_function_view("exact_view", impl, program_facts=facts)

    assert view is not None
    assert view.name == "exact_view"
    assert generator.generate_for_prepared_views([(view, facts)]) == []


def test_prepared_graph_view_consumes_exact_macro_receipts_for_lock_rules() -> None:
    from zscope.semantics.contracts import ApiContract, ObjectBinding, SymbolIdentity

    build = "ctx-a"
    lock_symbol = SymbolIdentity(
        "LOCK",
        "include/common.h",
        "#define LOCK(value)",
        "macro",
        build,
        "c:common.h@10@macro@LOCK",
    )
    unlock_symbol = SymbolIdentity(
        "UNLOCK",
        "include/common.h",
        "#define UNLOCK(value)",
        "macro",
        build,
        "c:common.h@20@macro@UNLOCK",
    )
    semantics = LocalPatternSemantics()
    semantics.contracts.add(
        ApiContract(
            lock_symbol,
            "lock",
            ObjectBinding("argument", 0),
            effect_cases=({"when": {"op": "true"}, "effect": "unknown"},),
            pairs=(unlock_symbol,),
            source="native_test_receipt",
        )
    )
    semantics.contracts.add(
        ApiContract(
            unlock_symbol,
            "unlock",
            ObjectBinding("argument", 0),
            source="native_test_receipt",
        )
    )
    semantics.add_api("lock", "LOCK", "native_test_receipt")
    semantics.add_api("unlock", "UNLOCK", "native_test_receipt")
    generator = GraphCandidateGenerator(object(), semantics, restrict_to_semantics=True)

    def facts(name: str, usr: str) -> dict:
        return {
            "complete": True,
            "build_context_id": build,
            "function_identity": {"build_context_id": build, "usr": usr},
            "functions": [
                {
                    "complete": True,
                    "owner": {"name": name, "usr": usr},
                    "events": [],
                }
            ],
            "referenced_macros": [
                {
                    "name": "LOCK",
                    "usr": lock_symbol.usr,
                    "function_identity": {"usr": usr, "build_context_id": build},
                },
                {
                    "name": "UNLOCK",
                    "usr": unlock_symbol.usr,
                    "function_identity": {"usr": usr, "build_context_id": build},
                },
            ],
        }

    outer_impl = {
        "file": "src/unit.c",
        "signature": "int outer(void)",
        "code": (
            "10 | int outer(void) {\n"
            "11 |     LOCK(&g_lock);\n"
            "12 |     inner();\n"
            "13 |     UNLOCK(&g_lock);\n"
            "14 |     return 0;\n"
            "15 | }"
        ),
        "callees": ["inner"],
    }
    inner_impl = {
        "file": "src/unit.c",
        "signature": "int inner(void)",
        "code": (
            "20 | int inner(void) {\n"
            "21 |     LOCK(&g_lock);\n"
            "22 |     UNLOCK(&g_lock);\n"
            "23 |     return 0;\n"
            "24 | }"
        ),
        "callees": [],
    }
    outer_facts = facts("outer", "c:@F@outer")
    inner_facts = facts("inner", "c:@F@inner")
    from zscope.semantics.call_context import bind_call_context

    with bind_call_context(
        {
            "func_name": "outer",
            "file_path": "src/unit.c",
            "signature": outer_impl["signature"],
            "code": outer_impl["code"],
            "program_facts": outer_facts,
        },
        generator.semantics.contracts,
    ):
        assert generator._lock_arg("LOCK(&g_lock);") == "&g_lock"
    foreign_facts = facts("outer", "c:@F@outer")
    foreign_facts["build_context_id"] = "ctx-b"
    foreign_facts["function_identity"]["build_context_id"] = "ctx-b"
    for reference in foreign_facts["referenced_macros"]:
        reference["function_identity"]["build_context_id"] = "ctx-b"
    with bind_call_context(
        {
            "func_name": "outer",
            "file_path": "src/unit.c",
            "signature": outer_impl["signature"],
            "code": outer_impl["code"],
            "program_facts": foreign_facts,
        },
        generator.semantics.contracts,
    ):
        assert generator._lock_arg("LOCK(&g_lock);") == ""
    outer = generator.prepare_function_view("outer", outer_impl, program_facts=outer_facts)
    inner = generator.prepare_function_view("inner", inner_impl, program_facts=inner_facts)

    assert outer is not None and inner is not None
    issues = generator.generate_for_prepared_views(
        [(outer, outer_facts), (inner, inner_facts)]
    )
    recursive = next(
        issue for issue in issues if issue["rule"] == "cross_function_recursive_lock"
    )
    assert recursive["function"] == "outer"
    assert recursive["sink"] == "inner:21:&g_lock"


def test_graph_candidates_cover_issue41_42_system_protocol_shapes(range_index) -> None:
    generator = GraphCandidateGenerator(range_index, _range_semantics())
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
    assert "path_state_checked_separately_from_key_generation" not in rules
    assert "unchecked_ownership_transfer_return_loses_node" in rules
    assert "protocol_mismatch_accepted_under_non_strict_auth" in rules

    premature = next(
        issue
        for issue in issues
        if issue.get("rule") == "destroy_shared_pool_while_active_tasks_remain"
    )
    assert "published to shared/global state" in "\n".join(premature["positive_evidence"])

    bridge_rules = {
        issue.get("rule") for issue in issues if issue.get("function") == "_peer_bridge_descriptor"
    }
    assert "unchecked_param_indexes_fixed_global_array" not in bridge_rules


def test_graph_registration_race_covers_scalar_check_before_lock(range_index) -> None:
    generator = GraphCandidateGenerator(range_index, _range_semantics())
    issues = generator.generate_for_functions(["_runtime_enqueue_rcu_batch"])

    issue = next(
        item
        for item in issues
        if item.get("rule") == "global_registration_slot_checked_before_lock"
    )
    assert issue["defect_class"] == "registration_race"
    assert "g_runtime_rcu_next_pending" in issue["source"]


def test_graph_view_and_batch_phases_can_be_scheduled_independently(range_index) -> None:
    generator = GraphCandidateGenerator(range_index, _range_semantics())

    view_only = generator.generate_for_functions(
        ["_runtime_enqueue_rcu_batch"],
        include_view_rules=True,
        include_batch_rules=False,
    )
    batch_only = generator.generate_for_functions(
        ["_runtime_enqueue_rcu_batch"],
        include_view_rules=False,
        include_batch_rules=True,
    )

    assert any(
        issue.get("rule") == "global_registration_slot_checked_before_lock" for issue in view_only
    )
    assert not any(
        issue.get("rule") == "global_registration_slot_checked_before_lock" for issue in batch_only
    )


def test_graph_candidates_lift_callee_key_generation_race(range_index) -> None:
    generator = GraphCandidateGenerator(range_index, _range_semantics())
    issues = generator.generate_for_functions(["_runtime_shutdown_local_session"])

    # Private path/hash names carry no implicit POSIX contract.
    assert not any(
        issue.get("rule") == "callee_path_state_checked_separately_from_key_generation"
        for issue in issues
    )


def test_graph_candidates_follow_external_length_into_callee_write_contract(range_index) -> None:
    generator = GraphCandidateGenerator(range_index, _range_semantics())
    issues = generator.generate_for_functions(["_peer_process_session_message"])

    issue = next(
        item for item in issues if item.get("rule") == "caller_limit_indexes_fixed_local_array"
    )
    assert issue["defect_class"] == "bounds"
    assert "frame.header.length" in issue["source"]
    assert "_peer_receive_session_frame" in "\n".join(issue["positive_evidence"])


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
    assert recursive["source"] == "api_update:2:&g_lock"
    assert recursive["sink"] == "helper_update:11:&g_lock"


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
        def get_function_impl(self, name: str, warn_missing: bool = False, max_lines=None):
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
    assert recursive["sink"] == "handler_update:11:&g_lock"
    assert (
        recursive["evidence_pack"]["path"]["call_evidence"]["source"]
        == "user_config:pointer_targets"
    )
    assert "configured target" in "\n".join(recursive["positive_evidence"])


def test_graph_candidates_expand_backend_indirect_call_line_evidence() -> None:
    class FakeIndex:
        def get_function_impl(self, name: str, warn_missing: bool = False, max_lines=None):
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
        def get_function_impl(self, name: str, warn_missing: bool = False, max_lines=None):
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
    assert recursive["sink"] == "handle_msg:11:&g_lock"
    assert recursive["evidence_pack"]["path"]["call_evidence"]["source"] == "user_config:dispatcher"
    assert "configured handler" in "\n".join(recursive["positive_evidence"])


def test_graph_candidates_expand_dispatcher_sibling_branches_at_depth_cap() -> None:
    class FakeIndex:
        def get_function_impl(self, name: str, warn_missing: bool = False, max_lines=None):
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
    assert recursive["sink"] == "handle_b:31:&g_lock"
