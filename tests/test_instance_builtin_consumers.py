"""Controlled consumer inputs, never native-origin or factory authorization proofs.

Each case runs the public detector entry and checks an actual emitted rule.
Allowed contracts model a caller-verified local; removing a role/contract or
shadowing a builtin must not be undone by checker defaults or literal patterns.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass

import pytest

from zscope.config.project_semantics import compiled_project_contracts, empty_project_semantics
from zscope.core.candidates.regex import RegexCandidateGenerator
from zscope.core.candidates.graph import GraphCandidateGenerator, FunctionView
from zscope.core.candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
from zscope.semantics.contracts import ApiContract
from zscope.semantics.defaults import default_local_pattern_semantics
from zscope.semantics.models import LocalPatternSemantics, CATEGORY_BY_ATTR


def controlled_local() -> LocalPatternSemantics:
    local = default_local_pattern_semantics()
    # These are explicit synthetic consumer capabilities. Production unknown
    # roots remain denied until the separate factory supplies native evidence.
    for role, names in {
        "lock": ("spin_lock", "exclusive_guard"),
        "unlock": ("spin_unlock",),
        "deallocator": ("delete",),
        "copy": ("bcopy", "strlcpy"),
        "standard_operation": (
            "access",
            "stat",
            "lstat",
            "ftok",
            "system",
            "getenv",
            "strlen",
            "strchr",
            "sleep",
            "usleep",
            "nanosleep",
            "poll",
            "select",
            "strcmp",
            "strncmp",
            "memcmp",
            "snprintf",
            "fstat",
            "__sync_bool_compare_and_swap",
            "__atomic_fetch_add",
            "__atomic_fetch_sub",
            "__builtin_add_overflow",
            "__builtin_mul_overflow",
            "__builtin_ctz",
            "__builtin_ctzll",
            "ntohl",
            "ntohs",
            "ARRAY_SIZE",
        ),
        "io_release": ("munmap",),
    }.items():
        for name in names:
            if not local.contracts.find(name, role):
                contract = ApiContract.from_row(
                    {
                        "name": name,
                        "kind": role,
                        "source": "builtin_defaults",
                        "contract": (
                            {"protocol": {"lock_mode": "exclusive"}} if role == "lock" else {}
                        ),
                    }
                )
                assert contract is not None
                local.contracts.add(contract)
                for attr, category in CATEGORY_BY_ATTR.items():
                    if category == role:
                        getattr(local, attr)[name] = ["builtin_defaults"]
    return local


def without(local, names, *, shadow=False):
    local = deepcopy(local)
    if shadow:
        local.contracts.shadowed_symbols.update(names)
    else:
        local.contracts.contracts = [
            c for c in local.contracts.contracts if c.symbol.name not in names
        ]
        for attr in CATEGORY_BY_ATTR:
            for name in names:
                getattr(local, attr).pop(name, None)
    return local


def generator(engine, local, *, restricted=True, overlay=None):
    kwargs = {"restrict_to_semantics": restricted}
    if engine == "graph":
        return GraphCandidateGenerator(object(), local, semantic_overlay=overlay, **kwargs)
    if engine == "clang":
        return ClangAstCfgCandidateGenerator(local, semantic_overlay=overlay, **kwargs)
    return RegexCandidateGenerator(local, **kwargs)


def emitted(engine, local, code, *, restricted=True, overlay=None):
    g = generator(engine, local, restricted=restricted, overlay=overlay)
    if engine == "graph":
        view = FunctionView(
            "entry", "src/demo.c", "int entry(void)", tuple(g._parse_lines(code)), ()
        )
        issues = g.generate_for_views([view])
    else:
        issues = g.generate_issues("entry", code, "src/demo.c")
    return {issue["rule"] for issue in issues}


@dataclass(frozen=True)
class Case:
    engine: str
    rule: str
    roots: tuple[str, ...]
    code: str
    allowed_emits: bool = True


CASES = [
    Case(
        "graph",
        "mutable_global_mode_drives_callback_without_lock",
        ("spin_lock",),
        """
int entry(void) {
 spin_lock(&L);
 g_mode = 1;
 if (g_mode) {
  g_table[0].cb();
 }
}
""",
        False,
    ),
    Case(
        "graph",
        "heap_thread_argument_not_released",
        ("free",),
        """
int entry(void) {
 Job *jobs = malloc(64);
 pthread_create(&t, 0, worker, &jobs[0]);
 free(jobs);
}
""",
        False,
    ),
    *[
        Case(
            "graph",
            "container_unlink_without_release",
            (release,),
            f"""
int entry(void) {{
 owner->next = node->next;
 node->next = NULL;
 {release}(node);
}}
""",
            False,
        )
        for release in ("free", "delete")
    ],
    *[
        Case(
            "graph",
            "heap_thread_argument_not_released",
            (allocation,),
            f"""
int entry(void) {{
 Job *jobs = {allocation}(source);
 pthread_create(&t, 0, worker, &jobs[0]);
}}
""",
        )
        for allocation in ("strdup", "strndup", "malloc")
    ],
    *[
        Case(
            engine,
            prefix + "double_checked_global_without_atomic",
            (lock,),
            f"""
int entry(void) {{
 if (!g_obj) {{
  {lock}(&L);
  if (!g_obj) {{
   g_obj = p;
  }}
 }}
}}
""",
        )
        for engine, prefix in (("regex", ""), ("clang", "clang_cfg_"))
        for lock in ("pthread_rwlock_rdlock", "pthread_rwlock_wrlock")
    ],
    *[
        Case(
            "clang",
            "clang_cfg_partial_aggregate_sent_with_sizeof",
            (copy,),
            f"""
int entry(void) {{
 struct Message m;
 m.tag = 1;
 {copy}(&m, dst, sizeof(m));
}}
""",
        )
        for copy in ("bcopy", "memcpy")
    ],
    Case(
        "clang",
        "clang_cfg_partial_aggregate_sent_with_sizeof",
        ("memset",),
        """
int entry(void) {
 struct Message m;
 m.tag = 1;
 memset(&m, 0, sizeof(m));
 send(fd, &m, sizeof(m));
}
""",
        False,
    ),
    *[
        Case(
            engine,
            prefix + "cond_wait_guarded_by_if",
            (wait,),
            f"""
int entry(void) {{
 if (g_pending == 0) {{
  {wait}(&cond, &L);
 }}
}}
""",
        )
        for engine, prefix in (("regex", ""), ("clang", "clang_cfg_"))
        for wait in ("pthread_cond_wait", "pthread_cond_timedwait")
    ],
    *[
        Case(
            engine,
            rule,
            ("pthread_create",),
            """
int entry(void) {
 FlushJob job;
 pthread_create(&t, 0, worker, &job);
 return 0;
}
""",
        )
        for engine, rule in (
            ("regex", "stack_address_to_thread"),
            ("clang", "clang_cfg_stack_address_passed_to_thread"),
        )
    ],
    *[
        Case(
            engine,
            rule,
            ("close",),
            """
int entry(void) {
 close(g_fd);
 return 0;
}
""",
        )
        for engine, rule in (
            ("regex", "fd_closed_without_invalidation"),
            ("clang", "clang_cfg_fd_closed_without_owner_invalidation"),
        )
    ],
    *[
        Case(
            engine,
            rule,
            ("munmap",),
            """
int entry(void) {
 munmap(g_mapping, len);
 return 0;
}
""",
        )
        for engine, rule in (
            ("regex", "mapping_unmapped_without_pointer_clear"),
            ("clang", "clang_cfg_global_mapping_unmapped_without_invalidation"),
        )
    ],
    *[
        Case(
            engine,
            prefix + "path_check_before_open",
            ("open",),
            """
int entry(void) {
 access(path, R_OK);
 open(path, O_RDONLY);
}
""",
        )
        for engine, prefix in (("regex", ""), ("clang", "clang_cfg_"))
    ],
    *[
        Case(
            engine,
            rule,
            ("system",),
            """
int entry(void) {
 system(command);
}
""",
        )
        for engine, rule in (
            ("regex", "system_with_constructed_command"),
            ("clang", "clang_cfg_system_with_nonliteral_command"),
        )
    ],
    Case(
        "graph",
        "queued_local_event_without_scheduler_wakeup",
        ("pthread_cond_signal",),
        """
int entry(void) {
 JobEvent event;
 g_event_list = &event;
 pthread_cond_signal(&cond);
}
""",
        False,
    ),
    Case(
        "clang",
        "zscope.c_cpp.cpp_clang_cfg.typed_resource_leak",
        ("fopen",),
        """
int entry(void) {
 FILE *file = fopen(path, "r");
 return 0;
}
""",
    ),
    Case(
        "clang",
        "zscope.c_cpp.cpp_clang_cfg.typed_resource_leak",
        ("fclose",),
        """
int entry(void) {
 FILE *file = fopen(path, "r");
 fclose(file);
 return 0;
}
""",
        False,
    ),
]


@pytest.mark.parametrize(
    "case", CASES, ids=lambda c: c.engine + ":" + c.rule + ":" + ",".join(c.roots)
)
@pytest.mark.parametrize("shadow", [False, True], ids=["missing", "shadowed"])
def test_instance_effects_change_actual_candidates_only_when_allowed(case, shadow):
    local = controlled_local()
    allowed = emitted(case.engine, local, case.code)
    denied = emitted(case.engine, without(local, case.roots, shadow=shadow), case.code)
    assert (case.rule in allowed) is case.allowed_emits, allowed
    assert (case.rule in denied) is not case.allowed_emits, denied


@pytest.mark.parametrize("engine", ["regex", "graph", "clang"])
def test_exact_mode_requires_explicit_local_and_owns_its_copy(engine):
    with pytest.raises(ValueError, match="explicit instance semantics"):
        generator(engine, None)
    local = controlled_local()
    first = generator(engine, local)
    second = generator(engine, local)
    first.semantics.contracts.shadowed_symbols.add("malloc")
    local.allocators.clear()
    assert "malloc" in second.semantics.allocators
    assert "malloc" not in second.semantics.contracts.shadowed_symbols
    assert "malloc" not in local.contracts.shadowed_symbols


@pytest.mark.parametrize("engine", ["graph", "clang"])
def test_overlay_cannot_restore_missing_roles(engine):
    local = without(controlled_local(), ("free", "spin_lock", "malloc", "bcopy"))
    overlay = {
        "resource_models": [
            {"name": "malloc", "kind": "allocator", "source": "builtin"},
            {"name": "free", "kind": "deallocator", "source": "builtin"},
            {"name": "bcopy", "kind": "copy", "source": "builtin"},
        ],
        "lock_models": [{"name": "spin_lock", "kind": "lock", "source": "builtin"}],
        "symbol_origins": {"free": "system", "spin_lock": "system"},
    }
    code = (
        "int entry(void) {\n p = malloc(32);\n free(p);\n free(p);\n spin_lock(&L);\n return 0;\n}"
    )
    assert emitted(engine, local, code, overlay=overlay) == emitted(engine, local, code)


@pytest.mark.parametrize("engine", ["regex", "graph", "clang"])
def test_bare_role_without_contract_does_not_mint_effect(engine):
    local = LocalPatternSemantics()
    local.allocators["malloc"] = ["manual"]
    local.lock_apis["pthread_mutex_lock"] = ["builtin"]
    g = generator(engine, local)
    assert not g.semantics.allocators
    assert not g.semantics.lock_apis
    assert not g.semantics.contracts.contracts


def test_checker_only_missing_origin_is_not_implicitly_allowed():
    local = default_local_pattern_semantics()
    code = "int entry(void) {\n owner->next = node->next;\n node->next = NULL;\n delete(node);\n}"
    assert "container_unlink_without_release" in emitted("graph", local, code)
    assert "container_unlink_without_release" not in emitted("graph", local, code, restricted=False)
    code = "int entry(void) {\n struct Message m;\n m.tag = 1;\n bcopy(&m, dst, sizeof(m));\n}"
    assert "clang_cfg_partial_aggregate_sent_with_sizeof" not in emitted("clang", local, code)
    assert "clang_cfg_partial_aggregate_sent_with_sizeof" in emitted(
        "clang", local, code, restricted=False
    )


# Reuse the original, unchanged engine fixture text. Expected rule IDs are
# explicit here; no product implementation is inspected to derive assertions.
# Both halves execute the public consumer. The empty instance has no effects,
# so it cannot emit API-based obligations merely from packaged spellings.
def fixture_code(function, variable="code", file="test_clang_ast_cfg_candidates.py"):
    import ast
    from pathlib import Path

    tree = ast.parse(Path(__file__).with_name(file).read_text(encoding="utf-8"))
    owner = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == function)
    for node in ast.walk(owner):
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == variable for t in node.targets
        ):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                return node.value.value
    raise AssertionError(f"missing original fixture: {function}:{variable}")


FIXTURE_CASES = [
    (
        "detects_double_free_and_use_after_free",
        "code",
        ("clang_cfg_same_object_released_twice", "clang_cfg_use_after_release"),
    ),
    (
        "detects_acquire_without_release_on_return",
        "code",
        ("clang_cfg_acquire_without_release_on_exit",),
    ),
    (
        "detects_parent_release_without_owned_member_cleanup",
        "explicit_code",
        ("clang_cfg_parent_release_without_owned_member_cleanup",),
    ),
    ("detects_return_while_lock_held", "code", ("clang_cfg_return_with_lock_held",)),
    (
        "detects_common_c_specialized_patterns",
        "code",
        (
            "clang_cfg_external_length_field_reaches_copy",
            "clang_cfg_allocation_size_arithmetic_without_overflow_guard",
            "clang_cfg_nonliteral_format_string",
            "clang_cfg_path_check_before_open",
        ),
    ),
    ("detects_command_injection_evidence", "builder_code", ("clang_cfg_shell_command_concat_env",)),
    (
        "detects_refcount_and_signed_unsigned_patterns",
        "code",
        ("clang_cfg_refcount_update_after_unlock", "clang_cfg_negative_length_cast_to_size_t"),
    ),
    (
        "keeps_object_publication_when_not_same_lock_region",
        "code",
        ("clang_cfg_object_published_before_initialization",),
    ),
    (
        "detects_lifecycle_gap_patterns",
        "code",
        (
            "clang_cfg_stack_address_passed_to_thread",
            "clang_cfg_partial_aggregate_sent_with_sizeof",
            "clang_cfg_free_non_owner_pointer_expression",
        ),
    ),
    (
        "detects_range_unified_missed_patterns",
        "td_init",
        ("clang_cfg_heap_thread_argument_owner_not_released",),
    ),
    (
        "detects_range_unified_missed_patterns",
        "log_leak",
        ("clang_cfg_log_error_path_allocation_not_released",),
    ),
    (
        "detects_range_unified_missed_patterns",
        "protocol_len",
        ("clang_cfg_protocol_units_length_reaches_copy_without_packet_bound",),
    ),
    (
        "detects_range_unified_missed_patterns",
        "refcount_close",
        ("clang_cfg_shared_resource_freed_without_refcount_protocol",),
    ),
    ("detects_unchecked_strchr_result", "code", ("clang_cfg_unchecked_strchr_result",)),
    (
        "detects_registry_unlink_free_after_unlock",
        "code",
        ("clang_cfg_registry_unlink_free_after_unlock",),
    ),
    (
        "detects_raw_fd_to_encoded_validator_mismatch",
        "code",
        ("clang_cfg_raw_fd_revalidated_as_encoded",),
    ),
    (
        "detects_structured_protocol_shapes",
        "code",
        (
            "clang_cfg_wide_count_read_without_magic_guard",
            "clang_cfg_fixed_byte_limit_before_spec_count_check",
            "clang_cfg_recv_retry_loop_without_timeout_or_budget",
            "clang_cfg_global_dynamic_array_resize_without_lock",
        ),
    ),
    (
        "promotes_wide_count_before_magic_when_count_reaches_copy_sink",
        "code",
        ("clang_cfg_wide_count_before_magic_reaches_memory_sink",),
    ),
    (
        "callback_under_lock_is_contract_risk_not_exploit_claim",
        "code",
        ("clang_cfg_callback_while_lock_held",),
    ),
    (
        "detects_callback_context_and_mapping_lifetime",
        "callback_code",
        ("clang_cfg_global_callback_stores_borrowed_object",),
    ),
    ("detects_free_of_derived_pointer_alias", "code", ("clang_cfg_free_derived_pointer_alias",)),
    (
        "detects_unchecked_allocation_use",
        "code",
        (
            "clang_cfg_allocation_result_used_without_null_check",
            "clang_cfg_alloc_result_deref_without_null_guard",
        ),
    ),
    (
        "detects_unbounded_heap_allocation",
        "code",
        ("clang_cfg_external_size_allocation_without_limit",),
    ),
    ("detects_fd_leak_on_error_return", "code", ("clang_cfg_fd_open_return_without_close",)),
    (
        "emits_heap_overflow_for_narrowed_allocation_then_original_copy",
        "code",
        ("clang_cfg_narrowed_allocation_original_length_copy",),
    ),
    (
        "emits_file_type_validation_order",
        "code",
        ("clang_cfg_file_type_validation_after_mapping_size_check",),
    ),
    (
        "emits_premature_destroy_for_active_shared_pool",
        "code",
        ("clang_cfg_active_owner_destroy_without_quiescence",),
    ),
    (
        "emits_timer_callback_lock_order_candidate",
        "code",
        ("clang_cfg_timer_callback_object_lock_without_scheduler_lock",),
    ),
    (
        "emits_pointer_backtrack_underread_and_underwrite",
        "read_code",
        ("clang_cfg_unchecked_pointer_backtrack",),
    ),
    (
        "emits_offset_length_overread",
        "code",
        ("clang_cfg_offset_length_copy_without_source_bound",),
    ),
    (
        "emits_slot_overwrite_leak",
        "code",
        ("clang_cfg_slot_overwrite_without_existing_owner_cleanup",),
    ),
    (
        "emits_key_truncation_and_key_generation_race",
        "truncation_code",
        ("clang_cfg_full_key_lookup_truncated_key_insert",),
    ),
    (
        "emits_key_truncation_and_key_generation_race",
        "race_code",
        ("clang_cfg_path_state_key_generation_before_locked_registration",),
    ),
    (
        "emits_header_length_copy_without_wire_bound",
        "code",
        ("clang_cfg_header_length_reaches_copy_without_wire_bound",),
    ),
]


@pytest.mark.parametrize(
    "name, variable, rules", FIXTURE_CASES, ids=[n + ":" + v for n, v, _ in FIXTURE_CASES]
)
def test_existing_clang_fixture_effects_are_not_reintroduced_into_empty_instance(
    name, variable, rules
):
    from semantic_fixtures import configured_test_semantics

    local = controlled_local()
    local.merge(configured_test_semantics())
    code = fixture_code("test_clang_ast_cfg_" + name, variable)
    positive = emitted("clang", local, code)
    negative = emitted("clang", LocalPatternSemantics(), code)
    assert set(rules) <= positive, positive
    # These rules also have structural branches independent of API effects.
    # Retain that evidence in an empty instance; exact mode is not a rule kill switch.
    structural = {
        "clang_cfg_object_published_before_initialization",
        "clang_cfg_raw_fd_revalidated_as_encoded",
        "clang_cfg_fixed_byte_limit_before_spec_count_check",
        "clang_cfg_file_type_validation_after_mapping_size_check",
        "clang_cfg_slot_overwrite_without_existing_owner_cleanup",
    }
    assert set(rules) & negative == set(rules) & structural, negative
    assert set(rules).isdisjoint(emitted("clang", local, "int entry(void) { return 0; }"))


REGEX_FIXTURES = [
    (
        "test_memory_and_concurrency_candidate_patterns",
        (
            "inline_allocation_size_overflow",
            "direct_realloc_assignment",
            "unchecked_strchr_result",
            "return_while_lock_held",
        ),
    ),
    (
        "test_deeper_c_lifetime_and_thread_patterns",
        (
            "object_published_before_initialization",
            "refcount_update_after_unlock",
            "global_callback_context_borrowed_under_lock",
            "callback_while_lock_held",
            "stack_address_to_thread",
            "cond_wait_guarded_by_if",
            "negative_length_cast_to_size_t",
            "partial_struct_sent",
            "free_non_owner_pointer",
        ),
    ),
    (
        "test_helper_publication_before_late_initialization_is_object_publication",
        ("object_published_by_helper_before_initialization",),
    ),
    (
        "test_safe_free_parent_still_reports_unreleased_member_allocations",
        ("member_allocation_not_released_with_parent",),
    ),
    (
        "test_unchecked_insert_after_node_allocation_is_ownership_candidate",
        ("unchecked_insert_after_ownership_handoff",),
    ),
    (
        "test_pointer_return_after_unlock_still_reports_borrowed_pointer",
        ("borrowed_pointer_returned_after_unlock",),
    ),
]


@pytest.mark.parametrize("name,rules", REGEX_FIXTURES)
def test_regex_original_positive_and_clean_negative_in_exact_mode(name, rules):
    from semantic_fixtures import configured_test_semantics

    local = controlled_local()
    local.merge(configured_test_semantics())
    code = fixture_code(name, file="test_regex_candidates.py")
    assert set(rules) <= emitted("regex", local, code)
    assert set(rules) & emitted("regex", LocalPatternSemantics(), code) == set(rules) & {
        "object_published_before_initialization"
    }
    assert set(rules).isdisjoint(emitted("regex", local, "int entry(void) { return 0; }"))


GRAPH_GROUPS = [
    (
        (
            "_plugin_unregister",
            "td_cleanup",
            "td_init",
            "_lifecycle_register_topic_subscription",
            "_lifecycle_unregister_topic_subscription",
            "_lifecycle_attach_proc_node",
            "_lifecycle_delete_os_node",
        ),
        (
            "cross_function_recursive_lock",
            "cleanup_contract_type_mismatch",
            "heap_thread_argument_not_released",
            "paired_nested_mutex_cleanup_omitted",
            "paired_child_list_cleanup_omitted",
            "child_list_cleanup_omitted",
        ),
    ),
    (
        (
            "_lifecycle_dispatch_pipe_tick",
            "_lifecycle_close_pipe",
            "_lifecycle_tick_timer_callback",
            "_lifecycle_avl_policy_upsert",
            "_lifecycle_avl_register_route",
        ),
        (
            "cross_function_lock_order_inversion",
            "timer_callback_cascade_wait",
            "full_key_lookup_truncated_insert",
            "insert_failure_leaves_stale_tree_node",
        ),
    ),
    (
        (
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
        ),
        (
            "peer_write_without_sigpipe_handling",
            "encoded_or_reliable_fd_passed_to_raw_fd_contract",
            "destroy_shared_pool_while_active_tasks_remain",
            "unchecked_param_indexes_fixed_global_array",
            "signal_path_mutates_shared_state_or_logs",
            "caller_limit_indexes_fixed_local_array",
            "global_registration_slot_checked_before_lock",
            "mutable_global_mode_drives_callback_without_lock",
            "unchecked_ownership_transfer_return_loses_node",
        ),
    ),
]


@pytest.fixture(scope="module")
def consumer_range_index():
    from test_graph_candidates import _range_index

    return _range_index()


@pytest.mark.parametrize("names,rules", GRAPH_GROUPS)
def test_graph_original_selected_fixture_positive_and_clean_negative(
    consumer_range_index, names, rules
):
    from test_graph_candidates import _range_semantics

    local = controlled_local()
    local.merge(_range_semantics())
    g = GraphCandidateGenerator(consumer_range_index, local, restrict_to_semantics=True)
    observed = {i["rule"] for i in g.generate_for_functions(names)}
    assert set(rules) <= observed, observed
    assert set(rules).isdisjoint(emitted("graph", local, "int entry(void) { return 0; }"))


EXTRA_CASES = [
    Case(
        "graph",
        "cas_result_ignored_before_slot_publication",
        ("__sync_bool_compare_and_swap",),
        "int entry(void) {\n (void)__sync_bool_compare_and_swap(&slot->state, 0, 1);\n slot->pid = pid;\n}",
    ),
    Case(
        "graph",
        "single_reader_field_under_shared_reader_count",
        ("__atomic_fetch_add",),
        "int entry(void) {\n __atomic_fetch_add(&readers, 1, 0);\n pool->reader = tid;\n __atomic_fetch_sub(&readers, 1, 0);\n}",
    ),
    Case(
        "graph",
        "wire_bitmap_ctz_without_endian_normalization",
        ("ntohl",),
        "int entry(void) {\n memcpy(&word, input + 4, 4);\n word = ntohl(word);\n int bit = __builtin_ctz(word);\n}",
        False,
    ),
    Case(
        "graph",
        "partial_stack_struct_copied_to_output",
        ("memset",),
        "int entry(void) {\n Message m;\n m.tag = 1;\n memset(&m, 0, sizeof(m));\n *out = m;\n}",
        False,
    ),
    Case(
        "graph",
        "nested_mutex_cleanup_omitted",
        ("pthread_mutex_destroy",),
        "int entry(void) {\n pthread_mutex_init(&node->mutex, 0);\n pthread_mutex_destroy(&node->mutex);\n free(node);\n}",
        False,
    ),
]


@pytest.mark.parametrize("case", EXTRA_CASES, ids=[c.rule for c in EXTRA_CASES])
@pytest.mark.parametrize("shadow", [False, True], ids=["missing", "shadowed"])
def test_additional_actual_emit_and_suppression_boundaries(case, shadow):
    local = controlled_local()
    assert (case.rule in emitted(case.engine, local, case.code)) == case.allowed_emits
    denied = without(local, case.roots, shadow=shadow)
    assert (case.rule in emitted(case.engine, denied, case.code)) != case.allowed_emits


def test_graph_paired_key_contracts_use_both_exact_api_roots():
    local = controlled_local()
    codes = {
        "lookup_key": "int lookup_key(char *key) {\n return strcmp(node->key, key);\n}",
        "insert_key": "int insert_key(char *key) {\n strncpy(node->key, key, ROUTE_KEY_LIMIT);\n}",
    }

    def rules(semantics):
        g = generator("graph", semantics)
        views = [
            FunctionView(
                name, "src/demo.c", f"int {name}(char *key)", tuple(g._parse_lines(code)), ()
            )
            for name, code in codes.items()
        ]
        return {i["rule"] for i in g.generate_for_views(views)}

    assert "paired_full_key_lookup_truncated_insert" in rules(local)
    assert "paired_full_key_lookup_truncated_insert" not in rules(without(local, ("strcmp",)))
    assert "paired_full_key_lookup_truncated_insert" not in rules(without(local, ("strncpy",)))


def test_graph_allowed_release_name_is_case_sensitive():
    code = "int entry(void) {\n insert_node(node);\n FREE(node);\n}"
    assert "insert_failure_leaves_stale_tree_node" not in emitted("graph", controlled_local(), code)
    assert "insert_failure_leaves_stale_tree_node" in emitted(
        "graph", controlled_local(), code.replace("FREE", "free")
    )


REGEX_EFFECT_CASES = [
    Case(
        "regex",
        "arithmetic_size_before_sink",
        ("malloc",),
        "int entry(size_t count, size_t stride) {\n size_t bytes = count * stride;\n void *p = malloc(bytes);\n}",
    ),
    Case(
        "regex",
        "derived_protocol_length_reaches_copy_without_input_bound",
        ("memcpy",),
        "int entry(size_t packet_len) {\n size_t length = count * 8;\n memcpy(dst, src, length);\n}",
    ),
    Case(
        "regex",
        "header_length_subtraction_reaches_copy",
        ("memcpy",),
        "int entry(void) {\n size_t body_len = header->total_length - 4;\n memcpy(dst, src, body_len);\n}",
    ),
    Case(
        "regex",
        "error_path_allocation_not_released",
        ("malloc",),
        "int entry(void) {\n void *p = malloc(10);\n return -1;\n}",
    ),
    Case(
        "regex",
        "same_function_allocation_not_released",
        ("malloc",),
        "int entry(void) {\n void *p = malloc(10);\n return 0;\n}",
    ),
    Case(
        "regex",
        "external_length_field_reaches_copy",
        ("memcpy",),
        "int entry(void) {\n size_t body_len = header->payload_length;\n memcpy(dst, src, body_len);\n}",
    ),
    Case(
        "regex", "nonliteral_format_string", ("printf",), "int entry(char *fmt) {\n printf(fmt);\n}"
    ),
    Case(
        "regex",
        "error_probe_can_return_success",
        ("printf",),
        "int entry(int ret) {\n printf(msg);\n if (ret < 0) return ret;\n return 0;\n}",
    ),
    Case(
        "regex",
        "lookup_like_call_under_held_lock",
        ("spin_lock",),
        "int entry(void) {\n spin_lock(&L);\n project_find_node(key);\n}",
    ),
    Case(
        "regex",
        "recv_retry_without_backoff",
        ("recv",),
        "int entry(void) {\n while (1) {\n int rc = recv(fd, buf, 1, 0);\n if (rc <= 0) continue;\n }\n}",
    ),
    Case(
        "regex",
        "same_expression_freed_twice",
        ("free",),
        "int entry(Node *node) {\n free(node->payload);\n free(node->payload);\n}",
    ),
    Case(
        "regex",
        "same_pointer_freed_twice",
        ("free",),
        "int entry(void) {\n void *p = malloc(10);\n free(p);\n free(p);\n}",
    ),
    Case(
        "regex",
        "truncated_key_used_for_route_insert",
        ("strncpy",),
        "int entry(char *full_key) {\n strncpy(node->key, full_key, 16);\n node->key[16] = '\\0';\n}",
    ),
    Case(
        "regex",
        "write_without_sigpipe_handling",
        ("write",),
        "int entry(void) {\n write(peer_fd, data, size);\n}",
    ),
    Case(
        "regex",
        "unsynchronized_shared_flag_or_counter",
        ("exclusive_guard",),
        "int entry(void) {\n exclusive_guard(&L);\n g_busy_flag = 1;\n}",
        False,
    ),
]


@pytest.mark.parametrize("case", REGEX_EFFECT_CASES, ids=[c.rule for c in REGEX_EFFECT_CASES])
@pytest.mark.parametrize("shadow", [False, True])
def test_regex_role_and_literal_effects(case, shadow):
    local = controlled_local()
    assert (case.rule in emitted(case.engine, local, case.code)) == case.allowed_emits
    assert (
        case.rule in emitted(case.engine, without(local, case.roots, shadow=shadow), case.code)
    ) != case.allowed_emits


@pytest.mark.parametrize("name", ["sleep", "usleep", "nanosleep", "poll", "select"])
def test_unverified_backoff_does_not_hide_retry_loop(name):
    local = controlled_local()
    code = f"int entry(void) {{\n while (1) {{\n int rc = recv(fd, buf, 1, 0);\n {name}(1);\n if (rc <= 0) continue;\n }}\n}}"
    assert "recv_retry_without_backoff" not in emitted("regex", local, code)
    assert "recv_retry_without_backoff" in emitted("regex", without(local, (name,)), code)


def test_unknown_delete_call_does_not_fake_tree_rollback():
    code = "int entry(void) {\n insert_node(node);\n delete(node);\n free(node);\n}"
    local = controlled_local()
    assert "insert_failure_leaves_stale_tree_node" not in emitted("graph", local, code)
    assert "insert_failure_leaves_stale_tree_node" in emitted(
        "graph", without(local, ("delete",)), code
    )


@pytest.mark.parametrize(
    "statement, rule",
    [
        (
            "void *p = malloc(body_len + 8);",
            "clang_cfg_allocation_size_arithmetic_without_overflow_guard",
        ),
        ("size_t body_total = body_len + extra;", "clang_cfg_size_addition_without_overflow_guard"),
        (
            "uint32_t small = (uint32_t)body_length;",
            "clang_cfg_narrowing_size_cast_without_range_guard",
        ),
    ],
)
def test_unrelated_overflow_intrinsic_cannot_discharge_arithmetic(statement, rule):
    code = f"int entry(size_t body_len, size_t body_length, size_t extra) {{\n __builtin_add_overflow(a, b, &out);\n {statement}\n}}"
    local = controlled_local()
    assert rule in emitted("clang", local, code)
    assert rule in emitted("clang", without(local, ("__builtin_add_overflow",)), code)


@pytest.mark.parametrize("engine", ["regex", "clang"])
@pytest.mark.parametrize("spelling", ["atomic_magic(&shared);", "std::atomic<int> local;"])
def test_atomic_spelling_cannot_hide_a_distinct_shared_write(engine, spelling):
    code = f"void entry(void) {{\n shared++; {spelling}\n}}"
    local = controlled_local()
    local.contracts.add(
        ApiContract.from_row(
            {"name": "atomic_magic", "kind": "standard_operation", "source": "builtin_defaults"}
        )
    )
    rule = ("clang_cfg_" if engine == "clang" else "") + "unsynchronized_shared_flag_or_counter"
    assert rule in emitted(engine, local, code)
    assert rule not in emitted(engine, local, code, restricted=False)


@pytest.mark.parametrize("engine", ["regex", "clang"])
@pytest.mark.parametrize("atomic, expected", [(True, False), (False, True)])
def test_current_native_access_atomicity_still_controls_shared_access_leads(
    engine, atomic, expected
):
    # A controlled fact input tests consumption only, not native generation.
    local = controlled_local()
    facts = {
        "complete": True,
        "accesses": [{"target": {"name": "shared"}, "location": {"line": 2}, "atomic": atomic}],
    }
    cls = RegexCandidateGenerator if engine == "regex" else ClangAstCfgCandidateGenerator
    g = cls(local, program_facts_provider=lambda *_: facts, restrict_to_semantics=True)
    code = "void entry(void) {\n shared++; atomic_magic(&other);\n}"
    rule = ("clang_cfg_" if engine == "clang" else "") + "unsynchronized_shared_flag_or_counter"
    assert any(i["rule"] == rule for i in g.generate_issues("entry", code, "a.c")) == expected


@pytest.mark.parametrize(
    ("engine", "expected_rule"),
    [
        ("regex", "path_check_before_open"),
        ("clang", "clang_cfg_path_check_before_open"),
    ],
)
def test_exact_native_path_query_wrapper_reaches_toctou_consumers(engine, expected_rule):
    build = "build-path-query"
    wrapper_usr = "c:@F@_file_exists"
    local = controlled_local()
    document = empty_project_semantics()
    document["interfaces"] = [
        {
            "id": "project:function:_file_exists:test",
            "primitive": False,
            "selector": {
                "kind": "function",
                "name": "_file_exists",
                "file": "src/path.c",
                "signature": "int (const char *)",
                "usr": wrapper_usr,
            },
            "basis": "derived_wrapper",
            "status": "confirmed",
            "cases": [
                {
                    "when": {
                        "op": "compare",
                        "left": {"kind": "argument", "index": 0},
                        "operator": "!=",
                        "right": {"kind": "literal", "value": None},
                    },
                    "effect": "applies",
                },
                {
                    "when": {
                        "op": "compare",
                        "left": {"kind": "argument", "index": 0},
                        "operator": "==",
                        "right": {"kind": "literal", "value": None},
                    },
                    "effect": "no_effect",
                },
            ],
            "effects": [
                {
                    "domain": "protocol",
                    "role": "standard_operation",
                    "operation": "standard_operation",
                    "carrier": {
                        "root": "argument",
                        "index": 0,
                        "phase": "post",
                        "dereference": 0,
                        "members": [],
                    },
                    "resource_family": "",
                    "strength": "must_under_guard",
                    "protocol": {},
                }
            ],
            "otherwise": "unknown",
            "pairs": [],
            "derived_from": ["builtin:stat"],
            "evidence_summary": "Current exact native wrapper proof.",
            "evidence_ref": "evidence.json#file-exists",
            "evidence_digest": "d" * 64,
            "variants": [
                {
                    "target_id": "main",
                    "build_context_id": build,
                    "usr": wrapper_usr,
                    "signature": "int (const char *)",
                    "file": "src/path.c",
                    "source_sha256": "a" * 64,
                    "evidence_sha256": "b" * 64,
                    "native_input_hash": "c" * 64,
                    "identity_status": "exact",
                }
            ],
        }
    ]
    payload = compiled_project_contracts(document, build_context_id=build)[0]
    contract = ApiContract.from_row(
        {
            "source": payload["source"],
            "kind": payload["role"],
            "contract": payload,
        }
    )
    assert contract is not None and contract.effects_trusted
    local.contracts.add(contract)
    local.contracts.build_context_id = build
    facts = {
        "complete": True,
        "build_context_id": build,
        "function_identity": {"usr": "c:@F@entry", "build_context_id": build},
        "functions": [
            {
                "complete": True,
                "owner": {"name": "entry", "usr": "c:@F@entry"},
                "events": [
                    {
                        "event_kind": "call",
                        "expression": "_file_exists(path)",
                        "arguments": ["path"],
                        "callee": {
                            "name": "_file_exists",
                            "usr": wrapper_usr,
                            "canonical_signature": "int (const char *)",
                        },
                        "location": {"line": 2},
                    }
                ],
            }
        ],
    }
    cls = RegexCandidateGenerator if engine == "regex" else ClangAstCfgCandidateGenerator
    code = """
int entry(const char *path) {
    if (!_file_exists(path)) return -1;
    return open(path, 0);
}
"""
    exact = cls(
        local,
        program_facts_provider=lambda *_: facts,
        restrict_to_semantics=True,
    ).generate_issues("entry", code, "src/demo.c")
    unknown_identity = cls(
        local,
        program_facts_provider=lambda *_: {**facts, "functions": []},
        restrict_to_semantics=True,
    ).generate_issues("entry", code, "src/demo.c")

    assert expected_rule in {issue["rule"] for issue in exact}
    assert expected_rule not in {issue["rule"] for issue in unknown_identity}
    if engine == "clang":
        key_code = """
int entry(const char *path) {
    if (!_file_exists(path)) return -1;
    int key = hash_path(path);
    pthread_mutex_lock(&g_lock); if (find_zone(path)) return -1;
    pthread_mutex_unlock(&g_lock);
    return key;
}
"""
        key_rules = cls(
            local,
            program_facts_provider=lambda *_: facts,
            restrict_to_semantics=True,
        ).generate_issues("entry", key_code, "src/demo.c")
        assert "clang_cfg_path_state_key_generation_before_locked_registration" in {
            issue["rule"] for issue in key_rules
        }


REVISED_RULES = [
    ["clang", "clang_cfg_unchecked_pointer_backtrack"],
    ["regex", "arithmetic_size_before_sink"],
    ["regex", "borrowed_pointer_returned_after_unlock"],
    ["regex", "callback_while_lock_held"],
    ["regex", "calloc_product_overflow"],
    ["regex", "cond_wait_guarded_by_if"],
    ["regex", "derived_protocol_length_reaches_copy_without_input_bound"],
    ["regex", "direct_realloc_assignment"],
    ["regex", "double_checked_global_without_atomic"],
    ["regex", "error_path_allocation_not_released"],
    ["regex", "error_probe_can_return_success"],
    ["regex", "external_length_field_reaches_copy"],
    ["regex", "fd_closed_without_invalidation"],
    ["regex", "free_non_owner_pointer"],
    ["regex", "global_callback_context_borrowed_under_lock"],
    ["regex", "header_length_subtraction_reaches_copy"],
    ["regex", "inline_allocation_size_overflow"],
    ["regex", "lookup_like_call_under_held_lock"],
    ["regex", "mapping_unmapped_without_pointer_clear"],
    ["regex", "member_allocation_not_released_with_parent"],
    ["regex", "negative_length_cast_to_size_t"],
    ["regex", "nonliteral_format_string"],
    ["regex", "object_published_before_initialization"],
    ["regex", "object_published_by_helper_before_initialization"],
    ["regex", "partial_struct_sent"],
    ["regex", "path_check_before_open"],
    ["regex", "recv_retry_without_backoff"],
    ["regex", "refcount_update_after_unlock"],
    ["regex", "return_while_lock_held"],
    ["regex", "same_expression_freed_twice"],
    ["regex", "same_function_allocation_not_released"],
    ["regex", "same_pointer_freed_twice"],
    ["regex", "stack_address_to_thread"],
    ["regex", "system_with_constructed_command"],
    ["regex", "truncated_key_used_for_route_insert"],
    ["regex", "unchecked_insert_after_ownership_handoff"],
    ["regex", "unchecked_strchr_result"],
    ["regex", "unsynchronized_shared_flag_or_counter"],
    ["regex", "write_without_sigpipe_handling"],
    ["clang", "clang_cfg_acquire_without_release_on_exit"],
    ["clang", "clang_cfg_active_owner_destroy_without_quiescence"],
    ["clang", "clang_cfg_alloc_result_deref_without_null_guard"],
    ["clang", "clang_cfg_allocation_result_used_without_null_check"],
    ["clang", "clang_cfg_allocation_size_arithmetic_without_overflow_guard"],
    ["clang", "clang_cfg_borrowed_pointer_returned_after_unlock"],
    ["clang", "clang_cfg_callback_while_lock_held"],
    ["clang", "clang_cfg_cond_wait_guarded_by_if"],
    ["clang", "clang_cfg_container_unlink_without_release"],
    ["clang", "clang_cfg_double_checked_global_without_atomic"],
    ["clang", "clang_cfg_external_length_field_reaches_copy"],
    ["clang", "clang_cfg_external_size_allocation_without_limit"],
    ["clang", "clang_cfg_fd_closed_without_owner_invalidation"],
    ["clang", "clang_cfg_fd_open_return_without_close"],
    ["clang", "clang_cfg_file_type_validation_after_mapping_size_check"],
    ["clang", "clang_cfg_fixed_byte_limit_before_spec_count_check"],
    ["clang", "clang_cfg_free_derived_pointer_alias"],
    ["clang", "clang_cfg_free_non_owner_pointer_expression"],
    ["clang", "clang_cfg_full_key_lookup_truncated_key_insert"],
    ["clang", "clang_cfg_global_callback_stores_borrowed_object"],
    ["clang", "clang_cfg_global_dynamic_array_resize_without_lock"],
    ["clang", "clang_cfg_global_mapping_unmapped_without_invalidation"],
    ["clang", "clang_cfg_global_pointer_length_pair_published_without_lock"],
    ["clang", "clang_cfg_global_state_written_with_and_without_lock"],
    ["clang", "clang_cfg_header_length_reaches_copy_without_wire_bound"],
    ["clang", "clang_cfg_heap_thread_argument_owner_not_released"],
    ["clang", "clang_cfg_incomplete_owned_member_cleanup"],
    ["clang", "clang_cfg_log_error_path_allocation_not_released"],
    ["clang", "clang_cfg_macro_guarded_lock_may_compile_to_noop"],
    ["clang", "clang_cfg_narrowed_allocation_original_length_copy"],
    ["clang", "clang_cfg_narrowing_size_cast_without_range_guard"],
    ["clang", "clang_cfg_negative_length_cast_to_size_t"],
    ["clang", "clang_cfg_nonliteral_format_string"],
    ["clang", "clang_cfg_object_published_before_initialization"],
    ["clang", "clang_cfg_offset_length_copy_without_source_bound"],
    ["clang", "clang_cfg_out_param_used_before_success_check"],
    ["clang", "clang_cfg_parent_release_without_owned_member_cleanup"],
    ["clang", "clang_cfg_partial_aggregate_sent_with_sizeof"],
    ["clang", "clang_cfg_path_check_before_open"],
    ["clang", "clang_cfg_path_state_key_generation_before_locked_registration"],
    ["clang", "clang_cfg_probe_error_branch_can_return_success_status"],
    ["clang", "clang_cfg_protocol_units_length_reaches_copy_without_packet_bound"],
    ["clang", "clang_cfg_raw_fd_revalidated_as_encoded"],
    ["clang", "clang_cfg_realloc_lost_original"],
    ["clang", "clang_cfg_recv_retry_loop_without_timeout_or_budget"],
    ["clang", "clang_cfg_refcount_update_after_unlock"],
    ["clang", "clang_cfg_registry_unlink_free_after_unlock"],
    ["clang", "clang_cfg_requested_permission_not_applied_to_mode"],
    ["clang", "clang_cfg_return_with_lock_held"],
    ["clang", "clang_cfg_role_specific_release_argument_mismatch"],
    ["clang", "clang_cfg_same_object_released_twice"],
    ["clang", "clang_cfg_shared_resource_freed_without_refcount_protocol"],
    ["clang", "clang_cfg_shell_command_concat_env"],
    ["clang", "clang_cfg_size_addition_without_overflow_guard"],
    ["clang", "clang_cfg_slot_overwrite_without_existing_owner_cleanup"],
    ["clang", "clang_cfg_stack_address_passed_to_thread"],
    ["clang", "clang_cfg_system_with_nonliteral_command"],
    ["clang", "clang_cfg_timer_callback_object_lock_without_scheduler_lock"],
    ["clang", "clang_cfg_unbounded_count_indexes_fixed_array"],
    ["clang", "clang_cfg_unchecked_insert_after_ownership_handoff"],
    ["clang", "clang_cfg_unchecked_param_indexes_fixed_global_array"],
    ["clang", "clang_cfg_unchecked_strchr_result"],
    ["clang", "clang_cfg_unlock_without_matching_lock"],
    ["clang", "clang_cfg_unsynchronized_shared_flag_or_counter"],
    ["clang", "clang_cfg_use_after_release"],
    ["clang", "clang_cfg_wide_count_before_magic_reaches_memory_sink"],
    ["clang", "clang_cfg_wide_count_read_without_magic_guard"],
    ["graph", "callback_can_free_current_event_before_reacquire"],
    ["graph", "callee_path_state_checked_separately_from_key_generation"],
    ["graph", "caller_limit_indexes_fixed_local_array"],
    ["graph", "caller_limit_indexes_fixed_member_array"],
    ["graph", "cas_result_ignored_before_slot_publication"],
    ["graph", "child_list_cleanup_omitted"],
    ["graph", "cleanup_contract_type_mismatch"],
    ["graph", "composed_string_copied_to_member_buffer_without_bound"],
    ["graph", "container_unlink_free_after_unlock"],
    ["graph", "container_unlink_without_release"],
    ["graph", "cross_function_lock_order_inversion"],
    ["graph", "cross_function_recursive_lock"],
    ["graph", "destroy_shared_pool_while_active_tasks_remain"],
    ["graph", "encoded_or_reliable_fd_passed_to_raw_fd_contract"],
    ["graph", "full_key_lookup_truncated_insert"],
    ["graph", "global_container_registration_without_cleanup_path"],
    ["graph", "global_registration_slot_checked_before_lock"],
    ["graph", "heap_thread_argument_not_released"],
    ["graph", "insert_failure_leaves_stale_tree_node"],
    ["graph", "lookup_before_insert_lock"],
    ["graph", "mutable_global_mode_drives_callback_without_lock"],
    ["graph", "nested_mutex_cleanup_omitted"],
    ["graph", "paired_child_list_cleanup_omitted"],
    ["graph", "paired_free_wrapper_omits_dynamic_member"],
    ["graph", "paired_full_key_lookup_truncated_insert"],
    ["graph", "paired_global_registration_cleanup_omitted"],
    ["graph", "paired_nested_mutex_cleanup_omitted"],
    ["graph", "partial_stack_struct_copied_to_output"],
    ["graph", "path_state_checked_separately_from_key_generation"],
    ["graph", "peer_write_without_sigpipe_handling"],
    ["graph", "published_before_member_initialization"],
    ["graph", "queued_local_event_without_scheduler_wakeup"],
    ["graph", "registered_global_object_missing_release_hook"],
    ["graph", "role_specific_release_uses_hardcoded_role"],
    ["graph", "same_function_helper_alloc_wrapper_member_leak"],
    ["graph", "signal_path_mutates_shared_state_or_logs"],
    ["graph", "signal_path_uses_locking_and_formatting"],
    ["graph", "single_reader_field_under_shared_reader_count"],
    ["graph", "timer_callback_cascade_wait"],
    ["graph", "unchecked_ownership_transfer_return_loses_node"],
    ["graph", "unchecked_param_indexes_fixed_global_array"],
    ["graph", "wire_bitmap_ctz_without_endian_normalization"],
    ["clang", "zscope.c_cpp.cpp_clang_cfg.resource_family_release_mismatch"],
    ["clang", "zscope.c_cpp.cpp_clang_cfg.typed_resource_leak"],
]


@pytest.mark.parametrize("engine,rule", REVISED_RULES, ids=[r for _, r in REVISED_RULES])
def test_revised_rule_requires_positive_evidence(engine, rule):
    assert rule not in emitted(engine, controlled_local(), "int entry(void) { return 0; }")


REMAINING_EFFECT_CASES = [
    Case(
        "graph",
        "published_before_member_initialization",
        ("spin_unlock",),
        """
int entry(void) {
 Node *node = malloc(64);
 g_head = node;
 spin_unlock(&L);
 node->value = 1;
}
""",
    ),
    Case(
        "graph",
        "container_unlink_free_after_unlock",
        ("free",),
        """
int entry(void) {
 Node *node = malloc(64);
 g_head = node->next;
 spin_unlock(&L);
 free(node);
}
""",
    ),
    Case(
        "graph",
        "lookup_before_insert_lock",
        ("exclusive_guard",),
        """
int entry(void) {
 if (find_node(key) != NULL) return 1;
 exclusive_guard(&L);
 g_head = node;
}
""",
    ),
    Case(
        "graph",
        "path_state_checked_separately_from_key_generation",
        ("ftok",),
        """
int entry(void) {
 access(path, 0);
 int key = ftok(path, 1);
 return key;
}
""",
    ),
    Case(
        "graph",
        "signal_path_uses_locking_and_formatting",
        ("pthread_mutex_trylock",),
        """
int signal(void) {
 pthread_mutex_trylock (&signal_lock);
 printf(message);
}
""",
    ),
    Case(
        "graph",
        "composed_string_copied_to_member_buffer_without_bound",
        ("strlen",),
        """
int entry(void) {
 snprintf(buffer, sizeof(buffer), "%s", input);
 memcpy(item.name, buffer, strlen(buffer));
}
""",
    ),
    Case(
        "graph",
        "caller_limit_indexes_fixed_member_array",
        ("ARRAY_SIZE",),
        """
int entry(void) {
 if (limit <= ARRAY_SIZE(obj->values)) {
  for (int i=0; i<limit; i++) {
   obj->values[i] = 1;
  }
 }
}
""",
        False,
    ),
    Case(
        "clang",
        "clang_cfg_borrowed_pointer_returned_after_unlock",
        ("spin_unlock",),
        """
char *entry(void) {
 char *p = node->value;
 spin_unlock(&L);
 return p;
}
""",
    ),
    Case(
        "clang",
        "clang_cfg_realloc_lost_original",
        ("realloc",),
        """
int entry(void) {
 char *p = malloc(8);
 p = realloc(p, 16);
 return 0;
}
""",
    ),
    Case(
        "clang",
        "zscope.c_cpp.cpp_clang_cfg.resource_family_release_mismatch",
        ("free",),
        """
int entry(void) {
 int *f = new int;
 free(f);
 return 0;
}
""",
    ),
]


@pytest.mark.parametrize("case", REMAINING_EFFECT_CASES, ids=lambda c: c.rule)
@pytest.mark.parametrize("shadow", [False, True])
def test_remaining_effect_boundaries(case, shadow):
    local = controlled_local()
    assert (case.rule in emitted(case.engine, local, case.code)) is case.allowed_emits
    denied = without(local, case.roots, shadow=shadow)
    assert (case.rule in emitted(case.engine, denied, case.code)) is not case.allowed_emits


@pytest.mark.parametrize("shadow", [False, True])
def test_callee_path_state_permission_boundary(shadow):
    from types import SimpleNamespace

    helper = {
        "code": "int helper(void) {\n access(path, 0);\n return ftok(path, 1);\n}",
        "file": "src/demo.c",
    }
    index = SimpleNamespace(
        get_function_impl=lambda name, **kwargs: helper if name == "helper" else None
    )
    rule = "callee_path_state_checked_separately_from_key_generation"
    for allowed in (True, False):
        local = controlled_local()
        if not allowed:
            local = without(local, ("ftok",), shadow=shadow)
        g = GraphCandidateGenerator(index, local, restrict_to_semantics=True)
        view = FunctionView(
            "entry",
            "src/demo.c",
            "int entry(void)",
            tuple(g._parse_lines("int entry(void) {\n return helper();\n}")),
            ("helper",),
        )
        assert (rule in {r["rule"] for r in g.generate_for_views([view])}) is allowed


def test_optional_release_hook_requires_authorized_fallback():
    local = controlled_local()
    hook = ApiContract.from_row(
        {
            "name": "optional_drop",
            "kind": "deallocator",
            "source": "builtin_defaults",
            "contract": {"conditions": ["hook_registered"]},
        }
    )
    assert hook is not None
    local.contracts.add(hook)
    rule = "registered_global_object_missing_release_hook"
    code = "int entry(void) {\n optional_drop(node);\n free(node);\n}"
    assert rule not in emitted("graph", local, code)
    for shadow in (False, True):
        assert rule in emitted("graph", without(local, ("free",), shadow=shadow), code)


def test_unconditional_unlock_permission_boundary():
    local = controlled_local()
    contract = ApiContract.from_row(
        {"name": "unconditional_unlock", "kind": "unlock", "source": "builtin_defaults"}
    )
    assert contract is not None
    local.contracts.add(contract)
    local.unlock_apis["unconditional_unlock"] = ["builtin_defaults"]
    code = "int entry(void) {\n unconditional_unlock(&L);\n return 0;\n}"
    rule = "clang_cfg_unlock_without_matching_lock"
    assert rule in emitted("clang", local, code)
    for shadow in (False, True):
        assert rule not in emitted(
            "clang", without(local, ("unconditional_unlock",), shadow=shadow), code
        )


@pytest.mark.parametrize("shadow", [False, True])
def test_callback_free_permission_controls_post_callback_use(shadow):
    callback_code = "void _complete(void *arg) {\n Event *event = (Event *)arg;\n free(event);\n}"
    caller_code = """
int entry(void) {
 Event *event = malloc(64);
 event->callback_arg = event;
 event->callback = _complete;
 event->callback(event->callback_arg);
 event->running = 0;
}
"""
    rule = "callback_can_free_current_event_before_reacquire"
    for allowed in (True, False):
        local = controlled_local()
        if not allowed:
            local = without(local, ("free",), shadow=shadow)
        g = generator("graph", local)
        views = [
            FunctionView(name, "src/demo.c", name + "(void)", tuple(g._parse_lines(code)), ())
            for name, code in (("_complete", callback_code), ("entry", caller_code))
        ]
        assert (rule in {row["rule"] for row in g.generate_for_views(views)}) is allowed


def test_global_container_cleanup_contract_actual_emit_and_suppression():
    from zscope.semantics.contracts import ObjectBinding, SymbolIdentity

    local = controlled_local()
    acquire = ApiContract(
        SymbolIdentity("prepare"),
        "allocator",
        ObjectBinding("global", global_name="slot"),
        pairs=(SymbolIdentity("dispose"),),
    )
    release = ApiContract(SymbolIdentity("dispose"), "deallocator", ObjectBinding("argument", 0))
    for contract in (acquire, release):
        local.contracts.add(contract)
        local.add_api(contract.role, contract.symbol.name, contract.source)
    rule = "global_container_registration_without_cleanup_path"
    for cleanup, missing in (
        ("dispose(slot);", False),
        ("dispose(other);", True),
        ("if (ok) dispose(slot);", True),
    ):
        code = "void entry(int ok) {\n prepare();\n" + cleanup + "\n}"
        assert (rule in emitted("graph", local, code)) is missing


@pytest.mark.parametrize("template", ["unique_ptr", "shared_ptr"])
@pytest.mark.parametrize("namespace", ["project", "std"])
@pytest.mark.parametrize("construction", ["(p)", "{p}"])
@pytest.mark.parametrize("shadow", [False, True])
def test_exact_template_spelling_keeps_new_ownership_unknown(
    template, namespace, construction, shadow
):
    local = LocalPatternSemantics()
    if shadow:
        local.contracts.shadowed_symbols.update({template, f"{namespace}::{template}"})
    rule = "clang_cfg_acquire_without_release_on_exit"
    prefix = "void entry(void) {\n int *p = new int;\n"
    construction_line = f" {namespace}::{template}<int> owner{construction};\n"
    g = ClangAstCfgCandidateGenerator(local, restrict_to_semantics=True)

    def rules(tail):
        return {
            issue["rule"]
            for issue in g.generate_issues("entry", prefix + tail + "}\n", "src/entry.cpp")
        }

    assert rule in rules(" return;\n")
    assert rule in rules(construction_line + " return;\n")
    assert rule not in rules(construction_line + " delete p;\n return;\n")


@pytest.mark.parametrize("template", ["unique_ptr", "shared_ptr"])
@pytest.mark.parametrize("namespace", ["project", "std"])
@pytest.mark.parametrize("construction, expected_leak", [("(p)", False), ("{p}", True)])
def test_legacy_template_spelling_lifetime_behavior_is_preserved(
    template, namespace, construction, expected_leak
):
    code = (
        "void entry(void) {\n int *p = new int;\n"
        f" {namespace}::{template}<int> owner{construction};\n return;\n}}"
    )
    rule = "clang_cfg_acquire_without_release_on_exit"
    default = ClangAstCfgCandidateGenerator()
    explicit = ClangAstCfgCandidateGenerator(restrict_to_semantics=False)
    for g in (default, explicit):
        assert (
            rule in {issue["rule"] for issue in g.generate_issues("entry", code, "src/entry.cpp")}
        ) is expected_leak


@pytest.mark.parametrize("array", [False, True])
def test_exact_new_delete_language_syntax_still_controls_lifetime(array):
    allocation = "new int[4]" if array else "new int"
    release = "delete[] p;" if array else "delete p;"
    mismatch = "delete p;" if array else "delete[] p;"
    prefix = f"void entry(void) {{\n int *p = {allocation};\n"
    local = LocalPatternSemantics()
    leak = "clang_cfg_acquire_without_release_on_exit"
    wrong_family = "zscope.c_cpp.cpp_clang_cfg.resource_family_release_mismatch"
    assert leak in emitted("clang", local, prefix + " return;\n}")
    assert leak not in emitted("clang", local, prefix + release + "\n return;\n}")
    assert wrong_family in emitted("clang", local, prefix + mismatch + "\n return;\n}")


@pytest.mark.parametrize(
    "authorized, spelling, shadow, expected",
    [
        ("malloc", "malloc", False, True),
        ("malloc", "MALLOC", False, False),
        ("malloc", "Malloc", False, False),
        ("malloc", "MALLOC", True, False),
        ("malloc", "malloc", True, False),
        ("MALLOC", "MALLOC", False, True),
        ("MALLOC", "MALLOC", True, False),
        ("MALLOC", "malloc", False, False),
        ("project_alloc", "project_alloc", False, True),
        ("project_alloc", "PROJECT_ALLOC", False, False),
    ],
)
def test_exact_clang_owned_member_acquirer_spelling(authorized, spelling, shadow, expected):
    local = without(controlled_local(), ("malloc",))
    contract = ApiContract.from_row(
        {"name": authorized, "kind": "allocator", "source": "builtin_defaults"}
    )
    assert contract is not None
    local.contracts.add(contract)
    local.allocators[authorized] = ["builtin_defaults"]
    if shadow:
        local.contracts.shadowed_symbols.add(spelling)
    rule = "clang_cfg_parent_release_without_owned_member_cleanup"
    prefix = f"void entry(Node *parent) {{\n parent->opaque = {spelling}(8);\n"
    assert (rule in emitted("clang", local, prefix + " free(parent);\n}")) is expected
    assert rule not in emitted("clang", local, prefix + " free(parent->opaque);\n free(parent);\n}")


def test_exact_clang_unknown_acquirer_does_not_create_owned_member_effect():
    rule = "clang_cfg_parent_release_without_owned_member_cleanup"
    local = without(controlled_local(), ("malloc",))
    code = "void entry(Node *parent) {\n parent->opaque = malloc(8);\n free(parent);\n}"
    assert rule not in emitted("clang", local, code)
    # A child-like member spelling is not independent ownership evidence.
    assert rule not in emitted("clang", local, code.replace("opaque", "children"))


def test_legacy_clang_owned_member_case_insensitive_acquirer_is_preserved():
    rule = "clang_cfg_parent_release_without_owned_member_cleanup"
    code = "void entry(Node *parent) {\n parent->opaque = MALLOC(8);\n free(parent);\n}"
    for g in (
        ClangAstCfgCandidateGenerator(),
        ClangAstCfgCandidateGenerator(restrict_to_semantics=False),
    ):
        assert rule in {issue["rule"] for issue in g.generate_issues("entry", code, "src/demo.c")}
