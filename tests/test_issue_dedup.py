from zscope.common.issue_identity import (
    canonical_issue_key,
    deduplicate_semantic_issues_programmatic,
    deduplicate_issues,
    normalize_issue_category,
    normalize_issue_fields,
)
from zscope.core.analysis.analyzer import Analyzer


def test_dedup_merges_chinese_needs_review_with_rule_finding() -> None:
    issues = [
        {
            "id": "RULE_SIGNED_UNSIGNED_318",
            "function": "_lifecycle_recv_packet",
            "location": "src/lifecycle.c:318",
            "category": "signed_unsigned",
            "description": "Signed length `received` is cast to size_t and later used by memcpy.",
        },
        {
            "id": "ISSUE_1",
            "function": "_lifecycle_recv_packet",
            "location": "src/lifecycle.c:318",
            "category": "memory_safety",
            "description": "当_net_recv_data返回-1时，(size_t)received转换为SIZE_MAX，导致memcpy越界读写",
        },
    ]

    deduped = deduplicate_issues(issues)

    assert len(deduped) == 1
    assert deduped[0]["dedup_key"] == (
        "signed_unsigned|src/lifecycle.c|_lifecycle_recv_packet|net_recv_data_negative_length"
    )
    assert deduped[0]["category"] == "signed_unsigned"
    assert deduped[0]["duplicate_count"] == 1


def test_dedup_keeps_same_helper_pattern_distinct_across_sink_functions() -> None:
    range_recv = {
        "id": "RANGE-029",
        "function": "_lifecycle_recv_packet",
        "location": "src/lifecycle.c:318",
        "category": "signed_unsigned",
        "description": "Signed length `received` from _net_recv_data is cast to size_t and later used by memcpy.",
    }
    real_recv = {
        "id": "REAL-017",
        "function": "_real_model_signed_recv_to_size",
        "location": "src/lifecycle.c:1531",
        "category": "signed_unsigned",
        "description": "Signed return `rc` from _net_recv_data is cast to size_t/SIZE_MAX and later used by memcpy.",
    }

    deduped = deduplicate_issues([range_recv, real_recv])

    assert len(deduped) == 2
    assert {
        item["dedup_key"] for item in deduped
    } == {
        "signed_unsigned|src/lifecycle.c|_lifecycle_recv_packet|net_recv_data_negative_length",
        "signed_unsigned|src/lifecycle.c|_real_model_signed_recv_to_size|real_model_signed_recv_to_size",
    }


def test_pipe_lock_order_findings_keep_distinct_path_functions() -> None:
    dispatch = {
        "function": "_lifecycle_dispatch_pipe_tick",
        "location": "src/lifecycle.c:689",
        "category": "deadlock",
        "description": "_lifecycle_dispatch_pipe_tick takes sched_lock then pipe->ctrl_lock.",
    }
    timer = {
        "function": "_lifecycle_tick_timer_callback",
        "location": "src/lifecycle.c:742",
        "category": "deadlock",
        "description": "_lifecycle_tick_timer_callback waits on pipe->ctrl_lock while close waits on scheduler lock.",
    }

    deduped = deduplicate_issues([dispatch, timer])

    assert len(deduped) == 2
    assert {
        item["dedup_key"] for item in deduped
    } == {
        "deadlock|src/lifecycle.c|_lifecycle_dispatch_pipe_tick|pipe_scheduler_control_lock_order",
        "deadlock|src/lifecycle.c|_lifecycle_tick_timer_callback|pipe_scheduler_control_lock_order",
    }


def test_dedup_merges_thread_id_leak_variants_by_resource_root_cause() -> None:
    issues = [
        {
            "function": "td_init",
            "location": "src/main.c:187",
            "category": "memory_leak",
            "description": "`thread_ids` is heap allocated and never released.",
        },
        {
            "function": "td_init",
            "location": "src/main.c:190",
            "category": "resource_leak",
            "description": "thread_ids分配失败时，之前分配的threads数组及所有更早资源未释放",
        },
    ]

    assert len(deduplicate_issues(issues)) == 1


def test_distinct_close_wrapper_stale_fd_findings_do_not_merge_by_file_only() -> None:
    close_wrapper = {
        "function": "_net_close_connection",
        "location": "src/network.c:118",
        "category": "stale_fd",
        "description": "File descriptor is closed without adjacent owner invalidation.",
    }
    init_error_path = {
        "function": "_net_init_server",
        "location": "src/network.c:36",
        "category": "stale_fd",
        "description": "File descriptor is closed without adjacent owner invalidation.",
    }

    assert canonical_issue_key(close_wrapper) != canonical_issue_key(init_error_path)


def test_use_after_scope_stack_thread_issue_normalizes_to_stack_escape() -> None:
    issue = {
        "id": "ISSUE_1",
        "function": "_lifecycle_schedule_flush",
        "location": "src/lifecycle.c:247-260",
        "category": "memory safety use after scope 栈内存逃逸到分离线程",
        "subcategory": "use_after_scope",
        "description": "FlushJob job is passed to pthread create as &job and later read by _flush_worker.",
        "positive_evidence": ["pthread_create(&tid, NULL, _flush_worker, &job)", "pthread_detach(tid)"],
        "source": "FlushJob job",
        "sink": "_flush_worker",
    }

    deduped = deduplicate_issues([issue])

    assert deduped[0]["category"] == "stack_escape"
    assert deduped[0]["subcategory"] == "stack_escape"
    assert deduped[0]["cwe"] == "CWE-562"
    assert deduped[0]["dedup_key"] == "stack_escape|src/lifecycle.c|flush_job"


def test_pthread_create_heap_owner_leak_stays_memory_leak() -> None:
    issue = {
        "function": "td_init",
        "location": "src/main.c:187",
        "category": "memory_leak",
        "description": "`thread_ids` is heap allocated and its element address is passed to pthread_create without owner cleanup.",
    }

    deduped = deduplicate_issues([issue])

    assert deduped[0]["category"] == "memory_leak"


def test_canonical_key_respects_structured_category_over_noisy_context() -> None:
    issue = {
        "function": "_executor_process_file",
        "location": "src/executor.c:101",
        "category": "path_traversal",
        "description": "File path is passed to fopen without path normalization.",
        "validation_reasoning": "Unrelated context also mentions payload_len and bounds checks.",
    }

    assert canonical_issue_key(issue).startswith("path_traversal|src/executor.c|")


def test_root_name_matching_handles_underscore_function_names() -> None:
    issue = {
        "function": "td_cleanup",
        "location": "src/main.c:455",
        "category": "type_confusion",
        "description": "_executor_cleanup_resources expects SharedResources * but receives a TaskConfig field.",
    }

    assert canonical_issue_key(issue) == (
        "type_confusion|src/main.c|executor_sharedresources_type_confusion"
    )


def test_range_custom_categories_are_preserved_and_normalized() -> None:
    issue = {
        "function": "_issue41_recv_retry_without_timeout",
        "location": "src/lifecycle.c:1720",
        "category": "concurrency",
        "description": "The retry path can spin in an infinite loop without timeout or delay.",
    }

    deduped = deduplicate_issues([issue])

    assert deduped[0]["category"] == "busy_loop"
    assert deduped[0]["normalized_category"] == "busy_loop"


def test_structured_categories_are_not_polluted_by_unrelated_sigpipe_text() -> None:
    for category in (
        "alignment",
        "held_lock_callback",
        "size_limit_mismatch",
        "memory_leak",
    ):
        issue = {
            "function": "api_entry",
            "location": "src/demo.c:10",
            "category": category,
            "normalized_category": "sigpipe_unhandled",
            "description": f"Structured {category} finding from clang observation.",
            "validation_reasoning": "Unrelated notes mention SIGPIPE, closed peer, and signal handling.",
        }

        normalize_issue_fields(issue)

        assert issue["category"] == category
        assert issue["normalized_category"] == category


def test_dynamic_array_category_does_not_capture_generic_race_or_double_free() -> None:
    assert normalize_issue_category("plain data race on global counter") == "race"
    assert normalize_issue_category("double free on ptr") == "double_free"
    assert normalize_issue_category("dynamic array resize race") == "dynamic_array_race"


def test_unknown_category_text_does_not_expand_identity_fields() -> None:
    prose = "logic incorrect permission check " + ("permission state narrative " * 500)
    issue = {
        "id": "ISSUE_1",
        "function": "_check_file_permission",
        "location": "src/utils.c:169-170",
        "category": "logic",
        "subcategory": "incorrect_permission_check",
        "description": prose,
        "validation_reasoning": prose,
    }

    normalize_issue_fields(issue)
    key = canonical_issue_key(issue)

    assert issue["category"] == "incorrect_permission_check"
    assert issue["normalized_category"] == "incorrect_permission_check"
    assert len(key) < 260


def test_free_form_unknown_category_falls_back_to_unknown() -> None:
    value = "custom prose category " + ("with narrative " * 200)

    assert normalize_issue_category(value) == "unknown"


def test_structured_candidate_wins_over_long_free_form_duplicate() -> None:
    free_form = {
        "id": "ISSUE_1",
        "function": "_lifecycle_unregister_guarded_subscription",
        "location": "src/lifecycle.c:641",
        "category": "memory_leak",
        "confidence": 0.82,
        "description": "A very long generic explanation about a subscription cleanup leak. " * 20,
    }
    structured = {
        "id": "GRAPH_MEMORY_LEAK_1",
        "function": "_lifecycle_unregister_guarded_subscription",
        "location": "src/lifecycle.c:641",
        "category": "memory_leak",
        "confidence": 0.82,
        "rule": "paired_nested_mutex_cleanup_omitted",
        "candidate_source": "graph",
        "description": "Paired creator initializes an embedded mutex but unregister frees the object without destroy.",
        "positive_evidence": ["pthread_mutex_init in creator", "SAFE_FREE in unregister"],
    }

    deduped = deduplicate_issues([free_form, structured])

    assert len(deduped) == 1
    assert deduped[0]["id"] == "GRAPH_MEMORY_LEAK_1"


def test_issue41_missing_refcount_variants_merge_across_entries_and_sources() -> None:
    free_form = {
        "id": "ISSUE_1",
        "function": "_issue41_missing_reference_count",
        "location": "src/lifecycle.c:1820-1824",
        "category": "missing_refcount",
        "analyzed_from": "td_run_issue41_cases",
        "description": "释放资源时未从全局链表 g_issue41_broker.resources 中移除节点，导致链表中存在悬空指针。",
        "sink": "第1828行 return res->ref_count 访问已释放内存。",
    }
    structured = {
        "id": "CLANG_CFG_MISSING_REFCOUNT_16af2c1ef0",
        "candidate_id": "CLANG_CFG_MISSING_REFCOUNT_16af2c1ef0",
        "candidate_source": "clang_ast_cfg",
        "rule": "clang_cfg_shared_resource_freed_without_refcount_protocol",
        "function": "_issue41_missing_reference_count",
        "location": "src/lifecycle.c:1822",
        "category": "missing_refcount",
        "analyzed_from": "_td_issue41_worker",
        "description": "Shared resource `res` is freed without checking or updating its reference-count protocol.",
        "sink": "SAFE_FREE(res) releases a resource still listed in g_issue41_broker.resources.",
    }

    deduped = deduplicate_issues([free_form, structured])

    assert len(deduped) == 1
    assert deduped[0]["id"] == "CLANG_CFG_MISSING_REFCOUNT_16af2c1ef0"
    assert deduped[0]["dedup_key"] == (
        "missing_refcount|src/lifecycle.c|issue41_resource_refcount_protocol"
    )
    assert deduped[0]["duplicate_count"] == 1


def test_issue41_partial_retry_symptoms_merge_to_compound_root() -> None:
    uninitialized_tag = {
        "function": "_issue41_partial_resource_leak_on_retry",
        "location": "src/lifecycle.c:1749",
        "category": "partial_resource_leak",
        "description": "未初始化变量 tag 被解引用，return tag[0]。",
        "root_cause": "资源限制检查的错误处理路径使用了未初始化变量。",
    }
    fail_step_leak = {
        "function": "_issue41_partial_resource_leak_on_retry",
        "location": "src/lifecycle.c:1756",
        "category": "partial_resource_leak",
        "description": "fail_step retry path returns -1 and leaks partition and partition->tag.",
        "root_cause": "错误路径缺少清理代码。",
    }

    deduped = deduplicate_issues([uninitialized_tag, fail_step_leak])

    assert len(deduped) == 1
    assert deduped[0]["dedup_key"] == (
        "partial_resource_leak|src/lifecycle.c|_issue41_partial_resource_leak_on_retry|"
        "issue41_partition_retry_cleanup"
    )


def test_structured_issue41_candidates_merge_across_entry_roots() -> None:
    direct_entry = {
        "id": "CLANG_CFG_VERSION_FILTERING_dc964ee8e6",
        "candidate_id": "CLANG_CFG_VERSION_FILTERING_dc964ee8e6",
        "candidate_source": "clang_ast_cfg",
        "rule": "clang_cfg_parsed_protocol_version_is_ignored",
        "function": "_issue41_missing_version_filter",
        "location": "src/lifecycle.c:1795",
        "category": "version_filtering",
        "entry_function": "td_handle_distributed_cs_message",
        "description": "Protocol version `version` is parsed and then explicitly ignored.",
        "sink": "(void)version;",
    }
    worker_entry = {
        "id": "CLANG_CFG_VERSION_FILTERING_dc964ee8e6",
        "candidate_id": "CLANG_CFG_VERSION_FILTERING_dc964ee8e6",
        "candidate_source": "clang_ast_cfg",
        "rule": "clang_cfg_parsed_protocol_version_is_ignored",
        "function": "_issue41_missing_version_filter",
        "location": "src/lifecycle.c:1795",
        "category": "version_filtering",
        "entry_function": "_td_issue41_worker",
        "description": "状态字段 state is processed after `(void)version;` drops the protocol version.",
        "sink": "Function returns success while accepting any version.",
    }

    deduped = deduplicate_issues([direct_entry, worker_entry])

    assert len(deduped) == 1
    assert deduped[0]["dedup_key"] == (
        "version_filtering|src/lifecycle.c|_issue41_missing_version_filter|"
        "parsed_protocol_version_ignored"
    )
    assert deduped[0]["duplicate_count"] == 1


def test_issue41_dynamic_array_variants_merge_across_entries_and_sources() -> None:
    free_form = {
        "id": "ISSUE_2",
        "function": "_issue41_dynamic_array_expand_race",
        "location": "src/lifecycle.c:1767-1780",
        "category": "dynamic_array_race",
        "validation_status": "validated",
        "description": "Global task array resize updates g_issue41_task_array without a lock.",
        "sink": "g_issue41_task_array = new_array; safe_free(old_array);",
    }
    structured = {
        "id": "CLANG_CFG_DYNAMIC_ARRAY_RACE_eec7b80104",
        "candidate_id": "CLANG_CFG_DYNAMIC_ARRAY_RACE_eec7b80104",
        "candidate_source": "clang_ast_cfg",
        "rule": "clang_cfg_global_dynamic_array_resize_without_lock",
        "function": "_issue41_dynamic_array_expand_race",
        "location": "src/lifecycle.c:1767",
        "category": "dynamic_array_race",
        "entry_function": "_td_issue41_worker",
        "description": "Global dynamic array `g_issue41_task_array` is resized and old storage is freed.",
        "sink": "g_issue41_task_array = new_array",
    }

    deduped = deduplicate_issues([free_form, structured])

    assert len(deduped) == 1
    assert deduped[0]["dedup_key"] == (
        "dynamic_array_race|src/lifecycle.c|_issue41_dynamic_array_expand_race|"
        "issue41_dynamic_array_resize"
    )
    assert deduped[0]["duplicate_count"] == 1


def test_real_model_unchecked_return_variants_merge_across_entry_roots() -> None:
    direct = {
        "id": "CLANG_CFG_UNCHECKED_RETURN_5b8e279112",
        "candidate_id": "CLANG_CFG_UNCHECKED_RETURN_5b8e279112",
        "candidate_source": "clang_ast_cfg",
        "rule": "clang_cfg_probe_error_branch_can_return_success_status",
        "function": "_real_model_ssl_error_returns_ok",
        "location": "src/lifecycle.c:1442",
        "category": "unchecked_return",
        "entry_function": "td_handle_real_protocol_message",
        "description": "Probe failure branch logs an error but returns ret.",
        "sink": "return ret;",
    }
    worker = {
        **direct,
        "entry_function": "_td_real_protocol_worker",
        "description": "Probe failure returns the transport status instead of an explicit error.",
        "sink": "function returns ret to caller",
    }

    deduped = deduplicate_issues([direct, worker])

    assert len(deduped) == 1
    assert deduped[0]["dedup_key"] == (
        "unchecked_return|src/lifecycle.c|_real_model_ssl_error_returns_ok|"
        "real_model_ssl_probe_status"
    )


def test_path_check_before_open_variants_merge_across_public_entries() -> None:
    command = {
        "id": "CLANG_CFG_TOCTOU_e4d912f50a",
        "candidate_id": "CLANG_CFG_TOCTOU_e4d912f50a",
        "candidate_source": "clang_ast_cfg",
        "rule": "clang_cfg_path_check_before_open",
        "function": "_validate_task",
        "location": "src/parser.c:361",
        "category": "sigpipe_unhandled",
        "entry_function": "td_execute_command",
        "description": "A pathname is checked separately from a later open/use operation.",
        "sink": "FILE* fp = fopen(path, \"r\");",
    }
    submit = {
        **command,
        "entry_function": "td_submit_task",
        "sink": "fopen(path, \"r\")",
    }

    deduped = deduplicate_issues([command, submit])

    assert len(deduped) == 1
    assert deduped[0]["dedup_key"] == (
        "path_check_use|src/parser.c|_validate_task|path_check_before_open"
    )


def test_issue41_size_limit_and_integer_overflow_variants_merge_by_numeric_root() -> None:
    size_limit = {
        "id": "CLANG_CFG_SIZE_LIMIT_MISMATCH_1967cce365",
        "candidate_id": "CLANG_CFG_SIZE_LIMIT_MISMATCH_1967cce365",
        "candidate_source": "clang_ast_cfg",
        "rule": "clang_cfg_fixed_byte_limit_mismatch",
        "function": "_issue41_label_cache_size_miscalc",
        "location": "src/lifecycle.c:1677",
        "category": "size_limit_mismatch",
        "description": "label_len is constrained before element_count is checked.",
        "sink": "label_len = element_count * sizeof(label)",
    }
    overflow = {
        "id": "ISSUE_5",
        "function": "_issue41_label_cache_size_miscalc",
        "location": "src/lifecycle.c:1677",
        "category": "integer_overflow",
        "description": "element_count multiplication can overflow before allocation.",
        "sink": "_safe_calloc(label_len + 1, 1)",
    }

    deduped = deduplicate_issues([size_limit, overflow])

    assert len(deduped) == 1
    assert deduped[0]["dedup_key"] == (
        "numeric_size_mismatch|src/lifecycle.c|_issue41_label_cache_size_miscalc|"
        "issue41_label_cache_size_miscalc"
    )


def test_same_function_same_file_distinct_resources_still_do_not_merge() -> None:
    thread_ids = {
        "function": "td_init",
        "location": "src/main.c:187",
        "category": "memory_leak",
        "description": "thread_ids is heap allocated and never released.",
    }
    queue_tasks = {
        "function": "td_init",
        "location": "src/main.c:187",
        "category": "memory_leak",
        "description": "g_dispatcher.queue.tasks is allocated and not freed on error.",
    }

    deduped = deduplicate_issues([thread_ids, queue_tasks])

    assert len(deduped) == 2


def test_td_init_distinct_memory_leaks_remain_separate() -> None:
    thread_ids = {
        "function": "td_init",
        "location": "src/main.c:187",
        "category": "memory_leak",
        "description": "thread_ids is heap allocated for pthread_create arguments and never released.",
    }
    queue_tasks = {
        "function": "td_init",
        "location": "src/main.c:160",
        "category": "memory_leak",
        "description": "g_dispatcher.queue.tasks is allocated before _plugin_registry_init; on failure it returns without freeing queue.tasks.",
    }

    deduped = deduplicate_issues([thread_ids, queue_tasks])

    assert len(deduped) == 2
    assert {
        item["dedup_key"] for item in deduped
    } == {
        "memory_leak|src/main.c|thread_ids",
        "memory_leak|src/main.c|td_init|g_dispatcher.queue.tasks",
    }


def test_semantic_dedup_merges_loop_aliases_by_concrete_root() -> None:
    busy = {
        "id": "BUSY",
        "function": "_real_model_recv_busy_loop",
        "location": "src/lifecycle.c:1500",
        "category": "busy_loop",
        "description": "recv retry path spins without timeout.",
    }
    infinite = {
        "id": "INF",
        "function": "_real_model_recv_busy_loop",
        "location": "src/lifecycle.c:1501",
        "category": "infinite_loop",
        "description": "The same recv retry path can spin in an infinite loop.",
    }

    deduped, summary = deduplicate_semantic_issues_programmatic([busy, infinite])

    assert len(deduped) == 1
    assert deduped[0]["duplicate_count"] == 1
    assert summary["programmatic_merge_count"] == 1


def test_semantic_dedup_merges_race_aliases_only_for_same_resource() -> None:
    dynamic = {
        "id": "DYNAMIC",
        "function": "_peer_expand_task_table",
        "location": "src/lifecycle.c:1767",
        "category": "dynamic_array_race",
        "description": "g_issue41_task_array is resized and swapped without a lock.",
    }
    shared = {
        "id": "SHARED",
        "function": "_peer_expand_task_table",
        "location": "src/lifecycle.c:1772",
        "category": "shared_state_race",
        "description": "Concurrent readers can observe g_issue41_task_array while it is replaced.",
    }
    other = {
        "id": "OTHER",
        "function": "_peer_expand_task_table",
        "location": "src/lifecycle.c:1778",
        "category": "race_condition",
        "description": "g_other_table is also updated without synchronization.",
    }

    deduped, _summary = deduplicate_semantic_issues_programmatic([dynamic, shared, other])

    assert len(deduped) == 2
    assert any(issue.get("duplicate_count") == 1 for issue in deduped)


def test_llm_dedup_guard_rejects_distinct_resources() -> None:
    thread_ids = {
        "id": "A",
        "function": "td_init",
        "location": "src/main.c:187",
        "category": "memory_leak",
        "description": "thread_ids is allocated and not freed.",
    }
    queue_tasks = {
        "id": "B",
        "function": "td_init",
        "location": "src/main.c:160",
        "category": "memory_leak",
        "description": "g_dispatcher.queue.tasks is allocated and not freed.",
    }
    decision = {
        "duplicate_groups": [
            {
                "primary_issue_id": "A",
                "duplicate_issue_ids": ["B"],
                "root_cause_key": "bad-merge",
                "confidence": 0.99,
                "reasoning": "LLM incorrectly merged different resources.",
            }
        ],
        "must_keep_distinct_issue_ids": [],
    }

    applied, rejected = Analyzer._apply_llm_dedup_decision(
        decision,
        {"A": thread_ids, "B": queue_tasks},
        set(),
        threshold=0.85,
    )

    assert applied == 0
    assert rejected == 1


def test_programmatic_semantic_dedup_keeps_distinct_concrete_roots() -> None:
    detach_leak = {
        "id": "DETACH",
        "function": "_control_session_detach_without_release",
        "location": "src/lifecycle.c:536",
        "category": "memory_leak",
        "description": "DETACH removes ControlSession from the global list but does not free it.",
    }
    mesh_cleanup = {
        "id": "MESH",
        "function": "_control_session_detach_without_release",
        "location": "src/lifecycle.c:538",
        "category": "memory_leak",
        "description": "pfnDropSession mesh cleanup hook loses ownership of the session and its guard mutex.",
        "sink": "ControlSession* session pointer is lost after the detach helper returns.",
    }

    deduped, summary = deduplicate_semantic_issues_programmatic([detach_leak, mesh_cleanup])

    assert len(deduped) == 2
    assert summary["programmatic_merge_count"] == 0
