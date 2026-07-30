from pathlib import Path

from zscope.common.issue_identity import (
    canonical_category,
    canonical_issue_key,
    deduplicate_semantic_issues_programmatic,
    deduplicate_issues,
    flatten_issue_text,
    issue_resource_signature,
    issue_rank,
    normalize_issue_category,
    normalize_issue_fields,
    root_cause_token,
    semantic_related_cluster_keys,
)
from zscope.core.analysis.analyzer import Analyzer


def test_candidate_policy_and_identity_have_no_benchmark_fixture_symbol_mappings() -> None:
    root = Path(__file__).resolve().parents[1]
    sources = {
        path: (root / path).read_text(encoding="utf-8").lower()
        for path in (
            "zscope/common/issue_identity.py",
            "zscope/core/candidates/regex.py",
            "zscope/snapshots/policy.py",
        )
    }
    forbidden_markers = (
        "_lifecycle_",
        "_runtime_",
        "_issue41_",
        "_real_model_",
        "g_issue41",
        "range-",
        "juliet",
        "sv-comp",
        "sv_comp",
        "reliable_fd",
        "detected_protocol",
        "auth_level",
        "_validate_encoded_fd",
        "fail_step",
        "label_len",
        "element_count",
        "pipe->next=pipe",
        "qrcu",
        "crcu",
        "lcore",
        "lfhash",
    )

    matches = {
        path: [marker for marker in forbidden_markers if marker in source]
        for path, source in sources.items()
    }
    assert not {path: markers for path, markers in matches.items() if markers}


def test_fixture_identifiers_alone_do_not_synthesize_root_cause_identity() -> None:
    cases = (
        (
            "partial_resource_leak",
            "fail_step changed before the function returned.",
            "retry_cleanup_missing",
        ),
        (
            "version_filtering",
            "The protocol parser contains `(void)version;`.",
            "parsed_protocol_version_ignored",
        ),
        (
            "integer_overflow",
            "label_len = element_count * sizeof(label).",
            "numeric_allocation_size_calculation",
        ),
        (
            "resource_leak",
            "pipe->next=pipe;",
            "self_referential_list_link",
        ),
        (
            "bounds",
            "timer uses lcore as an array index.",
            "timer_index_without_cpu_bound",
        ),
        (
            "race",
            "qrcu and crcu select a global mode during callback registration.",
            "rcu_global_mode_protocol",
        ),
        (
            "memory_leak",
            "lfhash uses a custom allocator.",
            "hash_node_allocator_pairing",
        ),
    )

    for category, description, fixture_root in cases:
        issue = {
            "function": "renamed_function",
            "location": "src/generic.c:10",
            "category": category,
            "description": description,
        }
        assert (
            root_cause_token(issue, category, flatten_issue_text(issue))
            != fixture_root
        )


def _precise_endpoint_issue(
    issue_id: str,
    *,
    category: str = "bounds",
    source_file: str = "src/demo.c",
    source_line: int = 10,
    sink_file: str = "src/demo.c",
    sink_line: int = 20,
    function: str = "entry",
    location_line: int = 100,
):
    return {
        "id": issue_id,
        "function": function,
        "location": f"src/demo.c:{location_line}",
        "category": category,
        "description": f"{issue_id} reports a source to sink issue.",
        "source_loc": f"{source_file}:{source_line}",
        "sink_loc": f"{sink_file}:{sink_line}",
        "source": f"source value at line {source_line}",
        "sink": f"sink operation at line {sink_line}",
    }


def test_dedup_merges_same_source_sink_locations_and_normalized_type() -> None:
    direct = _precise_endpoint_issue(
        "DIRECT",
        function="entry_a",
        location_line=100,
        category="bounds",
    )
    packed = {
        "id": "PACKED",
        "function": "entry_b",
        "location": "src/demo.c:220",
        "category": "bounds",
        "description": "Second detector found the same flow with a different report shape.",
        "dedup_key": "legacy-detector-specific-key",
        "evidence_pack": {
            "candidate_evidence": {
                "source": {"file": "src/demo.c", "line": 10},
                "sink": {"file": "src/demo.c", "line": 20},
            }
        },
    }

    deduped = deduplicate_issues([direct, packed])

    assert len(deduped) == 1
    assert deduped[0]["dedup_key"] == "source-sink-v1|bounds|src/demo.c:10|src/demo.c:20"
    assert deduped[0]["duplicate_count"] == 1
    assert deduped[0]["dedup_decisions"] == [
        {
            "method": "source_sink_location",
            "root_cause_key": "source-sink-v1|bounds|src/demo.c:10|src/demo.c:20",
        }
    ]


def test_source_sink_location_dedup_uses_normalized_category() -> None:
    signed = _precise_endpoint_issue(
        "SIGNED",
        category="signed_unsigned",
        function="signed_path",
        location_line=301,
    )
    truncation = _precise_endpoint_issue(
        "TRUNC",
        category="integer_truncation",
        function="truncation_path",
        location_line=302,
    )

    deduped = deduplicate_issues([signed, truncation])

    assert len(deduped) == 1
    assert deduped[0]["dedup_key"] == (
        "source-sink-v1|signed_unsigned|src/demo.c:10|src/demo.c:20"
    )


def test_source_sink_location_dedup_uses_issue_file_for_line_only_endpoints() -> None:
    first = {
        "id": "A",
        "function": "line_only_a",
        "location": "src/demo.c:801",
        "category": "bounds",
        "description": "Detector A reports the same source and sink lines.",
        "source": "request length at line 12",
        "sink": "buffer copy at line 30",
    }
    second = {
        "id": "B",
        "function": "line_only_b",
        "location": "src/demo.c:802",
        "category": "bounds",
        "description": "Detector B reaches the same source and sink lines.",
        "source": "tainted length at line 12",
        "sink": "write into buffer at line 30",
    }

    deduped = deduplicate_issues([first, second])

    assert len(deduped) == 1
    assert deduped[0]["dedup_key"] == "source-sink-v1|bounds|src/demo.c:12|src/demo.c:30"


def test_source_sink_location_dedup_requires_same_source_line() -> None:
    first = _precise_endpoint_issue("A", source_line=10, function="source_a", location_line=401)
    second = _precise_endpoint_issue("B", source_line=11, function="source_b", location_line=402)

    assert len(deduplicate_issues([first, second])) == 2


def test_source_sink_location_dedup_requires_same_sink_line() -> None:
    first = _precise_endpoint_issue("A", sink_line=20, function="sink_a", location_line=501)
    second = _precise_endpoint_issue("B", sink_line=21, function="sink_b", location_line=502)

    assert len(deduplicate_issues([first, second])) == 2


def test_source_sink_location_dedup_requires_same_endpoint_files() -> None:
    same_file = _precise_endpoint_issue("A", function="file_a", location_line=601)
    different_source_file = _precise_endpoint_issue(
        "B",
        source_file="src/other.c",
        function="file_b",
        location_line=602,
    )
    different_sink_file = _precise_endpoint_issue(
        "C",
        sink_file="src/other.c",
        function="file_c",
        location_line=603,
    )

    assert len(deduplicate_issues([same_file, different_source_file])) == 2
    assert len(deduplicate_issues([same_file, different_sink_file])) == 2


def test_source_sink_location_dedup_requires_same_type() -> None:
    bounds = _precise_endpoint_issue("BOUNDS", category="bounds", function="bounds_path", location_line=701)
    command = _precise_endpoint_issue(
        "COMMAND",
        category="command_injection",
        function="command_path",
        location_line=702,
    )

    assert len(deduplicate_issues([bounds, command])) == 2


def test_missing_source_sink_locations_fall_back_to_canonical_dedup() -> None:
    first = {
        "id": "A",
        "function": "copy_entry",
        "location": "src/demo.c:80",
        "category": "bounds",
        "description": "memcpy can write beyond the destination buffer.",
    }
    second = {
        "id": "B",
        "function": "copy_entry",
        "location": "src/demo.c:80",
        "category": "bounds",
        "description": "The same memcpy reaches an out of bounds write.",
    }

    deduped = deduplicate_issues([first, second])

    assert len(deduped) == 1
    assert deduped[0]["dedup_key"] == "bounds|src/demo.c|80|memcpy"


def test_same_detector_rule_does_not_delete_distinct_sink_occurrences() -> None:
    first = {
        "id": "ISSUE_1",
        "function": "copy_entry",
        "location": "src/demo.c:80",
        "category": "bounds",
        "rule": "clang_cfg_unchecked_copy",
        "root_cause_key": "unchecked_copy",
        "resource_signature": "left_buffer",
        "sink": "memcpy",
    }
    second = {
        "id": "ISSUE_2",
        "function": "copy_entry",
        "location": "src/demo.c:84",
        "category": "bounds",
        "rule": "clang_cfg_unchecked_copy",
        "root_cause_key": "unchecked_copy",
        "resource_signature": "right_buffer",
        "sink": "memcpy",
    }

    deduped = deduplicate_issues([first, second])

    assert len(deduped) == 2
    assert deduped[0]["dedup_key"] != deduped[1]["dedup_key"]


def test_issue_rank_prefers_precise_sink_over_generic_clang_candidate() -> None:
    generic = {
        "id": "GENERIC",
        "category": "integer_overflow",
        "defect_class": "integer_overflow",
        "candidate_source": "clang_ast_cfg",
        "candidate_priority_group": "generic_audit",
        "location": "src/demo.c:44",
        "confidence": 0.95,
        "description": "Allocation arithmetic may overflow.",
    }
    exact = {
        "id": "EXACT",
        "category": "heap_overflow",
        "defect_class": "heap_overflow",
        "candidate_priority_group": "exact_sink",
        "location": "src/demo.c:44",
        "confidence": 0.75,
        "description": "Narrowed allocation is smaller than memcpy length.",
    }

    assert issue_rank(exact) > issue_rank(generic)


def test_dedup_merges_chinese_needs_review_with_rule_finding() -> None:
    issues = [
        {
            "id": "RULE_SIGNED_UNSIGNED_318",
            "function": "decode_frame",
            "location": "src/decoder.c:318",
            "category": "signed_unsigned",
            "description": "Signed length `received` is cast to size_t and later used by memcpy.",
        },
        {
            "id": "ISSUE_1",
            "function": "decode_frame",
            "location": "src/decoder.c:318",
            "category": "memory_safety",
            "description": "当 recv 返回-1时，(size_t)received 转换为 SIZE_MAX，导致 memcpy 越界读写",
        },
    ]

    deduped = deduplicate_issues(issues)

    assert len(deduped) == 1
    assert deduped[0]["dedup_key"] == (
        "signed_unsigned|src/decoder.c|decode_frame|negative_length_to_unsigned_size"
    )
    assert deduped[0]["category"] == "signed_unsigned"
    assert deduped[0]["duplicate_count"] == 1


def test_dedup_keeps_same_helper_pattern_distinct_across_sink_functions() -> None:
    first_recv = {
        "id": "RULE-A",
        "function": "decode_primary_frame",
        "location": "src/io.c:318",
        "category": "signed_unsigned",
        "description": "Signed length `received` from recv is cast to size_t and later used by memcpy.",
    }
    second_recv = {
        "id": "RULE-B",
        "function": "decode_replica_frame",
        "location": "src/io.c:1531",
        "category": "signed_unsigned",
        "description": "Signed return `rc` from recv is cast to size_t/SIZE_MAX and later used by memcpy.",
    }

    deduped = deduplicate_issues([first_recv, second_recv])

    assert len(deduped) == 2
    assert {
        item["dedup_key"] for item in deduped
    } == {
        "signed_unsigned|src/io.c|decode_primary_frame|negative_length_to_unsigned_size",
        "signed_unsigned|src/io.c|decode_replica_frame|negative_length_to_unsigned_size",
    }


def test_pipe_lock_order_findings_keep_distinct_path_functions() -> None:
    dispatch = {
        "function": "dispatch_tick",
        "location": "src/worker.c:689",
        "category": "deadlock",
        "description": "dispatch_tick takes scheduler_lock then control_lock.",
        "lock_order": ["scheduler_lock", "control_lock"],
    }
    timer = {
        "function": "timer_callback",
        "location": "src/worker.c:742",
        "category": "deadlock",
        "description": "timer_callback waits on control_lock while close waits on scheduler_lock.",
        "lock_order": ["control_lock", "scheduler_lock"],
    }

    deduped = deduplicate_issues([dispatch, timer])

    assert len(deduped) == 2
    assert {
        item["dedup_key"] for item in deduped
    } == {
        "deadlock|src/worker.c|dispatch_tick|lock_order_control_lock_scheduler_lock",
        "deadlock|src/worker.c|timer_callback|lock_order_control_lock_scheduler_lock",
    }


def test_dedup_merges_thread_id_leak_variants_by_resource_root_cause() -> None:
    issues = [
        {
            "function": "initialize_workers",
            "location": "src/bootstrap.c:187",
            "category": "memory_leak",
            "resource_signature": "worker_handles",
            "description": "`worker_handles` is heap allocated and never released.",
        },
        {
            "function": "initialize_workers",
            "location": "src/bootstrap.c:190",
            "category": "resource_leak",
            "resource_signature": "worker_handles",
            "description": "分配失败时，之前分配的 worker_handles 数组未释放",
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
        "function": "schedule_flush",
        "location": "src/jobs.c:247-260",
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
    assert deduped[0]["dedup_key"] == (
        "stack_escape|src/jobs.c|schedule_flush|stack_address_async_escape_job"
    )


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


def test_type_confusion_root_uses_structured_type_pair_not_function_name() -> None:
    issue = {
        "function": "cleanup_context",
        "location": "src/bootstrap.c:455",
        "category": "type_confusion",
        "expected_type": "SharedResources",
        "actual_type": "TaskConfig",
        "description": "Cleanup expects SharedResources * but receives a TaskConfig field.",
    }

    assert canonical_issue_key(issue) == (
        "type_confusion|src/bootstrap.c|cleanup_context|"
        "type_confusion_taskconfig_to_sharedresources"
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
        "function": "unregister_subscription",
        "location": "src/subscription.c:641",
        "category": "memory_leak",
        "confidence": 0.82,
        "root_cause_key": "embedded_mutex_cleanup_omitted",
        "description": "A very long generic explanation about a subscription cleanup leak. " * 20,
    }
    structured = {
        "id": "GRAPH_MEMORY_LEAK_1",
        "function": "unregister_subscription",
        "location": "src/subscription.c:641",
        "category": "memory_leak",
        "confidence": 0.82,
        "rule": "paired_nested_mutex_cleanup_omitted",
        "root_cause_key": "embedded_mutex_cleanup_omitted",
        "candidate_source": "graph",
        "description": "Paired creator initializes an embedded mutex but unregister frees the object without destroy.",
        "positive_evidence": ["pthread_mutex_init in creator", "SAFE_FREE in unregister"],
    }

    deduped = deduplicate_issues([free_form, structured])

    assert len(deduped) == 1
    assert deduped[0]["id"] == "GRAPH_MEMORY_LEAK_1"


def test_missing_refcount_variants_merge_by_shared_resource_identity() -> None:
    free_form = {
        "id": "ISSUE_1",
        "function": "release_shared_session",
        "location": "src/session.c:1820-1824",
        "category": "missing_refcount",
        "analyzed_from": "handle_session_message",
        "resource_signature": "g_session_registry.resources",
        "description": "释放资源时未从全局链表 g_session_registry.resources 中移除节点，导致悬空指针。",
        "sink": "第1828行 return res->ref_count 访问已释放内存。",
    }
    structured = {
        "id": "CLANG_CFG_MISSING_REFCOUNT_16af2c1ef0",
        "candidate_id": "CLANG_CFG_MISSING_REFCOUNT_16af2c1ef0",
        "candidate_source": "clang_ast_cfg",
        "rule": "clang_cfg_shared_resource_freed_without_refcount_protocol",
        "function": "release_shared_session",
        "location": "src/session.c:1822",
        "category": "missing_refcount",
        "analyzed_from": "session_worker",
        "resource_signature": "g_session_registry.resources",
        "description": "Shared resource `res` is freed without checking or updating its reference-count protocol.",
        "sink": "SAFE_FREE(res) releases a resource still listed in g_session_registry.resources.",
    }

    deduped = deduplicate_issues([free_form, structured])

    assert len(deduped) == 1
    assert deduped[0]["id"] == "CLANG_CFG_MISSING_REFCOUNT_16af2c1ef0"
    assert deduped[0]["dedup_key"] == (
        "missing_refcount|src/session.c|g_session_registry.resources"
    )
    assert deduped[0]["duplicate_count"] == 1


def test_partial_retry_symptoms_merge_by_structured_cleanup_root() -> None:
    uninitialized_tag = {
        "function": "load_partition_with_retry",
        "location": "src/partition.c:1749",
        "category": "partial_resource_leak",
        "root_cause_key": "retry_cleanup_missing",
        "description": "未初始化变量 tag 被解引用，return tag[0]。",
        "root_cause": "资源限制检查的错误处理路径使用了未初始化变量。",
    }
    fail_step_leak = {
        "function": "load_partition_with_retry",
        "location": "src/partition.c:1756",
        "category": "partial_resource_leak",
        "root_cause_key": "retry_cleanup_missing",
        "description": "fail_step retry path returns -1 and leaks partition and partition->tag.",
        "root_cause": "错误路径缺少清理代码。",
    }

    deduped = deduplicate_issues([uninitialized_tag, fail_step_leak])

    assert len(deduped) == 1
    assert deduped[0]["dedup_key"] == (
        "partial_resource_leak|src/partition.c|load_partition_with_retry|"
        "retry_cleanup_missing"
    )


def test_structured_version_candidates_merge_across_entry_roots() -> None:
    direct_entry = {
        "id": "CLANG_CFG_VERSION_FILTERING_dc964ee8e6",
        "candidate_id": "CLANG_CFG_VERSION_FILTERING_dc964ee8e6",
        "candidate_source": "clang_ast_cfg",
        "rule": "clang_cfg_parsed_protocol_version_is_ignored",
        "function": "parse_protocol_version",
        "location": "src/protocol.c:1795",
        "category": "version_filtering",
        "entry_function": "handle_protocol_message",
        "description": "Protocol version `version` is parsed and then explicitly ignored.",
        "sink": "(void)version;",
    }
    worker_entry = {
        "id": "CLANG_CFG_VERSION_FILTERING_dc964ee8e6",
        "candidate_id": "CLANG_CFG_VERSION_FILTERING_dc964ee8e6",
        "candidate_source": "clang_ast_cfg",
        "rule": "clang_cfg_parsed_protocol_version_is_ignored",
        "function": "parse_protocol_version",
        "location": "src/protocol.c:1795",
        "category": "version_filtering",
        "entry_function": "protocol_worker",
        "description": "状态字段 state is processed after `(void)version;` drops the protocol version.",
        "sink": "Function returns success while accepting any version.",
    }

    deduped = deduplicate_issues([direct_entry, worker_entry])

    assert len(deduped) == 1
    assert deduped[0]["dedup_key"] == (
        "version_filtering|src/protocol.c|parse_protocol_version|"
        "parsed_protocol_version_ignored"
    )
    assert deduped[0]["duplicate_count"] == 1


def test_dynamic_array_variants_merge_by_global_resource_identity() -> None:
    free_form = {
        "id": "ISSUE_2",
        "function": "expand_task_table",
        "location": "src/tasks.c:1767-1780",
        "category": "dynamic_array_race",
        "validation_status": "validated",
        "resource_signature": "g_task_table",
        "description": "Global task array resize updates g_task_table without a lock.",
        "sink": "g_task_table = new_array; safe_free(old_array);",
    }
    structured = {
        "id": "CLANG_CFG_DYNAMIC_ARRAY_RACE_eec7b80104",
        "candidate_id": "CLANG_CFG_DYNAMIC_ARRAY_RACE_eec7b80104",
        "candidate_source": "clang_ast_cfg",
        "rule": "clang_cfg_global_dynamic_array_resize_without_lock",
        "function": "expand_task_table",
        "location": "src/tasks.c:1767",
        "category": "dynamic_array_race",
        "entry_function": "task_worker",
        "resource_signature": "g_task_table",
        "description": "Global dynamic array `g_task_table` is resized and old storage is freed.",
        "sink": "g_task_table = new_array",
    }

    deduped = deduplicate_issues([free_form, structured])

    assert len(deduped) == 1
    assert deduped[0]["dedup_key"] == "dynamic_array_race|src/tasks.c|g_task_table"
    assert deduped[0]["duplicate_count"] == 1


def test_error_return_variants_merge_by_detector_root() -> None:
    direct = {
        "id": "CLANG_CFG_UNCHECKED_RETURN_5b8e279112",
        "candidate_id": "CLANG_CFG_UNCHECKED_RETURN_5b8e279112",
        "candidate_source": "clang_ast_cfg",
        "rule": "clang_cfg_probe_error_branch_can_return_success_status",
        "function": "probe_transport_status",
        "location": "src/transport.c:1442",
        "category": "unchecked_return",
        "entry_function": "handle_transport_message",
        "description": "Probe failure branch logs an error but returns ret.",
        "sink": "return ret;",
    }
    worker = {
        **direct,
        "entry_function": "transport_worker",
        "description": "Probe failure returns the transport status instead of an explicit error.",
        "sink": "function returns ret to caller",
    }

    deduped = deduplicate_issues([direct, worker])

    assert len(deduped) == 1
    assert deduped[0]["dedup_key"] == (
        "unchecked_return|src/transport.c|probe_transport_status|"
        "error_branch_returns_success"
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


def test_numeric_root_does_not_merge_distinct_flows_without_flow_identity() -> None:
    size_limit = {
        "id": "CLANG_CFG_SIZE_LIMIT_MISMATCH_1967cce365",
        "candidate_id": "CLANG_CFG_SIZE_LIMIT_MISMATCH_1967cce365",
        "candidate_source": "clang_ast_cfg",
        "rule": "clang_cfg_fixed_byte_limit_mismatch",
        "function": "allocate_label_cache",
        "location": "src/cache.c:1677",
        "category": "size_limit_mismatch",
        "root_cause_key": "numeric_allocation_size_calculation",
        "description": "A derived byte total is constrained after a separate item quota.",
        "sink": "violet_bytes = orchid_items * sizeof(record)",
    }
    overflow = {
        "id": "ISSUE_5",
        "function": "allocate_label_cache",
        "location": "src/cache.c:1677",
        "category": "integer_overflow",
        "root_cause_key": "numeric_allocation_size_calculation",
        "description": "The item-count multiplication can overflow before allocation.",
        "sink": "_safe_calloc(violet_bytes + 1, 1)",
    }

    deduped = deduplicate_issues([size_limit, overflow])

    expected_root_key = (
        "numeric_size_mismatch|src/cache.c|allocate_label_cache|"
        "numeric_allocation_size_calculation"
    )
    assert len(deduped) == 2
    assert all(
        str(issue["dedup_key"]).startswith(expected_root_key) for issue in deduped
    )


def test_same_function_same_file_distinct_resources_still_do_not_merge() -> None:
    thread_ids = {
        "function": "initialize_workers",
        "location": "src/bootstrap.c:187",
        "category": "memory_leak",
        "description": "worker_handles is heap allocated and never released.",
    }
    queue_tasks = {
        "function": "initialize_workers",
        "location": "src/bootstrap.c:187",
        "category": "memory_leak",
        "description": "g_scheduler.queue.tasks is allocated and not freed on error.",
    }

    deduped = deduplicate_issues([thread_ids, queue_tasks])

    assert len(deduped) == 2


def test_distinct_memory_leaks_remain_separate() -> None:
    thread_ids = {
        "function": "initialize_workers",
        "location": "src/bootstrap.c:187",
        "category": "memory_leak",
        "description": "worker_handles is heap allocated for pthread_create arguments and never released.",
    }
    queue_tasks = {
        "function": "initialize_workers",
        "location": "src/bootstrap.c:160",
        "category": "memory_leak",
        "description": "g_scheduler.queue.tasks is allocated before registry initialization; on failure it is not freed.",
    }

    deduped = deduplicate_issues([thread_ids, queue_tasks])

    assert len(deduped) == 2
    assert {
        item["dedup_key"] for item in deduped
    } == {
        "memory_leak|src/bootstrap.c|initialize_workers|worker_handles",
        "memory_leak|src/bootstrap.c|g_scheduler.queue.tasks",
    }


def test_memory_leak_resource_signature_extracts_allocation_owner() -> None:
    pid_list = {
        "function": "_runtime_query_peak_stats",
        "location": "src/lifecycle.c:1422-1430",
        "category": "memory_leak",
        "description": "pid_list通过_safe_calloc分配后从未释放，函数返回时内存丢失",
    }
    child_member = {
        "function": "_runtime_unload_patch_member",
        "location": "src/lifecycle.c:1346-1350",
        "category": "memory_leak",
        "resource": "root->children分配的ServiceChild结构体及其name字段从未释放",
    }

    assert issue_resource_signature(pid_list) == "pid_list"
    assert issue_resource_signature(child_member) == "root->children"


def test_generic_memory_leak_text_does_not_become_root_token() -> None:
    issue = {
        "function": "generic_cleanup",
        "location": "src/demo.c:10",
        "category": "memory_leak",
        "description": "memory_leak memory leak resource leak",
    }
    text = flatten_issue_text(issue)
    category = canonical_category(issue, text)

    assert root_cause_token(issue, category, text) == ""
    assert canonical_issue_key(issue) == "memory_leak|src/demo.c|10|generic_cleanup"


def test_real018_style_memory_leak_stays_independent_from_patch_member_leak() -> None:
    patch_member = {
        "id": "ISSUE_4",
        "function": "_runtime_unload_patch_member",
        "location": "src/lifecycle.c:1346-1350",
        "category": "memory_leak",
        "validation_status": "validated",
        "confidence": 0.95,
        "description": "root->children分配的ServiceChild结构体及其name字段从未释放",
        "root_cause": "释放父节点时未递归释放子节点资源",
        "reasoning": "root->children及其内部name字段未被释放",
    }
    peak_stats = {
        "id": "ISSUE_2",
        "function": "_runtime_query_peak_stats",
        "location": "src/lifecycle.c:1422-1430",
        "category": "memory_leak",
        "validation_status": "validated",
        "confidence": 0.95,
        "description": "pid_list通过_safe_calloc分配后从未释放，函数返回时内存丢失",
        "root_cause": "函数获取所有权后既未释放也未转移所有权，违反所有权契约",
        "reasoning": "第1422行分配pid_list；第1430行返回时指针丢失",
    }

    deduped = deduplicate_issues([patch_member.copy(), peak_stats.copy()])
    semantic_deduped, summary = deduplicate_semantic_issues_programmatic(
        [patch_member.copy(), peak_stats.copy()]
    )

    assert len(deduped) == 2
    assert len(semantic_deduped) == 2
    assert summary["programmatic_merge_count"] == 0
    assert {
        issue_resource_signature(issue)
        for issue in semantic_deduped
    } == {"root->children", "pid_list"}


def test_semantic_dedup_merges_loop_aliases_by_concrete_root() -> None:
    busy = {
        "id": "BUSY",
        "function": "receive_with_retry",
        "location": "src/io.c:1500",
        "category": "busy_loop",
        "root_cause_key": "retry_without_progress",
        "description": "recv retry path spins without timeout.",
    }
    infinite = {
        "id": "INF",
        "function": "receive_with_retry",
        "location": "src/io.c:1501",
        "category": "infinite_loop",
        "root_cause_key": "retry_without_progress",
        "description": "The same recv retry path can spin in an infinite loop.",
    }

    deduped, summary = deduplicate_semantic_issues_programmatic([busy, infinite])

    assert len(deduped) == 1
    assert deduped[0]["duplicate_count"] == 1
    assert summary["programmatic_merge_count"] == 1


def test_semantic_dedup_merges_race_aliases_only_for_same_resource() -> None:
    dynamic = {
        "id": "DYNAMIC",
        "function": "expand_task_table",
        "location": "src/tasks.c:1767",
        "category": "dynamic_array_race",
        "resource_signature": "g_task_table",
        "description": "g_task_table is resized and swapped without a lock.",
    }
    shared = {
        "id": "SHARED",
        "function": "expand_task_table",
        "location": "src/tasks.c:1772",
        "category": "shared_state_race",
        "resource_signature": "g_task_table",
        "description": "Concurrent readers can observe g_task_table while it is replaced.",
    }
    other = {
        "id": "OTHER",
        "function": "expand_task_table",
        "location": "src/tasks.c:1778",
        "category": "race_condition",
        "resource_signature": "g_other_table",
        "description": "g_other_table is also updated without synchronization.",
    }

    deduped, _summary = deduplicate_semantic_issues_programmatic([dynamic, shared, other])

    assert len(deduped) == 2
    assert any(issue.get("duplicate_count") == 1 for issue in deduped)


def test_semantic_related_keys_cluster_cross_function_same_sink_and_path() -> None:
    direct = {
        "id": "A",
        "function": "_validate_task",
        "location": "src/parser.c:361",
        "category": "command_injection",
        "description": "user command reaches shell execution",
        "sink": "system(command)",
        "call_path": ["td_execute_command", "_validate_task", "system"],
    }
    wrapper = {
        "id": "B",
        "function": "_submit_task_frame",
        "location": "src/parser.c:420",
        "category": "command_injection",
        "description": "the submit path forwards the same command to system",
        "sink": "system(command)",
        "call_path": ["td_submit_task", "_submit_task_frame", "_validate_task", "system"],
    }

    direct_keys = set(semantic_related_cluster_keys(direct))
    wrapper_keys = set(semantic_related_cluster_keys(wrapper))

    assert any(key.startswith("semantic-sink-v1|command_injection|src/parser.c|system") for key in direct_keys)
    assert direct_keys.intersection(wrapper_keys)


def test_llm_dedup_guard_allows_cross_function_command_injection_same_sink() -> None:
    direct = {
        "id": "A",
        "function": "_validate_task",
        "location": "src/parser.c:361",
        "category": "command_injection",
        "description": "The command reaches system without shell escaping.",
        "sink": "system(command)",
    }
    wrapper = {
        "id": "B",
        "function": "_submit_task_frame",
        "location": "src/parser.c:420",
        "category": "command_injection",
        "description": "The submit path forwards the same command to the shell.",
        "sink": "system(command)",
    }
    decision = {
        "duplicate_groups": [
            {
                "primary_issue_id": "A",
                "duplicate_issue_ids": ["B"],
                "root_cause_key": "task_command_execution",
                "confidence": 0.92,
                "reasoning": "Both findings describe the same command execution sink.",
            }
        ],
        "must_keep_distinct_issue_ids": [],
    }

    applied, rejected = Analyzer._apply_llm_dedup_decision(
        decision,
        {"A": direct, "B": wrapper},
        set(),
        threshold=0.85,
    )

    assert applied == 1
    assert rejected == 0
    assert "duplicate_count" not in direct
    assert direct["dedup_cluster_suggestions"][0]["role"] == "primary"
    assert wrapper["dedup_cluster_suggestions"][0]["role"] == "possible_alias"


def test_llm_dedup_guard_rejects_cross_function_same_sink_distinct_resources() -> None:
    admin = {
        "id": "A",
        "function": "_run_admin_task",
        "location": "src/parser.c:500",
        "category": "command_injection",
        "description": "admin command reaches system",
        "sink": "system(command)",
        "resource_signature": "admin_command",
    }
    user = {
        "id": "B",
        "function": "_run_user_task",
        "location": "src/parser.c:540",
        "category": "command_injection",
        "description": "user command reaches system",
        "sink": "system(command)",
        "resource_signature": "user_command",
    }
    decision = {
        "duplicate_groups": [
            {
                "primary_issue_id": "A",
                "duplicate_issue_ids": ["B"],
                "root_cause_key": "bad-merge",
                "confidence": 0.99,
                "reasoning": "Both call system.",
            }
        ],
        "must_keep_distinct_issue_ids": [],
    }

    applied, rejected = Analyzer._apply_llm_dedup_decision(
        decision,
        {"A": admin, "B": user},
        set(),
        threshold=0.85,
    )

    assert applied == 0
    assert rejected == 1


def test_programmatic_semantic_dedup_merges_missing_refcount_and_uaf_same_resource() -> None:
    refcount = {
        "id": "REF",
        "function": "_issue41_missing_reference_count",
        "location": "src/lifecycle.c:1822",
        "category": "missing_refcount",
        "description": "Shared resource in g_issue41_broker.resources is freed without refcount protocol.",
        "resource_signature": "g_issue41_broker.resources",
        "sink": "SAFE_FREE(res)",
    }
    uaf = {
        "id": "UAF",
        "function": "_td_issue41_worker",
        "location": "src/lifecycle.c:1830",
        "category": "use_after_free",
        "description": "Worker reaches the same g_issue41_broker.resources node after SAFE_FREE(res).",
        "resource_signature": "g_issue41_broker.resources",
        "sink": "res->ref_count",
        "call_path": ["td_run_issue41_cases", "_td_issue41_worker", "_issue41_missing_reference_count"],
    }

    deduped, summary = deduplicate_semantic_issues_programmatic([refcount, uaf])

    assert len(deduped) == 1
    assert deduped[0]["duplicate_count"] == 1
    assert summary["programmatic_merge_count"] == 1


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


def test_llm_dedup_guard_rejects_td_init_distinct_allocation_members() -> None:
    dispatcher_threads = {
        "id": "A",
        "function": "td_init",
        "location": "src/main.c:185",
        "category": "memory_leak",
        "description": "g_dispatcher.threads allocation failure leaves earlier dispatcher resources allocated.",
    }
    thread_ids = {
        "id": "B",
        "function": "td_init",
        "location": "src/main.c:191",
        "category": "memory_leak",
        "description": "thread_ids allocation failure leaks the previously allocated thread argument array.",
    }
    decision = {
        "duplicate_groups": [
            {
                "primary_issue_id": "A",
                "duplicate_issue_ids": ["B"],
                "root_cause_key": "partial_cleanup_failure|src/main.c|td_init|g_dispatcher",
                "confidence": 0.92,
                "reasoning": "Both are cleanup failures in td_init.",
            }
        ],
        "must_keep_distinct_issue_ids": [],
    }

    applied, rejected = Analyzer._apply_llm_dedup_decision(
        decision,
        {"A": dispatcher_threads, "B": thread_ids},
        set(),
        threshold=0.85,
    )

    assert applied == 0
    assert rejected == 1


def test_llm_dedup_guard_allows_same_file_root_across_functions() -> None:
    callee = {
        "id": "A",
        "function": "expand_task_table",
        "location": "src/tasks.c:1789",
        "category": "dynamic_array_race",
        "resource_signature": "g_task_table",
        "description": "g_task_table is resized and the old array is freed without synchronization.",
        "sink": "g_task_table = new_array",
    }
    wrapper = {
        "id": "B",
        "function": "create_task_from_frame",
        "location": "src/tasks.c:1922",
        "category": "shared_state_race",
        "resource_signature": "g_task_table",
        "description": "The task creation path reaches the same unsynchronized g_task_table resize.",
        "sink": "g_task_table old storage can race with readers",
    }
    decision = {
        "duplicate_groups": [
            {
                "primary_issue_id": "A",
                "duplicate_issue_ids": ["B"],
                "root_cause_key": "g_task_table",
                "confidence": 0.93,
                "reasoning": "Both reports describe the same global task array resize root cause.",
            }
        ],
        "must_keep_distinct_issue_ids": [],
    }

    applied, rejected = Analyzer._apply_llm_dedup_decision(
        decision,
        {"A": callee, "B": wrapper},
        set(),
        threshold=0.85,
    )

    assert applied == 1
    assert rejected == 0
    assert "duplicate_count" not in callee
    assert callee["dedup_cluster_suggestions"][0]["role"] == "primary"


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


def test_semantic_dedup_keeps_same_shell_sink_distinct_without_dataflow_proof() -> None:
    parser_filter = {
        "id": "PARSER",
        "function": "_validate_task",
        "location": "src/parser.c:341",
        "category": "incomplete_input_validation",
        "description": "td_submit_task data reaches src/executor.c:87 system(full_command).",
        "sink": "system(full_command)",
    }
    executor_filter = {
        "id": "EXEC",
        "function": "_executor_validate_command",
        "location": "src/executor.c:207",
        "category": "insufficient_validation",
        "description": "task->payload.command.command and TASK_ENV reach system(full_command).",
        "sink": "system(full_command)",
    }

    deduped, summary = deduplicate_semantic_issues_programmatic([parser_filter, executor_filter])

    assert len(deduped) == 2
    assert summary["programmatic_merge_count"] == 0


def test_semantic_dedup_keeps_distinct_platform_command_root() -> None:
    task_command = {
        "id": "TASK",
        "function": "_executor_validate_command",
        "location": "src/executor.c:207",
        "category": "command_injection",
        "description": "task command reaches system(full_command).",
        "sink": "system(full_command)",
    }
    platform_command = {
        "id": "PLATFORM",
        "function": "platform_execute_task",
        "location": "src/platform_linux.c:30",
        "category": "command_injection",
        "description": "platform task reaches system(task).",
        "sink": "system(task)",
    }

    deduped, summary = deduplicate_semantic_issues_programmatic([task_command, platform_command])

    assert len(deduped) == 2
    assert summary["programmatic_merge_count"] == 0


def test_semantic_dedup_merges_uaf_with_refcount_by_resource_identity() -> None:
    refcount = {
        "id": "REF",
        "function": "publish_shared_session",
        "location": "src/session.c:1819",
        "category": "missing_refcount",
        "resource_signature": "g_session_registry.resources",
        "description": "g_session_registry.resources listener is freed without checking ref_count.",
        "sink": "SAFE_FREE(res)",
    }
    uaf = {
        "id": "UAF",
        "function": "publish_shared_session",
        "location": "src/session.c:1835",
        "category": "use_after_free",
        "resource_signature": "g_session_registry.resources",
        "description": "safe_free(res) leaves g_session_registry.resources linked and readers dereference res->next.",
        "sink": "res->next",
    }

    deduped, summary = deduplicate_semantic_issues_programmatic([refcount, uaf])

    assert len(deduped) == 1
    assert summary["programmatic_merge_count"] == 1
