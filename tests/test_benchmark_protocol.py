import argparse
import importlib.util
import json
import time
from pathlib import Path

from scripts import external_benchmark
from zscope.benchmarking.protocol import (
    CONDITION_CANDIDATES,
    FP_AUDIT_DUPLICATE_OF_GT,
    FP_AUDIT_FALSE_POSITIVE_SUPPRESS,
    FP_AUDIT_NEEDS_REVIEW_ONLY,
    FP_AUDIT_TRUE_EXTRA_ADD_GT,
    SCHEMA_VERSION,
    aggregate_trial_summaries,
    build_trial_summary,
    collect_environment_metadata,
    issue_identity,
    issue_identity_record,
    issue_matches,
    classify_false_positive_record,
    score_report,
    score_report_views,
)
from zscope.reporting.report import Issue


def _range_fp_audit_classifier():
    module_path = (
        Path(__file__).resolve().parents[1] / "test" / "range" / "benchmark" / "fp_audit_rules.py"
    )
    spec = importlib.util.spec_from_file_location("zscope_range_fp_audit_rules", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    classifier = getattr(module, "classify_range_false_positive_record")
    assert callable(classifier)
    return classifier


classify_range_false_positive_record = _range_fp_audit_classifier()


def _truth():
    return {
        "benchmark": "unit_suite",
        "suite": "unit",
        "vulnerabilities": [
            {
                "id": "BUG-1",
                "category": "memory_leak",
                "function": "leaky",
                "file": "src/demo.c",
                "line": 10,
            },
            {
                "id": "BUG-2",
                "category": "use_after_free",
                "function": "uaf",
                "file": "src/demo.c",
                "line": 40,
            },
        ],
        "safe_entries": [{"function": "safe"}],
    }


def _report():
    return {
        "issues": [
            {
                "category": "memory_leak",
                "function": "leaky",
                "location": "src/demo.c:10",
                "description": "memory leak on error path",
            }
        ],
        "report_views": {
            "default": {
                "issues": [
                    {
                        "category": "memory_leak",
                        "function": "leaky",
                        "location": "src/demo.c:10",
                        "description": "memory leak on error path",
                    }
                ]
            },
            "with_needs_review": {
                "issues": [
                    {
                        "category": "memory_leak",
                        "function": "leaky",
                        "location": "src/demo.c:10",
                        "description": "memory leak on error path",
                    },
                    {
                        "category": "use_after_free",
                        "function": "uaf",
                        "location": "src/demo.c:41",
                        "description": "use after free after cleanup",
                        "needs_review": True,
                    },
                ]
            },
        },
        "metadata": {
            "context_tokens": 120,
            "tool_call_count": 6,
            "workflow_progress": [{"step": "validate_findings"}],
            "subagent_reports": [
                {
                    "status": "completed",
                    "metadata": {"tool_call_count": 2},
                    "data": {"conclusion": "checked"},
                }
            ],
        },
    }


def test_score_report_views_includes_with_needs_review_metrics() -> None:
    views = score_report_views(_report(), _truth(), line_tolerance=5)

    assert views["default"]["true_positives"] == 1
    assert views["default"]["false_negatives"] == 1
    assert views["with_needs_review"]["true_positives"] == 2
    assert views["with_needs_review"]["recall"] == 1.0
    assert views["default"]["schema_version"] == SCHEMA_VERSION
    assert views["default"]["matched_pairs"][0]["truth_id"] == "BUG-1"


def test_issue_matches_secondary_sink_and_call_path_anchor() -> None:
    truth = {
        "id": "RANGE-012",
        "category": "command_injection",
        "function": "_executor_execute_command",
        "secondary_function": "_executor_build_command_args",
        "file": "src/executor.c",
        "line": 220,
        "end_line": 245,
        "keywords": ["system", "command", "argv"],
    }
    issue = {
        "category": "command_injection",
        "function": "_executor_build_command_args",
        "entry_function": "_executor_execute_command",
        "sink_function": "_executor_build_command_args",
        "call_path": ["_executor_execute_command", "_executor_build_command_args"],
        "location": "src/executor.c:236",
        "description": "Shell command injection reaches system() through argv construction.",
    }

    assert issue_matches(issue, truth, line_tolerance=8)


def test_benchmark_issue_identity_prefers_line_insensitive_fingerprint() -> None:
    issue = {
        "dedup_key": "memory_leak|src/demo.c|42|handle",
        "category": "memory_leak",
        "function": "open_handle",
        "location": "src/demo.c:42",
        "rule": "missing_close",
        "source": "SHM_FileOpen",
        "sink": "return",
        "candidate_source": "clang_ast_cfg",
        "baseline_match_strategy": "stable_fingerprint",
    }
    shifted = dict(issue, location="src/demo.c:57")

    assert issue_identity(issue) == issue_identity(shifted)
    record = issue_identity_record(issue)
    assert record["stable_fingerprint"]
    assert record["candidate_source"] == "clang_ast_cfg"
    assert record["baseline_match_strategy"] == "stable_fingerprint"


def test_score_report_emits_auditable_identity_records() -> None:
    report = {
        "issues": [
            {
                "category": "memory_leak",
                "function": "other",
                "location": "src/demo.c:88",
                "rule": "missing_close",
                "source": "SHM_FileOpen",
                "sink": "return",
                "candidate_source": "regex_local_rule",
                "baseline_match_strategy": "dedup_key",
            }
        ]
    }
    scored = score_report(report, _truth(), line_tolerance=2)

    assert scored["false_positive_issue_records"][0]["candidate_source"] == "regex_local_rule"
    assert scored["false_positive_issue_records"][0]["baseline_match_strategy"] == "dedup_key"


def test_score_report_classifies_duplicate_of_matched_separately() -> None:
    truth = {
        "benchmark": "unit_suite",
        "suite": "unit",
        "vulnerabilities": [
            {
                "id": "BUG-1",
                "category": "memory_leak",
                "function": "leaky",
                "file": "src/demo.c",
                "line": 10,
            }
        ],
    }
    report = {
        "issues": [
            {
                "category": "memory_leak",
                "function": "leaky",
                "location": "src/demo.c:10",
                "description": "memory leak on handle",
            },
            {
                "category": "resource_leak",
                "function": "leaky",
                "location": "src/demo.c:11",
                "description": "same memory leak on handle reported by another source",
            },
        ]
    }

    scored = score_report(report, truth, line_tolerance=2)
    raw_scored = score_report(
        report,
        truth,
        line_tolerance=2,
        count_duplicate_of_matched_as_fp=True,
    )

    assert scored["true_positives"] == 1
    assert scored["false_positives_raw"] == 1
    assert scored["false_positives"] == 0
    assert scored["duplicate_of_matched_count"] == 1
    assert raw_scored["false_positives"] == 1
    assert scored["false_positive_audit"]["counts"][FP_AUDIT_DUPLICATE_OF_GT] == 1


def test_default_false_positive_audit_keeps_unmatched_findings_for_review() -> None:
    audited = classify_false_positive_record(
        {
            "identity": "v1|api_contract_violation|src/main.c|td_query_status|audit_observation",
            "dedup_key": "api_contract_violation|src/main.c|613|return status",
        }
    )

    assert audited["fp_audit_classification"] == FP_AUDIT_NEEDS_REVIEW_ONLY


def test_range_false_positive_audit_classifies_suppress_duplicate_and_true_extra() -> None:
    suppress = classify_range_false_positive_record(
        {
            "identity": "v1|api_contract_violation|src/main.c|td_query_status|audit_observation",
            "dedup_key": "api_contract_violation|src/main.c|613|return status",
        }
    )
    duplicate = classify_range_false_positive_record(
        {
            "identity": "v1|insufficient_validation|src/executor.c|_executor_validate_command|verified_vulnerability|task command",
            "dedup_key": "insufficient_validation|src/executor.c|207|system(full_command)",
        }
    )
    true_extra = classify_range_false_positive_record(
        {
            "identity": "v1|busy_wait_loop|src/network.c|_net_send_data|needs_review|send returns EAGAIN forever",
            "dedup_key": "busy_wait_loop|src/network.c|104|send loop",
            "candidate_source": "needs_review",
        }
    )

    assert suppress["fp_audit_classification"] == FP_AUDIT_FALSE_POSITIVE_SUPPRESS
    assert duplicate["fp_audit_classification"] == FP_AUDIT_DUPLICATE_OF_GT
    assert true_extra["fp_audit_classification"] == FP_AUDIT_TRUE_EXTRA_ADD_GT


def test_score_report_accepts_suite_specific_fp_audit_classifier() -> None:
    report = {
        "issues": [
            {
                "category": "api_contract_violation",
                "function": "td_query_status",
                "location": "src/main.c:613",
                "description": "return status",
            }
        ]
    }

    scored = score_report(
        report,
        _truth(),
        line_tolerance=2,
        fp_audit_classifier=classify_range_false_positive_record,
    )

    assert (
        scored["false_positive_audit"]["counts"][FP_AUDIT_FALSE_POSITIVE_SUPPRESS]
        == 1
    )


def test_issue_matches_additional_function_and_location_anchor() -> None:
    truth = {
        "id": "RANGE-016",
        "category": "race",
        "function": "_worker_thread",
        "file": "src/main.c",
        "line": 55,
        "end_line": 62,
        "additional_locations": [
            {
                "file": "src/main.c",
                "function": "_signal_handler",
                "line": 51,
                "end_line": 52,
            }
        ],
        "keywords": ["g_running", "race", "signal"],
    }
    issue = {
        "category": "dynamic_array_race",
        "function": "_signal_handler",
        "location": "src/main.c:52",
        "description": "Signal handler writes g_running while worker threads read it without synchronization.",
    }

    assert issue_matches(issue, truth, line_tolerance=3)


def test_issue_matches_nested_evidence_location_anchor() -> None:
    truth = {
        "id": "RANGE-045",
        "category": "memory_leak",
        "function": "_lifecycle_delete_os_node",
        "file": "src/lifecycle.c",
        "line": 825,
        "end_line": 839,
        "additional_locations": [
            {
                "file": "src/main.c",
                "function": "td_update_os_policy",
                "line": 420,
                "end_line": 428,
            }
        ],
        "keywords": ["OSNode", "ProcNode", "child list leak"],
    }
    issue = {
        "category": "memory_leak",
        "function": "td_update_os_policy",
        "location": "src/main.c:12",
        "description": "OSNode delete path leaves ProcNode children attached.",
        "evidence_pack": {
            "sink": {
                "function": "_lifecycle_delete_os_node",
                "location": "src/lifecycle.c:831",
            },
            "entry": {
                "function": "td_update_os_policy",
                "location": "src/main.c:424",
            },
        },
    }

    assert issue_matches(issue, truth, line_tolerance=4)


def test_issue_matches_race_when_report_describes_dangling_unmap() -> None:
    truth = {
        "id": "RANGE-053",
        "category": "race",
        "function": "_lifecycle_map_rules",
        "file": "src/lifecycle.c",
        "line": 405,
        "end_line": 411,
        "secondary_function": "_lifecycle_unload_rules",
        "secondary_line": 415,
        "secondary_end_line": 418,
        "additional_locations": [
            {
                "file": "src/lifecycle.c",
                "function": "_lifecycle_match_rule_byte",
                "line": 422,
                "end_line": 428,
            }
        ],
        "keywords": ["g_rules_map", "munmap", "global state"],
    }
    issue = {
        "category": "use_after_free",
        "function": "_lifecycle_match_rule_byte",
        "location": "src/lifecycle.c:427",
        "description": "Reader can dereference dangling g_rules_map after concurrent munmap of global state.",
    }

    assert issue_matches(issue, truth, line_tolerance=4)


def test_issue_matches_sibling_role_release_location_anchor() -> None:
    truth = {
        "id": "REAL-021",
        "category": "memory_leak",
        "function": "_real_model_destroy_role_gt",
        "sibling_function": "_real_model_server_release_by_role",
        "file": "src/lifecycle.c",
        "line": 1285,
        "end_line": 1290,
        "additional_locations": [
            {
                "file": "src/lifecycle.c",
                "function": "_real_model_server_release_by_role",
                "line": 1271,
                "end_line": 1276,
            }
        ],
        "keywords": ["role", "release_by_role", "literal"],
    }
    issue = {
        "category": "memory_leak",
        "function": "_real_model_server_release_by_role",
        "location": "src/lifecycle.c:1274",
        "description": "Hardcoded role release_by_role frees the literal role and skips the stored-role payload.",
        "sink": "_real_model_server_release_by_role(node, 0)",
    }

    assert issue_matches(issue, truth, line_tolerance=3)


def test_issue_matches_ignores_placeholder_truth_line() -> None:
    truth = {
        "id": "REAL-013",
        "category": "size_limit_mismatch",
        "function": "_real_model_protocol_length_miscalc",
        "file": "src/lifecycle.c",
        "line": 1,
        "keywords": ["protocol", "length", "size limit"],
    }
    issue = {
        "category": "bounds",
        "function": "_real_model_protocol_length_miscalc",
        "location": "src/lifecycle.c:1359-1362",
        "description": "Protocol length uses a fixed size limit and can miscalculate frame bounds.",
    }

    assert issue_matches(issue, truth, line_tolerance=8)


def test_issue_matches_custom_category_aliases() -> None:
    truth = {
        "id": "ISSUE41-003",
        "category": "busy_loop",
        "function": "_issue41_recv_retry_without_timeout",
        "file": "src/lifecycle.c",
        "line": 1719,
        "keywords": ["retry", "timeout", "loop"],
    }
    issue = {
        "category": "infinite_loop",
        "function": "_issue41_recv_retry_without_timeout",
        "location": "src/lifecycle.c:1720",
        "description": "The retry path can spin in an infinite loop without timeout or delay.",
    }

    assert issue_matches(issue, truth, line_tolerance=8)


def test_issue_matches_fd_leak_category_alias() -> None:
    truth = {
        "id": "ISSUE43-015",
        "category": "missing_fd_release",
        "cwe": "CWE-775",
        "function": "_journal_metadata_validate",
        "file": "src/lifecycle.c",
        "line": 3312,
        "keywords": ["journal", "descriptor", "close"],
    }
    issue = {
        "category": "fd_leak",
        "cwe": "CWE-775",
        "function": "_journal_metadata_validate",
        "location": "src/lifecycle.c:3320",
        "description": "Opened journal fd returns on an error path without a close.",
    }

    assert issue_matches(issue, truth, line_tolerance=12)


def test_issue_matches_unlock_without_lock_alias() -> None:
    truth = {
        "id": "ISSUE43-017",
        "category": "unlock_without_lock",
        "cwe": "CWE-832",
        "function": "_runtime_lock_cache_abort",
        "file": "src/lifecycle.c",
        "line": 3345,
        "keywords": ["unlock", "cache", "not held"],
    }
    issue = {
        "category": "lock_protocol_violation",
        "cwe": "CWE-832",
        "function": "_runtime_lock_cache_abort",
        "location": "src/lifecycle.c:3350",
        "description": "The abort path calls pthread_mutex_unlock without owning the cache lock.",
    }

    assert issue_matches(issue, truth, line_tolerance=12)


def test_issue_matches_thread_cache_leak_without_cross_function_match() -> None:
    truth = {
        "id": "THREAD-CACHE-1",
        "category": "thread_cache_leak",
        "cwe": "CWE-772",
        "function": "_thread_cache_release",
        "file": "src/lifecycle.c",
        "line": 120,
        "keywords": ["thread cache", "cached blocks", "leak"],
    }
    matching_issue = {
        "category": "memory_leak",
        "cwe": "CWE-772",
        "function": "_thread_cache_release",
        "location": "src/lifecycle.c:121",
        "description": "Thread cache cached blocks are leaked on release.",
    }
    other_function_issue = {
        **matching_issue,
        "function": "_other_cache_release",
        "description": "Another function has a generic memory leak.",
    }

    assert issue_matches(matching_issue, truth, line_tolerance=4)
    assert not issue_matches(other_function_issue, truth, line_tolerance=4)


def test_issue_matches_heap_overflow_aliases_bounds_report() -> None:
    truth = {
        "id": "HEAP-1",
        "category": "heap_overflow",
        "cwe": "CWE-122",
        "function": "_copy_fragment",
        "file": "src/demo.c",
        "line": 44,
        "keywords": ["fragment_len", "copy_len", "heap buffer"],
    }
    issue = {
        "category": "bounds",
        "function": "_copy_fragment",
        "location": "src/demo.c:45",
        "description": "Heap buffer overflow: fragment_len is truncated for allocation but copy_len reaches memcpy.",
    }

    assert issue_matches(issue, truth, line_tolerance=4)


def test_issue_matches_buffer_underread_and_underwrite_aliases_underflow() -> None:
    underread_truth = {
        "id": "UNDERREAD-1",
        "category": "buffer_underread",
        "cwe": "CWE-127",
        "function": "_read_footer",
        "file": "src/demo.c",
        "line": 90,
        "keywords": ["footer_backtrack", "underread"],
    }
    underwrite_truth = {
        "id": "UNDERWRITE-1",
        "category": "buffer_underwrite",
        "cwe": "CWE-124",
        "function": "_compact_prefix",
        "file": "src/demo.c",
        "line": 120,
        "keywords": ["prefix_len", "underwrite"],
    }

    assert issue_matches(
        {
            "category": "buffer_underflow",
            "function": "_read_footer",
            "location": "src/demo.c:91",
            "description": "footer_backtrack can move before the buffer and cause a buffer underflow read.",
        },
        underread_truth,
        line_tolerance=4,
    )
    assert issue_matches(
        {
            "category": "buffer_underflow",
            "function": "_compact_prefix",
            "location": "src/demo.c:121",
            "description": "prefix_len can move before the output buffer and cause a buffer underflow write.",
        },
        underwrite_truth,
        line_tolerance=4,
    )


def test_issue_matches_signed_unsigned_with_integer_overflow_report_when_anchored() -> None:
    truth = {
        "id": "SIGNED-1",
        "category": "signed_unsigned",
        "cwe": "CWE-195",
        "function": "_receive_payload",
        "file": "src/demo.c",
        "line": 77,
        "keywords": ["negative", "size_t", "memcpy"],
    }
    issue = {
        "category": "integer_overflow",
        "function": "_receive_payload",
        "location": "src/demo.c:78",
        "description": "Negative receive result is converted to a huge size_t and reaches memcpy.",
    }

    assert issue_matches(issue, truth, line_tolerance=4)


def test_issue_matches_out_of_range_pointer_offset_alias_when_anchored() -> None:
    truth = {
        "id": "OFFSET-1",
        "category": "out_of_range_pointer_offset",
        "cwe": "CWE-823",
        "function": "_runtime_stream_map_object_offset",
        "file": "src/runtime.c",
        "line": 88,
        "keywords": ["offset", "object", "write"],
    }
    issue = {
        "category": "out_of_bounds_write",
        "function": "_runtime_stream_map_object_offset",
        "location": "src/runtime.c:91",
        "description": "Unchecked object offset forms an out of bounds write sink.",
    }

    assert issue_matches(issue, truth, line_tolerance=8)


def test_issue_matches_file_type_validation_alias_when_anchored() -> None:
    truth = {
        "id": "FILETYPE-1",
        "category": "file_type_validation",
        "cwe": "CWE-20",
        "function": "_runtime_map_reserved_region",
        "file": "src/lifecycle.c",
        "line": 2418,
        "keywords": ["file type", "mapping", "validation"],
    }
    issue = {
        "category": "incorrect_validation_order",
        "function": "_runtime_map_reserved_region",
        "location": "src/lifecycle.c:2426",
        "description": "Incorrect validation order: mapping size is checked before file type validation.",
    }

    assert issue_matches(issue, truth, line_tolerance=12)


def test_issue_matches_bounds_truth_with_magic_count_protocol_validation_when_anchored() -> None:
    truth = {
        "id": "MAGIC-COUNT-1",
        "category": "bounds",
        "cwe": "CWE-20",
        "function": "_runtime_read_control_magic",
        "file": "src/lifecycle.c",
        "line": 1375,
        "keywords": ["magic", "count", "memcpy"],
    }
    issue = {
        "category": "protocol_validation",
        "cwe": "CWE-20",
        "function": "_runtime_read_control_magic",
        "location": "src/lifecycle.c:1383",
        "description": "Unchecked count before magic validation reaches memcpy(preview, seed, count).",
    }

    assert issue_matches(issue, truth, line_tolerance=12)


def test_issue_matches_premature_destroy_truth_with_use_after_free_when_anchored() -> None:
    truth = {
        "id": "PBUF-1",
        "category": "premature_destroy",
        "cwe": "CWE-416",
        "function": "_runtime_release_packet_pool",
        "file": "src/lifecycle.c",
        "line": 2339,
        "keywords": ["active tasks", "pbuf pool", "use-after-free"],
    }
    issue = {
        "category": "use_after_free",
        "cwe": "CWE-416",
        "function": "_runtime_release_packet_pool",
        "location": "src/lifecycle.c:2351",
        "description": "g_runtime_pbuf_pool is freed while active tasks remain and then dereferenced after release.",
    }

    assert issue_matches(issue, truth, line_tolerance=16)


def test_issue_matches_permission_alias_when_anchored() -> None:
    truth = {
        "id": "PERM-1",
        "category": "permission",
        "cwe": "CWE-732",
        "function": "_runtime_open_named_segment",
        "file": "src/lifecycle.c",
        "line": 2542,
        "keywords": ["namedpipe", "permission", "0660"],
    }
    issue = {
        "category": "incorrect_permission_check",
        "function": "_runtime_open_named_segment",
        "location": "src/lifecycle.c:2552",
        "description": "Requested permission is checked against a hardcoded 0660 mode but not applied.",
    }

    assert issue_matches(issue, truth, line_tolerance=12)


def test_issue_matches_unsynchronized_shared_state_alias_when_anchored() -> None:
    truth = {
        "id": "STATE-1",
        "category": "unsynchronized_shared_state",
        "cwe": "CWE-362",
        "function": "_runtime_stream_update_watermark",
        "file": "src/lifecycle.c",
        "line": 3330,
        "keywords": ["watermark", "shared state", "unsynchronized"],
    }
    issue = {
        "category": "race",
        "function": "_runtime_stream_update_watermark",
        "location": "src/lifecycle.c:3341",
        "description": "Global watermark shared state is written without synchronization.",
    }

    assert issue_matches(issue, truth, line_tolerance=12)


def test_issue_matches_callback_deadlock_primary_anchor() -> None:
    truth = {
        "id": "DEADLOCK-1",
        "category": "deadlock",
        "cwe": "CWE-833",
        "function": "_lifecycle_tick_timer_callback",
        "file": "src/lifecycle.c",
        "line": 738,
        "secondary_function": "_lifecycle_close_pipe",
        "secondary_line": 720,
        "keywords": ["timer", "ctrl_lock", "deadlock"],
    }
    issue = {
        "category": "deadlock",
        "function": "_lifecycle_tick_timer_callback",
        "location": "src/lifecycle.c:743",
        "description": "Timer callback lock-order cycle: scheduler traversal then ctrl_lock can deadlock with close path.",
        "related_functions": ["_lifecycle_close_pipe"],
    }

    assert issue_matches(issue, truth, line_tolerance=8)


def test_score_report_uses_max_weight_matching_to_preserve_cardinality() -> None:
    truth = {
        "benchmark": "unit_suite",
        "suite": "unit",
        "vulnerabilities": [
            {
                "id": "T0",
                "category": "race",
                "function": "shared_path",
                "file": "src/demo.c",
                "line": 1,
                "keywords": ["race", "shared"],
            },
            {
                "id": "T1",
                "category": "use_after_free",
                "function": "sibling_path",
                "file": "src/demo.c",
                "line": 1,
                "keywords": ["use after free", "sibling"],
            },
        ],
    }
    report = {
        "issues": [
            {
                "category": "race",
                "function": "shared_path",
                "location": "src/demo.c:120",
                "description": "shared race; sibling_path has a possible use after free on the same object",
            },
            {
                "category": "data_race",
                "function": "shared_path",
                "location": "src/demo.c:121",
                "description": "shared race only",
            },
        ]
    }

    scored = score_report(report, truth, line_tolerance=8)

    assert scored["matched"] == ["T0", "T1"]
    assert scored["true_positives"] == 2


def test_score_report_prefers_strong_function_match_over_earlier_weak_truth() -> None:
    truth = {
        "benchmark": "unit_suite",
        "suite": "unit",
        "vulnerabilities": [
            {
                "id": "REAL-013",
                "category": "bounds",
                "function": "_real_model_protocol_length_miscalc",
                "file": "src/lifecycle.c",
                "line": 1,
                "keywords": ["protocol", "length", "buffer"],
            },
            {
                "id": "REAL-029",
                "category": "stale_fd",
                "function": "_real_model_stale_fd_after_close",
                "file": "src/lifecycle.c",
                "line": 1,
                "keywords": ["stale fd", "close", "reuse"],
            },
        ],
    }
    report = {
        "issues": [
            {
                "category": "stale_fd",
                "function": "_real_model_stale_fd_after_close",
                "location": "src/lifecycle.c:1500",
                "description": (
                    "stale fd after close; same protocol dispatcher also reaches "
                    "_real_model_protocol_length_miscalc and a protocol length buffer path"
                ),
            }
        ]
    }

    views = score_report_views(report, truth, line_tolerance=8)

    assert views["default"]["matched"] == ["REAL-029"]
    assert views["default"]["matched_pairs"][0]["truth_id"] == "REAL-029"


def test_issue_model_preserves_entry_to_sink_attribution_fields() -> None:
    issue = Issue.from_dict(
        {
            "id": "RULE_1",
            "function": "sink",
            "file": "src/demo.c:42",
            "category": "bounds",
            "subcategory": "copy",
            "description": "entry reaches sink through a wrapper.",
            "root_cause": "Unchecked length",
            "suggested_fix": "Check the length before copying.",
            "confidence": 0.8,
            "impact_level": "high",
            "entry_function": "entry",
            "sink_function": "sink",
            "call_path": ["entry", "sink"],
            "reachable_from_entry": True,
            "internal_sink_lifted": True,
        }
    )

    data = issue.to_dict()

    assert data["location"] == "src/demo.c:42"
    assert data["file"] == "src/demo.c:42"
    assert data["entry_function"] == "entry"
    assert data["sink_function"] == "sink"
    assert data["call_path"] == ["entry", "sink"]
    assert data["reachable_from_entry"] is True


def test_build_trial_summary_contains_cost_trajectory_grader_and_outcome(tmp_path: Path) -> None:
    started = time.time()
    env = collect_environment_metadata(
        suite_root=tmp_path,
        condition=CONDITION_CANDIDATES,
        run_kind="sample",
        command=["external_benchmark.py", "run-prepared"],
        started_at=started,
        finished_at=started + 2.5,
        return_code=0,
        config={"backend": "regex", "model": "unit-model", "prompt_autofill": {"enabled": False}},
    )

    summary = build_trial_summary(
        suite_root=tmp_path,
        run_dir=tmp_path / "run",
        condition=CONDITION_CANDIDATES,
        run_kind="sample",
        trial_index=1,
        report=_report(),
        truth=_truth(),
        environment=env,
        line_tolerance=5,
        conversation_files=["trajectory/pure_llm.jsonl"],
    )

    assert summary["schema_version"] == SCHEMA_VERSION
    assert summary["condition"] == CONDITION_CANDIDATES
    assert summary["environment"]["backend"] == "regex"
    assert summary["cost"]["tokens_per_verified_issue"] == 120.0
    assert summary["cost"]["tool_calls_per_verified_issue"] == 8.0
    assert summary["trajectory"]["worker_report_count"] == 1
    assert summary["grader"]["final_outcome"]["score"] == summary["evaluation"]["f1"]
    assert summary["final_outcome"]["true_positive_truth_ids"] == ["BUG-1"]


def test_aggregate_trial_summaries_reports_stability() -> None:
    base = {
        "schema_version": SCHEMA_VERSION,
        "condition": CONDITION_CANDIDATES,
        "evaluation": {
            "precision": 1.0,
            "recall": 0.5,
            "f1": 0.6667,
            "issue_identities": ["a", "b"],
            "true_positive_truth_ids": ["BUG-1"],
            "false_positive_issue_identities": ["b"],
        },
    }
    changed = json.loads(json.dumps(base))
    changed["evaluation"]["issue_identities"] = ["a", "c"]
    changed["evaluation"]["false_positive_issue_identities"] = ["c"]

    aggregate = aggregate_trial_summaries([base, changed])

    condition = aggregate["conditions"][CONDITION_CANDIDATES]
    assert condition["trial_count"] == 2
    assert condition["issue_jaccard"] == 0.3333
    assert condition["true_positive_overlap"] == 1.0
    assert condition["f1"]["mean"] == 0.6667


def test_external_benchmark_evaluate_writes_unified_schema(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    truth_path = tmp_path / "truth.json"
    output_path = tmp_path / "evaluation.json"
    report_path.write_text(json.dumps(_report()), encoding="utf-8")
    truth_path.write_text(json.dumps(_truth()), encoding="utf-8")

    result = external_benchmark.evaluate(
        argparse.Namespace(
            report=report_path,
            truth=truth_path,
            output=output_path,
            line_tolerance=5,
            view="default",
        )
    )

    written = json.loads(output_path.read_text(encoding="utf-8"))
    assert result["schema_version"] == SCHEMA_VERSION
    assert written["evaluation_views"]["with_needs_review"]["true_positives"] == 2


def test_zero_limit_still_means_formal_all_cases() -> None:
    assert external_benchmark._limit(0) is None
    assert external_benchmark._limit(-1) is None
    assert external_benchmark._limit(3) == 3


def test_suite_project_dir_accepts_nested_and_project_root_suites(tmp_path: Path) -> None:
    direct = tmp_path / "direct"
    nested_suite = tmp_path / "nested"
    (nested_suite / "project").mkdir(parents=True)
    direct.mkdir()

    assert external_benchmark._suite_project_dir(direct) == direct
    assert external_benchmark._suite_project_dir(nested_suite) == nested_suite / "project"


def test_run_prepared_candidate_layer_writes_protocol_summary(tmp_path: Path) -> None:
    suite_root = tmp_path / "suite"
    project = suite_root / "project"
    benchmark = suite_root / "benchmark"
    source = project / "src" / "demo.c"
    source.parent.mkdir(parents=True)
    benchmark.mkdir(parents=True)
    source.write_text(
        "#include <stdlib.h>\n"
        "int leaky(int flag) {\n"
        "  char *p = malloc(8);\n"
        "  if (flag) return 1;\n"
        "  free(p);\n"
        "  return 0;\n"
        "}\n",
        encoding="utf-8",
    )
    (project / "compile_commands.json").write_text(
        json.dumps(
            [
                {
                    "directory": project.as_posix(),
                    "command": f"clang -c {source.as_posix()}",
                    "file": source.as_posix(),
                }
            ]
        ),
        encoding="utf-8",
    )
    (benchmark / "entries.json").write_text(
        json.dumps({"functions": [{"function_name": "leaky", "file_path": "src/demo.c"}]}),
        encoding="utf-8",
    )
    (benchmark / "ground_truth.json").write_text(json.dumps(_truth()), encoding="utf-8")
    (suite_root / "zscope.benchmark.yaml").write_text(
        "project:\n  prompt_autofill:\n    enabled: false\nindexing:\n  backend: regex\n",
        encoding="utf-8",
    )
    run_dir = tmp_path / "run"

    summary = external_benchmark.run_prepared(
        argparse.Namespace(
            suite_root=suite_root,
            run_dir=run_dir,
            mode="candidates",
            condition=CONDITION_CANDIDATES,
            run_kind="smoke",
            trial_index=1,
            line_tolerance=8,
            view="default",
            env_file="",
        )
    )

    assert summary["schema_version"] == SCHEMA_VERSION
    assert summary["condition"] == CONDITION_CANDIDATES
    assert (run_dir / "summary.json").exists()
    assert (run_dir / "evaluation_views.json").exists()
