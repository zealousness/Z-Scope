from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import time
from pathlib import Path

import pytest

from scripts import external_benchmark
from zscope.benchmarking.protocol import (
    CONDITION_CANDIDATES,
    CONDITION_FULL_ZSCOPE,
    DEFAULT_BOOTSTRAP_SAMPLES,
    FP_AUDIT_DUPLICATE_OF_GT,
    FP_AUDIT_FALSE_POSITIVE_SUPPRESS,
    FP_AUDIT_NEEDS_REVIEW_ONLY,
    FP_AUDIT_TRUE_EXTRA_ADD_GT,
    SCHEMA_VERSION,
    aggregate_trial_summaries,
    build_benchmark_artifact_manifest,
    build_trial_summary,
    collect_environment_metadata,
    evaluate_improvement_claim,
    evaluate_non_regression_readiness,
    issue_identity,
    issue_identity_record,
    issue_matches,
    classify_false_positive_record,
    score_report,
    score_report_views,
    select_validator_arm,
    _select_max_weight_pairs,
)
from zscope.benchmarking.policy import DEFAULT_BENCHMARK_POLICY
from zscope.benchmarking.attestation import (
    ATTESTATION_SCHEMA_VERSION,
    finalize_balanced_attestation,
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


def test_max_weight_pair_selection_keeps_cardinality_for_large_reports() -> None:
    pair = {
        "truth_index": 99,
        "truth_id": "BUG-100",
        "issue_index": 19_999,
        "score": 1,
    }

    selected = _select_max_weight_pairs([pair], truth_count=100, issue_count=20_000)

    assert selected == [pair]


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
    assert scored["actionable_precision"] == 0.5
    assert scored["actionable_f1"] == 0.6667
    assert scored["actionable_false_discovery_rate"] == 0.5
    assert scored["root_cause_precision"] == 1.0
    assert scored["root_cause_f1"] == 1.0
    assert scored["false_discovery_rate"] == 0.0
    assert "false_positive_rate" not in scored
    assert "standard_false_positive_rate" not in scored
    assert "standard_false_positive_rate_metric" not in scored["scoring_contract"]
    assert raw_scored["false_positives"] == 1
    assert raw_scored["precision"] == raw_scored["actionable_precision"] == 0.5
    assert scored["false_positive_audit"]["counts"][FP_AUDIT_DUPLICATE_OF_GT] == 1


def test_default_false_positive_audit_keeps_unmatched_findings_for_review() -> None:
    audited = classify_false_positive_record(
        {
            "identity": "v1|api_contract_violation|src/main.c|td_query_status|audit_observation",
            "dedup_key": "api_contract_violation|src/main.c|613|return status",
        }
    )

    assert audited["fp_audit_classification"] == FP_AUDIT_NEEDS_REVIEW_ONLY


def test_actionable_precision_penalizes_wrong_class_at_the_same_location() -> None:
    truth = {
        "benchmark": "adversarial",
        "vulnerabilities": [
            {
                "id": "BUG-1",
                "category": "memory_leak",
                "function": "handle",
                "file": "src/demo.c",
                "line": 20,
                "keywords": ["allocation", "missing free"],
            }
        ],
    }
    report = {
        "issues": [
            {
                "category": "memory_leak",
                "function": "handle",
                "location": "src/demo.c:20",
                "description": "allocation is returned without a matching free",
            },
            {
                "category": "command_injection",
                "function": "handle",
                "location": "src/demo.c:20",
                "description": "shell command construction is unsafe",
            },
        ]
    }

    result = score_report(report, truth, line_tolerance=0)

    assert result["true_positives"] == 1
    assert result["false_positives_raw"] == 1
    assert result["duplicate_of_matched_count"] == 0
    assert result["actionable_precision"] == 0.5
    assert result["actionable_f1"] == 0.6667


def test_standard_false_positive_rate_uses_known_safe_entries() -> None:
    truth = {
        "benchmark": "negative-cases",
        "vulnerabilities": [],
        "safe_entries": [
            {"function": "safe_one", "file": "src/safe.c"},
            {"function": "safe_two", "file": "src/safe.c"},
        ],
    }
    report = {
        "issues": [
            {
                "category": "memory_leak",
                "entry_function": "safe_one",
                "function": "helper",
                "location": "src/safe.c:10",
                "description": "spurious warning attributed to safe_one",
            }
        ]
    }

    result = score_report(report, truth)

    assert result["false_discovery_rate"] == 1.0
    assert result["standard_false_positive_rate"] == 0.5
    assert result["safe_entry_alert_rate"] == 0.5
    assert result["alerted_safe_entry_count"] == 1
    assert result["alerted_safe_entries"] == ["src/safe.c|safe_one"]
    assert result["scoring_contract"]["standard_false_positive_rate_metric"] == (
        "safe_entry_alert_rate"
    )
    assert result["scoring_contract"]["safe_unit_rate_metric"] == "safe_entry_alert_rate"
    assert "false_positive_rate" not in result


def test_score_report_emits_high_critical_and_per_cwe_recall() -> None:
    truth = {
        "benchmark": "strata",
        "vulnerabilities": [
            {
                "id": "HIGH-1",
                "function": "high_bug",
                "file": "src/demo.c",
                "line": 10,
                "category": "memory_leak",
                "severity": "high",
                "cwe": "401",
            },
            {
                "id": "CRIT-1",
                "function": "critical_bug",
                "file": "src/demo.c",
                "line": 20,
                "category": "use_after_free",
                "severity": "critical",
                "cwe": "CWE401",
            },
            {
                "id": "LOW-1",
                "function": "low_bug",
                "file": "src/demo.c",
                "line": 30,
                "category": "unchecked_return",
                "severity": "low",
                "cwe": "CWE-252",
            },
        ],
        "safe_entries": [],
    }
    report = {
        "issues": [
            {
                "function": "high_bug",
                "location": "src/demo.c:10",
                "category": "memory_leak",
                "description": "allocation leaks",
            },
            {
                "function": "low_bug",
                "location": "src/demo.c:30",
                "category": "unchecked_return",
                "description": "return value is unchecked",
            },
        ]
    }

    result = score_report(report, truth, line_tolerance=0)

    assert result["high_critical_sample_count"] == 2
    assert result["high_critical_recall"] == 0.5
    assert result["per_cwe_recall"]["CWE-401"] == {
        "sample_count": 2,
        "true_positives": 1,
        "recall": 0.5,
    }
    assert result["per_cwe_recall"]["CWE-252"]["recall"] == 1.0


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

    assert scored["false_positive_audit"]["counts"][FP_AUDIT_FALSE_POSITIVE_SUPPRESS] == 1


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

    report = _report()
    report["metadata"]["report_assembly_seconds"] = 12.5
    summary = build_trial_summary(
        suite_root=tmp_path,
        run_dir=tmp_path / "run",
        condition=CONDITION_CANDIDATES,
        run_kind="sample",
        trial_index=1,
        report=report,
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
    assert summary["cost"]["report_tail_seconds"] == 12.5
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


def _release_summary(
    trial_index: int,
    *,
    actionable_precision: float = 0.75,
    actionable_fdr: float = 0.05,
    true_positives: int = 112,
    recall: float = 0.82,
    high_critical_recall: float = 0.92,
    safe_entry_alert_rate: float = 0.05,
    actionable_f1: float = 0.78,
    cwe_recall: float = 0.70,
    wall_time_seconds: float = 3500.0,
    billable_tokens: float = 9_000_000.0,
    report_tail_seconds: float = 100.0,
    tokens_per_verified_issue: float = 100.0,
    issue_identities: list[str] | None = None,
    true_positive_truth_ids: list[str] | None = None,
    cache_mode: str = "isolated_cold",
    integrity_status: str = "passed",
    validator_arm: str = "",
    baseline_frozen: bool = False,
) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "condition": CONDITION_FULL_ZSCOPE,
        "run_kind": "formal",
        "trial_index": trial_index,
        "environment": {
            "return_code": 1,
            "cache_mode": cache_mode,
        },
        "integrity": {
            "status": integrity_status,
            "cache_mode": cache_mode,
            "chain_sha256": "a" * 64,
        },
        "isolation": {
            "mode": "oci",
            "runtime": "podman",
            "runtime_path": "/usr/bin/podman",
            "available": True,
            "rootless_verified": True,
            "image_digest_verified": True,
            "execution_verified": True,
            "actual_inspection_collected": True,
            "release_capable": True,
            "truth_mounted": False,
            "repository_mounted": False,
            "scanner_cwd_isolated": True,
            "mounts_verified": True,
            "security_verified": True,
            "network_restriction_verified": True,
            "network_mode": "model-endpoint-only",
            "network_policy_sha256": "6" * 64,
            "image": "registry.example/zscope@sha256:" + "a" * 64,
            "scanner_cwd": "/zscope-input",
            "mounts": [
                {
                    "source": "/sealed/input",
                    "destination": "/zscope-input",
                    "purpose": "scan_input",
                    "read_only": True,
                },
                {
                    "source": "/sealed/output",
                    "destination": "/zscope-output",
                    "purpose": "artifact_output",
                    "read_only": False,
                },
                {
                    "source": "/sealed/cache",
                    "destination": "/zscope-cache",
                    "purpose": "cache",
                    "read_only": False,
                },
            ],
            "required_phases": ["scan"],
            "phase_executions": [
                {
                    "phase": "scan",
                    "inspect_verified": True,
                    "security_verified": True,
                    "network_peers_verified": True,
                    "network_contract_verified": True,
                    "proxy_verified": True,
                    "scanner_labels_verified": True,
                    "image_verified": True,
                    "unexpected_mount_count": 0,
                    "container_inspect_sha256": "7" * 64,
                    "network_inspect_sha256": "8" * 64,
                    "proxy_inspect_sha256": "9" * 64,
                }
            ],
            "errors": [],
        },
        "validator_replay_bundle": {
            "schema_version": "zscope.validator-replay-bundle.v1",
            "group_count": 2,
            "bundle_sha256": "b" * 64,
            "answer_material_present": False,
        },
        "artifact_manifest": {
            "truth_sha256": "1" * 64,
            "scorer_sha256": "2" * 64,
            "config_sha256": "3" * 64,
            "entries_sha256": "4" * 64,
            "source_manifest_sha256": "5" * 64,
            "benchmark_policy_sha256": DEFAULT_BENCHMARK_POLICY.sha256,
        },
        "evaluation": {
            "true_positives": true_positives,
            "actionable_precision": actionable_precision,
            "actionable_false_discovery_rate": actionable_fdr,
            "precision": actionable_precision,
            "distinct_root_recall": recall,
            "recall": recall,
            "high_critical_recall": high_critical_recall,
            "safe_entry_alert_rate": safe_entry_alert_rate,
            "actionable_f1": actionable_f1,
            "f1": actionable_f1,
            "per_cwe_recall": {
                "CWE-401": {
                    "sample_count": 20,
                    "true_positives": round(20 * cwe_recall),
                    "recall": cwe_recall,
                }
            },
            "issue_identities": issue_identities or ["issue-a", "issue-b"],
            "true_positive_truth_ids": true_positive_truth_ids or ["BUG-1", "BUG-2"],
            "false_positive_issue_identities": [],
            "attribution": {"explicit_coverage": 1.0},
        },
        "cost": {
            "wall_time_seconds": wall_time_seconds,
            "billable_tokens": billable_tokens,
            "report_tail_seconds": report_tail_seconds,
            "tokens_per_verified_issue": tokens_per_verified_issue,
            "usage_ledger": {
                "provider_usage_coverage": 1.0,
                "conservation_passed": True,
                "telemetry_complete": True,
            },
        },
        "release_evidence": {
            "queue_drained": True,
            "protocol_anomaly_count": 0,
            "budget_limited": False,
            "silent_rejection_without_proof_count": 0,
            "sealed_attested": True,
            "shadow_attested": True,
            "shadow_precision_at_25": 0.75,
            "shadow_high_critical_precision": 0.85,
            "active_discovery_exclusive_projects": ["p1", "p2", "p3"],
            "active_discovery_exclusive_cwe_families": ["CWE-119", "CWE-401"],
            "validator_arm": validator_arm,
            "baseline_frozen": baseline_frozen,
        },
    }


def _balanced_attestation() -> dict:
    metrics = {
        "sealed_confirmed_recall_delta_pp": 3.0,
        "sealed_actionable_precision_delta_pp": -1.0,
        "sealed_high_critical_recall_delta_pp": 0.0,
        "semantic_blind_review_unit_count": 100,
        "semantic_critical_contract_recall": 0.85,
        "semantic_unsupported_claim_rate": 0.05,
        "semantic_warm_cache_llm_call_reduction": 0.80,
        "active_discovery_exclusive_project_count": 3,
        "active_discovery_exclusive_cwe_family_count": 2,
        "safe_entry_alert_rate": 0.1,
        "safe_entry_alert_rate_delta_pp": 1.0,
        "shadow_precision_at_25": 0.7,
        "shadow_high_critical_precision": 0.8,
        "incomplete_scan_rate": 0.05,
        "silent_rejection_without_proof_count": 0,
    }
    return finalize_balanced_attestation(
        {
            "schema_version": ATTESTATION_SCHEMA_VERSION,
            "attestation_id": "test-attestation",
            "issued_at": "2026-08-12T12:00:00Z",
            "issuer": {
                "team": "independent-test",
                "independent_test_team": True,
                "signed_by": "review-board",
            },
            "bindings": {
                "dataset_sha256": "1" * 64,
                "truth_sha256": "2" * 64,
                "scanner_bundle_sha256": "3" * 64,
                "scorer_sha256": "4" * 64,
                "git_sha": "f" * 40,
                "config_sha256": "5" * 64,
                "rules_sha256": "6" * 64,
                "policy_sha256": DEFAULT_BENCHMARK_POLICY.sha256,
                "model_spec_sha256": "7" * 64,
                "baseline_sha256": "8" * 64,
                "public_external_aggregate_sha256": "9" * 64,
            },
            "coverage": {
                "sealed_project_count": 6,
                "domain_count": 3,
                "vulnerable_fixed_pair_count": 120,
                "safe_audit_unit_count": 1200,
                "max_project_share": 0.25,
                "max_cwe_share": 0.25,
                "rotation_fraction": 0.2,
                "shadow_project_count": 3,
                "public_external_suite_count": 3,
            },
            "metrics": metrics,
            "evidence": {
                "protected_artifact": True,
                "workflow_run_id": "test-run",
                "all_alerts_double_blind_reviewed": True,
                "all_disagreements_adjudicated": True,
                "public_external_formal_passed": True,
                "public_external_suites": ["Juliet", "SV-COMP", "Magma"],
            },
        }
    )


def test_release_readiness_passes_every_explicit_hard_gate() -> None:
    summaries = [_release_summary(index) for index in range(1, 6)]
    baseline = [
        _release_summary(
            index,
            actionable_precision=0.755,
            actionable_fdr=0.045,
            recall=0.78,
            high_critical_recall=0.91,
            safe_entry_alert_rate=0.04,
            validator_arm="A",
            baseline_frozen=True,
        )
        for index in range(1, 6)
    ]

    aggregate = aggregate_trial_summaries(
        summaries,
        baseline_summaries=baseline,
        balanced_attestation=_balanced_attestation(),
        balanced_attestation_workflow_run_id="test-run",
        release_sha="f" * 40,
        bootstrap_samples=100,
    )

    readiness = aggregate["release_readiness"]
    assert readiness["status"] == "passed"
    assert readiness["trial_protocol"]["paired_trial_count"] == 5
    required_gates = {
        "trial_protocol",
        "median_confirmed_tp",
        "median_tokens",
        "per_run_tokens",
        "actionable_fdr_delta_vs_arm_a_pp",
        "true_positive_jaccard",
        "recall_range_pp",
        "provider_usage_coverage",
        "explicit_attribution_coverage",
        "queue_drained_rate",
        "token_conservation_rate",
        "telemetry_complete_rate",
        "protocol_anomaly_count",
        "sealed_confirmed_recall_delta_pp",
        "sealed_actionable_precision_delta_pp",
        "sealed_high_critical_recall_delta_pp",
        "semantic_blind_review_unit_count",
        "semantic_critical_contract_recall",
        "semantic_unsupported_claim_rate",
        "semantic_warm_cache_llm_call_reduction",
        "active_discovery_exclusive_project_count",
        "active_discovery_exclusive_cwe_family_count",
        "safe_entry_alert_rate",
        "safe_entry_alert_rate_delta_pp",
        "shadow_precision_at_25",
        "shadow_high_critical_precision",
        "incomplete_scan_rate",
        "silent_rejection_without_proof_count",
        "arm_a_baseline_attested",
        "public_external_attested",
        "sealed_attested",
        "shadow_attested",
    }
    assert required_gates == set(readiness["hard_gates"])
    assert all(gate["passed"] for gate in readiness["hard_gates"].values())
    precision_stats = aggregate["conditions"][CONDITION_FULL_ZSCOPE]["actionable_precision"]
    assert precision_stats["bootstrap_ci"]["confidence_level"] == 0.95
    assert precision_stats["bootstrap_ci"]["lower"] == 0.75
    assert precision_stats["bootstrap_ci"]["upper"] == 0.75


def test_release_readiness_enforces_111_tp_and_two_token_caps() -> None:
    baseline = [
        _release_summary(
            index,
            recall=0.78,
            actionable_fdr=0.045,
            validator_arm="A",
            baseline_frozen=True,
        )
        for index in range(1, 6)
    ]
    low_tp = [_release_summary(index, true_positives=110) for index in range(1, 6)]
    readiness = aggregate_trial_summaries(
        low_tp, baseline_summaries=baseline, bootstrap_samples=20
    )["release_readiness"]
    assert readiness["hard_gates"]["median_confirmed_tp"]["passed"] is False

    high_median = [_release_summary(index, billable_tokens=10_000_001) for index in range(1, 6)]
    readiness = aggregate_trial_summaries(
        high_median, baseline_summaries=baseline, bootstrap_samples=20
    )["release_readiness"]
    assert readiness["hard_gates"]["median_tokens"]["passed"] is False

    high_one = [_release_summary(index) for index in range(1, 6)]
    high_one[0]["cost"]["billable_tokens"] = 12_000_001
    readiness = aggregate_trial_summaries(
        high_one, baseline_summaries=baseline, bootstrap_samples=20
    )["release_readiness"]
    assert readiness["hard_gates"]["per_run_tokens"]["passed"] is False


def test_release_readiness_rejects_unfrozen_or_non_arm_a_baseline() -> None:
    current = [_release_summary(index) for index in range(1, 6)]
    wrong_baseline = [
        _release_summary(index, validator_arm="B", baseline_frozen=True) for index in range(1, 6)
    ]

    readiness = aggregate_trial_summaries(
        current,
        baseline_summaries=wrong_baseline,
        balanced_attestation=_balanced_attestation(),
        balanced_attestation_workflow_run_id="test-run",
        release_sha="f" * 40,
        bootstrap_samples=20,
    )["release_readiness"]

    assert readiness["hard_gates"]["arm_a_baseline_attested"]["passed"] is False


def test_release_readiness_enforces_stability_jaccard_and_five_cold_trials() -> None:
    baseline = [
        _release_summary(
            index,
            recall=0.78,
            actionable_fdr=0.045,
            validator_arm="A",
            baseline_frozen=True,
        )
        for index in range(1, 6)
    ]
    only_four = [_release_summary(index) for index in range(1, 5)]
    four_readiness = aggregate_trial_summaries(
        only_four,
        baseline_summaries=baseline,
        bootstrap_samples=20,
    )["release_readiness"]
    assert four_readiness["hard_gates"]["trial_protocol"]["passed"] is False

    unstable_recall = [
        _release_summary(index, recall=value)
        for index, value in enumerate((0.80, 0.81, 0.82, 0.83, 0.84), start=1)
    ]
    recall_readiness = aggregate_trial_summaries(
        unstable_recall,
        baseline_summaries=baseline,
        bootstrap_samples=20,
    )["release_readiness"]
    assert recall_readiness["hard_gates"]["recall_range_pp"]["passed"] is False

    unstable_alerts = [
        _release_summary(
            index,
            issue_identities=[f"issue-{index}"],
            true_positive_truth_ids=[f"BUG-{index}"],
        )
        for index in range(1, 6)
    ]
    jaccard_readiness = aggregate_trial_summaries(
        unstable_alerts,
        baseline_summaries=baseline,
        bootstrap_samples=20,
    )["release_readiness"]
    assert jaccard_readiness["hard_gates"]["true_positive_jaccard"]["passed"] is False

    warm = [_release_summary(index) for index in range(1, 6)]
    warm[0] = _release_summary(1, cache_mode="warm")
    warm_readiness = aggregate_trial_summaries(
        warm,
        baseline_summaries=baseline,
        bootstrap_samples=20,
    )["release_readiness"]
    assert warm_readiness["hard_gates"]["trial_protocol"]["passed"] is False


def test_paired_improvement_claim_and_frozen_token_baseline() -> None:
    current = [
        _release_summary(
            index,
            actionable_f1=0.80,
            wall_time_seconds=100.0,
            tokens_per_verified_issue=100.0,
            recall=0.82,
        )
        for index in range(1, 6)
    ]
    baseline = [
        _release_summary(
            index,
            actionable_f1=0.74,
            wall_time_seconds=130.0,
            tokens_per_verified_issue=150.0,
            recall=0.78,
            actionable_precision=0.755,
            actionable_fdr=0.045,
            high_critical_recall=0.91,
            safe_entry_alert_rate=0.04,
            validator_arm="A",
            baseline_frozen=True,
        )
        for index in range(1, 6)
    ]
    for summary in baseline:
        summary["artifact_manifest"]["config_sha256"] = "9" * 64

    readiness = aggregate_trial_summaries(
        current,
        baseline_summaries=baseline,
        balanced_attestation=_balanced_attestation(),
        balanced_attestation_workflow_run_id="test-run",
        release_sha="f" * 40,
        require_improvement_claim=True,
        bootstrap_samples=100,
    )["release_readiness"]

    assert readiness["passed"]
    assert readiness["improvement_claim"]["quality_gain_path"]["passed"]
    assert readiness["improvement_claim"]["quality_delta_percentage_points"] == 6.0
    assert readiness["improvement_claim"]["quality_delta_bootstrap_ci"]["lower"] > 0
    assert readiness["non_regression_readiness"]["gates"]["tokens_per_kloc_or_tp_growth"]["passed"]


def test_improvement_claim_accepts_speed_path_with_at_most_two_point_quality_loss() -> None:
    current = [
        _release_summary(index, actionable_f1=0.79, wall_time_seconds=75.0) for index in range(1, 6)
    ]
    baseline = [
        _release_summary(index, actionable_f1=0.80, wall_time_seconds=100.0)
        for index in range(1, 6)
    ]

    claim = evaluate_improvement_claim(
        current,
        baseline,
        bootstrap_samples=50,
    )

    assert claim["passed"]
    assert claim["quality_gain_path"]["passed"] is False
    assert claim["performance_path"]["passed"]
    assert claim["quality_delta_percentage_points"] == pytest.approx(-1.0)
    assert claim["median_wall_time_reduction"] == 0.25


def test_validator_arm_tie_break_uses_lowest_median_tokens_within_one_point() -> None:
    selected = select_validator_arm(
        {
            "B": {"passed": True, "median_recall": 0.82, "median_tokens": 8_000_000},
            "C": {"passed": True, "median_recall": 0.829, "median_tokens": 9_000_000},
            "D": {"passed": False, "median_recall": 0.90, "median_tokens": 11_000_000},
        }
    )

    assert selected == "B"


def test_non_regression_enforces_two_points_and_twenty_five_percent_cost_growth() -> None:
    baseline = [
        _release_summary(
            index,
            recall=0.82,
            actionable_precision=0.80,
            high_critical_recall=0.90,
            tokens_per_verified_issue=100,
        )
        for index in range(1, 6)
    ]
    current = [
        _release_summary(
            index,
            recall=0.80,
            actionable_precision=0.78,
            high_critical_recall=0.88,
            tokens_per_verified_issue=125,
        )
        for index in range(1, 6)
    ]

    result = evaluate_non_regression_readiness(current, baseline)

    assert result["passed"] is True
    current[0]["cost"]["tokens_per_verified_issue"] = 200
    for item in current[1:]:
        item["cost"]["tokens_per_verified_issue"] = 126
    assert evaluate_non_regression_readiness(current, baseline)["passed"] is False


def test_formal_matrix_rejects_too_few_or_warm_trials_before_execution(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="at least 5 paired trials"):
        external_benchmark.run_matrix(
            argparse.Namespace(
                suite_root=tmp_path,
                trials=4,
                run_kind="formal",
                warm_cache=False,
            )
        )
    with pytest.raises(ValueError, match="isolated cold caches"):
        external_benchmark.run_matrix(
            argparse.Namespace(
                suite_root=tmp_path,
                trials=5,
                run_kind="formal",
                warm_cache=True,
            )
        )

    parser = external_benchmark.build_parser()
    args = parser.parse_args(["run-matrix", "--suite-root", str(tmp_path), "--trials", "5"])
    assert args.bootstrap_samples == DEFAULT_BOOTSTRAP_SAMPLES


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


def _write_integrity_suite(tmp_path: Path) -> tuple[Path, Path, str]:
    suite_root = tmp_path / "integrity_suite"
    project = suite_root / "project"
    benchmark = suite_root / "benchmark"
    source = project / "src" / "demo.c"
    source.parent.mkdir(parents=True)
    benchmark.mkdir(parents=True)
    source.write_text(
        "int leaky(void) {\n" "  void *p = malloc(8);\n" "  return p != 0;\n" "}\n",
        encoding="utf-8",
    )
    (benchmark / "entries.json").write_text(
        json.dumps({"functions": [{"function_name": "leaky", "file_path": "src/demo.c"}]}),
        encoding="utf-8",
    )
    truth = {
        "benchmark": "integrity_suite",
        "suite": "unit",
        "vulnerabilities": [
            {
                "id": "BUG-1",
                "category": "memory_leak",
                "function": "leaky",
                "file": "src/demo.c",
                "line": 2,
            }
        ],
        "safe_entries": [],
    }
    (benchmark / "ground_truth.json").write_text(json.dumps(truth), encoding="utf-8")
    (benchmark / "manifest.json").write_text(
        json.dumps({"suite": "unit", "entries": 1, "ground_truth": 1}),
        encoding="utf-8",
    )
    original_config = (
        "config_version: 2\n"
        "llms:\n"
        "  default:\n"
        '    base_urls: ["http://localhost/v1"]\n'
        '    models: ["unit-model"]\n'
        "    api_key: unit-key\n"
        "project:\n"
        f'  root: "{project.as_posix()}"\n'
        "  source_root: .\n"
        "  language: c_cpp\n"
        '  entry_functions_list: "../benchmark/entries.json"\n'
        "scan:\n"
        '  task: ""\n'
        "indexing:\n"
        "  backend: regex\n"
        "concurrency:\n"
        "  entry_workers: 1\n"
        "  validator_workers: 1\n"
        "  investigator_workers: 1\n"
        "  evidence_completion_workers: 1\n"
        "  index_workers: 1\n"
        "  svf_workers: 1\n"
        "  llm_max_inflight: 1\n"
    )
    (suite_root / "zscope.benchmark.yaml").write_text(original_config, encoding="utf-8")
    return suite_root, source, original_config


def test_artifact_manifest_detects_source_changes(tmp_path: Path) -> None:
    suite_root, source, _original_config = _write_integrity_suite(tmp_path)
    truth = json.loads((suite_root / "benchmark" / "ground_truth.json").read_text(encoding="utf-8"))
    before = build_benchmark_artifact_manifest(suite_root, truth=truth)

    source.write_text(source.read_text(encoding="utf-8") + "/* changed */\n", encoding="utf-8")
    after = build_benchmark_artifact_manifest(suite_root, truth=truth)

    for key in (
        "truth_sha256",
        "scorer_sha256",
        "config_sha256",
        "entries_sha256",
        "source_manifest_sha256",
        "benchmark_policy_sha256",
    ):
        assert len(str(before[key])) == 64
    assert before["source_manifest_sha256"] != after["source_manifest_sha256"]
    assert before["truth_sha256"] == after["truth_sha256"]


def test_cold_trial_refuses_a_nonempty_snapshot_cache(tmp_path: Path) -> None:
    suite_root, _source, _original_config = _write_integrity_suite(tmp_path)
    run_dir = tmp_path / "reused_run"
    cache_dir = run_dir / ".cold_snapshot_cache"
    cache_dir.mkdir(parents=True)
    (cache_dir / "stale.json").write_text("{}", encoding="utf-8")

    with pytest.raises(RuntimeError, match="Cold benchmark cache is not empty"):
        external_benchmark._prepare_trial_config(
            suite_root,
            run_dir,
            warm_cache=False,
        )


def test_integrity_rejects_noncomplete_schema_v2_report(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text("{}", encoding="utf-8")
    report_state = external_benchmark._file_integrity_state(report_path)
    manifest = {
        "truth_sha256": "a" * 64,
        "scorer_sha256": "b" * 64,
        "config_sha256": "c" * 64,
        "execution_config_sha256": "d" * 64,
        "benchmark_manifest_sha256": "e" * 64,
        "entries_sha256": "f" * 64,
        "source_manifest_sha256": "1" * 64,
        "benchmark_policy_sha256": DEFAULT_BENCHMARK_POLICY.sha256,
        "source_file_count": 1,
    }

    integrity = external_benchmark._validate_trial_integrity(
        condition=external_benchmark.CONDITION_FULL_ZSCOPE,
        return_code=1,
        started_at=time.time() - 1,
        report_before={"exists": False, "sha256": "", "mtime_ns": 0},
        report_after=report_state,
        report_payload={
            "schema_version": 2,
            "completeness": "degraded",
            "scan_outcome": "incomplete",
            "summary": {"functions_analyzed": 1, "interrupted": False},
            "metadata": {"interrupted": False},
        },
        artifact_manifest_before=manifest,
        artifact_manifest_after=manifest,
        expected_entry_count=1,
        cold_snapshot_cache=True,
    )

    assert integrity["status"] == "failed"
    assert len(integrity["chain_sha256"]) == 64
    assert any("completeness is degraded" in error for error in integrity["errors"])
    assert any("scan outcome is incomplete" in error for error in integrity["errors"])


def test_invalid_report_is_converted_to_fail_closed_payload(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text("{not-json", encoding="utf-8")

    payload = external_benchmark._load_report(report)

    assert payload["overall_verdict"] == "error"
    assert payload["metadata"]["invalid_report"] == report.as_posix()
    assert "JSONDecodeError" in payload["metadata"]["parse_error"]


def test_full_trial_uses_isolated_snapshot_cache_and_records_integrity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    suite_root, _source, original_config = _write_integrity_suite(tmp_path)
    project = suite_root / "project"
    run_dir = tmp_path / "full_run"
    observed_config: dict[str, str] = {}

    def fake_run(command, **kwargs):
        execution_config = Path(command[command.index("-c") + 1])
        observed_config["path"] = execution_config.as_posix()
        observed_config["text"] = execution_config.read_text(encoding="utf-8")
        observed_config["developer_mode"] = kwargs["env"]["Z_SCOPE_DEVELOPER_MODE"]
        runtime_override = Path(kwargs["env"]["Z_SCOPE_RUNTIME_SPEC"])
        observed_config["runtime_override"] = runtime_override.as_posix()
        observed_config["runtime_text"] = runtime_override.read_text(encoding="utf-8")
        report = {
            "type": "parallel_analysis_report",
            "summary": {
                "functions_analyzed": 1,
                "total_issues": 1,
                "interrupted": False,
            },
            "issues": [
                {
                    "category": "memory_leak",
                    "function": "leaky",
                    "location": "src/demo.c:2",
                    "description": "allocation has no matching free",
                }
            ],
            "metadata": {"interrupted": False},
        }
        (project / "zscope_batch_report.json").write_text(
            json.dumps(report),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="")

    monkeypatch.setattr(external_benchmark.subprocess, "run", fake_run)
    summary = external_benchmark.run_prepared(
        argparse.Namespace(
            suite_root=suite_root,
            run_dir=run_dir,
            mode="zscope",
            condition=external_benchmark.CONDITION_FULL_ZSCOPE,
            run_kind="sample",
            trial_index=1,
            line_tolerance=2,
            view="default",
            env_file="",
            warm_cache=False,
        )
    )

    assert (suite_root / "zscope.benchmark.yaml").read_text(encoding="utf-8") == original_config
    assert Path(observed_config["path"]).parent == run_dir
    assert observed_config["text"] == original_config
    assert observed_config["developer_mode"] == "1"
    assert Path(observed_config["runtime_override"]).parent == run_dir
    assert ".cold_snapshot_cache" in observed_config["runtime_text"]
    assert summary["integrity"]["status"] == "passed"
    assert summary["integrity"]["cache_mode"] == "isolated_cold"
    assert summary["artifact_manifest"]["truth_sha256"]
    assert summary["artifact_manifest"]["source_manifest_sha256"]
    assert summary["environment"]["execution_config"] == observed_config["path"]
    assert (run_dir / "integrity.json").exists()


def test_full_trial_rejects_a_stale_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    suite_root, _source, _original_config = _write_integrity_suite(tmp_path)
    project = suite_root / "project"
    run_dir = tmp_path / "stale_run"
    stale_report = {
        "type": "parallel_analysis_report",
        "summary": {"functions_analyzed": 1, "total_issues": 0, "interrupted": False},
        "issues": [],
        "metadata": {"interrupted": False},
    }
    (project / "zscope_batch_report.json").write_text(
        json.dumps(stale_report),
        encoding="utf-8",
    )

    def fake_run(command, **_kwargs):
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(external_benchmark.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="stale"):
        external_benchmark.run_prepared(
            argparse.Namespace(
                suite_root=suite_root,
                run_dir=run_dir,
                mode="zscope",
                condition=external_benchmark.CONDITION_FULL_ZSCOPE,
                run_kind="sample",
                trial_index=1,
                line_tolerance=2,
                view="default",
                env_file="",
                warm_cache=False,
            )
        )

    integrity = json.loads((run_dir / "integrity.json").read_text(encoding="utf-8"))
    assert integrity["status"] == "failed"
    assert any("stale" in message for message in integrity["errors"])


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
