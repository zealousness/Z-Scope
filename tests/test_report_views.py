from types import SimpleNamespace

import pytest

from zscope.orchestration.candidates import CandidateLedger
from zscope.orchestration.parallel_analyzer import ParallelAnalysisResult, ParallelAnalyzer
from zscope.reporting.views import build_report_views, findings_for_view


def test_build_report_views_includes_all_actionable_review_observations() -> None:
    issues = [
        {
            "id": "ISSUE_1",
            "function": "entry",
            "location": "src/demo.c:10",
            "category": "bounds",
            "description": "reported issue",
        }
    ]
    observations = [
        {
            "id": "REVIEW_1",
            "function": "entry",
            "location": "src/demo.c:20",
            "category": "race",
            "validation_status": "needs_review",
            "description": "review issue",
        },
        {
            "id": "UNCERTAIN_1",
            "function": "entry",
            "location": "src/demo.c:30",
            "category": "race",
            "validation_status": "uncertain",
            "description": "uncertain issue",
        },
    ]

    views = build_report_views(issues, observations)

    assert views["default"]["issue_count"] == 1
    assert views["with_needs_review"]["issue_count"] == 3
    assert views["with_needs_review"]["included_needs_review_count"] == 2
    assert {issue["id"] for issue in views["with_needs_review"]["issues"]} == {
        "ISSUE_1",
        "REVIEW_1",
        "UNCERTAIN_1",
    }


def test_build_report_views_attaches_duplicate_needs_review_observations() -> None:
    issues = [
        {
            "id": "ISSUE_VALIDATED",
            "function": "td_init",
            "location": "src/main.c:187",
            "category": "memory_leak",
            "resource_signature": "thread_ids",
            "description": "`thread_ids` is heap allocated and never released.",
            "validation_status": "validated",
        }
    ]
    observations = [
        {
            "id": "GRAPH_MEMORY_LEAK",
            "candidate_id": "GRAPH_MEMORY_LEAK",
            "function": "td_init",
            "location": "src/main.c:190",
            "category": "memory_leak",
            "resource_signature": "thread_ids",
            "validation_status": "needs_review",
            "description": "`thread_ids` owner allocation is passed into pthread_create without owner cleanup.",
        }
    ]

    views = build_report_views(issues, observations)
    with_review = views["with_needs_review"]

    assert with_review["issue_count"] == 1
    assert with_review["included_needs_review_count"] == 1
    assert with_review["independent_needs_review_count"] == 0
    assert with_review["attached_needs_review_count"] == 1
    issue = with_review["issues"][0]
    assert issue["id"] == "ISSUE_VALIDATED"
    assert issue["related_needs_review_observations"][0]["id"] == "GRAPH_MEMORY_LEAK"
    assert "related_needs_review_observations" not in views["default"]["issues"][0]


def test_canonical_projection_does_not_hide_review_related_to_confirmed() -> None:
    confirmed = {
        "id": "ISSUE_CONFIRMED",
        "candidate_disposition": "confirmed",
        "validation_cluster_uid": "VAL_confirmed",
        "function": "sink",
        "location": "src/main.c:42",
        "category": "memory_leak",
        "resource_signature": "shared_buffer",
    }
    review = {
        "id": "ISSUE_REVIEW",
        "candidate_disposition": "needs_review",
        "validation_status": "needs_review",
        "validation_cluster_uid": "VAL_review",
        "function": "sink",
        "location": "src/main.c:42",
        "category": "memory_leak",
        "resource_signature": "shared_buffer",
    }

    views = build_report_views(
        [confirmed],
        [review],
        canonical_projection=True,
    )

    with_review = views["with_needs_review"]
    assert with_review["issue_count"] == 2
    assert with_review["included_needs_review_count"] == 1
    assert with_review["attached_needs_review_count"] == 0
    assert [item["id"] for item in with_review["issues"]] == [
        "ISSUE_CONFIRMED",
        "ISSUE_REVIEW",
    ]
    assert views["default"]["is_subset_of_with_needs_review"] is True
    assert with_review["contains_all_default"] is True
    assert with_review["contains_all_canonical_needs_review"] is True


def test_canonical_projection_keeps_shadow_audit_out_of_both_security_views() -> None:
    confirmed = {
        "id": "ISSUE_CONFIRMED",
        "candidate_disposition": "confirmed",
        "validation_cluster_uid": "VAL_confirmed",
    }
    review = {
        "id": "ISSUE_REVIEW",
        "candidate_disposition": "needs_review",
        "validation_status": "needs_review",
        "validation_cluster_uid": "VAL_review",
    }
    audit = {
        "id": "AUDIT_ONLY",
        "candidate_disposition": "shadow_observation",
        # A stale legacy status must not leak an audit observation back into
        # the with-needs-review security projection.
        "validation_status": "needs_review",
        "validation_cluster_uid": "VAL_audit",
    }

    views = build_report_views(
        [confirmed],
        [review, audit],
        canonical_projection=True,
    )

    assert [item["id"] for item in views["default"]["issues"]] == ["ISSUE_CONFIRMED"]
    assert [item["id"] for item in views["with_needs_review"]["issues"]] == [
        "ISSUE_CONFIRMED",
        "ISSUE_REVIEW",
    ]
    assert views["with_needs_review"]["included_needs_review_count"] == 1
    assert views["with_needs_review"]["contains_all_canonical_needs_review"] is True


def test_build_report_views_treats_null_related_observations_as_empty() -> None:
    issues = [
        {
            "id": "ISSUE_VALIDATED",
            "function": "td_init",
            "location": "src/main.c:187",
            "category": "memory_leak",
            "resource_signature": "thread_ids",
            "validation_status": "validated",
            "related_needs_review_observations": None,
        }
    ]
    observations = [
        {
            "id": "GRAPH_MEMORY_LEAK",
            "function": "td_init",
            "location": "src/main.c:190",
            "category": "memory_leak",
            "resource_signature": "thread_ids",
            "validation_status": "needs_review",
            "description": "Same root cause needs review.",
        }
    ]

    issue = build_report_views(issues, observations)["with_needs_review"]["issues"][0]

    assert issue["related_needs_review_observations"][0]["id"] == "GRAPH_MEMORY_LEAK"


def test_attached_needs_review_observation_keeps_path_attribution() -> None:
    issues = [
        {
            "id": "ISSUE_VALIDATED",
            "function": "sink",
            "entry_function": "entry",
            "sink_function": "sink",
            "call_path": ["entry", "sink"],
            "source_identity": "src/demo.c:12:length",
            "sink_identity": "src/demo.c:42:sink",
            "location": "src/demo.c:42",
            "category": "bounds",
            "description": "entry reaches sink with unchecked length.",
            "validation_status": "validated",
        }
    ]
    observations = [
        {
            "id": "REVIEW_PATH",
            "function": "sink",
            "entry_function": "entry",
            "sink_function": "sink",
            "call_path": ["entry", "sink"],
            "source_identity": "src/demo.c:12:length",
            "sink_identity": "src/demo.c:42:sink",
            "evidence_pack": {
                "entry_function": "entry",
                "sink_function": "sink",
                "call_path": ["entry", "sink"],
            },
            "location": "src/demo.c:43",
            "category": "bounds",
            "validation_status": "needs_review",
            "description": "The same sink is reachable from entry.",
        }
    ]

    issue = build_report_views(issues, observations)["with_needs_review"]["issues"][0]
    compact = issue["related_needs_review_observations"][0]

    assert compact["entry_function"] == "entry"
    assert compact["sink_function"] == "sink"
    assert compact["call_path"] == ["entry", "sink"]
    assert compact["evidence_pack"]["sink_function"] == "sink"


def test_needs_review_with_same_entry_but_different_sink_stays_independent() -> None:
    issues = [
        {
            "id": "ISSUE_PARSE",
            "function": "_parse_task_buffer",
            "entry_function": "td_serialize_task_message",
            "sink_function": "_parse_task_buffer",
            "location": "src/parser.c:208",
            "category": "integer_overflow",
            "description": "task length arithmetic can overflow in parser helper",
            "validation_status": "validated",
        }
    ]
    observations = [
        {
            "id": "REVIEW_SERIALIZE",
            "function": "_serialize_task",
            "entry_function": "td_serialize_task_message",
            "sink_function": "_serialize_task",
            "location": "src/parser.c:223",
            "category": "integer_overflow",
            "validation_status": "needs_review",
            "description": "task length arithmetic can overflow in serializer helper",
        }
    ]

    with_review = build_report_views(issues, observations)["with_needs_review"]

    assert with_review["issue_count"] == 2
    assert with_review["independent_needs_review_count"] == 1
    assert "related_needs_review_observations" not in with_review["issues"][0]


def test_nearby_findings_for_different_objects_stay_independent() -> None:
    issues = [
        {
            "id": "CONFIRMED_LEFT",
            "function": "cleanup",
            "entry_function": "entry",
            "sink_function": "cleanup",
            "location": "src/demo.c:40",
            "category": "double_free",
            "resource_signature": "left_object",
            "source_loc": "src/demo.c:10",
            "sink_loc": "src/demo.c:40",
            "validation_status": "validated",
        }
    ]
    observations = [
        {
            "id": "REVIEW_RIGHT",
            "function": "cleanup",
            "entry_function": "entry",
            "sink_function": "cleanup",
            "location": "src/demo.c:43",
            "category": "double_free",
            "resource_signature": "right_object",
            "source_loc": "src/demo.c:12",
            "sink_loc": "src/demo.c:43",
            "validation_status": "needs_review",
        }
    ]

    with_review = build_report_views(issues, observations)["with_needs_review"]

    assert with_review["issue_count"] == 2
    assert with_review["independent_needs_review_count"] == 1
    assert with_review["attached_needs_review_count"] == 0


def test_needs_review_numeric_category_variant_attaches_by_root() -> None:
    issues = [
        {
            "id": "CLANG_CFG_SIZE_LIMIT_MISMATCH",
            "function": "allocate_label_cache",
            "location": "src/cache.c:1677",
            "category": "size_limit_mismatch",
            "root_cause_key": "numeric_allocation_size_calculation",
            "resource_signature": "label_cache",
            "validation_status": "validated",
            "description": "label cache size calculation uses the wrong limit.",
        }
    ]
    observations = [
        {
            "id": "ISSUE_INTEGER_OVERFLOW",
            "function": "allocate_label_cache",
            "location": "src/cache.c:1677",
            "category": "integer_overflow",
            "root_cause_key": "numeric_allocation_size_calculation",
            "resource_signature": "label_cache",
            "validation_status": "needs_review",
            "description": "element_count multiplication can overflow in the same label cache calculation.",
        }
    ]

    with_review = build_report_views(issues, observations)["with_needs_review"]

    assert with_review["issue_count"] == 1
    assert with_review["attached_needs_review_count"] == 1
    assert (
        with_review["issues"][0]["related_needs_review_observations"][0]["id"]
        == "ISSUE_INTEGER_OVERFLOW"
    )


def test_parallel_combined_report_rejects_noncanonical_report_only_input() -> None:
    analyzer = object.__new__(ParallelAnalyzer)
    analyzer.max_workers = 12
    results = {
        "entry": ParallelAnalysisResult(
            function_name="entry",
            verdict="issues_found",
            issues=[
                {
                    "id": "ISSUE_1",
                    "function": "entry",
                    "location": "src/demo.c:10",
                    "category": "bounds",
                    "description": "reported issue",
                }
            ],
            audit_observations=[
                {
                    "id": "REVIEW_1",
                    "function": "entry",
                    "location": "src/demo.c:20",
                    "category": "race",
                    "validation_status": "needs_review",
                    "description": "review issue",
                }
            ],
        )
    }

    with pytest.raises(RuntimeError, match="requires a Candidate Ledger"):
        analyzer.generate_combined_report(results)


def test_parallel_combined_report_does_not_fall_back_when_frozen_outcomes_are_empty() -> None:
    analyzer = object.__new__(ParallelAnalyzer)
    analyzer.max_workers = 12
    analyzer._candidate_ledger = CandidateLedger()
    results = {
        "entry": ParallelAnalysisResult(
            function_name="entry",
            verdict="issues_found",
            issues=[
                {
                    "id": "RAW_ISSUE",
                    "function": "entry",
                    "location": "src/demo.c:10",
                    "category": "bounds",
                    "description": "must not bypass the Candidate Ledger",
                }
            ],
        )
    }

    report = analyzer.generate_combined_report(results)

    assert report["summary"]["total_issues"] == 0
    assert report["summary"]["total_issues_with_needs_review"] == 0
    assert report["metadata"]["audit_observation_count"] == 0
    assert report["metadata"]["candidate_funnel"]["schema_version"] == (
        "zscope.candidate-funnel.v1"
    )
    assert findings_for_view(report, "default") == []
    assert findings_for_view(report, "with_needs_review") == []
    assert report["run_manifest"]["report_invariant_status"]["canonical_projection"] is True


def test_parallel_combined_report_separates_review_and_audit_with_terminal_conservation(
    monkeypatch,
) -> None:
    def finalize_trace(_self, issue, *, view_memberships):
        issue["decision_trace_ref"] = f"trace:{issue['validation_cluster_uid']}"
        issue["decision_trace_view_memberships"] = list(view_memberships)
        return issue

    # TerminalAuthority v4 is covered independently.  Keep this report-level
    # integration focused on the final frozen projection and its conservation
    # without manufacturing a proof envelope in the fixture.
    monkeypatch.setattr(
        "zscope.orchestration.decision_trace.DecisionTraceStore.finalize_issue",
        finalize_trace,
    )

    class FrozenLedger:
        @staticmethod
        def freeze():
            return {
                "outcomes": [
                    {
                        "validation_cluster_uid": "VAL_REVIEW_ONLY",
                        "terminal_disposition": "needs_review",
                        "status": "needs_review",
                        "issue": {
                            "id": "REVIEW_ONLY",
                            "candidate_uid": "CAND_REVIEW_ONLY",
                            "occurrence_uid": "OCC_REVIEW_ONLY",
                            "validation_cluster_uid": "VAL_REVIEW_ONLY",
                            "function": "review_sink",
                            "location": "src/review.c:11",
                            "category": "bounds",
                            "source_identity": "review_length",
                        },
                    },
                    {
                        "validation_cluster_uid": "VAL_AUDIT_ONLY",
                        "terminal_disposition": "shadow_observation",
                        "status": "uncertain",
                        "issue": {
                            "id": "AUDIT_ONLY",
                            "candidate_uid": "CAND_AUDIT_ONLY",
                            "occurrence_uid": "OCC_AUDIT_ONLY",
                            "validation_cluster_uid": "VAL_AUDIT_ONLY",
                            "function": "audit_sink",
                            "location": "src/audit.c:22",
                            "category": "generic",
                            "source_identity": "broad_pattern",
                            # A stale legacy field must not make this item
                            # actionable after its terminal disposition is
                            # frozen as audit-only.
                            "validation_status": "needs_review",
                        },
                    },
                ],
                "summary": {
                    "validation_group_count": 2,
                    "terminal_validation_count": 2,
                    "nonterminal_validation_count": 0,
                },
            }

    analyzer = object.__new__(ParallelAnalyzer)
    analyzer.max_workers = 1
    analyzer._candidate_ledger = FrozenLedger()
    results = {
        "entry": ParallelAnalysisResult(
            function_name="entry",
            verdict="no_issue_found",
        )
    }

    report = analyzer.generate_combined_report(results)

    assert findings_for_view(report, "default") == []
    assert [item["id"] for item in findings_for_view(report, "with_needs_review")] == [
        "REVIEW_ONLY"
    ]
    assert [item["id"] for item in report["metadata"]["audit_observations"]] == ["AUDIT_ONLY"]
    terminal = {
        item["id"]: item["candidate_disposition"] for item in report["candidate_terminal_states"]
    }
    assert terminal == {
        "AUDIT_ONLY": "shadow_observation",
        "REVIEW_ONLY": "needs_review",
    }
    assert report["summary"]["needs_review_issues"] == 1
    assert report["summary"]["audit_observations"] == 1
    assert len(report["candidate_terminal_states"]) == 2


def test_review_view_coalesces_88_equivalent_entry_occurrences() -> None:
    observations = [
        {
            "id": f"REVIEW_{index}",
            "candidate_uid": "CAND_SHARED",
            "validation_cluster_uid": "VAL_SHARED",
            "decision_evidence_hash": "DECISION",
            "occurrence_uid": f"OCC_{index}",
            "entry_identity": f"entry_{index}",
            "category": "bounds",
            "function": "sink",
            "location": "src/demo.c:42",
            "validation_status": "needs_review",
            "candidate_disposition": "needs_review",
            "description": "same structural obligation",
        }
        for index in range(88)
    ]

    with_review = build_report_views([], observations)["with_needs_review"]

    assert with_review["issue_count"] == 1
    assert with_review["included_needs_review_count"] == 1
    issue = with_review["issues"][0]
    assert issue["occurrence_count"] == 88
    assert issue["entry_count"] == 88
    assert len(issue["alias_occurrence_uids"]) == 87
    governance = with_review["needs_review_governance"]
    assert governance["raw_occurrence_count"] == 88
    assert governance["displayed_review_count"] == 1
    assert governance["grouped_alias_count"] == 87


def test_operational_obligations_do_not_become_security_review_findings() -> None:
    observations = [
        {
            "candidate_uid": "ENGINE_1",
            "operational_uid": "OP_1",
            "record_role": "operational_obligation",
            "candidate_disposition": "engine_failed",
            "engine": "svf",
            "reason": "timeout",
        }
    ]

    with_review = build_report_views([], observations)["with_needs_review"]

    assert with_review["issue_count"] == 0
    assert with_review["included_needs_review_count"] == 0
    assert with_review["needs_review_governance"]["operational_obligation_count"] == 1


def test_validator_v3_outcome_summary_reports_fact_success_and_transitions() -> None:
    summary = ParallelAnalyzer._validator_v3_outcome_summary(
        [
            {
                "validator_fact_resolutions": [
                    {
                        "fact_kind": "caller_contract",
                        "status": "completed_partial",
                        "terminal_status": "resolved",
                    }
                ],
                "validator_pass_history": [
                    {"pass": "initial", "verdict": "uncertain"},
                    {"pass": "evidence_recheck", "verdict": "verified"},
                ],
            },
            {
                "validator_fact_resolutions": [
                    {
                        "fact_kind": "value_range",
                        "status": "unsupported",
                        "terminal_status": "unsupported",
                    }
                ]
            },
        ]
    )

    assert summary["validator_fact_request_count"] == 2
    assert summary["validator_fact_resolution_success_count"] == 1
    assert summary["validator_fact_resolution_success_rate"] == 0.5
    assert summary["validator_fact_resolution_by_kind"] == {
        "caller_contract": {"resolved": 1},
        "value_range": {"unsupported": 1},
    }
    assert summary["validator_fact_terminal_status_counts"] == {
        "resolved": 1,
        "unsupported": 1,
    }
    assert summary["validator_verdict_transitions"] == {
        "initial:uncertain->evidence_recheck:verified": 1
    }
