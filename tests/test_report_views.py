from types import SimpleNamespace

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
    assert {
        issue["id"]
        for issue in views["with_needs_review"]["issues"]
    } == {"ISSUE_1", "REVIEW_1", "UNCERTAIN_1"}


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
    assert with_review["issues"][0]["related_needs_review_observations"][0]["id"] == "ISSUE_INTEGER_OVERFLOW"


def test_parallel_combined_report_exposes_needs_review_view() -> None:
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

    report = analyzer.generate_combined_report(results)

    assert report["summary"]["total_issues"] == 1
    assert report["summary"]["total_issues_with_needs_review"] == 2
    assert report["metadata"]["audit_observation_count"] == 1
    assert len(findings_for_view(report, "default")) == 1
    assert len(findings_for_view(report, "with_needs_review")) == 2


def test_parallel_combined_report_records_llm_dedup_suggestion(monkeypatch) -> None:
    analyzer = object.__new__(ParallelAnalyzer)
    analyzer.max_workers = 12
    analyzer._semantic_dedup_llm_cache = {}
    analyzer.base_config = SimpleNamespace(
        reporting=SimpleNamespace(
            semantic_dedup=SimpleNamespace(
                enabled=True,
                llm_enabled=True,
                llm_confidence_threshold=0.85,
                max_cluster_size=8,
            )
        )
    )
    calls = []

    class FakeReconciler:
        def run(self, payload):
            calls.append(payload)
            primary_uid = payload["issues"][0]["id"]
            duplicate_uid = payload["issues"][1]["id"]
            return SimpleNamespace(
                success=True,
                data={
                    "duplicate_groups": [
                        {
                            "primary_issue_id": primary_uid,
                            "duplicate_issue_ids": [duplicate_uid],
                            "root_cause_key": "same_bounds_guard",
                            "confidence": 0.95,
                            "reasoning": "Both findings describe the same missing bounds guard.",
                        }
                    ],
                    "must_keep_distinct_issue_ids": [],
                },
            )

    monkeypatch.setattr(
        analyzer,
        "_make_issue_reconciler_agent",
        lambda: FakeReconciler(),
    )

    results = {
        "entry_a": ParallelAnalysisResult(
            function_name="entry_a",
            verdict="issues_found",
            issues=[
                {
                    "id": "ISSUE_A",
                    "function": "parse_packet",
                    "location": "src/demo.c:10",
                    "category": "bounds",
                    "description": "array access lacks a guard on the first branch.",
                    "validation_status": "validated",
                }
            ],
        ),
        "entry_b": ParallelAnalysisResult(
            function_name="entry_b",
            verdict="issues_found",
            issues=[
                {
                    "id": "ISSUE_B",
                    "function": "parse_packet",
                    "location": "src/demo.c:42",
                    "category": "bounds",
                    "description": "array access lacks a guard on the second branch.",
                    "validation_status": "validated",
                }
            ],
        ),
    }

    report = analyzer.generate_combined_report(results)

    semantic_summary = report["summary"]["semantic_dedup"]
    assert len(calls) == 1
    assert report["summary"]["total_issues"] == 2
    assert report["issues"][0]["id"] == "ISSUE_A"
    assert "duplicate_count" not in report["issues"][0]
    assert report["issues"][0]["dedup_cluster_suggestions"][0]["role"] == "primary"
    assert semantic_summary["llm_enabled"] is True
    assert semantic_summary["after_programmatic_issue_count"] == 2
    assert semantic_summary["llm_clusters_called"] == 1
    assert semantic_summary["llm_merge_count"] == 0
    assert semantic_summary["llm_suggestion_count"] == 1
    assert semantic_summary["output_issue_count"] == 2
    assert report["metadata"]["semantic_dedup_summary"] == semantic_summary


def test_parallel_combined_report_skips_llm_semantic_dedup_when_interrupted(monkeypatch) -> None:
    analyzer = object.__new__(ParallelAnalyzer)
    analyzer.max_workers = 12
    analyzer._interrupted = True
    analyzer._semantic_dedup_llm_cache = {}
    analyzer.base_config = SimpleNamespace(
        reporting=SimpleNamespace(
            semantic_dedup=SimpleNamespace(
                enabled=True,
                llm_enabled=True,
                llm_confidence_threshold=0.85,
                max_cluster_size=8,
            )
        )
    )
    calls = []

    class FakeReconciler:
        def run(self, payload):
            calls.append(payload)
            return SimpleNamespace(success=True, data={})

    monkeypatch.setattr(
        analyzer,
        "_make_issue_reconciler_agent",
        lambda: FakeReconciler(),
    )

    results = {
        "entry_a": ParallelAnalysisResult(
            function_name="entry_a",
            verdict="issues_found",
            issues=[
                {
                    "id": "ISSUE_A",
                    "function": "parse_packet",
                    "location": "src/demo.c:10",
                    "category": "bounds",
                    "description": "array access lacks a guard on the first branch.",
                    "validation_status": "validated",
                }
            ],
        ),
        "entry_b": ParallelAnalysisResult(
            function_name="entry_b",
            verdict="issues_found",
            issues=[
                {
                    "id": "ISSUE_B",
                    "function": "parse_packet",
                    "location": "src/demo.c:42",
                    "category": "bounds",
                    "description": "array access lacks a guard on the second branch.",
                    "validation_status": "validated",
                }
            ],
        ),
    }

    report = analyzer.generate_combined_report(results)

    semantic_summary = report["summary"]["semantic_dedup"]
    assert calls == []
    assert report["summary"]["interrupted"] is True
    assert report["summary"]["total_issues"] == 2
    assert semantic_summary["llm_configured"] is True
    assert semantic_summary["llm_enabled"] is False
    assert semantic_summary["llm_disabled_reason"] == "interrupted_fast_shutdown"
    assert semantic_summary["output_issue_count"] == 2


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
    assert (
        with_review["needs_review_governance"]["operational_obligation_count"]
        == 1
    )
