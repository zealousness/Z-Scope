from zscope.orchestration.parallel_analyzer import ParallelAnalysisResult, ParallelAnalyzer
from zscope.reporting.views import build_report_views, findings_for_view


def test_build_report_views_adds_only_needs_review_observations() -> None:
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
    assert views["with_needs_review"]["issue_count"] == 2
    assert views["with_needs_review"]["included_needs_review_count"] == 1
    assert all(
        issue["id"] != "UNCERTAIN_1"
        for issue in views["with_needs_review"]["issues"]
    )


def test_build_report_views_attaches_duplicate_needs_review_observations() -> None:
    issues = [
        {
            "id": "ISSUE_VALIDATED",
            "function": "td_init",
            "location": "src/main.c:187",
            "category": "memory_leak",
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


def test_build_report_views_treats_null_related_observations_as_empty() -> None:
    issues = [
        {
            "id": "ISSUE_VALIDATED",
            "function": "td_init",
            "location": "src/main.c:187",
            "category": "memory_leak",
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


def test_needs_review_numeric_category_variant_attaches_by_root() -> None:
    issues = [
        {
            "id": "CLANG_CFG_SIZE_LIMIT_MISMATCH",
            "function": "_issue41_label_cache_size_miscalc",
            "location": "src/lifecycle.c:1677",
            "category": "size_limit_mismatch",
            "validation_status": "validated",
            "description": "label cache size calculation uses the wrong limit.",
        }
    ]
    observations = [
        {
            "id": "ISSUE_INTEGER_OVERFLOW",
            "function": "_issue41_label_cache_size_miscalc",
            "location": "src/lifecycle.c:1677",
            "category": "integer_overflow",
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
