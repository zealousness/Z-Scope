from __future__ import annotations

import json
from pathlib import Path

import pytest

from zscope.benchmarking.protocol import score_report
from zscope.common.defect_cwe_map import (
    DEFECT_CLASS_CWES,
    cwes_for_category,
    ensure_issue_cwes,
    cwe_tokens,
    merge_cwes,
)
from zscope.reporting.issue_aggregation import (
    ISSUE_AGGREGATION_VERSION,
    SINK_LINE_TOLERANCE,
    project_issue_aggregation,
)
from zscope.reporting.sarif_exporter import report_to_sarif
from zscope.rules.catalog import RuleCatalog

ROOT = Path(__file__).resolve().parents[1]
RANGE_TRUTH_PATH = ROOT / "test" / "range" / "benchmark" / "ground_truth.json"


SKILL_LANGUAGES = {
    "bounds_and_integer": ("c_cpp",),
    "code_semantic_modeling": ("c_cpp", "java"),
    "concurrency_lock_order": ("c_cpp",),
    "evidence_validation": ("c_cpp", "java"),
    "java_authz": ("java",),
    "java_concurrency": ("java",),
    "java_crypto": ("java",),
    "java_deserialization": ("java",),
    "java_injection": ("java",),
    "java_resource_lifecycle": ("java",),
    "java_web_security": ("java",),
    "null_and_failure": ("c_cpp",),
    "ownership_contract": ("c_cpp",),
    "resource_lifecycle": ("c_cpp",),
    "shared_state_race": ("c_cpp",),
    "snapshot_refresh_decision": ("c_cpp", "java"),
    "stack_escape": ("c_cpp",),
    "string_and_format": ("c_cpp",),
    "temporal_memory": ("c_cpp",),
}


def test_every_builtin_defect_class_maps_to_at_least_one_cwe() -> None:
    catalog = RuleCatalog.builtin(skill_languages=SKILL_LANGUAGES)
    uncovered = sorted({descriptor.defect_class for descriptor in catalog} - set(DEFECT_CLASS_CWES))
    assert uncovered == []
    for defect_class, cwes in DEFECT_CLASS_CWES.items():
        assert cwes, defect_class
        for cwe in cwes:
            assert cwe.startswith("CWE-") and cwe[4:].isdigit(), (defect_class, cwe)


def test_every_range_truth_category_maps_to_at_least_one_cwe() -> None:
    if not RANGE_TRUTH_PATH.is_file():
        pytest.skip("test/range benchmark fixtures are not available in this checkout")
    truth = json.loads(RANGE_TRUTH_PATH.read_text(encoding="utf-8"))
    uncovered = sorted(
        {vulnerability["category"] for vulnerability in truth["vulnerabilities"]}
        - set(DEFECT_CLASS_CWES)
    )
    assert uncovered == []


def test_cwe_tokens_parses_scalar_list_and_compound_text() -> None:
    assert cwe_tokens("CWE-401") == ["CWE-401"]
    assert cwe_tokens(["CWE-401", "CWE-772"]) == ["CWE-401", "CWE-772"]
    assert cwe_tokens("CWE-362/CWE-416") == ["CWE-362", "CWE-416"]
    assert cwe_tokens("maybe cwe_78 appears here") == ["CWE-78"]
    assert merge_cwes(["CWE-401"], ["CWE-772", "CWE-401"]) == ["CWE-401", "CWE-772"]


def test_ensure_issue_cwes_unions_primary_labels_and_category_map() -> None:
    issue = {"cwe": "CWE-772", "cwes": ["CWE-772", "CWE-125"], "category": "memory_leak"}
    ensure_issue_cwes(issue)
    assert issue["cwes"][0] == "CWE-772"
    assert set(issue["cwes"]) == {"CWE-772", "CWE-125", "CWE-401"}
    assert issue["cwe"] == "CWE-772"


def test_ensure_issue_cwes_backfills_primary_from_category() -> None:
    issue = {"defect_class": "use_after_free"}
    ensure_issue_cwes(issue)
    assert issue["cwe"] == "CWE-416"
    assert issue["cwes"] == ["CWE-416"]


def test_ensure_issue_cwes_keeps_unknown_categories_untouched() -> None:
    issue = {"category": "totally_unknown_class"}
    assert ensure_issue_cwes(issue) == []
    assert "cwes" not in issue


def test_uninitialized_pointer_rule_declares_variable_and_pointer_cwes() -> None:
    descriptor = RuleCatalog.builtin(skill_languages=SKILL_LANGUAGES).get(
        "clang_cfg_pointer_may_be_uninitialized_before_use"
    )

    assert descriptor is not None
    assert descriptor.revision == 7
    assert descriptor.cwes == ("CWE-824", "CWE-457")


def test_uninitialized_pointer_manifestation_matches_compound_truth_cwe() -> None:
    truth = {
        "benchmark": "unit",
        "vulnerabilities": [
            {
                "id": "T-UNINIT",
                "cwe": "CWE-401/CWE-457",
                "category": "partial_resource_leak",
                "file": "src/lifecycle.c",
                "function": "prepare_retry",
                "line": 40,
                "end_line": 55,
            }
        ],
    }
    report = {
        "issues": [
            {
                "candidate_uid": "C-UNINIT",
                "candidate_disposition": "confirmed",
                "category": "uninitialized_pointer",
                "defect_class": "uninitialized_pointer",
                "cwe": "CWE-824",
                "cwes": ["CWE-824", "CWE-457"],
                "file": "src/lifecycle.c",
                "function": "prepare_retry",
                "line": 47,
                "evidence_pack": {
                    "sink": {
                        "file": "src/lifecycle.c",
                        "function": "prepare_retry",
                        "line": 47,
                        "operation": "return tag[0]",
                    }
                },
            }
        ]
    }

    score = score_report(report, truth)

    assert score["true_positives"] == 1
    assert score["false_positives"] == 0


def _sink(file: str, line: int, operation: str = "memcpy") -> dict:
    return {"file": file, "line": line, "operation": operation}


def _outcome(
    uid: str,
    *,
    disposition: str = "confirmed",
    defect_class: str = "buffer_overflow",
    file_path: str = "src/a.c",
    function: str = "parse",
    sink: dict | None = None,
    cwe: str | None = "CWE-787",
    severity: str = "high",
) -> dict:
    issue: dict = {
        "candidate_uid": uid,
        "candidate_disposition": disposition,
        "defect_class": defect_class,
        "category": defect_class,
        "subcategory": defect_class,
        "file_path": file_path,
        "function": function,
        "cwe": cwe,
        "impact_level": severity,
        "occurrence_uid": f"occ-{uid}",
        "evidence_pack": {"sink": sink if sink is not None else _sink(file_path, 100)},
    }
    return issue


def test_same_site_outcomes_aggregate_with_cwe_and_category_union() -> None:
    items = [
        _outcome("C1", severity="high"),
        _outcome("C2", defect_class="bounds", cwe="CWE-125", severity="critical"),
    ]

    projection = project_issue_aggregation(items)

    assert projection.aggregation_count == 1
    assert projection.aggregation_alias_count == 1
    primary = next(item for item in projection.items if item["candidate_uid"] == "C2")
    alias = next(item for item in projection.items if item["candidate_uid"] == "C1")
    assert primary["candidate_disposition"] == "confirmed"
    assert primary["cwe"] == "CWE-125"
    assert primary["cwes"] == ["CWE-125", "CWE-787"]
    assert primary["categories"] == ["bounds", "buffer_overflow"]
    assert primary["aggregation_version"] == ISSUE_AGGREGATION_VERSION
    assert primary["aggregation_alias_count"] == 1
    assert primary["occurrence_count"] == 2
    assert primary["evidence_pack"]["cwes"] == primary["cwes"]
    assert alias["candidate_disposition"] == "deduplicated_alias"
    assert alias["aggregation_uid"] == primary["aggregation_uid"]
    assert alias["aggregation_primary_candidate_uid"] == "C2"


def test_same_site_confirmed_outcome_remains_primary_over_review_observation() -> None:
    confirmed = _outcome("CONFIRMED", severity="medium")
    review = _outcome("REVIEW", disposition="needs_review", severity="critical")

    projection = project_issue_aggregation([review, confirmed])
    by_uid = {item["candidate_uid"]: item for item in projection.items}

    assert by_uid["CONFIRMED"]["candidate_disposition"] == "confirmed"
    assert by_uid["REVIEW"]["candidate_disposition"] == "deduplicated_alias"
    assert by_uid["REVIEW"]["aggregation_primary_candidate_uid"] == "CONFIRMED"


def test_aggregation_respects_sink_line_tolerance_and_function_boundary() -> None:
    far_line = 100 + SINK_LINE_TOLERANCE + 1
    items = [
        _outcome("C1"),
        # Same bucket, but far beyond the line tolerance: not aggregated.
        _outcome("C2", sink=_sink("src/a.c", far_line)),
        # Same site, different function: not aggregated.
        _outcome("C3", function="other"),
    ]

    projection = project_issue_aggregation(items)

    assert projection.aggregation_alias_count == 0
    assert projection.aggregation_count == 3


def test_aggregation_passes_through_items_without_sink_anchor() -> None:
    items = [_outcome("C1"), {**_outcome("C2"), "evidence_pack": {}}]

    projection = project_issue_aggregation(items)

    assert projection.aggregation_alias_count == 0
    assert projection.aggregation_count == 2


def test_aggregation_only_folds_display_dispositions() -> None:
    items = [_outcome("C1"), _outcome("C2", disposition="rejected")]

    projection = project_issue_aggregation(items)

    assert projection.aggregation_alias_count == 0
    assert projection.aggregation_count == 1


def test_single_issue_can_match_multiple_truths_via_cwe_union() -> None:
    truth = {
        "benchmark": "unit",
        "vulnerabilities": [
            {
                "id": "T1",
                "cwe": "CWE-190",
                "category": "integer_overflow",
                "file": "src/a.c",
                "function": "parse",
                "line": 100,
                "end_line": 105,
            },
            {
                "id": "T2",
                "cwe": "CWE-193",
                "category": "off_by_one",
                "file": "src/a.c",
                "function": "parse",
                "line": 100,
                "end_line": 105,
            },
        ],
    }
    report = {
        "issues": [
            {
                "function": "parse",
                "location": "src/a.c:102",
                "category": "size_limit_mismatch",
                "cwes": ["CWE-190", "CWE-193"],
                "description": "size computation can overflow",
            }
        ]
    }

    result = score_report(report, truth, line_tolerance=5)

    assert result["true_positives"] == 2
    assert result["false_negatives"] == 0
    assert result["matched"] == ["T1", "T2"]
    assert {pair["issue_index"] for pair in result["matched_pairs"]} == {0}
    assert result["false_positives"] == 0


def test_multi_category_labels_join_the_category_gate() -> None:
    truth = {
        "benchmark": "unit",
        "vulnerabilities": [
            {
                "id": "T1",
                "cwe": "CWE-190",
                "category": "integer_overflow",
                "file": "src/a.c",
                "function": "parse",
                "line": 100,
                "end_line": 105,
            }
        ],
    }
    report = {
        "issues": [
            {
                "function": "parse",
                "location": "src/a.c:102",
                "category": "size_limit_mismatch",
                "categories": ["size_limit_mismatch", "integer_overflow"],
                "description": "size computation can overflow",
            }
        ]
    }

    result = score_report(report, truth, line_tolerance=5)

    assert result["true_positives"] == 1
    match = result["matched_pairs"][0]["match"]
    assert match["category"] == "category_exact:integer_overflow"


def test_aggregation_uid_duplicate_is_exempted_from_effective_fp() -> None:
    truth = {
        "benchmark": "unit",
        "vulnerabilities": [
            {
                "id": "T1",
                "cwe": "CWE-787",
                "category": "buffer_overflow",
                "file": "src/a.c",
                "function": "parse",
                "line": 100,
                "end_line": 105,
            }
        ],
    }
    primary = _outcome("C1")
    alias = _outcome("C2", defect_class="bounds", cwe="CWE-125")
    projection = project_issue_aggregation([primary, alias])
    visible = [
        item for item in projection.items if item["candidate_disposition"] != "deduplicated_alias"
    ]

    result = score_report({"issues": visible}, truth, line_tolerance=5)

    assert result["true_positives"] == 1
    assert result["same_product_root_count"] == 0
    assert result["false_positives"] == 0


def test_same_site_alias_keeps_duplicate_exemption_when_unmatched() -> None:
    # The alias itself stays visible in the scored view (e.g. with_needs_review
    # scoring over raw outcomes); it must be exempted via aggregation_uid.
    truth = {
        "benchmark": "unit",
        "vulnerabilities": [
            {
                "id": "T1",
                "cwe": "CWE-787",
                "category": "buffer_overflow",
                "file": "src/a.c",
                "function": "parse",
                "line": 100,
                "end_line": 105,
            }
        ],
    }
    primary = _outcome("C1")
    alias = _outcome("C2", defect_class="bounds", cwe="CWE-125")
    projection = project_issue_aggregation([primary, alias])
    # Both records are scored; alias retains deduplicated_alias disposition but
    # matching runs over every provided issue record.
    issues = [item for item in projection.items if item["candidate_uid"] in {"C1", "C2"}]

    result = score_report({"issues": issues}, truth, line_tolerance=5)

    assert result["true_positives"] == 1
    assert result["same_product_root_count"] == 1
    assert result["false_positives"] == 0


def test_category_and_cwe_gate_still_rejects_disjoint_labels() -> None:
    truth = {
        "benchmark": "unit",
        "vulnerabilities": [
            {
                "id": "T1",
                "cwe": "CWE-193",
                "category": "off_by_one",
                "file": "src/a.c",
                "function": "parse",
                "line": 100,
                "end_line": 105,
            }
        ],
    }
    report = {
        "issues": [
            {
                "function": "parse",
                "location": "src/a.c:102",
                "category": "memory_leak",
                "cwes": ["CWE-401", "CWE-772"],
                "description": "unrelated classification at the same site",
            }
        ]
    }

    result = score_report(report, truth, line_tolerance=5)

    assert result["true_positives"] == 0
    assert result["false_negatives"] == 1


def test_sarif_exports_full_cwe_set() -> None:
    report = {
        "issues": [
            {
                "id": "I1",
                "function": "parse",
                "location": "src/a.c:102",
                "category": "buffer_overflow",
                "defect_class": "buffer_overflow",
                "cwe": "CWE-787",
                "cwes": ["CWE-787", "CWE-120"],
                "description": "overflow",
                "rule_id": "some_rule",
            }
        ]
    }

    sarif = report_to_sarif(report)
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]

    assert rule["properties"]["cwe"] == "CWE-787"
    assert rule["properties"]["cwes"] == ["CWE-787", "CWE-120"]
    assert "CWE-787" in rule["properties"]["tags"]
    assert "CWE-120" in rule["properties"]["tags"]
