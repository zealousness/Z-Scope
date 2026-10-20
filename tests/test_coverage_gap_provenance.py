"""Coverage reason provenance over controlled serialized report data.

These projection regressions do not claim native extraction or real-project
scan acceptance; the separate native owner/HTTP browser test covers that flow.
"""

import copy
import json

import pytest

from zscope.reporting.acceptance import acceptance_coverage
from zscope.reporting.report import FinalReport


def _report(analyzed=2):
    report = FinalReport(entry_function="main", overall_verdict="no_issue_found")
    report.metadata["entry_instances"] = {
        "schema": "zscope.entry-instances.v1",
        "planned_instances": 2,
        "scheduled_instances": 2,
        "scan_coverage_complete": False,
        "gaps": [],
        "instance_analysis": {
            "schema": "zscope.instance-analysis.v1",
            "analyzed_instances": analyzed,
            "instance_scope_complete": True,
            "consumer_scope_complete": False,
            "scan_coverage_complete": False,
            "blocked_consumers": ["get_callees"],
        },
    }
    return json.loads(json.dumps(report.to_dict()))


@pytest.mark.parametrize("analyzed", [0, 2])
def test_incomplete_coverage_does_not_invent_an_unwired_reason(analyzed):
    report = _report(analyzed)
    before = copy.deepcopy(report)
    coverage = acceptance_coverage(report)
    kinds = [gap["kind"] for gap in coverage["gaps"]]
    assert "entry_instance_coverage_incomplete" in kinds
    assert "entry_instance_analysis_unwired" not in kinds
    assert report == before
    assert report["metadata"]["entry_instances"]["scan_coverage_complete"] is False
    assert (
        report["metadata"]["entry_instances"]["instance_analysis"]["analyzed_instances"] == analyzed
    )


def test_explicit_unwired_and_other_producer_reasons_survive_once():
    report = _report()
    report["metadata"]["entry_instances"]["gaps"] = [
        {"reason": "entry_instance_analysis_unwired", "detail": "explicit producer gap"},
        {"reason": "link_targets_unverified", "detail": "link receipt absent"},
    ]
    before = copy.deepcopy(report)
    gaps = acceptance_coverage(report)["gaps"]
    unwired = [gap for gap in gaps if gap["kind"] == "entry_instance_analysis_unwired"]
    assert unwired == [
        {"kind": "entry_instance_analysis_unwired", "detail": "explicit producer gap"}
    ]
    assert {"kind": "link_targets_unverified", "detail": "link receipt absent"} in gaps
    assert report == before


@pytest.mark.parametrize("flag", [None, 0, "false", True])
def test_other_flags_do_not_infer_a_specific_missing_capability(flag):
    report = _report()
    report["metadata"]["entry_instances"]["scan_coverage_complete"] = flag
    before = copy.deepcopy(report)
    kinds = [gap["kind"] for gap in acceptance_coverage(report)["gaps"]]
    assert "entry_instance_analysis_unwired" not in kinds
    assert "entry_instance_coverage_incomplete" not in kinds
    assert report == before


def test_missing_instance_measurements_remain_unknown():
    report = _report()
    report["metadata"].pop("entry_instances")
    report.pop("completeness", None)
    coverage = acceptance_coverage(report)
    assert coverage["build_coverage"] is None
    assert coverage["completeness"] is None
    assert coverage["gaps"] == []


def test_instance_reason_keeps_independent_build_and_validation_gaps():
    report = _report()
    report["completeness"] = "partial"
    report["metadata"]["build_coverage"] = {
        "scan_complete": False,
        "reasons": ["incomplete_compilation_instances"],
        "failed_instances": ["build-a"],
    }
    report["needs_review_governance"] = {"pending_validation_count": 2}
    before = copy.deepcopy(report)
    coverage = acceptance_coverage(report)
    kinds = [gap["kind"] for gap in coverage["gaps"]]
    assert "entry_instance_coverage_incomplete" in kinds
    assert "entry_instance_analysis_unwired" not in kinds
    assert {"kind": "scan_completeness", "detail": "partial"} in coverage["gaps"]
    assert {"kind": "incomplete_compilation_instances", "detail": "count=1"} in coverage["gaps"]
    assert {"kind": "pending_validation", "detail": "count=2"} in coverage["gaps"]
    assert coverage["build_coverage"]["scan_complete"] is False
    assert report == before
