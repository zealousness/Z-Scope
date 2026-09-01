from __future__ import annotations

import json
from pathlib import Path

from scripts.compare_range_matchers import compare_artifacts
from zscope.benchmarking.protocol import MATCHER_VERSION, issue_identity
from zscope.reporting.finding_roots import FINDING_ROOT_VERSION


def _write(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


def _finding(uid: str) -> dict:
    return {
        "candidate_uid": "CAND_shared",
        "validation_cluster_uid": f"VAL_{uid}",
        "occurrence_uid": f"OCC_{uid}",
        "candidate_disposition": "confirmed",
        "category": "bounds",
        "defect_class": "bounds",
        "file_path": "src/state.c",
        "function": "advance_state",
        "location": "src/state.c:50",
        "obligation_shape": "sink_sensitive",
        "security_obligation": {
            "defect_family": "bounds",
            "obligation_shape": "sink_sensitive",
            "subject_uid": "state.index",
            "decision_region_uid": "REGION_transition",
        },
        "decision_proof": {
            "outcome": "confirm",
            "completeness": "complete",
            "producer_engine": "cfg",
            "fact_ids": [f"fact:{uid}"],
            "subject_identity": "state.index",
        },
        "description": "A bounds transition can corrupt state.",
    }


def test_archived_matcher_comparison_never_infers_alias_without_v4_proof_root(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    truth_path = tmp_path / "truth.json"
    legacy_path = tmp_path / "legacy-score.json"
    issues = [_finding("a"), _finding("b")]
    _write(
        report_path,
        {
            "issues": issues,
            "report_views": {
                "default": {"issues": issues},
                "with_needs_review": {"issues": issues},
            },
        },
    )
    _write(
        truth_path,
        {
            "benchmark": "unit",
            "vulnerabilities": [
                {
                    "id": "STATE-1",
                    "category": "state_machine_violation",
                    "function": "advance_state",
                    "file": "src/state.c",
                    "line": 50,
                    "keywords": ["bounds", "transition", "state"],
                }
            ],
        },
    )
    legacy_view = {
        "report_issue_count": 2,
        "true_positives": 1,
        "matched": ["STATE-1"],
        "matched_pairs": [
            {
                "truth_id": "STATE-1",
                "issue_index": 0,
                "issue_identity": issue_identity(_finding("a")),
                "match": {"category": "keyword_hits:3"},
            }
        ],
    }
    _write(
        legacy_path,
        {
            "schema_version": "zscope.benchmark.v4",
            "scoring_contract": {},
            "report_views": {
                "default": legacy_view,
                "with_needs_review": legacy_view,
            },
        },
    )
    before = report_path.read_bytes()

    score, comparison = compare_artifacts(
        report_path=report_path,
        truth_path=truth_path,
        legacy_score_path=legacy_path,
    )

    assert report_path.read_bytes() == before
    assert score["matcher_version"] == MATCHER_VERSION
    assert score["finding_root_projection"]["schema_version"] == FINDING_ROOT_VERSION
    assert score["finding_root_projection"]["finding_root_alias_count"] == 0
    assert score["report_views"]["default"]["report_issue_count"] == 2
    assert score["report_views"]["default"]["true_positives"] == 0
    assert comparison["release_eligible"] is False
    assert comparison["views"]["default"]["legacy_only_truth_ids"] == ["STATE-1"]
    audit = comparison["keyword_only_legacy_tp_audit"]["default"]
    assert len(audit) == 1
    assert audit[0]["matcher_v2_matched"] is False
    pair_audit = comparison["legacy_matched_pair_audit"]["default"]
    assert pair_audit[0]["matcher_v2_disposition"] == "weak_legacy_overlap"
