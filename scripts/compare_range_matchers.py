#!/usr/bin/env python3
"""Compare an archived matcher-v1 score with matcher v2 without scanning again.

Finding-root projection is completed from the frozen report before ground truth
is opened.  The legacy score is treated as an immutable historical artifact;
the command writes a separate matcher-v2 score and an explicit contract-change
audit rather than overwriting either input.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, Mapping

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from zscope.benchmarking.protocol import MATCHER_VERSION, SCHEMA_VERSION, score_report_views
from zscope.reporting.finding_roots import FINDING_ROOT_VERSION, project_finding_roots


COMPARISON_SCHEMA_VERSION = "zscope.range-matcher-comparison.v1"
LEGACY_MATCHER_VERSION = "zscope.truth-matcher.v1-legacy"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_object(path: Path) -> Dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object: {path}")
    return value


def _write_object(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(dict(value), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def project_archived_report(report: Mapping[str, Any]) -> tuple[Dict[str, Any], Dict[str, Any]]:
    """Apply finding-root v2 to one frozen report without reading truth."""

    views = report.get("report_views")
    views = views if isinstance(views, Mapping) else {}
    review_view = views.get("with_needs_review")
    review_view = review_view if isinstance(review_view, Mapping) else {}
    source = review_view.get("issues")
    if not isinstance(source, list):
        source = report.get("issues")
    if not isinstance(source, list):
        raise ValueError("report has no default or with-needs-review issue list")
    source_issues = [copy.deepcopy(item) for item in source if isinstance(item, Mapping)]
    projection = project_finding_roots(source_issues)
    display = [
        copy.deepcopy(item)
        for item in projection.outcomes
        if str(item.get("candidate_disposition") or "").lower() in {"confirmed", "needs_review"}
    ]
    confirmed = [
        item
        for item in display
        if str(item.get("candidate_disposition") or "").lower() == "confirmed"
    ]
    projected = copy.deepcopy(dict(report))
    projected["issues"] = copy.deepcopy(confirmed)
    projected_views = projected.setdefault("report_views", {})
    if not isinstance(projected_views, dict):
        projected_views = {}
        projected["report_views"] = projected_views
    projected_views["default"] = {
        **dict(projected_views.get("default") or {}),
        "issues": copy.deepcopy(confirmed),
        "issue_count": len(confirmed),
    }
    projected_views["with_needs_review"] = {
        **dict(projected_views.get("with_needs_review") or {}),
        "issues": copy.deepcopy(display),
        "issue_count": len(display),
    }
    manifest = projected.setdefault("run_manifest", {})
    if isinstance(manifest, dict):
        manifest["finding_root_count"] = projection.finding_root_count
        manifest["finding_root_alias_count"] = projection.finding_root_alias_count
        manifest["finding_root_projection"] = dict(projection.summary)
    return projected, dict(projection.summary)


def _legacy_views(score: Mapping[str, Any]) -> Dict[str, Mapping[str, Any]]:
    views = score.get("report_views")
    if isinstance(views, Mapping):
        default = views.get("default")
        review = views.get("with_needs_review")
        if isinstance(default, Mapping) and isinstance(review, Mapping):
            return {"default": default, "with_needs_review": review}
    if score.get("view") == "default":
        return {"default": score, "with_needs_review": {}}
    raise ValueError("legacy score has no auditable default/with-needs-review views")


def _view_delta(legacy: Mapping[str, Any], current: Mapping[str, Any]) -> Dict[str, Any]:
    legacy_ids = {str(value) for value in legacy.get("matched") or []}
    current_ids = {str(value) for value in current.get("matched") or []}
    return {
        "legacy": {
            key: legacy.get(key)
            for key in (
                "report_issue_count",
                "true_positives",
                "false_positives_raw",
                "duplicate_of_matched_count",
                "actionable_precision",
                "root_cause_precision",
                "recall",
            )
        },
        "matcher_v2": {
            key: current.get(key)
            for key in (
                "report_issue_count",
                "true_positives",
                "false_positives_raw",
                "same_product_root_count",
                "truth_covered_additional_count",
                "cross_anchor_overlap_count",
                "weak_legacy_overlap_count",
                "false_positives_effective",
                "actionable_precision",
                "root_cause_precision",
                "recall",
            )
        },
        "legacy_only_truth_ids": sorted(legacy_ids - current_ids),
        "matcher_v2_only_truth_ids": sorted(current_ids - legacy_ids),
        "shared_truth_ids": sorted(legacy_ids & current_ids),
    }


def _keyword_pair_audit(
    legacy: Mapping[str, Any], current: Mapping[str, Any]
) -> list[Dict[str, Any]]:
    current_by_truth = {
        str(pair.get("truth_id") or ""): pair
        for pair in current.get("matched_pairs") or []
        if isinstance(pair, Mapping)
    }
    records: list[Dict[str, Any]] = []
    for pair in legacy.get("matched_pairs") or []:
        if not isinstance(pair, Mapping):
            continue
        match = pair.get("match")
        match = match if isinstance(match, Mapping) else {}
        category = str(match.get("category") or "")
        if not category.startswith("keyword_hits:"):
            continue
        truth_id = str(pair.get("truth_id") or "")
        current_pair = current_by_truth.get(truth_id)
        records.append(
            {
                "truth_id": truth_id,
                "legacy_issue_index": pair.get("issue_index"),
                "legacy_issue_identity": pair.get("issue_identity"),
                "legacy_category_reason": category,
                "matcher_v2_matched": current_pair is not None,
                "matcher_v2_issue_index": (
                    current_pair.get("issue_index") if current_pair else None
                ),
                "matcher_v2_pair_strength": (
                    dict(current_pair.get("match") or {}).get("pair_strength")
                    if current_pair
                    else None
                ),
            }
        )
    return records


def _legacy_pair_audit(
    legacy: Mapping[str, Any], current: Mapping[str, Any]
) -> list[Dict[str, Any]]:
    identity_to_index = {
        str(record.get("identity") or ""): index
        for index, record in enumerate(current.get("issue_identity_records") or [])
        if isinstance(record, Mapping) and record.get("identity")
    }
    matched_by_truth = {
        str(pair.get("truth_id") or ""): pair
        for pair in current.get("matched_pairs") or []
        if isinstance(pair, Mapping)
    }
    matched_by_issue = {
        int(pair.get("issue_index") or 0): pair
        for pair in current.get("matched_pairs") or []
        if isinstance(pair, Mapping)
    }
    unmatched_by_issue = {
        int(record.get("issue_index") or 0): record
        for record in current.get("unmatched_issue_classifications") or []
        if isinstance(record, Mapping)
    }
    records: list[Dict[str, Any]] = []
    for pair in legacy.get("matched_pairs") or []:
        if not isinstance(pair, Mapping):
            continue
        truth_id = str(pair.get("truth_id") or "")
        identity = str(pair.get("issue_identity") or "")
        current_index = identity_to_index.get(identity)
        current_truth_pair = matched_by_truth.get(truth_id)
        current_issue_pair = (
            matched_by_issue.get(current_index) if current_index is not None else None
        )
        classification = (
            unmatched_by_issue.get(current_index) if current_index is not None else None
        )
        if current_truth_pair is not None:
            disposition = "truth_still_matched_by_strong_pair"
        elif current_index is None:
            disposition = "issue_removed_by_finding_root_projection"
        elif current_issue_pair is not None:
            disposition = "issue_strongly_matched_to_different_truth"
        elif classification is not None:
            disposition = str(classification.get("classification") or "false_positive")
        else:
            disposition = "no_match"
        legacy_match = pair.get("match")
        records.append(
            {
                "truth_id": truth_id,
                "legacy_issue_index": pair.get("issue_index"),
                "legacy_issue_identity": identity,
                "legacy_match": dict(legacy_match or {}),
                "matcher_v2_disposition": disposition,
                "matcher_v2_issue_index": current_index,
                "matcher_v2_truth_issue_index": (
                    current_truth_pair.get("issue_index") if current_truth_pair else None
                ),
                "matcher_v2_issue_truth_id": (
                    current_issue_pair.get("truth_id") if current_issue_pair else None
                ),
                "matcher_v2_unmatched_classification": (
                    dict(classification) if classification is not None else None
                ),
            }
        )
    return records


def compare_artifacts(
    *,
    report_path: Path,
    truth_path: Path,
    legacy_score_path: Path,
) -> tuple[Dict[str, Any], Dict[str, Any]]:
    report = _load_object(report_path)
    projected_report, projection_summary = project_archived_report(report)

    # Truth and the historical truth-bearing score are opened only after the
    # answer-free finding-root projection has been frozen in memory.
    truth = _load_object(truth_path)
    legacy_score = _load_object(legacy_score_path)
    legacy_contract = legacy_score.get("scoring_contract")
    legacy_contract = legacy_contract if isinstance(legacy_contract, Mapping) else {}
    observed_legacy_matcher = str(legacy_contract.get("matcher_version") or "")
    if observed_legacy_matcher == MATCHER_VERSION:
        raise ValueError("legacy score already uses matcher v2")
    legacy_views = _legacy_views(legacy_score)
    v2_views = score_report_views(projected_report, truth)
    score_artifact = {
        "schema_version": SCHEMA_VERSION,
        "matcher_version": MATCHER_VERSION,
        "release_eligible": False,
        "comparison_only": True,
        "finding_root_projection": projection_summary,
        "report_views": v2_views,
        "input_sha256": {
            "report": _sha256(report_path),
            "truth": _sha256(truth_path),
        },
    }
    comparison = {
        "schema_version": COMPARISON_SCHEMA_VERSION,
        "release_eligible": False,
        "comparison_only": True,
        "reason": "scorer_contract_change_not_product_recall_regression",
        "contracts": {
            "legacy_matcher": observed_legacy_matcher or LEGACY_MATCHER_VERSION,
            "current_matcher": MATCHER_VERSION,
            "finding_root_projection": FINDING_ROOT_VERSION,
        },
        "input_sha256": {
            "report": _sha256(report_path),
            "truth": _sha256(truth_path),
            "legacy_score": _sha256(legacy_score_path),
        },
        "finding_root_projection": projection_summary,
        "views": {
            view: _view_delta(legacy_views[view], v2_views[view])
            for view in ("default", "with_needs_review")
        },
        "keyword_only_legacy_tp_audit": {
            view: _keyword_pair_audit(legacy_views[view], v2_views[view])
            for view in ("default", "with_needs_review")
        },
        "legacy_matched_pair_audit": {
            view: _legacy_pair_audit(legacy_views[view], v2_views[view])
            for view in ("default", "with_needs_review")
        },
    }
    return score_artifact, comparison


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--truth", required=True, type=Path)
    parser.add_argument("--legacy-score", required=True, type=Path)
    parser.add_argument("--v2-score-output", required=True, type=Path)
    parser.add_argument("--comparison-output", required=True, type=Path)
    parser.add_argument("--expect-default-issues", type=int)
    parser.add_argument("--expect-with-review-issues", type=int)
    parser.add_argument("--expect-aliases", type=int)
    args = parser.parse_args()

    try:
        score, comparison = compare_artifacts(
            report_path=args.report,
            truth_path=args.truth,
            legacy_score_path=args.legacy_score,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"matcher comparison refused: {exc}") from exc

    projection = comparison["finding_root_projection"]
    actual_default = score["report_views"]["default"]["report_issue_count"]
    actual_review = score["report_views"]["with_needs_review"]["report_issue_count"]
    expectations = (
        ("default issues", args.expect_default_issues, actual_default),
        ("with-needs-review issues", args.expect_with_review_issues, actual_review),
        ("finding-root aliases", args.expect_aliases, projection["finding_root_alias_count"]),
    )
    for label, expected, actual in expectations:
        if expected is not None and expected != actual:
            raise SystemExit(f"{label} mismatch: expected {expected}, observed {actual}")

    _write_object(args.v2_score_output, score)
    _write_object(args.comparison_output, comparison)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
