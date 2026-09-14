"""Replay Range benchmark scoring with FP audit and optional semantic dedup."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from zscope.benchmarking.protocol import report_issues, score_report
from zscope.common.issue_identity import deduplicate_semantic_issues_programmatic

FalsePositiveClassifier = Callable[[Dict[str, Any]], Dict[str, Any]]


def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def report_for_view(issues: List[Dict[str, Any]], view: str) -> Dict[str, Any]:
    if view == "default":
        return {"issues": issues}
    return {"report_views": {view: {"issues": issues}}}


def load_range_fp_audit_classifier() -> Optional[FalsePositiveClassifier]:
    module_path = REPO_ROOT / "test" / "range" / "benchmark" / "fp_audit_rules.py"
    if not module_path.exists():
        return None
    spec = importlib.util.spec_from_file_location("zscope_range_fp_audit_rules", module_path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    classifier = getattr(module, "classify_range_false_positive_record", None)
    return classifier if callable(classifier) else None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--truth", required=True, type=Path)
    parser.add_argument("--view", default="default", choices=("default", "with_needs_review"))
    parser.add_argument("--line-tolerance", type=int, default=8)
    parser.add_argument("--semantic-dedup", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    report = load_json(args.report)
    truth = load_json(args.truth)
    issues = [deepcopy(issue) for issue in report_issues(report, args.view)]
    dedup_summary: Dict[str, Any] = {
        "enabled": False,
        "input_issue_count": len(issues),
        "output_issue_count": len(issues),
    }
    if args.semantic_dedup:
        issues, summary = deduplicate_semantic_issues_programmatic(issues)
        dedup_summary = {
            **summary,
            "enabled": True,
            "input_issue_count": dedup_summary["input_issue_count"],
            "output_issue_count": len(issues),
        }

    replay_report = report_for_view(issues, args.view)
    scored = score_report(
        replay_report,
        truth,
        view=args.view,
        line_tolerance=args.line_tolerance,
        fp_audit_classifier=load_range_fp_audit_classifier(),
    )
    result = {
        "view": args.view,
        "semantic_dedup_replay": dedup_summary,
        "metrics": {
            key: scored.get(key)
            for key in (
                "report_issue_count",
                "ground_truth_count",
                "true_positives",
                "false_positives",
                "false_positives_raw",
                "false_positives_effective",
                "duplicate_of_matched_count",
                "false_negatives",
                "precision",
                "false_positive_rate",
                "recall",
                "f1",
            )
        },
        "missed": scored.get("missed", []),
        "false_positive_audit": scored.get("false_positive_audit", {}),
    }
    if args.output:
        write_json(args.output, result)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
