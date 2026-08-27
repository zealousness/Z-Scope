#!/usr/bin/env python3
"""Score the answer-free LLM Wiki demo after two scans have completed.

This module deliberately performs no scan and never imports or starts a Z-Scope
runtime.  It only reads two finished report JSON documents and the protected
demo truth file, then writes a digest-bound comparison artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from zscope.benchmarking.protocol import issue_identity, report_issues, score_report  # noqa: E402


SCHEMA_VERSION = "zscope.llm-wiki-demo-metrics.v1"


def _load_object(path: Path) -> Dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected a JSON object: {path}")
    return payload


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _disposition(issue: Mapping[str, Any]) -> str:
    value = str(issue.get("candidate_disposition") or issue.get("disposition") or "").lower()
    if value in {"confirmed", "validated", "verified"}:
        return "confirmed"
    if value in {"needs_review", "uncertain", "unvalidated", "pending"}:
        return "needs_review"
    validation = str(issue.get("validation_status") or "").lower()
    if validation in {"validated", "confirmed", "verified"}:
        return "confirmed"
    if validation in {"needs_review", "uncertain", "unvalidated", "pending"}:
        return "needs_review"
    return value or "unknown"


def _iter_distinct_issues(report: Mapping[str, Any]) -> Iterable[Dict[str, Any]]:
    seen: set[str] = set()
    for view in ("default", "with_needs_review"):
        for issue in report_issues(dict(report), view=view):
            identity = issue_identity(issue)
            if identity in seen:
                continue
            seen.add(identity)
            yield issue


def _target_dispositions(report: Mapping[str, Any], target: Mapping[str, Any]) -> List[str]:
    expected_file = str(target.get("file") or "").replace("\\", "/")
    expected_function = str(target.get("function") or target.get("function_name") or "")
    observed: set[str] = set()
    for issue in _iter_distinct_issues(report):
        issue_file = str(
            issue.get("file")
            or issue.get("file_path")
            or issue.get("source_file")
            or ""
        ).replace("\\", "/")
        issue_function = str(
            issue.get("function") or issue.get("function_name") or issue.get("func_name") or ""
        )
        file_matches = issue_file == expected_file or issue_file.endswith("/" + expected_file)
        if file_matches and issue_function == expected_function:
            observed.add(_disposition(issue))
    return sorted(observed)


def _view_metrics(report: Mapping[str, Any], truth: Mapping[str, Any], view: str) -> Dict[str, Any]:
    scored = score_report(
        dict(report),
        dict(truth),
        view=view,
        line_tolerance=int(
            (truth.get("matching") or {}).get("line_tolerance", 8)
            if isinstance(truth.get("matching"), dict)
            else 8
        ),
    )
    # Keep the demo artifact compact while retaining enough detail for a human
    # to audit every TP/FP/FN decision.
    return {
        "reported": scored["report_issue_count"],
        "true_positives": scored["true_positives"],
        "false_positives": scored["false_positives"],
        "false_negatives": scored["false_negatives"],
        "precision": scored["precision"],
        "recall": scored["recall"],
        "matched": scored["matched"],
        "missed": scored["missed"],
        "matched_pairs": scored["matched_pairs"],
        "false_positive_issue_identities": scored["false_positive_issue_identities"],
    }


def score_demo_reports(
    off_report: Mapping[str, Any],
    active_report: Mapping[str, Any],
    truth: Mapping[str, Any],
    *,
    off_report_sha256: Optional[str] = None,
    active_report_sha256: Optional[str] = None,
    truth_sha256: Optional[str] = None,
) -> Dict[str, Any]:
    """Return the digest-bound, two-mode/two-view demo score."""

    target = truth.get("transition_target")
    if not isinstance(target, dict):
        raise ValueError("truth.transition_target must be an object")

    expected_off = str(target.get("off_disposition") or "confirmed")
    expected_active = str(target.get("active_disposition") or "needs_review")
    off_observed = _target_dispositions(off_report, target)
    active_observed = _target_dispositions(active_report, target)

    return {
        "schema_version": SCHEMA_VERSION,
        "benchmark": truth.get("benchmark", "zscope-llm-wiki-demo"),
        "suite": truth.get("suite", "llm_wiki_demo"),
        "valid": True,
        "truth_sha256": truth_sha256,
        "report_sha256": {"off": off_report_sha256, "active": active_report_sha256},
        "views": {
            "off": {
                "confirmed": _view_metrics(off_report, truth, "default"),
                "with_needs_review": _view_metrics(off_report, truth, "with_needs_review"),
            },
            "active": {
                "confirmed": _view_metrics(active_report, truth, "default"),
                "with_needs_review": _view_metrics(
                    active_report, truth, "with_needs_review"
                ),
            },
        },
        "transition_check": {
            "target": {
                "file": target.get("file"),
                "function": target.get("function") or target.get("function_name"),
            },
            "expected": {"off": expected_off, "active": expected_active},
            "observed": {"off": off_observed, "active": active_observed},
            "passed": expected_off in off_observed and expected_active in active_observed,
        },
        "metric_definition": {
            "precision": "true_positives / (true_positives + false_positives)",
            "recall": "true_positives / (true_positives + false_negatives)",
            "confirmed_view": "report default view only",
            "with_needs_review_view": "confirmed plus needs_review observations",
        },
    }


def score_demo_files(off_report_path: Path, active_report_path: Path, truth_path: Path) -> Dict[str, Any]:
    off_report_path = Path(off_report_path)
    active_report_path = Path(active_report_path)
    truth_path = Path(truth_path)
    return score_demo_reports(
        _load_object(off_report_path),
        _load_object(active_report_path),
        _load_object(truth_path),
        off_report_sha256=_sha256_file(off_report_path),
        active_report_sha256=_sha256_file(active_report_path),
        truth_sha256=_sha256_file(truth_path),
    )


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--off-report", required=True, type=Path)
    parser.add_argument("--active-report", required=True, type=Path)
    parser.add_argument(
        "--truth",
        type=Path,
        default=ROOT / "test" / "llm_wiki_demo" / "benchmark" / "ground_truth.json",
    )
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    metrics = score_demo_files(args.off_report, args.active_report, args.truth)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(metrics, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
