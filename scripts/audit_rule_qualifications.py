#!/usr/bin/env python3
"""Audit rule activation and qualification without changing the catalog."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from zscope.benchmarking.protocol import finding_attribution, report_issues, score_report_views
from zscope.rules.catalog import RuleCatalog
from zscope.rules.qualification import QualificationRegistry, qualification_rows

_BENCHMARK_VIEWS = ("default", "with_needs_review")


def _load_json_object(path: Path, *, label: str) -> Dict[str, Any]:
    resolved = path.expanduser().resolve()
    try:
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load {label} JSON {resolved}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} JSON must contain an object: {resolved}")
    return value


def _rule_id_values(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        normalized = value.strip()
        if normalized:
            yield normalized
        return
    if isinstance(value, Mapping):
        for key in ("rule_id", "rule", "id"):
            yield from _rule_id_values(value.get(key))
        return
    if isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            yield from _rule_id_values(item)


def _mapping_values(value: Any) -> Iterable[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        yield value
    elif isinstance(value, (list, tuple)):
        for item in value:
            if isinstance(item, Mapping):
                yield item


def _issue_rule_ids(issue: Mapping[str, Any]) -> set[str]:
    """Read detector IDs from the three supported candidate payload layers."""

    containers: list[Mapping[str, Any]] = [issue]
    evidence_packs = list(_mapping_values(issue.get("evidence_pack")))
    containers.extend(evidence_packs)
    containers.extend(_mapping_values(issue.get("candidate_payload")))
    for evidence_pack in evidence_packs:
        containers.extend(_mapping_values(evidence_pack.get("candidate_payload")))

    values: set[str] = set()
    for container in containers:
        for key in ("rule_id", "rule"):
            values.update(_rule_id_values(container.get(key)))
    return values


def benchmark_tp_rule_participation(
    report: Dict[str, Any],
    truth: Dict[str, Any],
    *,
    catalog: RuleCatalog,
    registry: QualificationRegistry,
    view: str = "default",
) -> Dict[str, Any]:
    """Summarize catalog rules participating in benchmark true positives.

    Scoring remains owned by ``score_report_views``.  This post-scan audit only
    joins its matched issue indices back to the selected report view.
    """

    if view not in _BENCHMARK_VIEWS:
        raise ValueError(f"view must be one of: {', '.join(_BENCHMARK_VIEWS)}")
    scores = score_report_views(report, truth)
    selected_score = scores[view]
    issues = report_issues(report, view=view)
    matched_indices = {
        int(value)
        for value in selected_score.get("matched_issue_indices") or []
        if isinstance(value, int) and not isinstance(value, bool)
    }
    truth_ids_by_issue: Dict[int, set[str]] = {}
    for pair in selected_score.get("matched_pairs") or []:
        if not isinstance(pair, Mapping):
            continue
        issue_index = pair.get("issue_index")
        truth_id = str(pair.get("truth_id") or "").strip()
        if (
            isinstance(issue_index, int)
            and not isinstance(issue_index, bool)
            and issue_index in matched_indices
            and truth_id
        ):
            truth_ids_by_issue.setdefault(issue_index, set()).add(truth_id)

    known: Dict[str, Dict[str, Any]] = {}
    unknown: Dict[str, Dict[str, Any]] = {}
    missing_rule_truth_ids: set[str] = set()
    deterministic_tp_indices: set[int] = set()
    for issue_index in sorted(matched_indices):
        if issue_index < 0 or issue_index >= len(issues):
            continue
        issue = issues[issue_index]
        attribution = finding_attribution(issue)
        if "deterministic_rule" not in set(attribution.get("discovered_by") or []):
            continue
        deterministic_tp_indices.add(issue_index)
        truth_ids = truth_ids_by_issue.get(issue_index, set())
        detector_ids = _issue_rule_ids(issue)
        if not detector_ids:
            missing_rule_truth_ids.update(truth_ids)
            continue
        for detector_id in detector_ids:
            canonical_id = catalog.canonical_id(detector_id)
            owner = known if canonical_id else unknown
            key = canonical_id or detector_id
            entry = owner.setdefault(
                key,
                {
                    "issue_indices": set(),
                    "truth_ids": set(),
                    "observed_detector_ids": set(),
                },
            )
            entry["issue_indices"].add(issue_index)
            entry["truth_ids"].update(truth_ids)
            entry["observed_detector_ids"].add(detector_id)

    qualification_by_rule = {
        str(row["rule_id"]): row for row in qualification_rows(catalog, registry)
    }
    participating_rules = []
    for rule_id, entry in sorted(known.items()):
        descriptor = catalog.require(rule_id)
        qualification = qualification_by_rule[rule_id]
        participating_rules.append(
            {
                "rule_id": rule_id,
                "tp_count": len(entry["issue_indices"]),
                "truth_ids": sorted(entry["truth_ids"]),
                "current_revision": descriptor.revision,
                "qualification_state": qualification["qualification_state"],
                "evidence_verified": bool(qualification["evidence_verified"]),
                "default_enabled": bool(qualification["default_enabled"]),
                "observed_detector_ids": sorted(entry["observed_detector_ids"]),
            }
        )
    unknown_detectors = [
        {
            "detector_id": detector_id,
            "tp_count": len(entry["issue_indices"]),
            "truth_ids": sorted(entry["truth_ids"]),
        }
        for detector_id, entry in sorted(unknown.items())
    ]
    per_rule_tp_count_sum = sum(row["tp_count"] for row in participating_rules)
    return {
        "schema_version": "zscope.rule-benchmark-tp-audit.v1",
        "view": view,
        "selected_view_true_positives": int(selected_score.get("true_positives") or 0),
        "matched_issue_count": len(matched_indices),
        "deterministic_rule_tp_issue_count": len(deterministic_tp_indices),
        "participating_rule_ids": [row["rule_id"] for row in participating_rules],
        "participating_rules": participating_rules,
        "unknown_detectors": unknown_detectors,
        "missing_detector": {
            "tp_count": sum(
                1
                for issue_index in deterministic_tp_indices
                if not _issue_rule_ids(issues[issue_index])
            ),
            "truth_ids": sorted(missing_rule_truth_ids),
        },
        "per_rule_tp_count_sum": per_rule_tp_count_sum,
        "per_rule_counts_overlap": True,
        "counting_contract": (
            "A TP may be attributed to multiple deterministic rules; per-rule TP counts "
            "overlap and MUST NOT be summed as distinct benchmark true positives."
        ),
    }


def audit(
    *,
    catalog_path: Optional[Path] = None,
    registry_path: Optional[Path] = None,
    benchmark_report_path: Optional[Path] = None,
    benchmark_truth_path: Optional[Path] = None,
    view: str = "default",
) -> dict:
    if (benchmark_report_path is None) != (benchmark_truth_path is None):
        raise ValueError("benchmark_report_path and benchmark_truth_path must be provided together")
    catalog = (
        RuleCatalog.from_path(catalog_path, builtin=True)
        if catalog_path is not None
        else RuleCatalog.builtin()
    )
    registry = (
        QualificationRegistry.from_path(registry_path, catalog=catalog)
        if registry_path is not None
        else QualificationRegistry.builtin(catalog=catalog)
    )
    rows = list(qualification_rows(catalog, registry))
    pending = [row for row in rows if row["qualification_state"] == "pending"]
    failed = [row for row in rows if row["qualification_state"] == "failed"]
    unverified = [
        row
        for row in rows
        if row["qualification_state"] == "qualified" and not row.get("evidence_verified")
    ]
    result = {
        "schema_version": "zscope.rule-qualification-audit.v1",
        "catalog_schema_version": catalog.version,
        "catalog_sha256": catalog.source_sha256,
        "qualification_registry": registry.summary(),
        "summary": {
            "rules": len(rows),
            "default_enabled": sum(bool(row["default_enabled"]) for row in rows),
            "pending": len(pending),
            "failed": len(failed),
            "qualified": sum(row["qualification_state"] == "qualified" for row in rows),
            "evidence_verified": sum(bool(row.get("evidence_verified")) for row in rows),
            "unverified_qualified": len(unverified),
        },
        "pending": pending,
        "failed": failed,
        "unverified_qualified": unverified,
        "rows": rows,
    }
    if benchmark_report_path is not None and benchmark_truth_path is not None:
        result["benchmark_tp_participation"] = benchmark_tp_rule_participation(
            _load_json_object(benchmark_report_path, label="benchmark report"),
            _load_json_object(benchmark_truth_path, label="benchmark truth"),
            catalog=catalog,
            registry=registry,
            view=view,
        )
    return result


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path)
    parser.add_argument("--registry", type=Path)
    parser.add_argument("--benchmark-report", type=Path)
    parser.add_argument("--benchmark-truth", type=Path)
    parser.add_argument("--view", choices=_BENCHMARK_VIEWS, default="default")
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--require-qualified-stable",
        action="store_true",
        help="Fail if a stable rule is pending or failed.",
    )
    args = parser.parse_args(argv)
    if (args.benchmark_report is None) != (args.benchmark_truth is None):
        parser.error("--benchmark-report and --benchmark-truth must be provided together")
    result = audit(
        catalog_path=args.catalog,
        registry_path=args.registry,
        benchmark_report_path=args.benchmark_report,
        benchmark_truth_path=args.benchmark_truth,
        view=args.view,
    )
    rendered = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    if args.require_qualified_stable and (
        result["summary"]["pending"]
        or result["summary"]["failed"]
        or result["summary"]["unverified_qualified"]
    ):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
