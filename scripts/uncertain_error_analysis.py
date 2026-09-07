"""Plan Phase 2.3 (offline part): classify the uncertain-verdict population.

Reads a frozen trial's ``report.json`` + ``score.json`` and produces the
error-analysis artifact that anchors the validator confidence rubric work:
per-item records (missing-fact bucket, verdict trajectory, sub-state,
confidence band, truth match) plus aggregates.  Truth is only read from the
already-scored ``score.json`` matched pairs; no prompt or scanner input is
derived from it here.

Usage::

    PYTHONPATH=. python scripts/uncertain_error_analysis.py \
        --report benchmark-artifacts/.../report.json \
        --score benchmark-artifacts/.../score.json \
        --output benchmarks/experiments/balanced_confirmed_tp/uncertain_error_analysis.json
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List


def _missing_bucket(kinds: List[str]) -> str:
    if not kinds:
        return "obligation_complete"
    kinds_set = set(kinds)
    if {"event:acquire", "event:exit"} & kinds_set:
        return "event_lifecycle"
    if "happens_before" in kinds_set:
        return "happens_before"
    if "lockset" in kinds_set and "event:shared_state_access" in kinds_set:
        return "lockset_pair"
    if "lockset" in kinds_set:
        return "lockset"
    return "other"


def _confidence_band(value: Any) -> str:
    if value is None or (isinstance(value, str) and not value.strip()):
        return "unknown"
    try:
        conf = float(value)
    except (TypeError, ValueError):
        return "unknown"
    if conf >= 0.80:
        return ">=0.80"
    if conf >= 0.70:
        return "0.70-0.79"
    if conf >= 0.60:
        return "0.60-0.69"
    return "<0.60"


def analyze(report: Dict[str, Any], score: Dict[str, Any]) -> Dict[str, Any]:
    matched_indices = {
        int(pair.get("issue_index"))
        for pair in score.get("matched_pairs") or []
        if isinstance(pair, dict) and isinstance(pair.get("issue_index"), int)
    }
    index_by_dedup: Dict[str, int] = {}
    for index, issue in enumerate(report.get("issues") or []):
        if isinstance(issue, dict):
            key = str(issue.get("dedup_key") or "")
            if key and key not in index_by_dedup:
                index_by_dedup[key] = index

    rows: List[Dict[str, Any]] = []
    for issue in report.get("issues_with_needs_review") or []:
        if not isinstance(issue, dict):
            continue
        if str(issue.get("validator_verdict")) != "uncertain":
            continue
        if str(issue.get("candidate_disposition") or "") != "needs_review":
            continue
        missing = [str(k) for k in issue.get("missing_fact_kinds") or []]
        dedup = str(issue.get("dedup_key") or "")
        matched = index_by_dedup.get(dedup) in matched_indices
        history = issue.get("validator_pass_history") or []
        passes = [str(entry.get("pass") or "") for entry in history if isinstance(entry, dict)]
        components = issue.get("score_components") or {}
        rows.append(
            {
                "validation_cluster_uid": issue.get("validation_cluster_uid"),
                "rule": issue.get("rule"),
                "cwe": issue.get("cwe"),
                "truth_match": "TP" if matched else "UNMATCHED",
                "missing_fact_bucket": _missing_bucket(missing),
                "missing_fact_kinds": missing,
                "evidence_completion_status": issue.get("evidence_completion_status"),
                "needs_review_sub_state": issue.get("needs_review_sub_state"),
                "passes": passes,
                "confidence_band": _confidence_band(components.get("validation_confidence")),
                "final_score": components.get("final_score"),
            }
        )

    def cross(rows_group: List[Dict[str, Any]], key: str) -> Dict[str, Dict[str, int]]:
        table: Dict[str, Counter] = defaultdict(Counter)
        for row in rows_group:
            table[str(row.get(key))][str(row.get("truth_match"))] += 1
        return {key_: dict(counter) for key_, counter in sorted(table.items())}

    tp_rows = [row for row in rows if row["truth_match"] == "TP"]
    return {
        "schema_version": "zscope.uncertain-error-analysis.v1",
        "population": len(rows),
        "truth_match": dict(Counter(row["truth_match"] for row in rows)),
        "by_missing_fact_bucket": cross(rows, "missing_fact_bucket"),
        "by_confidence_band": cross(rows, "confidence_band"),
        "by_sub_state": cross(rows, "needs_review_sub_state"),
        "by_completion_status": cross(rows, "evidence_completion_status"),
        "by_passes_shape": (
            cross(
                rows,
                "passes",
            )
            if False
            else dict(Counter("+".join(row["passes"]) or "initial_only" for row in rows))
        ),
        "tp_rows": tp_rows,
        "top_rules_unmatched": dict(
            Counter(
                str(row.get("rule")) for row in rows if row["truth_match"] == "UNMATCHED"
            ).most_common(10)
        ),
        "rows": rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--score", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = json.loads(args.report.read_text(encoding="utf-8"))
    score = json.loads(args.score.read_text(encoding="utf-8"))
    result = analyze(report, score)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"population={result['population']} truth_match={result['truth_match']} -> {args.output}")


if __name__ == "__main__":
    main()
