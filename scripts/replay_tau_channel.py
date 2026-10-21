"""Replay the R3 high-confidence-band confirmation policy over a frozen trial.

Implements the exact ``_high_confidence_uncertain_confirms`` predicate from
``zscope.core.validation.pipeline`` as an offline measurement (zero LLM cost)
and scores each candidate threshold against the plan's FDR gate:

    uncertain verdict
    AND final_score >= 0.6
    AND confidence >= tau
    AND no missing_fact_kinds
    AND no blocking/negative evidence

Promoted items are joined to the score's matched pairs (via the report issue
index) to count confirmed TP/FP deltas.  The plan's gate is ``FDR +1pp``;
a threshold that breaches it must stay disabled.

Usage::

    PYTHONPATH=. python scripts/replay_tau_channel.py \\
        --trial benchmark-artifacts/c_cpp/trial/20260904T094432Z/run-01 \\
        --output benchmarks/experiments/balanced_confirmed_tp/tau_channel_replay.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

CONFIRM_FINAL_SCORE_FLOOR = 0.6
DEFAULT_TAU_SWEEP = (0.80, 0.85, 0.90)
FDR_GATE_DELTA = 0.01


def _load_json(path: Path) -> Dict[str, Any]:
    from zscope.reporting.json_io import read_report
    return read_report(path)


def _tau_predicate(issue: Dict[str, Any], tau: float) -> bool:
    """Mirror ``ValidationPipeline._high_confidence_uncertain_confirms``."""

    if str(issue.get("validator_verdict") or "") != "uncertain":
        return False
    try:
        final_score = float(issue.get("final_score") or 0.0)
    except (TypeError, ValueError):
        return False
    if final_score < CONFIRM_FINAL_SCORE_FLOOR:
        return False
    raw_confidence = issue.get("confidence_score")
    if raw_confidence is None:
        raw_confidence = issue.get("confidence")
    try:
        confidence = float(raw_confidence)
    except (TypeError, ValueError):
        return False
    if confidence < tau:
        return False
    if issue.get("missing_fact_kinds"):
        return False
    if issue.get("blocking_negative_evidence") is True:
        return False
    if issue.get("negative_evidence"):
        return False
    return True


def _promoted_at(
    needs_review: List[Dict[str, Any]],
    index_by_dedup: Dict[Any, int],
    matched_index: Dict[int, str],
    tau: float,
) -> List[Dict[str, Any]]:
    promoted: List[Dict[str, Any]] = []
    for issue in needs_review:
        if not _tau_predicate(issue, tau):
            continue
        report_index = index_by_dedup.get(issue.get("dedup_key"))
        truth_id = matched_index.get(report_index or -1)
        promoted.append(
            {
                "validation_cluster_uid": issue.get("validation_cluster_uid"),
                "candidate_uid": issue.get("candidate_uid"),
                "rule": issue.get("rule"),
                "function": issue.get("function"),
                "confidence": issue.get("confidence"),
                "final_score": issue.get("final_score"),
                "matched_truth_id": truth_id,
                "is_true_positive": truth_id is not None,
            }
        )
    return promoted


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--trial",
        type=Path,
        required=True,
        help="Frozen trial run directory containing report.json and score.json.",
    )
    parser.add_argument("--output", type=Path, help="Write the measurement JSON here.")
    parser.add_argument(
        "--tau",
        type=float,
        nargs="*",
        default=list(DEFAULT_TAU_SWEEP),
        help="Threshold sweep (default: 0.80 0.85 0.90).",
    )
    parser.add_argument(
        "--fdr-gate",
        type=float,
        default=FDR_GATE_DELTA,
        help="Maximum allowed FDR delta in absolute fraction (default 0.01).",
    )
    arguments = parser.parse_args(argv)

    report = _load_json(arguments.trial / "report.json")
    score = _load_json(arguments.trial / "score.json")

    matched_index: Dict[int, str] = {
        int(pair["issue_index"]): str(pair.get("truth_id") or "")
        for pair in score.get("matched_pairs") or []
    }
    index_by_dedup: Dict[Any, int] = {}
    for index, issue in enumerate(report.get("issues") or []):
        index_by_dedup.setdefault(issue.get("dedup_key"), index)

    needs_review = report.get("issues_with_needs_review") or []
    baseline_tp = int(score.get("true_positives") or 0)
    baseline_fp = int(score.get("false_positives_effective") or 0)
    baseline_fdr = float(score.get("actionable_false_discovery_rate") or 0.0)

    sweep: List[Dict[str, Any]] = []
    for tau in arguments.tau:
        promoted = _promoted_at(needs_review, index_by_dedup, matched_index, tau)
        tp_delta = sum(1 for item in promoted if item["is_true_positive"])
        fp_delta = len(promoted) - tp_delta
        confirmed_tp = baseline_tp + tp_delta
        confirmed_fp = baseline_fp + fp_delta
        fdr = confirmed_fp / (confirmed_tp + confirmed_fp) if (confirmed_tp + confirmed_fp) else 0.0
        fdr_delta = fdr - baseline_fdr
        sweep.append(
            {
                "tau": tau,
                "promoted": len(promoted),
                "tp_delta": tp_delta,
                "fp_delta": fp_delta,
                "confirmed_tp": confirmed_tp,
                "confirmed_fp": confirmed_fp,
                "fdr": fdr,
                "fdr_delta": fdr_delta,
                "passes_fdr_gate": fdr_delta <= arguments.fdr_gate,
                "items": promoted,
            }
        )

    passing = [row for row in sweep if row["passes_fdr_gate"]]
    result = {
        "schema_version": "zscope.tau-channel-replay.v1",
        "trial": str(arguments.trial),
        "predicate": "ValidationPipeline._high_confidence_uncertain_confirms (offline mirror)",
        "baseline": {
            "true_positives": baseline_tp,
            "false_positives_effective": baseline_fp,
            "actionable_false_discovery_rate": baseline_fdr,
            "needs_review_issues": len(needs_review),
            "uncertain_issues": sum(
                1
                for issue in needs_review
                if str(issue.get("validator_verdict") or "") == "uncertain"
            ),
        },
        "fdr_gate_delta": arguments.fdr_gate,
        "sweep": sweep,
        "recommended_tau": (
            max((row["tau"] for row in passing), default=None) if passing else None
        ),
        "gate_conclusion": (
            "enable at recommended tau"
            if passing
            else "no threshold passes the FDR gate; channel stays disabled"
        ),
    }

    payload = json.dumps(result, ensure_ascii=False, indent=2)
    if arguments.output is not None:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(payload + "\n", encoding="utf-8")
    summary_lines = [
        f"baseline TP={baseline_tp} FP={baseline_fp} FDR={baseline_fdr:.4f}",
    ]
    for row in sweep:
        summary_lines.append(
            f"tau={row['tau']:.2f}: promoted={row['promoted']} (+{row['tp_delta']}TP/"
            f"+{row['fp_delta']}FP) confirmed_TP={row['confirmed_tp']} "
            f"FDR_delta={row['fdr_delta']:+.4f} gate={'PASS' if row['passes_fdr_gate'] else 'FAIL'}"
        )
    summary_lines.append(f"conclusion: {result['gate_conclusion']}")
    print("\n".join(summary_lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
