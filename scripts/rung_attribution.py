#!/usr/bin/env python3
"""Marginal TP attribution across escalation-ladder rung runs.

Consumes one or more zscope trial/formal run directories (each containing
``score.json``, ``report.json``, and optionally ``llm_usage_events.jsonl``)
in rung order and emits the marginal contribution table required by
``new_docs/balanced_confirmed_tp_plan.md`` Phase 5:

* confirmed-TP truth set per run, decomposed by ``confirmed_via``
* per-rung marginal ``TP_added / TP_lost / FP_added / tokens_added`` and
  ``marginal_tokens_per_added_tp``
* per-rung token totals keyed by ``escalation_rung`` (usage events without
  the field derive it from ``call_kind`` so pre-rung artifacts still diff)

Usage::

    python scripts/rung_attribution.py \
        --run-dir benchmark-artifacts/c_cpp/trial/<stamp>/run-01 \
        --run-dir benchmark-artifacts/c_cpp/trial/<stamp2>/run-01 \
        [--label R1_balanced --label R2_v3] [--output out.json]

The first run is the baseline row (no marginal section).  Replay-arm ledgers
are accepted via ``--usage-jsonl`` overrides when comparing offline arms.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from zscope.framework.llm_usage import escalation_rung_for_call_kind  # noqa: E402

R1_DEFAULT = "R1_validator_v1"


def _load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _confirmed_via_of_pair(pair: Dict[str, Any]) -> str:
    """Resolve the confirmation path for one matched pair.

    Prefers the ``confirmed_via`` dimension added to finding attribution;
    falls back to ``decided_by`` so frozen baseline artifacts still diff.
    """

    attribution = pair.get("attribution") if isinstance(pair.get("attribution"), dict) else {}
    confirmed_via = str(attribution.get("confirmed_via") or "").strip()
    if confirmed_via:
        return confirmed_via
    decided_by = str(attribution.get("decided_by") or "").strip()
    if decided_by == "deterministic_proof":
        return "deterministic_proof"
    if decided_by == "validator_llm":
        return "validator_model"
    return decided_by or "unknown"


def _usage_tokens_by_rung(path: Optional[Path]) -> Tuple[Dict[str, int], int]:
    if path is None or not path.is_file():
        return {}, 0
    by_rung: Dict[str, int] = {}
    total = 0
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            rung = str(event.get("escalation_rung") or "")
            if not rung:
                rung = escalation_rung_for_call_kind(event.get("call_kind"))
            if not rung:
                rung = R1_DEFAULT
            tokens = int(event.get("total_tokens") or 0)
            by_rung[rung] = by_rung.get(rung, 0) + tokens
            total += tokens
    return by_rung, total


def summarize_run(
    run_dir: Path,
    *,
    label: Optional[str] = None,
    usage_override: Optional[Path] = None,
) -> Dict[str, Any]:
    score = _load_json(run_dir / "score.json")
    report = _load_json(run_dir / "report.json")

    pairs = score.get("matched_pairs") or []
    issues = report.get("issues") or []
    tp_truth_ids = sorted(str(pair.get("truth_id") or "") for pair in pairs if pair.get("truth_id"))
    by_via: Dict[str, int] = {}
    truth_via: Dict[str, str] = {}
    for pair in pairs:
        truth_id = str(pair.get("truth_id") or "")
        via = _confirmed_via_of_pair(pair)
        by_via[via] = by_via.get(via, 0) + 1
        if truth_id:
            truth_via[truth_id] = via

    usage_path = usage_override or (run_dir / "llm_usage_events.jsonl")
    tokens_by_rung, tokens_total = _usage_tokens_by_rung(usage_path)

    return {
        "label": label or run_dir.name,
        "run_dir": run_dir.as_posix(),
        "confirmed_tp": int(score.get("true_positives") or len(pairs)),
        "false_positives": int(score.get("false_positives") or 0),
        "confirmed_recall": score.get("confirmed_recall"),
        "confirmed_precision": score.get("confirmed_precision"),
        "tp_truth_ids": tp_truth_ids,
        "tp_truth_via": truth_via,
        "tp_by_confirmed_via": dict(sorted(by_via.items())),
        "tokens_total": tokens_total,
        "tokens_by_rung": dict(sorted(tokens_by_rung.items())),
        "queue_empty": bool(score.get("queue_empty")),
        "protocol_anomaly_count": int(score.get("protocol_anomaly_count") or 0),
        "issue_count": len(issues),
    }


def marginal(previous: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
    prev_ids = set(previous["tp_truth_ids"])
    curr_ids = set(current["tp_truth_ids"])
    added_ids = sorted(curr_ids - prev_ids)
    lost_ids = sorted(prev_ids - curr_ids)
    fp_delta = current["false_positives"] - previous["false_positives"]
    tokens_delta = current["tokens_total"] - previous["tokens_total"]
    current_via = current.get("tp_truth_via") or {}
    added_by_via: Dict[str, List[str]] = {}
    for truth_id in added_ids:
        via = str(current_via.get(truth_id) or "unknown")
        added_by_via.setdefault(via, []).append(truth_id)
    return {
        "from": previous["label"],
        "to": current["label"],
        "tp_added": len(added_ids),
        "tp_added_truth_ids": added_ids,
        "tp_lost": len(lost_ids),
        "tp_lost_truth_ids": lost_ids,
        "fp_added": fp_delta,
        "tokens_added": tokens_delta,
        "marginal_tokens_per_added_tp": (
            round(tokens_delta / len(added_ids), 1) if added_ids and tokens_delta > 0 else None
        ),
        "confirmed_recall_delta": _delta(
            previous.get("confirmed_recall"), current.get("confirmed_recall")
        ),
        "confirmed_precision_delta": _delta(
            previous.get("confirmed_precision"), current.get("confirmed_precision")
        ),
        "added_by_confirmed_via": {key: sorted(value) for key, value in added_by_via.items()},
        "queue_empty": current["queue_empty"],
        "protocol_anomaly_count": current["protocol_anomaly_count"],
    }


def _delta(previous: Any, current: Any) -> Optional[float]:
    if isinstance(previous, (int, float)) and isinstance(current, (int, float)):
        return round(float(current) - float(previous), 4)
    return None


def build_report(summaries: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    marginals = [
        marginal(summaries[index - 1], summaries[index]) for index in range(1, len(summaries))
    ]
    return {
        "schema_version": "zscope.rung-attribution.v1",
        "runs": summaries,
        "marginals": marginals,
        "summary_line": [
            {
                "rung": summary["label"],
                "confirmed_tp": summary["confirmed_tp"],
                "fp": summary["false_positives"],
                "tokens": summary["tokens_total"],
            }
            for summary in summaries
        ],
    }


def _print_table(report: Dict[str, Any]) -> None:
    print("== rung summary ==")
    header = f"{'rung':<28}{'confirmed_tp':>13}{'fp':>6}{'tokens':>12}"
    print(header)
    for row in report["summary_line"]:
        print(f"{row['rung']:<28}{row['confirmed_tp']:>13}{row['fp']:>6}{row['tokens']:>12}")
    if report["marginals"]:
        print("== marginals ==")
        header = (
            f"{'transition':<40}{'tp_added':>9}{'tp_lost':>8}"
            f"{'fp_added':>9}{'tokens_added':>14}{'tokens/tp':>11}"
        )
        print(header)
        for row in report["marginals"]:
            transition = f"{row['from']} -> {row['to']}"
            per_tp = row["marginal_tokens_per_added_tp"]
            print(
                f"{transition:<40}{row['tp_added']:>9}{row['tp_lost']:>8}"
                f"{row['fp_added']:>9}{row['tokens_added']:>14}"
                f"{per_tp if per_tp is not None else '-':>11}"
            )


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--run-dir",
        action="append",
        required=True,
        type=Path,
        help="Run directory containing score.json/report.json (repeat in rung order).",
    )
    parser.add_argument(
        "--label",
        action="append",
        default=[],
        help="Optional display label per --run-dir (same order).",
    )
    parser.add_argument(
        "--usage-jsonl",
        action="append",
        default=[],
        type=Path,
        help="Optional usage JSONL override per --run-dir (same order, replay arms).",
    )
    parser.add_argument("--output", type=Path, help="Write the full JSON report to this path.")
    arguments = parser.parse_args(argv)

    labels: Iterable[Optional[str]] = list(arguments.label) + [None] * (
        len(arguments.run_dir) - len(arguments.label)
    )
    usages: List[Optional[Path]] = list(arguments.usage_jsonl) + [None] * (
        len(arguments.run_dir) - len(arguments.usage_jsonl)
    )
    summaries = [
        summarize_run(run_dir, label=label, usage_override=usage)
        for run_dir, label, usage in zip(arguments.run_dir, labels, usages)
    ]
    report = build_report(summaries)
    if arguments.output is not None:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    _print_table(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
