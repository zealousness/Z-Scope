"""Audit preserved evidence after the trial exited without an archived report.

Truth is used only for post-scan candidate inventory, never sent to a model.
This deliberately does not manufacture a report, TP/FP score, or replay bundle.
"""

from collections import Counter
import json
from pathlib import Path
import re

from compare_runs import LOST


def main() -> None:
    root = Path(__file__).resolve().parents[3]
    artifacts = root / "benchmark-artifacts/pool-protocol-v3"
    run = root / "benchmark-artifacts/c_cpp/trial/20260910T193027Z/run-01"
    execution = json.loads((artifacts / "benchmark-execution.json").read_text())
    assert execution["status"] == "failed"
    log = (run / "scan.log").read_text(encoding="utf-8")
    totals = {}
    pattern = re.compile(
        r"\[T:([^]]+)\].*\[LLM API Trace\].*Prompt ≈ ([\d,]+) tk.*"
        r"Completion ≈ ([\d,]+) tk.*Total ≈ ([\d,]+) tk"
    )
    for line in log.splitlines():
        match = pattern.search(line)
        if not match:
            continue
        thread = match[1]
        phase = (
            "modeling"
            if thread.startswith("zscope-modeling")
            else ("validation" if thread.startswith("zscope-validator") else "other")
        )
        row = totals.setdefault(phase, Counter())
        row["events"] += 1
        for key, value in zip(
            ("prompt_tokens", "completion_tokens", "total_tokens"), match.groups()[1:]
        ):
            row[key] += int(value.replace(",", ""))
    queue = re.search(
        r"\[validation-queue\] end unique_groups=(\d+) confirmed=(\d+) review=(\d+) duration=([\d.]+)s",
        log,
    )
    assert queue is not None
    replay = json.loads((artifacts / "full-contract-replay-v9-final/replay.json").read_text())
    truth = {
        r["id"]: r
        for r in json.loads((root / "test/range/benchmark/ground_truth.json").read_text())[
            "vulnerabilities"
        ]
    }
    rows = []
    for tid in LOST:
        target = truth[tid]
        consumers = {
            name: value
            for name, value in replay["consumers"].items()
            if name.split(":", 1)[1].split("@", 1)[0] == target["function"]
        }
        rows.append(
            {
                "truth_id": tid,
                "function": target["function"],
                "file": target["file"],
                "same_function_candidates": [
                    {"consumer": name, **candidate}
                    for name, value in consumers.items()
                    for candidate in value.get("candidates", [])
                ],
                "project_interface_events": [
                    {"consumer": name, **event}
                    for name, value in consumers.items()
                    for event in value.get("calls", [])
                    if event.get("source") != "builtin_defaults"
                ],
            }
        )
    result = {
        "status": "unscored_failed_trial",
        "release_eligible": False,
        "failure": execution["failure"],
        "missing_final_artifacts": [
            name
            for name in (
                "report.json",
                "score.json",
                "llm_usage_events.jsonl",
                "validator-replay-bundle.json",
            )
            if not (run / name).exists()
        ],
        "observed_written_report_bytes_before_workspace_loss": 9560754108,
        "validation_queue_log": dict(
            zip(("unique_groups", "model_confirmed", "review"), map(int, queue.groups()[:3]))
        ),
        "validation_queue_seconds": float(queue[4]),
        "successful_usage_reconstructed_from_log": {k: dict(v) for k, v in totals.items()},
        "usage_limitation": "Reconstructed API trace totals, not the missing final usage ledger; failed requests without provider usage and exact per-candidate attribution are unavailable.",
        "regressions_26_candidate_inventory": rows,
        "candidate_inventory_limitation": "Final v9 zero-LLM standalone consumer replay; same function only, not defect matching or validated recovery. Experimental/default-disabled detectors may appear. This is not a TP/FP score.",
        "snapshot_source_assertion": "Final component probes register zero snapshot candidates. The failed full trial's missing report prevents final envelope/usage-join verification.",
    }
    (run / "failure-analysis.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {k: v for k, v in result.items() if k != "regressions_26_candidate_inventory"},
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
