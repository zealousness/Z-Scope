"""Independent scorer for frozen review replay outputs; no model calls."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from copy import deepcopy
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from zscope.benchmarking.protocol import score_report
from zscope.benchmarking.review_experiment import compare_paired_replays, load_audit
from zscope.core.validation.review_checks import ReviewClaimChecker, checked_receipt
from zscope.retrieval.validation_facts import CompleteFactStore
from zscope.reporting.finding_roots import project_finding_roots


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--run", required=True, action="append", type=Path)
    parser.add_argument("--audit", required=True, type=Path)
    parser.add_argument("--truth", required=True, type=Path)
    parser.add_argument("--project", required=True, type=Path)
    parser.add_argument("--compile-commands", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    # Freeze all run bytes before opening any scoring answers.
    paths = [args.baseline, *args.run]
    raw = [path.read_bytes() for path in paths]
    runs = [json.loads(value) for value in raw]
    if any(
        run.get("schema_version") != "zscope.review-replay.v1" or run.get("complete") is not True
        for run in runs
    ):
        parser.error("scoring requires completed frozen replay outputs")
    audit = load_audit(args.audit)
    truth_bytes = args.truth.read_bytes()
    truth = json.loads(truth_bytes)
    for run in runs:
        roots = project_finding_roots(run["outcomes"]).outcomes
        confirmed = [i for i in roots if i.get("candidate_disposition") == "confirmed"]
        review = [i for i in roots if i.get("candidate_disposition") == "needs_review"]
        default_score = score_report({"issues": confirmed}, truth, view="default")
        review_score = score_report({"issues": review}, truth, view="default")
        run["confirmed_truth_ids"] = default_score["true_positive_truth_ids"]
        run["review_truth_ids"] = review_score["true_positive_truth_ids"]
        run["official_default_score"] = default_score
        run["official_review_score"] = review_score
    checker = ReviewClaimChecker(
        CompleteFactStore(
            args.project, args.compile_commands, args.output.parent / "proof-replay-facts"
        )
    )

    def replay_proof(original):
        item = deepcopy(original)
        old = item.get("review_checked_proof") or {}
        try:
            if (
                not old.get("dependencies")
                or CompleteFactStore._hash_files(old["dependencies"]) != old["dependencies"]
            ):
                return False
        except (OSError, TypeError):
            return False
        item.pop("review_checked_proof", None)
        checker.prepare(item)
        checker.check(item)
        new = checked_receipt(item)
        return bool(
            new
            and new["reason"] == old.get("reason")
            and new["dependencies"] == old["dependencies"]
        )

    evaluation = compare_paired_replays(runs[0], runs[1:], audit, replay_proof=replay_proof)
    evaluation["inputs"] = {
        str(path): hashlib.sha256(value).hexdigest() for path, value in zip(paths, raw)
    }
    evaluation["truth_sha256"] = hashlib.sha256(truth_bytes).hexdigest()
    evaluation["official_scores"] = [
        {
            "arm": run.get("arm"),
            "pair_id": run.get("pair_id"),
            "default": run["official_default_score"],
            "review": run["official_review_score"],
        }
        for run in runs
    ]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(evaluation, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"status": evaluation["status"], "output": str(args.output)}))


if __name__ == "__main__":
    main()
