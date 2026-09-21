"""Post-scan official rescoring under one frozen matcher; never makes LLM calls."""

from __future__ import annotations

import gc
import hashlib
import json
from pathlib import Path

from zscope.benchmarking.runner import score_artifact


def main() -> None:
    root = Path(__file__).resolve().parents[3]
    artifacts = root / "benchmark-artifacts/pool-protocol-v3"
    execution = json.loads((artifacts / "benchmark-execution.json").read_text())
    assert execution["status"] in {"complete", "completed", "failed"}, "Wait for scan exit"
    matcher = root / "zscope/benchmarking/protocol.py"
    matcher_hash = hashlib.sha256(matcher.read_bytes()).hexdigest()
    assert matcher_hash == execution["source_start_hashes"]["zscope/benchmarking/protocol.py"]
    truth = root / "test/range/benchmark/ground_truth.json"
    output = artifacts / "same-matcher-comparison"
    output.mkdir(exist_ok=True)
    records = {}
    for label in ("20260908T055018Z", "20260910T015537Z", "20260910T193027Z"):
        run = root / "benchmark-artifacts/c_cpp/trial" / label / "run-01"
        score = score_artifact(run / "report.json", truth, output / f"{label}.score.json")
        views = score["report_views"]
        records[label] = {
            "views": {
                name: {
                    k: view.get(k)
                    for k in (
                        "true_positives",
                        "false_positives_raw",
                        "recall",
                        "report_issue_count",
                        "matched",
                    )
                }
                for name, view in views.items()
            },
            "usage_accounting": score.get("usage_accounting", {}),
        }
        print(
            json.dumps(
                {
                    "run": label,
                    "views": {
                        n: {k: v for k, v in r.items() if k != "matched"}
                        for n, r in records[label]["views"].items()
                    },
                },
                ensure_ascii=False,
            ),
            flush=True,
        )
        del score, views
        gc.collect()
    result = {
        "matcher_sha256": matcher_hash,
        "truth_sha256": hashlib.sha256(truth.read_bytes()).hexdigest(),
        "release_eligible": False,
        "runs": records,
    }
    (output / "comparison.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
