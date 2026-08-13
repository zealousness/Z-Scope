#!/usr/bin/env python3
"""Score 25 frozen D0-D4 semantic/discovery ablation artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from zscope.benchmarking.discovery_ablation_experiment import (
    DiscoveryAblationExperimentError,
    score_discovery_ablation_experiment,
    write_discovery_ablation_experiment,
)


TrialKey = Tuple[str, int]


def _parse_path(value: str) -> Tuple[TrialKey, Path]:
    arm_id, separator, remainder = str(value or "").partition(":")
    trial_text, separator_two, path_text = remainder.partition(":")
    if (
        not separator
        or not separator_two
        or arm_id not in ("D0", "D1", "D2", "D3", "D4")
        or not trial_text.isdigit()
        or not path_text
    ):
        raise argparse.ArgumentTypeError("artifact path must use ARM:TRIAL:PATH with ARM D0-D4")
    trial_index = int(trial_text)
    if trial_index < 1 or trial_index > 5:
        raise argparse.ArgumentTypeError("artifact trial index must be 1-5")
    return (arm_id, trial_index), Path(path_text)


def _parse_hash(value: str) -> Tuple[TrialKey, str]:
    arm_id, separator, remainder = str(value or "").partition(":")
    trial_text, separator_two, sha256 = remainder.partition(":")
    if (
        not separator
        or not separator_two
        or arm_id not in ("D0", "D1", "D2", "D3", "D4")
        or not trial_text.isdigit()
        or int(trial_text) < 1
        or int(trial_text) > 5
        or len(sha256) != 64
        or any(character not in "0123456789abcdef" for character in sha256)
    ):
        raise argparse.ArgumentTypeError("artifact hash must use ARM:TRIAL:LOWERCASE_SHA256")
    return (arm_id, int(trial_text)), sha256


def _unique_mapping(rows, *, label: str):
    result = {}
    for key, value in rows:
        if key in result:
            raise DiscoveryAblationExperimentError(f"duplicate {label}: {key[0]} trial {key[1]}")
        result[key] = value
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--expected-plan-sha256", required=True)
    parser.add_argument("--truth", required=True, type=Path)
    parser.add_argument("--expected-truth-sha256", required=True)
    parser.add_argument(
        "--execution",
        action="append",
        required=True,
        type=_parse_path,
        metavar="ARM:TRIAL:PATH",
        help="Execution artifact; provide D0-D4 trials 1-5 exactly once.",
    )
    parser.add_argument(
        "--report",
        action="append",
        required=True,
        type=_parse_path,
        metavar="ARM:TRIAL:PATH",
        help="Corresponding scanner report; provide D0-D4 trials 1-5 exactly once.",
    )
    parser.add_argument(
        "--usage-sidecar",
        action="append",
        required=True,
        type=_parse_path,
        metavar="ARM:TRIAL:PATH",
        help="Raw LLM usage JSONL sidecar; provide D0-D4 trials 1-5 exactly once.",
    )
    parser.add_argument(
        "--expected-execution-sha256",
        action="append",
        required=True,
        type=_parse_hash,
        metavar="ARM:TRIAL:SHA256",
        help="Externally frozen canonical execution hash for every trial.",
    )
    parser.add_argument(
        "--expected-report-sha256",
        action="append",
        required=True,
        type=_parse_hash,
        metavar="ARM:TRIAL:SHA256",
        help="Externally frozen canonical report hash for every trial.",
    )
    parser.add_argument(
        "--expected-execution-file-sha256",
        action="append",
        required=True,
        type=_parse_hash,
        metavar="ARM:TRIAL:SHA256",
        help="Externally frozen byte-level execution artifact hash for every trial.",
    )
    parser.add_argument(
        "--expected-report-file-sha256",
        action="append",
        required=True,
        type=_parse_hash,
        metavar="ARM:TRIAL:SHA256",
        help="Externally frozen byte-level report artifact hash for every trial.",
    )
    parser.add_argument(
        "--expected-usage-sidecar-sha256",
        action="append",
        required=True,
        type=_parse_hash,
        metavar="ARM:TRIAL:SHA256",
        help="Externally frozen raw usage sidecar SHA-256 for every trial.",
    )
    parser.add_argument(
        "--cold-trials-attested",
        action="store_true",
        required=True,
        help="Attest that all 25 report/execution pairs are independent isolated-cold runs.",
    )
    parser.add_argument("--line-tolerance", type=int, default=8)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        executions: Dict[TrialKey, Path] = _unique_mapping(args.execution, label="execution path")
        reports: Dict[TrialKey, Path] = _unique_mapping(args.report, label="report path")
        usage_sidecars: Dict[TrialKey, Path] = _unique_mapping(
            args.usage_sidecar, label="usage sidecar path"
        )
        execution_hashes: Dict[TrialKey, str] = _unique_mapping(
            args.expected_execution_sha256, label="execution canonical hash"
        )
        report_hashes: Dict[TrialKey, str] = _unique_mapping(
            args.expected_report_sha256, label="report canonical hash"
        )
        execution_file_hashes: Dict[TrialKey, str] = _unique_mapping(
            args.expected_execution_file_sha256, label="execution file hash"
        )
        report_file_hashes: Dict[TrialKey, str] = _unique_mapping(
            args.expected_report_file_sha256, label="report file hash"
        )
        usage_sidecar_hashes: Dict[TrialKey, str] = _unique_mapping(
            args.expected_usage_sidecar_sha256, label="usage sidecar hash"
        )
        result = score_discovery_ablation_experiment(
            plan_path=args.plan,
            execution_paths=executions,
            report_paths=reports,
            usage_sidecar_paths=usage_sidecars,
            truth_path=args.truth,
            expected_plan_sha256=args.expected_plan_sha256,
            expected_truth_sha256=args.expected_truth_sha256,
            expected_execution_sha256s=execution_hashes,
            expected_report_sha256s=report_hashes,
            expected_execution_file_sha256s=execution_file_hashes,
            expected_report_file_sha256s=report_file_hashes,
            expected_usage_sidecar_sha256s=usage_sidecar_hashes,
            cold_trials_attested=args.cold_trials_attested,
            line_tolerance=args.line_tolerance,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        write_discovery_ablation_experiment(args.output, result)
    except (OSError, TypeError, ValueError) as exc:
        parser.error(str(exc))

    print(
        json.dumps(
            {
                "schema_version": result["schema_version"],
                "experiment_sha256": result["experiment_sha256"],
                "release_eligible": False,
                "quality_comparable_arms": result["interpretation"]["quality_comparable_arms"],
                "cost_upper_bound_arms": result["interpretation"]["cost_upper_bound_arms"],
                "output": str(args.output),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
