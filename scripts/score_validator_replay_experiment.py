#!/usr/bin/env python3
"""Independently score a frozen five-trial Validator A-E replay experiment."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from zscope.benchmarking.validator_experiment import (
    ValidatorExperimentError,
    score_validator_replay_experiment,
    write_validator_replay_experiment,
)


def _parse_run(value: str) -> Tuple[Tuple[str, int], Path]:
    arm_id, separator, remainder = str(value or "").partition(":")
    trial_text, separator_two, path_text = remainder.partition(":")
    if (
        not separator
        or not separator_two
        or arm_id not in tuple("ABCDE")
        or not trial_text.isdigit()
        or not path_text
    ):
        raise argparse.ArgumentTypeError("run must use ARM:TRIAL:PATH with ARM A-E")
    trial_index = int(trial_text)
    if trial_index < 1 or trial_index > 5:
        raise argparse.ArgumentTypeError("run trial index must be 1-5")
    return (arm_id, trial_index), Path(path_text)


def _parse_expected_run_hash(value: str) -> Tuple[Tuple[str, int], str]:
    arm_id, separator, remainder = str(value or "").partition(":")
    trial_text, separator_two, sha256 = remainder.partition(":")
    if (
        not separator
        or not separator_two
        or arm_id not in tuple("ABCDE")
        or not trial_text.isdigit()
        or int(trial_text) < 1
        or int(trial_text) > 5
        or len(sha256) != 64
        or any(char not in "0123456789abcdef" for char in sha256)
    ):
        raise argparse.ArgumentTypeError("expected run hash must use ARM:TRIAL:LOWERCASE_SHA256")
    return (arm_id, int(trial_text)), sha256


def _unique_mapping(rows, *, label: str):
    result = {}
    for key, value in rows:
        if key in result:
            raise ValidatorExperimentError(f"duplicate {label}: Arm {key[0]} trial {key[1]}")
        result[key] = value
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--expected-bundle-sha256", required=True)
    parser.add_argument("--truth", required=True, type=Path)
    parser.add_argument("--expected-truth-sha256", required=True)
    parser.add_argument("--arm-catalog", type=Path)
    parser.add_argument("--expected-arm-catalog-sha256", required=True)
    parser.add_argument(
        "--run",
        action="append",
        required=True,
        type=_parse_run,
        metavar="ARM:TRIAL:PATH",
        help="Frozen replay ledger; provide Arms A-E trials 1-5 exactly once.",
    )
    parser.add_argument(
        "--expected-run-sha256",
        action="append",
        required=True,
        type=_parse_expected_run_hash,
        metavar="ARM:TRIAL:SHA256",
        help="Externally recorded run hash; provide Arms A-E trials 1-5 exactly once.",
    )
    parser.add_argument(
        "--cold-trials-attested",
        action="store_true",
        required=True,
        help="Attest that all 25 ledgers are independent cold trials.",
    )
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        runs: Dict[Tuple[str, int], Path] = _unique_mapping(args.run, label="run")
        expected_hashes: Dict[Tuple[str, int], str] = _unique_mapping(
            args.expected_run_sha256, label="expected run hash"
        )
        result = score_validator_replay_experiment(
            bundle_path=args.bundle,
            run_paths=[runs[key] for key in sorted(runs)],
            truth_path=args.truth,
            expected_bundle_sha256=args.expected_bundle_sha256,
            expected_truth_sha256=args.expected_truth_sha256,
            expected_arm_catalog_sha256=args.expected_arm_catalog_sha256,
            expected_run_sha256s=expected_hashes,
            arm_catalog_path=args.arm_catalog,
            cold_trials_attested=args.cold_trials_attested,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        write_validator_replay_experiment(args.output, result)
    except (OSError, TypeError, ValueError) as exc:
        parser.error(str(exc))

    selection = result["selection"]
    print(
        json.dumps(
            {
                "schema_version": result["schema_version"],
                "status": selection["status"],
                "selected_arm": selection["selected_arm"],
                "eligible_arms": selection["eligible_arms"],
                "experiment_sha256": result["experiment_sha256"],
                "output": str(args.output),
            },
            ensure_ascii=False,
        )
    )
    return 0 if selection["selected_arm"] is not None else 2


if __name__ == "__main__":
    raise SystemExit(main())
