#!/usr/bin/env python3
"""Run one frozen Validator arm against an answer-free replay bundle."""

from __future__ import annotations

import argparse
import importlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Optional, Sequence, cast

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from zscope.benchmarking.replay_bundle import load_validator_replay_bundle
from zscope.benchmarking.replay_provider import (
    BuiltinProviderReplayExecutor,
    assert_expected_builtin_identity,
)
from zscope.benchmarking.validator_replay import (
    ReplayExecutor,
    load_validator_arm_catalog,
    run_validator_replay,
    validator_arm,
    write_validator_replay_run,
)


def _load_executor(reference: str) -> ReplayExecutor:
    module_name, separator, attribute = str(reference or "").partition(":")
    if not separator or not module_name or not attribute:
        raise ValueError("executor must use the form package.module:callable")
    value: Any = getattr(importlib.import_module(module_name), attribute)
    if isinstance(value, type):
        value = value()
    if not callable(value) and not callable(getattr(value, "execute", None)):
        raise ValueError("executor reference is not callable and has no execute() method")
    return cast(ReplayExecutor, value)


def _reject_truth_environment() -> None:
    forbidden = [
        key
        for key, value in os.environ.items()
        if value and ("GROUND_TRUTH" in key.upper() or "BENCHMARK_TRUTH" in key.upper())
    ]
    if forbidden:
        raise ValueError(
            "validator replay refuses truth-bearing environment variables: "
            + ", ".join(sorted(forbidden))
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--expected-bundle-sha256", required=True)
    parser.add_argument("--arm", required=True, choices=tuple("ABCDE"))
    parser.add_argument("--arm-catalog", type=Path)
    parser.add_argument("--trial-index", type=int, default=1)
    parser.add_argument(
        "--expected-total-tokens",
        type=int,
        required=False,
        help=("Optional post-run cost expectation. It never rejects or truncates a replay call."),
    )
    executor_group = parser.add_mutually_exclusive_group()
    executor_group.add_argument(
        "--executor",
        default="",
        help=(
            "External package.module:callable adapter. Required for Arm E until a "
            "replay-safe legacy session interface exists. This in-process path is "
            "always non-formal; it cannot self-attest OCI isolation."
        ),
    )
    executor_group.add_argument(
        "--builtin-provider-config",
        type=Path,
        help=(
            "Strict answer-free zscope.validator-replay-provider.v1 JSON config. "
            "Supported for Arms A-D only."
        ),
    )
    parser.add_argument(
        "--expected-executor-sha256",
        "--executor-sha256",
        dest="executor_sha256",
        required=True,
    )
    parser.add_argument(
        "--expected-model-spec-sha256",
        "--model-spec-sha256",
        dest="model_spec_sha256",
        required=True,
    )
    parser.add_argument(
        "--expected-prompt-sha256",
        "--prompt-sha256",
        dest="prompt_sha256",
        required=True,
    )
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    executor: Optional[ReplayExecutor] = None,
) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        _reject_truth_environment()
        expected_identity = {
            "executor_sha256": args.executor_sha256,
            "model_spec_sha256": args.model_spec_sha256,
            "prompt_sha256": args.prompt_sha256,
        }
        if executor is not None:
            if args.builtin_provider_config is not None or args.executor:
                raise ValueError(
                    "an injected executor cannot be combined with a CLI executor option"
                )
            selected_executor = executor
            execution_identity = expected_identity
            executor_trust = {
                "mode": "untrusted_external",
                "oci_evidence_sha256": "",
            }
        elif args.builtin_provider_config is not None:
            if args.arm == "E":
                raise ValueError(
                    "Arm E has no replay-safe built-in legacy executor; provide an "
                    "explicit external --executor adapter"
                )
            builtin = BuiltinProviderReplayExecutor.from_config(args.builtin_provider_config)
            assert_expected_builtin_identity(builtin, expected_identity)
            selected_executor = builtin
            execution_identity = dict(builtin.execution_identity)
            executor_trust = {
                "mode": "builtin_provider",
                "oci_evidence_sha256": "",
            }
        else:
            selected_executor = _load_executor(args.executor)
            execution_identity = expected_identity
            executor_trust = {
                "mode": "untrusted_external",
                "oci_evidence_sha256": "",
            }
        bundle = load_validator_replay_bundle(args.bundle)
        catalog = load_validator_arm_catalog(args.arm_catalog)
        arm = validator_arm(catalog, args.arm)
        result = run_validator_replay(
            bundle,
            arm,
            executor=selected_executor,
            execution_identity=execution_identity,
            expected_bundle_sha256=args.expected_bundle_sha256,
            arm_catalog_sha256=catalog["catalog_sha256"],
            trial_index=args.trial_index,
            expected_total_tokens=args.expected_total_tokens,
            executor_trust=executor_trust,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        write_validator_replay_run(args.output, result)
    except (ImportError, AttributeError, OSError, TypeError, ValueError) as exc:
        parser.error(str(exc))
    print(
        json.dumps(
            {
                "schema_version": result["schema_version"],
                "arm_id": result["arm_id"],
                "trial_index": result["trial_index"],
                "group_count": result["group_count"],
                "planned_group_count": result["planned_group_count"],
                "expected_total_tokens": result["expected_total_tokens"],
                "cost_expectation_met": result["cost_expectation_met"],
                "executor_usage_scope": result["contract"]["executor_usage_scope"],
                "complete": result["complete"],
                "run_sha256": result["run_sha256"],
                "output": str(args.output),
            },
            ensure_ascii=False,
        )
    )
    return 0 if result["complete"] and result["cost_expectation_met"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
