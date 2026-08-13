#!/usr/bin/env python3
"""Create answer-free, hash-bound D0-D4 semantic/discovery run requests."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from zscope.benchmarking.discovery_ablation import (
    ABLATION_ARM_IDS,
    DiscoveryAblationError,
    build_discovery_ablation_plan,
    build_discovery_ablation_run_request,
    write_discovery_ablation_plan,
    write_discovery_ablation_run_request,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-id", required=True)
    parser.add_argument("--answer-free-manifest", required=True, type=Path)
    parser.add_argument("--expected-answer-free-manifest-sha256", required=True)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--runtime-spec", required=True, type=Path)
    parser.add_argument("--validator-config", required=True, type=Path)
    parser.add_argument("--model-spec", required=True, type=Path)
    parser.add_argument("--scanner-bundle-sha256", required=True)
    parser.add_argument("--rule-catalog-sha256", required=True)
    parser.add_argument("--prompt-bundle-sha256", required=True)
    parser.add_argument("--production-executor-sha256", required=True)
    parser.add_argument("--legacy-executor-sha256", required=True)
    parser.add_argument("--arm-catalog", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--requests-dir",
        type=Path,
        help="Optionally materialize all 25 external-harness run requests.",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        plan = build_discovery_ablation_plan(
            dataset_id=args.dataset_id,
            answer_free_manifest=args.answer_free_manifest,
            expected_answer_free_manifest_sha256=(args.expected_answer_free_manifest_sha256),
            config=args.config,
            runtime_spec=args.runtime_spec,
            validator_config=args.validator_config,
            model_spec=args.model_spec,
            scanner_bundle_sha256=args.scanner_bundle_sha256,
            rule_catalog_sha256=args.rule_catalog_sha256,
            prompt_bundle_sha256=args.prompt_bundle_sha256,
            production_executor_sha256=args.production_executor_sha256,
            legacy_executor_sha256=args.legacy_executor_sha256,
            catalog_path=args.arm_catalog,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        write_discovery_ablation_plan(args.output, plan, catalog_path=args.arm_catalog)
        request_count = 0
        if args.requests_dir is not None:
            args.requests_dir.mkdir(parents=True, exist_ok=True)
            for arm_id in ABLATION_ARM_IDS:
                for trial_index in range(1, 6):
                    request = build_discovery_ablation_run_request(
                        plan,
                        arm_id=arm_id,
                        trial_index=trial_index,
                        expected_plan_sha256=plan["plan_sha256"],
                        catalog_path=args.arm_catalog,
                    )
                    write_discovery_ablation_run_request(
                        args.requests_dir / f"{arm_id.lower()}-trial-{trial_index}.json",
                        request,
                        catalog_path=args.arm_catalog,
                    )
                    request_count += 1
    except (DiscoveryAblationError, OSError, TypeError, ValueError) as exc:
        parser.error(str(exc))
    print(
        json.dumps(
            {
                "schema_version": plan["schema_version"],
                "dataset_id": plan["answer_free_input"]["dataset_id"],
                "arms": list(ABLATION_ARM_IDS),
                "cold_trials_per_arm": 5,
                "expected_max_tokens_per_run": 12_000_000,
                "validator_config_sha256": plan["config_identity"]["validator_config_sha256"],
                "config_identity_sha256": plan["config_identity"]["combined_sha256"],
                "plan_sha256": plan["plan_sha256"],
                "request_count": request_count,
                "output": str(args.output),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
