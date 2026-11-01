#!/usr/bin/env python3
"""Compare Validator model throughput on one answer-free evidence sample.

This is a non-scoring preflight.  It deterministically selects the first N
canonical validation groups from one validated replay bundle, runs every model
against the exact same subset, and records protocol validity plus successful
packs per minute.  It never accepts a truth path or benchmark answer material.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from zscope.benchmarking.replay_bundle import (  # noqa: E402
    canonical_json_sha256,
    load_validator_replay_bundle,
    validate_validator_replay_bundle,
)
from zscope.benchmarking.replay_provider import (  # noqa: E402
    BuiltinProviderReplayExecutor,
    ReplayProviderSpec,
)
from zscope.benchmarking.validator_replay import (  # noqa: E402
    load_validator_arm_catalog,
    run_validator_replay,
    validator_arm,
    write_validator_replay_run,
)
from zscope.reporting.json_io import write_report_atomic  # noqa: E402


SCHEMA_VERSION = "zscope.validator-model-throughput-preflight.v1"


def _subset_bundle(
    bundle: Mapping[str, Any],
    group_count: int,
    *,
    start_index: int = 0,
) -> Dict[str, Any]:
    if group_count <= 0:
        raise ValueError("group_count must be positive")
    if start_index < 0:
        raise ValueError("start_index must be non-negative")
    groups = bundle.get("canonical_groups")
    if not isinstance(groups, list) or len(groups) < start_index + group_count:
        raise ValueError("replay bundle has fewer groups than requested")
    subset = copy.deepcopy(dict(bundle))
    subset["canonical_groups"] = copy.deepcopy(groups[start_index : start_index + group_count])
    subset["group_count"] = group_count
    subset.pop("bundle_sha256", None)
    subset["bundle_sha256"] = canonical_json_sha256(subset)
    validate_validator_replay_bundle(subset)
    return subset


def _run_metrics(
    model: str,
    result: Mapping[str, Any],
    elapsed_seconds: float,
) -> Dict[str, Any]:
    groups = result.get("groups")
    groups = groups if isinstance(groups, list) else []
    successful = sum(
        1
        for row in groups
        if isinstance(row, Mapping)
        and row.get("execution_status") == "complete"
        and row.get("protocol_valid") is True
    )
    protocol_error_groups = sum(
        1 for row in groups if isinstance(row, Mapping) and row.get("protocol_valid") is not True
    )
    total = len(groups)
    return {
        "model": model,
        "group_count": total,
        "successful_group_count": successful,
        "protocol_error_group_count": protocol_error_groups,
        "protocol_error_rate": round(protocol_error_groups / total, 6) if total else 1.0,
        "elapsed_seconds": round(max(0.0, elapsed_seconds), 3),
        "successful_packs_per_minute": (
            round(successful * 60.0 / elapsed_seconds, 4) if elapsed_seconds > 0 else 0.0
        ),
        "complete": result.get("complete") is True,
        "run_sha256": str(result.get("run_sha256") or ""),
        "usage": copy.deepcopy(dict(result.get("usage") or {})),
    }


def _recommended_model(
    rows: Sequence[Mapping[str, Any]],
    *,
    speedup_threshold: float,
) -> tuple[str, str]:
    if len(rows) != 2:
        return "", "comparison_requires_exactly_two_models"
    primary, secondary = rows
    primary_rate = float(primary.get("successful_packs_per_minute") or 0.0)
    secondary_rate = float(secondary.get("successful_packs_per_minute") or 0.0)
    primary_errors = float(primary.get("protocol_error_rate") or 0.0)
    secondary_errors = float(secondary.get("protocol_error_rate") or 0.0)
    if (
        secondary_rate > primary_rate
        and (primary_rate == 0.0 or secondary_rate >= primary_rate * speedup_threshold)
        and secondary_errors <= primary_errors
    ):
        return str(secondary.get("model") or ""), "secondary_meets_speed_and_protocol_gate"
    return str(primary.get("model") or ""), "keep_primary_model"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--model", action="append", required=True)
    parser.add_argument("--group-count", type=int, default=20)
    parser.add_argument("--start-index", type=int, default=0)
    parser.add_argument("--arm", choices=tuple("ABCD"), default="B")
    parser.add_argument("--arm-catalog", type=Path)
    parser.add_argument("--base-url-env", default="Z_SCOPE_LLM_BASE_URL")
    parser.add_argument("--api-key-env", default="Z_SCOPE_API_KEY")
    parser.add_argument("--timeout-seconds", type=float, default=180.0)
    parser.add_argument(
        "--supports-structured-output",
        action=argparse.BooleanOptionalAction,
        default=False,
    )
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--switch-speedup", type=float, default=1.2)
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if len(args.model) != 2 or len(set(args.model)) != 2:
        raise SystemExit("--model must be supplied exactly twice with distinct IDs")
    if args.switch_speedup < 1.0:
        raise SystemExit("--switch-speedup must be at least 1.0")
    base_url = str(os.environ.get(args.base_url_env) or "").strip()
    api_key = str(os.environ.get(args.api_key_env) or "")
    if not base_url or not api_key:
        raise SystemExit("configured base URL and API key environment variables are required")

    source = load_validator_replay_bundle(args.bundle)
    subset = _subset_bundle(source, args.group_count, start_index=args.start_index)
    catalog = load_validator_arm_catalog(args.arm_catalog)
    arm = validator_arm(catalog, args.arm)
    args.output_dir.mkdir(parents=True, exist_ok=True)

    rows: list[Dict[str, Any]] = []
    for trial_index, model in enumerate(args.model, start=1):
        spec = ReplayProviderSpec(
            base_url=base_url.rstrip("/"),
            api_key_env=args.api_key_env,
            model=model,
            timeout_seconds=args.timeout_seconds,
            supports_structured_output=args.supports_structured_output,
            temperature=args.temperature,
        )
        executor = BuiltinProviderReplayExecutor(spec, api_key)
        raw_protocol_audit: list[Dict[str, Any]] = []

        class CapturingExecutor:
            def execute(self, call: Any) -> Mapping[str, Any]:
                response = executor.execute(call)
                raw_protocol_audit.append(
                    {
                        "validation_cluster_uid": call.validation_cluster_uid,
                        "candidate_uid": call.candidate_uid,
                        "call_index": call.call_index,
                        "call_kind": call.call_kind,
                        "validation_pass": call.validation_pass,
                        "result": copy.deepcopy(response.get("result")),
                        "provider_response": copy.deepcopy(
                            executor.last_provider_response
                        ),
                    }
                )
                return response

        started = time.monotonic()
        result = run_validator_replay(
            subset,
            arm,
            executor=CapturingExecutor(),
            execution_identity=executor.execution_identity,
            expected_bundle_sha256=subset["bundle_sha256"],
            arm_catalog_sha256=catalog["catalog_sha256"],
            trial_index=trial_index,
            executor_trust={"mode": "builtin_provider", "oci_evidence_sha256": ""},
        )
        elapsed = time.monotonic() - started
        ledger_path = args.output_dir / f"{trial_index:02d}-{model.replace('/', '_')}.json"
        write_validator_replay_run(ledger_path, result)
        audit_path = args.output_dir / (
            f"{trial_index:02d}-{model.replace('/', '_')}-raw-protocol.json"
        )
        audit_payload = {
            "schema_version": "zscope.validator-model-raw-protocol-audit.v1",
            "answer_material_present": False,
            "truth_access": "forbidden",
            "model": model,
            "sample_bundle_sha256": subset["bundle_sha256"],
            "calls": raw_protocol_audit,
        }
        audit_payload["audit_sha256"] = canonical_json_sha256(audit_payload)
        write_report_atomic(audit_path, audit_payload)
        row = _run_metrics(model, result, elapsed)
        row["ledger"] = ledger_path.name
        row["raw_protocol_audit"] = audit_path.name
        rows.append(row)

    recommendation, reason = _recommended_model(
        rows,
        speedup_threshold=args.switch_speedup,
    )
    summary = {
        "schema_version": SCHEMA_VERSION,
        "answer_material_present": False,
        "truth_access": "forbidden",
        "source_bundle_sha256": source["bundle_sha256"],
        "sample_bundle_sha256": subset["bundle_sha256"],
        "sample_group_count": subset["group_count"],
        "sample_start_index": args.start_index,
        "selection": "validation_cluster_uid_ascending_contiguous_slice",
        "arm_id": args.arm,
        "switch_speedup_threshold": args.switch_speedup,
        "models": rows,
        "recommended_model": recommendation,
        "recommendation_reason": reason,
    }
    summary["summary_sha256"] = canonical_json_sha256(summary)
    summary_path = args.output_dir / "summary.json"
    write_report_atomic(summary_path, summary)
    print(
        json.dumps(
            {
                "schema_version": summary["schema_version"],
                "sample_group_count": summary["sample_group_count"],
                "models": rows,
                "recommended_model": recommendation,
                "recommendation_reason": reason,
                "summary": str(summary_path),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
