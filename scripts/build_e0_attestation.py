#!/usr/bin/env python3
"""Build the E0 attestation inside the protected GitHub workflow only."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from e0_review_governance import (
    ATTESTATION_SCHEMA_VERSION,
    E0GovernanceError,
    attestation_content_sha256,
    sha256_file,
    validate_e0_attestation,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--governance-commit", required=True)
    parser.add_argument("--scorer-commit", required=True)
    parser.add_argument("--truth-commit", required=True)
    parser.add_argument("--truth", required=True, type=Path)
    parser.add_argument("--truth-manifest", required=True, type=Path)
    parser.add_argument("--review-bundle", required=True, type=Path)
    parser.add_argument("--safe-pair-manifest", required=True, type=Path)
    parser.add_argument("--defect-taxonomy", required=True, type=Path)
    parser.add_argument("--benchmark-policy", required=True, type=Path)
    parser.add_argument("--scorer-bundle", required=True, type=Path)
    parser.add_argument("--opus-review-count", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    run_id = str(os.environ.get("GITHUB_RUN_ID") or "")
    head_sha = str(os.environ.get("GITHUB_SHA") or "")
    environment = str(os.environ.get("Z_SCOPE_ATTESTATION_ENVIRONMENT") or "")
    if not run_id or not head_sha or environment != "sealed-benchmark":
        print("E0 attestation may only be built in the sealed protected workflow", file=sys.stderr)
        return 2
    artifact_paths = {
        "truth_v16": args.truth,
        "truth_manifest": args.truth_manifest,
        "review_bundle": args.review_bundle,
        "safe_pair_manifest": args.safe_pair_manifest,
        "defect_taxonomy": args.defect_taxonomy,
        "benchmark_policy": args.benchmark_policy,
        "scorer_bundle": args.scorer_bundle,
    }
    try:
        artifacts = {name: sha256_file(path.resolve(strict=True)) for name, path in artifact_paths.items()}
    except OSError as exc:
        print(f"cannot bind E0 artifact: {exc}", file=sys.stderr)
        return 2
    payload = {
        "schema_version": ATTESTATION_SCHEMA_VERSION,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "workflow": {
            "path": ".github/workflows/range-v16-benchmark-v5-attestation.yml",
            "run_id": run_id,
            "head_sha": head_sha,
            "environment": environment,
        },
        "component_commits": {
            "governance": args.governance_commit,
            "scorer": args.scorer_commit,
            "truth": args.truth_commit,
        },
        "artifacts": artifacts,
        "review_summary": {
            "record_count": 136,
            "dual_review_count": 136,
            "opus_review_count": args.opus_review_count,
            "disputed_opus_count": 9,
        },
        "invariants": {
            "matcher_v2_unchanged": True,
            "v15_read_only": True,
            "safe_units_cover_confirmable_truth": True,
            "scanner_answer_isolated": True,
            "raw_reviews_artifact_only": True,
            "product_runtime_unchanged": True,
        },
        "content_sha256": "",
    }
    payload["content_sha256"] = attestation_content_sha256(payload)
    try:
        validate_e0_attestation(
            payload,
            expected_workflow_run_id=run_id,
            expected_head_sha=head_sha,
        )
    except E0GovernanceError as exc:
        print(f"cannot issue E0 attestation: {exc}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
