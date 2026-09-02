#!/usr/bin/env python3
"""Freeze or score one selected P6 cold-balanced producer."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from zscope.benchmarking.p6_balanced_orchestrator import (
    BalancedRunIdentity,
    P6BalancedOrchestratorError,
    freeze_balanced_scan,
    revalidate_balanced_quality_bundle,
    score_frozen_balanced_scan,
    verify_committed_local_balanced_evidence,
)
from zscope.benchmarking.p6_protocol import derive_p6_artifact_canaries


def _identity(args: argparse.Namespace) -> BalancedRunIdentity:
    return BalancedRunIdentity(
        workflow_run_id=args.workflow_run_id,
        workflow_run_attempt=args.workflow_run_attempt,
        attempt_id=args.attempt_id,
        control_plane_commit=args.control_plane_commit,
        candidate_git_sha=args.candidate_git_sha,
        candidate_git_tree=args.candidate_git_tree,
    )


def _freeze(args: argparse.Namespace) -> int:
    freeze_balanced_scan(
        aggregate_path=args.aggregate,
        report_path=args.report,
        producer_metrics_path=args.producer_metrics,
        projection_path=args.producer_projection,
        provider_config_path=args.provider_config,
        identity=_identity(args),
        output=args.output,
        literal_canaries=derive_p6_artifact_canaries(
            workflow_run_id=args.workflow_run_id,
            workflow_run_attempt=args.workflow_run_attempt,
            candidate_git_sha=args.candidate_git_sha,
        ),
    )
    return 0


def _score(args: argparse.Namespace) -> int:
    score_frozen_balanced_scan(
        frozen_root=args.frozen_root,
        projection_path=args.producer_projection,
        legacy_truth_path=args.legacy_truth,
        v16_truth_path=args.v16_truth,
        identity=_identity(args),
        output=args.output,
        repository_root=args.repository_root,
        failure_aggregate_path=args.failure_aggregate,
    )
    return 0


def _revalidate(args: argparse.Namespace) -> int:
    revalidate_balanced_quality_bundle(
        restored_bundle=args.restored_bundle,
        legacy_truth_path=args.legacy_truth,
        v16_truth_path=args.v16_truth,
        identity=_identity(args),
        output=args.output,
        receipt_path=args.receipt,
        repository_root=args.repository_root,
    )
    return 0


def _verify_local_evidence(args: argparse.Namespace) -> int:
    verify_committed_local_balanced_evidence(
        repository_root=args.repository_root,
        hosted_control_plane_commit=args.hosted_control_plane_commit,
        evidence_commit=args.evidence_commit,
        expected_receipt_sha256=args.receipt_sha256,
    )
    return 0


def _add_identity(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--workflow-run-id", required=True)
    parser.add_argument("--workflow-run-attempt", type=int, required=True)
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--control-plane-commit", required=True)
    parser.add_argument("--candidate-git-sha", required=True)
    parser.add_argument("--candidate-git-tree", required=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    freeze = commands.add_parser("freeze")
    _add_identity(freeze)
    freeze.add_argument("--aggregate", type=Path, required=True)
    freeze.add_argument("--report", type=Path, required=True)
    freeze.add_argument("--producer-metrics", type=Path, required=True)
    freeze.add_argument("--producer-projection", type=Path, required=True)
    freeze.add_argument("--provider-config", type=Path, required=True)
    freeze.add_argument("--output", type=Path, required=True)
    freeze.set_defaults(handler=_freeze)

    score = commands.add_parser("score")
    _add_identity(score)
    score.add_argument("--frozen-root", type=Path, required=True)
    score.add_argument("--producer-projection", type=Path, required=True)
    score.add_argument("--legacy-truth", type=Path, required=True)
    score.add_argument("--v16-truth", type=Path, required=True)
    score.add_argument("--repository-root", type=Path, default=Path("."))
    score.add_argument("--output", type=Path, required=True)
    score.add_argument("--failure-aggregate", type=Path)
    score.set_defaults(handler=_score)

    revalidate = commands.add_parser("revalidate")
    _add_identity(revalidate)
    revalidate.add_argument("--restored-bundle", type=Path, required=True)
    revalidate.add_argument("--legacy-truth", type=Path, required=True)
    revalidate.add_argument("--v16-truth", type=Path, required=True)
    revalidate.add_argument("--repository-root", type=Path, default=Path("."))
    revalidate.add_argument("--output", type=Path, required=True)
    revalidate.add_argument("--receipt", type=Path, required=True)
    revalidate.set_defaults(handler=_revalidate)

    local_evidence = commands.add_parser("verify-local-evidence")
    local_evidence.add_argument("--repository-root", type=Path, default=Path("."))
    local_evidence.add_argument("--hosted-control-plane-commit", required=True)
    local_evidence.add_argument("--evidence-commit", required=True)
    local_evidence.add_argument("--receipt-sha256", required=True)
    local_evidence.set_defaults(handler=_verify_local_evidence)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        return int(args.handler(args))
    except (P6BalancedOrchestratorError, OSError, ValueError):
        print(
            "stage=report_finding; class=quality_no_progress_gate_failed:1; count=1",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
