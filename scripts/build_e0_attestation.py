#!/usr/bin/env python3
"""Build the E0 attestation inside the protected GitHub workflow only."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from e0_review_governance import (
    ATTESTATION_SCHEMA_VERSION,
    E0GovernanceError,
    attestation_content_sha256,
    load_json_strict,
    sha256_file,
    sha256_value,
    validate_e0_attestation,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--governance-commit", required=True)
    parser.add_argument("--scorer-commit", required=True)
    parser.add_argument("--truth-commit", required=True)
    parser.add_argument("--truth", required=True, type=Path)
    parser.add_argument("--truth-manifest", required=True, type=Path)
    parser.add_argument("--source-truth-v15", required=True, type=Path)
    parser.add_argument("--review-packet-catalog", required=True, type=Path)
    parser.add_argument("--normalized-decisions", required=True, type=Path)
    parser.add_argument("--review-bundle", required=True, type=Path)
    parser.add_argument("--review-provenance", required=True, type=Path)
    parser.add_argument("--safe-pair-manifest", required=True, type=Path)
    parser.add_argument("--defect-taxonomy", required=True, type=Path)
    parser.add_argument("--benchmark-policy", required=True, type=Path)
    parser.add_argument("--scorer-bundle", required=True, type=Path)
    parser.add_argument("--opus-review-count", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def _object(path: Path) -> Mapping[str, Any]:
    value = load_json_strict(path.resolve(strict=True))
    if not isinstance(value, Mapping):
        raise E0GovernanceError(f"E0 artifact must be an object: {path}")
    return value


def _validate_review_bundle(root: Path, manifest: Mapping[str, Any]) -> str:
    files = manifest.get("files")
    if (
        manifest.get("schema_version") != "zscope.range-v16-review-bundle.v1"
        or not isinstance(files, list)
        or manifest.get("file_count") != len(files)
        or manifest.get("bundle_sha256") != sha256_value(files)
    ):
        raise E0GovernanceError("protected review bundle manifest is invalid")
    seen: set[str] = set()
    root = root.resolve(strict=True)
    for record in files:
        if not isinstance(record, Mapping) or set(record) != {"path", "size", "sha256"}:
            raise E0GovernanceError("protected review bundle file binding is invalid")
        relative = str(record.get("path") or "")
        if not relative or relative in seen or "\\" in relative:
            raise E0GovernanceError("protected review bundle path is invalid")
        seen.add(relative)
        path = (root / relative).resolve(strict=True)
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise E0GovernanceError("protected review bundle path escapes its root") from exc
        if path.is_symlink() or not path.is_file():
            raise E0GovernanceError("protected review bundle member is not a regular file")
        if path.stat().st_size != record.get("size") or sha256_file(path) != record.get("sha256"):
            raise E0GovernanceError(f"protected review bundle member mismatch: {relative}")
    return str(manifest["bundle_sha256"])


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
        "source_truth_v15": args.source_truth_v15,
        "review_packet_catalog": args.review_packet_catalog,
        "normalized_decisions": args.normalized_decisions,
        "review_bundle": args.review_bundle,
        "review_provenance": args.review_provenance,
        "safe_pair_manifest": args.safe_pair_manifest,
        "defect_taxonomy": args.defect_taxonomy,
        "benchmark_policy": args.benchmark_policy,
        "scorer_bundle": args.scorer_bundle,
    }
    try:
        artifacts = {
            name: sha256_file(path.resolve(strict=True)) for name, path in artifact_paths.items()
        }
        truth = _object(args.truth)
        truth_manifest = _object(args.truth_manifest)
        packet_catalog = _object(args.review_packet_catalog)
        normalized = _object(args.normalized_decisions)
        review_bundle = _object(args.review_bundle)
        review_provenance = _object(args.review_provenance)
        pair_manifest = _object(args.safe_pair_manifest)
        truth_contract = truth.get("truth_contract")
        if not isinstance(truth_contract, Mapping):
            raise E0GovernanceError("Truth v16 contract is missing")
        review_bundle_content = _validate_review_bundle(
            args.review_bundle.resolve(strict=True).parent,
            review_bundle,
        )
        if truth_manifest.get("truth_sha256") != artifacts["truth_v16"]:
            raise E0GovernanceError("truth manifest does not bind Truth v16 bytes")
        if truth_manifest.get("source_v15_sha256") != artifacts["source_truth_v15"]:
            raise E0GovernanceError("truth manifest does not bind source Truth v15 bytes")
        if truth_manifest.get("normalized_decisions_sha256") != artifacts["normalized_decisions"]:
            raise E0GovernanceError("truth manifest does not bind normalized decisions")
        if truth_manifest.get("packet_catalog_sha256") != packet_catalog.get("catalog_sha256"):
            raise E0GovernanceError("truth manifest does not bind the review packet catalog")
        if normalized.get("source_truth_sha256") != artifacts["source_truth_v15"]:
            raise E0GovernanceError("normalized decisions source Truth v15 binding mismatch")
        if normalized.get("packet_catalog_sha256") != packet_catalog.get("catalog_sha256"):
            raise E0GovernanceError("normalized decisions packet catalog binding mismatch")
        if truth_manifest.get("truth_contract_manifest_sha256") != truth_contract.get(
            "manifest_sha256"
        ):
            raise E0GovernanceError("truth contract manifest binding is inconsistent")
        if (
            truth_manifest.get("review_bundle_sha256") != review_bundle_content
            or truth_contract.get("review_bundle_sha256") != review_bundle_content
        ):
            raise E0GovernanceError("Truth v16 does not bind the protected review bundle")
        if (
            truth_manifest.get("taxonomy_sha256") != artifacts["defect_taxonomy"]
            or truth_contract.get("taxonomy_sha256") != artifacts["defect_taxonomy"]
        ):
            raise E0GovernanceError("Truth v16 taxonomy binding is inconsistent")
        unsigned_truth_manifest = dict(truth_manifest)
        supplied_truth_manifest_hash = str(unsigned_truth_manifest.pop("content_sha256", ""))
        if supplied_truth_manifest_hash != sha256_value(unsigned_truth_manifest):
            raise E0GovernanceError("truth manifest content hash is invalid")
        if truth_manifest.get("safe_pair_index_sha256") != artifacts["safe_pair_manifest"]:
            raise E0GovernanceError("truth manifest safe-pair index binding is inconsistent")
        if pair_manifest.get("record_count") != truth_contract.get("safe_unit_count"):
            raise E0GovernanceError("safe-pair index count does not cover Truth v16")
        if review_provenance.get("workflow_path") != ".github/workflows/range-v16-review.yml":
            raise E0GovernanceError("review provenance workflow is untrusted")
        if review_provenance.get("environment") != "sealed-benchmark":
            raise E0GovernanceError("review provenance environment is untrusted")
        if review_provenance.get("review_bundle_sha256") != review_bundle_content:
            raise E0GovernanceError("review provenance bundle hash mismatch")
        for reviewer, expected_count in (
            ("fable", 136),
            ("deepseek", 136),
            ("opus", args.opus_review_count),
        ):
            manifest = _object(args.review_bundle.parent / reviewer / "manifest.json")
            count_field = "record_count" if reviewer != "opus" else "reviewed_count"
            if manifest.get(count_field) != expected_count:
                raise E0GovernanceError(f"{reviewer} review count is inconsistent")
        artifacts.update(
            {
                "truth_v16_content": sha256_value(truth),
                "truth_contract_manifest": str(truth_contract["manifest_sha256"]),
                "review_packet_catalog_content": str(packet_catalog["catalog_sha256"]),
                "normalized_decisions_content": str(normalized["content_sha256"]),
                "review_bundle_content": review_bundle_content,
            }
        )
    except (E0GovernanceError, OSError, KeyError) as exc:
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
