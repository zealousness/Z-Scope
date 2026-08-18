#!/usr/bin/env python3
"""Bind a completed E0 review artifact to its protected workflow identity."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from e0_review_governance import (
    E0GovernanceError,
    load_json_strict,
    validate_review_provenance,
)


_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _object(path: Path) -> Mapping[str, Any]:
    value = load_json_strict(path.resolve(strict=True))
    if not isinstance(value, Mapping):
        raise E0GovernanceError(f"artifact must be an object: {path}")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet-catalog", required=True, type=Path)
    parser.add_argument("--review-bundle-manifest", required=True, type=Path)
    parser.add_argument("--artifact-name", required=True)
    parser.add_argument("--artifact-digest", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    run_id = str(os.environ.get("GITHUB_RUN_ID") or "")
    environment = str(os.environ.get("Z_SCOPE_E0_REVIEW_ENVIRONMENT") or "")
    if not run_id.isdigit() or int(run_id) < 1 or environment != "sealed-benchmark":
        print("E0 review provenance requires the sealed protected workflow", file=sys.stderr)
        return 2
    if not _SHA_RE.fullmatch(args.head_sha):
        print("E0 review provenance head SHA is invalid", file=sys.stderr)
        return 2
    if not _DIGEST_RE.fullmatch(args.artifact_digest):
        print("E0 review artifact digest is invalid", file=sys.stderr)
        return 2
    try:
        actual_head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        ).stdout.strip()
        if actual_head != args.head_sha:
            raise E0GovernanceError("review provenance does not bind checked-out HEAD")
        catalog = _object(args.packet_catalog)
        bundle = _object(args.review_bundle_manifest)
        catalog_sha = str(catalog.get("catalog_sha256") or "")
        bundle_sha = str(bundle.get("bundle_sha256") or "")
        if not re.fullmatch(r"[0-9a-f]{64}", catalog_sha) or not re.fullmatch(
            r"[0-9a-f]{64}", bundle_sha
        ):
            raise E0GovernanceError("review component content hashes are invalid")
        payload = {
            "schema_version": "zscope.range-v16-review-provenance.v1",
            "workflow_path": ".github/workflows/range-v16-review.yml",
            "workflow_run_id": int(run_id),
            "head_sha": args.head_sha,
            "environment": environment,
            "artifact_name": args.artifact_name,
            "artifact_digest": args.artifact_digest,
            "packet_catalog_sha256": catalog_sha,
            "review_bundle_sha256": bundle_sha,
        }
        validate_review_provenance(
            payload,
            expected_workflow_run_id=run_id,
            expected_head_sha=args.head_sha,
            expected_artifact_digest=args.artifact_digest,
        )
    except (E0GovernanceError, OSError, subprocess.SubprocessError) as exc:
        print(f"cannot bind E0 review provenance: {exc}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(json.dumps(payload, indent=2).encode("utf-8") + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
