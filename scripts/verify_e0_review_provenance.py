#!/usr/bin/env python3
"""Verify protected E0 review provenance against external workflow identity."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Mapping, Sequence

from e0_review_governance import (
    E0GovernanceError,
    load_json_strict,
    validate_review_provenance,
)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provenance", required=True, type=Path)
    parser.add_argument("--workflow-run-id", required=True)
    parser.add_argument("--workflow-head-sha", required=True)
    parser.add_argument("--packet-source-sha", required=True)
    parser.add_argument("--artifact-digest", required=True)
    args = parser.parse_args(argv)
    try:
        value = load_json_strict(args.provenance.resolve(strict=True))
        if not isinstance(value, Mapping):
            raise E0GovernanceError("review provenance must be an object")
        validate_review_provenance(
            value,
            expected_workflow_run_id=args.workflow_run_id,
            expected_workflow_head_sha=args.workflow_head_sha,
            expected_packet_source_sha=args.packet_source_sha,
            expected_artifact_digest=args.artifact_digest,
        )
    except (E0GovernanceError, OSError) as exc:
        print(f"invalid E0 review provenance: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
