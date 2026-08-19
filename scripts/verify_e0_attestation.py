#!/usr/bin/env python3
"""Verify a protected-workflow E0 attestation and its external run identity."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Mapping, Sequence

from e0_review_governance import E0GovernanceError, load_json_strict, validate_e0_attestation


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attestation", required=True, type=Path)
    parser.add_argument("--workflow-run-id", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        value = load_json_strict(args.attestation.resolve(strict=True))
        if not isinstance(value, Mapping):
            raise E0GovernanceError("E0 attestation must be an object")
        validate_e0_attestation(
            value,
            expected_workflow_run_id=args.workflow_run_id,
            expected_head_sha=args.head_sha,
        )
    except (E0GovernanceError, OSError) as exc:
        print(f"invalid E0 attestation: {exc}", file=sys.stderr)
        return 2
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(dict(value), indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
