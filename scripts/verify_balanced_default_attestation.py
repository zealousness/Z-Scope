#!/usr/bin/env python3
"""Validate and export an independently produced balanced-default attestation."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from zscope.benchmarking.attestation import load_balanced_attestation


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--attestation", type=Path, required=True)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--workflow-run-id", required=True)
    parser.add_argument(
        "--reject-under",
        type=Path,
        help="Reject an issuer file stored below this scanner checkout/workspace.",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    source = args.attestation.expanduser().resolve(strict=True)
    if args.reject_under is not None:
        rejected_root = args.reject_under.expanduser().resolve(strict=True)
        if _is_within(source, rejected_root):
            raise SystemExit(
                "independent attestation source must not be stored in the scanner checkout"
            )

    result = load_balanced_attestation(
        source,
        release_sha=str(args.release_sha),
        workflow_run_id=str(args.workflow_run_id),
    )
    if result.get("passed") is not True:
        raise SystemExit(
            "balanced-default attestation is invalid: "
            + json.dumps(result.get("errors") or [], ensure_ascii=False)
        )

    output = args.output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, output)
    print(
        json.dumps(
            {
                "passed": True,
                "attestation_id": result.get("attestation_id"),
                "content_sha256": result.get("content_sha256"),
                "output": str(output),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
