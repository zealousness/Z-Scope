#!/usr/bin/env python3
"""Verify the P5 authority contract, release latch, UI, and import isolation in a wheel."""

from __future__ import annotations

import argparse
import json
import zipfile
from pathlib import Path
from typing import Optional, Sequence

try:
    from scripts.check_p1_runtime_reachability import wheel_errors as reachability_errors
except ModuleNotFoundError:  # Direct ``python scripts/...`` execution.
    from check_p1_runtime_reachability import wheel_errors as reachability_errors
from zscope.orchestration.runtime_authority import validate_p5_release_status


RELEASE_STATUS = "zscope/orchestration/p5-release-status.json"
REQUIRED_ENTRIES = {
    RELEASE_STATUS,
    "zscope/orchestration/runtime_authority.py",
    "zscope/orchestration/schemas/runtime-authority-manifest-v1.schema.json",
    "zscope/orchestration/schemas/p5-release-status-v1.schema.json",
    "zscope/agents/hypothesis_hunter/AGENT.md",
    "zscope/agents/proof_engine/AGENT.md",
    "zscope/semantics/security_specs/runtime.py",
    "zscope/web/static/index.html",
    "zscope/web/static/offline_template.html",
}
FORBIDDEN_PROOF_ADAPTER_FRAGMENTS = {
    "_run_evidence_slice_protocol",
    "submit_validator_evidence_claim",
    "execute_validator_evidence_action",
    "get_data_flow",
    "claim_verifier",
}


def wheel_errors(path: Path, *, expected_status: str | None = None) -> list[str]:
    errors = list(reachability_errors(path))
    try:
        with zipfile.ZipFile(path) as archive:
            names = set(archive.namelist())
            errors.extend(
                f"wheel missing P5 authority entry: {name}"
                for name in sorted(REQUIRED_ENTRIES - names)
            )
            if RELEASE_STATUS in names:
                raw = json.loads(archive.read(RELEASE_STATUS).decode("utf-8"))
                if not isinstance(raw, dict):
                    errors.append("P5 release status must be an object")
                else:
                    valid, reason = validate_p5_release_status(raw)
                    if not valid:
                        errors.append(f"P5 release status invalid: {reason}")
                    elif expected_status is not None and raw.get("status") != expected_status:
                        errors.append(
                            "P5 release status mismatch: "
                            f"expected {expected_status}, got {raw.get('status')}"
                        )
            proof_agent = "zscope/agents/proof_engine/agent.py"
            if proof_agent in names:
                source = archive.read(proof_agent).decode("utf-8")
                for fragment in sorted(FORBIDDEN_PROOF_ADAPTER_FRAGMENTS):
                    if fragment in source:
                        errors.append(
                            "Proof Engine wheel retains forbidden legacy adapter path: "
                            f"{fragment}"
                        )
    except (OSError, ValueError, UnicodeError, zipfile.BadZipFile) as exc:
        errors.append(f"cannot read P5 wheel contract: {exc}")
    return sorted(set(errors))


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("wheel", type=Path)
    parser.add_argument("--expect-status", choices=("in_progress", "complete"))
    args = parser.parse_args(argv)
    errors = wheel_errors(args.wheel, expected_status=args.expect_status)
    if errors:
        for value in errors:
            print(value)
        return 1
    print("P5 runtime authority wheel gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
