from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

from scripts.check_p1_runtime_reachability import REQUIRED_WHEEL_ENTRIES
from scripts.check_p5_runtime_authority_package import (
    RELEASE_STATUS,
    REQUIRED_ENTRIES,
    SUCCESSOR_QUALIFICATION,
    wheel_errors,
)
from zscope.orchestration.proof_promotion_qualification import SOURCE_BOUND_PATHS


ROOT = Path(__file__).resolve().parents[1]


def _status(*, value: str = "in_progress") -> dict:
    body = {
        "schema_version": "zscope.p5-release-status.v1",
        "phase": "P5",
        "status": value,
        "reviewed_commit": "",
        "reviewed_tree": "",
        "qualification_manifest_sha256": "",
        "review_artifact_sha256": {
            "product_architecture": "",
            "proof_security": "",
        },
    }
    payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {**body, "content_sha256": hashlib.sha256(payload).hexdigest()}


def _wheel(
    path: Path,
    *,
    omit_status: bool = False,
    tamper: bool = False,
    legacy_adapter: bool = False,
    omit_successor: bool = False,
    tamper_successor_source: bool = False,
) -> None:
    entries = set(REQUIRED_WHEEL_ENTRIES) | set(REQUIRED_ENTRIES) | set(SOURCE_BOUND_PATHS)
    with zipfile.ZipFile(path, "w") as archive:
        for name in entries:
            if name == RELEASE_STATUS:
                if omit_status:
                    continue
                status = _status()
                if tamper:
                    status["cache_epoch"] = "pre-p5"
                archive.writestr(name, json.dumps(status))
            elif name == SUCCESSOR_QUALIFICATION:
                if omit_successor:
                    continue
                archive.writestr(name, (ROOT / name).read_bytes())
            elif name in SOURCE_BOUND_PATHS:
                source_bytes = (ROOT / name).read_bytes()
                if legacy_adapter and name == "zscope/agents/proof_engine/agent.py":
                    source_bytes = b"def submit_validator_evidence_claim(): pass\n"
                if tamper_successor_source and name.endswith("closure.py"):
                    source_bytes += b"\n# tampered\n"
                archive.writestr(name, source_bytes)
            else:
                source = (
                    "def submit_validator_evidence_claim(): pass\n"
                    if legacy_adapter and name == "zscope/agents/proof_engine/agent.py"
                    else ""
                )
                archive.writestr(name, source)


def test_p5_package_gate_accepts_content_addressed_in_progress_candidate(
    tmp_path: Path,
) -> None:
    wheel = tmp_path / "candidate.whl"
    _wheel(wheel)

    assert wheel_errors(wheel, expected_status="in_progress") == []


def test_p5_package_gate_rejects_missing_or_tampered_release_latch(tmp_path: Path) -> None:
    missing = tmp_path / "missing.whl"
    _wheel(missing, omit_status=True)
    assert any("release-status" in value for value in wheel_errors(missing))

    tampered = tmp_path / "tampered.whl"
    _wheel(tampered, tamper=True)
    assert any("release status invalid" in value for value in wheel_errors(tampered))


def test_p5_package_gate_rejects_legacy_proof_adapter_path(tmp_path: Path) -> None:
    wheel = tmp_path / "legacy-adapter.whl"
    _wheel(wheel, legacy_adapter=True)

    assert any("forbidden legacy adapter path" in value for value in wheel_errors(wheel))


def test_p5_package_gate_requires_exact_successor_qualification(tmp_path: Path) -> None:
    missing = tmp_path / "missing-successor.whl"
    _wheel(missing, omit_successor=True)
    assert any(SUCCESSOR_QUALIFICATION in value for value in wheel_errors(missing))

    tampered_source = tmp_path / "tampered-successor-source.whl"
    _wheel(tampered_source, tamper_successor_source=True)
    assert any(
        "successor-bound source hash mismatch" in value for value in wheel_errors(tampered_source)
    )
