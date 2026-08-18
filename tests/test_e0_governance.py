from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import run_e0_reviewers as reviewer_runner

from scripts.e0_review_governance import (
    ATTESTATION_SCHEMA_VERSION,
    DECISION_SCHEMA_VERSION,
    E0GovernanceError,
    PACKET_SCHEMA_VERSION,
    attestation_content_sha256,
    sha256_value,
    validate_e0_attestation,
    validate_review_decision,
    validate_review_packet,
)


def _packet() -> dict:
    packet = {
        "schema_version": PACKET_SCHEMA_VERSION,
        "packet_uid": "range-v16:RANGE-001",
        "source_truth_sha256": "1" * 64,
        "truth_record": {"id": "RANGE-001", "category": "bounds"},
        "code_windows": [
            {
                "path": "src/example.c",
                "start_line": 1,
                "end_line": 2,
                "content": "void f(void) {}\nreturn;\n",
                "sha256": hashlib.sha256(
                    b"void f(void) {}\nreturn;\n"
                ).hexdigest(),
            }
        ],
        "threat_assumptions": ["The public function can receive untrusted input."],
        "safe_pair_candidate": {"kind": "fixed"},
        "packet_sha256": "",
    }
    unsigned = dict(packet)
    unsigned.pop("packet_sha256")
    packet["packet_sha256"] = sha256_value(unsigned)
    return packet


def _decision(packet: dict) -> dict:
    return {
        "schema_version": DECISION_SCHEMA_VERSION,
        "packet_uid": packet["packet_uid"],
        "packet_sha256": packet["packet_sha256"],
        "reviewer_role": "primary_fable",
        "reviewer_model": "claude-fable-5",
        "contract_kind": "concrete_trigger",
        "disposition": "keep",
        "confidence": 0.9,
        "defect_taxonomy_id": "bounds",
        "cwe_ids": ["CWE-125"],
        "structured_anchors": [
            {
                "kind": "primary",
                "corrected": False,
                "file": "src/example.c",
                "function": "f",
                "start_line": 1,
                "end_line": 2,
            }
        ],
        "required_evidence_clauses": [
            {
                "clause_id": "path_exists",
                "predicate": "A path reaches the operation.",
                "evidence_refs": ["src/example.c:1-2"],
            }
        ],
        "evidence_refs": ["src/example.c:1"],
        "trigger_summary": "An unchecked path reaches the operation.",
        "threat_assumptions": ["The input is externally controllable."],
        "safe_pair_recommendation": {
            "kind": "fixed",
            "invariant_summary": "The path is guarded.",
            "vulnerable_summary": "The path is unguarded.",
            "safe_summary": "The path is guarded before use.",
            "compile_requirements": ["Compile as C11."],
        },
        "reason_codes": ["TRIGGER_PRESENT", "SAFE_PAIR_REQUIRED"],
    }


def _attestation() -> dict:
    payload = {
        "schema_version": ATTESTATION_SCHEMA_VERSION,
        "issued_at": "2026-08-18T00:00:00+00:00",
        "workflow": {
            "path": ".github/workflows/range-v16-benchmark-v5-attestation.yml",
            "run_id": "123",
            "head_sha": "a" * 40,
            "environment": "sealed-benchmark",
        },
        "component_commits": {
            "governance": "b" * 40,
            "scorer": "c" * 40,
            "truth": "d" * 40,
        },
        "artifacts": {
            "truth_v16": "1" * 64,
            "truth_manifest": "2" * 64,
            "review_bundle": "3" * 64,
            "safe_pair_manifest": "4" * 64,
            "defect_taxonomy": "5" * 64,
            "benchmark_policy": "6" * 64,
            "scorer_bundle": "7" * 64,
        },
        "review_summary": {
            "record_count": 136,
            "dual_review_count": 136,
            "opus_review_count": 12,
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
    return payload


def test_review_packet_and_decision_bind_exact_packet() -> None:
    packet = _packet()
    validate_review_packet(packet)
    validate_review_decision(
        _decision(packet),
        expected_packet_uid=packet["packet_uid"],
        expected_packet_sha256=packet["packet_sha256"],
        expected_role="primary_fable",
    )


@pytest.mark.parametrize(
    "value",
    [
        {"candidate_uid": "secret"},
        {"notes": "copied from benchmark-artifacts/run/report.json"},
        {"nested": [{"text": "api_key=do-not-send"}]},
    ],
)
def test_review_packet_recursively_rejects_product_results_and_credentials(value: dict) -> None:
    packet = _packet()
    packet["safe_pair_candidate"] = value
    unsigned = dict(packet)
    unsigned.pop("packet_sha256")
    packet["packet_sha256"] = sha256_value(unsigned)
    with pytest.raises(E0GovernanceError):
        validate_review_packet(packet)


def test_review_packet_rejects_content_tampering() -> None:
    packet = _packet()
    packet["truth_record"]["category"] = "state_machine"
    with pytest.raises(E0GovernanceError, match="hash mismatch"):
        validate_review_packet(packet)


def test_review_packet_rejects_tampered_code_window_even_after_packet_rehash() -> None:
    packet = _packet()
    packet["code_windows"][0]["content"] = "void changed(void) {}\nreturn;\n"
    unsigned = dict(packet)
    unsigned.pop("packet_sha256")
    packet["packet_sha256"] = sha256_value(unsigned)
    with pytest.raises(E0GovernanceError, match="code window hash"):
        validate_review_packet(packet)


def test_e0_attestation_requires_external_workflow_identity_and_hash() -> None:
    payload = _attestation()
    validate_e0_attestation(payload, expected_workflow_run_id="123", expected_head_sha="a" * 40)
    with pytest.raises(E0GovernanceError, match="run ID"):
        validate_e0_attestation(
            payload,
            expected_workflow_run_id="self-asserted",
            expected_head_sha="a" * 40,
        )
    tampered = deepcopy(payload)
    tampered["invariants"]["matcher_v2_unchanged"] = False
    with pytest.raises(E0GovernanceError):
        validate_e0_attestation(
            tampered,
            expected_workflow_run_id="123",
            expected_head_sha="a" * 40,
        )


def test_primary_reviewer_resume_reuses_verified_outputs_and_finishes_catalog(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    packet_dir = tmp_path / "packets"
    output_dir = tmp_path / "output"
    packet_dir.mkdir()
    (output_dir / "decisions").mkdir(parents=True)
    (output_dir / "raw").mkdir()
    packets: list[dict] = []
    for index in range(136):
        packet = _packet()
        truth_id = f"CASE-{index:03d}"
        packet["packet_uid"] = f"range-v16:{truth_id}"
        packet["truth_record"]["id"] = truth_id
        unsigned = dict(packet)
        unsigned.pop("packet_sha256")
        packet["packet_sha256"] = sha256_value(unsigned)
        packets.append(packet)
        (packet_dir / f"{truth_id}.json").write_text(
            json.dumps(packet), encoding="utf-8"
        )

    def raw_for(packet: dict) -> dict:
        return {
            "schema_version": "zscope.range-v16-review-raw-envelope.v1",
            "reviewer_role": "primary_fable",
            "reviewer_model": "claude-fable-5",
            "packet_uid": packet["packet_uid"],
            "packet_sha256": packet["packet_sha256"],
            "input_delivery": "embedded_prompt",
            "command_identity": ["claude", "--print"],
            "exit_code": 0,
            "stdout": "{}",
            "stderr_sha256": sha256_value(""),
        }

    first = packets[0]
    first_decision = _decision(first)
    first_decision["packet_uid"] = first["packet_uid"]
    first_decision["packet_sha256"] = first["packet_sha256"]
    (output_dir / "decisions" / "CASE-000.json").write_text(
        json.dumps(first_decision), encoding="utf-8"
    )
    (output_dir / "raw" / "CASE-000.json").write_text(
        json.dumps(raw_for(first)), encoding="utf-8"
    )

    reviewed: list[str] = []

    def fake_run_model(packet: dict, **_: object) -> tuple[dict, dict]:
        reviewed.append(packet["packet_uid"])
        decision = _decision(packet)
        decision["packet_uid"] = packet["packet_uid"]
        decision["packet_sha256"] = packet["packet_sha256"]
        return decision, raw_for(packet)

    monkeypatch.setattr(reviewer_runner, "_run_model", fake_run_model)
    args = SimpleNamespace(
        packet_dir=packet_dir,
        output_dir=output_dir,
        reviewer="fable",
        workers=4,
        resume=True,
    )
    assert reviewer_runner.run_primary(args) == 0
    assert len(reviewed) == 135
    manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["record_count"] == 136
    assert len(manifest["records"]) == 136
    assert manifest["records"][0]["status"] == "reused"
