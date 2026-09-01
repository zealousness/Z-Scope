from __future__ import annotations

import copy
import json
from pathlib import Path

from scripts.qualify_p6_proof_promotion import qualify
from zscope.core.validation.proof_kernel.canonical import content_sha256
from zscope.orchestration import proof_promotion_qualification as qualification


ROOT = Path(__file__).resolve().parents[1]


def _reseal(raw: dict) -> dict:
    body = {key: value for key, value in raw.items() if key != "content_sha256"}
    return {**body, "content_sha256": content_sha256(body)}


def test_successor_replay_matches_packaged_local_candidate() -> None:
    generated = qualify()
    packaged = qualification.load_successor_qualification()

    assert generated == packaged
    assert packaged["status"] == "local_candidate_qualified"
    assert packaged["requires_independent_review"] is True
    assert packaged["authorizes_phase_completion"] is False
    assert packaged["answer_free"] is True
    assert packaged["network"] is False
    assert packaged["llm_calls"] == 0
    assert packaged["case_counts"]["safe_false_confirmation_count"] == 0


def test_successor_artifact_conforms_to_strict_schema() -> None:
    schema = json.loads(
        (
            ROOT
            / "zscope/orchestration/schemas"
            / "p6-proof-promotion-qualification-v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    packaged = qualification.load_successor_qualification()
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(packaged)
    assert schema["properties"]["schema_version"]["const"] == packaged["schema_version"]
    assert schema["properties"]["status"]["const"] == packaged["status"]
    protocol_schema = schema["properties"]["protocol_identity"]
    assert protocol_schema["additionalProperties"] is False
    assert set(protocol_schema["required"]) == set(packaged["protocol_identity"])


def test_successor_binds_every_live_promotion_and_view_surface() -> None:
    required = {
        "zscope/agents/base.py",
        "zscope/agents/proof_engine/agent.py",
        "zscope/alerts/verifier.py",
        "zscope/cli/cli.py",
        "zscope/cli/explain.py",
        "zscope/core/analysis/analyzer.py",
        "zscope/core/validation/evidence_completion.py",
        "zscope/core/validation/runner.py",
        "zscope/orchestration/candidates.py",
        "zscope/orchestration/parallel_analyzer.py",
        "zscope/reporting/assembler.py",
        "zscope/reporting/finding_roots.py",
        "zscope/reporting/report.py",
        "zscope/reporting/schema.py",
        "zscope/reporting/views.py",
    }

    assert required.issubset(set(qualification.SOURCE_BOUND_PATHS))


def test_successor_source_bindings_are_package_local_and_answer_free() -> None:
    forbidden = ("ground_truth", "ground-truth", "/truth/", "scorer", "/packets/", "/reviews/")

    assert len(qualification.SOURCE_BOUND_PATHS) == len(set(qualification.SOURCE_BOUND_PATHS))
    assert all(path.startswith("zscope/") for path in qualification.SOURCE_BOUND_PATHS)
    assert set(qualification.current_source_hashes()) == set(qualification.SOURCE_BOUND_PATHS)
    assert all(
        not any(token in f"/{path.casefold()}/" for token in forbidden)
        for path in qualification.SOURCE_BOUND_PATHS
    )


def test_successor_rejects_authority_escalation_and_content_tamper() -> None:
    packaged = qualification.load_successor_qualification()

    escalated = copy.deepcopy(packaged)
    escalated["authorizes_phase_completion"] = True
    escalated = _reseal(escalated)
    valid, reason = qualification.validate_successor_qualification(escalated)
    assert valid is False
    assert reason == "successor_qualification_authority_boundary_invalid"

    tampered = copy.deepcopy(packaged)
    tampered["case_counts"]["complete_confirmation_count"] += 1
    valid, reason = qualification.validate_successor_qualification(tampered)
    assert valid is False
    assert reason == "successor_qualification_content_hash_mismatch"


def test_successor_freshness_rejects_dependency_or_source_drift(monkeypatch) -> None:
    packaged = qualification.load_successor_qualification()

    dependencies = dict(packaged["qualification_dependencies"])
    dependencies["p4_hypothesis_qualification_sha256"] = "0" * 64
    monkeypatch.setattr(
        qualification,
        "current_dependency_qualifications",
        lambda: dependencies,
    )
    valid, reason = qualification.validate_successor_freshness(packaged)
    assert valid is False
    assert reason == "successor_qualification_dependency_stale"

    monkeypatch.undo()
    sources = dict(packaged["source_sha256"])
    sources["zscope/core/validation/proof_kernel/closure.py"] = "0" * 64
    monkeypatch.setattr(qualification, "current_source_hashes", lambda: sources)
    valid, reason = qualification.validate_successor_freshness(packaged)
    assert valid is False
    assert reason == "successor_qualification_source_stale"
