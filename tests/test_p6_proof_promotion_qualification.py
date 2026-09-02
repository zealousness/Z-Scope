from __future__ import annotations

import copy
import json
import sys
from pathlib import Path, PurePath

import pytest
import zscope

from scripts.qualify_p6_proof_promotion import main as qualify_main
from scripts.qualify_p6_proof_promotion import qualify
from zscope.core.validation.proof_kernel.canonical import content_sha256
from zscope.orchestration import proof_promotion_qualification as qualification
from zscope.orchestration.successor_runtime_review_status import (
    validate_successor_runtime_review_status,
)


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


def test_generator_atomically_reseals_qualification_and_in_progress_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    qualification_path = tmp_path / "qualification.json"
    status_path = tmp_path / "status.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "qualify_p6_proof_promotion.py",
            "--output",
            str(qualification_path),
            "--status-output",
            str(status_path),
        ],
    )

    assert qualify_main() == 0
    generated = json.loads(qualification_path.read_text(encoding="utf-8"))
    status = json.loads(status_path.read_text(encoding="utf-8"))
    assert generated == qualify()
    assert validate_successor_runtime_review_status(
        status,
        expected_implementation_root_sha256=generated["implementation_root_sha256"],
        expected_successor_qualification_sha256=generated["content_sha256"],
    ) == (True, "valid")
    assert status["status"] == "in_progress"
    assert status["candidate_git_sha"] == ""
    assert status["review_set_sha256"] == ""


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
        "zscope/core/candidates/clang_ast_cfg.py",
        "zscope/core/candidates/cpp_domains/concurrency_shared_state.py",
        "zscope/core/candidates/cpp_domains/resource_lifecycle.py",
        "zscope/core/candidates/regex.py",
        "zscope/core/validation/evidence_completion.py",
        "zscope/core/validation/runner.py",
        "zscope/orchestration/candidate_envelope.py",
        "zscope/orchestration/candidates.py",
        "zscope/orchestration/parallel_analyzer.py",
        "zscope/retrieval/clang_backend.py",
        "zscope/retrieval/clang_extractor.py",
        "zscope/retrieval/knowledge_db.py",
        "zscope/benchmarking/runner.py",
        "zscope/framework/llm_client.py",
        "zscope/orchestration/successor_runtime_review_status.py",
        "zscope/reporting/assembler.py",
        "zscope/reporting/finding_roots.py",
        "zscope/reporting/report.py",
        "zscope/reporting/schema.py",
        "zscope/reporting/views.py",
        "zscope/semantics/security_map.py",
        "zscope/rules/builtin_catalog.yaml",
        "zscope/rules/qualification_registry.yaml",
    }

    assert required.issubset(set(qualification.SOURCE_BOUND_PATHS))


def test_successor_source_bindings_are_package_local_and_answer_free() -> None:
    forbidden = ("ground_truth", "ground-truth", "/truth/", "scorer", "/packets/", "/reviews/")

    assert len(qualification.SOURCE_BOUND_PATHS) == len(set(qualification.SOURCE_BOUND_PATHS))
    assert all(path.startswith("zscope/") for path in qualification.SOURCE_BOUND_PATHS)
    assert set(qualification.current_source_hashes()) == set(qualification.SOURCE_BOUND_PATHS)
    assert not (
        set(qualification.IMPLEMENTATION_ROOT_EXCLUDED_PATHS)
        & set(qualification.SOURCE_BOUND_PATHS)
    )
    assert all(
        not any(token in f"/{path.casefold()}/" for token in forbidden)
        for path in qualification.SOURCE_BOUND_PATHS
    )
    packaged = qualification.load_successor_qualification()
    assert packaged["implementation_root_sha256"] == qualification.implementation_root_sha256(
        packaged["source_sha256"]
    )


def test_successor_source_set_equals_every_regular_packaged_file_minus_explicit_exclusions() -> (
    None
):
    package_root = Path(zscope.__file__).resolve().parent
    all_regular = {
        "zscope/" + path.relative_to(package_root).as_posix()
        for path in package_root.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    expected = {
        path
        for path in all_regular
        if not qualification._implementation_path_excluded(path, name=PurePath(path).name)
    }

    assert set(qualification.SOURCE_BOUND_PATHS) == expected


@pytest.mark.parametrize(
    "path",
    (
        "zscope/retrieval/knowledge_db.py",
        "zscope/semantics/security_map.py",
    ),
)
def test_successor_rejects_missing_graph_lineage_source_binding(path: str) -> None:
    generated = qualify()
    assert path in generated["source_sha256"]
    generated["source_sha256"].pop(path)
    generated = _reseal(generated)

    valid, reason = qualification.validate_successor_qualification(generated)

    assert valid is False
    assert reason == "successor_qualification_source_set_mismatch"


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
