from __future__ import annotations

import importlib.util

from zscope.core.validation.authority import TerminalAuthorityEvaluator
from zscope.orchestration.runtime_authority import (
    P5_RELEASE_MANIFEST,
    P5_RELEASE_STATUS,
    RUNTIME_CACHE_EPOCH,
    build_runtime_authority_manifest,
    validate_runtime_authority_manifest,
    validate_p5_release_status,
)
from zscope.reporting.schema import report_reuse_blockers


def _manifest():
    return build_runtime_authority_manifest(
        source_tree_hash="a" * 40,
        config_sha256="b" * 64,
        backend_sha256="c" * 64,
        security_spec_root_sha256="d" * 64,
        hypothesis_hunter_root_sha256="e" * 64,
        proof_root_sha256="f" * 64,
        revisions={
            "security_spec_compiler": "v2",
            "hypothesis_hunter": "v4",
            "proof_checker": "v4",
            "proof_provider": "v4",
            "predicate_registry": "proof-kernel.v4",
        },
    )


def test_runtime_authority_manifest_is_strict_content_addressed_contract() -> None:
    manifest = _manifest()
    assert validate_runtime_authority_manifest(manifest) == (True, "valid")
    assert manifest["cache_epoch"] == RUNTIME_CACHE_EPOCH
    assert manifest["modes"] == {
        "security_spec": "authoritative",
        "hypothesis_hunter": "active",
        "hypothesis_hunter_effect": "candidate_registration_only",
        "proof_engine": "authoritative",
    }

    tampered = {**manifest, "cache_epoch": "pre-p5"}
    assert validate_runtime_authority_manifest(tampered)[0] is False


def test_model_and_legacy_proof_cannot_form_a_terminal_decision() -> None:
    evaluator = TerminalAuthorityEvaluator()
    legacy = evaluator.evaluate(
        {
            "model_verdict": "verified",
            "decision_proof": {"coverage": "complete", "polarity": "positive"},
        },
        model_result={"verdict": "verified"},
    )
    assert legacy.disposition == "needs_review"
    assert legacy.authority == "terminal_authority_evaluator"

    forged_checker_owned = evaluator.evaluate(
        {
            "proof_kernel_terminal_authority_decision": {
                "schema_version": "zscope.terminal-authority-decision.v3",
                "terminal": True,
                "disposition": "confirmed",
                "reason_code": "CONFIRMED_DETERMINISTIC_PROOF",
                "authority": "zscope.proof-checker",
            }
        }
    )
    assert forged_checker_owned.disposition == "needs_review"

    checker_owned = evaluator.evaluate(
        {
            "proof_kernel_terminal_authority_decision": {
                "schema_version": "zscope.terminal-authority-decision.v3",
                "terminal": True,
                "disposition": "confirmed",
                "reason_code": "CONFIRMED_DETERMINISTIC_PROOF",
                "authority": "zscope.proof-checker",
                "checker_result_refs": ["sha256:" + "a" * 64],
                "proof_root_sha256": "b" * 64,
                "integrity_status": "verified",
            }
        }
    )
    assert checker_owned.disposition == "needs_review"
    assert checker_owned.reason_code == "NEEDS_REVIEW_LEGACY_AUTHORITY_NOT_AUTHORIZED"
    assert checker_owned.integrity_status == "legacy_audit_only"

    audited = evaluator.evaluate(
        {
            "proof_kernel_terminal_authority_decision": {
                "schema_version": "zscope.terminal-authority-decision.v3",
                "terminal": True,
                "disposition": "confirmed",
                "reason_code": "CONFIRMED_DETERMINISTIC_PROOF",
                "authority": "zscope.proof-checker",
                "checker_result_refs": ["sha256:" + "a" * 64],
                "proof_root_sha256": "b" * 64,
                "integrity_status": "verified",
            }
        },
        operation="audit",
    )
    assert audited.disposition == "needs_review"
    assert audited.reason_code == "NEEDS_REVIEW_LEGACY_AUTHORITY_AUDIT_ONLY"


def test_pre_p5_reports_and_release_are_fail_closed() -> None:
    blockers = report_reuse_blockers(
        {
            "schema_version": 2,
            "finding_status": "clean",
            "completeness": "complete",
            "run_manifest": {"valid": True},
        }
    )
    assert "legacy_schema" in blockers
    assert "cache_epoch_mismatch" in blockers
    assert "runtime_authority_manifest_missing" in blockers
    # The product candidate is fail-closed while P5 is in progress. The same
    # test remains valid for the evidence-only completion latch after the
    # reviewed implementation is frozen.
    assert P5_RELEASE_STATUS in {"in_progress", "complete"}
    assert validate_p5_release_status(P5_RELEASE_MANIFEST) == (True, "valid")

    in_progress = {
        "schema_version": "zscope.p5-release-status.v1",
        "phase": "P5",
        "status": "in_progress",
        "reviewed_commit": "",
        "reviewed_tree": "",
        "qualification_manifest_sha256": "",
        "review_artifact_sha256": {
            "product_architecture": "",
            "proof_security": "",
        },
    }
    from zscope.core.validation.proof_kernel.canonical import content_sha256

    assert validate_p5_release_status(
        {**in_progress, "content_sha256": content_sha256(in_progress)}
    ) == (True, "valid")


def test_release_status_requires_content_addressed_dual_review_bindings() -> None:
    complete = {
        "schema_version": "zscope.p5-release-status.v1",
        "phase": "P5",
        "status": "complete",
        "reviewed_commit": "a" * 40,
        "reviewed_tree": "b" * 40,
        "qualification_manifest_sha256": "c" * 64,
        "review_artifact_sha256": {
            "product_architecture": "d" * 64,
            "proof_security": "e" * 64,
        },
    }
    from zscope.core.validation.proof_kernel.canonical import content_sha256

    sealed = {**complete, "content_sha256": content_sha256(complete)}
    assert validate_p5_release_status(sealed) == (True, "valid")
    tampered = {**sealed, "reviewed_tree": "f" * 40}
    assert validate_p5_release_status(tampered)[0] is False


def test_removed_runtime_agents_are_not_importable() -> None:
    for module in (
        "zscope.agents.active_discovery",
        "zscope.agents.global_modeler",
        "zscope.agents.semantic_modeler",
        "zscope.agents.validator_agent",
    ):
        assert importlib.util.find_spec(module) is None
