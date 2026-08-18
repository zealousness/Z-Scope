import copy
from pathlib import Path

import pytest

from scripts.check_zscope_2_design_evidence import (
    DESIGN_MANIFEST,
    DuplicateJsonKeyError,
    load_json,
    main,
    resolve_repository_path,
    validate_design_evidence,
    validate_formal_review_documents,
    validate_json_schema,
    validate_phase_gates,
)


ROOT = Path(__file__).resolve().parents[1]
DESIGN_ROOT = ROOT / DESIGN_MANIFEST.parent


def _design_documents() -> tuple[dict, dict, dict]:
    manifest = load_json(DESIGN_ROOT / "design-manifest.json")
    evidence = load_json(DESIGN_ROOT / "acceptance" / "evidence-index.json")
    schema = load_json(DESIGN_ROOT / "acceptance" / "evidence-index.schema.json")
    return manifest, evidence, schema


def _formal_review_documents() -> tuple[dict, dict, dict]:
    manifest, _, _ = _design_documents()
    formal = manifest["formal_reviews"]
    schema = load_json(DESIGN_ROOT / formal["schema"])
    reviews = {
        role: load_json(DESIGN_ROOT / spec["path"]) for role, spec in formal["artifacts"].items()
    }
    return manifest, reviews, schema


def test_current_design_evidence_is_consistent_without_ignored_artifacts() -> None:
    report = validate_design_evidence(ROOT)

    assert report.errors == []
    assert len(report.warnings) in {0, 3}
    if report.warnings:
        assert all(
            "external hash-bound artifact is unavailable locally" in row for row in report.warnings
        )


def test_strict_external_artifact_check_fails_when_archives_are_not_copied() -> None:
    report = validate_design_evidence(ROOT, strict_external_artifacts=True)

    assert len(report.errors) in {0, 3}
    assert report.warnings == []
    if report.errors:
        assert all("bound artifact does not exist" in row for row in report.errors)


def test_evidence_schema_rejects_unknown_and_missing_governance_fields() -> None:
    _, evidence, schema = _design_documents()
    mutated = copy.deepcopy(evidence)
    mutated["evidence"][0]["unreviewed_override"] = True
    del mutated["evidence"][0]["verification"]

    errors = validate_json_schema(mutated, schema)

    assert any("unexpected property 'unreviewed_override'" in row for row in errors)
    assert any("missing required property 'verification'" in row for row in errors)


def test_phase_gate_rejects_starting_p1_before_p0_completion_and_approval() -> None:
    manifest, evidence, _ = _design_documents()
    mutated_manifest = copy.deepcopy(manifest)
    mutated_evidence = copy.deepcopy(evidence)
    mutated_manifest["status"] = "reviewed"
    mutated_manifest["phase_status"]["P0"] = "in_progress"
    mutated_manifest["phase_status"]["P1"] = "in_progress"
    mutated_manifest["approval"]["approved_at"] = ""
    mutated_manifest["approval"]["approved_commit"] = ""
    mutated_manifest["approval"]["tag_created"] = False
    for phase in mutated_evidence["phases"]:
        if phase["phase"] == "P0":
            phase["status"] = "in_progress"
        if phase["phase"] == "P1":
            phase["status"] = "in_progress"

    errors = validate_phase_gates(mutated_manifest, mutated_evidence)

    assert any("before P0 completion" in row for row in errors)
    assert any("approved or later" in row for row in errors)


def test_reviewed_design_cannot_claim_an_approval_tag() -> None:
    manifest, evidence, _ = _design_documents()
    mutated = copy.deepcopy(manifest)
    mutated_evidence = copy.deepcopy(evidence)
    mutated["status"] = "reviewed"
    mutated["phase_status"]["P0"] = "in_progress"
    mutated["approval"]["tag_created"] = True
    for phase in mutated_evidence["phases"]:
        if phase["phase"] == "P0":
            phase["status"] = "in_progress"

    errors = validate_phase_gates(mutated, mutated_evidence)

    assert "reviewed design must not claim that its approval tag was created" in errors


def test_p0_completion_requires_three_approved_role_separated_reviews() -> None:
    manifest, reviews, schema = _formal_review_documents()
    mutated = copy.deepcopy(reviews)
    mutated["proof_security"]["decision"] = "changes_required"
    mutated["proof_security"]["blocking_findings"] = [
        {
            "id": "BLOCK-1",
            "severity": "high",
            "title": "synthetic blocker",
            "evidence": "test mutation",
            "required_action": "reject completion",
        }
    ]

    errors = validate_formal_review_documents(manifest, mutated, schema, require_approval=True)

    assert any("requires an approved review decision" in row for row in errors)
    assert any("requires zero blocking findings" in row for row in errors)


def test_formal_reviews_bind_one_common_commit_and_tree() -> None:
    manifest, reviews, schema = _formal_review_documents()
    mutated = copy.deepcopy(reviews)
    mutated["independent_benchmark"]["reviewed_tree"] = "0" * 40

    errors = validate_formal_review_documents(manifest, mutated, schema, require_approval=True)

    assert any("reviewed tree differs from the common review target" in row for row in errors)


def test_proof_security_review_records_max_reasoning_and_read_only_mode() -> None:
    _, reviews, _ = _formal_review_documents()

    harness = reviews["proof_security"]["harness"]
    assert "reasoning_effort=max" in harness
    assert "permission_mode=read-only" in harness


def test_repository_path_resolution_rejects_escape() -> None:
    with pytest.raises(ValueError, match="unsafe repository-relative path"):
        resolve_repository_path(ROOT, "../ground_truth.json")


def test_json_loader_rejects_duplicate_governance_keys(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.json"
    path.write_text('{"status": "reviewed", "status": "approved"}\n', encoding="utf-8")

    with pytest.raises(DuplicateJsonKeyError, match="duplicate JSON key: status"):
        load_json(path)


def test_design_evidence_cli_reports_external_limitations(capsys) -> None:
    code = main(["--repo-root", str(ROOT)])

    captured = capsys.readouterr()
    assert code == 0
    assert "design evidence valid" in captured.out
    assert "external limitation(s)" in captured.out
    if "0 external limitation(s)" in captured.out:
        assert captured.err == ""
    else:
        assert "WARNING:" in captured.err
