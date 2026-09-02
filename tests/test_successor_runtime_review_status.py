from __future__ import annotations

import ast
import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from zscope.orchestration import runtime_authority
from zscope.orchestration import successor_runtime_review_status as review_status


def content_sha256(value: dict) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _reseal(raw: dict) -> dict:
    body = {key: value for key, value in raw.items() if key != "content_sha256"}
    return {**body, "content_sha256": content_sha256(body)}


def _reviewed_projection() -> dict:
    raw = copy.deepcopy(review_status.SUCCESSOR_RUNTIME_REVIEW_MANIFEST)
    raw.update(
        {
            "status": "reviewed",
            "candidate_git_sha": "1" * 40,
            "candidate_git_tree": "2" * 40,
            "p6_qualification_file_sha256": "3" * 64,
            "p6_qualification_content_sha256": "4" * 64,
            "p6_final_evidence_manifest_file_sha256": "5" * 64,
            "evidence_bundle_sha256": "6" * 64,
            "review_set_sha256": "7" * 64,
        }
    )
    for index, role in enumerate(review_status.SUCCESSOR_REVIEW_ROLES, start=1):
        raw["reviewer_roots"][role] = {
            "artifact_id": str(index),
            "artifact_sha256": f"{10 + index:064x}",
            "packet_sha256": f"{20 + index:064x}",
            "decision_sha256": f"{30 + index:064x}",
            "raw_envelope_sha256": f"{40 + index:064x}",
            "reviewer_identity_sha256": review_status._REVIEWER_IDENTITY_SHA256[role],
            "review_artifact_sha256": f"{50 + index:064x}",
            "decision": "approved",
            "blocker_count": 0,
        }
    return _reseal(raw)


def test_current_successor_status_is_structural_and_always_non_release() -> None:
    raw = review_status.SUCCESSOR_RUNTIME_REVIEW_MANIFEST

    assert review_status.validate_successor_runtime_review_status(raw) == (True, "valid")
    assert raw["p6_formal_benchmark"] is False
    assert raw["p6_release_eligible"] is False
    assert raw["status"] in {"in_progress", "reviewed"}
    expected_reviewed = raw["status"] == "reviewed"
    assert review_status.current_successor_reviewed() is expected_reviewed
    assert runtime_authority.current_successor_reviewed() is expected_reviewed


def test_reviewed_projection_requires_every_exact_independent_root() -> None:
    reviewed = _reviewed_projection()
    assert review_status.validate_successor_runtime_review_status(reviewed) == (True, "valid")

    duplicated = copy.deepcopy(reviewed)
    duplicated["reviewer_roots"]["proof_security"] = copy.deepcopy(
        duplicated["reviewer_roots"]["product_architecture"]
    )
    duplicated = _reseal(duplicated)
    valid, reason = review_status.validate_successor_runtime_review_status(duplicated)
    assert valid is False
    assert reason == "successor_review_status_reviewer_roots_invalid"


def test_coordinator_reseal_cannot_become_current_without_physical_bundle(
    monkeypatch, tmp_path: Path
) -> None:
    reviewed = _reviewed_projection()
    monkeypatch.setattr(
        review_status,
        "load_successor_qualification",
        lambda: {
            "implementation_root_sha256": reviewed["implementation_root_sha256"],
            "content_sha256": reviewed["successor_qualification_sha256"],
        },
    )
    monkeypatch.setattr(review_status.resources, "files", lambda _package: tmp_path)

    assert review_status.validate_successor_runtime_review_status(reviewed) == (True, "valid")
    assert review_status.validate_current_successor_runtime_review_status(reviewed) == (
        False,
        "successor_review_evidence_unavailable",
    )


def test_in_progress_current_resource_requires_evidence_and_receipt_absent(
    monkeypatch, tmp_path: Path
) -> None:
    in_progress = review_status.build_in_progress_successor_runtime_review_status(
        {
            "implementation_root_sha256": "a" * 64,
            "content_sha256": "b" * 64,
        }
    )
    monkeypatch.setattr(
        review_status,
        "load_successor_qualification",
        lambda: {
            "implementation_root_sha256": "a" * 64,
            "content_sha256": "b" * 64,
        },
    )
    monkeypatch.setattr(review_status.resources, "files", lambda _package: tmp_path)
    assert review_status.validate_current_successor_runtime_review_status(in_progress) == (
        False,
        "successor_review_in_progress",
    )

    (tmp_path / review_status.SUCCESSOR_REVIEW_EVIDENCE_DIRECTORY).mkdir()
    assert review_status.validate_current_successor_runtime_review_status(in_progress) == (
        False,
        "successor_review_in_progress_contains_review_evidence",
    )


@pytest.mark.parametrize(
    ("relative", "directory"),
    (
        (review_status.SUCCESSOR_REVIEW_EVIDENCE_DIRECTORY, True),
        (review_status.SUCCESSOR_REVIEW_INTEGRATION_RECEIPT_RESOURCE, False),
    ),
)
def test_in_progress_rejects_broken_review_resource_symlink(
    monkeypatch, tmp_path: Path, relative: str, directory: bool
) -> None:
    in_progress = review_status.build_in_progress_successor_runtime_review_status(
        {
            "implementation_root_sha256": "a" * 64,
            "content_sha256": "b" * 64,
        }
    )
    monkeypatch.setattr(
        review_status,
        "load_successor_qualification",
        lambda: {
            "implementation_root_sha256": "a" * 64,
            "content_sha256": "b" * 64,
        },
    )
    monkeypatch.setattr(review_status.resources, "files", lambda _package: tmp_path)
    link = tmp_path / relative
    try:
        link.symlink_to(tmp_path / "missing-target", target_is_directory=directory)
    except OSError:
        pytest.skip("symlinks are unavailable on this platform")
    assert link.is_symlink() and not link.exists()
    assert review_status.validate_current_successor_runtime_review_status(in_progress) == (
        False,
        "successor_review_in_progress_contains_review_evidence",
    )


def test_reviewed_current_resource_requires_bound_integration_receipt(
    monkeypatch, tmp_path: Path
) -> None:
    reviewed = _reviewed_projection()
    monkeypatch.setattr(
        review_status,
        "load_successor_qualification",
        lambda: {
            "implementation_root_sha256": reviewed["implementation_root_sha256"],
            "content_sha256": reviewed["successor_qualification_sha256"],
        },
    )
    monkeypatch.setattr(review_status.resources, "files", lambda _package: tmp_path)
    bundle = tmp_path / review_status.SUCCESSOR_REVIEW_EVIDENCE_DIRECTORY
    bundle.mkdir()
    (bundle / "evidence.json").write_text("{}\n", encoding="utf-8")
    reviewed["evidence_bundle_sha256"] = review_status._regular_tree_sha256(bundle)
    reviewed = _reseal(reviewed)
    monkeypatch.setattr(
        review_status,
        "load_successor_qualification",
        lambda: {
            "implementation_root_sha256": reviewed["implementation_root_sha256"],
            "content_sha256": reviewed["successor_qualification_sha256"],
        },
    )
    assert review_status.validate_current_successor_runtime_review_status(reviewed) == (
        False,
        "successor_review_evidence_unavailable",
    )

    receipt = tmp_path / review_status.SUCCESSOR_REVIEW_INTEGRATION_RECEIPT_RESOURCE
    receipt.write_text("{}\n", encoding="utf-8")
    assert review_status.validate_current_successor_runtime_review_status(reviewed) == (
        False,
        "successor_review_evidence_binding_mismatch",
    )

    receipt.write_text(
        json.dumps(review_status._integration_receipt_projection(reviewed)) + "\n",
        encoding="utf-8",
    )
    assert review_status.validate_current_successor_runtime_review_status(reviewed) == (
        True,
        "current_successor_reviewed",
    )
    (bundle / "unbound.json").write_text("{}\n", encoding="utf-8")
    assert review_status.validate_current_successor_runtime_review_status(reviewed) == (
        False,
        "successor_review_evidence_binding_mismatch",
    )


def test_live_status_module_has_no_benchmark_or_heavy_projector_dependency() -> None:
    source = Path(review_status.__file__).read_text(encoding="utf-8")
    imported_modules = {
        node.module
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }
    imported_modules.update(
        alias.name
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Import)
        for alias in node.names
    )
    assert not any(name.startswith("zscope.benchmarking") for name in imported_modules)
    assert "successor_review_evidence" not in imported_modules
    assert "project_successor_runtime_review_status" not in source
    assert "import_module" not in source
    assert "__import__" not in source

    isolated = subprocess.run(
        [
            sys.executable,
            "-S",
            "-c",
            (
                "import sys; "
                "import zscope.orchestration.runtime_authority; "
                "assert not any(name == 'zscope.benchmarking' or "
                "name.startswith('zscope.benchmarking.') for name in sys.modules); "
                "assert not any(name == 'zscope.agents' or "
                "name.startswith('zscope.agents.') for name in sys.modules); "
                "assert 'zscope.orchestration.successor_review_evidence' not in sys.modules; "
                "assert 'zscope.orchestration.successor_review_integration' not in sys.modules; "
                "assert 'zscope.framework.llm_client' not in sys.modules; "
                "assert 'requests' not in sys.modules"
            ),
        ],
        check=False,
        cwd=Path(__file__).resolve().parents[1],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert isolated.returncode == 0


def test_current_status_fails_closed_when_shared_qualification_is_stale(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        review_status,
        "load_successor_qualification",
        lambda: (_ for _ in ()).throw(ValueError("successor_qualification_source_stale")),
    )

    assert review_status.validate_current_successor_runtime_review_status(
        review_status.SUCCESSOR_RUNTIME_REVIEW_MANIFEST
    ) == (False, "successor_review_status_qualification_not_current")


def test_live_qualification_recomputes_current_source_bytes(monkeypatch) -> None:
    current = review_status.current_source_hashes()
    path = next(iter(current))
    tampered = {**current, path: "0" * 64 if current[path] != "0" * 64 else "1" * 64}
    monkeypatch.setattr(review_status, "current_source_hashes", lambda: tampered)

    with pytest.raises(ValueError, match="successor_review_qualification_source_stale"):
        review_status.load_successor_qualification()


def test_integration_receipt_requires_exact_fields_seal_and_status_binding(tmp_path: Path) -> None:
    reviewed = _reviewed_projection()
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "evidence.json").write_text("{}\n", encoding="utf-8")
    reviewed["evidence_bundle_sha256"] = review_status._regular_tree_sha256(bundle)
    reviewed = _reseal(reviewed)
    receipt = review_status._integration_receipt_projection(reviewed)
    assert review_status._integration_receipt_valid(receipt, expected_status=reviewed) is True

    extra = {**receipt, "unbound": True}
    assert review_status._integration_receipt_valid(extra, expected_status=reviewed) is False
    forged = {**receipt, "review_set_sha256": "f" * 64}
    forged = _reseal(forged)
    assert review_status._integration_receipt_valid(forged, expected_status=reviewed) is False


def test_reviewed_projection_requires_approved_zero_blocker_decisions() -> None:
    reviewed = _reviewed_projection()

    unapproved = copy.deepcopy(reviewed)
    unapproved["reviewer_roots"]["proof_security"]["decision"] = ""
    unapproved = _reseal(unapproved)
    assert review_status.validate_successor_runtime_review_status(unapproved) == (
        False,
        "successor_review_status_reviewer_roots_invalid",
    )

    blocked = copy.deepcopy(reviewed)
    blocked["reviewer_roots"]["proof_security"]["blocker_count"] = 1
    blocked = _reseal(blocked)
    assert review_status.validate_successor_runtime_review_status(blocked) == (
        False,
        "successor_review_status_reviewer_roots_invalid",
    )

    boolean_blocker = copy.deepcopy(reviewed)
    boolean_blocker["reviewer_roots"]["proof_security"]["blocker_count"] = False
    boolean_blocker = _reseal(boolean_blocker)
    assert review_status.validate_successor_runtime_review_status(boolean_blocker) == (
        False,
        "successor_review_status_reviewer_roots_invalid",
    )


def test_schema_and_python_relational_validation_have_explicit_boundary() -> None:
    reviewed = _reviewed_projection()
    schema = json.loads(
        (
            Path(__file__).resolve().parents[1]
            / "zscope/orchestration/schemas/successor-runtime-review-status-v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    assert schema["$schema"].endswith("2020-12/schema")
    reviewed_roots = schema["allOf"][1]["then"]["properties"]["reviewer_roots"]
    assert {row["$ref"] for row in reviewed_roots["properties"].values()} == {
        "#/$defs/reviewedReviewerRoot"
    }
    assert review_status.validate_successor_runtime_review_status(reviewed) == (
        True,
        "valid",
    )

    # JSON Schema cannot express uniqueness between differently named role
    # properties.  The Python relational validator must reject the collision.
    duplicated = copy.deepcopy(reviewed)
    duplicated["reviewer_roots"]["proof_security"] = copy.deepcopy(
        duplicated["reviewer_roots"]["product_architecture"]
    )
    duplicated = _reseal(duplicated)
    # Every role is independently valid against the same schema ref, so JSON
    # Schema has no cross-property uniqueness relation to reject this object.
    # The Python validator owns and rejects that relational constraint.
    assert review_status.validate_successor_runtime_review_status(duplicated) == (
        False,
        "successor_review_status_reviewer_roots_invalid",
    )

    boolean_blocker = copy.deepcopy(reviewed)
    boolean_blocker["reviewer_roots"]["proof_security"]["blocker_count"] = False
    boolean_blocker = _reseal(boolean_blocker)
    assert schema["$defs"]["reviewedReviewerRoot"]["allOf"][1]["properties"]["blocker_count"] == {
        "const": 0
    }
    assert review_status.validate_successor_runtime_review_status(boolean_blocker)[0] is False


def test_in_progress_projection_cannot_claim_review_or_p6_release() -> None:
    in_progress = review_status.build_in_progress_successor_runtime_review_status(
        {
            "implementation_root_sha256": "a" * 64,
            "content_sha256": "b" * 64,
        }
    )
    claimed = copy.deepcopy(in_progress)
    claimed["candidate_git_sha"] = "a" * 40
    claimed = _reseal(claimed)
    assert review_status.validate_successor_runtime_review_status(claimed) == (
        False,
        "successor_review_in_progress_must_not_claim_evidence",
    )

    released = copy.deepcopy(in_progress)
    released["p6_release_eligible"] = True
    released = _reseal(released)
    assert review_status.validate_successor_runtime_review_status(released) == (
        False,
        "successor_review_status_p6_non_release_boundary_invalid",
    )
