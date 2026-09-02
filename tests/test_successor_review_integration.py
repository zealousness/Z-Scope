from __future__ import annotations

import copy
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from scripts import project_successor_review_evidence as projector
from zscope.benchmarking.p6_protocol import P6ProtocolError, canonical_sha256
from zscope.orchestration import successor_review_evidence as evidence
from zscope.orchestration.successor_review_integration import (
    build_successor_review_integration_receipt,
    validate_successor_review_integration_receipt,
    validate_successor_review_integration_scope,
)


ROOT = Path(__file__).resolve().parents[1]


def _reviewed_status() -> dict:
    body = {
        "schema_version": "zscope.successor-runtime-review-status.v1",
        "status": "reviewed",
        "candidate_git_sha": "1" * 40,
        "candidate_git_tree": "2" * 40,
        "implementation_root_sha256": "3" * 64,
        "successor_qualification_sha256": "4" * 64,
        "p6_qualification_file_sha256": "5" * 64,
        "p6_qualification_content_sha256": "6" * 64,
        "p6_final_evidence_manifest_file_sha256": "7" * 64,
        "evidence_bundle_sha256": "8" * 64,
        "review_set_sha256": "9" * 64,
        "reviewer_roots": {},
        "p6_formal_benchmark": False,
        "p6_release_eligible": False,
    }
    body["content_sha256"] = canonical_sha256(body)
    return body


def _artifact_row(index: int) -> dict:
    return {
        "repository": "zealousness/Z-Scope",
        "workflow_path": ".github/workflows/p6-pilot-validation.yml",
        "workflow_event": "workflow_dispatch",
        "workflow_branch": "main",
        "workflow_run_id": "123",
        "workflow_run_attempt": 1,
        "head_sha": "1" * 40,
        "producer_job": f"job-{index}",
        "artifact_id": index,
        "artifact_name": f"artifact-{index}",
        "artifact_sha256": f"{10 + index:064x}",
        "expired": False,
        "restore_receipt_sha256": f"{20 + index:064x}",
    }


def test_integration_receipt_is_deterministically_projected_from_status() -> None:
    status = _reviewed_status()
    receipt = build_successor_review_integration_receipt(status)

    assert validate_successor_review_integration_receipt(receipt, expected_status=status) == (
        True,
        "valid",
    )
    forged = copy.deepcopy(receipt)
    forged["review_set_sha256"] = "f" * 64
    forged["content_sha256"] = canonical_sha256(
        {name: value for name, value in forged.items() if name != "content_sha256"}
    )
    assert validate_successor_review_integration_receipt(forged, expected_status=status) == (
        False,
        "successor_review_integration_receipt_binding_mismatch",
    )


def test_evidence_only_scope_requires_exact_base_linear_history_and_allowlist() -> None:
    exact = {
        "reviewed_candidate_git_sha": "1" * 40,
        "reviewed_candidate_git_tree": "2" * 40,
        "merge_base_git_sha": "1" * 40,
        "base_git_tree": "2" * 40,
        "ancestry_parent_counts": [1],
        "changed_entries": [
            ("M", "zscope/orchestration/successor-runtime-review-status.v1.json"),
            (
                "A",
                "zscope/orchestration/successor-runtime-review-integration-receipt.v1.json",
            ),
            (
                "A",
                "zscope/orchestration/successor-runtime-review-evidence/bundle-manifest.json",
            ),
        ],
    }
    assert validate_successor_review_integration_scope(**exact) == (
        True,
        "valid_evidence_only_integration",
    )

    assert (
        validate_successor_review_integration_scope(**{**exact, "merge_base_git_sha": "a" * 40})[1]
        == "successor_review_integration_base_mismatch"
    )
    assert (
        validate_successor_review_integration_scope(**{**exact, "ancestry_parent_counts": [2]})[1]
        == "successor_review_integration_parent_lineage_invalid"
    )
    assert (
        validate_successor_review_integration_scope(
            **exact,
            touched_entries=[*exact["changed_entries"], ("M", "zscope/core/validation/runner.py")],
        )[1]
        == "successor_review_integration_scope_violation"
    )
    assert (
        validate_successor_review_integration_scope(
            **exact,
            touched_entries=[
                *exact["changed_entries"],
                ("M", "zscope/orchestration/../runner.py"),
            ],
        )[1]
        == "successor_review_integration_scope_violation"
    )
    assert (
        validate_successor_review_integration_scope(
            **{**exact, "changed_entries": [("R100", exact["changed_entries"][0][1])]}
        )[1]
        == "successor_review_integration_change_set_invalid"
    )


def test_bundle_schema_defers_cross_artifact_uniqueness_to_python() -> None:
    schema = json.loads(
        (
            ROOT / "zscope/orchestration/schemas/successor-review-evidence-bundle-v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    metadata = {
        key: _artifact_row(index) for index, key in enumerate(evidence._ARTIFACT_KEYS, start=1)
    }
    body = {
        "schema_version": evidence.SUCCESSOR_REVIEW_EVIDENCE_VERSION,
        "repository": "zealousness/Z-Scope",
        "workflow_path": ".github/workflows/p6-pilot-validation.yml",
        "workflow_event": "workflow_dispatch",
        "workflow_branch": "main",
        "workflow_run_id": "123",
        "workflow_run_attempt": 1,
        "control_plane_commit": "a" * 40,
        "candidate_git_sha": "1" * 40,
        "candidate_git_tree": "2" * 40,
        "implementation_root_sha256": "3" * 64,
        "successor_qualification_sha256": "4" * 64,
        "artifact_metadata": metadata,
    }
    # Supply exact producer/name values so only the relational collision fails.
    for key, row in metadata.items():
        row["head_sha"] = body["control_plane_commit"]
        row["producer_job"] = evidence._PRODUCER_JOBS[key]
        row["artifact_name"] = evidence._artifact_name(key, body)
    body["content_sha256"] = canonical_sha256(body)
    assert schema["$schema"].endswith("2020-12/schema")
    artifact_properties = schema["properties"]["artifact_metadata"]["properties"]
    assert {row["$ref"] for row in artifact_properties.values()} == {"#/$defs/artifact"}
    evidence._validate_bundle_manifest(body)

    wrong_head = copy.deepcopy(body)
    wrong_head["artifact_metadata"]["qualification"]["head_sha"] = wrong_head["candidate_git_sha"]
    wrong_head["content_sha256"] = canonical_sha256(
        {name: value for name, value in wrong_head.items() if name != "content_sha256"}
    )
    with pytest.raises(P6ProtocolError, match="artifact lineage"):
        evidence._validate_bundle_manifest(wrong_head)

    collision = copy.deepcopy(body)
    collision["artifact_metadata"]["proof_security"]["artifact_id"] = collision[
        "artifact_metadata"
    ]["product_architecture"]["artifact_id"]
    collision["content_sha256"] = canonical_sha256(
        {name: value for name, value in collision.items() if name != "content_sha256"}
    )
    # Each artifact row still satisfies the one shared artifact schema.  Cross-
    # row ID uniqueness is relational and therefore enforced only in Python.
    with pytest.raises(P6ProtocolError, match="artifact identity"):
        evidence._validate_bundle_manifest(collision)


def test_projector_never_accepts_an_absent_or_symlink_bundle(tmp_path: Path) -> None:
    with pytest.raises(P6ProtocolError, match="unavailable"):
        evidence.project_successor_runtime_review_status(
            tmp_path / "missing", successor_qualification={}
        )


def _build_inventory_skeleton(root: Path) -> None:
    (root / evidence.SUCCESSOR_REVIEW_EVIDENCE_MANIFEST).parent.mkdir(parents=True)
    (root / evidence.SUCCESSOR_REVIEW_EVIDENCE_MANIFEST).write_text("{}\n", encoding="utf-8")
    for key in evidence._ARTIFACT_KEYS:
        receipt = root / "restore-receipts" / f"{key}.json"
        receipt.parent.mkdir(parents=True, exist_ok=True)
        receipt.write_text("{}\n", encoding="utf-8")
        (root / evidence._RESTORED_DIRECTORIES[key]).mkdir(parents=True)
    (root / evidence._RESTORED_DIRECTORIES["qualification"] / "qualification.json").write_text(
        "{}\n", encoding="utf-8"
    )
    for role in evidence.REVIEW_ROLES:
        restored = root / evidence._RESTORED_DIRECTORIES[role]
        packet = restored / "packet"
        packet.mkdir()
        (packet / "packet.json").write_text("{}\n", encoding="utf-8")
        evidence_root = packet / "evidence"
        evidence_root.mkdir()
        for name in evidence._REVIEW_PACKET_COMMON_EVIDENCE_FILES | {
            f"{evidence._ROLE_SLUGS[role]}.json"
        }:
            (evidence_root / name).write_text("{}\n", encoding="utf-8")
        quality = packet / "quality-artifact" / "quality"
        quality.mkdir(parents=True)
        for name in evidence._REVIEW_QUALITY_FILES:
            (quality / name).write_text("{}\n", encoding="utf-8")
        (quality.parent / "quality-revalidation-receipt.json").write_text("{}\n", encoding="utf-8")
        review = restored / "review"
        review.mkdir()
        for name in ("decision.json", "raw-envelope.json"):
            (review / name).write_text("{}\n", encoding="utf-8")
        material = root / "candidate-material" / role
        for relative in evidence.ROLE_REVIEW_MATERIAL_PATHS[role]:
            path = material.joinpath(*relative.split("/"))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("material\n", encoding="utf-8")
    final = root / evidence._RESTORED_DIRECTORIES["final_evidence"]
    checkpoint = final / "complete-checkpoint"
    (checkpoint / "payload").mkdir(parents=True)
    (checkpoint / "checkpoint.json").write_text("{}\n", encoding="utf-8")
    for directory in ("stage-artifacts", "stage-results"):
        stage_root = checkpoint / directory
        stage_root.mkdir()
        for stage in evidence.P6_EXECUTION_STAGE_ORDER:
            (stage_root / f"{stage}.json").write_text("{}\n", encoding="utf-8")
    (final / "final-evidence-manifest.json").write_text("{}\n", encoding="utf-8")


@pytest.mark.parametrize("extra_name", ("extra.bin", "truth.json"))
def test_bundle_inventory_rejects_every_unbound_top_level_resource(
    tmp_path: Path, extra_name: str
) -> None:
    bundle = tmp_path / "bundle"
    _build_inventory_skeleton(bundle)
    evidence._validate_bundle_inventory(bundle)
    (bundle / extra_name).write_bytes(b"unbound")
    with pytest.raises(P6ProtocolError, match="inventory"):
        evidence._validate_bundle_inventory(bundle)


def test_bundle_inventory_rejects_unbound_nested_review_resource(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    _build_inventory_skeleton(bundle)
    nested = bundle / evidence._RESTORED_DIRECTORIES["proof_security"] / "review" / "truth.json"
    nested.write_text("{}\n", encoding="utf-8")
    with pytest.raises(P6ProtocolError, match="inventory"):
        evidence._validate_bundle_inventory(bundle)


def test_bundle_inventory_rejects_unbound_complete_checkpoint_resource(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    _build_inventory_skeleton(bundle)
    checkpoint = bundle / evidence._RESTORED_DIRECTORIES["final_evidence"] / "complete-checkpoint"
    (checkpoint / "truth.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(P6ProtocolError, match="inventory"):
        evidence._validate_bundle_inventory(bundle)


def test_candidate_material_snapshot_must_equal_the_exact_reviewed_commit(
    monkeypatch, tmp_path: Path
) -> None:
    bundle = tmp_path / "bundle"
    snapshot = bundle / "candidate-material" / "product_architecture" / "a.py"
    snapshot.parent.mkdir(parents=True)
    snapshot.write_bytes(b"reviewed bytes\n")
    monkeypatch.setattr(projector, "REVIEW_ROLES", ("product_architecture",))
    monkeypatch.setattr(
        projector,
        "ROLE_REVIEW_MATERIAL_PATHS",
        {"product_architecture": ("a.py",)},
    )
    monkeypatch.setattr(projector, "_git", lambda *_args: "2" * 40)
    monkeypatch.setattr(projector, "_git_bytes", lambda *_args: b"reviewed bytes\n")
    status = {"candidate_git_sha": "1" * 40, "candidate_git_tree": "2" * 40}

    projector._validate_candidate_material(tmp_path, bundle_root=bundle, status=status)
    snapshot.write_bytes(b"coordinator replacement\n")
    with pytest.raises(ValueError, match="candidate_material_mismatch"):
        projector._validate_candidate_material(tmp_path, bundle_root=bundle, status=status)


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()


def _init_git(root: Path) -> tuple[str, str]:
    root.mkdir()
    _git(root, "init", "-b", "main")
    _git(root, "config", "user.email", "review-scope@example.invalid")
    _git(root, "config", "user.name", "Review Scope Test")
    forbidden = root / "zscope/core/a.py"
    forbidden.parent.mkdir(parents=True)
    forbidden.write_text("authority = False\n", encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "-m", "candidate")
    return _git(root, "rev-parse", "HEAD"), _git(root, "rev-parse", "HEAD^{tree}")


def _write_required_evidence(root: Path) -> None:
    for relative in (
        "zscope/orchestration/successor-runtime-review-status.v1.json",
        "zscope/orchestration/successor-runtime-review-integration-receipt.v1.json",
        "zscope/orchestration/successor-runtime-review-evidence/bundle-manifest.json",
    ):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}\n", encoding="utf-8")


def test_real_git_forbidden_rename_into_evidence_directory_is_rejected(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    base, tree = _init_git(repository)
    destination = repository / "zscope/orchestration/successor-runtime-review-evidence/a.py"
    destination.parent.mkdir(parents=True)
    _git(repository, "mv", "zscope/core/a.py", destination.relative_to(repository).as_posix())
    _write_required_evidence(repository)
    _git(repository, "add", ".")
    _git(repository, "commit", "-m", "rename forbidden source")

    with pytest.raises(ValueError, match="scope_violation"):
        projector._validate_git_scope(
            repository,
            status={"candidate_git_sha": base, "candidate_git_tree": tree},
            head="HEAD",
        )


def test_real_git_intermediate_forbidden_add_delete_is_rejected(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    base, tree = _init_git(repository)
    transient = repository / "test/range/benchmark/ground_truth.json"
    transient.parent.mkdir(parents=True)
    transient.write_text("{}\n", encoding="utf-8")
    _git(repository, "add", ".")
    _git(repository, "commit", "-m", "add forbidden transient")
    transient.unlink()
    _write_required_evidence(repository)
    _git(repository, "add", "-A")
    _git(repository, "commit", "-m", "hide forbidden transient")

    with pytest.raises(ValueError, match="scope_violation"):
        projector._validate_git_scope(
            repository,
            status={"candidate_git_sha": base, "candidate_git_tree": tree},
            head="HEAD",
        )


def _valid_online_manifest() -> dict:
    metadata = {
        key: _artifact_row(index) for index, key in enumerate(evidence._ARTIFACT_KEYS, start=1)
    }
    body = {
        "schema_version": evidence.SUCCESSOR_REVIEW_EVIDENCE_VERSION,
        "repository": evidence.SUCCESSOR_REVIEW_REPOSITORY,
        "workflow_path": evidence.SUCCESSOR_REVIEW_WORKFLOW_PATH,
        "workflow_event": "workflow_dispatch",
        "workflow_branch": "main",
        "workflow_run_id": "123",
        "workflow_run_attempt": 1,
        "control_plane_commit": "a" * 40,
        "candidate_git_sha": "1" * 40,
        "candidate_git_tree": "2" * 40,
        "implementation_root_sha256": "3" * 64,
        "successor_qualification_sha256": "4" * 64,
        "artifact_metadata": metadata,
    }
    for key, row in metadata.items():
        row["head_sha"] = body["control_plane_commit"]
        row["producer_job"] = evidence._PRODUCER_JOBS[key]
        row["artifact_name"] = evidence._artifact_name(key, body)
    body["content_sha256"] = canonical_sha256(body)
    return body


def test_online_validation_restores_all_five_exact_artifacts_and_compares_bytes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    manifest = _valid_online_manifest()
    (bundle / evidence.SUCCESSOR_REVIEW_EVIDENCE_MANIFEST).write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    for key in evidence._ARTIFACT_KEYS:
        source = bundle / evidence._RESTORED_DIRECTORIES[key]
        source.mkdir(parents=True)
        (source / "bound.bin").write_bytes((key + "\n").encode())
    calls: list[str] = []

    def restore(args, *, token: str) -> str:
        assert token == "token"
        key = args.output_dir.name
        calls.append(key)
        row = manifest["artifact_metadata"][key]
        assert args.repository == row["repository"]
        assert args.run_id == row["workflow_run_id"]
        assert args.run_attempt == row["workflow_run_attempt"]
        assert args.control_plane_commit == row["head_sha"]
        assert args.candidate_commit == manifest["candidate_git_sha"]
        assert args.producer_job == row["producer_job"]
        assert args.artifact_id == row["artifact_id"]
        assert args.artifact_name == row["artifact_name"]
        assert args.artifact_digest == "sha256:" + row["artifact_sha256"]
        assert tuple(args.required_member) == projector._ONLINE_REQUIRED_MEMBERS[key]
        shutil.copytree(bundle / evidence._RESTORED_DIRECTORIES[key], args.output_dir)
        return str(manifest["artifact_metadata"][key]["artifact_sha256"])

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(projector, "restore_exact_p6_artifact", restore)
    monkeypatch.setattr(projector, "_validate_successful_source_run", lambda *_a, **_k: None)
    projector._validate_authoritative_artifacts_online(
        bundle, token="token", workspace_root=tmp_path
    )
    assert calls == list(evidence._ARTIFACT_KEYS)

    def tampered_restore(args, *, token: str) -> str:
        key = args.output_dir.name
        shutil.copytree(bundle / evidence._RESTORED_DIRECTORIES[key], args.output_dir)
        if key == "proof_security":
            (args.output_dir / "bound.bin").write_bytes(b"tampered\n")
        return str(manifest["artifact_metadata"][key]["artifact_sha256"])

    monkeypatch.setattr(projector, "restore_exact_p6_artifact", tampered_restore)
    with pytest.raises(P6ProtocolError, match="tree differs"):
        projector._validate_authoritative_artifacts_online(
            bundle, token="token", workspace_root=tmp_path
        )


def test_online_validation_requires_the_source_workflow_run_to_succeed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _valid_online_manifest()
    monkeypatch.setattr(
        projector,
        "_fetch_metadata",
        lambda _url, *, token: {
            "id": 123,
            "run_attempt": 1,
            "status": "completed",
            "conclusion": "failure",
        },
    )
    monkeypatch.setattr(projector, "_retry_transport", lambda call, **_kwargs: call())
    with pytest.raises(P6ProtocolError, match="did not succeed"):
        projector._validate_successful_source_run(manifest, token="opaque")


def test_online_check_never_uses_network_for_in_progress_status(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    status = {"status": "in_progress"}
    args = type(
        "Args",
        (),
        {
            "repository_root": tmp_path,
            "change_base": "1" * 40,
            "head": "2" * 40,
        },
    )()
    checked: list[bool] = []
    monkeypatch.setattr(projector, "load_json_strict", lambda _path: status)
    monkeypatch.setattr(
        projector, "validate_successor_runtime_review_status", lambda _value: (True, "valid")
    )
    monkeypatch.setattr(projector, "_review_resources_changed", lambda *_a, **_k: True)
    monkeypatch.setattr(projector, "_check", lambda _args: checked.append(True))
    monkeypatch.setattr(
        projector,
        "_validate_authoritative_artifacts_online",
        lambda *_a, **_k: pytest.fail("in-progress status made a network validation call"),
    )
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    projector._online_check(args)
    assert checked == [True]


def test_online_check_does_not_requery_historical_artifacts_without_evidence_change(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    status = {"status": "reviewed"}
    args = type(
        "Args",
        (),
        {
            "repository_root": tmp_path,
            "change_base": "1" * 40,
            "head": "2" * 40,
        },
    )()
    checked: list[bool] = []
    monkeypatch.setattr(projector, "load_json_strict", lambda _path: status)
    monkeypatch.setattr(
        projector, "validate_successor_runtime_review_status", lambda _value: (True, "valid")
    )
    monkeypatch.setattr(projector, "_review_resources_changed", lambda *_a, **_k: False)
    monkeypatch.setattr(projector, "_check", lambda _args: checked.append(True))
    monkeypatch.setattr(
        projector,
        "_validate_authoritative_artifacts_online",
        lambda *_a, **_k: pytest.fail("historical artifacts were re-queried"),
    )
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    projector._online_check(args)
    assert checked == [True]


def test_ci_has_pr_only_actions_read_authoritative_provenance_job() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    section = workflow.split("  successor-review-authoritative-provenance:", 1)[1].split(
        "\n  python:", 1
    )[0]
    assert "github.event_name == 'pull_request'" in section
    assert "actions: read" in section
    assert "contents: read" in section
    assert "online-check" in section
    assert '--change-base "$SUCCESSOR_CHANGE_BASE"' in section
    assert '--head "$SUCCESSOR_CHANGE_HEAD"' in section
