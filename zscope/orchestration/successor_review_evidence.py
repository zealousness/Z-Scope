"""Strict, resource-backed projection of current-successor review evidence.

The source-controlled status JSON is only a projection.  It cannot grant
authority by resealing hashes supplied by an integrator: a reviewed projection
must be reproduced from the complete packaged P6 final-evidence tree, the
actual three review envelopes, and exact candidate-material snapshots.

No reviewed bundle is shipped while P6 is in progress.  A later evidence-only
change may add the fixed resource directory described by this module.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from zscope.benchmarking.p6_protocol import (
    P6_EXECUTION_STAGE_ORDER,
    P6ProtocolError,
    canonical_sha256,
    load_json_strict,
    sha256_file,
    validate_final_evidence_manifest,
)
from zscope.benchmarking.p6_review import (
    REVIEW_ROLES,
    ROLE_REVIEW_MATERIAL_PATHS,
    aggregate_review_set,
    project_role_evidence,
    reviewer_identity_sha256,
)


SUCCESSOR_REVIEW_EVIDENCE_VERSION = "zscope.successor-review-evidence-bundle.v1"
SUCCESSOR_REVIEW_EVIDENCE_DIRECTORY = "successor-runtime-review-evidence"
SUCCESSOR_REVIEW_EVIDENCE_MANIFEST = "bundle-manifest.json"
SUCCESSOR_REVIEW_WORKFLOW_PATH = ".github/workflows/p6-pilot-validation.yml"
SUCCESSOR_REVIEW_REPOSITORY = "zealousness/Z-Scope"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT_OBJECT_RE = re.compile(r"^[0-9a-f]{40}$")
_RUN_ID_RE = re.compile(r"^[1-9][0-9]*$")
_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema_version",
        "repository",
        "workflow_path",
        "workflow_event",
        "workflow_branch",
        "workflow_run_id",
        "workflow_run_attempt",
        "control_plane_commit",
        "candidate_git_sha",
        "candidate_git_tree",
        "implementation_root_sha256",
        "successor_qualification_sha256",
        "artifact_metadata",
        "content_sha256",
    }
)
_ARTIFACT_FIELDS = frozenset(
    {
        "repository",
        "workflow_path",
        "workflow_event",
        "workflow_branch",
        "workflow_run_id",
        "workflow_run_attempt",
        "head_sha",
        "producer_job",
        "artifact_id",
        "artifact_name",
        "artifact_sha256",
        "expired",
        "restore_receipt_sha256",
    }
)
_ARTIFACT_KEYS = (
    "qualification",
    "product_architecture",
    "proof_security",
    "independent_benchmark",
    "final_evidence",
)
_ROLE_SLUGS = {
    "product_architecture": "product-architecture",
    "proof_security": "proof-security",
    "independent_benchmark": "independent-benchmark",
}
_PRODUCER_JOBS = {
    "qualification": "conservation and qualification seal",
    "product_architecture": "independent product architecture review",
    "proof_security": "independent proof security review",
    "independent_benchmark": "independent benchmark review",
    "final_evidence": "zero-call finalize reviewed P6 evidence",
}
_RESTORED_DIRECTORIES = {key: f"restored-artifacts/{key}" for key in _ARTIFACT_KEYS}
_RESTORE_RECEIPT_FIELDS = (_ARTIFACT_FIELDS - {"restore_receipt_sha256"}) | {
    "schema_version",
    "restored_tree_sha256",
    "content_sha256",
}
_RESTORE_RECEIPT_VERSION = "zscope.successor-review-artifact-restore-receipt.v1"
_BUNDLE_TOP_LEVEL_FILES = frozenset({SUCCESSOR_REVIEW_EVIDENCE_MANIFEST})
_BUNDLE_TOP_LEVEL_DIRECTORIES = frozenset(
    {"restore-receipts", "restored-artifacts", "candidate-material"}
)
_REVIEW_PACKET_COMMON_EVIDENCE_FILES = frozenset(
    {
        "e0-lineage.json",
        "common-review-evidence.json",
        "successor-qualification.json",
        "p6-balanced-quality-gate.json",
        "p6-balanced-bindings.json",
        "p6-balanced-frozen-manifest.json",
        "p6-balanced-producer-projection.json",
        "p6-balanced-quality-revalidation-receipt.json",
        "review-material-manifest.json",
    }
)
_REVIEW_QUALITY_FILES = frozenset(
    {
        "bindings.json",
        "frozen-manifest.json",
        "p6-balanced-quality-gate.json",
        "producer-projection.json",
    }
)


def _strict_json_file(path: Path) -> Mapping[str, Any]:
    value = load_json_strict(path)
    if not isinstance(value, Mapping):
        raise P6ProtocolError("successor review evidence object is invalid")
    return value


def _safe_child(root: Path, relative: str, *, directory: bool = False) -> Path:
    pure = PurePosixPath(relative)
    if (
        pure.is_absolute()
        or not pure.parts
        or any(part in {"", ".", ".."} for part in pure.parts)
        or pure.as_posix() != relative
    ):
        raise P6ProtocolError("successor review evidence path is invalid")
    candidate = root.joinpath(*pure.parts)
    try:
        candidate.resolve().relative_to(root.resolve())
    except (OSError, ValueError) as exc:
        raise P6ProtocolError("successor review evidence path escapes its root") from exc
    if candidate.is_symlink() or (not candidate.is_dir() if directory else not candidate.is_file()):
        raise P6ProtocolError("successor review evidence resource is unavailable")
    return candidate


def _strict_directory_inventory(
    root: Path,
    *,
    files: frozenset[str],
    directories: frozenset[str],
) -> None:
    """Reject unbound resources and every non-regular directory entry."""

    if root.is_symlink() or not root.is_dir():
        raise P6ProtocolError("successor review evidence directory is unavailable")
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    for path in root.iterdir():
        if path.is_symlink():
            raise P6ProtocolError("successor review evidence contains a symlink")
        if path.is_file():
            actual_files.add(path.name)
        elif path.is_dir():
            actual_directories.add(path.name)
        else:
            raise P6ProtocolError("successor review evidence contains a special resource")
    if actual_files != set(files) or actual_directories != set(directories):
        raise P6ProtocolError("successor review evidence inventory is invalid")


def _strict_tree_inventory(root: Path, *, files: frozenset[str]) -> None:
    """Require one exact recursive regular-file and directory inventory."""

    expected_directories = {
        parent.as_posix()
        for relative in files
        for parent in PurePosixPath(relative).parents
        if parent.as_posix() != "."
    }
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    if root.is_symlink() or not root.is_dir():
        raise P6ProtocolError("successor review evidence directory is unavailable")
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise P6ProtocolError("successor review evidence contains a symlink")
        if path.is_file():
            actual_files.add(relative)
        elif path.is_dir():
            actual_directories.add(relative)
        else:
            raise P6ProtocolError("successor review evidence contains a special resource")
    if actual_files != set(files) or actual_directories != expected_directories:
        raise P6ProtocolError("successor review evidence inventory is invalid")


def _validate_bundle_inventory(bundle_root: Path) -> None:
    """Validate the frozen v1 directory grammar before reading any claim."""

    _strict_directory_inventory(
        bundle_root,
        files=_BUNDLE_TOP_LEVEL_FILES,
        directories=_BUNDLE_TOP_LEVEL_DIRECTORIES,
    )
    receipt_root = _safe_child(bundle_root, "restore-receipts", directory=True)
    _strict_directory_inventory(
        receipt_root,
        files=frozenset(f"{key}.json" for key in _ARTIFACT_KEYS),
        directories=frozenset(),
    )
    restored_root = _safe_child(bundle_root, "restored-artifacts", directory=True)
    _strict_directory_inventory(
        restored_root,
        files=frozenset(),
        directories=frozenset(_ARTIFACT_KEYS),
    )
    material_root = _safe_child(bundle_root, "candidate-material", directory=True)
    _strict_directory_inventory(
        material_root,
        files=frozenset(),
        directories=frozenset(REVIEW_ROLES),
    )

    qualification_root = _safe_child(
        bundle_root, _RESTORED_DIRECTORIES["qualification"], directory=True
    )
    _strict_directory_inventory(
        qualification_root,
        files=frozenset({"qualification.json"}),
        directories=frozenset(),
    )
    for role in REVIEW_ROLES:
        role_root = _safe_child(bundle_root, _RESTORED_DIRECTORIES[role], directory=True)
        _strict_directory_inventory(
            role_root,
            files=frozenset(),
            directories=frozenset({"packet", "review"}),
        )
        packet_root = _safe_child(role_root, "packet", directory=True)
        _strict_directory_inventory(
            packet_root,
            files=frozenset({"packet.json"}),
            directories=frozenset({"evidence", "quality-artifact"}),
        )
        role_evidence_root = _safe_child(packet_root, "evidence", directory=True)
        _strict_directory_inventory(
            role_evidence_root,
            files=_REVIEW_PACKET_COMMON_EVIDENCE_FILES | frozenset({f"{_ROLE_SLUGS[role]}.json"}),
            directories=frozenset(),
        )
        quality_artifact_root = _safe_child(packet_root, "quality-artifact", directory=True)
        _strict_directory_inventory(
            quality_artifact_root,
            files=frozenset({"quality-revalidation-receipt.json"}),
            directories=frozenset({"quality"}),
        )
        quality_root = _safe_child(quality_artifact_root, "quality", directory=True)
        _strict_directory_inventory(
            quality_root,
            files=_REVIEW_QUALITY_FILES,
            directories=frozenset(),
        )
        review_root = _safe_child(role_root, "review", directory=True)
        _strict_directory_inventory(
            review_root,
            files=frozenset({"decision.json", "raw-envelope.json"}),
            directories=frozenset(),
        )
        _validate_material_snapshot(
            _safe_child(bundle_root, f"candidate-material/{role}", directory=True), role
        )

    final_root = _safe_child(bundle_root, _RESTORED_DIRECTORIES["final_evidence"], directory=True)
    _strict_directory_inventory(
        final_root,
        files=frozenset({"final-evidence-manifest.json"}),
        directories=frozenset({"complete-checkpoint"}),
    )
    checkpoint_root = _safe_child(final_root, "complete-checkpoint", directory=True)
    _strict_directory_inventory(
        checkpoint_root,
        files=frozenset({"checkpoint.json"}),
        directories=frozenset({"payload", "stage-artifacts", "stage-results"}),
    )
    expected_stage_files = frozenset(f"{stage}.json" for stage in P6_EXECUTION_STAGE_ORDER)
    _strict_directory_inventory(
        _safe_child(checkpoint_root, "stage-artifacts", directory=True),
        files=expected_stage_files,
        directories=frozenset(),
    )
    _strict_directory_inventory(
        _safe_child(checkpoint_root, "stage-results", directory=True),
        files=expected_stage_files,
        directories=frozenset(),
    )


def _artifact_name(key: str, manifest: Mapping[str, Any]) -> str:
    control = str(manifest["control_plane_commit"])
    candidate = str(manifest["candidate_git_sha"])
    attempt = int(manifest["workflow_run_attempt"])
    run_id = str(manifest["workflow_run_id"])
    if key == "qualification":
        return f"p6-qualification-{control}-{candidate}-{attempt}"
    if key == "final_evidence":
        return f"p6-non-release-evidence-{control}-{candidate}-{run_id}-{attempt}"
    slug = _ROLE_SLUGS[key]
    return f"p6-review-{slug}-{control}-{candidate}-{attempt}"


def _regular_tree_sha256(root: Path) -> str:
    if root.is_symlink() or not root.is_dir():
        raise P6ProtocolError("successor review restored artifact is unavailable")
    rows: list[Mapping[str, str]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if path.is_symlink():
            raise P6ProtocolError("successor review restored artifact contains a symlink")
        if path.is_file():
            rows.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "sha256": sha256_file(path),
                }
            )
    if not rows:
        raise P6ProtocolError("successor review restored artifact is empty")
    return canonical_sha256(
        {"schema_version": "zscope.successor-review-restored-tree.v1", "files": rows}
    )


def _validate_restore_receipt(
    bundle_root: Path,
    *,
    key: str,
    metadata: Mapping[str, Any],
) -> Path:
    restored_root = _safe_child(bundle_root, _RESTORED_DIRECTORIES[key], directory=True)
    receipt_path = _safe_child(bundle_root, f"restore-receipts/{key}.json")
    receipt = _strict_json_file(receipt_path)
    if (
        set(receipt) != _RESTORE_RECEIPT_FIELDS
        or receipt.get("schema_version") != _RESTORE_RECEIPT_VERSION
        or sha256_file(receipt_path) != metadata.get("restore_receipt_sha256")
        or any(
            receipt.get(name) != metadata.get(name)
            for name in _ARTIFACT_FIELDS - {"restore_receipt_sha256"}
        )
        or receipt.get("restored_tree_sha256") != _regular_tree_sha256(restored_root)
    ):
        raise P6ProtocolError("successor review artifact restore receipt is invalid")
    unsigned = {name: value for name, value in receipt.items() if name != "content_sha256"}
    if receipt.get("content_sha256") != canonical_sha256(unsigned):
        raise P6ProtocolError("successor review artifact restore receipt seal is invalid")
    return restored_root


def _validate_artifact_metadata(manifest: Mapping[str, Any]) -> Mapping[str, Mapping[str, Any]]:
    metadata = manifest.get("artifact_metadata")
    if not isinstance(metadata, Mapping) or set(metadata) != set(_ARTIFACT_KEYS):
        raise P6ProtocolError("successor review artifact metadata set is invalid")
    seen_ids: set[int] = set()
    seen_digests: set[str] = set()
    projected: dict[str, Mapping[str, Any]] = {}
    for key in _ARTIFACT_KEYS:
        row = metadata.get(key)
        if not isinstance(row, Mapping) or set(row) != _ARTIFACT_FIELDS:
            raise P6ProtocolError("successor review artifact metadata fields are invalid")
        artifact_id = row.get("artifact_id")
        run_attempt = row.get("workflow_run_attempt")
        digest = str(row.get("artifact_sha256") or "")
        receipt_sha = str(row.get("restore_receipt_sha256") or "")
        if (
            type(artifact_id) is not int
            or artifact_id <= 0
            or artifact_id in seen_ids
            or type(run_attempt) is not int
            or run_attempt != manifest["workflow_run_attempt"]
            or _SHA256_RE.fullmatch(digest) is None
            or digest in seen_digests
            or _SHA256_RE.fullmatch(receipt_sha) is None
        ):
            raise P6ProtocolError("successor review artifact identity is invalid")
        seen_ids.add(artifact_id)
        seen_digests.add(digest)
        expected_common = {
            "repository": manifest["repository"],
            "workflow_path": manifest["workflow_path"],
            "workflow_event": manifest["workflow_event"],
            "workflow_branch": manifest["workflow_branch"],
            "workflow_run_id": manifest["workflow_run_id"],
            "workflow_run_attempt": manifest["workflow_run_attempt"],
            # GitHub run/job/artifact metadata is bound to the workflow head
            # (the immutable control plane).  The separately checked scanner
            # candidate may intentionally differ.
            "head_sha": manifest["control_plane_commit"],
            "producer_job": _PRODUCER_JOBS[key],
            "artifact_name": _artifact_name(key, manifest),
            "expired": False,
        }
        if any(row.get(name) != value for name, value in expected_common.items()):
            raise P6ProtocolError("successor review artifact lineage is invalid")
        projected[key] = row
    return projected


def _validate_bundle_manifest(value: Mapping[str, Any]) -> None:
    if set(value) != _TOP_LEVEL_FIELDS:
        raise P6ProtocolError("successor review evidence manifest fields are invalid")
    if (
        value.get("schema_version") != SUCCESSOR_REVIEW_EVIDENCE_VERSION
        or value.get("repository") != SUCCESSOR_REVIEW_REPOSITORY
        or value.get("workflow_path") != SUCCESSOR_REVIEW_WORKFLOW_PATH
        or value.get("workflow_event") != "workflow_dispatch"
        or value.get("workflow_branch") != "main"
        or _RUN_ID_RE.fullmatch(str(value.get("workflow_run_id") or "")) is None
        or type(value.get("workflow_run_attempt")) is not int
        or int(value["workflow_run_attempt"]) < 1
        or _GIT_OBJECT_RE.fullmatch(str(value.get("control_plane_commit") or "")) is None
        or _GIT_OBJECT_RE.fullmatch(str(value.get("candidate_git_sha") or "")) is None
        or _GIT_OBJECT_RE.fullmatch(str(value.get("candidate_git_tree") or "")) is None
        or any(
            _SHA256_RE.fullmatch(str(value.get(name) or "")) is None
            for name in ("implementation_root_sha256", "successor_qualification_sha256")
        )
    ):
        raise P6ProtocolError("successor review evidence manifest identity is invalid")
    body = {name: item for name, item in value.items() if name != "content_sha256"}
    if value.get("content_sha256") != canonical_sha256(body):
        raise P6ProtocolError("successor review evidence manifest seal is invalid")
    _validate_artifact_metadata(value)


def _validate_material_snapshot(root: Path, role: str) -> None:
    expected = set(ROLE_REVIEW_MATERIAL_PATHS[role])
    try:
        _strict_tree_inventory(root, files=frozenset(expected))
    except P6ProtocolError as exc:
        raise P6ProtocolError("successor review material snapshot set is invalid") from exc


def project_successor_runtime_review_status(
    bundle_root: Path,
    *,
    successor_qualification: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Validate a complete physical bundle and deterministically project status."""

    bundle_root = bundle_root.absolute()
    if bundle_root.is_symlink() or not bundle_root.is_dir():
        raise P6ProtocolError("successor review evidence bundle is unavailable")
    _validate_bundle_inventory(bundle_root)
    manifest_path = _safe_child(bundle_root, SUCCESSOR_REVIEW_EVIDENCE_MANIFEST)
    manifest = _strict_json_file(manifest_path)
    _validate_bundle_manifest(manifest)
    if manifest["implementation_root_sha256"] != successor_qualification.get(
        "implementation_root_sha256"
    ) or manifest["successor_qualification_sha256"] != successor_qualification.get(
        "content_sha256"
    ):
        raise P6ProtocolError("successor review evidence successor binding is invalid")

    metadata = _validate_artifact_metadata(manifest)
    restored_roots = {
        key: _validate_restore_receipt(bundle_root, key=key, metadata=metadata[key])
        for key in _ARTIFACT_KEYS
    }
    final_root = _safe_child(
        restored_roots["final_evidence"], "complete-checkpoint/payload", directory=True
    )
    final_manifest_path = _safe_child(final_root, "final-evidence-manifest.json")
    published_final_manifest_path = _safe_child(
        restored_roots["final_evidence"], "final-evidence-manifest.json"
    )
    if published_final_manifest_path.read_bytes() != final_manifest_path.read_bytes():
        raise P6ProtocolError("successor final evidence manifests are not byte exact")
    final_bytes = validate_final_evidence_manifest(
        final_manifest_path,
        payload_root=final_root,
        expected_run_id=str(manifest["workflow_run_id"]),
        expected_run_attempt=int(manifest["workflow_run_attempt"]),
        expected_control_plane_commit=str(manifest["control_plane_commit"]),
        expected_candidate_git_sha=str(manifest["candidate_git_sha"]),
        expected_candidate_sha256=hashlib.sha256(
            str(manifest["candidate_git_sha"]).encode("utf-8")
        ).hexdigest(),
    )
    final_manifest = json.loads(final_bytes.decode("utf-8"))
    if not isinstance(final_manifest, Mapping):
        raise P6ProtocolError("successor final evidence manifest is invalid")
    artifact_rows = final_manifest.get("artifacts")
    if not isinstance(artifact_rows, list):
        raise P6ProtocolError("successor final evidence artifact inventory is invalid")
    payload_files = {"final-evidence-manifest.json"}
    for row in artifact_rows:
        if not isinstance(row, Mapping) or not isinstance(row.get("path"), str):
            raise P6ProtocolError("successor final evidence artifact inventory is invalid")
        payload_files.add(str(row["path"]))
    _strict_tree_inventory(final_root, files=frozenset(payload_files))

    qualification_path = _safe_child(final_root, "qualification.json")
    restored_qualification_path = _safe_child(restored_roots["qualification"], "qualification.json")
    if restored_qualification_path.read_bytes() != qualification_path.read_bytes():
        raise P6ProtocolError("successor qualification copies are not byte exact")
    qualification = _strict_json_file(restored_qualification_path)
    # The three projections share the strict full-qualification validation.
    for role in REVIEW_ROLES:
        project_role_evidence(qualification, role=role)
    candidate_sha = str(manifest["candidate_git_sha"])
    toolchain = qualification.get("toolchain_evidence")
    if (
        qualification.get("candidate_sha256")
        != hashlib.sha256(candidate_sha.encode("utf-8")).hexdigest()
        or not isinstance(toolchain, Mapping)
        or toolchain.get("candidate_git_sha") != candidate_sha
        or toolchain.get("candidate_git_tree") != manifest["candidate_git_tree"]
        or qualification.get("control_plane_commit") != manifest["control_plane_commit"]
    ):
        raise P6ProtocolError("successor P6 qualification candidate binding is invalid")

    packet_paths: dict[str, Path] = {}
    output_dirs: dict[str, Path] = {}
    material_roots: dict[str, Path] = {}
    for role in REVIEW_ROLES:
        slug = _ROLE_SLUGS[role]
        final_review_root = _safe_child(final_root, f"reviews/{slug}", directory=True)
        restored_review_root = restored_roots[role]
        restored_packet_root = _safe_child(restored_review_root, "packet", directory=True)
        restored_output_root = _safe_child(restored_review_root, "review", directory=True)
        packet_paths[role] = _safe_child(restored_packet_root, "packet.json")
        _safe_child(restored_output_root, "decision.json")
        _safe_child(restored_output_root, "raw-envelope.json")
        output_dirs[role] = restored_output_root
        byte_pairs = (
            (packet_paths[role], _safe_child(final_review_root, "packet.json")),
            (
                restored_output_root / "decision.json",
                _safe_child(final_review_root, "decision.json"),
            ),
            (
                restored_output_root / "raw-envelope.json",
                _safe_child(final_review_root, "raw-envelope.json"),
            ),
        )
        if any(source.read_bytes() != target.read_bytes() for source, target in byte_pairs):
            raise P6ProtocolError("successor review copies are not byte exact")
        restored_evidence = _safe_child(restored_packet_root, "evidence", directory=True)
        final_evidence = _safe_child(final_review_root, "evidence", directory=True)
        if _regular_tree_sha256(restored_evidence) != _regular_tree_sha256(final_evidence):
            raise P6ProtocolError("successor review evidence copies are not byte exact")
        material = _safe_child(bundle_root, f"candidate-material/{role}", directory=True)
        _validate_material_snapshot(material, role)
        material_roots[role] = material

    review_set = aggregate_review_set(
        packet_paths=packet_paths,
        output_dirs=output_dirs,
        material_roots=material_roots,
    )
    stored_review_set_path = _safe_child(final_root, "p6-independent-reviews.json")
    stored_review_set = _strict_json_file(stored_review_set_path)
    if dict(stored_review_set) != dict(review_set):
        raise P6ProtocolError("successor review set differs from physical review artifacts")

    qualification_sha = str(qualification["qualification_sha256"])
    evidence_roots: set[str] = set()
    reviewer_roots: dict[str, Mapping[str, Any]] = {}
    for role in REVIEW_ROLES:
        packet = _strict_json_file(packet_paths[role])
        decision_path = output_dirs[role] / "decision.json"
        raw_path = output_dirs[role] / "raw-envelope.json"
        decision = _strict_json_file(decision_path)
        raw = _strict_json_file(raw_path)
        if (
            packet.get("candidate_sha256") != qualification["candidate_sha256"]
            or packet.get("qualification_sha256") != qualification_sha
            or raw.get("reviewer_identity_sha256") != reviewer_identity_sha256(role)
        ):
            raise P6ProtocolError("successor review packet lineage is invalid")
        common_path = packet_paths[role].parent / "evidence" / "common-review-evidence.json"
        common = _strict_json_file(common_path)
        if (
            common.get("successor_qualification_sha256")
            != successor_qualification.get("content_sha256")
            or common.get("qualification_sha256") != qualification_sha
            or common.get("evidence_root_sha256") != packet.get("evidence_root_sha256")
        ):
            raise P6ProtocolError("successor review common evidence binding is invalid")
        evidence_roots.add(str(packet["evidence_root_sha256"]))
        aggregate_row = next(row for row in review_set["reviews"] if row["role"] == role)
        reviewer_roots[role] = {
            "artifact_id": str(metadata[role]["artifact_id"]),
            "artifact_sha256": str(metadata[role]["artifact_sha256"]),
            "packet_sha256": str(packet["packet_sha256"]),
            "decision_sha256": canonical_sha256(decision),
            "raw_envelope_sha256": sha256_file(raw_path),
            "reviewer_identity_sha256": reviewer_identity_sha256(role),
            "review_artifact_sha256": str(aggregate_row["review_artifact_sha256"]),
            "decision": "approved",
            "blocker_count": 0,
        }
    if len(evidence_roots) != 1:
        raise P6ProtocolError("successor independent reviews do not share one evidence root")

    body: dict[str, Any] = {
        "schema_version": "zscope.successor-runtime-review-status.v1",
        "status": "reviewed",
        "candidate_git_sha": candidate_sha,
        "candidate_git_tree": str(manifest["candidate_git_tree"]),
        "implementation_root_sha256": str(manifest["implementation_root_sha256"]),
        "successor_qualification_sha256": str(manifest["successor_qualification_sha256"]),
        "p6_qualification_file_sha256": sha256_file(restored_qualification_path),
        "p6_qualification_content_sha256": qualification_sha,
        # This is deliberately the physical final-manifest file digest, not a
        # self-reported semantic hash from the manifest body.
        "p6_final_evidence_manifest_file_sha256": sha256_file(final_manifest_path),
        # Bind every physical file, including exact restored artifacts,
        # receipts, and candidate-material snapshots.  The manifest seal alone
        # would only bind paths and metadata claimed by the integrator.
        "evidence_bundle_sha256": _regular_tree_sha256(bundle_root),
        "review_set_sha256": canonical_sha256(review_set),
        "reviewer_roots": reviewer_roots,
        "p6_formal_benchmark": False,
        "p6_release_eligible": False,
    }
    body["content_sha256"] = canonical_sha256(body)
    return body


__all__ = [
    "SUCCESSOR_REVIEW_EVIDENCE_DIRECTORY",
    "SUCCESSOR_REVIEW_EVIDENCE_MANIFEST",
    "SUCCESSOR_REVIEW_EVIDENCE_VERSION",
    "project_successor_runtime_review_status",
]
