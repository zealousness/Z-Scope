"""Fail-closed review status for the current successor implementation.

The historical P5 release latch remains immutable evidence for its reviewed
tree.  This module adds a separate, package-local projection for the current
implementation.  An ``in_progress`` projection never grants release authority;
only an evidence-only integration change may install a fully bound ``reviewed``
projection after independent P6 review.
"""

from __future__ import annotations

import hashlib
import json
import re
from importlib import resources
from pathlib import Path
from typing import Any, Mapping

from .proof_promotion_qualification import (
    P6_PROOF_PROMOTION_QUALIFICATION_RESOURCE,
    validate_successor_qualification,
)
from .successor_implementation_root import (
    current_source_hashes,
    implementation_root_sha256,
)

SUCCESSOR_RUNTIME_REVIEW_STATUS_VERSION = "zscope.successor-runtime-review-status.v1"
SUCCESSOR_RUNTIME_REVIEW_STATUS_RESOURCE = "successor-runtime-review-status.v1.json"
SUCCESSOR_REVIEW_EVIDENCE_DIRECTORY = "successor-runtime-review-evidence"
SUCCESSOR_REVIEW_INTEGRATION_RECEIPT_VERSION = "zscope.successor-review-integration-receipt.v1"
SUCCESSOR_REVIEW_INTEGRATION_RECEIPT_RESOURCE = (
    "successor-runtime-review-integration-receipt.v1.json"
)
SUCCESSOR_REVIEW_ROLES = (
    "product_architecture",
    "proof_security",
    "independent_benchmark",
)
_REVIEWER_IDENTITY_SHA256 = {
    "product_architecture": "3597aafd39a276de4d2168d2c26470259b43e95f19bbe43d470492391fa4718d",
    "proof_security": "8b3e8fa565353bc66055d154c7af30e4fa07842fcf0a101d3c1f3aff03a95710",
    "independent_benchmark": "8738cf916a714cfa0dd04cb961e0d5b1afd2e9e6c9c473eefd0552bc1024789c",
}

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT_OBJECT_RE = re.compile(r"^[0-9a-f]{40}$")
_ARTIFACT_ID_RE = re.compile(r"^[1-9][0-9]*$")
_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "candidate_git_sha",
        "candidate_git_tree",
        "implementation_root_sha256",
        "successor_qualification_sha256",
        "p6_qualification_file_sha256",
        "p6_qualification_content_sha256",
        "p6_final_evidence_manifest_file_sha256",
        "evidence_bundle_sha256",
        "review_set_sha256",
        "reviewer_roots",
        "p6_formal_benchmark",
        "p6_release_eligible",
        "content_sha256",
    }
)
_REVIEW_ROOT_FIELDS = frozenset(
    {
        "artifact_id",
        "artifact_sha256",
        "packet_sha256",
        "decision_sha256",
        "raw_envelope_sha256",
        "reviewer_identity_sha256",
        "review_artifact_sha256",
        "decision",
        "blocker_count",
    }
)
_UNIQUE_REVIEW_ROOT_FIELDS = _REVIEW_ROOT_FIELDS - {"decision", "blocker_count"}
_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "candidate_git_sha",
        "candidate_git_tree",
        "implementation_root_sha256",
        "successor_qualification_sha256",
        "evidence_bundle_sha256",
        "projected_status_sha256",
        "p6_qualification_file_sha256",
        "p6_qualification_content_sha256",
        "p6_final_evidence_manifest_file_sha256",
        "review_set_sha256",
        "p6_formal_benchmark",
        "p6_release_eligible",
        "content_sha256",
    }
)


def _content_sha256(value: Mapping[str, Any]) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _load_json_object(path: Any) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("successor_review_duplicate_json_key")
            result[key] = value
        return result

    value = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicates,
        parse_constant=lambda _value: (_ for _ in ()).throw(
            ValueError("successor_review_non_finite_json_number")
        ),
    )
    if not isinstance(value, dict):
        raise ValueError("successor_review_json_object_required")
    return value


def load_successor_qualification() -> dict[str, Any]:
    """Load a structurally valid qualification bound to current package bytes.

    The full offline freshness check additionally replays P3/P4 dependency
    loaders.  The live latch intentionally avoids that execution graph, while
    still requiring the exact source inventory, byte hashes, and shared
    implementation-root reducer used by the qualification builder.
    """

    raw = _load_json_object(
        resources.files(__package__).joinpath(P6_PROOF_PROMOTION_QUALIFICATION_RESOURCE)
    )
    valid, _ = validate_successor_qualification(raw)
    if not valid:
        raise ValueError("successor_review_qualification_invalid")
    current_sources = current_source_hashes()
    if dict(raw.get("source_sha256") or {}) != current_sources:
        raise ValueError("successor_review_qualification_source_stale")
    if raw.get("implementation_root_sha256") != implementation_root_sha256(current_sources):
        raise ValueError("successor_review_qualification_root_stale")
    return raw


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _regular_tree_sha256(root: Path) -> str:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("successor_review_evidence_unavailable")
    rows: list[Mapping[str, str]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if path.is_symlink():
            raise ValueError("successor_review_evidence_link_invalid")
        if path.is_file():
            rows.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "sha256": _sha256_file(path),
                }
            )
        elif not path.is_dir():
            raise ValueError("successor_review_evidence_resource_invalid")
    if not rows:
        raise ValueError("successor_review_evidence_empty")
    return _content_sha256(
        {"schema_version": "zscope.successor-review-restored-tree.v1", "files": rows}
    )


def _integration_receipt_projection(status: Mapping[str, Any]) -> dict[str, Any]:
    body: dict[str, Any] = {
        "schema_version": SUCCESSOR_REVIEW_INTEGRATION_RECEIPT_VERSION,
        "candidate_git_sha": status.get("candidate_git_sha"),
        "candidate_git_tree": status.get("candidate_git_tree"),
        "implementation_root_sha256": status.get("implementation_root_sha256"),
        "successor_qualification_sha256": status.get("successor_qualification_sha256"),
        "evidence_bundle_sha256": status.get("evidence_bundle_sha256"),
        "projected_status_sha256": status.get("content_sha256"),
        "p6_qualification_file_sha256": status.get("p6_qualification_file_sha256"),
        "p6_qualification_content_sha256": status.get("p6_qualification_content_sha256"),
        "p6_final_evidence_manifest_file_sha256": status.get(
            "p6_final_evidence_manifest_file_sha256"
        ),
        "review_set_sha256": status.get("review_set_sha256"),
        "p6_formal_benchmark": False,
        "p6_release_eligible": False,
    }
    body["content_sha256"] = _content_sha256(body)
    return body


def _integration_receipt_valid(
    raw: Mapping[str, Any], *, expected_status: Mapping[str, Any]
) -> bool:
    if (
        set(raw) != _RECEIPT_FIELDS
        or raw.get("schema_version") != SUCCESSOR_REVIEW_INTEGRATION_RECEIPT_VERSION
        or _GIT_OBJECT_RE.fullmatch(str(raw.get("candidate_git_sha") or "")) is None
        or _GIT_OBJECT_RE.fullmatch(str(raw.get("candidate_git_tree") or "")) is None
        or raw.get("p6_formal_benchmark") is not False
        or raw.get("p6_release_eligible") is not False
    ):
        return False
    hash_fields = _RECEIPT_FIELDS - {
        "schema_version",
        "candidate_git_sha",
        "candidate_git_tree",
        "p6_formal_benchmark",
        "p6_release_eligible",
    }
    if any(_SHA256_RE.fullmatch(str(raw.get(name) or "")) is None for name in hash_fields):
        return False
    body = {key: value for key, value in raw.items() if key != "content_sha256"}
    return raw.get("content_sha256") == _content_sha256(body) and dict(raw) == (
        _integration_receipt_projection(expected_status)
    )


def _review_roots_valid(value: Any, *, reviewed: bool) -> bool:
    if not isinstance(value, Mapping) or set(value) != set(SUCCESSOR_REVIEW_ROLES):
        return False
    seen: dict[str, set[str]] = {field: set() for field in _UNIQUE_REVIEW_ROOT_FIELDS}
    for role in SUCCESSOR_REVIEW_ROLES:
        row = value.get(role)
        if not isinstance(row, Mapping) or set(row) != _REVIEW_ROOT_FIELDS:
            return False
        if not reviewed:
            if (
                any(row.get(field) != "" for field in _UNIQUE_REVIEW_ROOT_FIELDS)
                or row.get("decision") != ""
                or row.get("blocker_count") is not None
            ):
                return False
            continue
        artifact_id = str(row.get("artifact_id") or "")
        if _ARTIFACT_ID_RE.fullmatch(artifact_id) is None:
            return False
        for field in _REVIEW_ROOT_FIELDS - {"artifact_id"}:
            if field in {"decision", "blocker_count"}:
                continue
            if _SHA256_RE.fullmatch(str(row.get(field) or "")) is None:
                return False
        if (
            row.get("decision") != "approved"
            or type(row.get("blocker_count")) is not int
            or row.get("blocker_count") != 0
            or row.get("reviewer_identity_sha256") != _REVIEWER_IDENTITY_SHA256[role]
        ):
            return False
        for field in _UNIQUE_REVIEW_ROOT_FIELDS:
            rendered = str(row[field])
            if rendered in seen[field]:
                return False
            seen[field].add(rendered)
    return True


def review_set_sha256(review_set: Mapping[str, Any]) -> str:
    """Hash a physically reconstructed P6 review set."""

    return _content_sha256(review_set)


def validate_successor_runtime_review_status(
    raw: Mapping[str, Any],
    *,
    expected_implementation_root_sha256: str | None = None,
    expected_successor_qualification_sha256: str | None = None,
) -> tuple[bool, str]:
    """Validate the sealed projection without consulting Git or the network."""

    if set(raw) != _TOP_LEVEL_FIELDS:
        return False, "successor_review_status_fields_mismatch"
    if raw.get("schema_version") != SUCCESSOR_RUNTIME_REVIEW_STATUS_VERSION:
        return False, "successor_review_status_schema_mismatch"
    status = raw.get("status")
    if status not in {"in_progress", "reviewed"}:
        return False, "successor_review_status_invalid"
    if raw.get("p6_formal_benchmark") is not False or raw.get("p6_release_eligible") is not False:
        return False, "successor_review_status_p6_non_release_boundary_invalid"
    implementation_root = str(raw.get("implementation_root_sha256") or "")
    successor_sha = str(raw.get("successor_qualification_sha256") or "")
    if _SHA256_RE.fullmatch(implementation_root) is None:
        return False, "successor_review_status_implementation_root_invalid"
    if _SHA256_RE.fullmatch(successor_sha) is None:
        return False, "successor_review_status_qualification_invalid"
    if (
        expected_implementation_root_sha256 is not None
        and implementation_root != expected_implementation_root_sha256
    ):
        return False, "successor_review_status_implementation_root_mismatch"
    if (
        expected_successor_qualification_sha256 is not None
        and successor_sha != expected_successor_qualification_sha256
    ):
        return False, "successor_review_status_qualification_mismatch"

    reviewed = status == "reviewed"
    candidate_sha = str(raw.get("candidate_git_sha") or "")
    candidate_tree = str(raw.get("candidate_git_tree") or "")
    evidence_hashes = tuple(
        str(raw.get(name) or "")
        for name in (
            "p6_qualification_file_sha256",
            "p6_qualification_content_sha256",
            "p6_final_evidence_manifest_file_sha256",
            "evidence_bundle_sha256",
            "review_set_sha256",
        )
    )
    if reviewed:
        if (
            _GIT_OBJECT_RE.fullmatch(candidate_sha) is None
            or _GIT_OBJECT_RE.fullmatch(candidate_tree) is None
        ):
            return False, "successor_review_status_candidate_binding_invalid"
        if any(_SHA256_RE.fullmatch(value) is None for value in evidence_hashes):
            return False, "successor_review_status_evidence_binding_invalid"
    elif any((candidate_sha, candidate_tree, *evidence_hashes)):
        return False, "successor_review_in_progress_must_not_claim_evidence"
    if not _review_roots_valid(raw.get("reviewer_roots"), reviewed=reviewed):
        return False, "successor_review_status_reviewer_roots_invalid"
    # Relational review-set validation requires physical packet/raw/decision
    # resources and is intentionally deferred to the current-status validator.
    body = {key: value for key, value in raw.items() if key != "content_sha256"}
    if raw.get("content_sha256") != _content_sha256(body):
        return False, "successor_review_status_content_hash_mismatch"
    return True, "valid"


def validate_current_successor_runtime_review_status(
    raw: Mapping[str, Any],
) -> tuple[bool, str]:
    try:
        successor = load_successor_qualification()
    except (OSError, TypeError, ValueError):
        return False, "successor_review_status_qualification_not_current"
    valid, reason = validate_successor_runtime_review_status(
        raw,
        expected_implementation_root_sha256=str(successor["implementation_root_sha256"]),
        expected_successor_qualification_sha256=str(successor["content_sha256"]),
    )
    if not valid:
        return valid, reason
    package_resources = resources.files(__package__)
    bundle_root = Path(str(package_resources.joinpath(SUCCESSOR_REVIEW_EVIDENCE_DIRECTORY)))
    receipt_path = Path(
        str(package_resources.joinpath(SUCCESSOR_REVIEW_INTEGRATION_RECEIPT_RESOURCE))
    )
    if raw.get("status") != "reviewed":
        if (
            bundle_root.exists()
            or bundle_root.is_symlink()
            or receipt_path.exists()
            or receipt_path.is_symlink()
        ):
            return False, "successor_review_in_progress_contains_review_evidence"
        return False, "successor_review_in_progress"
    if bundle_root.is_symlink() or not bundle_root.is_dir():
        return False, "successor_review_evidence_unavailable"
    try:
        tree_sha256 = _regular_tree_sha256(bundle_root)
    except (OSError, TypeError, ValueError):
        return False, "successor_review_evidence_binding_mismatch"
    if tree_sha256 != raw.get("evidence_bundle_sha256"):
        return False, "successor_review_evidence_binding_mismatch"
    if receipt_path.is_symlink() or not receipt_path.is_file():
        return False, "successor_review_evidence_unavailable"
    try:
        receipt = _load_json_object(receipt_path)
    except (OSError, TypeError, ValueError):
        return False, "successor_review_evidence_binding_mismatch"
    if not _integration_receipt_valid(receipt, expected_status=raw):
        return False, "successor_review_evidence_binding_mismatch"
    return True, "current_successor_reviewed"


def build_in_progress_successor_runtime_review_status(
    successor_qualification: Mapping[str, Any],
) -> dict[str, Any]:
    """Build the only status allowed before physical review evidence exists."""

    empty_root = {
        "artifact_id": "",
        "artifact_sha256": "",
        "packet_sha256": "",
        "decision_sha256": "",
        "raw_envelope_sha256": "",
        "reviewer_identity_sha256": "",
        "review_artifact_sha256": "",
        "decision": "",
        "blocker_count": None,
    }
    body: dict[str, Any] = {
        "schema_version": SUCCESSOR_RUNTIME_REVIEW_STATUS_VERSION,
        "status": "in_progress",
        "candidate_git_sha": "",
        "candidate_git_tree": "",
        "implementation_root_sha256": str(successor_qualification["implementation_root_sha256"]),
        "successor_qualification_sha256": str(successor_qualification["content_sha256"]),
        "p6_qualification_file_sha256": "",
        "p6_qualification_content_sha256": "",
        "p6_final_evidence_manifest_file_sha256": "",
        "evidence_bundle_sha256": "",
        "review_set_sha256": "",
        "reviewer_roots": {role: dict(empty_root) for role in SUCCESSOR_REVIEW_ROLES},
        "p6_formal_benchmark": False,
        "p6_release_eligible": False,
    }
    body["content_sha256"] = _content_sha256(body)
    return body


def _load_successor_runtime_review_status() -> dict[str, Any]:
    try:
        raw = _load_json_object(
            resources.files(__package__).joinpath(SUCCESSOR_RUNTIME_REVIEW_STATUS_RESOURCE)
        )
    except (OSError, TypeError, ValueError):
        return {}
    if not validate_successor_runtime_review_status(raw)[0]:
        return {}
    return raw


SUCCESSOR_RUNTIME_REVIEW_MANIFEST = _load_successor_runtime_review_status()
SUCCESSOR_RUNTIME_REVIEW_STATUS = str(SUCCESSOR_RUNTIME_REVIEW_MANIFEST.get("status") or "blocked")


def current_successor_reviewed() -> bool:
    return validate_current_successor_runtime_review_status(SUCCESSOR_RUNTIME_REVIEW_MANIFEST)[0]


__all__ = [
    "SUCCESSOR_REVIEW_ROLES",
    "SUCCESSOR_RUNTIME_REVIEW_MANIFEST",
    "SUCCESSOR_RUNTIME_REVIEW_STATUS",
    "SUCCESSOR_RUNTIME_REVIEW_STATUS_RESOURCE",
    "SUCCESSOR_RUNTIME_REVIEW_STATUS_VERSION",
    "current_successor_reviewed",
    "build_in_progress_successor_runtime_review_status",
    "review_set_sha256",
    "validate_current_successor_runtime_review_status",
    "validate_successor_runtime_review_status",
]
