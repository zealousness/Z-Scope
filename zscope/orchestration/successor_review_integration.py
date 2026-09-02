"""Deterministic evidence-only integration receipt and change-scope rules."""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

from zscope.benchmarking.p6_protocol import canonical_sha256


SUCCESSOR_REVIEW_INTEGRATION_RECEIPT_VERSION = "zscope.successor-review-integration-receipt.v1"
SUCCESSOR_REVIEW_INTEGRATION_RECEIPT_RESOURCE = (
    "successor-runtime-review-integration-receipt.v1.json"
)
SUCCESSOR_REVIEW_ALLOWED_EXACT_PATHS = frozenset(
    {
        "zscope/orchestration/successor-runtime-review-status.v1.json",
        "zscope/orchestration/successor-runtime-review-integration-receipt.v1.json",
    }
)
SUCCESSOR_REVIEW_ALLOWED_PREFIXES = ("zscope/orchestration/successor-runtime-review-evidence/",)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT_OBJECT_RE = re.compile(r"^[0-9a-f]{40}$")
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


def build_successor_review_integration_receipt(
    projected_status: Mapping[str, Any],
) -> Mapping[str, Any]:
    if projected_status.get("status") != "reviewed":
        raise ValueError("successor_review_integration_requires_reviewed_projection")
    body: dict[str, Any] = {
        "schema_version": SUCCESSOR_REVIEW_INTEGRATION_RECEIPT_VERSION,
        "candidate_git_sha": projected_status.get("candidate_git_sha"),
        "candidate_git_tree": projected_status.get("candidate_git_tree"),
        "implementation_root_sha256": projected_status.get("implementation_root_sha256"),
        "successor_qualification_sha256": projected_status.get("successor_qualification_sha256"),
        "evidence_bundle_sha256": projected_status.get("evidence_bundle_sha256"),
        "projected_status_sha256": projected_status.get("content_sha256"),
        "p6_qualification_file_sha256": projected_status.get("p6_qualification_file_sha256"),
        "p6_qualification_content_sha256": projected_status.get("p6_qualification_content_sha256"),
        "p6_final_evidence_manifest_file_sha256": projected_status.get(
            "p6_final_evidence_manifest_file_sha256"
        ),
        "review_set_sha256": projected_status.get("review_set_sha256"),
        "p6_formal_benchmark": False,
        "p6_release_eligible": False,
    }
    body["content_sha256"] = canonical_sha256(body)
    valid, reason = validate_successor_review_integration_receipt(
        body, expected_status=projected_status
    )
    if not valid:
        raise ValueError(reason)
    return body


def validate_successor_review_integration_receipt(
    raw: Mapping[str, Any],
    *,
    expected_status: Mapping[str, Any] | None = None,
) -> tuple[bool, str]:
    if set(raw) != _RECEIPT_FIELDS:
        return False, "successor_review_integration_receipt_fields_mismatch"
    if raw.get("schema_version") != SUCCESSOR_REVIEW_INTEGRATION_RECEIPT_VERSION:
        return False, "successor_review_integration_receipt_schema_mismatch"
    if (
        _GIT_OBJECT_RE.fullmatch(str(raw.get("candidate_git_sha") or "")) is None
        or _GIT_OBJECT_RE.fullmatch(str(raw.get("candidate_git_tree") or "")) is None
        or any(
            _SHA256_RE.fullmatch(str(raw.get(name) or "")) is None
            for name in _RECEIPT_FIELDS
            - {
                "schema_version",
                "candidate_git_sha",
                "candidate_git_tree",
                "p6_formal_benchmark",
                "p6_release_eligible",
            }
        )
        or raw.get("p6_formal_benchmark") is not False
        or raw.get("p6_release_eligible") is not False
    ):
        return False, "successor_review_integration_receipt_identity_invalid"
    body = {name: value for name, value in raw.items() if name != "content_sha256"}
    if raw.get("content_sha256") != canonical_sha256(body):
        return False, "successor_review_integration_receipt_seal_invalid"
    if expected_status is not None:
        expected = build_successor_review_integration_receipt_projection(expected_status)
        if dict(raw) != expected:
            return False, "successor_review_integration_receipt_binding_mismatch"
    return True, "valid"


def build_successor_review_integration_receipt_projection(
    projected_status: Mapping[str, Any],
) -> dict[str, Any]:
    body = {
        "schema_version": SUCCESSOR_REVIEW_INTEGRATION_RECEIPT_VERSION,
        "candidate_git_sha": projected_status.get("candidate_git_sha"),
        "candidate_git_tree": projected_status.get("candidate_git_tree"),
        "implementation_root_sha256": projected_status.get("implementation_root_sha256"),
        "successor_qualification_sha256": projected_status.get("successor_qualification_sha256"),
        "evidence_bundle_sha256": projected_status.get("evidence_bundle_sha256"),
        "projected_status_sha256": projected_status.get("content_sha256"),
        "p6_qualification_file_sha256": projected_status.get("p6_qualification_file_sha256"),
        "p6_qualification_content_sha256": projected_status.get("p6_qualification_content_sha256"),
        "p6_final_evidence_manifest_file_sha256": projected_status.get(
            "p6_final_evidence_manifest_file_sha256"
        ),
        "review_set_sha256": projected_status.get("review_set_sha256"),
        "p6_formal_benchmark": False,
        "p6_release_eligible": False,
    }
    body["content_sha256"] = canonical_sha256(body)
    return body


def validate_successor_review_integration_scope(
    *,
    reviewed_candidate_git_sha: str,
    reviewed_candidate_git_tree: str,
    merge_base_git_sha: str,
    base_git_tree: str,
    ancestry_parent_counts: Iterable[int],
    changed_entries: Iterable[tuple[str, str]],
    touched_entries: Iterable[tuple[str, str]] | None = None,
) -> tuple[bool, str]:
    """Validate the Git facts supplied by the repository-facing CLI.

    JSON Schema cannot express Git ancestry or change-scope relations, so the
    CLI derives these facts from Git and this pure reducer enforces them.
    """

    if (
        _GIT_OBJECT_RE.fullmatch(reviewed_candidate_git_sha) is None
        or _GIT_OBJECT_RE.fullmatch(reviewed_candidate_git_tree) is None
        or merge_base_git_sha != reviewed_candidate_git_sha
        or base_git_tree != reviewed_candidate_git_tree
    ):
        return False, "successor_review_integration_base_mismatch"
    counts = tuple(ancestry_parent_counts)
    if not counts or any(type(count) is not int or count != 1 for count in counts):
        return False, "successor_review_integration_parent_lineage_invalid"

    def canonical_path_allowed(path: object) -> bool:
        if not isinstance(path, str) or not path or "\\" in path or path.startswith("/"):
            return False
        parts = path.split("/")
        if any(part in {"", ".", ".."} for part in parts):
            return False
        return path in SUCCESSOR_REVIEW_ALLOWED_EXACT_PATHS or path.startswith(
            SUCCESSOR_REVIEW_ALLOWED_PREFIXES
        )

    def validate_entries(
        entries: Iterable[tuple[str, str]],
    ) -> tuple[tuple[tuple[str, str], ...], tuple[str, ...], str | None]:
        materialized = tuple(entries)
        if not materialized:
            return (), (), "successor_review_integration_change_set_invalid"
        seen: set[str] = set()
        paths: list[str] = []
        for entry in materialized:
            if (
                not isinstance(entry, tuple)
                or len(entry) != 2
                or entry[0] not in {"A", "M", "D"}
                or not isinstance(entry[1], str)
                or entry[1] in seen
            ):
                return (), (), "successor_review_integration_change_set_invalid"
            if not canonical_path_allowed(entry[1]):
                return (), (), "successor_review_integration_scope_violation"
            seen.add(entry[1])
            paths.append(entry[1])
        return materialized, tuple(paths), None

    changed_rows, paths, error = validate_entries(changed_entries)
    if error is not None:
        return False, error
    touched = validate_entries(touched_entries if touched_entries is not None else changed_rows)
    _, _, error = touched
    if error is not None:
        return False, error
    required = {
        "zscope/orchestration/successor-runtime-review-status.v1.json",
        "zscope/orchestration/successor-runtime-review-integration-receipt.v1.json",
    }
    final_present = {path for status, path in changed_rows if status in {"A", "M"}}
    if not required.issubset(final_present) or not any(
        path.startswith(SUCCESSOR_REVIEW_ALLOWED_PREFIXES) for path in final_present
    ):
        return False, "successor_review_integration_evidence_missing"
    return True, "valid_evidence_only_integration"


__all__ = [
    "SUCCESSOR_REVIEW_ALLOWED_EXACT_PATHS",
    "SUCCESSOR_REVIEW_ALLOWED_PREFIXES",
    "SUCCESSOR_REVIEW_INTEGRATION_RECEIPT_RESOURCE",
    "SUCCESSOR_REVIEW_INTEGRATION_RECEIPT_VERSION",
    "build_successor_review_integration_receipt",
    "validate_successor_review_integration_receipt",
    "validate_successor_review_integration_scope",
]
