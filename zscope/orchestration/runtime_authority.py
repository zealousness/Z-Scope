"""Strict P5 runtime-authority identity and cache epoch.

The manifest is data, not a feature switch.  Public entry points bind the same
semantic, hunting, proof, and trace revisions so pre-P5 reports cannot be
mistaken for current decision evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
from importlib import resources
from typing import Any, Mapping

from .decision_trace import DECISION_TRACE_SCHEMA_VERSION


RUNTIME_AUTHORITY_SCHEMA_VERSION = "zscope.runtime-authority-manifest.v1"
RUNTIME_AUTHORITY_PROTOCOL_REVISION = 1
RUNTIME_CACHE_EPOCH = "zscope.runtime-authority.p5"
P5_RELEASE_STATUS_SCHEMA_VERSION = "zscope.p5-release-status.v1"
SECURITY_SPEC_MODE = "authoritative"
HYPOTHESIS_HUNTER_MODE = "active"
ACTIVE_PRODUCT_EFFECT = "candidate_registration_only"
PROOF_KERNEL_MODE = "authoritative"
_HEX_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _content_sha256(value: Mapping[str, Any]) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def validate_p5_release_status(raw: Mapping[str, Any]) -> tuple[bool, str]:
    """Validate the evidence-only release latch bundled with the wheel.

    The latch is deliberately data rather than product code so completion can
    bind final read-only reviews without changing the reviewed implementation.
    Invalid or missing data always blocks release.
    """

    expected = {
        "schema_version",
        "phase",
        "status",
        "reviewed_commit",
        "reviewed_tree",
        "qualification_manifest_sha256",
        "review_artifact_sha256",
        "content_sha256",
    }
    if set(raw) != expected:
        return False, "p5_release_status_fields_mismatch"
    if raw.get("schema_version") != P5_RELEASE_STATUS_SCHEMA_VERSION:
        return False, "p5_release_status_schema_mismatch"
    if raw.get("phase") != "P5":
        return False, "p5_release_status_phase_mismatch"
    status = raw.get("status")
    if status not in {"in_progress", "complete"}:
        return False, "p5_release_status_invalid"
    reviewed_commit = str(raw.get("reviewed_commit") or "")
    reviewed_tree = str(raw.get("reviewed_tree") or "")
    qualification_hash = str(raw.get("qualification_manifest_sha256") or "")
    reviews = raw.get("review_artifact_sha256")
    if not isinstance(reviews, Mapping) or set(reviews) != {
        "product_architecture",
        "proof_security",
    }:
        return False, "p5_release_review_bindings_invalid"
    if status == "complete":
        if _HEX_RE.fullmatch(reviewed_commit) is None or len(reviewed_commit) != 40:
            return False, "p5_release_reviewed_commit_invalid"
        if _HEX_RE.fullmatch(reviewed_tree) is None or len(reviewed_tree) != 40:
            return False, "p5_release_reviewed_tree_invalid"
        if _SHA256_RE.fullmatch(qualification_hash) is None:
            return False, "p5_release_qualification_binding_invalid"
        if any(_SHA256_RE.fullmatch(str(value)) is None for value in reviews.values()):
            return False, "p5_release_review_binding_invalid"
    elif any((reviewed_commit, reviewed_tree, qualification_hash, *reviews.values())):
        return False, "p5_release_in_progress_must_not_claim_reviews"
    body = {key: value for key, value in raw.items() if key != "content_sha256"}
    if raw.get("content_sha256") != _content_sha256(body):
        return False, "p5_release_status_content_hash_mismatch"
    return True, "valid"


def _load_p5_release_status() -> dict[str, Any]:
    try:
        raw = json.loads(
            resources.files("zscope.orchestration")
            .joinpath("p5-release-status.json")
            .read_text(encoding="utf-8")
        )
    except (OSError, ValueError, TypeError):
        return {}
    if not isinstance(raw, dict) or not validate_p5_release_status(raw)[0]:
        return {}
    return raw


P5_RELEASE_MANIFEST = _load_p5_release_status()
P5_RELEASE_STATUS = str(P5_RELEASE_MANIFEST.get("status") or "blocked")


def build_runtime_authority_manifest(
    *,
    source_tree_hash: str,
    config_sha256: str,
    backend_sha256: str,
    security_spec_root_sha256: str = "",
    hypothesis_hunter_root_sha256: str = "",
    proof_root_sha256: str = "",
    revisions: Mapping[str, str],
) -> dict[str, Any]:
    body = {
        "schema_version": RUNTIME_AUTHORITY_SCHEMA_VERSION,
        "protocol_revision": RUNTIME_AUTHORITY_PROTOCOL_REVISION,
        "cache_epoch": RUNTIME_CACHE_EPOCH,
        "source_tree_hash": str(source_tree_hash),
        "config_sha256": str(config_sha256),
        "backend_sha256": str(backend_sha256),
        "artifact_roots": {
            "security_spec": str(security_spec_root_sha256),
            "hypothesis_hunter": str(hypothesis_hunter_root_sha256),
            "proof_engine": str(proof_root_sha256),
        },
        "modes": {
            "security_spec": SECURITY_SPEC_MODE,
            "hypothesis_hunter": HYPOTHESIS_HUNTER_MODE,
            "hypothesis_hunter_effect": ACTIVE_PRODUCT_EFFECT,
            "proof_engine": PROOF_KERNEL_MODE,
        },
        "revisions": {str(key): str(value) for key, value in sorted(revisions.items())},
        "decision_trace_schema": DECISION_TRACE_SCHEMA_VERSION,
    }
    valid, reason = validate_runtime_authority_manifest(body, sealed=False)
    if not valid:
        raise ValueError(reason)
    return {**body, "content_sha256": _content_sha256(body)}


def validate_runtime_authority_manifest(
    raw: Mapping[str, Any], *, sealed: bool = True
) -> tuple[bool, str]:
    required = {
        "schema_version",
        "protocol_revision",
        "cache_epoch",
        "source_tree_hash",
        "config_sha256",
        "backend_sha256",
        "artifact_roots",
        "modes",
        "revisions",
        "decision_trace_schema",
    }
    expected = required | ({"content_sha256"} if sealed else set())
    if set(raw) != expected:
        return False, "runtime_authority_manifest_fields_mismatch"
    if raw.get("schema_version") != RUNTIME_AUTHORITY_SCHEMA_VERSION:
        return False, "runtime_authority_manifest_schema_mismatch"
    if raw.get("protocol_revision") != RUNTIME_AUTHORITY_PROTOCOL_REVISION:
        return False, "runtime_authority_protocol_revision_mismatch"
    if raw.get("cache_epoch") != RUNTIME_CACHE_EPOCH:
        return False, "runtime_authority_cache_epoch_mismatch"
    if _HEX_RE.fullmatch(str(raw.get("source_tree_hash") or "")) is None:
        return False, "runtime_authority_source_tree_hash_invalid"
    for key in ("config_sha256", "backend_sha256"):
        if _SHA256_RE.fullmatch(str(raw.get(key) or "")) is None:
            return False, f"runtime_authority_{key}_invalid"
    roots = raw.get("artifact_roots")
    if not isinstance(roots, Mapping) or set(roots) != {
        "security_spec",
        "hypothesis_hunter",
        "proof_engine",
    }:
        return False, "runtime_authority_artifact_roots_invalid"
    if any(value and _SHA256_RE.fullmatch(str(value)) is None for value in roots.values()):
        return False, "runtime_authority_artifact_root_hash_invalid"
    modes = raw.get("modes")
    if not isinstance(modes, Mapping) or dict(modes) != {
        "security_spec": SECURITY_SPEC_MODE,
        "hypothesis_hunter": HYPOTHESIS_HUNTER_MODE,
        "hypothesis_hunter_effect": ACTIVE_PRODUCT_EFFECT,
        "proof_engine": PROOF_KERNEL_MODE,
    }:
        return False, "runtime_authority_modes_invalid"
    revisions = raw.get("revisions")
    if not isinstance(revisions, Mapping) or not revisions:
        return False, "runtime_authority_revisions_missing"
    if any(not str(key) or not str(value) for key, value in revisions.items()):
        return False, "runtime_authority_revision_identity_empty"
    if raw.get("decision_trace_schema") != DECISION_TRACE_SCHEMA_VERSION:
        return False, "runtime_authority_trace_schema_mismatch"
    if sealed:
        body = {key: value for key, value in raw.items() if key != "content_sha256"}
        if raw.get("content_sha256") != _content_sha256(body):
            return False, "runtime_authority_content_hash_mismatch"
    return True, "valid"
