#!/usr/bin/env python3
"""Strict helpers for E0 review packets, decisions, and protected evidence."""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Mapping


PACKET_SCHEMA_VERSION = "zscope.range-v16-review-packet.v1"
DECISION_SCHEMA_VERSION = "zscope.range-v16-review-decision.v1"
ATTESTATION_SCHEMA_VERSION = "zscope.e0-attestation.v1"
REVIEW_PROVENANCE_SCHEMA_VERSION = "zscope.range-v16-review-provenance.v1"
CONTRACT_KINDS = {
    "concrete_trigger",
    "public_api_contract",
    "pattern_model",
    "retired",
}
REVIEWER_ROLES = {"primary_fable", "primary_deepseek", "arbiter_opus"}
DISPOSITIONS = {"keep", "correct", "retire", "unresolved"}
REASON_CODES = {
    "TRIGGER_PRESENT",
    "PUBLIC_CONTRACT_SUPPORTED",
    "TRIGGER_INCOMPLETE",
    "THREAT_ASSUMPTION_UNSUPPORTED",
    "ANCHOR_CORRECTION_REQUIRED",
    "CATEGORY_CORRECTION_REQUIRED",
    "DUPLICATE_TRUTH",
    "CODE_COUNTEREVIDENCE",
    "SAFE_PAIR_REQUIRED",
    "INSUFFICIENT_EVIDENCE",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
CLAUSE_ID_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
TAXONOMY_ID_RE = re.compile(r"^[a-z][a-z0-9_]{1,127}$")
CWE_ID_RE = re.compile(r"^CWE-[0-9]+$")
ARTIFACT_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

_FORBIDDEN_KEYS = {
    "candidate_id",
    "candidate_uid",
    "candidate_ledger",
    "finding_id",
    "findings",
    "product_report",
    "report_path",
    "rule_id",
    "rule_ids",
    "score",
    "scorer_output",
    "validation_result",
    "validator_verdict",
    "llm_usage",
}
_FORBIDDEN_VALUE_MARKERS = (
    "benchmark-artifacts/",
    "benchmark-artifacts\\",
    "zscope_batch_report.json",
    "llm_usage_events.jsonl",
    "candidate_ledger",
    "score.json",
    "evaluation.json",
)
_SECRET_RE = re.compile(
    r"(?i)(?:api[_-]?key|authorization|bearer|secret|password)\s*[:=]\s*[^\s,}\]]+"
)


class E0GovernanceError(ValueError):
    """Raised when an E0 governance artifact fails closed."""


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_value(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json_strict(path: Path) -> Any:
    def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise E0GovernanceError(f"duplicate JSON key in {path}: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate,
            parse_constant=lambda raw: (_ for _ in ()).throw(
                E0GovernanceError(f"non-finite JSON number in {path}: {raw}")
            ),
        )
    except UnicodeDecodeError as exc:
        raise E0GovernanceError(f"artifact is not UTF-8: {path}") from exc
    if _contains_non_finite(value):
        raise E0GovernanceError(f"artifact contains non-finite number: {path}")
    return value


def _contains_non_finite(value: Any) -> bool:
    if isinstance(value, float):
        return not math.isfinite(value)
    if isinstance(value, Mapping):
        return any(_contains_non_finite(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_non_finite(item) for item in value)
    return False


def assert_minimal_review_packet(value: Any, *, path: str = "$") -> None:
    """Reject product results, score material, credentials, and non-packet data."""

    if isinstance(value, Mapping):
        for raw_key, nested in value.items():
            key = str(raw_key).strip().lower()
            if key in _FORBIDDEN_KEYS:
                raise E0GovernanceError(f"forbidden review-packet key at {path}.{raw_key}")
            assert_minimal_review_packet(nested, path=f"{path}.{raw_key}")
        return
    if isinstance(value, list):
        for index, nested in enumerate(value):
            assert_minimal_review_packet(nested, path=f"{path}[{index}]")
        return
    if isinstance(value, str):
        lowered = value.lower()
        for marker in _FORBIDDEN_VALUE_MARKERS:
            if marker.lower() in lowered:
                raise E0GovernanceError(
                    f"forbidden review-packet scalar marker at {path}: {marker}"
                )
        if _SECRET_RE.search(value):
            raise E0GovernanceError(f"possible credential in review packet at {path}")


def validate_review_packet(packet: Mapping[str, Any]) -> None:
    expected = {
        "schema_version",
        "packet_uid",
        "source_truth_sha256",
        "truth_record",
        "code_windows",
        "threat_assumptions",
        "safe_pair_candidate",
        "packet_sha256",
    }
    if set(packet) != expected:
        raise E0GovernanceError("review packet fields do not match v1 contract")
    if packet.get("schema_version") != PACKET_SCHEMA_VERSION:
        raise E0GovernanceError("review packet schema_version is invalid")
    if not str(packet.get("packet_uid") or "").startswith("range-v16:"):
        raise E0GovernanceError("review packet UID is invalid")
    if not SHA256_RE.fullmatch(str(packet.get("source_truth_sha256") or "")):
        raise E0GovernanceError("review packet source truth hash is invalid")
    truth_record = packet.get("truth_record")
    if not isinstance(truth_record, Mapping) or not str(truth_record.get("id") or ""):
        raise E0GovernanceError("review packet truth record is invalid")
    if packet.get("packet_uid") != f"range-v16:{truth_record['id']}":
        raise E0GovernanceError("review packet UID does not bind the truth record")
    windows = packet.get("code_windows")
    if not isinstance(windows, list) or not windows:
        raise E0GovernanceError("review packet requires code windows")
    for window in windows:
        if not isinstance(window, Mapping) or set(window) != {
            "path",
            "start_line",
            "end_line",
            "content",
            "sha256",
        }:
            raise E0GovernanceError("review packet code window fields are invalid")
        raw_path = window.get("path")
        if not isinstance(raw_path, str) or not raw_path or "\\" in raw_path:
            raise E0GovernanceError("review packet code window path is invalid")
        path = PurePosixPath(raw_path)
        if (
            path.is_absolute()
            or str(path) != raw_path
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise E0GovernanceError("review packet code window path is not canonical")
        start_line = window.get("start_line")
        end_line = window.get("end_line")
        if (
            isinstance(start_line, bool)
            or not isinstance(start_line, int)
            or isinstance(end_line, bool)
            or not isinstance(end_line, int)
            or start_line < 1
            or end_line < start_line
        ):
            raise E0GovernanceError("review packet code window line range is invalid")
        content = window.get("content")
        if not isinstance(content, str) or not content:
            raise E0GovernanceError("review packet code window content is invalid")
        expected_line_count = end_line - start_line + 1
        if len(content.splitlines()) != expected_line_count:
            raise E0GovernanceError("review packet code window line count is inconsistent")
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        if window.get("sha256") != content_hash:
            raise E0GovernanceError("review packet code window hash mismatch")
    assumptions = packet.get("threat_assumptions")
    if not isinstance(assumptions, list) or not all(
        isinstance(item, str) and item.strip() for item in assumptions
    ):
        raise E0GovernanceError("review packet threat assumptions are invalid")
    if not isinstance(packet.get("safe_pair_candidate"), Mapping):
        raise E0GovernanceError("review packet safe pair candidate is invalid")
    assert_minimal_review_packet(packet)
    claimed = str(packet.get("packet_sha256") or "")
    unsigned = dict(packet)
    unsigned.pop("packet_sha256", None)
    if claimed != sha256_value(unsigned):
        raise E0GovernanceError("review packet content hash mismatch")


def validate_review_decision(
    decision: Mapping[str, Any],
    *,
    expected_packet_uid: str,
    expected_packet_sha256: str,
    expected_role: str,
) -> None:
    expected = {
        "schema_version",
        "packet_uid",
        "packet_sha256",
        "reviewer_role",
        "reviewer_model",
        "contract_kind",
        "disposition",
        "confidence",
        "defect_taxonomy_id",
        "cwe_ids",
        "structured_anchors",
        "required_evidence_clauses",
        "evidence_refs",
        "trigger_summary",
        "threat_assumptions",
        "safe_pair_recommendation",
        "reason_codes",
    }
    if set(decision) != expected:
        raise E0GovernanceError("review decision fields do not match v1 contract")
    if decision.get("schema_version") != DECISION_SCHEMA_VERSION:
        raise E0GovernanceError("review decision schema_version is invalid")
    if decision.get("packet_uid") != expected_packet_uid:
        raise E0GovernanceError("review decision packet UID mismatch")
    if decision.get("packet_sha256") != expected_packet_sha256:
        raise E0GovernanceError("review decision packet hash mismatch")
    if decision.get("reviewer_role") != expected_role or expected_role not in REVIEWER_ROLES:
        raise E0GovernanceError("review decision role mismatch")
    if decision.get("contract_kind") not in CONTRACT_KINDS:
        raise E0GovernanceError("review decision contract kind is invalid")
    if decision.get("disposition") not in DISPOSITIONS:
        raise E0GovernanceError("review decision disposition is invalid")
    confidence = decision.get("confidence")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise E0GovernanceError("review decision confidence must be numeric")
    if not math.isfinite(float(confidence)) or not 0 <= float(confidence) <= 1:
        raise E0GovernanceError("review decision confidence is outside [0,1]")
    if not TAXONOMY_ID_RE.fullmatch(str(decision.get("defect_taxonomy_id") or "")):
        raise E0GovernanceError("review decision defect taxonomy ID is invalid")
    cwe_ids = decision.get("cwe_ids")
    if (
        not isinstance(cwe_ids, list)
        or not cwe_ids
        or not all(isinstance(value, str) and CWE_ID_RE.fullmatch(value) for value in cwe_ids)
    ):
        raise E0GovernanceError("review decision CWE identities are invalid")
    if len(set(cwe_ids)) != len(cwe_ids):
        raise E0GovernanceError("review decision CWE identities are duplicate")
    anchors = decision.get("structured_anchors")
    if not isinstance(anchors, list) or not anchors:
        raise E0GovernanceError("review decision structured_anchors must be non-empty")
    for anchor in anchors:
        if not isinstance(anchor, Mapping) or set(anchor) != {
            "kind",
            "corrected",
            "file",
            "function",
            "start_line",
            "end_line",
        }:
            raise E0GovernanceError("review decision structured anchor fields are invalid")
        if anchor.get("kind") not in {"primary", "secondary", "additional"}:
            raise E0GovernanceError("review decision structured anchor kind is invalid")
        if not isinstance(anchor.get("corrected"), bool):
            raise E0GovernanceError("review decision anchor correction flag is invalid")
        if not isinstance(anchor.get("file"), str) or not anchor["file"]:
            raise E0GovernanceError("review decision structured anchor file is invalid")
        path = PurePosixPath(str(anchor["file"]))
        if (
            path.is_absolute()
            or str(path) != anchor["file"]
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise E0GovernanceError("review decision structured anchor path is not canonical")
        if not isinstance(anchor.get("function"), str) or not anchor["function"]:
            raise E0GovernanceError("review decision structured anchor function is invalid")
        start = anchor.get("start_line")
        end = anchor.get("end_line")
        if (
            isinstance(start, bool)
            or not isinstance(start, int)
            or isinstance(end, bool)
            or not isinstance(end, int)
            or start < 1
            or end < start
        ):
            raise E0GovernanceError("review decision structured anchor range is invalid")
    clauses = decision.get("required_evidence_clauses")
    if not isinstance(clauses, list) or not clauses:
        raise E0GovernanceError("review decision required evidence clauses must be non-empty")
    clause_ids: set[str] = set()
    for clause in clauses:
        if not isinstance(clause, Mapping) or set(clause) != {
            "clause_id",
            "predicate",
            "evidence_refs",
        }:
            raise E0GovernanceError("review decision evidence clause fields are invalid")
        clause_id = str(clause.get("clause_id") or "")
        if not CLAUSE_ID_RE.fullmatch(clause_id) or clause_id in clause_ids:
            raise E0GovernanceError("review decision evidence clause ID is invalid or duplicate")
        clause_ids.add(clause_id)
        if not isinstance(clause.get("predicate"), str) or not clause["predicate"].strip():
            raise E0GovernanceError("review decision evidence clause predicate is invalid")
        clause_refs = clause.get("evidence_refs")
        if not isinstance(clause_refs, list) or not all(
            isinstance(value, str) and value.strip() for value in clause_refs
        ):
            raise E0GovernanceError("review decision evidence clause refs are invalid")
    evidence_refs = decision.get("evidence_refs")
    if not isinstance(evidence_refs, list) or not all(
        isinstance(value, str) and value.strip() for value in evidence_refs
    ):
        raise E0GovernanceError("review decision evidence refs are invalid")
    if (
        not isinstance(decision.get("trigger_summary"), str)
        or not decision["trigger_summary"].strip()
    ):
        raise E0GovernanceError("review decision trigger summary is invalid")
    threat_assumptions = decision.get("threat_assumptions")
    if (
        not isinstance(threat_assumptions, list)
        or not threat_assumptions
        or not all(isinstance(value, str) and value.strip() for value in threat_assumptions)
    ):
        raise E0GovernanceError("review decision threat assumptions are invalid")
    codes = decision.get("reason_codes")
    if not isinstance(codes, list) or not codes or not set(codes).issubset(REASON_CODES):
        raise E0GovernanceError("review decision reason codes are invalid")
    safe_pair = decision.get("safe_pair_recommendation")
    if not isinstance(safe_pair, Mapping) or set(safe_pair) != {
        "kind",
        "invariant_summary",
        "vulnerable_summary",
        "safe_summary",
        "compile_requirements",
    }:
        raise E0GovernanceError("review decision safe pair recommendation is invalid")
    if safe_pair.get("kind") not in {"fixed", "near_miss"}:
        raise E0GovernanceError("review decision safe pair kind is invalid")
    for field in ("invariant_summary", "vulnerable_summary", "safe_summary"):
        if not isinstance(safe_pair.get(field), str) or not safe_pair[field].strip():
            raise E0GovernanceError(f"review decision safe pair {field} is invalid")
    compile_requirements = safe_pair.get("compile_requirements")
    if (
        not isinstance(compile_requirements, list)
        or not compile_requirements
        or not all(isinstance(value, str) and value.strip() for value in compile_requirements)
    ):
        raise E0GovernanceError("review decision compile requirements are invalid")


def validate_review_provenance(
    value: Mapping[str, Any],
    *,
    expected_workflow_run_id: str | None = None,
    expected_workflow_head_sha: str | None = None,
    expected_packet_source_sha: str | None = None,
    expected_artifact_digest: str | None = None,
) -> None:
    expected = {
        "schema_version",
        "workflow_path",
        "workflow_run_id",
        "workflow_head_sha",
        "packet_source_sha",
        "environment",
        "artifact_name",
        "artifact_digest",
        "packet_catalog_sha256",
        "review_bundle_sha256",
    }
    if set(value) != expected or value.get("schema_version") != REVIEW_PROVENANCE_SCHEMA_VERSION:
        raise E0GovernanceError("review provenance fields or schema are invalid")
    if value.get("workflow_path") != ".github/workflows/range-v16-review.yml":
        raise E0GovernanceError("review provenance workflow is untrusted")
    run_id = value.get("workflow_run_id")
    if isinstance(run_id, bool) or not isinstance(run_id, int) or run_id < 1:
        raise E0GovernanceError("review provenance run ID is invalid")
    if expected_workflow_run_id is not None and str(run_id) != str(expected_workflow_run_id):
        raise E0GovernanceError("review provenance run ID mismatch")
    workflow_head_sha = str(value.get("workflow_head_sha") or "")
    packet_source_sha = str(value.get("packet_source_sha") or "")
    if not GIT_SHA_RE.fullmatch(workflow_head_sha) or not GIT_SHA_RE.fullmatch(packet_source_sha):
        raise E0GovernanceError("review provenance commit identity is invalid")
    if expected_workflow_head_sha is not None and workflow_head_sha != expected_workflow_head_sha:
        raise E0GovernanceError("review provenance workflow head SHA mismatch")
    if expected_packet_source_sha is not None and packet_source_sha != expected_packet_source_sha:
        raise E0GovernanceError("review provenance packet source SHA mismatch")
    if value.get("environment") != "sealed-benchmark":
        raise E0GovernanceError("review provenance environment is untrusted")
    if value.get("artifact_name") != f"range-v16-reviewed-{packet_source_sha}":
        raise E0GovernanceError("review provenance artifact name is invalid")
    digest = str(value.get("artifact_digest") or "")
    if not ARTIFACT_DIGEST_RE.fullmatch(digest):
        raise E0GovernanceError("review provenance artifact digest is invalid")
    if expected_artifact_digest is not None and digest != expected_artifact_digest:
        raise E0GovernanceError("review provenance artifact digest mismatch")
    for field in ("packet_catalog_sha256", "review_bundle_sha256"):
        if not SHA256_RE.fullmatch(str(value.get(field) or "")):
            raise E0GovernanceError(f"review provenance {field} is invalid")


def attestation_content_sha256(payload: Mapping[str, Any]) -> str:
    unsigned = dict(payload)
    unsigned.pop("content_sha256", None)
    return sha256_value(unsigned)


def validate_e0_attestation(
    payload: Mapping[str, Any],
    *,
    expected_workflow_run_id: str,
    expected_head_sha: str,
) -> None:
    expected = {
        "schema_version",
        "issued_at",
        "workflow",
        "component_commits",
        "artifacts",
        "review_summary",
        "invariants",
        "content_sha256",
    }
    if set(payload) != expected or payload.get("schema_version") != ATTESTATION_SCHEMA_VERSION:
        raise E0GovernanceError("E0 attestation fields or schema are invalid")
    issued_at = payload.get("issued_at")
    if not isinstance(issued_at, str):
        raise E0GovernanceError("E0 attestation issue time is invalid")
    try:
        issued = datetime.fromisoformat(issued_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise E0GovernanceError("E0 attestation issue time is invalid") from exc
    if issued.tzinfo is None:
        raise E0GovernanceError("E0 attestation issue time must include a timezone")
    workflow = payload.get("workflow")
    if not isinstance(workflow, Mapping) or set(workflow) != {
        "path",
        "run_id",
        "head_sha",
        "environment",
    }:
        raise E0GovernanceError("E0 attestation workflow identity is missing")
    if workflow.get("path") != ".github/workflows/range-v16-benchmark-v5-attestation.yml":
        raise E0GovernanceError("E0 attestation workflow path is untrusted")
    if str(workflow.get("run_id") or "") != str(expected_workflow_run_id):
        raise E0GovernanceError("E0 attestation workflow run ID mismatch")
    if workflow.get("head_sha") != expected_head_sha or not GIT_SHA_RE.fullmatch(
        str(expected_head_sha)
    ):
        raise E0GovernanceError("E0 attestation head SHA mismatch")
    if workflow.get("environment") != "sealed-benchmark":
        raise E0GovernanceError("E0 attestation environment is untrusted")
    commits = payload.get("component_commits")
    if not isinstance(commits, Mapping) or set(commits) != {"governance", "scorer", "truth"}:
        raise E0GovernanceError("E0 component commit bindings are invalid")
    if not all(GIT_SHA_RE.fullmatch(str(item or "")) for item in commits.values()):
        raise E0GovernanceError("E0 component commit SHA is invalid")
    artifacts = payload.get("artifacts")
    required_artifacts = {
        "truth_v16",
        "truth_v16_content",
        "truth_contract_manifest",
        "truth_manifest",
        "source_truth_v15",
        "review_packet_catalog",
        "review_packet_catalog_content",
        "normalized_decisions",
        "normalized_decisions_content",
        "safe_pair_author_manifest",
        "safe_pair_author_content",
        "safe_pair_author_artifact",
        "review_bundle",
        "review_bundle_content",
        "review_provenance",
        "safe_pair_manifest",
        "defect_taxonomy",
        "benchmark_policy",
        "scorer_bundle",
    }
    if not isinstance(artifacts, Mapping) or set(artifacts) != required_artifacts:
        raise E0GovernanceError("E0 artifact bindings are incomplete")
    if not all(SHA256_RE.fullmatch(str(item or "")) for item in artifacts.values()):
        raise E0GovernanceError("E0 artifact SHA is invalid")
    summary = payload.get("review_summary")
    if not isinstance(summary, Mapping) or set(summary) != {
        "record_count",
        "dual_review_count",
        "opus_review_count",
        "disputed_opus_count",
    }:
        raise E0GovernanceError("E0 review summary is missing")
    if summary.get("record_count") != 136 or summary.get("dual_review_count") != 136:
        raise E0GovernanceError("E0 requires 136 dual-reviewed records")
    opus_count = summary.get("opus_review_count")
    if (
        isinstance(opus_count, bool)
        or not isinstance(opus_count, int)
        or not 9 <= opus_count <= 136
        or summary.get("disputed_opus_count") != 9
    ):
        raise E0GovernanceError("E0 Opus arbitration coverage is incomplete")
    invariants = payload.get("invariants")
    required_invariants = {
        "matcher_v2_unchanged",
        "v15_read_only",
        "safe_units_cover_confirmable_truth",
        "scanner_answer_isolated",
        "raw_reviews_artifact_only",
        "product_runtime_unchanged",
    }
    if not isinstance(invariants, Mapping) or set(invariants) != required_invariants:
        raise E0GovernanceError("E0 invariant declaration is invalid")
    if any(invariants.get(key) is not True for key in required_invariants):
        raise E0GovernanceError("E0 hard invariant is not satisfied")
    if payload.get("content_sha256") != attestation_content_sha256(payload):
        raise E0GovernanceError("E0 attestation content hash mismatch")


__all__ = [
    "ATTESTATION_SCHEMA_VERSION",
    "DECISION_SCHEMA_VERSION",
    "E0GovernanceError",
    "PACKET_SCHEMA_VERSION",
    "REVIEW_PROVENANCE_SCHEMA_VERSION",
    "assert_minimal_review_packet",
    "attestation_content_sha256",
    "canonical_json_bytes",
    "load_json_strict",
    "sha256_file",
    "sha256_value",
    "validate_e0_attestation",
    "validate_review_decision",
    "validate_review_packet",
    "validate_review_provenance",
]
