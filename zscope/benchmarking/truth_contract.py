"""Versioned, independently attestable Range truth verification contracts."""

from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import PurePosixPath
from typing import Any, Dict, Mapping, Sequence


TRUTH_CONTRACT_SCHEMA_VERSION = "zscope.range-truth-contract.v1"
TRUTH_CONTRACT_V2_SCHEMA_VERSION = "zscope.range-truth-contract.v2"
TRUTH_CONTRACT_KINDS = frozenset(
    {"concrete_trigger", "public_api_contract", "pattern_model", "retired"}
)
TRUTH_ADJUDICATION_STATUSES = frozenset({"accepted", "corrected", "retired"})
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_TAXONOMY_ID_RE = re.compile(r"^[a-z][a-z0-9_]{1,127}$")
_CLAUSE_ID_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
_ANCHOR_KINDS = frozenset({"primary", "secondary", "additional"})


def _records(truth: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    raw = truth.get("vulnerabilities")
    return [value for value in raw if isinstance(value, Mapping)] if isinstance(raw, list) else []


def summarize_truth_contract(truth: Mapping[str, Any]) -> Dict[str, Any]:
    """Validate v16+ contracts, while keeping v15 artifacts historical/read-only."""

    manifest = truth.get("truth_contract")
    if not isinstance(manifest, Mapping):
        records = _records(truth)
        return {
            "schema_version": TRUTH_CONTRACT_SCHEMA_VERSION,
            "present": False,
            "formal_eligible": False,
            "truth_version": str(truth.get("version") or ""),
            "confirmable_truth_count": len(records),
            "pattern_model_count": 0,
            "retired_count": 0,
            "required_confirmed_tp": math.ceil(0.85 * len(records)),
            "manifest_sha256": "",
            "attestation_sha256": "",
            "reason": "historical truth has no independently attested verification contract",
        }
    if manifest.get("schema_version") == TRUTH_CONTRACT_V2_SCHEMA_VERSION:
        return _summarize_truth_contract_v2(truth, manifest)
    allowed = {
        "schema_version",
        "manifest_sha256",
        "attestation_sha256",
        "independent_review_complete",
        "review_protocol",
    }
    if set(manifest) - allowed:
        raise ValueError("truth_contract contains unknown fields")
    if manifest.get("schema_version") != TRUTH_CONTRACT_SCHEMA_VERSION:
        raise ValueError("unsupported Range truth contract schema")
    manifest_sha = str(manifest.get("manifest_sha256") or "")
    attestation_sha = str(manifest.get("attestation_sha256") or "")
    if not _SHA256_RE.fullmatch(manifest_sha) or not _SHA256_RE.fullmatch(attestation_sha):
        raise ValueError("truth contract manifest and attestation hashes must be sha256")
    if manifest.get("independent_review_complete") is not True:
        raise ValueError("truth contract requires completed independent review")

    counts = {kind: 0 for kind in sorted(TRUTH_CONTRACT_KINDS)}
    canonical_records: list[Dict[str, Any]] = []
    seen: set[str] = set()
    for record in _records(truth):
        truth_id = str(record.get("id") or "")
        if not truth_id or truth_id in seen:
            raise ValueError("truth contract IDs must be unique and non-empty")
        seen.add(truth_id)
        contract = record.get("verification_contract")
        if not isinstance(contract, Mapping):
            raise ValueError(f"truth {truth_id} is missing verification_contract")
        allowed_contract = {
            "kind",
            "adjudication_status",
            "threat_assumptions",
            "required_evidence",
            "adjudication_artifact_sha256",
        }
        if set(contract) - allowed_contract:
            raise ValueError(f"truth {truth_id} verification_contract has unknown fields")
        kind = str(contract.get("kind") or "")
        status = str(contract.get("adjudication_status") or "")
        artifact_sha = str(contract.get("adjudication_artifact_sha256") or "")
        if kind not in TRUTH_CONTRACT_KINDS:
            raise ValueError(f"truth {truth_id} has invalid verification contract kind")
        if status not in TRUTH_ADJUDICATION_STATUSES:
            raise ValueError(f"truth {truth_id} has invalid adjudication status")
        if not _SHA256_RE.fullmatch(artifact_sha):
            raise ValueError(f"truth {truth_id} adjudication artifact hash is invalid")
        if kind == "retired" and status != "retired":
            raise ValueError(f"truth {truth_id} retired contract must have retired status")
        assumptions = contract.get("threat_assumptions")
        required = contract.get("required_evidence")
        if not isinstance(assumptions, list) or not all(
            isinstance(value, str) and value.strip() for value in assumptions
        ):
            raise ValueError(f"truth {truth_id} threat_assumptions must be strings")
        if not isinstance(required, list) or not all(
            isinstance(value, str) and value.strip() for value in required
        ):
            raise ValueError(f"truth {truth_id} required_evidence must be strings")
        counts[kind] += 1
        canonical_records.append(
            {
                "truth_id": truth_id,
                "kind": kind,
                "adjudication_status": status,
                "threat_assumptions": assumptions,
                "required_evidence": required,
                "adjudication_artifact_sha256": artifact_sha,
            }
        )
    calculated_manifest = hashlib.sha256(
        json.dumps(
            canonical_records,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    if calculated_manifest != manifest_sha:
        raise ValueError("truth contract manifest hash does not bind verification records")
    confirmable = counts["concrete_trigger"] + counts["public_api_contract"]
    return {
        "schema_version": TRUTH_CONTRACT_SCHEMA_VERSION,
        "present": True,
        "formal_eligible": True,
        "truth_version": str(truth.get("version") or ""),
        "confirmable_truth_count": confirmable,
        "pattern_model_count": counts["pattern_model"],
        "retired_count": counts["retired"],
        "required_confirmed_tp": math.ceil(0.85 * confirmable),
        "counts_by_kind": counts,
        "manifest_sha256": manifest_sha,
        "attestation_sha256": attestation_sha,
        "review_protocol": str(manifest.get("review_protocol") or ""),
    }


def _summarize_truth_contract_v2(
    truth: Mapping[str, Any], manifest: Mapping[str, Any]
) -> Dict[str, Any]:
    allowed_manifest = {
        "schema_version",
        "manifest_sha256",
        "review_bundle_sha256",
        "taxonomy_sha256",
        "independent_review_complete",
        "review_protocol",
        "safe_unit_count",
    }
    if set(manifest) != allowed_manifest:
        raise ValueError("truth_contract v2 fields do not match the contract")
    for field in ("manifest_sha256", "review_bundle_sha256", "taxonomy_sha256"):
        if not _SHA256_RE.fullmatch(str(manifest.get(field) or "")):
            raise ValueError(f"truth contract v2 {field} must be sha256")
    if manifest.get("independent_review_complete") is not True:
        raise ValueError("truth contract v2 requires completed independent review")
    safe_unit_count = manifest.get("safe_unit_count")
    if isinstance(safe_unit_count, bool) or not isinstance(safe_unit_count, int):
        raise ValueError("truth contract v2 safe_unit_count must be an integer")
    if safe_unit_count < 0:
        raise ValueError("truth contract v2 safe_unit_count cannot be negative")

    expected_contract_fields = {
        "schema_version",
        "kind",
        "adjudication_status",
        "defect_taxonomy_id",
        "structured_anchors",
        "trigger",
        "threat_assumptions",
        "required_evidence_clauses",
        "review_artifacts",
        "safe_pair",
        "fixture_sha256",
    }
    counts = {kind: 0 for kind in sorted(TRUTH_CONTRACT_KINDS)}
    canonical_records: list[Dict[str, Any]] = []
    seen: set[str] = set()
    fixture_hashes: set[str] = set()
    for record in _records(truth):
        truth_id = str(record.get("id") or "")
        if not truth_id or truth_id in seen:
            raise ValueError("truth contract v2 IDs must be unique and non-empty")
        seen.add(truth_id)
        contract = record.get("verification_contract")
        if not isinstance(contract, Mapping) or set(contract) != expected_contract_fields:
            raise ValueError(f"truth {truth_id} verification_contract v2 fields are invalid")
        if contract.get("schema_version") != "zscope.range-truth-record.v2":
            raise ValueError(f"truth {truth_id} record contract schema is invalid")
        kind = str(contract.get("kind") or "")
        status = str(contract.get("adjudication_status") or "")
        if kind not in TRUTH_CONTRACT_KINDS:
            raise ValueError(f"truth {truth_id} has invalid verification contract kind")
        if status not in TRUTH_ADJUDICATION_STATUSES:
            raise ValueError(f"truth {truth_id} has invalid adjudication status")
        if (kind == "retired") != (status == "retired"):
            raise ValueError(f"truth {truth_id} retired contract/status is inconsistent")
        taxonomy_id = str(contract.get("defect_taxonomy_id") or "")
        if not _TAXONOMY_ID_RE.fullmatch(taxonomy_id):
            raise ValueError(f"truth {truth_id} defect taxonomy identity is missing")
        if record.get("category") != taxonomy_id:
            raise ValueError(f"truth {truth_id} category/taxonomy identity is inconsistent")
        anchors = contract.get("structured_anchors")
        if not isinstance(anchors, list) or not anchors:
            raise ValueError(f"truth {truth_id} structured anchors are missing")
        primary_anchors: list[Mapping[str, Any]] = []
        anchor_identities: set[tuple[Any, ...]] = set()
        for anchor in anchors:
            if not isinstance(anchor, Mapping) or set(anchor) != {
                "kind",
                "file",
                "function",
                "start_line",
                "end_line",
            }:
                raise ValueError(f"truth {truth_id} structured anchor is invalid")
            if anchor.get("kind") not in _ANCHOR_KINDS:
                raise ValueError(f"truth {truth_id} structured anchor kind is invalid")
            file_name = str(anchor.get("file") or "")
            path = PurePosixPath(file_name)
            if (
                not file_name
                or "\\" in file_name
                or path.is_absolute()
                or str(path) != file_name
                or any(part in {"", ".", ".."} for part in path.parts)
            ):
                raise ValueError(f"truth {truth_id} anchor file is not canonical")
            if not str(anchor.get("function") or "").strip():
                raise ValueError(f"truth {truth_id} anchor file/function is missing")
            start = anchor.get("start_line")
            end = anchor.get("end_line")
            if (
                isinstance(start, bool)
                or isinstance(end, bool)
                or not isinstance(start, int)
                or not isinstance(end, int)
                or start < 1
                or end < start
            ):
                raise ValueError(f"truth {truth_id} anchor line range is invalid")
            identity = (
                anchor.get("kind"),
                file_name,
                anchor.get("function"),
                start,
                end,
            )
            if identity in anchor_identities:
                raise ValueError(f"truth {truth_id} structured anchors are duplicate")
            anchor_identities.add(identity)
            if anchor.get("kind") == "primary":
                primary_anchors.append(anchor)
        if len(primary_anchors) != 1:
            raise ValueError(f"truth {truth_id} requires exactly one primary anchor")
        primary = primary_anchors[0]
        if any(
            record.get(field) != primary.get(anchor_field)
            for field, anchor_field in (
                ("file", "file"),
                ("function", "function"),
                ("line", "start_line"),
            )
        ):
            raise ValueError(f"truth {truth_id} primary anchor projection is inconsistent")
        trigger = contract.get("trigger")
        if not isinstance(trigger, Mapping) or set(trigger) != {"summary", "evidence_refs"}:
            raise ValueError(f"truth {truth_id} trigger contract is invalid")
        if not str(trigger.get("summary") or ""):
            raise ValueError(f"truth {truth_id} trigger summary is missing")
        evidence_refs = trigger.get("evidence_refs")
        if not isinstance(evidence_refs, list) or not all(
            isinstance(value, str) and value.strip() for value in evidence_refs
        ):
            raise ValueError(f"truth {truth_id} trigger evidence refs are invalid")
        assumptions = contract.get("threat_assumptions")
        clauses = contract.get("required_evidence_clauses")
        if (
            not isinstance(assumptions, list)
            or not assumptions
            or not all(isinstance(value, str) and value.strip() for value in assumptions)
        ):
            raise ValueError(f"truth {truth_id} threat assumptions are invalid")
        if len(assumptions) != len(set(assumptions)):
            raise ValueError(f"truth {truth_id} threat assumptions are duplicate")
        if not isinstance(clauses, list) or not clauses:
            raise ValueError(f"truth {truth_id} required evidence clauses are invalid")
        clause_ids: set[str] = set()
        for clause in clauses:
            if not isinstance(clause, Mapping) or set(clause) != {
                "clause_id",
                "predicate",
                "evidence_refs",
            }:
                raise ValueError(f"truth {truth_id} required evidence clause is invalid")
            clause_id = str(clause.get("clause_id") or "")
            if not _CLAUSE_ID_RE.fullmatch(clause_id) or clause_id in clause_ids:
                raise ValueError(f"truth {truth_id} evidence clause identity is invalid")
            clause_ids.add(clause_id)
            if not str(clause.get("predicate") or "").strip():
                raise ValueError(f"truth {truth_id} evidence clause predicate is invalid")
            refs = clause.get("evidence_refs")
            if not isinstance(refs, list) or not all(
                isinstance(value, str) and value.strip() for value in refs
            ):
                raise ValueError(f"truth {truth_id} evidence clause refs are invalid")
            if len(refs) != len(set(refs)):
                raise ValueError(f"truth {truth_id} evidence clause refs are duplicate")
        reviews = contract.get("review_artifacts")
        required_reviews = {"fable_sha256", "deepseek_sha256", "normalized_sha256"}
        if not isinstance(reviews, Mapping) or not required_reviews.issubset(reviews):
            raise ValueError(f"truth {truth_id} dual review artifacts are missing")
        if set(reviews) - (required_reviews | {"opus_sha256"}):
            raise ValueError(f"truth {truth_id} review artifacts contain unknown fields")
        if not all(_SHA256_RE.fullmatch(str(value or "")) for value in reviews.values()):
            raise ValueError(f"truth {truth_id} review artifact hash is invalid")
        pair = contract.get("safe_pair")
        if not isinstance(pair, Mapping):
            raise ValueError(f"truth {truth_id} safe pair contract is invalid")
        if kind in {"concrete_trigger", "public_api_contract"}:
            required_pair = {
                "pair_uid",
                "manifest_sha256",
                "vulnerable_sha256",
                "fixed_or_near_miss_sha256",
            }
            if set(pair) != required_pair or not str(pair.get("pair_uid") or ""):
                raise ValueError(f"truth {truth_id} confirmable contract requires a safe pair")
            if not all(
                _SHA256_RE.fullmatch(str(value or ""))
                for key, value in pair.items()
                if key != "pair_uid"
            ):
                raise ValueError(f"truth {truth_id} safe pair hash is invalid")
        elif pair:
            raise ValueError(f"truth {truth_id} non-confirmable contract cannot bind a safe pair")
        fixture_sha = str(contract.get("fixture_sha256") or "")
        if not _SHA256_RE.fullmatch(fixture_sha):
            raise ValueError(f"truth {truth_id} fixture hash is invalid")
        fixture_hashes.add(fixture_sha)
        counts[kind] += 1
        canonical_records.append({"truth_id": truth_id, **dict(contract)})

    if len(fixture_hashes) != 1:
        raise ValueError("truth contract v2 records do not bind one fixture snapshot")

    calculated_manifest = hashlib.sha256(
        json.dumps(
            canonical_records,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    if calculated_manifest != str(manifest.get("manifest_sha256")):
        raise ValueError("truth contract v2 manifest hash does not bind verification records")
    confirmable = counts["concrete_trigger"] + counts["public_api_contract"]
    if safe_unit_count < confirmable:
        raise ValueError("truth contract v2 safe units do not cover confirmable truth")
    return {
        "schema_version": TRUTH_CONTRACT_V2_SCHEMA_VERSION,
        "present": True,
        "formal_eligible": True,
        "truth_version": str(truth.get("version") or ""),
        "confirmable_truth_count": confirmable,
        "pattern_model_count": counts["pattern_model"],
        "retired_count": counts["retired"],
        "required_confirmed_tp": math.ceil(0.85 * confirmable),
        "counts_by_kind": counts,
        "safe_unit_count": safe_unit_count,
        "manifest_sha256": str(manifest.get("manifest_sha256")),
        "review_bundle_sha256": str(manifest.get("review_bundle_sha256")),
        "taxonomy_sha256": str(manifest.get("taxonomy_sha256")),
        "attestation_sha256": "",
        "review_protocol": str(manifest.get("review_protocol") or ""),
    }


def truth_records_for_contract(
    truth: Mapping[str, Any],
    *,
    kinds: Sequence[str],
) -> list[Dict[str, Any]]:
    selected = set(kinds)
    result: list[Dict[str, Any]] = []
    for record in _records(truth):
        contract = record.get("verification_contract")
        if not isinstance(contract, Mapping):
            continue
        if str(contract.get("kind") or "") in selected:
            result.append(dict(record))
    return result


__all__ = [
    "TRUTH_ADJUDICATION_STATUSES",
    "TRUTH_CONTRACT_KINDS",
    "TRUTH_CONTRACT_SCHEMA_VERSION",
    "TRUTH_CONTRACT_V2_SCHEMA_VERSION",
    "summarize_truth_contract",
    "truth_records_for_contract",
]
