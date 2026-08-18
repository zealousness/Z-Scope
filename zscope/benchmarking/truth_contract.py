"""Versioned, independently attestable Range truth verification contracts."""

from __future__ import annotations

import hashlib
import json
import math
import re
from typing import Any, Dict, Mapping, Sequence


TRUTH_CONTRACT_SCHEMA_VERSION = "zscope.range-truth-contract.v1"
TRUTH_CONTRACT_KINDS = frozenset(
    {"concrete_trigger", "public_api_contract", "pattern_model", "retired"}
)
TRUTH_ADJUDICATION_STATUSES = frozenset({"accepted", "corrected", "retired"})
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


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
    "summarize_truth_contract",
    "truth_records_for_contract",
]
