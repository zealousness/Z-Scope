"""Allowlisted, key-and-scalar candidate-blind prompt projection."""

from __future__ import annotations

import json
import re
import unicodedata
from typing import Any, Mapping, Sequence

from .models import validate_attack_surface_audit_unit, validate_hypothesis_offer


class CandidateBlindProjectionError(ValueError):
    """Raised when a P4 prompt projection contains a prohibited signal."""


_PROHIBITED_TOKENS = frozenset(
    {
        "candidate",
        "ledger",
        "rule",
        "groundtruth",
        "truth",
        "benchmark",
        "scorer",
        "score",
        "verdict",
        "confirmed",
        "rejected",
        "historicalverdict",
    }
)
_PROHIBITED_PATTERNS = (
    re.compile(r"\bcand(?:idate)?[_-]?[a-z0-9]{6,}\b", re.IGNORECASE),
    re.compile(r"\brule[_-]?[a-z0-9]{3,}\b", re.IGNORECASE),
    re.compile(r"\b(?:tp|fp|fn|tn)[_-]?\d+\b", re.IGNORECASE),
)


def _guard_text(value: Any) -> str:
    normalized = unicodedata.normalize("NFKC", str(value)).casefold()
    return re.sub(r"[^a-z0-9]+", "", normalized)


def _walk(value: Any, *, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key)
            guarded = _guard_text(key_text)
            if any(token in guarded for token in _PROHIBITED_TOKENS):
                raise CandidateBlindProjectionError(f"prohibited prompt key at {path}.{key_text}")
            _walk(item, path=f"{path}.{key_text}")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _walk(item, path=f"{path}[{index}]")
        return
    if isinstance(value, (str, int, float, bool)):
        text = str(value)
        guarded = _guard_text(text)
        if any(token in guarded for token in _PROHIBITED_TOKENS):
            raise CandidateBlindProjectionError(f"prohibited prompt scalar at {path}")
        if any(pattern.search(text) for pattern in _PROHIBITED_PATTERNS):
            raise CandidateBlindProjectionError(f"prohibited prompt identifier at {path}")


def assert_candidate_blind(value: Mapping[str, Any]) -> None:
    """Reject leakage in both structured keys and ordinary scalar values."""

    _walk(value)
    # Exercise the exact serialized form passed to the model as a second guard.
    serialized = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    _walk(serialized, path="$serialized")


def build_candidate_blind_projection(
    audit_unit: Mapping[str, Any],
    offers: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    valid, reason = validate_attack_surface_audit_unit(audit_unit)
    if not valid:
        raise ValueError("invalid_attack_surface_audit_unit:" + reason)
    projected_offers = []
    allowed_evidence: set[str] = set()
    allowed_facts: set[str] = set()
    for offer in offers:
        valid, reason = validate_hypothesis_offer(offer)
        if not valid:
            raise ValueError("invalid_hypothesis_offer:" + reason)
        if offer.get("audit_unit_uid") != audit_unit.get("audit_unit_uid"):
            raise ValueError("offer_audit_unit_binding_mismatch")
        action_summaries = [
            {
                "action_uid": str(action.get("action_uid") or ""),
                "predicate_id": str(action.get("predicate_id") or ""),
                "fact_kind": str(action.get("fact_kind") or ""),
                "quantifier": str(action.get("quantifier") or ""),
            }
            for action in offer.get("evidence_actions") or []
        ]
        fact_refs = {
            "supporting_fact_refs": list(offer.get("supporting_fact_refs") or []),
            "opposing_fact_refs": list(offer.get("opposing_fact_refs") or []),
            "unknown_fact_refs": list(offer.get("unknown_fact_refs") or []),
        }
        projected_offers.append(
            {
                "offer_uid": str(offer.get("offer_uid") or ""),
                "defect_family": str(offer.get("defect_family") or ""),
                "subject_uid": str(offer.get("subject_uid") or ""),
                "decision_region_uid": str(offer.get("decision_region_uid") or ""),
                "location": dict(offer.get("location") or {}),
                "source_ref": offer.get("source_ref"),
                "sink_ref": offer.get("sink_ref"),
                "resource_ref": offer.get("resource_ref"),
                "proof_clauses": {
                    "positive": [
                        {
                            "clause_uid": str(value.get("clause_uid") or ""),
                            "predicate_id": str(value.get("predicate_id") or ""),
                            "fact_kind": str(value.get("fact_kind") or ""),
                            "quantifier": str(value.get("quantifier") or ""),
                        }
                        for value in (offer.get("proof_obligation") or {}).get(
                            "confirmation_clauses", []
                        )
                    ],
                    "negative": [
                        {
                            "clause_uid": str(value.get("clause_uid") or ""),
                            "predicate_id": str(value.get("predicate_id") or ""),
                            "fact_kind": str(value.get("fact_kind") or ""),
                            "quantifier": str(value.get("quantifier") or ""),
                        }
                        for value in (offer.get("proof_obligation") or {}).get(
                            "counterproof_clauses", []
                        )
                    ],
                    "open": [
                        {
                            "clause_uid": str(value.get("clause_uid") or ""),
                            "predicate_id": str(value.get("predicate_id") or ""),
                            "fact_kind": str(value.get("fact_kind") or ""),
                            "quantifier": str(value.get("quantifier") or ""),
                        }
                        for value in (offer.get("proof_obligation") or {}).get("open_clauses", [])
                    ],
                },
                "evidence_actions": action_summaries,
                **fact_refs,
                "evidence_refs": list(offer.get("evidence_refs") or []),
            }
        )
        allowed_evidence.update(map(str, offer.get("evidence_refs") or []))
        for values in fact_refs.values():
            allowed_facts.update(map(str, values))
    projection = {
        "schema_version": "zscope.hypothesis-hunter-projection.v2",
        "audit_unit": {
            "audit_unit_uid": str(audit_unit.get("audit_unit_uid") or ""),
            "unit_fingerprint_sha256": str(audit_unit.get("unit_fingerprint_sha256") or ""),
            "risk_level": int(audit_unit.get("risk_score") or 0),
            # The model sees only neutral attack/gap reasons, never the source
            # data used to compute localized signal desert state.
            "attack_signals": [
                ("localized_signal_desert" if value == "localized_candidate_desert" else value)
                for value in audit_unit.get("trigger_kinds") or []
            ],
            "root_entry_uids": list(audit_unit.get("root_entry_uids") or []),
            "member_function_uids": list(audit_unit.get("member_function_uids") or []),
            "event_refs": list(audit_unit.get("event_refs") or []),
            "security_spec_refs": list(audit_unit.get("security_spec_refs") or []),
            "unknown_refs": list(audit_unit.get("unknown_refs") or []),
            "backend_coverage": dict(audit_unit.get("backend_coverage") or {}),
        },
        "offers": projected_offers,
        "allowed_evidence_refs": sorted(allowed_evidence),
        "allowed_fact_refs": sorted(allowed_facts),
    }
    assert_candidate_blind(projection)
    return projection
