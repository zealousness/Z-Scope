"""Deterministic verification of model-proposed evidence claims.

The Validator may select a predicate and cite read-only tool results.  It may
not create an authoritative fact.  This module independently checks the
predicate against the frozen structured payload and emits a content-addressed
certificate only when the claim is mechanically supported.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple, cast


EVIDENCE_CLAIM_SCHEMA_VERSION = "zscope.evidence-claim-request.v1"
EVIDENCE_CLAIM_RESULT_VERSION = "zscope.evidence-claim-verification.v1"
EVIDENCE_CERTIFICATE_VERSION = "zscope.evidence-certificate.v1"

CLAIM_STATUSES = frozenset({"verified_true", "verified_false", "unknown", "conflicting"})
CLAIM_POLARITIES = frozenset({"supports", "refutes"})

PREDICATE_FACT_KINDS: Dict[str, str] = {
    "guard_dominates_sink": "guard_dominance",
    "caller_contract_holds": "caller_contract",
    "source_is_externally_controllable": "source_controllability",
    "ownership_transfer_exists": "ownership_transfer",
    "cleanup_covers_all_exits": "cleanup_coverage",
    "lock_must_hold_at_access": "lockset",
    "happens_before_edge_exists": "happens_before",
    "same_object_identity": "object_identity",
    "value_range_is_proved": "value_range",
    "source_sink_path_exists": "source_sink_reachability",
    "signal_context_is_reachable": "signal_context",
    "container_path_is_reachable": "container_reachability",
    "type_layout_is_resolved": "type_layout",
}
FACT_KIND_PREDICATES = {value: key for key, value in PREDICATE_FACT_KINDS.items()}

_TRUE_KEYS: Dict[str, frozenset[str]] = {
    "guard_dominates_sink": frozenset({"guard_dominates_sink", "dominates", "is_conclusive"}),
    "caller_contract_holds": frozenset(
        {"caller_contract_holds", "contract_precondition_enforced", "contract_complete"}
    ),
    "source_is_externally_controllable": frozenset(
        {
            "attacker_controlled",
            "externally_controllable",
            "source_controllable",
            "scanned_entry_parameter_source",
        }
    ),
    "ownership_transfer_exists": frozenset(
        {
            "ownership_transfer_complete",
            "all_exits_release_or_transfer",
            "transfer_complete",
        }
    ),
    "cleanup_covers_all_exits": frozenset(
        {"cleanup_all_paths", "all_exits_covered", "complete_exit_coverage", "cleanup_complete"}
    ),
    "lock_must_hold_at_access": frozenset(
        {"lock_must_hold", "lock_dominates_access", "all_accesses_guarded"}
    ),
    "happens_before_edge_exists": frozenset({"happens_before_proved", "ordered", "hb_edge_exists"}),
    "same_object_identity": frozenset(
        {"same_object", "same_object_identity", "must_alias", "field_sensitive_object_match"}
    ),
    "value_range_is_proved": frozenset(
        {"range_complete", "value_range_proved", "all_paths_index_in_range"}
    ),
    "source_sink_path_exists": frozenset(
        {"reachable", "path_exists", "source_to_sink_complete", "entry_to_sink_path_complete"}
    ),
    "signal_context_is_reachable": frozenset(
        {"signal_context_reachable", "registered_signal_path"}
    ),
    "container_path_is_reachable": frozenset(
        {"container_reachable", "container_traversal_reachable", "path_exists"}
    ),
    "type_layout_is_resolved": frozenset(
        {"type_layout_complete", "layout_resolved", "is_conclusive"}
    ),
}
_SEQUENCE_KEYS: Dict[str, frozenset[str]] = {
    "source_sink_path_exists": frozenset({"flows", "paths", "data_flows", "path_edges"}),
    "happens_before_edge_exists": frozenset({"happens_before", "hb_edges"}),
    "lock_must_hold_at_access": frozenset({"must_hold_locks", "lockset"}),
    "ownership_transfer_exists": frozenset({"transfers", "ownership_transfers"}),
    "cleanup_covers_all_exits": frozenset({"cleanup_paths", "covered_exits"}),
    "type_layout_is_resolved": frozenset({"matches", "declarations", "members"}),
    "caller_contract_holds": frozenset({"contracts", "preconditions"}),
}
_COMPLETENESS_KEYS = frozenset(
    {
        "complete",
        "coverage_complete",
        "complete_exit_coverage",
        "is_conclusive",
        "analysis_complete",
    }
)

_STRICT_PREDICATE_ALLOWED_TOOLS: Dict[str, frozenset[str]] = {
    # Legacy V3 tool results are observations.  ``get_call_graph`` enumerates
    # callers/callees, ``query_pointer_alias`` is only an indirect-callee
    # compatibility alias, and unified ``get_data_flow`` returns backend bug
    # signatures.  None can certify CFG paths, lock/HB, ownership, cleanup,
    # type layout or object identity.  New scans use EvidenceCertificate v2
    # actions; this empty registry makes old claims fail closed during replay.
    predicate: frozenset()
    for predicate in PREDICATE_FACT_KINDS
}

_LEGACY_REPLAY_ALLOWED_TOOLS: Dict[str, frozenset[str]] = {
    "source_sink_path_exists": frozenset({"get_data_flow", "get_call_graph", "get_callers"}),
    "guard_dominates_sink": frozenset({"get_data_flow"}),
    "lock_must_hold_at_access": frozenset({"get_data_flow", "query_pointer_alias"}),
    "happens_before_edge_exists": frozenset({"get_data_flow", "get_call_graph"}),
    "cleanup_covers_all_exits": frozenset({"get_data_flow", "get_call_graph"}),
    "ownership_transfer_exists": frozenset({"get_data_flow", "query_pointer_alias"}),
    "caller_contract_holds": frozenset({"get_callers", "get_call_graph"}),
    "source_is_externally_controllable": frozenset(
        {"get_data_flow", "get_callers", "get_call_graph"}
    ),
    "same_object_identity": frozenset({"query_pointer_alias", "get_data_flow", "get_type_info"}),
    "value_range_is_proved": frozenset({"get_data_flow", "get_type_info"}),
    "type_layout_is_resolved": frozenset({"get_type_info"}),
    "signal_context_is_reachable": frozenset(
        {"get_callers", "get_call_graph", "find_function_pointers"}
    ),
    "container_path_is_reachable": frozenset(
        {"get_data_flow", "get_call_graph", "query_pointer_alias"}
    ),
}


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _hash(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _clean(value: Any, *, limit: int = 1000) -> str:
    return " ".join(str(value or "").strip().split())[:limit]


def _normalized_key(value: Any) -> str:
    return str(value or "").strip().lower().replace("-", "_")


@dataclass(frozen=True)
class EvidenceClaimRequest:
    claim_uid: str
    obligation_uid: str
    fact_kind: str
    predicate: str
    polarity: str
    subject_uid: str
    decision_region_uid: str
    arguments: Dict[str, Any]
    cited_evidence_refs: Tuple[str, ...]
    schema_version: str = EVIDENCE_CLAIM_SCHEMA_VERSION

    @classmethod
    def from_mapping(
        cls,
        raw: Mapping[str, Any],
        *,
        default_obligation_uid: str = "",
        default_subject_uid: str = "",
        default_decision_region_uid: str = "",
    ) -> "EvidenceClaimRequest":
        fact_kind = _normalized_key(raw.get("fact_kind"))
        predicate = _normalized_key(raw.get("predicate") or FACT_KIND_PREDICATES.get(fact_kind))
        polarity = _normalized_key(raw.get("polarity") or "supports")
        obligation_uid = _clean(raw.get("obligation_uid") or default_obligation_uid, limit=512)
        subject_uid = _clean(raw.get("subject_uid") or default_subject_uid, limit=512)
        region_uid = _clean(
            raw.get("decision_region_uid") or default_decision_region_uid,
            limit=512,
        )
        arguments = raw.get("arguments")
        if not isinstance(arguments, Mapping):
            arguments = {}
        refs = raw.get("cited_evidence_refs") or raw.get("evidence_refs")
        if not isinstance(refs, Sequence) or isinstance(refs, str):
            refs = []
        refs_tuple = tuple(sorted({str(item) for item in refs if str(item)}))
        if predicate not in PREDICATE_FACT_KINDS:
            raise ValueError(f"unsupported evidence predicate: {predicate}")
        if PREDICATE_FACT_KINDS[predicate] != fact_kind:
            raise ValueError("evidence predicate does not match fact_kind")
        if polarity not in CLAIM_POLARITIES:
            raise ValueError(f"unsupported evidence claim polarity: {polarity}")
        if not obligation_uid:
            raise ValueError("evidence claim obligation_uid is required")
        if not refs_tuple or len(refs_tuple) > 8:
            raise ValueError("evidence claim requires between 1 and 8 cited refs")
        payload = {
            "obligation_uid": obligation_uid,
            "fact_kind": fact_kind,
            "predicate": predicate,
            "polarity": polarity,
            "subject_uid": subject_uid,
            "decision_region_uid": region_uid,
            "arguments": dict(arguments),
            "cited_evidence_refs": refs_tuple,
        }
        expected_uid = "CLAIM_" + _hash(payload)[:32]
        supplied_uid = _clean(raw.get("claim_uid"), limit=64)
        if supplied_uid and supplied_uid != expected_uid:
            raise ValueError("evidence claim UID does not match its canonical content")
        return cls(
            claim_uid=expected_uid,
            obligation_uid=obligation_uid,
            fact_kind=fact_kind,
            predicate=predicate,
            polarity=polarity,
            subject_uid=subject_uid,
            decision_region_uid=region_uid,
            arguments=dict(arguments),
            cited_evidence_refs=refs_tuple,
        )

    def to_dict(self) -> Dict[str, Any]:
        value = asdict(self)
        value["cited_evidence_refs"] = list(self.cited_evidence_refs)
        return value


@dataclass(frozen=True)
class EvidenceClaimVerification:
    claim_uid: str
    status: str
    reason_code: str
    fact_kind: str
    predicate: str
    polarity: str
    certificate: Dict[str, Any]
    verified_fact: Optional[Dict[str, Any]] = None
    schema_version: str = EVIDENCE_CLAIM_RESULT_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class EvidenceClaimVerifier:
    """Conservative, replayable verifier for frozen read-only tool results."""

    verifier_id = "zscope.structured-tool-claim-verifier"
    verifier_version = "v1"

    def __init__(self, *, allow_legacy_observation_claims: bool = True) -> None:
        # True is retained for read-only historical replay/tests. Production
        # ValidationRunner explicitly selects strict mode and uses certificate
        # actions instead of generic repository tools.
        self.allow_legacy_observation_claims = bool(allow_legacy_observation_claims)

    def verify(
        self,
        claim: EvidenceClaimRequest,
        *,
        issue: Mapping[str, Any],
        tool_catalog: Mapping[str, Mapping[str, Any]],
    ) -> EvidenceClaimVerification:
        identity_error = self._identity_error(claim, issue)
        if identity_error:
            return self._result(claim, "unknown", identity_error, (), ())
        records: list[Mapping[str, Any]] = []
        for ref in claim.cited_evidence_refs:
            record = tool_catalog.get(ref)
            if not isinstance(record, Mapping):
                return self._result(claim, "unknown", "unknown_evidence_ref", (), ())
            result_payload = record.get("result_payload")
            if not isinstance(result_payload, Mapping):
                return self._result(claim, "unknown", "missing_replay_payload", (), ())
            result_hash = str(record.get("result_hash") or "")
            if (
                not re.fullmatch(r"[0-9a-f]{64}", result_hash)
                or _hash(result_payload) != result_hash
            ):
                return self._result(claim, "unknown", "tool_result_hash_mismatch", (), ())
            if result_payload.get("success") is False:
                return self._result(claim, "unknown", "tool_result_failed", (), ())
            tool_name = _normalized_key(record.get("tool_name"))
            allowed_tools = (
                _LEGACY_REPLAY_ALLOWED_TOOLS
                if self.allow_legacy_observation_claims
                else _STRICT_PREDICATE_ALLOWED_TOOLS
            )
            if tool_name not in allowed_tools[claim.predicate]:
                return self._result(
                    claim, "unknown", "tool_not_authoritative_for_predicate", (), ()
                )
            dependency_hash = str(record.get("dependency_code_hash") or "")
            if not re.fullmatch(r"[0-9a-f]{64}", dependency_hash):
                return self._result(claim, "unknown", "missing_dependency_hash", (), ())
            records.append(record)
        if not claim.arguments or not self._arguments_match(claim.arguments, records):
            return self._result(
                claim,
                "unknown",
                "claim_arguments_not_replayed",
                tuple(str(value.get("result_hash") or "") for value in records),
                tuple(str(value.get("dependency_code_hash") or "") for value in records),
            )

        true_signal = False
        false_signal = False
        complete = False
        result_hashes: list[str] = []
        dependency_hashes: list[str] = []
        locations: list[Mapping[str, Any]] = []
        for record in records:
            payload = cast(Mapping[str, Any], record["result_payload"])
            truths, falses = self._boolean_signals(payload, _TRUE_KEYS[claim.predicate])
            true_signal = true_signal or truths
            false_signal = false_signal or falses
            true_signal = true_signal or self._sequence_signal(
                payload, _SEQUENCE_KEYS.get(claim.predicate, frozenset())
            )
            complete = complete or self._completeness_signal(payload)
            result_hashes.append(str(record.get("result_hash") or ""))
            dependency_hashes.append(str(record.get("dependency_code_hash") or ""))
            location = record.get("location")
            if isinstance(location, Mapping):
                locations.append(dict(location))

        # Existence predicates can be proved by a concrete non-empty witness.
        # A false/absence claim is universal and therefore requires complete
        # backend coverage rather than an empty query result alone.
        if true_signal and false_signal:
            status = "conflicting"
            reason = "structured_tool_results_conflict"
        elif true_signal and locations and any(dependency_hashes):
            status = "verified_true" if claim.polarity == "supports" else "verified_false"
            reason = (
                "structured_predicate_witness"
                if claim.polarity == "supports"
                else "structured_predicate_contradicts_refutation"
            )
        elif false_signal and complete:
            status = "verified_true" if claim.polarity == "refutes" else "verified_false"
            reason = (
                "complete_structured_refutation_witness"
                if claim.polarity == "refutes"
                else "complete_structured_counter_witness"
            )
        else:
            status = "unknown"
            reason = "insufficient_structured_witness"
        return self._result(
            claim,
            status,
            reason,
            tuple(result_hashes),
            tuple(dependency_hashes),
            locations=locations,
            complete=complete,
        )

    def _result(
        self,
        claim: EvidenceClaimRequest,
        status: str,
        reason: str,
        result_hashes: Sequence[str],
        dependency_hashes: Sequence[str],
        *,
        locations: Sequence[Mapping[str, Any]] = (),
        complete: bool = False,
    ) -> EvidenceClaimVerification:
        if status not in CLAIM_STATUSES:
            raise ValueError(f"invalid evidence verification status: {status}")
        certificate_body = {
            "schema_version": EVIDENCE_CERTIFICATE_VERSION,
            "verifier_id": self.verifier_id,
            "verifier_version": self.verifier_version,
            "claim_uid": claim.claim_uid,
            "obligation_uid": claim.obligation_uid,
            "fact_kind": claim.fact_kind,
            "predicate": claim.predicate,
            "polarity": claim.polarity,
            "subject_uid": claim.subject_uid,
            "decision_region_uid": claim.decision_region_uid,
            "cited_evidence_refs": list(claim.cited_evidence_refs),
            "tool_result_hashes": sorted({value for value in result_hashes if value}),
            "dependency_hashes": sorted({value for value in dependency_hashes if value}),
            "locations": [dict(value) for value in locations],
            "analysis_complete": bool(complete),
            "status": status,
            "reason": reason,
        }
        certificate_hash = _hash(certificate_body)
        certificate = {**certificate_body, "certificate_sha256": certificate_hash}
        fact: Optional[Dict[str, Any]] = None
        if status == "verified_true":
            fact_uid = "FACT_VERIFIED_" + certificate_hash[:32]
            fact = {
                "fact_uid": fact_uid,
                "fact_kind": claim.fact_kind,
                "predicate": claim.predicate,
                "polarity": claim.polarity,
                "subject_uid": claim.subject_uid,
                "decision_region_uid": claim.decision_region_uid,
                "evidence_refs": list(claim.cited_evidence_refs),
                "producer_engine": self.verifier_id,
                "provider_id": self.verifier_id,
                "dependency_code_hash": _hash(certificate_body["dependency_hashes"]),
                "locations": [dict(value) for value in locations],
                "verification_status": status,
                "verification_certificate": certificate,
                "satisfies_fact_kinds": [claim.fact_kind],
                "origin": "verified_validator_tool_claim",
            }
        return EvidenceClaimVerification(
            claim_uid=claim.claim_uid,
            status=status,
            reason_code=reason,
            fact_kind=claim.fact_kind,
            predicate=claim.predicate,
            polarity=claim.polarity,
            certificate=certificate,
            verified_fact=fact,
        )

    @staticmethod
    def _identity_error(claim: EvidenceClaimRequest, issue: Mapping[str, Any]) -> str:
        obligation = issue.get("security_obligation")
        obligation = obligation if isinstance(obligation, Mapping) else {}
        obligation_uid = str(
            issue.get("obligation_uid")
            or obligation.get("obligation_uid")
            or issue.get("candidate_uid")
            or ""
        )
        if obligation_uid and claim.obligation_uid != obligation_uid:
            return "claim_obligation_mismatch"
        expected_subjects = {
            str(value)
            for value in (
                issue.get("resource_identity"),
                issue.get("resource_signature"),
                issue.get("source_identity"),
                issue.get("subject_uid"),
                obligation.get("subject_uid"),
                obligation.get("source_uid"),
                obligation.get("sink_uid"),
            )
            if str(value or "")
        }
        if claim.subject_uid and expected_subjects and claim.subject_uid not in expected_subjects:
            return "claim_subject_mismatch"
        expected_region = str(
            issue.get("decision_region_uid") or obligation.get("decision_region_uid") or ""
        )
        if expected_region and claim.decision_region_uid != expected_region:
            return "claim_decision_region_mismatch"
        return ""

    @staticmethod
    def _walk(value: Any) -> Iterable[tuple[str, Any]]:
        if isinstance(value, Mapping):
            for key, nested in value.items():
                normalized = _normalized_key(key)
                yield normalized, nested
                yield from EvidenceClaimVerifier._walk(nested)
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            for nested in value:
                yield from EvidenceClaimVerifier._walk(nested)

    @classmethod
    def _arguments_match(
        cls,
        arguments: Mapping[str, Any],
        records: Sequence[Mapping[str, Any]],
    ) -> bool:
        """Require every model argument to occur verbatim in cited data.

        This prevents a real evidence ref from being paired with a fabricated
        subject, bound, path endpoint, or prose summary.  The verifier still
        recomputes the predicate; argument matching is only an identity gate.
        """

        searchable = [
            (record.get("arguments") or {}, record.get("result_payload") or {})
            for record in records
        ]
        for raw_key, expected in arguments.items():
            key = _normalized_key(raw_key)
            matched = False
            for values in searchable:
                for container in values:
                    for found_key, actual in cls._walk(container):
                        if found_key == key and actual == expected:
                            matched = True
                            break
                    if matched:
                        break
                if matched:
                    break
            if not matched:
                return False
        return True

    @classmethod
    def _boolean_signals(
        cls,
        payload: Mapping[str, Any],
        keys: frozenset[str],
    ) -> tuple[bool, bool]:
        true_signal = False
        false_signal = False
        for key, value in cls._walk(payload):
            if key not in keys or not isinstance(value, bool):
                continue
            true_signal = true_signal or value is True
            false_signal = false_signal or value is False
        return true_signal, false_signal

    @classmethod
    def _sequence_signal(cls, payload: Mapping[str, Any], keys: frozenset[str]) -> bool:
        for key, value in cls._walk(payload):
            if key not in keys:
                continue
            if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
                if len(value) > 0:
                    return True
            if isinstance(value, Mapping) and value:
                return True
        return False

    @classmethod
    def _completeness_signal(cls, payload: Mapping[str, Any]) -> bool:
        return any(key in _COMPLETENESS_KEYS and value is True for key, value in cls._walk(payload))


def verify_evidence_certificate(certificate: Mapping[str, Any]) -> tuple[bool, str]:
    supplied = str(certificate.get("certificate_sha256") or "")
    body = dict(certificate)
    body.pop("certificate_sha256", None)
    if not re.fullmatch(r"[0-9a-f]{64}", supplied):
        return False, "invalid certificate sha256"
    if _hash(body) != supplied:
        return False, "certificate hash mismatch"
    if str(body.get("schema_version") or "") != EVIDENCE_CERTIFICATE_VERSION:
        return False, "unsupported certificate schema"
    if str(body.get("status") or "") not in CLAIM_STATUSES:
        return False, "invalid certificate status"
    return True, "ok"
