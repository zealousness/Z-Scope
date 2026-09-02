"""Attack-surface and localized-coverage planning for the P4 shadow Hunter."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Sequence, Tuple

from ...semantics.security_map import FunctionSecurityRecord, SecurityEvent, SecuritySemanticMap
from .models import (
    build_attack_surface_audit_unit,
    build_hypothesis_offer,
    build_localized_coverage_key,
)


_FAMILY_TO_DEFECT = {
    "memory_bounds": "memory_bounds",
    "resource_lifecycle": "resource_lifecycle",
    "callback_concurrency": "concurrency_safety",
    "state_protocol": "state_protocol",
    "input_boundary": "untrusted_dataflow",
    "auth_boundary": "authorization_boundary",
    "sensitive_sink": "sensitive_operation",
}
_SENSITIVE_FAMILIES = frozenset(
    {
        "memory_bounds",
        "resource_lifecycle",
        "callback_concurrency",
        "auth_boundary",
        "sensitive_sink",
    }
)
_RISK_WEIGHTS = {
    "external_reachable_sensitive": 25,
    "security_spec_unknown": 15,
    "security_spec_conflict": 20,
    "dynamic_call_gap": 15,
    "backend_coverage_gap": 15,
    "localized_candidate_desert": 25,
}


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class PlannedHunt:
    audit_unit: Mapping[str, Any]
    offers: Tuple[Mapping[str, Any], ...]


ProofBundleProvider = Callable[
    [FunctionSecurityRecord, SecurityEvent, Mapping[str, Any]],
    Sequence[Mapping[str, Any]],
]


class AttackSurfacePlanner:
    """Create local work only from attack surface and explicit coverage gaps."""

    def __init__(self, *, risk_threshold: int, max_units: int | None = None) -> None:
        self.risk_threshold = max(0, min(101, int(risk_threshold)))
        self.max_units = max_units if max_units is None else max(0, int(max_units))
        self.diagnostics: list[dict[str, Any]] = []

    def plan(
        self,
        semantic_map: SecuritySemanticMap,
        *,
        security_spec_runtime: Mapping[str, Any] | None = None,
        covered_localized_keys: Iterable[str] = (),
        canonical_investigation_roots: Mapping[str, str] | None = None,
        proof_bundle_provider: ProofBundleProvider | None = None,
    ) -> Tuple[PlannedHunt, ...]:
        if self.max_units == 0:
            return ()
        covered = {str(value) for value in covered_localized_keys if str(value)}
        alias_roots = {
            str(key): str(value)
            for key, value in (canonical_investigation_roots or {}).items()
            if str(key) and str(value)
        }
        spec_refs, conflicting_subjects = self._spec_state(security_spec_runtime or {})
        unknown_by_subject = {
            str(value.subject_uid): str(value.unknown_id) for value in semantic_map.unknowns
        }
        planned: list[PlannedHunt] = []
        seen_roots: set[str] = set()
        for record in sorted(semantic_map.functions, key=lambda value: value.function_uid):
            for event in sorted(record.events, key=lambda value: (value.line, value.event_id)):
                defect_family = _FAMILY_TO_DEFECT.get(event.family)
                if defect_family is None:
                    continue
                provisional = self._provisional_identity(semantic_map, record, event, defect_family)
                try:
                    bundles = (
                        list(proof_bundle_provider(record, event, provisional))
                        if proof_bundle_provider is not None
                        else []
                    )
                except (KeyError, TypeError, ValueError) as exc:
                    # One malformed or currently unexecutable FunctionIR proof
                    # offer is an audit-unit boundary, not permission to drop
                    # every remaining Hunter unit.  Keep the public diagnostic
                    # answer-free: the exception body may contain backend or
                    # source-derived material.
                    bundles = []
                    self.diagnostics.append(
                        {
                            "localized_coverage_key_uid": str(
                                provisional.get("decision_region_uid") or ""
                            ),
                            "reason_code": "PROOF_BUNDLE_PROVIDER_REJECTED",
                            "failure_class": type(exc).__name__,
                        }
                    )
                identities = bundles or [provisional]
                for identity in identities:
                    offer_defect_family = str(identity.get("defect_family") or defect_family)
                    subject_uid = str(identity.get("subject_uid") or provisional["subject_uid"])
                    region_uid = str(
                        identity.get("decision_region_uid") or provisional["decision_region_uid"]
                    )
                    structural_hash = _sha(
                        {
                            "family": defect_family,
                            "function": record.function_uid,
                            "event_kind": event.kind,
                            "subject": subject_uid,
                            "region": region_uid,
                            "code": record.code_hash,
                        }
                    )
                    localized = build_localized_coverage_key(
                        project_uid=semantic_map.project_id,
                        revision_uid=semantic_map.revision,
                        function_uid=record.function_uid,
                        defect_family=defect_family,
                        subject_uid=subject_uid,
                        decision_region_uid=region_uid,
                        structural_fingerprint_sha256=structural_hash,
                    )
                    local_uid = str(localized["key_uid"])
                    investigation_root = alias_roots.get(local_uid, local_uid)
                    if investigation_root in seen_roots:
                        self.diagnostics.append(
                            {
                                "localized_coverage_key_uid": local_uid,
                                "reason_code": "ALIAS_CLUSTER_ALREADY_SCHEDULED",
                            }
                        )
                        continue
                    triggers = self._triggers(
                        record,
                        event,
                        local_uid=local_uid,
                        covered=covered,
                        has_unknown=record.function_uid in unknown_by_subject,
                        has_conflict=record.function_uid in conflicting_subjects,
                    )
                    risk = min(100, sum(_RISK_WEIGHTS[value] for value in triggers))
                    if risk < self.risk_threshold:
                        self.diagnostics.append(
                            {
                                "localized_coverage_key_uid": local_uid,
                                "reason_code": "RISK_BELOW_PROFILE_THRESHOLD",
                                "risk_score": risk,
                            }
                        )
                        continue
                    # A proof-backed offer is bound to the exact ProgramProofIR
                    # dependency domain.  The semantic-map code hash remains a
                    # planner input through the structural fingerprint, but it
                    # must not be appended to a different frozen proof domain.
                    dependency_hashes = sorted(
                        {
                            str(value)
                            for value in identity.get("dependency_hashes") or []
                            if len(str(value)) == 64
                        }
                    )
                    if not bundles and len(str(record.code_hash)) == 64:
                        dependency_hashes = [str(record.code_hash)]
                    if not dependency_hashes:
                        dependency_hashes = [_sha(record.to_dict())]
                    unit = build_attack_surface_audit_unit(
                        project_uid=semantic_map.project_id,
                        revision_uid=semantic_map.revision,
                        risk_score=risk,
                        trigger_kinds=triggers,
                        localized_coverage_key=localized,
                        root_entry_uids=record.entry_identities,
                        member_function_uids=(record.function_uid,),
                        event_refs=(event.evidence_ref,),
                        security_spec_refs=spec_refs.get(record.function_uid, ()),
                        unknown_refs=(
                            (unknown_by_subject[record.function_uid],)
                            if record.function_uid in unknown_by_subject
                            else ()
                        ),
                        dependency_hashes=dependency_hashes,
                        backend_coverage=record.backend_coverage,
                    )
                    offers: list[Mapping[str, Any]] = []
                    if bundles:
                        try:
                            offers.append(
                                build_hypothesis_offer(
                                    audit_unit_uid=str(unit["audit_unit_uid"]),
                                    defect_family=offer_defect_family,
                                    subject_uid=subject_uid,
                                    decision_region_uid=region_uid,
                                    location=identity["location"],
                                    source_ref=identity.get("source_ref"),
                                    sink_ref=identity.get("sink_ref"),
                                    resource_ref=identity.get("resource_ref"),
                                    proof_ir=identity["proof_ir"],
                                    proof_obligation=identity["proof_obligation"],
                                    evidence_actions=identity["evidence_actions"],
                                    supporting_fact_refs=identity.get("supporting_fact_refs", ()),
                                    opposing_fact_refs=identity.get("opposing_fact_refs", ()),
                                    unknown_fact_refs=identity.get("unknown_fact_refs", ()),
                                    evidence_refs=identity.get(
                                        "evidence_refs", (event.evidence_ref,)
                                    ),
                                    dependency_hashes=dependency_hashes,
                                )
                            )
                        except (KeyError, TypeError, ValueError) as exc:
                            self.diagnostics.append(
                                {
                                    "localized_coverage_key_uid": local_uid,
                                    "reason_code": "PROOF_OFFER_REJECTED",
                                    "failure_class": type(exc).__name__,
                                }
                            )
                    seen_roots.add(investigation_root)
                    planned.append(PlannedHunt(audit_unit=unit, offers=tuple(offers)))
                    if self.max_units is not None and len(planned) >= self.max_units:
                        return tuple(planned)
        return tuple(planned)

    @staticmethod
    def _provisional_identity(
        semantic_map: SecuritySemanticMap,
        record: FunctionSecurityRecord,
        event: SecurityEvent,
        defect_family: str,
    ) -> dict[str, Any]:
        subject_uid = (
            "HSUBJ_"
            + _sha([semantic_map.project_id, record.function_uid, defect_family, event.kind])[:32]
        )
        region_uid = (
            "HREGION_" + _sha([record.file_path, record.function_uid, event.line, event.kind])[:32]
        )
        return {
            "subject_uid": subject_uid,
            "decision_region_uid": region_uid,
            "dependency_hashes": [record.code_hash] if len(record.code_hash) == 64 else [],
            # The proof catalog consumes this system-owned identity before it
            # accepts any FunctionIR graph.  Keeping it nested prevents a
            # provider-produced offer from substituting one field without
            # invalidating the complete record/revision binding.
            "graph_record_binding": {
                "project_uid": semantic_map.project_id,
                "revision_uid": semantic_map.revision,
                "function_uid": record.function_uid,
                "function_name": record.function_name,
                "file": record.file_path,
                "code_sha256": record.code_hash,
            },
            "location": {
                "file": record.file_path,
                "function_uid": record.function_uid,
                "start_line": max(1, int(event.line)),
                "end_line": max(1, int(event.line)),
                "statement_uid": event.event_id,
            },
            "source_ref": event.evidence_ref if event.family in {"input_boundary"} else None,
            "sink_ref": event.evidence_ref if event.family != "resource_lifecycle" else None,
            "resource_ref": (event.evidence_ref if event.family == "resource_lifecycle" else None),
        }

    @staticmethod
    def _triggers(
        record: FunctionSecurityRecord,
        event: SecurityEvent,
        *,
        local_uid: str,
        covered: set[str],
        has_unknown: bool,
        has_conflict: bool,
    ) -> list[str]:
        values: list[str] = []
        if event.family in _SENSITIVE_FAMILIES and bool(record.entry_identities):
            values.append("external_reachable_sensitive")
        if has_unknown:
            values.append("security_spec_unknown")
        if has_conflict:
            values.append("security_spec_conflict")
        if record.unresolved_callees:
            values.append("dynamic_call_gap")
        backend_text = _canonical(record.backend_coverage).lower()
        if any(
            value in backend_text for value in ("unavailable", "degraded", "partial", "unknown")
        ):
            values.append("backend_coverage_gap")
        if local_uid not in covered:
            values.append("localized_candidate_desert")
        return values or ["localized_candidate_desert"]

    @staticmethod
    def _spec_state(
        runtime: Mapping[str, Any],
    ) -> tuple[dict[str, tuple[str, ...]], set[str]]:
        compilation = runtime.get("compilation")
        compilation = compilation if isinstance(compilation, Mapping) else {}
        refs: dict[str, list[str]] = {}
        conflicts: set[str] = set()
        for value in compilation.get("compiled_specs") or []:
            if not isinstance(value, Mapping):
                continue
            subject = value.get("subject")
            subject = subject if isinstance(subject, Mapping) else {}
            uid = str(subject.get("function_uid") or subject.get("signature") or "")
            ref = str(value.get("content_sha256") or value.get("compiled_uid") or "")
            if uid and ref:
                refs.setdefault(uid, []).append(ref)
        for value in runtime.get("conflicting_specs") or []:
            if not isinstance(value, Mapping):
                continue
            subject = value.get("subject")
            subject = subject if isinstance(subject, Mapping) else {}
            uid = str(subject.get("function_uid") or subject.get("signature") or "")
            if uid:
                conflicts.add(uid)
        return {key: tuple(sorted(set(values))) for key, values in refs.items()}, conflicts
