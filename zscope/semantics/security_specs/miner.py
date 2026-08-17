"""Deterministic-first SecuritySpec miner with bounded proposal caching."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence

from .canonical import canonical_json, content_sha256
from .compiler import SecuritySpecCompiler
from .models import build_security_spec, validate_security_spec
from .registry import PREDICATE_REGISTRY, registry_manifest


_CLAIM_TO_PREDICATE = {
    "input_origin": "source",
    "sensitive_sink": "sink",
    "sanitizer": "sanitize",
    "resource_transition": "acquire",
    "ownership_transfer": "transfer",
    "state_transition": "state_transition",
    "callback_lifetime": "callback_retains",
}


def _default_parameters(predicate: str, value: Mapping[str, Any]) -> Optional[dict[str, Any]]:
    slot = str(value.get("slot") or value.get("source_slot") or "")
    label = str(value.get("label") or "untrusted")
    if predicate == "source" and slot:
        return {"source_slot": slot, "label": label}
    if predicate == "sink" and slot:
        return {"sink_slot": slot, "label": label}
    if predicate == "sanitize":
        source_slots = value.get("from_slots")
        target = str(value.get("to_slot") or "")
        if isinstance(source_slots, list) and source_slots and target:
            return {"from_slots": list(source_slots), "to_slot": target, "label": label}
    if predicate == "acquire" and slot:
        return {
            "resource_slot": slot,
            "resource_kind": str(value.get("resource_kind") or "custom"),
        }
    if predicate == "transfer" and slot:
        return {
            "resource_slot": slot,
            "from_owner": str(value.get("from_owner") or "caller"),
            "to_owner": str(value.get("to_owner") or "callee"),
        }
    if predicate == "state_transition" and slot and "from_value" in value and "to_value" in value:
        return {
            "state_slot": slot,
            "from_value": value["from_value"],
            "to_value": value["to_value"],
        }
    if predicate == "callback_retains" and slot:
        retained = value.get("retained_slots")
        if isinstance(retained, list) and retained:
            return {
                "callback_slot": slot,
                "retained_slots": list(retained),
                "lifetime": str(value.get("lifetime") or "async"),
            }
    return None


class SecuritySpecMiner:
    """Project strict semantic claims into verified-scoped spec candidates."""

    def mine_program_facts(self, facts: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
        """Project exact index/AST/user-workbook facts through the finite DSL.

        Adapters must provide already-resolved subjects, slots, scopes, evidence,
        and dependency hashes.  An incomplete binding remains an observation;
        this boundary never guesses a slot or widens a scope.
        """

        specs: list[dict[str, Any]] = []
        observations: list[dict[str, Any]] = []
        for index, raw in enumerate(facts):
            fact = dict(raw)
            fact_id = str(fact.get("fact_id") or f"program_fact:{index}")
            if fact.get("binding_complete") is not True:
                observations.append(
                    {"fact_id": fact_id, "reason": "program_fact_binding_incomplete"}
                )
                continue
            predicate = str(fact.get("predicate") or "")
            if predicate not in PREDICATE_REGISTRY:
                observations.append(
                    {"fact_id": fact_id, "reason": "program_fact_predicate_unregistered"}
                )
                continue
            try:
                spec = build_security_spec(
                    subject=dict(fact.get("subject") or {}),
                    scope=dict(fact.get("scope") or {}),
                    predicate=predicate,
                    parameters=dict(fact.get("parameters") or {}),
                    evidence_refs=list(fact.get("evidence_refs") or []),
                    dependency_hashes=list(fact.get("dependency_hashes") or []),
                    origin=str(fact.get("origin") or "program"),
                    confidence=float(fact.get("confidence", 1.0)),
                    status="verified_scoped",
                    explanation=f"Projected from exact program fact {fact_id}",
                    impact_preview=list(fact.get("impact_preview") or []),
                )
            except (TypeError, ValueError) as exc:
                observations.append(
                    {"fact_id": fact_id, "reason": f"strict_program_projection_failed:{exc}"}
                )
                continue
            specs.append(spec)
        return {
            "schema_version": "zscope.security-spec-mining-result.v2",
            "mode": "shadow",
            "specs": specs,
            "observations": observations,
        }

    def mine(self, semantic_map: Any) -> dict[str, Any]:
        records = {
            str(record.function_uid): record
            for record in getattr(semantic_map, "functions", ()) or ()
        }
        specs: list[dict[str, Any]] = []
        observations: list[dict[str, Any]] = []
        for claim in getattr(semantic_map, "claims", ()) or ():
            if str(getattr(claim, "origin", "")) == "llm":
                observations.append(
                    {
                        "claim_id": str(getattr(claim, "claim_id", "")),
                        "reason": "llm_claim_requires_bounded_proposal_id",
                    }
                )
                continue
            predicate = _CLAIM_TO_PREDICATE.get(str(getattr(claim, "kind", "")))
            record = records.get(str(getattr(claim, "subject_uid", "")))
            value = getattr(claim, "value", {})
            parameters = (
                _default_parameters(predicate, value)
                if predicate and isinstance(value, Mapping)
                else None
            )
            if predicate is None or record is None or parameters is None:
                observations.append(
                    {
                        "claim_id": str(getattr(claim, "claim_id", "")),
                        "reason": "subject_scope_or_parameters_not_exact",
                    }
                )
                continue
            slots = sorted(
                {
                    str(item)
                    for key, raw in parameters.items()
                    if key.endswith("slot") or key.endswith("slots")
                    for item in (raw if isinstance(raw, list) else [raw])
                }
            )
            dependency_hashes = sorted(
                {
                    str(record.code_hash),
                    str(
                        getattr(record, "backend_coverage", {}).get("content_sha256")
                        or content_sha256(getattr(record, "backend_coverage", {}))
                    ),
                }
            )
            origin = str(getattr(claim, "origin", "program"))
            spec_origin = "user_config" if origin == "user" else origin
            status = "verified_scoped"
            try:
                spec = build_security_spec(
                    subject={
                        "language": str(getattr(semantic_map, "language", "c_cpp") or "c_cpp"),
                        "function_uid": str(record.function_uid),
                        "signature": str(record.signature),
                        "slot_uids": slots,
                    },
                    scope={"kind": "function", "target": str(record.function_uid)},
                    predicate=predicate,
                    parameters=parameters,
                    evidence_refs=list(getattr(claim, "evidence_refs", ()) or ()),
                    dependency_hashes=dependency_hashes,
                    origin=spec_origin,
                    confidence=float(getattr(claim, "confidence", 0.0)),
                    status=status,
                    explanation=f"Projected from semantic claim {getattr(claim, 'claim_id', '')}",
                    impact_preview=[str(record.function_uid)],
                )
            except (TypeError, ValueError) as exc:
                observations.append(
                    {
                        "claim_id": str(getattr(claim, "claim_id", "")),
                        "reason": f"strict_projection_failed:{exc}",
                    }
                )
                continue
            specs.append(spec)
        return {
            "schema_version": "zscope.security-spec-mining-result.v2",
            "mode": "shadow",
            "specs": specs,
            "observations": observations,
        }


class SecuritySpecProposalEngine:
    """Call a supplied model adapter only for unknown units and cache strict proposals."""

    prompt_revision = "zscope.security-spec-miner.v2"

    def __init__(
        self,
        cache_root: Path,
        proposal_fn: Callable[[Mapping[str, Any]], Mapping[str, Any]],
        *,
        model_profile_hash: str,
    ) -> None:
        self.cache_root = Path(cache_root)
        self.proposal_fn = proposal_fn
        self.model_profile_hash = str(model_profile_hash)
        self.llm_call_count = 0

    def propose(
        self,
        *,
        unit_id: str,
        unit_fingerprint: str,
        allowed_subjects: Sequence[Mapping[str, Any]],
        allowed_scopes: Sequence[Mapping[str, Any]],
        allowed_evidence_refs: Sequence[str],
        dependency_hashes: Sequence[str],
        allowed_proposals: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        subject_values = {canonical_json(value) for value in allowed_subjects}
        scope_values = {canonical_json(value) for value in allowed_scopes}
        evidence_values = set(map(str, allowed_evidence_refs))
        dependency_values = sorted(set(map(str, dependency_hashes)))
        proposal_catalog: dict[str, dict[str, Any]] = {}
        for raw in allowed_proposals:
            spec = dict(raw)
            valid, reason = validate_security_spec(spec)
            if not valid:
                raise ValueError("security_spec_allowed_proposal_invalid:" + reason)
            if spec["origin"] != "llm" or spec["status"] != "proposed":
                raise ValueError("security_spec_allowed_proposal_must_be_llm_proposed")
            if canonical_json(spec["subject"]) not in subject_values:
                raise ValueError("security_spec_allowed_proposal_subject_not_allowed")
            if canonical_json(spec["scope"]) not in scope_values:
                raise ValueError("security_spec_allowed_proposal_scope_not_allowed")
            if not set(map(str, spec["evidence_refs"])).issubset(evidence_values):
                raise ValueError("security_spec_allowed_proposal_evidence_not_allowed")
            if sorted(spec["dependency_hashes"]) != dependency_values:
                raise ValueError("security_spec_allowed_proposal_dependency_mismatch")
            proposal_id = "SPECPROP_" + content_sha256(spec)[:32]
            proposal_catalog[proposal_id] = spec
        request = {
            "schema_version": "zscope.security-spec-proposal-request.v2",
            "unit_id": unit_id,
            "unit_fingerprint": unit_fingerprint,
            "allowed_subjects": [dict(value) for value in allowed_subjects],
            "allowed_scopes": [dict(value) for value in allowed_scopes],
            "allowed_evidence_refs": sorted(set(map(str, allowed_evidence_refs))),
            "allowed_proposals": [
                {
                    "proposal_id": proposal_id,
                    "predicate": spec["predicate"],
                    "subject": spec["subject"],
                    "scope": spec["scope"],
                    "parameters": spec["parameters"],
                    "evidence_refs": spec["evidence_refs"],
                }
                for proposal_id, spec in sorted(proposal_catalog.items())
            ],
            "dependency_hashes": dependency_values,
            "prompt_revision": self.prompt_revision,
            "registry_sha256": content_sha256(registry_manifest()),
            "compiler_revision": SecuritySpecCompiler.compiler_version,
            "model_profile_hash": self.model_profile_hash,
        }
        cache_key = content_sha256(request)
        path = self.cache_root / f"{cache_key}.json"
        if path.exists():
            cached = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(cached, dict):
                raise ValueError("security_spec_cache_not_mapping")
            return cached
        self.llm_call_count += 1
        raw = self.proposal_fn(request)
        selected = raw.get("proposal_ids") if isinstance(raw, Mapping) else None
        if not isinstance(selected, list) or any(not isinstance(value, str) for value in selected):
            raise ValueError("security_spec_proposal_ids_not_array")
        if len(selected) != len(set(selected)):
            raise ValueError("security_spec_proposal_ids_duplicate")
        unknown = sorted(set(selected) - set(proposal_catalog))
        if unknown:
            raise ValueError("security_spec_model_selected_unknown_proposal_id")
        accepted = [proposal_catalog[value] for value in selected]
        result = {
            "schema_version": "zscope.security-spec-proposal-result.v2",
            "unit_id": unit_id,
            "unit_fingerprint": unit_fingerprint,
            "specs": accepted,
            "cache_key": cache_key,
        }
        self.cache_root.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(canonical_json(result) + "\n", encoding="utf-8")
        temporary.replace(path)
        return result
