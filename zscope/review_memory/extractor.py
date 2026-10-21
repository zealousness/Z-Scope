from __future__ import annotations

from typing import Any, Dict
import json

from .schema import validate_pattern

from .identity import (
    CANDIDATE_STABLE_FIELDS_SCHEMA, candidate_projection, candidate_scope,
    normalize_candidate_value, review_subject_id, stable_id, utc_now,
)


def build_extraction_input(record: Dict[str, Any]) -> Dict[str, Any]:
    """Build a compact, program-owned projection for the extraction Agent."""
    finding = record.get("finding") or {}
    source = record.get("source_context") or {}
    return {
        "schema_version": "zscope.review-memory-extraction-input.v1",
        "review": {"review_id": record.get("review_id", ""), "user_rebuttal": record.get("user_rebuttal", ""), "manual_decision": "rejected"},
        "scope": {key: finding.get(key, "") for key in ("project_id", "rule", "category", "cwe")},
        "finding": {"candidate_id": finding.get("candidate_id", ""), "function": finding.get("function", ""), "file": finding.get("file", finding.get("source", "")), "line": finding.get("line", finding.get("location", "")), "source_expression": finding.get("source", ""), "sink_expression": finding.get("sink", ""), "code_snippet": finding.get("code_snippet", ""), "source_context_fingerprint": source.get("source_context_fingerprint", "")},
        "program_facts": {"function_role": finding.get("function_role", ""), "input_is_received_here": finding.get("input_is_received_here"), "allocation_copy_relation": finding.get("allocation_copy_relation", ""), "guard_facts": finding.get("guard_facts", []), "call_site_facts": finding.get("call_site_facts", [])},
        "evidence_refs": list(record.get("evidence_refs") or []),
        "candidate_projection": candidate_projection(finding),
    }


def proposal_from_record(record: Dict[str, Any]) -> Dict[str, Any]:
    finding = record.get("finding") or {}
    projection = candidate_projection(finding)
    fields = projection["fields"]
    scope = candidate_scope(finding)
    groups = []
    for key in ("function", "history_key", "candidate_uid", "stable_fingerprint"):
        if fields.get(key):
            groups.append({"all": [{"path": key, "operator": "eq", "value": fields[key]}]})
    semantic = []
    if fields.get("root_cause_key"):
        semantic.append({"path": "root_cause_key", "operator": "eq", "value": fields["root_cause_key"]})
    for key in ("source_identity", "sink_identity", "resource_identity", "obligation_shape"):
        if fields.get(key):
            semantic.append({"path": key, "operator": "eq", "value": fields[key]})
            if len(semantic) >= 2:
                break
    if semantic:
        groups.append({"all": semantic})
    contract = {"schema_version": CANDIDATE_STABLE_FIELDS_SCHEMA, "groups": groups}
    features = [{"kind": p["path"], "value": str(p["value"]), "matchable": True} for g in groups for p in g["all"]]
    contract_digest = stable_id("contract", contract)
    source_fingerprint = record.get("source_context", {}).get("source_context_fingerprint")
    proposal = {
        "schema_version": "zscope.false-positive-pattern-proposal.v1",
        "pattern_id": stable_id("fp", {"project_id": record.get("project_id", ""), "scope": scope, "contract": contract}),
        "project_id": record.get("project_id", ""), "scope": scope,
        "trigger_features": features,
        "match_contract": contract,
        "contract_digest": contract_digest,
        "false_positive_reason": "", "required_checks": [], "counter_conditions": [],
        "evidence_refs": list(record.get("evidence_refs") or []),
        "source_fingerprints": [str(source_fingerprint)] if source_fingerprint else [],
        "origin_review_ids": [str(record.get("review_id"))],
        "review_subject_id": review_subject_id(record),
        "status": "semantic_only" if not features else "proposed",
        "candidate_snapshot": dict(finding),
        "candidate_projection": projection,
        "generator": {"kind": "program", "extractor_version": "v1"},
        "created_at": utc_now(), "updated_at": utc_now(),
    }
    return proposal


def extract_with_llm(record: Dict[str, Any], llm_client: Any) -> Dict[str, Any]:
    """Turn one record into a validated proposal; program-owned fields win."""
    base = proposal_from_record(record)
    program_features = list(base.get("trigger_features") or [])
    program_contract = base.get("match_contract") or {}
    from ..agents.review_memory.agent import ReviewMemoryAgent
    response = ReviewMemoryAgent(llm_client).run({"extraction_input": build_extraction_input(record)})
    if not response.success:
        raise ValueError(response.error or "review pattern finalization failed")
    parsed = response.data
    for key in ("false_positive_reason", "required_checks", "counter_conditions"):
        if key in parsed:
            base[key] = parsed[key]
    proposed_contract = parsed.get("match_contract")
    if isinstance(proposed_contract, dict):
        allowed = {(p.get("path"), str(p.get("value"))) for g in program_contract.get("groups", []) for p in g.get("all", [])}
        valid_groups = []
        for group in proposed_contract.get("groups", []):
            predicates = []
            raw_predicates = group.get("all", []) if isinstance(group, dict) else []
            for predicate in raw_predicates:
                if not isinstance(predicate, dict):
                    continue
                if (predicate.get("path"), str(predicate.get("value"))) in allowed and predicate.get("operator", "eq") in {"eq", "contains"}:
                    predicates.append({"path": predicate["path"], "operator": predicate.get("operator", "eq"), "value": normalize_candidate_value(predicate["value"])})
            if predicates:
                valid_groups.append({"all": predicates})
        if valid_groups:
            base["match_contract"] = {"schema_version": CANDIDATE_STABLE_FIELDS_SCHEMA, "groups": valid_groups}
            base["contract_digest"] = stable_id("contract", base["match_contract"])
    if "trigger_features" in parsed:
        base["trigger_features"] = parsed["trigger_features"]
    parsed_refs = parsed.get("evidence_refs")
    if parsed_refs is not None:
        allowed_refs = {str(ref) for ref in record.get("evidence_refs", [])}
        if not isinstance(parsed_refs, list) or any(str(ref) not in allowed_refs for ref in parsed_refs):
            raise ValueError("LLM cannot introduce evidence references")
        base["evidence_refs"] = [str(ref) for ref in parsed_refs]
    allowed_features = {
        (str(item.get("kind")), str(item.get("value")))
        for item in program_features
        if isinstance(item, dict) and item.get("matchable")
    }
    normalized_features = []
    for item in base.get("trigger_features", []):
        if not isinstance(item, dict):
            continue
        candidate = dict(item)
        if (str(candidate.get("kind")), str(candidate.get("value"))) not in allowed_features:
            candidate["matchable"] = False
        normalized_features.append(candidate)
    base["trigger_features"] = normalized_features
    if not proposed_contract:
        selected = [
            {"path": str(item["kind"]), "operator": "eq", "value": normalize_candidate_value(item["value"])}
            for item in normalized_features
            if item.get("matchable") and item.get("value")
        ]
        if selected:
            base["match_contract"] = {"schema_version": CANDIDATE_STABLE_FIELDS_SCHEMA, "groups": [{"all": [item]} for item in selected]}
            base["contract_digest"] = stable_id("contract", base["match_contract"])
    base["generator"] = {"kind": "llm", "extractor_version": "v1", "model": getattr(llm_client, "models", [""])[0]}
    base["status"] = "proposed"
    validate_pattern(base)
    return base
