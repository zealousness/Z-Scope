from __future__ import annotations

from typing import Any, Dict
import json

from .schema import validate_pattern

from .identity import review_subject_id, stable_id, utc_now


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
    }


def proposal_from_record(record: Dict[str, Any]) -> Dict[str, Any]:
    finding = record.get("finding") or {}
    scope = {key: finding.get(key, "") for key in ("rule", "category", "defect_class", "subcategory")}
    features = []
    issue_fingerprint = finding.get("stable_fingerprint")
    if issue_fingerprint:
        features.append({"kind": "fingerprint", "value": str(issue_fingerprint), "matchable": True})
    source_fingerprint = record.get("source_context", {}).get("source_context_fingerprint")
    proposal = {
        "schema_version": "zscope.false-positive-pattern-proposal.v1",
        "pattern_id": stable_id("fp", {"review_subject_id": review_subject_id(record)}),
        "project_id": record.get("project_id", ""), "scope": scope,
        "trigger_features": features,
        "false_positive_reason": "", "required_checks": [], "counter_conditions": [],
        "evidence_refs": list(record.get("evidence_refs") or []),
        "source_fingerprints": [str(source_fingerprint)] if source_fingerprint else [],
        "origin_review_ids": [str(record.get("review_id"))],
        "review_subject_id": review_subject_id(record),
        "status": "semantic_only" if not features else "proposed",
        "generator": {"kind": "program", "extractor_version": "v1"},
        "created_at": utc_now(), "updated_at": utc_now(),
    }
    return proposal


def extract_with_llm(record: Dict[str, Any], llm_client: Any) -> Dict[str, Any]:
    """Turn one record into a validated proposal; program-owned fields win."""
    base = proposal_from_record(record)
    program_features = list(base.get("trigger_features") or [])
    from ..agents.review_memory.agent import ReviewMemoryAgent
    response = ReviewMemoryAgent(llm_client).run({"extraction_input": build_extraction_input(record)})
    if not response.success:
        raise ValueError(response.error or "review pattern finalization failed")
    parsed = response.data
    for key in ("false_positive_reason", "required_checks", "counter_conditions"):
        if key in parsed:
            base[key] = parsed[key]
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
    base["generator"] = {"kind": "llm", "extractor_version": "v1", "model": getattr(llm_client, "models", [""])[0]}
    base["status"] = "proposed"
    validate_pattern(base)
    return base
