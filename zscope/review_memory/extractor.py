from __future__ import annotations

from typing import Any, Dict
import json

from .schema import validate_pattern

from .identity import stable_id, utc_now


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
        "pattern_id": stable_id("fp", {"project_id": record.get("project_id"), "review_id": record.get("review_id")}),
        "project_id": record.get("project_id", ""), "scope": scope,
        "trigger_features": features,
        "false_positive_reason": "", "required_checks": [], "counter_conditions": [],
        "evidence_refs": list(record.get("evidence_refs") or []),
        "source_fingerprints": [str(source_fingerprint)] if source_fingerprint else [],
        "origin_review_ids": [str(record.get("review_id"))],
        "status": "semantic_only" if not features else "proposed",
        "generator": {"kind": "program", "extractor_version": "v1"},
        "created_at": utc_now(), "updated_at": utc_now(),
    }
    return proposal


def extract_with_llm(record: Dict[str, Any], llm_client: Any) -> Dict[str, Any]:
    """Turn one record into a validated proposal; program-owned fields win."""
    base = proposal_from_record(record)
    program_features = list(base.get("trigger_features") or [])
    prompt = {
        "task": "Abstract a conservative false-positive review pattern.",
        "rules": ["Return JSON only", "Do not invent evidence_refs", "Do not decide activation or suppression"],
        "review_record": record,
        "proposal_fields": ["false_positive_reason", "required_checks", "counter_conditions", "trigger_features"],
    }
    response = llm_client.chat_completion(
        [{"role": "system", "content": "You propose advisory review patterns. Current source evidence remains authoritative."},
         {"role": "user", "content": json.dumps(prompt, ensure_ascii=False)}],
        temperature=0.0,
        response_format={"type": "json_object"},
        trace_agent="review_memory",
        trace_label="pattern_extraction",
    )
    content = str(((response.get("choices") or [{}])[0].get("message") or {}).get("content") or "")
    parsed = json.loads(content)
    if not isinstance(parsed, dict):
        raise ValueError("LLM pattern output must be an object")
    for key in ("false_positive_reason", "required_checks", "counter_conditions", "trigger_features"):
        if key in parsed:
            base[key] = parsed[key]
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
