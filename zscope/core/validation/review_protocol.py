"""Review-only envelope; the public ValidatorResult v3 remains unchanged."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Iterable, Optional

from ...common.validator_protocol import parse_validator_result_v3, validator_result_schema_v3

REVIEW_VERSION = "zscope.review-adjudication.v1"
REJECTION_ASSESSMENTS = (
    "fact_refuted",
    "scope_refuted",
    "unsupported",
    "supported",
    "not_applicable",
)


def review_result_schema() -> Dict[str, Any]:
    refs = {"type": "array", "items": {"type": "string", "minLength": 1}, "maxItems": 32}
    text = {"type": "string", "maxLength": 2000}
    prior = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "assessment": {"type": "string", "enum": list(REJECTION_ASSESSMENTS)},
            "reason": text,
            "evidence_refs": refs,
        },
        "required": ["assessment", "reason", "evidence_refs"],
    }
    case = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "status": {"type": "string", "enum": ["supported", "incomplete", "contradicted"]},
            "subject": text,
            "source": text,
            "sink": text,
            "path": text,
            "trigger": text,
            "guard_analysis": text,
            "evidence_refs": refs,
            "missing_conditions": refs,
        },
        "required": [
            "status",
            "subject",
            "source",
            "sink",
            "path",
            "trigger",
            "guard_analysis",
            "evidence_refs",
            "missing_conditions",
        ],
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "schema_version": {"type": "string", "enum": [REVIEW_VERSION]},
            "decision": validator_result_schema_v3(),
            "prior_rejection": prior,
            "defect_case": case,
        },
        "required": ["schema_version", "decision", "prior_rejection", "defect_case"],
    }


def parse_review_result(
    value: Any,
    *,
    candidate_uid: str,
    cluster_uid: str,
    expected_pass: str,
    allowed_refs: Iterable[str],
    rejection_expected: bool,
) -> Optional[Dict[str, Any]]:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "decision",
        "prior_rejection",
        "defect_case",
    }:
        return None
    if value["schema_version"] != REVIEW_VERSION:
        return None
    allowed_refs = set(allowed_refs)
    decision = parse_validator_result_v3(
        value["decision"],
        candidate_uid=candidate_uid,
        validation_cluster_uid=cluster_uid,
        expected_pass=expected_pass,
        allowed_evidence_refs=allowed_refs,
    )
    if decision is None:
        return None
    prior, case = value["prior_rejection"], value["defect_case"]
    schema = review_result_schema()["properties"]
    for name, record in (("prior_rejection", prior), ("defect_case", case)):
        if not isinstance(record, dict) or set(record) != set(schema[name]["required"]):
            return None
        for key, spec in schema[name]["properties"].items():
            item = record[key]
            if spec["type"] == "string":
                if not isinstance(item, str) or len(item) > spec.get("maxLength", 2000):
                    return None
                if "enum" in spec and item not in spec["enum"]:
                    return None
            elif (
                not isinstance(item, list)
                or len(item) > 32
                or any(not isinstance(ref, str) or not ref or len(ref) > 2000 for ref in item)
            ):
                return None
    allowed = set(allowed_refs)
    if any(ref not in allowed for ref in prior["evidence_refs"] + case["evidence_refs"]):
        return None
    if rejection_expected == (prior["assessment"] == "not_applicable"):
        return None
    return deepcopy(value)


def adjudicate_review(
    envelope: Dict[str, Any], *, backed_refs: Iterable[str]
) -> tuple[Dict[str, Any], str]:
    """Apply necessary evidence gates, never grant deterministic proof authority.

    Passing this gate still requires the ordinary validation promotion policy.
    backed_refs are populated by the runtime, not supplied by the model.
    """
    decision = deepcopy(envelope["decision"])
    case, prior = envelope["defect_case"], envelope["prior_rejection"]
    refs = set(case["evidence_refs"])
    supported = bool(
        case["status"] == "supported"
        and not case["missing_conditions"]
        and refs
        and refs.issubset(set(backed_refs))
        and refs.issubset(set(decision["evidence_refs"]))
        and all(
            str(case[key]).strip()
            for key in ("subject", "source", "sink", "path", "trigger", "guard_analysis")
        )
        and not decision["blocking_negative_evidence"]
        and decision["missing_fact_request"] is None
    )
    refuted = prior["assessment"] in {"fact_refuted", "scope_refuted"} and bool(
        prior["evidence_refs"] and set(prior["evidence_refs"]).issubset(set(backed_refs))
    )
    reason = "review_evidence_recorded"
    if decision["verdict"] == "verified" and not supported:
        decision.update(
            verdict="uncertain", missing_fact_request=None, stop_reason="unsupported_fact"
        )
        reason = "positive_case_incomplete"
    if refuted and not supported:
        decision.update(
            verdict="uncertain", missing_fact_request=None, stop_reason="unsupported_fact"
        )
        reason = "rejection_refuted_unconfirmed"
    elif decision["verdict"] == "verified":
        reason = "positive_case_submitted_for_validation"
    return decision, reason
