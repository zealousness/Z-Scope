"""Strict contracts for the bounded Validator v3 state machine.

The model contract intentionally contains only decision data.  Runtime and
policy fields (for example the final report bucket) are added by the validation
pipeline and are never accepted from a model response.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple


VALIDATOR_RESULT_VERSION = "zscope.validator-result.v3"
VALIDATOR_PROTOCOL_VERSION = "zscope.validator-protocol.v3"
VALIDATOR_PASSES = frozenset({"initial", "evidence_recheck", "investigation_synthesis"})
VALIDATOR_VERDICTS = frozenset({"verified", "rejected", "uncertain"})
VALIDATOR_MISSING_FACT_KINDS = frozenset(
    {
        "guard_dominance",
        "caller_contract",
        "source_controllability",
        "ownership_transfer",
        "cleanup_coverage",
        "lockset",
        "happens_before",
        "object_identity",
        "value_range",
        "source_sink_reachability",
        "signal_context",
        "container_reachability",
        "type_layout",
    }
)
VALIDATOR_STOP_REASONS = frozenset(
    {
        "decision_complete",
        "missing_fact",
        "no_evidence_gain",
        "unsupported_fact",
        "fact_timeout",
        "duplicate_fact_request",
        "output_truncated",
        "malformed_output",
        "investigation_complete",
        "investigation_exhausted",
    }
)
DYNAMIC_REPRODUCTION_REQUEST_VERSION = "zscope.dynamic-reproduction-request.v1"
DYNAMIC_REPRODUCTION_RESULT_VERSION = "zscope.dynamic-reproduction-result.v1"


def validator_result_schema_v3(
    *,
    candidate_uid: str = "",
    validation_cluster_uid: str = "",
    expected_pass: str = "",
    allowed_evidence_refs: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """Return the provider-facing strict JSON schema.

    Runtime callers bind immutable identities and the evidence-reference
    allow-list directly into the schema.  This makes a provider's structured
    output constraint match the stricter local parser instead of asking the
    model to reproduce those bindings from prose alone.
    """

    schema: Dict[str, Any] = {
        "type": "object",
        "properties": {
            "schema_version": {
                "type": "string",
                "enum": [VALIDATOR_RESULT_VERSION],
            },
            "candidate_uid": {"type": "string", "minLength": 1},
            "validation_cluster_uid": {"type": "string", "minLength": 1},
            "pass": {"type": "string", "enum": sorted(VALIDATOR_PASSES)},
            "verdict": {"type": "string", "enum": sorted(VALIDATOR_VERDICTS)},
            "reasoning": {"type": "string", "minLength": 1, "maxLength": 4000},
            "positive_evidence": {
                "type": "array",
                "items": {"type": "string", "minLength": 1, "maxLength": 1000},
                "maxItems": 12,
            },
            "negative_evidence": {
                "type": "array",
                "items": {"type": "string", "minLength": 1, "maxLength": 1000},
                "maxItems": 12,
            },
            "evidence_refs": {
                "type": "array",
                "items": {"type": "string", "minLength": 1, "maxLength": 512},
                "maxItems": 32,
            },
            "blocking_negative_evidence": {"type": "boolean"},
            "missing_fact_request": {
                "type": ["object", "null"],
                "properties": {
                    "fact_kind": {
                        "type": "string",
                        "enum": sorted(VALIDATOR_MISSING_FACT_KINDS),
                    },
                    "subject_uid": {"type": "string", "maxLength": 512},
                    "function_uid": {"type": "string", "maxLength": 512},
                    "reason": {"type": "string", "minLength": 1, "maxLength": 1000},
                },
                "required": ["fact_kind", "reason"],
                "additionalProperties": False,
            },
            "stop_reason": {
                "type": "string",
                "enum": sorted(VALIDATOR_STOP_REASONS),
            },
        },
        "required": [
            "schema_version",
            "candidate_uid",
            "validation_cluster_uid",
            "pass",
            "verdict",
            "reasoning",
            "positive_evidence",
            "negative_evidence",
            "evidence_refs",
            "blocking_negative_evidence",
            "missing_fact_request",
            "stop_reason",
        ],
        "additionalProperties": False,
        "allOf": [
            {
                "if": {
                    "properties": {"missing_fact_request": {"type": "object"}},
                    "required": ["missing_fact_request"],
                },
                "then": {
                    "properties": {
                        "verdict": {"const": "uncertain"},
                        "stop_reason": {"const": "missing_fact"},
                    }
                },
            },
            {
                "if": {
                    "properties": {"missing_fact_request": {"type": "null"}},
                    "required": ["missing_fact_request"],
                },
                "then": {
                    "properties": {
                        "stop_reason": {"enum": sorted(VALIDATOR_STOP_REASONS - {"missing_fact"})}
                    }
                },
            },
        ],
    }
    properties = schema["properties"]
    if candidate_uid:
        properties["candidate_uid"]["const"] = candidate_uid
    if validation_cluster_uid:
        properties["validation_cluster_uid"]["const"] = validation_cluster_uid
    if expected_pass:
        properties["pass"]["const"] = expected_pass
    if allowed_evidence_refs is not None:
        allowed = sorted({str(value) for value in allowed_evidence_refs if str(value)})
        if allowed:
            properties["evidence_refs"]["items"]["enum"] = allowed
        else:
            properties["evidence_refs"]["maxItems"] = 0
    return schema


_REQUIRED_FIELDS = frozenset(validator_result_schema_v3()["required"])
_MISSING_FIELD_FAILURE_CLASSES = {
    "schema_version": "required_schema_version_missing",
    "candidate_uid": "required_candidate_uid_missing",
    "validation_cluster_uid": "required_validation_cluster_uid_missing",
    "pass": "required_pass_missing",
    "verdict": "required_verdict_missing",
    "reasoning": "required_reasoning_missing",
    "positive_evidence": "required_positive_evidence_missing",
    "negative_evidence": "required_negative_evidence_missing",
    "evidence_refs": "required_evidence_refs_missing",
    "blocking_negative_evidence": "required_blocking_flag_missing",
    "missing_fact_request": "required_missing_fact_request_missing",
    "stop_reason": "required_stop_reason_missing",
}


@dataclass(frozen=True)
class ValidatorResultV3:
    candidate_uid: str
    validation_cluster_uid: str
    validation_pass: str
    verdict: str
    reasoning: str
    positive_evidence: Tuple[str, ...]
    negative_evidence: Tuple[str, ...]
    evidence_refs: Tuple[str, ...]
    blocking_negative_evidence: bool
    missing_fact_request: Optional[Dict[str, str]]
    stop_reason: str

    def __post_init__(self) -> None:
        if not _valid_required_string(self.candidate_uid):
            raise ValueError("candidate_uid must be a non-empty string")
        if not _valid_required_string(self.validation_cluster_uid):
            raise ValueError("validation_cluster_uid must be a non-empty string")
        if self.validation_pass not in VALIDATOR_PASSES:
            raise ValueError("unsupported Validator v3 pass")
        if self.verdict not in VALIDATOR_VERDICTS:
            raise ValueError("unsupported Validator v3 verdict")
        if not _valid_required_string(self.reasoning, max_length=4000):
            raise ValueError("reasoning must be a 1..4000 character string")
        if not _valid_string_tuple(self.positive_evidence, limit=12, max_length=1000):
            raise ValueError("positive_evidence violates the Validator v3 schema")
        if not _valid_string_tuple(self.negative_evidence, limit=12, max_length=1000):
            raise ValueError("negative_evidence violates the Validator v3 schema")
        if not _valid_string_tuple(self.evidence_refs, limit=32, max_length=512):
            raise ValueError("evidence_refs violates the Validator v3 schema")
        if not isinstance(self.blocking_negative_evidence, bool):
            raise ValueError("blocking_negative_evidence must be boolean")
        if self.stop_reason not in VALIDATOR_STOP_REASONS:
            raise ValueError("unsupported Validator v3 stop_reason")
        if self.missing_fact_request is not None:
            if not _valid_missing_fact_request(self.missing_fact_request):
                raise ValueError("missing_fact_request violates the Validator v3 schema")
            if self.verdict != "uncertain" or self.stop_reason != "missing_fact":
                raise ValueError(
                    "missing_fact_request requires uncertain verdict and missing_fact stop_reason"
                )
        elif self.stop_reason == "missing_fact":
            raise ValueError("missing_fact stop_reason requires missing_fact_request")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": VALIDATOR_RESULT_VERSION,
            "candidate_uid": self.candidate_uid,
            "validation_cluster_uid": self.validation_cluster_uid,
            "pass": self.validation_pass,
            "verdict": self.verdict,
            "reasoning": self.reasoning,
            "positive_evidence": list(self.positive_evidence),
            "negative_evidence": list(self.negative_evidence),
            "evidence_refs": list(self.evidence_refs),
            "blocking_negative_evidence": self.blocking_negative_evidence,
            "missing_fact_request": (
                dict(self.missing_fact_request) if self.missing_fact_request is not None else None
            ),
            "stop_reason": self.stop_reason,
        }


@dataclass(frozen=True)
class DynamicReproductionRequest:
    """Reserved V4 interface; no scheduler consumes it in this release."""

    request_id: str
    candidate_uid: str
    validation_cluster_uid: str
    reproduction_kind: str
    target: str
    evidence_refs: Tuple[str, ...] = ()
    timeout_seconds: int = 0
    memory_limit_mb: int = 0

    def __post_init__(self) -> None:
        if not self.request_id or not self.candidate_uid or not self.validation_cluster_uid:
            raise ValueError("dynamic reproduction request identities must be non-empty")
        if self.reproduction_kind not in {"asan", "ubsan", "tsan", "poc", "test"}:
            raise ValueError("unsupported dynamic reproduction kind")
        if self.timeout_seconds < 0 or self.memory_limit_mb < 0:
            raise ValueError("dynamic reproduction limits must be non-negative")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": DYNAMIC_REPRODUCTION_REQUEST_VERSION,
            "request_id": self.request_id,
            "candidate_uid": self.candidate_uid,
            "validation_cluster_uid": self.validation_cluster_uid,
            "decision_level": "V4",
            "reproduction_kind": self.reproduction_kind,
            "target": self.target,
            "evidence_refs": list(self.evidence_refs),
            "timeout_seconds": self.timeout_seconds,
            "memory_limit_mb": self.memory_limit_mb,
            "dispatch_status": "reserved_not_implemented",
        }


@dataclass(frozen=True)
class DynamicReproductionResult:
    """Reserved V4 result shape kept separate from ValidatorResult v3."""

    request_id: str
    outcome: str
    reasoning: str
    evidence_refs: Tuple[str, ...] = ()
    artifact_refs: Tuple[str, ...] = ()
    duration_ms: int = 0

    def __post_init__(self) -> None:
        if not self.request_id or not self.reasoning:
            raise ValueError("dynamic reproduction result identity/reasoning must be non-empty")
        if self.outcome not in {"reproduced", "not_reproduced", "inconclusive", "failed"}:
            raise ValueError("unsupported dynamic reproduction outcome")
        if self.duration_ms < 0:
            raise ValueError("dynamic reproduction duration must be non-negative")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": DYNAMIC_REPRODUCTION_RESULT_VERSION,
            "request_id": self.request_id,
            "decision_level": "V4",
            "outcome": self.outcome,
            "reasoning": self.reasoning,
            "evidence_refs": list(self.evidence_refs),
            "artifact_refs": list(self.artifact_refs),
            "duration_ms": self.duration_ms,
        }


def parse_validator_result_v3(
    value: Any,
    *,
    candidate_uid: str = "",
    validation_cluster_uid: str = "",
    expected_pass: str = "",
    allowed_evidence_refs: Optional[Iterable[str]] = None,
) -> Optional[ValidatorResultV3]:
    """Validate a model payload without accepting coercive legacy aliases."""

    if not isinstance(value, Mapping):
        return None
    if set(value) != _REQUIRED_FIELDS:
        return None
    if value.get("schema_version") != VALIDATOR_RESULT_VERSION:
        return None

    actual_candidate = _strict_string(value.get("candidate_uid"), required=True)
    actual_cluster = _strict_string(value.get("validation_cluster_uid"), required=True)
    validation_pass = _strict_string(value.get("pass"), required=True)
    verdict = _strict_string(value.get("verdict"), required=True)
    reasoning = _strict_string(value.get("reasoning"), required=True, max_length=4000)
    stop_reason = _strict_string(value.get("stop_reason"), required=True)
    if (
        actual_candidate is None
        or actual_cluster is None
        or validation_pass is None
        or verdict is None
        or reasoning is None
        or stop_reason is None
    ):
        return None
    if candidate_uid and actual_candidate != candidate_uid:
        return None
    if validation_cluster_uid and actual_cluster != validation_cluster_uid:
        return None
    if validation_pass not in VALIDATOR_PASSES or (
        expected_pass and validation_pass != expected_pass
    ):
        return None
    if verdict not in VALIDATOR_VERDICTS or stop_reason not in VALIDATOR_STOP_REASONS:
        return None

    positive = _string_tuple(value.get("positive_evidence"), limit=12, max_length=1000)
    negative = _string_tuple(value.get("negative_evidence"), limit=12, max_length=1000)
    refs = _string_tuple(value.get("evidence_refs"), limit=32, max_length=512)
    if positive is None or negative is None or refs is None:
        return None
    if allowed_evidence_refs is not None:
        allowed = {str(item) for item in allowed_evidence_refs if str(item)}
        if any(ref not in allowed for ref in refs):
            return None
    blocking = value.get("blocking_negative_evidence")
    if not isinstance(blocking, bool):
        return None

    request = value.get("missing_fact_request")
    normalized_request: Optional[Dict[str, str]] = None
    if request is not None:
        if not isinstance(request, Mapping):
            return None
        if not {"fact_kind", "reason"}.issubset(request):
            return None
        if set(request) - {"fact_kind", "subject_uid", "function_uid", "reason"}:
            return None
        fact_kind = _strict_string(request.get("fact_kind"), required=True)
        reason = _strict_string(request.get("reason"), required=True, max_length=1000)
        subject_uid = _strict_string(request.get("subject_uid", ""), max_length=512)
        function_uid = _strict_string(request.get("function_uid", ""), max_length=512)
        if fact_kind is None or reason is None or subject_uid is None or function_uid is None:
            return None
        if fact_kind not in VALIDATOR_MISSING_FACT_KINDS:
            return None
        normalized_request = {
            "fact_kind": fact_kind,
            "subject_uid": subject_uid,
            "function_uid": function_uid,
            "reason": reason,
        }
    if verdict == "uncertain" and normalized_request is not None:
        if stop_reason != "missing_fact":
            return None
    elif normalized_request is not None:
        return None
    if stop_reason == "missing_fact" and normalized_request is None:
        return None

    try:
        return ValidatorResultV3(
            candidate_uid=actual_candidate,
            validation_cluster_uid=actual_cluster,
            validation_pass=validation_pass,
            verdict=verdict,
            reasoning=reasoning,
            positive_evidence=positive,
            negative_evidence=negative,
            evidence_refs=refs,
            blocking_negative_evidence=blocking,
            missing_fact_request=normalized_request,
            stop_reason=stop_reason,
        )
    except ValueError:
        return None


def validator_result_v3_failure_class(
    value: Any,
    *,
    candidate_uid: str = "",
    validation_cluster_uid: str = "",
    expected_pass: str = "",
    allowed_evidence_refs: Optional[Iterable[str]] = None,
) -> str:
    """Return one fixed, answer-free contract failure class.

    The classifier deliberately reports neither values nor exception text.  It
    is suitable for sealed protocol metadata and lets an operator distinguish
    provider-schema drift from local identity or evidence-binding failures.
    """

    if not isinstance(value, Mapping):
        return "payload_not_object"
    if set(value) != _REQUIRED_FIELDS:
        missing = _REQUIRED_FIELDS - set(value)
        additional = set(value) - _REQUIRED_FIELDS
        if len(missing) == 1:
            missing_class = _MISSING_FIELD_FAILURE_CLASSES[next(iter(missing))]
            return missing_class + ("_with_additional" if additional else "")
        if missing and additional:
            return "multiple_required_fields_missing_with_additional"
        if missing:
            return "multiple_required_fields_missing"
        return "additional_field_present"
    if value.get("schema_version") != VALIDATOR_RESULT_VERSION:
        return "schema_version_mismatch"

    actual_candidate = _strict_string(value.get("candidate_uid"), required=True)
    actual_cluster = _strict_string(value.get("validation_cluster_uid"), required=True)
    validation_pass = _strict_string(value.get("pass"), required=True)
    verdict = _strict_string(value.get("verdict"), required=True)
    reasoning = _strict_string(value.get("reasoning"), required=True, max_length=4000)
    stop_reason = _strict_string(value.get("stop_reason"), required=True)
    if actual_candidate is None or actual_cluster is None:
        return "identity_shape_invalid"
    if validation_pass is None:
        return "pass_shape_invalid"
    if verdict is None or stop_reason is None:
        return "decision_enum_shape_invalid"
    if reasoning is None:
        return "reasoning_shape_invalid"
    if candidate_uid and actual_candidate != candidate_uid:
        return "candidate_binding_mismatch"
    if validation_cluster_uid and actual_cluster != validation_cluster_uid:
        return "cluster_binding_mismatch"
    if validation_pass not in VALIDATOR_PASSES or (
        expected_pass and validation_pass != expected_pass
    ):
        return "pass_binding_mismatch"
    if verdict not in VALIDATOR_VERDICTS or stop_reason not in VALIDATOR_STOP_REASONS:
        return "decision_enum_invalid"

    positive = _string_tuple(value.get("positive_evidence"), limit=12, max_length=1000)
    negative = _string_tuple(value.get("negative_evidence"), limit=12, max_length=1000)
    refs = _string_tuple(value.get("evidence_refs"), limit=32, max_length=512)
    if positive is None or negative is None:
        return "evidence_list_shape_invalid"
    if refs is None:
        return "evidence_ref_shape_invalid"
    if allowed_evidence_refs is not None:
        allowed = {str(item) for item in allowed_evidence_refs if str(item)}
        if any(ref not in allowed for ref in refs):
            return "evidence_ref_binding_mismatch"
    if not isinstance(value.get("blocking_negative_evidence"), bool):
        return "blocking_flag_shape_invalid"

    request = value.get("missing_fact_request")
    if request is not None:
        if not isinstance(request, Mapping):
            return "missing_fact_shape_invalid"
        if not {"fact_kind", "reason"}.issubset(request) or set(request) - {
            "fact_kind",
            "subject_uid",
            "function_uid",
            "reason",
        }:
            return "missing_fact_field_set_invalid"
        fact_kind = _strict_string(request.get("fact_kind"), required=True)
        reason = _strict_string(request.get("reason"), required=True, max_length=1000)
        subject_uid = _strict_string(request.get("subject_uid", ""), max_length=512)
        function_uid = _strict_string(request.get("function_uid", ""), max_length=512)
        if fact_kind is None or reason is None or subject_uid is None or function_uid is None:
            return "missing_fact_value_shape_invalid"
        if fact_kind not in VALIDATOR_MISSING_FACT_KINDS:
            return "missing_fact_kind_invalid"
        if verdict != "uncertain" or stop_reason != "missing_fact":
            return "missing_fact_coherence_invalid"
    elif stop_reason == "missing_fact":
        return "missing_fact_coherence_invalid"

    if (
        parse_validator_result_v3(
            value,
            candidate_uid=candidate_uid,
            validation_cluster_uid=validation_cluster_uid,
            expected_pass=expected_pass,
            allowed_evidence_refs=allowed_evidence_refs,
        )
        is None
    ):
        return "result_construction_invalid"
    return "none"


def _strict_string(
    value: Any,
    *,
    required: bool = False,
    max_length: Optional[int] = None,
) -> Optional[str]:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if required and not normalized:
        return None
    if max_length is not None and len(value) > max_length:
        return None
    return normalized


def _valid_required_string(value: Any, *, max_length: Optional[int] = None) -> bool:
    return _strict_string(value, required=True, max_length=max_length) is not None


def _valid_string_tuple(value: Any, *, limit: int, max_length: int) -> bool:
    if not isinstance(value, tuple) or len(value) > limit:
        return False
    return all(
        isinstance(item, str) and bool(item.strip()) and len(item) <= max_length for item in value
    )


def _valid_missing_fact_request(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    if not {"fact_kind", "reason"}.issubset(value):
        return False
    if set(value) - {"fact_kind", "subject_uid", "function_uid", "reason"}:
        return False
    fact_kind = _strict_string(value.get("fact_kind"), required=True)
    reason = _strict_string(value.get("reason"), required=True, max_length=1000)
    subject_uid = _strict_string(value.get("subject_uid", ""), max_length=512)
    function_uid = _strict_string(value.get("function_uid", ""), max_length=512)
    return (
        fact_kind in VALIDATOR_MISSING_FACT_KINDS
        and reason is not None
        and subject_uid is not None
        and function_uid is not None
    )


def _string_tuple(
    value: Any,
    *,
    limit: int,
    max_length: int,
) -> Optional[Tuple[str, ...]]:
    if not isinstance(value, list) or len(value) > limit:
        return None
    result = []
    for item in value:
        if not isinstance(item, str) or not item.strip() or len(item) > max_length:
            return None
        result.append(item.strip())
    return tuple(result)
