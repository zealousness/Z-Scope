"""Strict Validator V3 contracts and reserved V4 transport shapes.

Models own decisions; the runtime binds identity and stop metadata.
Reporting policy remains in the validation pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
import json
import math
import re
from types import MappingProxyType
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

VALIDATOR_RESULT_VERSION = "zscope.validator-result.v3"
VALIDATOR_PROTOCOL_VERSION = "zscope.validator-protocol.v3"
# Runtime decision policy, separate from the model's response schema.
VALIDATION_POLICY_VERSION = "zscope.validation-policy.v3"
# v2b_adjudication independently audits a rejection without deterministic proof.
VALIDATOR_PASSES = frozenset(
    {"initial", "evidence_recheck", "investigation_synthesis", "v2b_adjudication"}
)
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
VALIDATOR_UNCERTAIN_TERMINAL_REASONS = frozenset(
    {
        "unsupported_fact",
        "fact_timeout",
        "no_evidence_gain",
        "duplicate_fact_request",
        "output_truncated",
        "malformed_output",
        "investigation_exhausted",
    }
)
# One decision table drives schema generation and runtime validation. A completed
# investigation keeps its existing spelling; exhaustion never completes a verdict.
_DECISION_STATES = (
    ({"verified", "rejected"}, False, {"decision_complete", "investigation_complete"}),
    ({"uncertain"}, True, {"missing_fact"}),
    ({"uncertain"}, False, VALIDATOR_UNCERTAIN_TERMINAL_REASONS),
)
VALIDATOR_STOP_REASONS = frozenset().union(*(reasons for _, _, reasons in _DECISION_STATES))
DYNAMIC_REPRODUCTION_REQUEST_VERSION = "zscope.dynamic-reproduction-request.v1"
DYNAMIC_REPRODUCTION_RESULT_VERSION = "zscope.dynamic-reproduction-result.v1"
_EVIDENCE_LIMITS = {
    "positive_evidence": (12, 1000),
    "negative_evidence": (12, 1000),
    "evidence_refs": (32, 512),
}


def _unique_object(pairs: list[tuple[str, Any]]) -> Dict[str, Any]:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("Duplicate JSON keys")
    return result


def _finite_number(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(f"Non-finite JSON number: {value}")
    return number


def decode_validator_json(value: str) -> Any:
    """Decode public JSON and provider fragments with the same unambiguous syntax."""
    return json.loads(
        value,
        object_pairs_hook=_unique_object,
        parse_float=_finite_number,
        parse_constant=_finite_number,
    )


def _string_schema(*, max_length: Optional[int] = None) -> Dict[str, Any]:
    schema: Dict[str, Any] = {"type": "string", "minLength": 1, "pattern": r"\S"}
    if max_length is not None:
        schema["maxLength"] = max_length
    return schema


def validator_result_schema_v3() -> Dict[str, Any]:
    """Return the complete conditional ValidatorResult v3 contract."""

    properties = {
        "schema_version": {
            "type": "string",
            "enum": [VALIDATOR_RESULT_VERSION],
        },
        "candidate_uid": _string_schema(),
        "validation_cluster_uid": _string_schema(),
        "pass": {"type": "string", "enum": sorted(VALIDATOR_PASSES)},
        "verdict": {"type": "string", "enum": sorted(VALIDATOR_VERDICTS)},
        "reasoning": {
            **_string_schema(max_length=4000),
            "description": (
                "Explain how the cited facts support the verdict, without restating the "
                "evidence lists. Use Simplified Chinese; preserve paths, symbols and ref UIDs."
            ),
        },
        **{
            name: {
                "type": "array",
                "items": _string_schema(max_length=max_length),
                "maxItems": limit,
            }
            for name, (limit, max_length) in _EVIDENCE_LIMITS.items()
        },
        "blocking_negative_evidence": {
            "type": "boolean",
            "description": (
                "True only for a concrete fact blocking this candidate's defect confirmation. "
                "Use false for verified; refuting a prior rejection is not blocking evidence."
            ),
        },
        "missing_fact_request": {
            "type": ["object", "null"],
            "properties": {
                "fact_kind": {
                    "type": "string",
                    "enum": sorted(VALIDATOR_MISSING_FACT_KINDS),
                },
                "subject_uid": {"type": "string", "maxLength": 512},
                "function_uid": {"type": "string", "maxLength": 512},
                "reason": {
                    **_string_schema(max_length=1000),
                    "description": "The unresolved premise and why this fact would decide it, in Simplified Chinese.",
                },
            },
            "required": ["fact_kind", "reason"],
            "additionalProperties": False,
        },
        "stop_reason": {
            "type": "string",
            "enum": sorted(VALIDATOR_STOP_REASONS),
        },
    }
    properties["positive_evidence"][
        "description"
    ] = "Concrete supporting facts in Simplified Chinese."
    properties["negative_evidence"][
        "description"
    ] = "Concrete counter-facts in Simplified Chinese; missing context is not counter-evidence."
    return {
        "type": "object",
        "properties": properties,
        "required": list(properties),
        # Field-level schemas alone cannot exclude a completed verdict that
        # simultaneously requests missing evidence.
        "oneOf": [
            {
                "type": "object",
                "properties": {
                    "verdict": {"enum": sorted(verdicts)},
                    "missing_fact_request": {"type": "object"} if needs_fact else {"const": None},
                    "stop_reason": {"enum": sorted(reasons)},
                },
                "required": ["verdict", "missing_fact_request", "stop_reason"],
            }
            for verdicts, needs_fact, reasons in _DECISION_STATES
        ],
        "additionalProperties": False,
    }


def validator_result_provider_schema_v3(
    *,
    allowed_missing_fact_kinds: Optional[Iterable[str]] = None,
    allowed_evidence_refs: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """Flatten the historical result for gateways that truncate required via oneOf.

    Keep conditional validation local; generation gets the complete field set.
    """

    schema = validator_result_schema_v3()
    schema.pop("oneOf", None)
    if allowed_evidence_refs is not None:
        refs = sorted(
            {
                value
                for value in allowed_evidence_refs
                if _strict_string(value, required=True, max_length=512) is not None
            }
        )
        evidence_refs = schema["properties"]["evidence_refs"]
        if refs:
            evidence_refs["items"] = {"type": "string", "enum": refs}
        else:
            evidence_refs["maxItems"] = 0
    request = schema["properties"]["missing_fact_request"]
    if allowed_missing_fact_kinds is not None:
        allowed = sorted(
            {
                value
                for value in allowed_missing_fact_kinds
                if isinstance(value, str) and value in VALIDATOR_MISSING_FACT_KINDS
            }
        )
        if not allowed:
            schema["properties"]["missing_fact_request"] = {
                "type": "null",
                "description": (
                    "No executable evidence provider remains for this candidate; "
                    "this field must be null for every verdict."
                ),
            }
            schema["properties"]["stop_reason"]["enum"].remove("missing_fact")
            return schema
        request["properties"]["fact_kind"]["enum"] = allowed
    # An explicit null branch avoids object-shaped placeholder requests at
    # compatible providers. The parser still enforces verdict/stop pairing.
    schema["properties"]["missing_fact_request"] = {
        "description": (
            "Use JSON null for verified/rejected or when no fact is requested. "
            "An object is only for verdict=uncertain with stop_reason=missing_fact "
            "and a real unresolved fact; never fill a placeholder request."
        ),
        "anyOf": [{"type": "null"}, {**request, "type": "object"}],
    }
    return schema


_REQUIRED_FIELDS = frozenset(validator_result_schema_v3()["required"])
_DECISION_FIELDS = _REQUIRED_FIELDS - {
    "schema_version",
    "candidate_uid",
    "validation_cluster_uid",
    "pass",
    "stop_reason",
}


def validator_decision_schema_v3(
    *,
    allowed_missing_fact_kinds: Optional[Iterable[str]] = None,
    allowed_evidence_refs: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """Expose model decisions while keeping invocation metadata program-owned."""
    schema = validator_result_provider_schema_v3(
        allowed_missing_fact_kinds=allowed_missing_fact_kinds,
        allowed_evidence_refs=allowed_evidence_refs,
    )
    properties = schema["properties"]
    schema["properties"] = {
        key: value for key, value in properties.items() if key in _DECISION_FIELDS
    }
    schema["required"] = list(schema["properties"])
    request = properties["missing_fact_request"]
    if "anyOf" in request:
        request["description"] = (
            "Request one decisive fact only for verdict=uncertain; otherwise use JSON null."
        )
        for branch in request["anyOf"]:
            if branch.get("type") == "object":
                del branch["properties"]["subject_uid"], branch["properties"]["function_uid"]
    return schema


_DSML_PARAMETER = re.compile(
    r'\s*<｜DSML｜\s*parameter\s+name="(?P<name>[^"]+)"\s+'
    r'string="(?P<string>true|false)">(?P<value>.*?)</parameter>',
    re.DOTALL,
)
_DSML_TERMINAL = re.compile(r"<｜DSML｜\s*invoke>\s*$", re.DOTALL)


def normalize_validator_provider_payload_v3(value: Any) -> Optional[Dict[str, Any]]:
    """Recover the known one-key DSML terminal envelope, never general markup.

    A gateway defect places all terminal arguments under schema_version.
    Require its exact version, terminal marker and complete V3 field set.
    """

    if not isinstance(value, Mapping) or set(value) != {"schema_version"}:
        return None
    encoded = value.get("schema_version")
    if not isinstance(encoded, str):
        return None
    first_marker = encoded.find("<｜DSML｜")
    if first_marker < 0:
        return None
    prefix = encoded[:first_marker].strip()
    if prefix != f"{VALIDATOR_RESULT_VERSION}</parameter>":
        return None
    payload: Dict[str, Any] = {"schema_version": VALIDATOR_RESULT_VERSION}
    body = encoded[first_marker:]
    cursor = 0
    # Match only the next parameter; searching later tags rescans malformed tails.
    while match := _DSML_PARAMETER.match(body, cursor):
        cursor = match.end()
        name = str(match.group("name") or "")
        if name in payload or name not in _REQUIRED_FIELDS:
            return None
        raw = match.group("value")
        if match.group("string") == "true":
            payload[name] = raw
        else:
            try:
                payload[name] = decode_validator_json(raw)
            except (ValueError, RecursionError):
                return None
    tail = body[cursor:]
    if _DSML_TERMINAL.fullmatch(tail.strip()) is None:
        return None
    if set(payload) != _REQUIRED_FIELDS:
        return None
    return payload


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
    missing_fact_request: Optional[Mapping[str, str]]
    stop_reason: str

    def __post_init__(self) -> None:
        for name in (
            "candidate_uid",
            "validation_cluster_uid",
            "validation_pass",
            "verdict",
            "reasoning",
            "stop_reason",
        ):
            value = _strict_string(
                getattr(self, name), required=True, max_length=4000 if name == "reasoning" else None
            )
            if value is None:
                raise ValueError(f"{name} violates the Validator v3 string contract")
        if self.validation_pass not in VALIDATOR_PASSES:
            raise ValueError("unsupported Validator v3 pass")
        if self.verdict not in VALIDATOR_VERDICTS:
            raise ValueError("unsupported Validator v3 verdict")
        for name, (limit, max_length) in _EVIDENCE_LIMITS.items():
            values = getattr(self, name)
            if not _valid_string_tuple(values, limit=limit, max_length=max_length):
                raise ValueError(f"{name} violates the Validator v3 schema")
        if not isinstance(self.blocking_negative_evidence, bool):
            raise ValueError("blocking_negative_evidence must be boolean")
        if self.missing_fact_request is not None:
            request = _normalize_missing_fact_request(self.missing_fact_request)
            if request is None:
                raise ValueError("missing_fact_request violates the Validator v3 schema")
            object.__setattr__(self, "missing_fact_request", MappingProxyType(request))
        if not any(
            self.verdict in verdicts
            and (self.missing_fact_request is not None) == needs_fact
            and self.stop_reason in reasons
            for verdicts, needs_fact, reasons in _DECISION_STATES
        ):
            raise ValueError("inconsistent verdict, missing_fact_request and stop_reason")

    def to_dict(self) -> Dict[str, Any]:
        return {"schema_version": VALIDATOR_RESULT_VERSION, **_wire_fields(self, ValidatorResultV3)}


@dataclass(frozen=True)
class DynamicReproductionRequest:
    """V4 transport shape; execution is owned by dynamic reproduction policy."""

    request_id: str
    candidate_uid: str
    validation_cluster_uid: str
    reproduction_kind: str
    target: str
    evidence_refs: Tuple[str, ...] = ()
    timeout_seconds: int = 0
    memory_limit_mb: int = 0

    def __post_init__(self) -> None:
        _validate_dynamic_fields(
            self,
            ("request_id", "candidate_uid", "validation_cluster_uid", "target"),
            ("timeout_seconds", "memory_limit_mb"),
            ("evidence_refs",),
        )
        if _strict_string(self.reproduction_kind) not in {"asan", "ubsan", "tsan", "poc", "test"}:
            raise ValueError("unsupported dynamic reproduction kind")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": DYNAMIC_REPRODUCTION_REQUEST_VERSION,
            **_wire_fields(self, DynamicReproductionRequest),
            "decision_level": "V4",
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
        _validate_dynamic_fields(
            self, ("request_id", "reasoning"), ("duration_ms",), ("evidence_refs", "artifact_refs")
        )
        if _strict_string(self.outcome) not in {
            "reproduced",
            "not_reproduced",
            "inconclusive",
            "failed",
        }:
            raise ValueError("unsupported dynamic reproduction outcome")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": DYNAMIC_REPRODUCTION_RESULT_VERSION,
            **_wire_fields(self, DynamicReproductionResult),
            "decision_level": "V4",
        }


def _wire_fields(value: Any, contract: type) -> Dict[str, Any]:
    """Project only declared contract fields, without deep-copying evidence."""
    result = {}
    for field in fields(contract):
        item = getattr(value, field.name)
        result["pass" if field.name == "validation_pass" else field.name] = (
            list(item)
            if isinstance(item, tuple)
            else dict(item) if isinstance(item, Mapping) else item
        )
    return result


def _validate_dynamic_fields(
    value: Any, strings: Tuple[str, ...], limits: Tuple[str, ...], references: Tuple[str, ...]
) -> None:
    for name in strings:
        if _strict_string(getattr(value, name), required=True) is None:
            raise ValueError(f"{name} must be a non-empty string")
    for name in limits:
        number = getattr(value, name)
        if type(number) is not int or number < 0:
            raise ValueError(f"{name} must be a non-negative integer")
    for name in references:
        refs = getattr(value, name)
        if not isinstance(refs, tuple) or any(
            _strict_string(ref, required=True) is None for ref in refs
        ):
            raise ValueError(f"{name} must be a tuple of non-empty strings")


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

    # Validate the wire container types here; the result object owns all field
    # limits and cross-field rules, including runtime-generated failure outcomes.
    fields = {key: value[key] for key in _REQUIRED_FIELDS - {"schema_version", "pass"}}
    fields["validation_pass"] = value["pass"]
    for name in _EVIDENCE_LIMITS:
        if not isinstance(fields[name], list):
            return None
        fields[name] = tuple(fields[name])
    try:
        result = ValidatorResultV3(**fields)
    except ValueError:
        return None
    for expected, actual in (
        (candidate_uid, result.candidate_uid),
        (validation_cluster_uid, result.validation_cluster_uid),
        (expected_pass, result.validation_pass),
    ):
        if expected and expected != actual:
            return None
    if allowed_evidence_refs is not None:
        allowed = {item for item in allowed_evidence_refs if isinstance(item, str)}
        if not set(result.evidence_refs).issubset(allowed):
            return None
    return result


def bind_validator_decision(
    value: Any,
    *,
    candidate_uid: str,
    validation_cluster_uid: str,
    expected_pass: str,
    allowed_evidence_refs: Optional[Iterable[str]] = None,
    allowed_missing_fact_kinds: Optional[Iterable[str]] = None,
    subject_uid: str = "",
    function_uid: str = "",
) -> Optional[ValidatorResultV3]:
    """Bind a compact decision, or validate a complete historical result unchanged."""
    if not isinstance(value, Mapping) or any(
        _strict_string(item, required=True) is None
        for item in (candidate_uid, validation_cluster_uid, expected_pass)
    ):
        return None
    if set(value) == _DECISION_FIELDS:
        request = value["missing_fact_request"]
        if request is not None:
            if not isinstance(request, Mapping) or set(request) != {"fact_kind", "reason"}:
                return None
            request = {**request, "subject_uid": subject_uid, "function_uid": function_uid}
        stop_reason = (
            "decision_complete"
            if value["verdict"] in ("verified", "rejected")
            else "missing_fact" if request is not None else "no_evidence_gain"
        )
        value = {
            **value,
            "schema_version": VALIDATOR_RESULT_VERSION,
            "candidate_uid": candidate_uid,
            "validation_cluster_uid": validation_cluster_uid,
            "pass": expected_pass,
            "stop_reason": stop_reason,
            "missing_fact_request": request,
        }
    # Never overwrite historical identities: the strict parser rejects mismatches
    # and partial mixtures of compact decisions and complete result envelopes.
    result = parse_validator_result_v3(
        value,
        candidate_uid=candidate_uid,
        validation_cluster_uid=validation_cluster_uid,
        expected_pass=expected_pass,
        allowed_evidence_refs=allowed_evidence_refs,
    )
    if result is not None and result.missing_fact_request is not None:
        if (
            allowed_missing_fact_kinds is not None
            and result.missing_fact_request["fact_kind"] not in allowed_missing_fact_kinds
        ):
            return None
    return result


def _strict_string(
    value: Any,
    *,
    required: bool = False,
    max_length: Optional[int] = None,
) -> Optional[str]:
    if not isinstance(value, str):
        return None
    if required and not value.strip():
        return None
    if max_length is not None and len(value) > max_length:
        return None
    return value


def _valid_string_tuple(value: Any, *, limit: int, max_length: int) -> bool:
    if not isinstance(value, tuple) or len(value) > limit:
        return False
    return all(
        isinstance(item, str) and bool(item.strip()) and len(item) <= max_length for item in value
    )


def _normalize_missing_fact_request(value: Any) -> Optional[Dict[str, str]]:
    if not isinstance(value, Mapping) or not {"fact_kind", "reason"}.issubset(value):
        return None
    if set(value) - {"fact_kind", "subject_uid", "function_uid", "reason"}:
        return None
    result = {}
    for name in ("fact_kind", "reason", "subject_uid", "function_uid"):
        item = _strict_string(
            value.get(name, ""),
            required=name in {"fact_kind", "reason"},
            max_length=1000 if name == "reason" else 512,
        )
        if item is None or (name == "fact_kind" and item not in VALIDATOR_MISSING_FACT_KINDS):
            return None
        result[name] = item
    return result
