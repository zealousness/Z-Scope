"""Legacy result decoding, isolated from the strict V3 protocol.

Only known envelopes and verdict spellings are accepted. Shape recognition
normalizes historical responses; the validation pipeline still owns admission.
"""

from functools import lru_cache
import json
from typing import Any, Dict, Optional

from ..base import JsonOutputSpec
from ...common.validator_protocol import VALIDATOR_MISSING_FACT_KINDS


_VERDICT_ALIASES = {
    "verified": ("verified", "valid", "true", "confirmed", "true_positive", "tp"),
    "rejected": ("rejected", "invalid", "false", "reject", "false_positive", "fp"),
    "uncertain": ("uncertain", "needs_review", "need_review", "unknown", "inconclusive"),
}


class LegacyResult:
    """Schema and decoder for the existing non-V3 wire format."""

    @classmethod
    def instructions(cls) -> str:
        """Only legacy sessions load this contract; V3 receives its own wire schema."""
        return (
            "Legacy validation: return one validation_result JSON object, without wrappers or prose. "
            "Use is_valid only for verified; finding_kind is verified_vulnerability, rejected, "
            "or audit_observation. Explain the source, sink, trigger and guard when applicable. "
            "The output contract is: " + json.dumps(cls.schema(), ensure_ascii=False)
        )

    @classmethod
    def output_spec(cls) -> JsonOutputSpec:
        """Legacy replay contract; V3 never uses this permissive shape recognition."""
        return JsonOutputSpec(
            type_name="validation_result",
            schema=cls.schema(),
            final_tool_name="emit_validation_result",
            final_tool_description="Emit the final Z-Scope validation_result object.",
            validator=lambda data: cls.parse(data) is not None,
            nested_keys=tuple(sorted(cls.WRAPPER_KEYS)),
            metadata_prefix="validator",
        )

    @staticmethod
    def schema() -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "type": {"type": "string", "enum": ["validation_result"]},
                "issue_id": {"type": "string"},
                "verdict": {"type": "string", "enum": ["verified", "rejected", "uncertain"]},
                "finding_kind": {"type": "string"},
                "is_valid": {"type": "boolean"},
                "confidence_score": {"type": "number", "minimum": 0, "maximum": 1},
                "reasoning": {"type": "string"},
                "positive_evidence": {"type": "array", "items": {"type": "string"}},
                "negative_evidence": {"type": "array", "items": {"type": "string"}},
                "blocking_negative_evidence": {
                    "type": "boolean",
                    "description": "True only when a concrete guard, ownership, lock, reachability, or contract fact blocks confirmation; uncertainty alone is false.",
                },
                "missing_context": {"type": "array", "items": {"type": "string"}},
                "exploit_scenario": {"type": "string"},
                "source": {"type": "string"},
                "sink": {"type": "string"},
                "control_of_source": {"type": "string"},
                "guard_analysis": {"type": "string"},
                "missing_fact_request": {
                    "type": ["object", "null"],
                    "properties": {
                        "fact_kind": {
                            "type": "string",
                            "enum": sorted(VALIDATOR_MISSING_FACT_KINDS),
                        },
                        "subject_uid": {"type": "string"},
                        "function_uid": {"type": "string"},
                        "reason": {"type": "string"},
                    },
                    "required": ["fact_kind", "reason"],
                    "additionalProperties": False,
                },
            },
            "required": ["type", "verdict", "reasoning", "blocking_negative_evidence"],
            "additionalProperties": True,
        }

    @classmethod
    def accept_fast_path(cls, data: Dict[str, Any]) -> bool:
        verdict = cls.verdict(data.get("verdict"), data.get("is_valid"))
        # Confidence and proof admission belong to the policy layer: low
        # confidence stays reviewable, rejection needs deterministic proof.
        # A reasoned verdict closes this session; retrieval would duplicate
        # analysis and bypass those gates.
        return bool(
            verdict in {"verified", "rejected", "uncertain"}
            and str(data.get("reasoning") or "").strip()
        )

    @classmethod
    @lru_cache(maxsize=1)
    def _detail_keys(cls) -> frozenset[str]:
        # Shape recognition for legacy replay, not evidence or verdict authorization.
        return frozenset(cls.schema()["properties"]) - {
            "type",
            "verdict",
            "is_valid",
            "missing_fact_request",
        }

    @classmethod
    def recognizes(cls, data: Any) -> bool:
        if not isinstance(data, dict):
            return False
        has_verdict = bool(cls.verdict(data.get("verdict"), data.get("is_valid")))
        if not has_verdict:
            return False
        if data.get("type") == "validation_result" or "is_valid" in data:
            return True
        return not cls._detail_keys().isdisjoint(data)

    @classmethod
    def parse(cls, data: Any) -> Optional[Dict[str, Any]]:
        # An explicit stack keeps deep legacy envelopes off the Python call stack.
        pending = [data]
        while pending:
            current = pending.pop()
            if not isinstance(current, dict):
                continue
            if cls.recognizes(current):
                return cls._normalize(current)
            scalar_result = current.get("validation_result")
            scalar_verdict = cls.verdict(scalar_result, current.get("is_valid"))
            if isinstance(scalar_result, str) and scalar_verdict:
                candidate = dict(current)
                candidate.pop("validation_result")
                candidate["verdict"] = scalar_verdict
                return cls._normalize(candidate)
            # Reverse pushes preserve the original left-to-right depth-first order.
            for key, value in reversed(current.items()):
                if cls._wrapper_key(key) in cls.WRAPPER_KEYS:
                    pending.extend(reversed(value) if isinstance(value, list) else [value])
        return None

    @staticmethod
    def _wrapper_key(key: Any) -> str:
        return "".join(ch for ch in str(key or "").lower() if ch.isalnum())

    @staticmethod
    def _normalize(data: Dict[str, Any]) -> Dict[str, Any]:
        # Both callers have already recognized a verdict or adapted its scalar envelope.
        verdict = LegacyResult.verdict(data.get("verdict"), data.get("is_valid"))
        return {
            **data,
            "type": "validation_result",
            "verdict": verdict,
            "is_valid": verdict == "verified",
        }

    @staticmethod
    def verdict(verdict: Any, is_valid: Any = None) -> Optional[str]:
        raw_verdict = str(verdict or "").strip().lower()
        for canonical, aliases in _VERDICT_ALIASES.items():
            if raw_verdict in aliases:
                return canonical

        bool_value = LegacyResult._bool(is_valid)
        if bool_value is not None:
            return "verified" if bool_value else "rejected"
        return None

    @staticmethod
    def _bool(value: Any) -> Optional[bool]:
        if isinstance(value, bool):
            return value
        if value is None:
            return None
        if isinstance(value, (int, float)):
            return bool(value)
        text = str(value).strip().lower()
        if text in {"true", "1", "yes", "y"}:
            return True
        if text in {"false", "0", "no", "n"}:
            return False
        return None

    # Legacy-only envelope allowlist: never descend into arbitrary finding/context
    # objects. V3 uses parse_validator_result_v3 and accepts no wrappers or aliases.
    WRAPPER_KEYS = frozenset(
        {
            "answer",
            "data",
            "decision",
            "decisions",
            "output",
            "outputs",
            "payload",
            "response",
            "responses",
            "result",
            "results",
            "validation",
            "validationresult",
            "validationresults",
        }
    )
