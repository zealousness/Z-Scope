"""读取旧版入口的复核答案，交给现有报告使用。"""

import json
from typing import Any, Dict, Optional

from ..base import JsonOutputSpec
from ...common.validator_protocol import VALIDATOR_MISSING_FACT_KINDS, VALIDATOR_VERDICTS
from ...framework.base import validate_function_arguments


class LegacyResult:
    """规定旧版答案要填哪些项，并检查收到的内容是否合格。"""

    @classmethod
    def instructions(cls) -> str:
        """只把这份填答说明发给使用旧版格式的模型会话。"""
        return (
            "Legacy validation: return one validation_result JSON object, without wrappers or prose. "
            "The program derives is_valid from verdict. Use finding_kind verified_vulnerability, rejected, "
            "or audit_observation. Explain the source, sink, trigger and guard when applicable. "
            "The output contract is: " + json.dumps(cls.schema(), ensure_ascii=False)
        )

    @classmethod
    def output_spec(cls) -> JsonOutputSpec:
        """首次交卷和改正格式都用同一份填写要求。"""
        return JsonOutputSpec(
            type_name="validation_result",
            schema=cls.schema(),
            final_tool_name="emit_validation_result",
            final_tool_description="Emit the final Z-Scope validation_result object.",
            validator=lambda data: isinstance(data, dict),
            metadata_prefix="validator",
        )

    @staticmethod
    def schema() -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "type": {"type": "string", "enum": ["validation_result"]},
                "issue_id": {"type": "string"},
                "verdict": {"type": "string", "enum": sorted(VALIDATOR_VERDICTS)},
                "finding_kind": {"type": "string"},
                "confidence_score": {"type": "number", "minimum": 0, "maximum": 1},
                "reasoning": {"type": "string", "pattern": r"\S"},
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
    def parse(cls, data: Any) -> Optional[Dict[str, Any]]:
        if not isinstance(data, dict) or validate_function_arguments(cls.schema(), data):
            return None
        return cls.with_validity(data)

    @staticmethod
    def with_validity(data: Dict[str, Any]) -> Dict[str, Any]:
        """报告里的“是否已确认”由结论直接得出，结论为“确认”时才填“是”。"""
        return {**data, "is_valid": data["verdict"] == "verified"}
