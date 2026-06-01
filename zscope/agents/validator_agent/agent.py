from typing import Any, Dict, Iterable, List, Optional
import logging

from ..base import ToolCallingAgent
from ...tools.policy import ToolPolicy
from ...framework.base import AgentResponse
from ...framework.llm_client import LLMClient
from ...common.utils import extract_json_blocks

logger = logging.getLogger(__name__)


class ValidatorAgent(ToolCallingAgent):
    """Agent for verifying and triaging findings."""

    def __init__(
        self,
        llm_client: LLMClient,
        tools: List[Any],
        tool_policy: Optional[ToolPolicy] = None,
    ):
        super().__init__(
            name="validator_agent",
            description="Verifies suspect findings and attempts to find exploit paths.",
            llm_client=llm_client,
            tools=tools,
            tool_policy=tool_policy,
        )

    def run(self, input_data: Dict[str, Any], max_retries: int = 2) -> AgentResponse:
        finding = input_data.get("finding")
        context_code = input_data.get("context_code")
        evidence_pack = input_data.get("evidence_pack")
        evidence_text = ""
        if evidence_pack:
            import json
            evidence_text = (
                "\n\nCompact Evidence Pack:\n"
                + json.dumps(evidence_pack, ensure_ascii=False, indent=2)
            )
        prompt = (
            f"Suspected Finding:\n{finding}"
            f"{evidence_text}"
            f"\n\nRelevant Code Context:\n{context_code}"
        )
        last_error = ""
        token_metadata = {
            "context_tokens": 0,
            "cumulative_prompt_tokens": 0,
            "cumulative_completion_tokens": 0,
            "cumulative_total_tokens": 0,
            "iterations": 0,
            "tool_call_count": 0,
        }

        for attempt in range(1, max_retries + 1):
            messages = self._messages(input_data, prompt)
            if attempt > 1:
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            "The previous response did not contain a valid validation_result JSON "
                            f"(error: {last_error}). Re-output only one JSON block that follows "
                            "the system prompt format. The JSON object itself must be the "
                            "validation_result; do not wrap it in result/data/validation_result."
                        ),
                    }
                )
                logger.info(
                    "Validator retry %d/%d for finding: %s",
                    attempt,
                    max_retries,
                    str(finding)[:80],
                )

            try:
                result = self._run_tool_conversation(
                    messages,
                    trace_label=f"attempt={attempt}; finding={str(finding)[:120]}",
                )
                for key in token_metadata:
                    token_metadata[key] += int(result.get(key, 0) or 0)
                parsed = self._extract_validation_payload(
                    str(result.get("content") or ""),
                    result,
                    result.get("conversation", []),
                )
                if parsed:
                    return AgentResponse(
                        success=True,
                        data=parsed,
                        metadata=dict(token_metadata),
                    )

                candidates = self._extract_first_json(
                    str(result.get("content") or ""),
                    result,
                    result.get("conversation", []),
                )
                last_error = (
                    "JSON parsed but no validation_result found"
                    if candidates
                    else "No JSON block found"
                )
                logger.warning(
                    "Validator attempt %d/%d failed: %s",
                    attempt,
                    max_retries,
                    last_error,
                )
            except Exception as exc:
                last_error = str(exc)
                logger.warning(
                    "Validator attempt %d/%d exception: %s",
                    attempt,
                    max_retries,
                    last_error,
                )

        return AgentResponse(
            success=False,
            data={},
            error=f"Failed after {max_retries} validation attempt(s): {last_error}",
        )

    @staticmethod
    def _is_validation_result(data: Any) -> bool:
        if not isinstance(data, dict):
            return False
        has_verdict = bool(
            ValidatorAgent._normalize_verdict_value(data.get("verdict"), data.get("is_valid"))
        )
        if not has_verdict:
            return False
        if data.get("type") == "validation_result" or "is_valid" in data:
            return True
        return any(key in data for key in ValidatorAgent._VALIDATION_RESULT_KEYS)

    def _extract_validation_payload(
        self,
        content: str,
        result: Dict[str, Any],
        conversation: Iterable[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Extract and normalize validator JSON, including common wrapper shapes."""
        for text in self._text_sources(content, result, conversation):
            for data in extract_json_blocks(text):
                parsed = self._coerce_validation_result(data)
                if parsed:
                    return parsed
        return None

    @classmethod
    def _coerce_validation_result(cls, data: Any) -> Optional[Dict[str, Any]]:
        if not isinstance(data, dict):
            return None

        if cls._is_validation_result(data):
            return cls._normalize_validation_result(data)

        scalar_result = data.get("validation_result")
        scalar_verdict = cls._normalize_verdict_value(scalar_result, data.get("is_valid"))
        if isinstance(scalar_result, str) and scalar_verdict:
            candidate = dict(data)
            candidate.pop("validation_result", None)
            candidate["verdict"] = scalar_verdict
            return cls._normalize_validation_result(candidate)

        for key, value in data.items():
            if cls._normalized_wrapper_key(key) not in cls._WRAPPER_KEYS:
                continue
            parsed = cls._coerce_validation_result(value)
            if parsed:
                return parsed
            if isinstance(value, list):
                for item in value:
                    parsed = cls._coerce_validation_result(item)
                    if parsed:
                        return parsed
        return None

    @staticmethod
    def _normalized_wrapper_key(key: Any) -> str:
        return "".join(ch for ch in str(key or "").lower() if ch.isalnum())

    @staticmethod
    def _normalize_validation_result(data: Dict[str, Any]) -> Dict[str, Any]:
        normalized = dict(data)
        normalized["type"] = "validation_result"
        verdict = ValidatorAgent._normalize_verdict_value(
            normalized.get("verdict"),
            normalized.get("is_valid"),
        )
        if verdict:
            normalized["verdict"] = verdict
            normalized["is_valid"] = verdict == "verified"
        return normalized

    @staticmethod
    def _normalize_verdict_value(verdict: Any, is_valid: Any = None) -> Optional[str]:
        raw_verdict = str(verdict or "").strip().lower()
        aliases = {
            "valid": "verified",
            "true": "verified",
            "confirmed": "verified",
            "true_positive": "verified",
            "tp": "verified",
            "invalid": "rejected",
            "false": "rejected",
            "reject": "rejected",
            "rejected": "rejected",
            "false_positive": "rejected",
            "fp": "rejected",
            "needs_review": "uncertain",
            "need_review": "uncertain",
            "unknown": "uncertain",
            "inconclusive": "uncertain",
            "uncertain": "uncertain",
            "verified": "verified",
        }
        normalized = aliases.get(raw_verdict, raw_verdict)
        if normalized in {"verified", "rejected", "uncertain"}:
            return normalized

        bool_value = ValidatorAgent._coerce_bool(is_valid)
        if bool_value is not None:
            return "verified" if bool_value else "rejected"
        return None

    @staticmethod
    def _coerce_bool(value: Any) -> Optional[bool]:
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

    _WRAPPER_KEYS = {
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

    _VALIDATION_RESULT_KEYS = {
        "confidence_score",
        "control_of_source",
        "exploit_scenario",
        "finding_kind",
        "guard_analysis",
        "issue_id",
        "missing_context",
        "negative_evidence",
        "positive_evidence",
        "reasoning",
        "sink",
        "source",
    }
