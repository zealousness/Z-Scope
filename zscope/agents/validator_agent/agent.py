import json
import logging
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..base import JsonOutputSpec, JsonToolAgent
from ...tools.policy import ToolPolicy
from ...framework.base import AgentResponse
from ...framework.llm_client import LLMClient
from ...common.utils import extract_json_blocks

logger = logging.getLogger(__name__)


class ValidatorAgent(JsonToolAgent):
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
            "validator_fast_path_attempted": 0,
            "validator_fast_path_accepted": 0,
            "validator_repair_attempted": 0,
            "validator_repair_accepted": 0,
            "validator_final_tool_call_count": 0,
        }

        for attempt in range(1, max_retries + 1):
            messages = self._messages(input_data, prompt)
            if attempt == 1 and evidence_pack:
                fast_data = self._run_fast_path(messages, finding, token_metadata)
                if fast_data:
                    return AgentResponse(
                        success=True,
                        data=fast_data,
                        metadata=dict(token_metadata),
                    )
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
                self._merge_result_metadata(token_metadata, result)
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

                last_error, json_blocks_found = self._classify_invalid_result(
                    str(result.get("content") or ""),
                    result,
                    result.get("conversation", []),
                )
                self._log_invalid_result(
                    attempt,
                    max_retries,
                    last_error,
                    phase="evidence_gathering",
                    finding=finding,
                    result=result,
                    content=str(result.get("content") or ""),
                    json_blocks_found=json_blocks_found,
                )
                repaired = self._run_json_repair(
                    messages,
                    result,
                    error_type=last_error,
                    attempt=attempt,
                    finding=finding,
                    token_metadata=token_metadata,
                )
                if repaired:
                    return AgentResponse(
                        success=True,
                        data=repaired,
                        metadata=dict(token_metadata),
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
            metadata=dict(token_metadata, validator_last_error_type=last_error),
        )

    def _run_fast_path(
        self,
        messages: List[Dict[str, Any]],
        finding: Any,
        token_metadata: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Try one no-tool validation pass from the compact evidence pack."""
        fast_messages = list(messages)
        fast_messages.append(
            {
                "role": "user",
                "content": (
                    "Fast-path validation: use only the suspected finding and Compact Evidence Pack. "
                    "Do not ask for tools. Return exactly one validation_result JSON block. "
                    "Use `uncertain` if a decisive fact requires code not present in the pack."
                ),
            }
        )
        token_metadata["validator_fast_path_attempted"] = int(
            token_metadata.get("validator_fast_path_attempted", 0) or 0
        ) + 1
        try:
            result = self._run_tool_conversation(
                fast_messages,
                max_iterations=1,
                trace_label=f"fast_path; finding={str(finding)[:120]}",
            )
        except Exception as exc:
            logger.debug("Validator fast path failed before fallback: %s", exc)
            return None

        self._merge_result_metadata(token_metadata, result)
        parsed = self._extract_validation_payload(
            str(result.get("content") or ""),
            result,
            result.get("conversation", []),
        )
        if not parsed or not self._accept_fast_path_result(parsed):
            return None
        token_metadata["validator_fast_path_accepted"] = int(
            token_metadata.get("validator_fast_path_accepted", 0) or 0
        ) + 1
        parsed["validator_fast_path"] = True
        return parsed

    def _run_json_repair(
        self,
        messages: List[Dict[str, Any]],
        result: Dict[str, Any],
        *,
        error_type: str,
        attempt: int,
        finding: Any,
        token_metadata: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Run one final no-retrieval pass whose only job is validator JSON."""
        repair_seed = dict(result)
        for key in (
            "context_tokens",
            "cumulative_prompt_tokens",
            "cumulative_completion_tokens",
            "cumulative_total_tokens",
            "iterations",
            "tool_call_count",
            "final_tool_call_count",
        ):
            repair_seed[key] = 0
        response = self._run_json_final_repair(
            messages,
            repair_seed,
            json_output_spec=self._validation_json_output_spec(),
            extractor=lambda content, repair_result, conversation: self._extract_validation_payload(
                content,
                repair_result,
                conversation,
            ),
            trace_label=f"attempt={attempt}; finding={str(finding)[:120]}",
            parse_label="validation_result JSON",
            error_type=error_type,
            max_json_retries=1,
            post_process=lambda data: self._coerce_validation_result(data) or data,
        )
        self._merge_result_metadata(token_metadata, response.metadata or {})
        if response.success:
            return response.data
        logger.warning(
            "Validator repair failed: issue_id=%s phase=repair error_type=%s error=%s",
            self._issue_id_from_finding(finding),
            error_type,
            response.error,
        )
        return None

    @classmethod
    def _validation_json_output_spec(cls) -> JsonOutputSpec:
        return JsonOutputSpec(
            type_name="validation_result",
            schema=cls._validation_result_schema(),
            final_tool_name="emit_validation_result",
            final_tool_description="Emit the final Z-Scope validation_result object.",
            validator=lambda data: cls._coerce_validation_result(data) is not None,
            nested_keys=tuple(cls._WRAPPER_KEYS),
            metadata_prefix="validator",
        )

    @staticmethod
    def _validation_result_schema() -> Dict[str, Any]:
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
            },
            "required": ["type", "verdict", "reasoning", "blocking_negative_evidence"],
            "additionalProperties": True,
        }

    @classmethod
    def _accept_fast_path_result(cls, data: Dict[str, Any]) -> bool:
        verdict = cls._normalize_verdict_value(data.get("verdict"), data.get("is_valid"))
        # Any reasoned structured verdict closes the Validator's decision
        # obligation.  Confidence/evidence promotion belongs to the validation
        # policy layer: low-confidence ``verified`` is routed to needs-review,
        # and ``rejected`` cannot suppress a candidate without deterministic
        # proof.  Retrying either result with up to 50 retrieval turns merely
        # duplicates analysis and bypasses those centralized gates.
        return bool(
            verdict in {"verified", "rejected", "uncertain"}
            and str(data.get("reasoning") or "").strip()
        )

    @staticmethod
    def _merge_result_metadata(target: Dict[str, Any], result: Dict[str, Any]) -> None:
        for key in (
            "context_tokens",
            "cumulative_prompt_tokens",
            "cumulative_completion_tokens",
            "cumulative_total_tokens",
            "iterations",
            "tool_call_count",
            "validator_repair_attempted",
            "validator_repair_accepted",
            "validator_final_tool_call_count",
        ):
            try:
                target[key] = int(target.get(key, 0) or 0) + int(result.get(key, 0) or 0)
            except (TypeError, ValueError):
                continue
        try:
            target["validator_final_tool_call_count"] = int(
                target.get("validator_final_tool_call_count", 0) or 0
            ) + int(result.get("final_tool_call_count", 0) or 0)
        except (TypeError, ValueError):
            pass

    @staticmethod
    def _merge_chat_response_metadata(
        target: Dict[str, Any],
        response: Dict[str, Any],
        messages: List[Dict[str, Any]],
        assistant_message: Dict[str, Any],
    ) -> None:
        prompt_tokens, completion_tokens = LLMClient._response_token_usage(
            response,
            messages,
            assistant_message,
        )
        target["context_tokens"] = int(target.get("context_tokens", 0) or 0) + LLMClient.estimate_tokens(messages)
        target["cumulative_prompt_tokens"] = int(
            target.get("cumulative_prompt_tokens", 0) or 0
        ) + prompt_tokens
        target["cumulative_completion_tokens"] = int(
            target.get("cumulative_completion_tokens", 0) or 0
        ) + completion_tokens
        target["cumulative_total_tokens"] = int(
            target.get("cumulative_prompt_tokens", 0) or 0
        ) + int(target.get("cumulative_completion_tokens", 0) or 0)
        target["iterations"] = int(target.get("iterations", 0) or 0) + 1

    def _classify_invalid_result(
        self,
        content: str,
        result: Dict[str, Any],
        conversation: Iterable[Dict[str, Any]],
    ) -> Tuple[str, int]:
        json_blocks_found = self._json_candidate_count(content, result, conversation)
        if json_blocks_found:
            return "schema_mismatch", json_blocks_found
        if result.get("final_tool_call_without_json"):
            return "final_tool_call_without_json", json_blocks_found

        text = "\n".join(self._text_sources(content, result, conversation)).strip()
        if result.get("truncated") or result.get("finish_reason") == "length":
            if "{" in text or "```json" in text.lower():
                return "truncated_json", json_blocks_found
            if not text:
                return "empty_final_content", json_blocks_found
        if not text:
            return "empty_final_content", json_blocks_found
        return "prose_without_json", json_blocks_found

    def _log_invalid_result(
        self,
        attempt: int,
        max_retries: int,
        error_type: str,
        *,
        phase: str,
        finding: Any,
        result: Dict[str, Any],
        content: str,
        json_blocks_found: int,
    ) -> None:
        logger.warning(
            "Validator attempt %d/%d failed: issue_id=%s phase=%s error_type=%s "
            "finish_reason=%s truncated=%s content_len=%d tool_call_count=%s "
            "json_blocks_found=%d provider_model=%s",
            attempt,
            max_retries,
            self._issue_id_from_finding(finding),
            phase,
            error_type,
            result.get("finish_reason"),
            bool(result.get("truncated")),
            len(content or ""),
            result.get("tool_call_count", 0),
            json_blocks_found,
            result.get("provider_model") or (getattr(self.llm_client, "models", []) or ["unknown"])[0],
        )

    @staticmethod
    def _issue_id_from_finding(finding: Any) -> str:
        if isinstance(finding, dict):
            return str(finding.get("id") or finding.get("issue_id") or "unknown")
        if isinstance(finding, str):
            try:
                data = json.loads(finding)
                if isinstance(data, dict):
                    return str(data.get("id") or data.get("issue_id") or "unknown")
            except Exception:
                return "unknown"
        return "unknown"

    @staticmethod
    def _message_preview(message: Dict[str, Any], limit: int = 500) -> str:
        content = str(message.get("content") or "")
        if not content and message.get("reasoning_content"):
            content = str(message.get("reasoning_content") or "")
        if not content and message.get("tool_calls"):
            names = [
                str((tool_call.get("function") or {}).get("name") or "unknown")
                for tool_call in message.get("tool_calls") or []
            ]
            content = "tool_calls=" + ",".join(names)
        return content[:limit]

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
        for data in self._validation_result_tool_payloads(result, conversation):
            parsed = self._coerce_validation_result(data)
            if parsed:
                return parsed
        for text in self._text_sources(content, result, conversation):
            for data in extract_json_blocks(text):
                parsed = self._coerce_validation_result(data)
                if parsed:
                    return parsed
        return None

    def _extract_first_json(
        self,
        content: str,
        result: Dict[str, Any],
        conversation: Iterable[Dict[str, Any]],
    ) -> Any:
        for data in self._validation_result_tool_payloads(result, conversation):
            return data
        return super()._extract_first_json(content, result, conversation)

    def _json_candidate_count(
        self,
        content: str,
        result: Dict[str, Any],
        conversation: Iterable[Dict[str, Any]],
    ) -> int:
        count = len(list(self._validation_result_tool_payloads(result, conversation)))
        for text in self._text_sources(content, result, conversation):
            count += len(extract_json_blocks(text))
        return count

    @classmethod
    def _validation_result_tool_payloads(
        cls,
        result: Dict[str, Any],
        conversation: Iterable[Dict[str, Any]],
    ) -> Iterable[Dict[str, Any]]:
        messages = []
        if isinstance(result.get("message"), dict):
            messages.append(result["message"])
        messages.extend(list(conversation))
        for message in reversed(messages):
            tool_calls = message.get("tool_calls") if isinstance(message, dict) else None
            if not isinstance(tool_calls, list):
                continue
            for tool_call in tool_calls:
                function = tool_call.get("function") if isinstance(tool_call, dict) else None
                if not isinstance(function, dict):
                    continue
                if function.get("name") != "emit_validation_result":
                    continue
                payload = cls._coerce_tool_arguments(function.get("arguments"))
                if payload is not None:
                    yield payload

    @staticmethod
    def _coerce_tool_arguments(arguments: Any) -> Optional[Dict[str, Any]]:
        if isinstance(arguments, dict):
            return arguments
        if not isinstance(arguments, str):
            return None
        try:
            data = json.loads(arguments)
        except Exception:
            return None
        return data if isinstance(data, dict) else None

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
        "blocking_negative_evidence",
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
