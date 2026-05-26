from typing import Any, Dict, List, Optional
import logging

from ..base import ToolCallingAgent
from ...tools.policy import ToolPolicy
from ...framework.base import AgentResponse
from ...framework.llm_client import LLMClient

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
                            "the system prompt format."
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
                parsed = self._extract_valid_payload(
                    str(result.get("content") or ""),
                    result,
                    result.get("conversation", []),
                    validator=self._is_validation_result,
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
        return isinstance(data, dict) and (
            data.get("type") == "validation_result" or "is_valid" in data or "verdict" in data
        )
