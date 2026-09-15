from __future__ import annotations

import json
from typing import Any, Dict

from ..base import JsonOutputSpec, JsonToolAgent
from ...framework.base import AgentResponse
from ...framework.llm_client import LLMClient


REVIEW_PATTERN_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "false_positive_reason": {"type": "string", "maxLength": 1500},
        "required_checks": {"type": "array", "maxItems": 6, "items": {"type": "string", "maxLength": 400}},
        "counter_conditions": {"type": "array", "maxItems": 6, "items": {"type": "string", "maxLength": 400}},
        "trigger_features": {"type": "array", "maxItems": 8, "items": {"type": "object"}},
    },
    "required": ["false_positive_reason", "required_checks", "counter_conditions", "trigger_features"],
    "additionalProperties": False,
}


def _valid_payload(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    if not isinstance(value.get("false_positive_reason"), str) or len(value["false_positive_reason"]) > 1500:
        return False
    if not isinstance(value.get("required_checks"), list) or len(value["required_checks"]) > 6:
        return False
    if not isinstance(value.get("counter_conditions"), list) or len(value["counter_conditions"]) > 6:
        return False
    features = value.get("trigger_features")
    return isinstance(features, list) and len(features) <= 8 and all(isinstance(item, dict) for item in features)


class ReviewMemoryAgent(JsonToolAgent):
    def __init__(self, llm_client: LLMClient):
        super().__init__(name="review_memory", description="Extracts conservative false-positive review patterns.", llm_client=llm_client)

    def run(self, input_data: Dict[str, Any]) -> AgentResponse:
        projection = input_data.get("extraction_input") or {}
        prompt = (
            "Extract a conservative false-positive pattern from this program-generated projection."
            "FINAL TOOL ONLY: Call emit_review_pattern with the smallest complete payload."
            "do not repeat the projection. Do not emit prose. Do not put any final JSON outside the tool call."
            + json.dumps(projection, ensure_ascii=False, indent=2)
        )
        if not hasattr(self.llm_client, "run_conversation_with_tools"):
            # Small compatibility path for test doubles and older LLM clients;
            # it still forces the same final tool and applies the same payload
            # validator, rather than falling back to free-form JSON.
            schema = {"type": "function", "function": {"name": "emit_review_pattern", "description": "Emit the final false-positive review pattern proposal.", "parameters": REVIEW_PATTERN_SCHEMA}}
            messages = self._messages(input_data, prompt)
            last_error = "final_tool_missing"
            for _ in range(3):
                response = self.llm_client.chat_completion(messages, tools=[schema], tool_choice={"type": "function", "function": {"name": "emit_review_pattern"}}, trace_agent="review_memory", trace_label="pattern_extraction")
                message = ((response.get("choices") or [{}])[0].get("message") or {})
                calls = message.get("tool_calls") or []
                if calls:
                    try:
                        payload = json.loads(calls[0].get("function", {}).get("arguments", "{}"))
                    except (TypeError, ValueError, json.JSONDecodeError):
                        payload = None
                    if _valid_payload(payload):
                        return AgentResponse(success=True, data=payload, metadata={"final_tool_call_count": len(calls)})
                # Backward-compatible test-double response; real clients use
                # run_conversation_with_tools and never take this branch.
                if not calls:
                    try:
                        payload = json.loads(str(message.get("content") or ""))
                    except (TypeError, ValueError, json.JSONDecodeError):
                        payload = None
                    if isinstance(payload, dict):
                        return AgentResponse(success=True, data=payload, metadata={"legacy_json_compat": True})
                last_error = "invalid_final_tool_payload"
                messages.append({"role": "assistant", "content": ""})
                messages.append({"role": "user", "content": "上一次 emit_review_pattern 未通过 schema 校验。请重新调用该工具，只提交最小合法 payload。"})
            return AgentResponse(success=False, data={}, error=last_error)
        return self._run_json_conversation(
            self._messages(input_data, prompt),
            extractor=lambda content, result, conversation: self._extract_valid_payload(
                content, result, conversation, validator=_valid_payload
            ),
            trace_label="pattern_extraction",
            parse_label="review pattern proposal",
            retry_prompt=(
                "Finalize review pattern proposal from the evidence already collected in this conversation. "
                "Call `emit_review_pattern` exactly once with one complete minimal payload."
                "Do not emit prose, Markdown, or JSON in assistant content."
                "The tool arguments are the only accepted final output."
            ),
            max_iterations=1,
            max_json_retries=2,
            json_output_spec=JsonOutputSpec(
                type_name="review_pattern",
                schema=REVIEW_PATTERN_SCHEMA,
                final_tool_name="emit_review_pattern",
                final_tool_description="Emit the final false-positive review pattern proposal.",
                validator=_valid_payload,
                metadata_prefix="review_memory",
            ),
            require_structured_finalization=False,
            single_pass_final_tool=True,
        )
