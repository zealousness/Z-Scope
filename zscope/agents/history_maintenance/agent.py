"""Advisory review of historical findings after source changes."""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

from ..base import JsonOutputSpec, JsonToolAgent
from ...framework.base import AgentResponse
from ...framework.llm_client import LLMClient
from ...tools.policy import ToolPolicy

logger = logging.getLogger(__name__)


VERIFY_FIX_PROMPT = """Mode: Verify Fix

A historical vulnerability was previously found in this function. The code
has since changed. Determine whether the same root cause is still visible.
This is advisory maintenance evidence only: an absence judgment cannot erase
the historical finding without deterministic counterproof.

Historical Issue:
{historical_issue}

Updated Source Code:
```text
{new_code}
```

Return exactly one JSON object with this shape:
{{
  "still_exists": true,
  "new_location": "145",
  "reasoning": "The same unchecked operation remains reachable."
}}
"""


VERIFY_FIX_DECISION_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "still_exists": {"type": "boolean"},
        "new_location": {"type": ["string", "null"]},
        "reasoning": {"type": "string"},
    },
    "required": ["still_exists", "reasoning"],
    "additionalProperties": True,
}


class HistoryMaintenanceAgent(JsonToolAgent):
    """Review one historical finding against changed code."""

    def __init__(self, llm_client: LLMClient, tool_policy: Optional[ToolPolicy] = None):
        super().__init__(
            name="history_maintenance_agent",
            description="Reviews historical findings after source changes.",
            llm_client=llm_client,
            tools=[],
            tool_policy=tool_policy,
        )

    def run(self, input_data: Dict[str, Any], max_iterations: int = 2) -> AgentResponse:
        del max_iterations
        if input_data.get("mode") != "verify_fix":
            return AgentResponse(
                success=False,
                data={},
                error="HistoryMaintenanceAgent supports verify_fix only",
            )
        prompt = VERIFY_FIX_PROMPT.format(
            historical_issue=json.dumps(
                input_data.get("historical_issue", {}), ensure_ascii=False, indent=2
            ),
            new_code=str(input_data.get("new_code") or ""),
        )
        try:
            response = self._run_json_conversation(
                self._messages({}, prompt),
                extractor=lambda content, result, conversation: self._extract_structured_json_payload(
                    content,
                    result,
                    conversation,
                    self._json_output_spec(),
                ),
                trace_label="history_maintenance_verify_fix",
                parse_label="verify_fix_decision JSON",
                retry_prompt=(
                    "The previous response did not contain a valid verify_fix_decision JSON. "
                    "Re-output exactly one JSON object."
                ),
                max_iterations=1,
                max_json_retries=1,
                json_output_spec=self._json_output_spec(),
            )
            if not response.success:
                logger.error("Failed to parse history maintenance JSON: %s", response.error)
            return response
        except Exception as exc:
            logger.exception("History maintenance agent failed")
            return AgentResponse(success=False, data={}, error=str(exc))

    @staticmethod
    def _json_output_spec() -> JsonOutputSpec:
        return JsonOutputSpec(
            type_name="verify_fix_decision",
            schema=VERIFY_FIX_DECISION_SCHEMA,
            final_tool_name="emit_verify_fix_decision",
            final_tool_description="Emit the historical finding review decision.",
            validator=lambda data: isinstance(data, dict)
            and isinstance(data.get("still_exists"), bool),
            metadata_prefix="history_maintenance",
        )
