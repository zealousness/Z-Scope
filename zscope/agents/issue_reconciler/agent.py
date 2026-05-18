from typing import Any, Dict, Optional
import json
import logging

from ..base import ToolCallingAgent
from ...core.tool_policy import ToolPolicy
from ...framework.base import AgentResponse
from ...framework.llm_client import LLMClient

logger = logging.getLogger(__name__)

DEDUPLICATE_PROMPT = """Mode: Deduplicate

Here are the historical issues for this function:
{historical_issues}

Here is the newly found issue:
{new_issue}

Are these two issues describing the exact same underlying vulnerability/defect? Look at the subcategory, root cause, and the actual code logic involved. Even if line numbers have shifted slightly, if the semantic defect is identical, they match.

You must output a JSON code block in EXACTLY this format:
```json
{{
  "is_duplicate": true,
  "matched_historical_id": "ISSUE_X",
  "reasoning": "Both issues describe a buffer overflow at memcpy due to missing size checks on value_size. The location changed from line 42 to 44, but the defect is identical."
}}
```
If it is NOT a duplicate of any historical issue, output:
```json
{{
  "is_duplicate": false,
  "matched_historical_id": null,
  "reasoning": "The new issue describes a use-after-free which is distinct from the historical null pointer dereferences."
}}
```
"""

VERIFY_FIX_PROMPT = """Mode: Verify Fix

A historical vulnerability was previously found in this function. The code has since been modified.
Does the vulnerability STILL EXIST in the updated code?

Historical Issue:
{historical_issue}

Updated Source Code for the function:
```c
{new_code}
```

Carefully trace the modified code to see if the root cause described in the historical issue is still present, or if it has been remediated (e.g., a size check was added, memory is now freed correctly).

You must output a JSON code block in EXACTLY this format:
```json
{{
  "still_exists": true,
  "new_location": "145",
  "reasoning": "The fix only checks if value is NULL, but still passes an unverified value_size to memcpy on line 145. The overflow is still possible."
}}
```
Or if it is fixed:
```json
{{
  "still_exists": false,
  "new_location": null,
  "reasoning": "A bounds check `if (value_size > MAX)` was added before memcpy, preventing the buffer overflow."
}}
```
"""


class IssueReconcilerAgent(ToolCallingAgent):
    """Agent for reconciling historical issues with new code or new findings."""

    def __init__(self, llm_client: LLMClient, tool_policy: Optional[ToolPolicy] = None):
        super().__init__(
            name="issue_reconciler_agent",
            description="Reconciles historical issues with new analysis results.",
            llm_client=llm_client,
            tools=[],
            tool_policy=tool_policy,
        )

    def run(self, input_data: Dict[str, Any], max_iterations: int = 2) -> AgentResponse:
        mode = input_data.get("mode")

        if mode == "deduplicate":
            return self._run_deduplicate(input_data)
        if mode == "verify_fix":
            return self._run_verify_fix(input_data)
        return AgentResponse(success=False, data={}, error=f"Unknown mode: {mode}")

    def _run_deduplicate(self, input_data: Dict[str, Any]) -> AgentResponse:
        hist_issues = input_data.get("historical_issues", [])
        new_issue = input_data.get("new_issue", {})

        if not hist_issues:
            return AgentResponse(success=True, data={"is_duplicate": False})

        minimal_hist = []
        for issue in hist_issues:
            minimal_hist.append(
                {
                    "id": issue.get("id"),
                    "subcategory": issue.get("subcategory"),
                    "description": issue.get("description"),
                    "code_snippet": issue.get("code_snippet"),
                    "location": issue.get("location"),
                }
            )

        prompt = DEDUPLICATE_PROMPT.format(
            historical_issues=json.dumps(minimal_hist, ensure_ascii=False, indent=2),
            new_issue=json.dumps(new_issue, ensure_ascii=False, indent=2),
        )
        return self._call_llm(prompt)

    def _run_verify_fix(self, input_data: Dict[str, Any]) -> AgentResponse:
        hist_issue = input_data.get("historical_issue", {})
        new_code = input_data.get("new_code", "")

        prompt = VERIFY_FIX_PROMPT.format(
            historical_issue=json.dumps(hist_issue, ensure_ascii=False, indent=2),
            new_code=new_code,
        )
        return self._call_llm(prompt)

    def _call_llm(self, user_prompt: str) -> AgentResponse:
        try:
            result = self._run_tool_conversation(
                self._messages({}, user_prompt),
                max_iterations=1,
                trace_label=self._trace_label(user_prompt),
            )
            decision = self._extract_first_json(
                str(result.get("content") or ""),
                result,
                result.get("conversation", []),
            )
            if not isinstance(decision, dict):
                logger.error("Failed to parse JSON from IssueReconciler: %s", result.get("content", ""))
                return AgentResponse(success=False, data={}, error="No JSON block found")

            logger.debug("IssueReconciler decision: %s", decision)
            return AgentResponse(success=True, data=decision)
        except Exception as exc:
            logger.exception("IssueReconciler agent failed")
            return AgentResponse(success=False, data={}, error=str(exc))

    @staticmethod
    def _trace_label(user_prompt: str) -> str:
        first_line = next((line.strip() for line in user_prompt.splitlines() if line.strip()), "")
        return first_line[:120]
