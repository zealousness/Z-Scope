from typing import Any, Dict, List, Optional
import json
import logging

from ..base import JsonOutputSpec, JsonToolAgent
from ...tools.policy import ToolPolicy
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


DEDUPLICATE_CLUSTER_PROMPT = """Mode: Deduplicate Cluster

You are reviewing a small cluster of findings from the same Z-SCOPE report.
Your job is only to decide whether some findings are duplicate descriptions of
the exact same underlying vulnerability/root cause. Do not decide whether the
vulnerability is real; that is the validator's job.

Rules:
- Merge only when the findings describe the same defect in the same code/resource.
- Keep findings distinct when they involve different resources, member fields,
  ownership paths, source/sink paths, or independent failure paths.
- Prefer the most concrete/local/backend-backed finding as the primary issue.
- If unsure, keep findings distinct.

Cluster:
{cluster}

You must output a JSON code block in EXACTLY this format:
```json
{{
  "duplicate_groups": [
    {{
      "primary_issue_id": "ISSUE_A",
      "duplicate_issue_ids": ["ISSUE_B"],
      "root_cause_key": "category|file|function|resource",
      "confidence": 0.91,
      "reasoning": "Both findings describe the same missing cleanup of the same object on the same failure path."
    }}
  ],
  "must_keep_distinct_issue_ids": ["ISSUE_C"]
}}
```

If there are no duplicates, output:
```json
{{
  "duplicate_groups": [],
  "must_keep_distinct_issue_ids": ["ISSUE_A", "ISSUE_B"]
}}
```
"""


DEDUPLICATE_DECISION_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "is_duplicate": {"type": "boolean"},
        "matched_historical_id": {"type": ["string", "null"]},
        "reasoning": {"type": "string"},
    },
    "required": ["is_duplicate", "reasoning"],
    "additionalProperties": True,
}

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

DEDUPLICATE_CLUSTER_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "duplicate_groups": {"type": "array", "items": {"type": "object"}},
        "must_keep_distinct_issue_ids": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["duplicate_groups", "must_keep_distinct_issue_ids"],
    "additionalProperties": True,
}


class IssueReconcilerAgent(JsonToolAgent):
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
        if mode == "deduplicate_cluster":
            return self._run_deduplicate_cluster(input_data)
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

    def _run_deduplicate_cluster(self, input_data: Dict[str, Any]) -> AgentResponse:
        issues = input_data.get("issues", [])
        if not isinstance(issues, list) or len(issues) < 2:
            return AgentResponse(
                success=True,
                data={"duplicate_groups": [], "must_keep_distinct_issue_ids": []},
            )

        compact_issues = [self._compact_cluster_issue(issue) for issue in issues if isinstance(issue, dict)]
        cluster = {
            "cluster_id": input_data.get("cluster_id"),
            "issues": compact_issues,
            "deterministic_hints": input_data.get("deterministic_hints", {}),
        }
        prompt = DEDUPLICATE_CLUSTER_PROMPT.format(
            cluster=json.dumps(cluster, ensure_ascii=False, indent=2)
        )
        response = self._call_llm(prompt)
        if not response.success:
            return response
        normalized = self._normalize_cluster_decision(response.data, compact_issues)
        if normalized is None:
            return AgentResponse(
                success=False,
                data={},
                error="Invalid deduplicate_cluster JSON schema",
                metadata=response.metadata,
            )
        return AgentResponse(success=True, data=normalized, metadata=response.metadata)

    def _call_llm(self, user_prompt: str) -> AgentResponse:
        try:
            spec = self._json_output_spec_for_prompt(user_prompt)
            response = self._run_json_conversation(
                self._messages({}, user_prompt),
                extractor=lambda content, result, conversation: self._extract_structured_json_payload(
                    content,
                    result,
                    conversation,
                    spec,
                ),
                trace_label=self._trace_label(user_prompt),
                parse_label=f"{spec.type_name} JSON",
                retry_prompt=(
                    f"The previous response did not contain a valid {spec.type_name} JSON. "
                    "Re-output exactly one JSON object."
                ),
                max_iterations=1,
                max_json_retries=1,
                json_output_spec=spec,
            )
            if not response.success:
                logger.error("Failed to parse JSON from IssueReconciler: %s", response.error)
                return response

            logger.debug("IssueReconciler decision: %s", response.data)
            return response
        except Exception as exc:
            logger.exception("IssueReconciler agent failed")
            return AgentResponse(success=False, data={}, error=str(exc))

    @classmethod
    def _json_output_spec_for_prompt(cls, user_prompt: str) -> JsonOutputSpec:
        first_line = next((line.strip() for line in user_prompt.splitlines() if line.strip()), "")
        if "Deduplicate Cluster" in first_line:
            return JsonOutputSpec(
                type_name="deduplicate_cluster_decision",
                schema=DEDUPLICATE_CLUSTER_SCHEMA,
                final_tool_name="emit_deduplicate_cluster_decision",
                final_tool_description="Emit the final deduplicate cluster decision.",
                validator=cls._is_cluster_decision_payload,
                metadata_prefix="issue_reconciler",
            )
        if "Verify Fix" in first_line:
            return JsonOutputSpec(
                type_name="verify_fix_decision",
                schema=VERIFY_FIX_DECISION_SCHEMA,
                final_tool_name="emit_verify_fix_decision",
                final_tool_description="Emit the final historical fix verification decision.",
                validator=cls._is_verify_fix_payload,
                metadata_prefix="issue_reconciler",
            )
        return JsonOutputSpec(
            type_name="deduplicate_decision",
            schema=DEDUPLICATE_DECISION_SCHEMA,
            final_tool_name="emit_deduplicate_decision",
            final_tool_description="Emit the final historical issue deduplication decision.",
            validator=cls._is_deduplicate_payload,
            metadata_prefix="issue_reconciler",
        )

    @staticmethod
    def _is_deduplicate_payload(data: Any) -> bool:
        return isinstance(data, dict) and isinstance(data.get("is_duplicate"), bool)

    @staticmethod
    def _is_verify_fix_payload(data: Any) -> bool:
        return isinstance(data, dict) and isinstance(data.get("still_exists"), bool)

    @staticmethod
    def _is_cluster_decision_payload(data: Any) -> bool:
        return (
            isinstance(data, dict)
            and isinstance(data.get("duplicate_groups"), list)
            and isinstance(data.get("must_keep_distinct_issue_ids"), list)
        )

    @staticmethod
    def _compact_cluster_issue(issue: Dict[str, Any]) -> Dict[str, Any]:
        keep = (
            "id",
            "category",
            "category_family",
            "function",
            "file",
            "location",
            "root_cause",
            "description",
            "positive_evidence",
            "candidate_source",
            "resource_signature",
            "root_cause_key",
            "source",
            "sink",
            "call_path",
        )
        return {key: issue.get(key) for key in keep if issue.get(key) not in (None, "", [], {})}

    @staticmethod
    def _normalize_cluster_decision(
        data: Dict[str, Any],
        issues: List[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        if not isinstance(data, dict):
            return None
        issue_ids = {str(issue.get("id")) for issue in issues if issue.get("id")}
        raw_groups = data.get("duplicate_groups", [])
        raw_keep = data.get("must_keep_distinct_issue_ids", [])
        if not isinstance(raw_groups, list) or not isinstance(raw_keep, list):
            return None

        groups = []
        for raw_group in raw_groups:
            if not isinstance(raw_group, dict):
                return None
            primary_id = str(raw_group.get("primary_issue_id") or "")
            duplicate_ids = [
                str(item)
                for item in raw_group.get("duplicate_issue_ids", [])
                if str(item or "") in issue_ids
            ]
            if primary_id not in issue_ids or not duplicate_ids:
                return None
            try:
                confidence = float(raw_group.get("confidence", 0) or 0)
            except (TypeError, ValueError):
                return None
            groups.append(
                {
                    "primary_issue_id": primary_id,
                    "duplicate_issue_ids": duplicate_ids,
                    "root_cause_key": str(raw_group.get("root_cause_key") or ""),
                    "confidence": confidence,
                    "reasoning": str(raw_group.get("reasoning") or ""),
                }
            )

        keep_distinct = [str(item) for item in raw_keep if str(item or "") in issue_ids]
        return {
            "duplicate_groups": groups,
            "must_keep_distinct_issue_ids": keep_distinct,
        }

    @staticmethod
    def _trace_label(user_prompt: str) -> str:
        first_line = next((line.strip() for line in user_prompt.splitlines() if line.strip()), "")
        return first_line[:120]
