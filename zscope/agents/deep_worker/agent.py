from typing import Any, Dict, List, Optional
import logging
import json

from ..base import JsonOutputSpec, JsonToolAgent
from ...tools.policy import ToolPolicy
from ...framework.base import AgentResponse
from ...framework.llm_client import LLMClient

logger = logging.getLogger(__name__)


WORKER_REPORT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "type": {"type": "string", "enum": ["worker_report"]},
        "ticket_id": {"type": "string"},
        "issues_found": {"type": "array", "items": {"type": "object"}},
        "conclusion": {"type": "string"},
        "needs_human_review": {"type": "boolean"},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
    },
    "required": ["type", "ticket_id", "issues_found", "conclusion"],
    "additionalProperties": True,
}


class DeepWorkerAgent(JsonToolAgent):
    """
    Worker Agent that receives a narrow, isolated ticket (e.g. a DFG slice and hypothesis)
    from the Manager Agent to perform deep structural vulnerability traversal.
    """

    def __init__(
        self,
        llm_client: LLMClient,
        tools: List[Any],
        tool_policy: Optional[ToolPolicy] = None,
    ):
        super().__init__(
            name="deep_worker",
            description="Executes a narrow investigation ticket passed by the Manager.",
            llm_client=llm_client,
            tools=tools,
            tool_policy=tool_policy,
        )

    def run(self, input_data: Dict[str, Any]) -> AgentResponse:
        ticket = input_data.get("ticket", {})
        ticket_id = ticket.get("id", "UNKNOWN")
        context_slice = input_data.get("context_slice", "")
        skill_contract = input_data.get("skill_contract", "")
        max_iterations = int(input_data.get("max_iterations", 20))
        execution_policy = input_data.get("execution_policy") or {}
        nested_spawn_allowed = bool(input_data.get("nested_spawn_allowed", False))
        worktree_isolation = input_data.get("worktree_isolation") or {}

        prompt = (
            f"Ticket ID: {ticket_id}\n"
            f"Skill: {ticket.get('skill')}\n"
            f"Trigger: {ticket.get('trigger')} at line {ticket.get('line')}\n"
            f"Origin: {ticket.get('origin')}\n"
            f"Sink: {ticket.get('sink')}\n"
            f"Sources: {json.dumps(ticket.get('sources') or [], ensure_ascii=False)}\n"
            f"Call paths: {json.dumps(ticket.get('call_paths') or [], ensure_ascii=False)}\n"
            f"Structured evidence: {json.dumps(ticket.get('evidence') or {}, ensure_ascii=False, indent=2)}\n"
            f"Task: {ticket.get('task')}\n"
            f"Execution policy: {json.dumps(execution_policy, ensure_ascii=False)}\n"
            f"Worktree isolation: {json.dumps(worktree_isolation, ensure_ascii=False)}\n"
            f"Nested subagent spawning allowed: {nested_spawn_allowed}\n\n"
            f"Skill Contract:\n{skill_contract or '[no skill contract loaded]'}\n\n"
            f"Focused Code Context:\n```c\n{context_slice}\n```"
        )

        logger.info("DeepWorkerAgent dispatching ticket %s", ticket_id)
        try:
            messages = self._messages(input_data, prompt)
            response = self._run_json_conversation(
                messages,
                extractor=lambda content, result, conversation: self._extract_valid_payload(
                    content,
                    result,
                    conversation,
                    validator=self._is_worker_report,
                ),
                trace_label=f"ticket={ticket_id}; skill={ticket.get('skill')}",
                parse_label="worker_report JSON",
                retry_prompt=(
                    "The previous response did not contain a valid worker_report JSON. "
                    "Re-output only one complete JSON object with type=worker_report."
                ),
                max_iterations=max_iterations,
                json_output_spec=JsonOutputSpec(
                    type_name="worker_report",
                    schema=WORKER_REPORT_SCHEMA,
                    final_tool_name="emit_worker_report",
                    final_tool_description="Emit the final focused worker_report object.",
                    validator=self._is_worker_report,
                    metadata_prefix="worker_report",
                ),
            )
            if response.success:
                parsed = response.data
                metadata = dict(response.metadata or {})
                metadata.update(
                    {
                        "truncated": bool(metadata.get("truncated", False)),
                        "max_iterations": max_iterations,
                        "needs_human_review": bool(parsed.get("needs_human_review")),
                    }
                )
                return AgentResponse(
                    success=True,
                    data=parsed,
                    metadata=metadata,
                )

            partial_result = self._extract_last_text_from_response(response)
            failure_kind = (
                "partial"
                if response.metadata.get("truncated") and partial_result
                else "invalid_report"
            )
            metadata = dict(response.metadata or {})
            metadata.update(
                {
                    "max_iterations": max_iterations,
                    "failure_kind": failure_kind,
                    "needs_human_review": True,
                }
            )
            return AgentResponse(
                success=False,
                data={
                    "raw_output": str(response.data.get("raw_output") or ""),
                    "partial_result": partial_result,
                },
                error=f"Deep worker {ticket_id} did not return a worker_report JSON.",
                metadata=metadata,
            )
        except KeyboardInterrupt:
            return AgentResponse(
                success=False,
                data={},
                error=f"Deep worker {ticket_id} was interrupted.",
                metadata={"failure_kind": "aborted"},
            )
        except Exception as exc:
            return AgentResponse(
                success=False,
                data={},
                error=str(exc),
                metadata={"failure_kind": "failed"},
            )

    @staticmethod
    def _is_worker_report(data: Any) -> bool:
        return isinstance(data, dict) and data.get("type") == "worker_report"

    @staticmethod
    def _extract_last_text(content: str, conversation: List[Dict[str, Any]]) -> str:
        if content:
            return content
        for msg in reversed(conversation):
            if msg.get("role") == "assistant" and msg.get("content"):
                return str(msg.get("content"))
        return ""

    @staticmethod
    def _extract_last_text_from_response(response: AgentResponse) -> str:
        raw_output = response.data.get("raw_output") if isinstance(response.data, dict) else ""
        partial_result = response.data.get("partial_result") if isinstance(response.data, dict) else ""
        return str(partial_result or raw_output or "")
