from typing import Any, Dict, List, Optional
import logging
import json

from ..base import ToolCallingAgent
from ...tools.policy import ToolPolicy
from ...framework.base import AgentResponse
from ...framework.llm_client import LLMClient

logger = logging.getLogger(__name__)


class DeepWorkerAgent(ToolCallingAgent):
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
            result = self._run_tool_conversation(
                self._messages(input_data, prompt),
                max_iterations=max_iterations,
                trace_label=f"ticket={ticket_id}; skill={ticket.get('skill')}",
            )
            content = str(result.get("content") or "")
            conversation = result.get("conversation", [])
            parsed = self._extract_valid_payload(
                content,
                result,
                conversation,
                validator=self._is_worker_report,
            )
            if parsed:
                return AgentResponse(
                    success=True,
                    data=parsed,
                    metadata={
                        "context_tokens": result.get("context_tokens", 0),
                        "iterations": result.get("iterations", 0),
                        "tool_call_count": result.get(
                            "tool_call_count",
                            self._count_tool_result_messages(conversation),
                        ),
                        "truncated": bool(result.get("truncated", False)),
                        "max_iterations": max_iterations,
                        "needs_human_review": bool(parsed.get("needs_human_review")),
                    },
                )

            partial_result = self._extract_last_text(content, conversation)
            failure_kind = "partial" if result.get("truncated") and partial_result else "invalid_report"
            return AgentResponse(
                success=False,
                data={
                    "raw_output": content,
                    "partial_result": partial_result,
                },
                error=f"Deep worker {ticket_id} did not return a worker_report JSON.",
                metadata={
                    "context_tokens": result.get("context_tokens", 0),
                    "iterations": result.get("iterations", 0),
                    "tool_call_count": result.get(
                        "tool_call_count",
                        self._count_tool_result_messages(conversation),
                    ),
                    "truncated": bool(result.get("truncated", False)),
                    "max_iterations": max_iterations,
                    "failure_kind": failure_kind,
                    "needs_human_review": True,
                },
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
    def _count_tool_result_messages(conversation: List[Dict[str, Any]]) -> int:
        return sum(1 for msg in conversation if msg.get("role") == "tool")
