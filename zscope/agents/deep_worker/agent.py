from typing import Any, Dict, List, cast
import logging
import json
from ...framework.base import BaseAgent, AgentResponse
from ...framework.llm_client import LLMClient

logger = logging.getLogger(__name__)

WORKER_PROMPT = """You are a Deep Worker Agent inside Z-SCOPE.
Your goal is to focus EXCLUSIVELY on resolving the assigned 'Ticket'.
You have been provided with a specific code slice or specific hypothesis from the Manager Agent.
Do not get distracted by other parts of the codebase.
Use only the skill contract and the allowed tools to answer the ticket. If the
provided slice is insufficient, call tools for the minimum missing context.

Output your findings securely in the following format:
```json
{
  "type": "worker_report",
  "ticket_id": "<ID>",
  "issues_found": [...],
  "conclusion": "<Summary of your deep dive>"
}
```
"""

class DeepWorkerAgent(BaseAgent):
    """
    Worker Agent that receives a narrow, isolated ticket (e.g. a DFG slice and hypothesis)
    from the Manager Agent to perform deep structural vulnerability traversal.
    """
    
    def __init__(self, llm_client: LLMClient, tools: List[Any]):
        super().__init__(
            name="deep_worker",
            description="Executes a narrow investigation ticket passed by the Manager."
        )
        self.llm_client = llm_client
        self.tools = tools
        self.tools_schema = [t.get_schema() for t in tools]

    def _tool_executor(self, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        for tool in self.tools:
            if tool.name == name:
                return cast(Dict[str, Any], tool.execute(args))
        return {"error": f"Unknown tool: {name}"}

    def run(self, input_data: Dict[str, Any]) -> AgentResponse:
        ticket = input_data.get("ticket", {})
        ticket_id = ticket.get("id", "UNKNOWN")
        context_slice = input_data.get("context_slice", "")
        skill_contract = input_data.get("skill_contract", "")
        max_iterations = int(input_data.get("max_iterations", 20))
        
        prompt = (
            f"Ticket ID: {ticket_id}\n"
            f"Skill: {ticket.get('skill')}\n"
            f"Trigger: {ticket.get('trigger')} at line {ticket.get('line')}\n"
            f"Task: {ticket.get('task')}\n\n"
            f"Skill Contract:\n{skill_contract or '[no skill contract loaded]'}\n\n"
            f"Focused Code Context:\n```c\n{context_slice}\n```"
        )
        
        messages = [
            {"role": "system", "content": WORKER_PROMPT},
            {"role": "user", "content": prompt}
        ]
        
        logger.info(f"DeepWorkerAgent dispatching ticket {ticket_id}")
        try:
            result = self.llm_client.run_conversation_with_tools(
                messages=messages,
                tools_schema=self.tools_schema,
                tool_executor=self._tool_executor,
                max_iterations=max_iterations,
            )
            content = result.get("content", "")
            conversation = result.get("conversation", [])

            from ...common.utils import extract_json_blocks

            for text in [content] + [
                msg.get("content", "")
                for msg in reversed(conversation)
                if msg.get("role") == "assistant"
            ]:
                for data in extract_json_blocks(text):
                    if isinstance(data, dict) and data.get("type") == "worker_report":
                        return AgentResponse(
                            success=True,
                            data=data,
                            metadata={"context_tokens": result.get("context_tokens", 0)},
                        )

            return AgentResponse(
                success=False,
                data={},
                error=f"Deep worker {ticket_id} did not return a worker_report JSON.",
                metadata={"context_tokens": result.get("context_tokens", 0)},
            )
        except Exception as e:
            return AgentResponse(success=False, data={}, error=str(e))
