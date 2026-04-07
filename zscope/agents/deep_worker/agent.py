from typing import Dict, Any, List
import logging
import json
from ...framework.base import BaseAgent, AgentResponse
from ...framework.llm_client import LLMClient

logger = logging.getLogger(__name__)

WORKER_PROMPT = """You are a Deep Worker Agent inside Z-SCOPE.
Your goal is to focus EXCLUSIVELY on resolving the assigned 'Ticket'.
You have been provided with a specific code slice or specific hypothesis from the Manager Agent.
Do not get distracted by other parts of the codebase.

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
                return tool.execute(args)
        return {"error": f"Unknown tool: {name}"}

    def run(self, input_data: Dict[str, Any]) -> AgentResponse:
        ticket = input_data.get("ticket", {})
        ticket_id = ticket.get("id", "UNKNOWN")
        context_slice = input_data.get("context_slice", "")
        
        prompt = f"Ticket ID: {ticket_id}\nTask: {ticket.get('task')}\nData Flow Context:\n```c\n{context_slice}\n```"
        
        messages = [
            {"role": "system", "content": WORKER_PROMPT},
            {"role": "user", "content": prompt}
        ]
        
        # Scaffold logic: returning a mocked format.
        logger.info(f"DeepWorkerAgent dispatching ticket {ticket_id}")
        return AgentResponse(success=True, data={"status": "scaffolded", "ticket_id": ticket_id})
