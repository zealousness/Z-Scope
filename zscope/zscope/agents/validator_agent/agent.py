from typing import Dict, Any, List
import json
import re
from ...framework.base import BaseAgent, AgentResponse
from ...framework.llm_client import LLMClient

SYSTEM_PROMPT = """
You are the Validator Agent for Z-SCOPE. 
Your goal is to perform a balanced verification of suspected vulnerabilities. 
You will receive a 'finding' which includes the Auditor's 'reasoning'. You MUST evaluate this logic step-by-step against the 'context_code'.

While you should look for false positives (e.g., proper guards or checks in parent functions), you must NOT reject a finding unless there is clear, verifiable evidence that the issue is mitigated.

If the provided context is insufficient to prove the issue is a False Positive, you should TEND TO VALIDATE the finding but note any uncertainties in the 'missing_context' field.

You MUST output a JSON block with type 'validation_result'.

Schema:
{
  "type": "validation_result",
  "issue_id": "ISSUE_1",
  "is_valid": true/false (Set to true if there is a reasonable possibility of a defect),
  "confidence_score": 0.0-1.0,
  "reasoning": "Detailed justification in Chinese",
  "missing_context": ["What else we need to see to be certain"],
  "exploit_scenario": "If valid, describe how it could be triggered in Chinese"
}

IMPORTANT: Erring on the side of caution means reporting potential issues for human review, rather than silently discarding them. If the Auditor's reasoning seems plausible and you can't find clear proof of a mitigation, you MUST validate it.
"""

class ValidatorAgent(BaseAgent):
    """Agent for verifying and triaging findings."""
    
    def __init__(self, llm_client: LLMClient, tools: List[Any]):
        super().__init__(
            name="validator_agent",
            description="Verifies suspect findings and attempts to find exploit paths."
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
        finding = input_data.get("finding")
        context_code = input_data.get("context_code")

        prompt = f"Suspected Finding:\n{finding}\n\nRelevant Code Context:\n{context_code}"
        
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ]

        try:
            result = self.llm_client.run_conversation_with_tools(
                messages=messages,
                tools_schema=self.tools_schema,
                tool_executor=self._tool_executor
            )
            
            content = result["content"]
            from ...common.utils import extract_json_blocks
            
            candidates = extract_json_blocks(content)
            for data in candidates:
                if isinstance(data, dict) and (data.get("type") == "validation_result" or "is_valid" in data):
                    return AgentResponse(success=True, data=data)
            
            return AgentResponse(success=False, data={}, error="Failed to parse validation JSON")
            
        except Exception as e:
            return AgentResponse(success=False, data={}, error=str(e))
