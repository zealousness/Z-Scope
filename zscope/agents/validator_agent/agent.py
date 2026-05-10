from typing import Any, Dict, List, cast
import json
import logging
import re
from ...framework.base import BaseAgent, AgentResponse
from ...framework.llm_client import LLMClient

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """
You are the Validator Agent for Z-SCOPE.
Your goal is to perform a balanced verification of suspected vulnerabilities.
You will receive a 'finding' which includes the Auditor's 'reasoning'. You MUST evaluate this logic step-by-step against the 'context_code'.

While you should look for false positives (e.g., proper guards or checks in parent functions), you must NOT reject a finding unless there is clear, verifiable evidence that the issue is mitigated.

If the provided context is insufficient to prove the issue is a False Positive, you should TEND TO VALIDATE the finding but note any uncertainties in the 'missing_context' field.

【输出格式 — 严格遵守】
分析完成后，你必须在回复的最后输出且仅输出一个 JSON 代码块，格式如下（用 ```json 包裹）：

```json
{
  "type": "validation_result",
  "issue_id": "ISSUE_1",
  "is_valid": true,
  "confidence_score": 0.85,
  "reasoning": "中文详细理由",
  "missing_context": ["缺失的上下文说明"],
  "exploit_scenario": "中文触发场景描述"
}
```

字段说明：
- "type": 必须为 "validation_result"
- "is_valid": bool，true 表示缺陷合理存在，false 表示已被缓解
- "confidence_score": 0到1之间的小数，如 0.85
- "reasoning": 中文详细理由
- "missing_context": 字符串数组，无缺失则为空数组 []
- "exploit_scenario": 若 is_valid=true 则描述触发场景，否则为空字符串

禁止输出多个 JSON 块，禁止省略任何字段，禁止在 JSON 外包裹额外结构。

IMPORTANT: Erring on the side of caution means reporting potential issues for human review, rather than silently discarding them. If the Auditor's reasoning seems plausible and you can't find clear proof of a mitigation, you MUST validate it.

Tooling requirements:
- If the finding depends on the behavior of a callee or downstream function (e.g., "might overflow in VOS_VFS_CreateDir"), you MUST use tools to retrieve that callee's implementation or snapshot (get_function_impl/get_function_snapshot). Do not assume the callee is unsafe without checking.
- If the callee cannot be found or code is unavailable, explicitly record that in 'missing_context' and explain the uncertainty in 'reasoning'.
- Use list_known_functions to locate likely callee names when uncertain.
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
                return cast(Dict[str, Any], tool.execute(args))
        return {"error": f"Unknown tool: {name}"}

    def run(self, input_data: Dict[str, Any], max_retries: int = 2) -> AgentResponse:
        finding = input_data.get("finding")
        context_code = input_data.get("context_code")
        agent_contract = input_data.get("agent_contract")
        skill_contracts = input_data.get("skill_contracts")
        workflow_context = input_data.get("workflow_context")

        prompt = f"Suspected Finding:\n{finding}\n\nRelevant Code Context:\n{context_code}"
        last_error = ""

        for attempt in range(1, max_retries + 1):
            system_prompt = SYSTEM_PROMPT
            if workflow_context:
                system_prompt += f"\n\n[Workflow Contract]\n{workflow_context}"
            if agent_contract:
                system_prompt += f"\n\n[Agent Contract]\n{agent_contract}"
            if skill_contracts:
                system_prompt += f"\n\n[Loaded Skill Contracts]\n{skill_contracts}"
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ]
            # 重试时追加格式提醒
            if attempt > 1:
                messages.append({
                    "role": "user",
                    "content": (
                        f"上一次输出未能解析出有效的 validation_result JSON（错误: {last_error}）。"
                        "请严格按照 system prompt 中的 JSON 格式重新输出结果。"
                    ),
                })
                logger.info("Validator retry %d/%d for finding: %s", attempt, max_retries, str(finding)[:80])

            try:
                result = self.llm_client.run_conversation_with_tools(
                    messages=messages,
                    tools_schema=self.tools_schema,
                    tool_executor=self._tool_executor,
                    trace_agent=self.name,
                    trace_label=f"attempt={attempt}; finding={str(finding)[:120]}",
                )
                content = result["content"]
                from ...common.utils import extract_json_blocks

                candidates = extract_json_blocks(content)
                for data in candidates:
                    if isinstance(data, dict) and (
                        data.get("type") == "validation_result" or "is_valid" in data
                    ):
                        return AgentResponse(success=True, data=data)

                last_error = f"JSON解析失败，提取到 {len(candidates)} 个候选块但无 validation_result"
                logger.warning(
                    "Validator attempt %d/%d: %s | LLM原始输出(前500字符): %s",
                    attempt, max_retries, last_error, content[:500],
                )
            except Exception as e:
                last_error = str(e)
                logger.warning("Validator attempt %d/%d exception: %s", attempt, max_retries, last_error)

        return AgentResponse(success=False, data={}, error=f"经过{max_retries}次尝试仍失败: {last_error}")
