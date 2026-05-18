"""Shared runtime helpers for Z-SCOPE agents."""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, cast

from ..common.utils import extract_json_blocks
from ..framework.base import AgentResponse, BaseAgent
from ..framework.llm_client import LLMClient
from ..core.tool_policy import ToolPolicy

logger = logging.getLogger(__name__)

JsonValidator = Callable[[Any], bool]
JsonExtractor = Callable[[str, Dict[str, Any], List[Dict[str, Any]]], Any]
PostProcessor = Callable[[Any], Any]


class ToolCallingAgent(BaseAgent):
    """Base class for agents that call the shared LLM tool loop."""

    def __init__(
        self,
        *,
        name: str,
        description: str,
        llm_client: LLMClient,
        tools: Optional[List[Any]] = None,
        tool_policy: Optional[ToolPolicy] = None,
    ) -> None:
        super().__init__(name=name, description=description)
        self.llm_client = llm_client
        self.tools = tools or []
        self.tool_policy = tool_policy or ToolPolicy.allow_all()
        self.tools_schema = self.tool_policy.filter_tool_schemas(
            [tool.get_schema() for tool in self.tools]
        )
        self._tool_by_name = {tool.name: tool for tool in self.tools}

    def _tool_executor(self, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        tool = self._tool_by_name.get(name)
        if not tool:
            return {"error": f"Unknown tool: {name}"}
        policy_error = self.tool_policy.enforce_tool(
            name,
            args,
            schema=tool.get_schema(),
            actor=self.name,
        )
        if policy_error:
            return policy_error
        start = time.perf_counter()
        result = cast(Dict[str, Any], tool.execute(args))
        self.tool_policy.run_post_hooks(
            "tool",
            name,
            args,
            result=result,
            actor=self.name,
            duration_ms=(time.perf_counter() - start) * 1000,
        )
        return result

    def _compose_system_prompt(
        self,
        input_data: Optional[Dict[str, Any]] = None,
        *,
        substitutions: Optional[Dict[str, Any]] = None,
        active_skill_names: Optional[List[str]] = None,
    ) -> str:
        input_data = input_data or {}
        system_prompt = self._agent_system_prompt(
            input_data,
            substitutions=substitutions,
            active_skill_names=active_skill_names,
        )
        workflow_context = input_data.get("workflow_context")
        if workflow_context:
            system_prompt += f"\n\n[Workflow Contract]\n{workflow_context}"
        skill_contracts = input_data.get("skill_contracts")
        if skill_contracts:
            system_prompt += f"\n\n[Loaded Skill Contracts]\n{skill_contracts}"
        return system_prompt

    def _messages(
        self,
        input_data: Optional[Dict[str, Any]],
        user_prompt: str,
        *,
        substitutions: Optional[Dict[str, Any]] = None,
        active_skill_names: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        return [
            {
                "role": "system",
                "content": self._compose_system_prompt(
                    input_data,
                    substitutions=substitutions,
                    active_skill_names=active_skill_names,
                ),
            },
            {"role": "user", "content": user_prompt},
        ]

    def _run_tool_conversation(
        self,
        messages: List[Dict[str, Any]],
        *,
        max_iterations: int = 50,
        trace_label: str = "",
    ) -> Dict[str, Any]:
        return self.llm_client.run_conversation_with_tools(
            messages=messages,
            tools_schema=self.tools_schema,
            tool_executor=self._tool_executor,
            max_iterations=max_iterations,
            trace_agent=self.name,
            trace_label=trace_label,
        )

    @staticmethod
    def _text_sources(
        content: str,
        result: Dict[str, Any],
        conversation: Iterable[Dict[str, Any]],
    ) -> List[str]:
        sources = [content]
        if result.get("reasoning_content"):
            sources.append(str(result["reasoning_content"]))

        for message in reversed(list(conversation)):
            if message.get("role") != "assistant":
                continue
            sources.append(str(message.get("content") or ""))
            if message.get("reasoning_content"):
                sources.append(str(message["reasoning_content"]))
        return [source for source in sources if source]

    def _extract_valid_payload(
        self,
        content: str,
        result: Dict[str, Any],
        conversation: Iterable[Dict[str, Any]],
        *,
        validator: JsonValidator,
        nested_keys: Sequence[str] = (),
    ) -> Any:
        for text in self._text_sources(content, result, conversation):
            for data in extract_json_blocks(text):
                if validator(data):
                    return data
                if isinstance(data, dict):
                    for key in nested_keys:
                        nested = data.get(key)
                        if validator(nested):
                            return nested
        return None

    def _extract_first_json(
        self,
        content: str,
        result: Dict[str, Any],
        conversation: Iterable[Dict[str, Any]],
    ) -> Any:
        for text in self._text_sources(content, result, conversation):
            blocks = extract_json_blocks(text)
            if blocks:
                return blocks[0]
        return None


class JsonToolAgent(ToolCallingAgent):
    """Tool-calling agent with common JSON extraction and retry behavior."""

    def _run_json_conversation(
        self,
        messages: List[Dict[str, Any]],
        *,
        extractor: JsonExtractor,
        trace_label: str,
        parse_label: str,
        retry_prompt: str,
        max_iterations: int = 50,
        max_json_retries: int = 2,
        fail_on_truncated: bool = False,
        truncated_error: str = "Max iterations reached without finding a JSON result in history",
        post_process: Optional[PostProcessor] = None,
    ) -> AgentResponse:
        try:
            result = self._run_tool_conversation(
                messages,
                max_iterations=max_iterations,
                trace_label=trace_label,
            )
            content = str(result.get("content") or "")
            conversation = result.get("conversation", [])
            ctx_tokens = int(result.get("context_tokens", 0) or 0)

            parsed = extractor(content, result, conversation)
            if parsed:
                if post_process:
                    parsed = post_process(parsed)
                return AgentResponse(
                    success=True,
                    data=parsed,
                    metadata={"context_tokens": ctx_tokens},
                )

            if fail_on_truncated and result.get("truncated"):
                return AgentResponse(success=False, data={}, error=truncated_error)

            for retry in range(1, max_json_retries + 1):
                logger.warning(
                    "[Retry %d/%d] Failed to parse %s for %s. Asking LLM to re-output valid JSON.",
                    retry,
                    max_json_retries,
                    parse_label,
                    self.name,
                )
                conversation.append({"role": "user", "content": retry_prompt})
                retry_response = self.llm_client.chat_completion(
                    conversation,
                    tools=None,
                    trace_agent=self.name,
                    trace_label=f"{trace_label}; json_retry={retry}",
                    trace_iteration=retry,
                )
                retry_choice = retry_response.get("choices", [{}])[0]
                retry_message = retry_choice.get("message", {})
                retry_content = str(retry_message.get("content") or "")
                conversation.append(retry_message)

                parsed = extractor(retry_content, {}, conversation)
                if parsed:
                    if post_process:
                        parsed = post_process(parsed)
                    retry_ctx_tokens = LLMClient.estimate_tokens(conversation)
                    logger.info(
                        "[Retry %d] Successfully parsed %s for %s",
                        retry,
                        parse_label,
                        self.name,
                    )
                    return AgentResponse(
                        success=True,
                        data=parsed,
                        metadata={"context_tokens": ctx_tokens + retry_ctx_tokens},
                    )

            last_msg_debug = json.dumps(
                conversation[-1] if conversation else {},
                ensure_ascii=False,
            )
            logger.error(
                "Failed to parse %s for %s after %d retries. Last API message: %s",
                parse_label,
                self.name,
                max_json_retries,
                last_msg_debug,
            )
            return AgentResponse(
                success=False,
                data={},
                error=f"Failed to parse {parse_label}. See logs for full content.",
            )
        except Exception as exc:
            return AgentResponse(success=False, data={}, error=str(exc))
