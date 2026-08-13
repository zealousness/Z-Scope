"""Shared runtime helpers for Z-SCOPE agents."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple, cast

from ..common.utils import extract_json_blocks
from ..framework.base import AgentResponse, BaseAgent
from ..framework.llm_client import LLMClient
from ..tools.policy import ToolPolicy

logger = logging.getLogger(__name__)

JsonValidator = Callable[[Any], bool]
JsonExtractor = Callable[[str, Dict[str, Any], List[Dict[str, Any]]], Any]
PostProcessor = Callable[[Any], Any]


@dataclass(frozen=True)
class JsonOutputSpec:
    """Runtime contract for agents that must emit one structured JSON payload."""

    type_name: str
    schema: Dict[str, Any]
    final_tool_name: str
    final_tool_description: str
    validator: JsonValidator
    nested_keys: Sequence[str] = ()
    fallback_empty_payload: Optional[Dict[str, Any]] = None
    metadata_prefix: str = "json"


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

    def _tool_executor(self, name: str, args: Any) -> Dict[str, Any]:
        tool = self._tool_by_name.get(name)
        if not tool:
            return {"error": f"Unknown tool: {name}"}
        if not isinstance(args, dict):
            validation_error = tool.validate_arguments(args)
            if validation_error:
                return cast(Dict[str, Any], validation_error)
            return {
                "success": False,
                "error": "Tool arguments must be a JSON object; please correct the payload and retry.",
            }
        policy_error = self.tool_policy.enforce_tool(
            name,
            args,
            schema=tool.get_schema(),
            actor=self.name,
        )
        if policy_error:
            return policy_error
        validation_error = tool.validate_arguments(args)
        if validation_error:
            return cast(Dict[str, Any], validation_error)
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
        additional_tools_schema: Optional[List[Dict[str, Any]]] = None,
        terminal_tool_name: Optional[str] = None,
        terminal_tool_handler: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        terminal_tool_validator: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        terminal_tool_required: bool = False,
        tool_executor: Optional[Callable[[str, Any], Dict[str, Any]]] = None,
        preserve_reasoning_metadata: bool = False,
    ) -> Dict[str, Any]:
        tools_schema = list(self.tools_schema)
        if additional_tools_schema:
            tools_schema.extend(additional_tools_schema)
        call_kwargs: Dict[str, Any] = {
            "messages": messages,
            "tools_schema": tools_schema,
            "tool_executor": tool_executor or self._tool_executor,
            "max_iterations": max_iterations,
            "trace_agent": self.name,
            "trace_label": trace_label,
        }
        if preserve_reasoning_metadata:
            call_kwargs["preserve_reasoning_metadata"] = True
        if (
            terminal_tool_name
            or terminal_tool_handler
            or terminal_tool_validator
            or terminal_tool_required
        ):
            call_kwargs.update(
                {
                    "terminal_tool_name": terminal_tool_name,
                    "terminal_tool_handler": terminal_tool_handler,
                    "terminal_tool_validator": terminal_tool_validator,
                    "terminal_tool_required": terminal_tool_required,
                }
            )
        return self.llm_client.run_conversation_with_tools(
            **call_kwargs,
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
        json_output_spec: Optional[JsonOutputSpec] = None,
        require_structured_finalization: bool = False,
        single_pass_final_tool: bool = False,
    ) -> AgentResponse:
        try:
            terminal_schema = (
                self._final_json_tool_schema(json_output_spec)
                if single_pass_final_tool and json_output_spec
                else None
            )

            def terminal_handler(payload: Dict[str, Any]) -> Dict[str, Any]:
                if not json_output_spec:
                    return {"valid": True, "payload": payload}
                parsed_payload = self._coerce_payload_for_spec(payload, json_output_spec)
                if parsed_payload is None:
                    return {
                        "valid": False,
                        "error": (
                            f"Invalid {json_output_spec.type_name} payload; follow the supplied "
                            "schema and call the terminal tool again."
                        ),
                    }
                return {"valid": True, "payload": parsed_payload}

            result = self._run_tool_conversation(
                messages,
                max_iterations=max_iterations,
                trace_label=trace_label,
                additional_tools_schema=[terminal_schema] if terminal_schema else None,
                terminal_tool_name=(
                    json_output_spec.final_tool_name
                    if json_output_spec is not None and terminal_schema
                    else None
                ),
                terminal_tool_handler=terminal_handler if terminal_schema else None,
                terminal_tool_required=bool(terminal_schema),
            )
            content = str(result.get("content") or "")
            conversation = result.get("conversation", [])
            ctx_tokens = int(result.get("context_tokens", 0) or 0)

            if result.get("terminal_loop_guard_triggered"):
                metadata = self._json_result_metadata(result, json_output_spec)
                metadata["reason"] = "terminal_tool_loop_guard"
                metadata["terminal_loop_guard_triggered"] = True
                metadata["terminal_loop_guard_reason"] = str(
                    result.get("terminal_loop_guard_reason") or ""
                )
                repeated_terminal = result.get("repeated_terminal_tool_call")
                if isinstance(repeated_terminal, dict):
                    metadata["repeated_terminal_tool_call"] = repeated_terminal
                return AgentResponse(
                    success=False,
                    data={},
                    error="Stopped after repeated invalid terminal tool calls.",
                    metadata=metadata,
                )

            if (
                require_structured_finalization
                and json_output_spec
                and not result.get("loop_guard_triggered")
                and not single_pass_final_tool
            ):
                return self._run_json_structured_finalization(
                    messages,
                    result,
                    json_output_spec=json_output_spec,
                    extractor=extractor,
                    trace_label=trace_label,
                    parse_label=parse_label,
                    max_json_retries=max_json_retries,
                    post_process=post_process,
                )

            parsed = self._extract_json_output(
                content,
                result,
                conversation,
                extractor=extractor,
                json_output_spec=json_output_spec,
            )
            if parsed:
                if post_process:
                    parsed = post_process(parsed)
                metadata = self._json_result_metadata(result, json_output_spec)
                if single_pass_final_tool and json_output_spec:
                    metadata["single_pass"] = True
                    metadata["finalization_mode"] = "single_pass_tool"
                    metadata["terminal_tool_name"] = json_output_spec.final_tool_name
                    metadata["terminal_tool_valid"] = bool(result.get("terminal_tool_valid"))
                    metadata["terminal_tool_call_count"] = int(
                        result.get("terminal_tool_call_count", 0) or 0
                    )
                return AgentResponse(
                    success=True,
                    data=parsed,
                    metadata=metadata,
                )

            if single_pass_final_tool and json_output_spec:
                metadata = self._json_result_metadata(result, json_output_spec)
                metadata["single_pass"] = True
                metadata["finalization_mode"] = "single_pass_tool"
                metadata["terminal_tool_name"] = json_output_spec.final_tool_name
                metadata["terminal_tool_valid"] = bool(result.get("terminal_tool_valid"))
                metadata["terminal_tool_call_count"] = int(
                    result.get("terminal_tool_call_count", 0) or 0
                )
                metadata["snapshot_terminal_tool_failed"] = True
                return AgentResponse(
                    success=False,
                    data={
                        "raw_output": content,
                        "partial_result": self._extract_last_assistant_text(content, conversation),
                    },
                    error=f"Failed to produce {parse_label} with terminal tool.",
                    metadata=metadata,
                )

            if json_output_spec:
                error_type, json_blocks_found = self._classify_json_result_failure(
                    content,
                    result,
                    conversation,
                    json_output_spec=json_output_spec,
                )
                self._log_json_result_failure(
                    attempt=1,
                    max_retries=max_json_retries,
                    error_type=error_type,
                    phase="finalize",
                    parse_label=parse_label,
                    result=result,
                    content=content,
                    json_blocks_found=json_blocks_found,
                )
                repair_response = self._run_json_final_repair(
                    messages,
                    result,
                    json_output_spec=json_output_spec,
                    extractor=extractor,
                    trace_label=trace_label,
                    parse_label=parse_label,
                    error_type=error_type,
                    max_json_retries=max_json_retries,
                    post_process=post_process,
                )
                if result.get("loop_guard_triggered"):
                    repair_response.metadata = dict(repair_response.metadata or {})
                    repair_response.metadata["loop_guard_triggered"] = True
                    repeated = result.get("repeated_tool_call")
                    if isinstance(repeated, dict):
                        repair_response.metadata["repeated_tool_call"] = repeated
                if repair_response.success:
                    return repair_response
                if fail_on_truncated and result.get("truncated"):
                    metadata = repair_response.metadata or self._json_result_metadata(
                        result,
                        json_output_spec,
                    )
                    return AgentResponse(
                        success=False,
                        data={},
                        error=truncated_error,
                        metadata=metadata,
                    )
                if not repair_response.data:
                    repair_response.data = {
                        "raw_output": content,
                        "partial_result": self._extract_last_assistant_text(content, conversation),
                    }
                return repair_response

            if result.get("loop_guard_triggered"):
                metadata = self._conversation_token_metadata(result)
                repeated = result.get("repeated_tool_call")
                if isinstance(repeated, dict):
                    metadata["repeated_tool_call"] = repeated
                metadata["loop_guard_triggered"] = True
                return AgentResponse(
                    success=False,
                    data={},
                    error="Stopped after repeated identical tool calls.",
                    metadata=metadata,
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
                retry_prompt_tokens, retry_completion_tokens = LLMClient._response_token_usage(
                    retry_response,
                    conversation,
                    retry_message,
                )
                conversation.append(retry_message)

                parsed = extractor(retry_content, {}, conversation)
                if parsed:
                    if post_process:
                        parsed = post_process(parsed)
                    retry_ctx_tokens = LLMClient.estimate_tokens(conversation)
                    retry_metadata = self._conversation_token_metadata(result)
                    retry_metadata["context_tokens"] = ctx_tokens + retry_ctx_tokens
                    retry_metadata["cumulative_prompt_tokens"] = (
                        int(retry_metadata.get("cumulative_prompt_tokens", 0) or 0)
                        + retry_prompt_tokens
                    )
                    retry_metadata["cumulative_completion_tokens"] = (
                        int(retry_metadata.get("cumulative_completion_tokens", 0) or 0)
                        + retry_completion_tokens
                    )
                    retry_metadata["cumulative_total_tokens"] = int(
                        retry_metadata.get("cumulative_prompt_tokens", 0) or 0
                    ) + int(retry_metadata.get("cumulative_completion_tokens", 0) or 0)
                    logger.info(
                        "[Retry %d] Successfully parsed %s for %s",
                        retry,
                        parse_label,
                        self.name,
                    )
                    return AgentResponse(
                        success=True,
                        data=parsed,
                        metadata=retry_metadata,
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

    def _extract_json_output(
        self,
        content: str,
        result: Dict[str, Any],
        conversation: Iterable[Dict[str, Any]],
        *,
        extractor: JsonExtractor,
        json_output_spec: Optional[JsonOutputSpec],
    ) -> Any:
        if json_output_spec:
            parsed = self._extract_structured_json_payload(
                content,
                result,
                conversation,
                json_output_spec,
            )
            if parsed is not None:
                return parsed
        return extractor(content, result, list(conversation))

    def _extract_structured_json_payload(
        self,
        content: str,
        result: Dict[str, Any],
        conversation: Iterable[Dict[str, Any]],
        json_output_spec: JsonOutputSpec,
    ) -> Any:
        for data in self._final_tool_payloads(result, conversation, json_output_spec):
            parsed = self._coerce_payload_for_spec(data, json_output_spec)
            if parsed is not None:
                return parsed
        for text in self._text_sources(content, result, conversation):
            for data in extract_json_blocks(text):
                parsed = self._coerce_payload_for_spec(data, json_output_spec)
                if parsed is not None:
                    return parsed
        return None

    @staticmethod
    def _coerce_payload_for_spec(data: Any, json_output_spec: JsonOutputSpec) -> Any:
        if json_output_spec.validator(data):
            return data
        if isinstance(data, dict):
            for key in json_output_spec.nested_keys:
                nested = data.get(key)
                if json_output_spec.validator(nested):
                    return nested
        return None

    @classmethod
    def _final_tool_payloads(
        cls,
        result: Dict[str, Any],
        conversation: Iterable[Dict[str, Any]],
        json_output_spec: JsonOutputSpec,
    ) -> Iterable[Dict[str, Any]]:
        messages = []
        if isinstance(result.get("message"), dict):
            messages.append(result["message"])
        messages.extend(list(conversation))
        for message in reversed(messages):
            tool_calls = message.get("tool_calls") if isinstance(message, dict) else None
            if not isinstance(tool_calls, list):
                continue
            for tool_call in tool_calls:
                function = tool_call.get("function") if isinstance(tool_call, dict) else None
                if not isinstance(function, dict):
                    continue
                if function.get("name") != json_output_spec.final_tool_name:
                    continue
                payload = cls._coerce_tool_arguments(function.get("arguments"))
                if payload is not None:
                    yield payload

    @staticmethod
    def _coerce_tool_arguments(arguments: Any) -> Optional[Dict[str, Any]]:
        if isinstance(arguments, dict):
            return arguments
        if not isinstance(arguments, str):
            return None
        try:
            data = json.loads(arguments)
        except Exception:
            return None
        return data if isinstance(data, dict) else None

    def _run_json_structured_finalization(
        self,
        messages: List[Dict[str, Any]],
        result: Dict[str, Any],
        *,
        json_output_spec: JsonOutputSpec,
        extractor: JsonExtractor,
        trace_label: str,
        parse_label: str,
        max_json_retries: int = 1,
        post_process: Optional[PostProcessor] = None,
    ) -> AgentResponse:
        """Finalize a tool conversation through the schema-aware API path."""
        chat_completion = getattr(self.llm_client, "chat_completion", None)
        metadata = self._json_result_metadata(result, json_output_spec)
        if not callable(chat_completion):
            return AgentResponse(
                success=False,
                data={},
                error=f"Failed to finalize {parse_label}: chat completion is unavailable",
                metadata=metadata,
            )

        final_tool_schema = self._final_json_tool_schema(json_output_spec)
        result_conversation = result.get("conversation")
        base_messages = (
            list(result_conversation)
            if isinstance(result_conversation, list) and result_conversation
            else list(messages)
        )
        last_result = result
        last_error = "structured_finalization_failed"
        total_attempts = 1 + max(0, max_json_retries)

        for attempt in range(1, total_attempts + 1):
            if attempt == 1:
                self._increment_metadata_counter(
                    metadata,
                    json_output_spec,
                    "finalization_attempted",
                )
                final_prompt = self._json_finalization_prompt(
                    parse_label,
                    json_output_spec=json_output_spec,
                )
                trace_phase = "json_finalization"
            else:
                self._increment_metadata_counter(
                    metadata,
                    json_output_spec,
                    "repair_attempted",
                )
                final_prompt = self._json_repair_prompt(
                    parse_label,
                    error_type=last_error,
                    result=last_result,
                    json_output_spec=json_output_spec,
                )
                trace_phase = "json_finalization_repair"

            final_messages = [
                *base_messages,
                {"role": "user", "content": final_prompt},
            ]
            response = self._call_json_repair_completion(
                chat_completion,
                final_messages,
                final_tool_schema=final_tool_schema,
                json_output_spec=json_output_spec,
                trace_label=f"{trace_label}; {trace_phase}={attempt}",
                trace_iteration=attempt,
                force_final_tool=True,
            )
            if response is None:
                last_error = "finalization_call_failed"
                continue

            choice = response.get("choices", [{}])[0]
            message = choice.get("message", {})
            self._merge_chat_metadata(
                metadata,
                response,
                final_messages,
                message,
                json_output_spec,
            )
            final_conversation = [*final_messages, message]
            tool_calls = message.get("tool_calls") or []
            if tool_calls:
                self._increment_metadata_counter(
                    metadata,
                    json_output_spec,
                    "final_tool_call_count",
                    len(tool_calls),
                )

            final_result = {
                "content": str(message.get("content") or ""),
                "conversation": final_conversation,
                "message": message,
                "reasoning_content": message.get("reasoning_content"),
                "finish_reason": choice.get("finish_reason"),
                "provider_model": response.get("model")
                or (getattr(self.llm_client, "models", []) or [""])[0],
                "tool_call_count": 0,
                "final_tool_call_count": len(tool_calls),
                "last_assistant_preview": self._message_preview(message),
            }
            parsed = self._extract_json_output(
                str(final_result.get("content") or ""),
                final_result,
                final_conversation,
                extractor=extractor,
                json_output_spec=json_output_spec,
            )
            if parsed is not None:
                if post_process:
                    parsed = post_process(parsed)
                if attempt == 1:
                    self._increment_metadata_counter(
                        metadata,
                        json_output_spec,
                        "finalization_accepted",
                    )
                else:
                    self._increment_metadata_counter(
                        metadata,
                        json_output_spec,
                        "repair_accepted",
                    )
                    if isinstance(parsed, dict):
                        parsed.setdefault(
                            f"{json_output_spec.metadata_prefix}_json_repaired",
                            True,
                        )
                        parsed.setdefault(
                            f"{json_output_spec.metadata_prefix}_repair_error_type",
                            last_error,
                        )
                return AgentResponse(success=True, data=parsed, metadata=metadata)

            last_error, json_blocks_found = self._classify_json_result_failure(
                str(final_result.get("content") or ""),
                final_result,
                final_conversation,
                json_output_spec=json_output_spec,
            )
            self._log_json_result_failure(
                attempt=attempt,
                max_retries=total_attempts,
                error_type=last_error,
                phase="structured_finalize",
                parse_label=parse_label,
                result=final_result,
                content=str(final_result.get("content") or ""),
                json_blocks_found=json_blocks_found,
            )
            last_result = final_result
            base_messages = final_conversation

        if json_output_spec.fallback_empty_payload is not None:
            fallback = dict(json_output_spec.fallback_empty_payload)
            self._increment_metadata_counter(
                metadata,
                json_output_spec,
                "repair_fallback_used",
            )
            fallback.setdefault(
                f"{json_output_spec.metadata_prefix}_repair_error_type",
                last_error,
            )
            return AgentResponse(success=True, data=fallback, metadata=metadata)

        metadata[f"{json_output_spec.metadata_prefix}_last_error_type"] = last_error
        return AgentResponse(
            success=False,
            data={},
            error=f"Failed to finalize {parse_label}: {last_error}",
            metadata=metadata,
        )

    def _run_json_final_repair(
        self,
        messages: List[Dict[str, Any]],
        result: Dict[str, Any],
        *,
        json_output_spec: JsonOutputSpec,
        extractor: JsonExtractor,
        trace_label: str,
        parse_label: str,
        error_type: str,
        max_json_retries: int = 1,
        post_process: Optional[PostProcessor] = None,
    ) -> AgentResponse:
        chat_completion = getattr(self.llm_client, "chat_completion", None)
        metadata = self._json_result_metadata(result, json_output_spec)
        if not callable(chat_completion):
            return AgentResponse(
                success=False,
                data={},
                error=f"Failed to parse {parse_label}: {error_type}",
                metadata=metadata,
            )

        final_tool_schema = self._final_json_tool_schema(json_output_spec)
        last_error = error_type
        result_conversation = result.get("conversation")
        base_messages = (
            list(result_conversation)
            if isinstance(result_conversation, list) and result_conversation
            else list(messages)
        )
        for retry in range(1, max(1, max_json_retries) + 1):
            self._increment_metadata_counter(metadata, json_output_spec, "repair_attempted")
            repair_messages = list(base_messages)
            repair_messages.append(
                {
                    "role": "user",
                    "content": self._json_repair_prompt(
                        parse_label,
                        error_type=last_error,
                        result=result,
                        json_output_spec=json_output_spec,
                    ),
                }
            )
            prompt_messages = list(repair_messages)
            response = self._call_json_repair_completion(
                chat_completion,
                prompt_messages,
                final_tool_schema=final_tool_schema,
                json_output_spec=json_output_spec,
                trace_label=f"{trace_label}; json_repair={retry}; error={last_error}",
                trace_iteration=retry,
                force_final_tool=True,
            )
            if response is None:
                last_error = "repair_call_failed"
                continue

            choice = response.get("choices", [{}])[0]
            message = choice.get("message", {})
            self._merge_chat_metadata(
                metadata, response, prompt_messages, message, json_output_spec
            )
            repair_messages.append(message)
            tool_calls = message.get("tool_calls") or []
            if tool_calls:
                self._increment_metadata_counter(
                    metadata,
                    json_output_spec,
                    "final_tool_call_count",
                    len(tool_calls),
                )

            repair_result = {
                "content": str(message.get("content") or ""),
                "conversation": repair_messages,
                "message": message,
                "reasoning_content": message.get("reasoning_content"),
                "finish_reason": choice.get("finish_reason"),
                "provider_model": response.get("model")
                or (getattr(self.llm_client, "models", []) or [""])[0],
                "tool_call_count": 0,
                "final_tool_call_count": len(tool_calls),
                "last_assistant_preview": self._message_preview(message),
            }
            parsed = self._extract_json_output(
                str(repair_result.get("content") or ""),
                repair_result,
                repair_messages,
                extractor=extractor,
                json_output_spec=json_output_spec,
            )
            if parsed is not None:
                if post_process:
                    parsed = post_process(parsed)
                self._increment_metadata_counter(metadata, json_output_spec, "repair_accepted")
                if isinstance(parsed, dict):
                    parsed.setdefault(f"{json_output_spec.metadata_prefix}_json_repaired", True)
                    parsed.setdefault(
                        f"{json_output_spec.metadata_prefix}_repair_error_type", error_type
                    )
                return AgentResponse(success=True, data=parsed, metadata=metadata)

            last_error, json_blocks_found = self._classify_json_result_failure(
                str(repair_result.get("content") or ""),
                repair_result,
                repair_messages,
                json_output_spec=json_output_spec,
            )
            self._log_json_result_failure(
                attempt=retry,
                max_retries=max_json_retries,
                error_type=last_error,
                phase="repair",
                parse_label=parse_label,
                result=repair_result,
                content=str(repair_result.get("content") or ""),
                json_blocks_found=json_blocks_found,
            )
            base_messages = repair_messages

        if json_output_spec.fallback_empty_payload is not None:
            fallback = dict(json_output_spec.fallback_empty_payload)
            self._increment_metadata_counter(metadata, json_output_spec, "repair_fallback_used")
            fallback.setdefault(f"{json_output_spec.metadata_prefix}_repair_error_type", last_error)
            return AgentResponse(success=True, data=fallback, metadata=metadata)

        metadata[f"{json_output_spec.metadata_prefix}_last_error_type"] = last_error
        return AgentResponse(
            success=False,
            data={},
            error=f"Failed to parse {parse_label}: {last_error}",
            metadata=metadata,
        )

    def _call_json_repair_completion(
        self,
        chat_completion: Callable[..., Dict[str, Any]],
        prompt_messages: List[Dict[str, Any]],
        *,
        final_tool_schema: Dict[str, Any],
        json_output_spec: JsonOutputSpec,
        trace_label: str,
        trace_iteration: int,
        force_final_tool: bool = False,
    ) -> Optional[Dict[str, Any]]:
        response_format = (
            self._json_response_format(json_output_spec)
            if bool(getattr(self.llm_client, "supports_structured_output", False))
            else None
        )
        tools = None if response_format else [final_tool_schema]
        tool_choice: Any = None
        if tools:
            tool_choice = (
                {
                    "type": "function",
                    "function": {"name": json_output_spec.final_tool_name},
                }
                if force_final_tool
                else "auto"
            )
        try:
            return chat_completion(
                prompt_messages,
                tools=tools,
                tool_choice=tool_choice,
                response_format=response_format,
                trace_agent=self.name,
                trace_label=trace_label,
                trace_iteration=trace_iteration,
            )
        except TypeError:
            return chat_completion(
                prompt_messages,
                tools=[final_tool_schema],
                trace_agent=self.name,
                trace_label=trace_label,
                trace_iteration=trace_iteration,
            )
        except Exception as exc:
            if not response_format:
                logger.warning(
                    "JSON repair call failed for %s: %s",
                    json_output_spec.type_name,
                    exc,
                )
                return None
            try:
                return chat_completion(
                    prompt_messages,
                    tools=[final_tool_schema],
                    tool_choice=(
                        {
                            "type": "function",
                            "function": {"name": json_output_spec.final_tool_name},
                        }
                        if force_final_tool
                        else "auto"
                    ),
                    trace_agent=self.name,
                    trace_label=f"{trace_label}; structured_fallback=tool",
                    trace_iteration=trace_iteration,
                )
            except TypeError:
                return chat_completion(
                    prompt_messages,
                    tools=[final_tool_schema],
                    trace_agent=self.name,
                    trace_label=f"{trace_label}; structured_fallback=tool",
                    trace_iteration=trace_iteration,
                )
            except Exception as fallback_exc:
                logger.warning(
                    "JSON repair call failed for %s after structured fallback: %s; fallback_error=%s",
                    json_output_spec.type_name,
                    exc,
                    fallback_exc,
                )
                return None

    @staticmethod
    def _json_repair_prompt(
        parse_label: str,
        *,
        error_type: str,
        result: Dict[str, Any],
        json_output_spec: JsonOutputSpec,
    ) -> str:
        diagnostics = {
            "error_type": error_type,
            "finish_reason": result.get("finish_reason"),
            "truncated": bool(result.get("truncated")),
            "final_tool_call_without_json": bool(result.get("final_tool_call_without_json")),
            "last_assistant_preview": result.get("last_assistant_preview")
            or str(result.get("content") or "")[:500],
        }
        return (
            f"Final JSON repair for {parse_label}. The prior answer did not produce "
            f"a usable {json_output_spec.type_name} payload. Do not ask for tools or "
            "more context. Use the already provided task context and diagnostics below "
            "to produce exactly one final payload.\n\n"
            f"Diagnostics:\n{json.dumps(diagnostics, ensure_ascii=False, indent=2)}\n\n"
            f"Return by calling {json_output_spec.final_tool_name}, or return exactly "
            f"one JSON object with type={json_output_spec.type_name}."
        )

    @staticmethod
    def _json_finalization_prompt(
        parse_label: str,
        *,
        json_output_spec: JsonOutputSpec,
    ) -> str:
        return (
            f"Finalize {parse_label} from the evidence already collected in this "
            "conversation. Do not request more tools or context. Produce exactly one "
            f"{json_output_spec.type_name} payload using "
            f"{json_output_spec.final_tool_name} or the configured structured-output "
            "schema."
        )

    @staticmethod
    def _final_json_tool_schema(json_output_spec: JsonOutputSpec) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": json_output_spec.final_tool_name,
                "description": json_output_spec.final_tool_description,
                "parameters": json_output_spec.schema,
            },
        }

    @staticmethod
    def _json_response_format(json_output_spec: JsonOutputSpec) -> Dict[str, Any]:
        return {
            "type": "json_schema",
            "json_schema": {
                "name": json_output_spec.type_name,
                "strict": False,
                "schema": json_output_spec.schema,
            },
        }

    def _classify_json_result_failure(
        self,
        content: str,
        result: Dict[str, Any],
        conversation: Iterable[Dict[str, Any]],
        *,
        json_output_spec: JsonOutputSpec,
    ) -> Tuple[str, int]:
        json_blocks_found = self._json_candidate_count(
            content,
            result,
            conversation,
            json_output_spec=json_output_spec,
        )
        if json_blocks_found:
            return "schema_mismatch", json_blocks_found
        if result.get("final_tool_call_without_json"):
            return "final_tool_call_without_json", json_blocks_found

        text = "\n".join(self._text_sources(content, result, conversation)).strip()
        if result.get("truncated") or result.get("finish_reason") == "length":
            if "{" in text or "```json" in text.lower():
                return "truncated_json", json_blocks_found
            if not text:
                return "empty_final_content", json_blocks_found
        if not text:
            return "empty_final_content", json_blocks_found
        return "prose_without_json", json_blocks_found

    def _json_candidate_count(
        self,
        content: str,
        result: Dict[str, Any],
        conversation: Iterable[Dict[str, Any]],
        *,
        json_output_spec: JsonOutputSpec,
    ) -> int:
        count = len(list(self._final_tool_payloads(result, conversation, json_output_spec)))
        for text in self._text_sources(content, result, conversation):
            count += len(extract_json_blocks(text))
        return count

    def _log_json_result_failure(
        self,
        *,
        attempt: int,
        max_retries: int,
        error_type: str,
        phase: str,
        parse_label: str,
        result: Dict[str, Any],
        content: str,
        json_blocks_found: int,
    ) -> None:
        logger.warning(
            "%s JSON attempt %d/%d failed for %s: phase=%s error_type=%s "
            "finish_reason=%s truncated=%s content_len=%d tool_call_count=%s "
            "json_blocks_found=%d provider_model=%s",
            self.name,
            attempt,
            max_retries,
            parse_label,
            phase,
            error_type,
            result.get("finish_reason"),
            bool(result.get("truncated")),
            len(content or ""),
            result.get("tool_call_count", 0),
            json_blocks_found,
            result.get("provider_model")
            or (getattr(self.llm_client, "models", []) or ["unknown"])[0],
        )

    @staticmethod
    def _message_preview(message: Dict[str, Any], limit: int = 500) -> str:
        content = str(message.get("content") or "")
        if not content and message.get("reasoning_content"):
            content = str(message.get("reasoning_content") or "")
        if not content and message.get("tool_calls"):
            names = [
                str((tool_call.get("function") or {}).get("name") or "unknown")
                for tool_call in message.get("tool_calls") or []
            ]
            content = "tool_calls=" + ",".join(names)
        return content[:limit]

    @staticmethod
    def _increment_metadata_counter(
        metadata: Dict[str, Any],
        json_output_spec: JsonOutputSpec,
        name: str,
        amount: int = 1,
    ) -> None:
        key = f"{json_output_spec.metadata_prefix}_{name}"
        metadata[key] = int(metadata.get(key, 0) or 0) + amount

    @staticmethod
    def _merge_chat_metadata(
        metadata: Dict[str, Any],
        response: Dict[str, Any],
        messages: List[Dict[str, Any]],
        assistant_message: Dict[str, Any],
        json_output_spec: JsonOutputSpec,
    ) -> None:
        prompt_tokens, completion_tokens = LLMClient._response_token_usage(
            response,
            messages,
            assistant_message,
        )
        metadata["context_tokens"] = int(
            metadata.get("context_tokens", 0) or 0
        ) + LLMClient.estimate_tokens(messages)
        metadata["api_call_count"] = int(metadata.get("api_call_count", 0) or 0) + 1
        metadata["cumulative_prompt_tokens"] = (
            int(metadata.get("cumulative_prompt_tokens", 0) or 0) + prompt_tokens
        )
        metadata["cumulative_completion_tokens"] = (
            int(metadata.get("cumulative_completion_tokens", 0) or 0) + completion_tokens
        )
        metadata["cumulative_total_tokens"] = int(
            metadata.get("cumulative_prompt_tokens", 0) or 0
        ) + int(metadata.get("cumulative_completion_tokens", 0) or 0)
        metadata["iterations"] = int(metadata.get("iterations", 0) or 0) + 1

    @staticmethod
    def _json_result_metadata(
        result: Dict[str, Any],
        json_output_spec: Optional[JsonOutputSpec] = None,
    ) -> Dict[str, Any]:
        metadata = JsonToolAgent._conversation_token_metadata(result)
        for key in (
            "iterations",
            "tool_call_count",
            "api_call_count",
            "terminal_tool_call_count",
            "terminal_invalid_call_count",
        ):
            try:
                metadata[key] = int(result.get(key, 0) or 0)
            except (TypeError, ValueError):
                metadata[key] = 0
        for key in ("terminal_tool_name", "terminal_loop_guard_reason"):
            if key in result:
                metadata[key] = result.get(key)
        for key in ("terminal_tool_valid", "terminal_loop_guard_triggered"):
            if key in result:
                metadata[key] = bool(result.get(key))
        repeated_terminal = result.get("repeated_terminal_tool_call")
        if isinstance(repeated_terminal, dict):
            metadata["repeated_terminal_tool_call"] = repeated_terminal
        if json_output_spec:
            final_tool_count = int(result.get("final_tool_call_count", 0) or 0)
            if final_tool_count:
                JsonToolAgent._increment_metadata_counter(
                    metadata,
                    json_output_spec,
                    "final_tool_call_count",
                    final_tool_count,
                )
        metadata["truncated"] = bool(result.get("truncated", False))
        return metadata

    @staticmethod
    def _extract_last_assistant_text(
        content: str,
        conversation: Iterable[Dict[str, Any]],
    ) -> str:
        if content:
            return content
        for message in reversed(list(conversation)):
            if message.get("role") == "assistant" and message.get("content"):
                return str(message.get("content"))
        return ""

    @staticmethod
    def _conversation_token_metadata(result: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "context_tokens": int(result.get("context_tokens", 0) or 0),
            "cumulative_prompt_tokens": int(result.get("cumulative_prompt_tokens", 0) or 0),
            "cumulative_completion_tokens": int(result.get("cumulative_completion_tokens", 0) or 0),
            "cumulative_total_tokens": int(result.get("cumulative_total_tokens", 0) or 0),
        }
