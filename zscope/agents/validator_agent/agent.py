"""安排一次告警复核，让模型回答，再检查答案能否用于报告。"""

import hashlib
import json
import logging
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..base import JsonOutputSpec, JsonToolAgent
from .investigation import InvestigationSession
from .legacy import LegacyResult
from ...common.cancellation import CancellationError
from ...tools.policy import ToolPolicy
from ...framework.base import AgentResponse, validate_function_arguments
from ...framework.llm_client import LLMClient
from .output import DecisionOutput, current_message, is_incomplete, terminal_payload
from ...common.validator_protocol import (
    VALIDATOR_PASSES,
    VALIDATOR_PROTOCOL_VERSION as VALIDATOR_PROTOCOL_V3,
    ValidatorResultV3,
    bind_validator_decision,
    decode_validator_json,
    validator_decision_schema_v3,
)

logger = logging.getLogger(__name__)
_RESULT_COUNTERS = (
    "context_tokens",
    "cumulative_prompt_tokens",
    "cumulative_completion_tokens",
    "cumulative_total_tokens",
    "iterations",
    "tool_call_count",
    "validator_repair_attempted",
    "validator_repair_accepted",
)


class ValidatorAgent(JsonToolAgent):
    """复核一条可疑告警，给出确认、排除或待查的结论。"""

    @staticmethod
    def _execution_context_metadata() -> Dict[str, Any]:
        """从本次任务取编译设置的编号和检查起点，避免把别处的证据算到这条告警上。"""
        from ...core.validation.execution_context import current_execution_context

        context = current_execution_context()
        entry_name, entry_usr = context.entry_symbol
        return {
            "execution_build_context_id": context.build_context_id,
            "execution_entry_symbol": entry_name,
            "execution_entry_usr": entry_usr,
        }

    def __init__(
        self,
        llm_client: LLMClient,
        tools: List[Any],
        tool_policy: Optional[ToolPolicy] = None,
    ):
        super().__init__(
            name="validator_agent",
            description="Verifies suspect findings and attempts to find exploit paths.",
            llm_client=llm_client,
            tools=tools,
            tool_policy=tool_policy,
        )

    def _new_metadata(self, input_data: Dict[str, Any], **counters: int) -> Dict[str, Any]:
        return {
            **dict.fromkeys(_RESULT_COUNTERS, 0),
            "validator_api_call_count": 0,
            "validator_fast_path_attempted": 0,
            "validator_fast_path_accepted": 0,
            "validator_final_tool_call_count": 0,
            "validator_length_retry_count": 0,
            "validator_session_count": 1,
            "evidence_slice_token_count": int(input_data.get("evidence_slice_token_count") or 0),
            **self._execution_context_metadata(),
            **counters,
        }

    def run(self, input_data: Dict[str, Any], max_retries: int = 2) -> AgentResponse:
        if isinstance(input_data.get("evidence_slice"), dict):
            if input_data["evidence_slice"].get("protocol_version") == VALIDATOR_PROTOCOL_V3:
                response = self._run_validator_v3_protocol(input_data)
            else:
                response = self._run_evidence_slice_protocol(input_data)
        else:
            response = self._run_legacy_protocol(input_data, max_retries)
        self._finalize_slice_metadata(response.metadata)
        return response

    def _run_legacy_protocol(self, input_data: Dict[str, Any], max_retries: int) -> AgentResponse:
        finding = input_data.get("finding")
        evidence_pack = input_data.get("evidence_pack")
        evidence_text = (
            "\n\nCompact Evidence Pack:\n" + json.dumps(evidence_pack, ensure_ascii=False, indent=2)
            if evidence_pack
            else ""
        )
        prompt = (
            f"Suspected Finding:\n{finding}"
            f"{evidence_text}"
            f"\n\nRelevant Code Context:\n{input_data.get('context_code')}"
        )
        last_error = ""
        token_metadata = self._new_metadata(input_data)

        for attempt in range(1, max_retries + 1):
            messages = self._legacy_messages(input_data, prompt)
            if attempt == 1 and evidence_pack:
                fast_data = self._run_fast_path(messages, finding, token_metadata)
                if fast_data:
                    return AgentResponse(
                        success=True, data=fast_data, metadata=dict(token_metadata)
                    )
            if attempt > 1:
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            "The previous response did not contain a valid validation_result JSON "
                            f"(error: {last_error}). Re-output only one JSON block that follows "
                            "the system prompt format. The JSON object itself must be the "
                            "validation_result; do not wrap it in result/data/validation_result."
                        ),
                    }
                )
                logger.info(
                    "Validator retry %d/%d for finding: %s",
                    attempt,
                    max_retries,
                    str(finding)[:80],
                )

            try:
                parsed, last_error = self._legacy_attempt(
                    messages, finding, token_metadata, attempt, max_retries
                )
                if parsed:
                    return AgentResponse(success=True, data=parsed, metadata=dict(token_metadata))
                if last_error == "context_window_exceeded":
                    break
            except CancellationError:
                raise
            except Exception as exc:
                last_error = type(exc).__name__
                logger.warning(
                    "Validator attempt %d/%d exception: %s",
                    attempt,
                    max_retries,
                    last_error,
                )

        return AgentResponse(
            success=False,
            data={},
            error=f"Failed after {max_retries} validation attempt(s): {last_error}",
            metadata=dict(token_metadata, validator_last_error_type=last_error),
        )

    def _legacy_messages(self, input_data: Dict[str, Any], prompt: str) -> List[Dict[str, Any]]:
        return self._messages(input_data, LegacyResult.instructions() + "\n\n" + prompt)

    def _legacy_attempt(
        self,
        messages: List[Dict[str, Any]],
        finding: Any,
        metadata: Dict[str, Any],
        attempt: int,
        max_retries: int,
        *,
        max_iterations: int = 50,
        trace_label: str = "",
    ) -> Tuple[Optional[Dict[str, Any]], str]:
        result = self._run_tool_conversation(
            messages,
            max_iterations=max_iterations,
            trace_label=trace_label or f"attempt={attempt}; finding={str(finding)[:120]}",
        )
        self._merge_result_metadata(metadata, result)
        if result.get("finish_reason") == "context_window_exceeded":
            return None, "context_window_exceeded"
        content, conversation = str(result.get("content") or ""), result.get("conversation", [])
        parsed = self._extract_validation_payload(content, result, conversation)
        if parsed:
            return parsed, ""
        error, count = self._classify_json_result_failure(
            content,
            result,
            conversation,
            json_output_spec=LegacyResult.output_spec(),
        )
        self._log_json_result_failure(
            attempt=attempt,
            max_retries=max_retries,
            error_type=error,
            phase="evidence_gathering",
            parse_label="validation_result",
            result=result,
            content=content,
            json_blocks_found=count,
        )
        return (
            self._run_json_repair(
                messages,
                result,
                error_type=error,
                attempt=attempt,
                finding=finding,
                token_metadata=metadata,
            ),
            error,
        )

    def _run_validator_v3_protocol(self, input_data: Dict[str, Any]) -> AgentResponse:
        """先用现有材料问一次。答案写错格式或被截断时，最多请模型重答一次。"""
        evidence = input_data["evidence_slice"]
        obligation = evidence.get("obligation") or {}
        scope = {
            "candidate_uid": input_data.get("finding_uid") or obligation.get("candidate_uid", ""),
            "validation_cluster_uid": input_data.get("validation_cluster_uid")
            or obligation.get("validation_cluster_uid", ""),
            "expected_pass": input_data.get("validation_pass")
            or evidence.get("validation_pass", "initial"),
            "allowed_evidence_refs": set(evidence.get("evidence_ref_catalog") or {}),
            "allowed_missing_fact_kinds": set(evidence.get("allowed_missing_fact_kinds") or []),
            "subject_uid": input_data.get("candidate_subject_uid")
            or obligation.get("subject_uid")
            or "",
            "function_uid": obligation.get("function_uid") or obligation.get("function") or "",
        }
        if scope["expected_pass"] not in VALIDATOR_PASSES:
            return AgentResponse(success=False, data={}, error="Unsupported validation pass.")
        metadata = self._new_metadata(input_data)
        trace = input_data.get("_initial_trace_identity") or {}
        trace_label = (
            f"validator_v3; pass={scope['expected_pass']}; call_kind={scope['expected_pass']}; "
            f"candidate_uid={str(trace.get('candidate_uid') or scope['candidate_uid'])[:120]}; "
            f"validation_cluster_uid={str(trace.get('validation_cluster_uid') or scope['validation_cluster_uid'])[:120]}; "
            f"new_fact_count={self._v3_evidence_delta_count(evidence.get('evidence_delta'))}"
        )

        def call(repair: str = "") -> Optional[Dict[str, Any]]:
            messages = self._messages(
                input_data,
                self._validator_v3_prompt(
                    evidence,
                    scope["expected_pass"],
                    compact=bool(repair),
                ),
            )
            overrides: Dict[str, Any] = (
                {"max_tokens": self._v3_length_retry_max_tokens(), "thinking": {"type": "disabled"}}
                if repair
                else {}
            )
            metadata["validator_api_call_count"] += 1
            response, result = self._direct_v3_completion(
                messages,
                trace_label=trace_label + (f"; {repair}_retry=1" if repair else ""),
                allowed_missing_fact_kinds=scope["allowed_missing_fact_kinds"],
                allowed_evidence_refs=scope["allowed_evidence_refs"],
                **overrides,
            )
            if response is not None:
                self._merge_v3_response_metadata(metadata, response, messages, result or {})
            return result

        result = call()
        if result is None:
            return AgentResponse(
                success=False,
                data={},
                metadata=metadata,
                error="Validator v3 direct structured completion failed.",
            )
        parsed, audit = self._read_v3_response(result, scope)
        if parsed is None:
            # 让模型重新交一份完整答案。从半句话猜结尾，可能会改变它的原意。
            metadata["validator_first_attempt_audit"] = audit
            repair = "length" if result.get("finish_reason") == "length" else "protocol"
            if repair == "length":
                metadata["validator_length_retry_count"] = 1
                metadata["validator_length_first_attempt_audit"] = audit
            else:
                metadata["validator_repair_attempted"] = 1
            retried = call(repair)
            metadata["validator_repair_thinking_disabled"] = 1
            if retried is not None:
                result = retried
                parsed, audit = self._read_v3_response(result, scope)
                metadata["validator_repair_accepted"] = int(
                    repair == "protocol" and parsed is not None
                )
        metadata["validator_protocol_audit"] = audit
        metadata["finish_reason"] = result.get("finish_reason") or ""
        if parsed is None:
            stop = (
                "output_truncated" if metadata["finish_reason"] == "length" else "malformed_output"
            )
            parsed = self._v3_uncertain_result(
                scope["candidate_uid"],
                scope["validation_cluster_uid"],
                scope["expected_pass"],
                stop_reason=stop,
                reasoning=(
                    "The response was truncated; targeted investigation may recover missing evidence."
                    if stop == "output_truncated"
                    else "The response did not satisfy the decision contract; investigation may recover missing evidence."
                ),
            )
            metadata.update(validator_protocol_exhausted=1, validator_stop_reason=stop.upper())
        else:
            metadata.update(
                validator_protocol=VALIDATOR_PROTOCOL_V3, validator_pass=scope["expected_pass"]
            )
        return AgentResponse(success=True, data=parsed, metadata=metadata)

    @staticmethod
    def _v3_evidence_delta_count(value: Any) -> int:
        if not isinstance(value, dict) or not value:
            return 0
        count = 0
        for key in ("facts", "decision_facts", "proofs", "path_edges", "semantic_claims"):
            items = value.get(key)
            if isinstance(items, (list, dict)):
                count += len(items)
        return count or 1

    @staticmethod
    def _validator_v3_prompt(
        evidence_slice: Dict[str, Any],
        validation_pass: str,
        *,
        compact: bool = False,
    ) -> str:
        return (
            f"Validator {validation_pass}: decide using only this evidence slice; do not browse. "
            "Cite only evidence_ref_catalog keys. Return the decision fields in the supplied schema; "
            "the runtime binds identities, stage and stop status. Request one allowed decisive fact "
            "only when uncertain; otherwise missing_fact_request is null. "
            + (
                "This is the only repair attempt: return a complete object, keep reasoning under "
                "600 characters and do not place XML/DSML markup in fields. "
                if compact
                else ""
            )
            + "\n\nEvidence:\n"
            + json.dumps(evidence_slice, ensure_ascii=False, separators=(",", ":"))
        )

    def _direct_v3_completion(
        self,
        messages: List[Dict[str, Any]],
        *,
        trace_label: str,
        max_tokens: Optional[int] = None,
        thinking: Optional[Dict[str, Any]] = None,
        allowed_missing_fact_kinds: Optional[set[str]] = None,
        allowed_evidence_refs: Optional[set[str]] = None,
    ) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        chat_completion = getattr(self.llm_client, "chat_completion", None)
        direct = callable(chat_completion)
        kwargs: Dict[str, Any] = {"trace_agent": self.name, "trace_label": trace_label}
        if direct:
            kwargs.update(
                self._direct_v3_request_options(
                    allowed_missing_fact_kinds=allowed_missing_fact_kinds,
                    allowed_evidence_refs=allowed_evidence_refs,
                )
            )
            kwargs["trace_iteration"] = 1
            # 第一次提问沿用模型原有的回答长度限制。
            if max_tokens is not None:
                kwargs["max_tokens"] = max_tokens
            if thinking:
                kwargs["thinking"] = dict(thinking)
        else:
            # 旧客户端也只收到提交答案的工具，保证这一步只用题目附带的材料。
            spec = self._validation_json_output_spec_v3(
                allowed_missing_fact_kinds=allowed_missing_fact_kinds,
                allowed_evidence_refs=allowed_evidence_refs,
            )
            kwargs.update(
                messages=messages,
                tools_schema=[self._final_json_tool_schema(spec)],
                max_iterations=1,
                tool_executor=lambda name, args: {
                    "success": False,
                    "error": "Only the terminal result tool is permitted.",
                },
                trace_label=f"{trace_label}; compatibility_adapter=1",
                terminal_tool_name=spec.final_tool_name,
                terminal_tool_required=True,
            )
        response_format = kwargs.get("response_format")
        try:
            response = (
                chat_completion(messages, **kwargs)
                if callable(chat_completion)
                else self.llm_client.run_conversation_with_tools(**kwargs)
            )
        except CancellationError:
            raise
        except Exception as exc:
            # 服务报错就结束这次请求，避免换种方式再发一遍。
            # 日志只记请求设置和错误类别，因为服务返回的原文可能含有敏感信息。
            logger.warning(
                "Validator v3 completion failed: %s | compatibility_adapter=%s "
                "structured_output=%s response_format=%s tool_choice=%s max_tokens=%s",
                type(exc).__name__,
                not direct,
                bool(response_format),
                (response_format.get("type") if isinstance(response_format, dict) else None),
                kwargs.get("tool_choice") or "auto(default)",
                kwargs.get("max_tokens"),
            )
            return None, None
        if not direct:
            legacy_message = current_message(response)
            return {
                "choices": [
                    {"finish_reason": response.get("finish_reason"), "message": legacy_message}
                ],
                "usage": {
                    "prompt_tokens": response.get("cumulative_prompt_tokens", 0),
                    "completion_tokens": response.get("cumulative_completion_tokens", 0),
                },
            }, {**response, "message": legacy_message}
        choices = response.get("choices")
        choice = (
            choices[0]
            if isinstance(choices, list) and choices and isinstance(choices[0], dict)
            else {}
        )
        message = choice.get("message")
        if not isinstance(message, dict):
            message = {"role": "assistant", "content": ""}
        result = {
            "content": str(message.get("content") or ""),
            "message": message,
            "conversation": [*messages, message],
            "reasoning_content": message.get("reasoning_content"),
            "finish_reason": choice.get("finish_reason"),
            "provider_model": response.get("model"),
        }
        return response, result

    def _direct_v3_request_options(
        self,
        *,
        allowed_missing_fact_kinds: Optional[set[str]] = None,
        allowed_evidence_refs: Optional[set[str]] = None,
    ) -> Dict[str, Any]:
        """发出请求和判断旧答案能否沿用，都从这里读取设置，避免两处规则走样。"""
        spec = self._validation_json_output_spec_v3(
            allowed_missing_fact_kinds=allowed_missing_fact_kinds,
            allowed_evidence_refs=allowed_evidence_refs,
        )
        options: Dict[str, Any] = {"temperature": 0.1}
        if bool(getattr(self.llm_client, "supports_structured_output", False)):
            response_format = self._json_response_format(spec)
            response_format["json_schema"]["strict"] = True
            options["response_format"] = response_format
        else:
            options["tools"] = [self._final_json_tool_schema(spec)]
            options["tool_choice"] = "required"
        return options

    def initial_reuse_descriptor(self, input_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """记下这次初审的问题、模型和设置，供下次比较两次提问是否相同。"""
        evidence = input_data.get("evidence_slice")
        if (
            not isinstance(evidence, dict)
            or evidence.get("protocol_version") != VALIDATOR_PROTOCOL_V3
            or str(
                input_data.get("validation_pass") or evidence.get("validation_pass") or "initial"
            )
            != "initial"
            or "_review_session" in input_data
            or not callable(getattr(self.llm_client, "chat_completion", None))
        ):
            return None
        models = list(getattr(self.llm_client, "models", []) or [])
        if not models or not all(isinstance(model, str) and model for model in models):
            return None
        options = self._direct_v3_request_options(
            allowed_missing_fact_kinds=set(evidence.get("allowed_missing_fact_kinds") or []),
            allowed_evidence_refs=set(evidence.get("evidence_ref_catalog") or {}),
        )
        endpoints = getattr(self.llm_client, "base_urls", None) or [
            getattr(self.llm_client, "base_url", "")
        ]
        return {
            "messages": self._messages(input_data, self._validator_v3_prompt(evidence, "initial")),
            "request_options": options,
            "model_contract": {
                "client_type": type(self.llm_client).__module__
                + "."
                + type(self.llm_client).__qualname__,
                "models": models,
                # 只保存由地址算出的识别码，以后仍能比对两次使用的服务地址是否相同。
                "route_digest": hashlib.sha256(json.dumps(endpoints).encode("utf-8")).hexdigest(),
                **{
                    name: getattr(self.llm_client, name, None)
                    for name in (
                        "llm_ref",
                        "max_tokens",
                        "context_window",
                        "model_context_windows",
                        "supports_structured_output",
                        "_portable_tool_schema_only",
                    )
                },
            },
        }

    def _v3_length_retry_max_tokens(self) -> int:
        """回答写到一半就超长时，给重答留出更多篇幅。"""

        try:
            configured = int(getattr(self.llm_client, "max_tokens", None) or 0)
        except (TypeError, ValueError):
            configured = 0
        if configured <= 0:
            # 与模型客户端约定的默认长度一致。
            configured = 8192
        return max(2 * configured, 8192)

    @staticmethod
    def _read_v3_response(
        result: Dict[str, Any], scope: Dict[str, Any]
    ) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
        output = DecisionOutput.from_result(result)
        parsed = bind_validator_decision(output.payload, **scope)
        return (
            parsed.to_dict() if parsed is not None else None,
            output.audit(parsed is not None, result.get("finish_reason") or ""),
        )

    @staticmethod
    def _merge_v3_response_metadata(
        metadata: Dict[str, Any],
        response: Dict[str, Any],
        messages: List[Dict[str, Any]],
        result: Dict[str, Any],
    ) -> None:
        message = result.get("message")
        message = message if isinstance(message, dict) else {}
        prompt_tokens, completion_tokens = LLMClient._response_token_usage(
            response, messages, message
        )
        ValidatorAgent._merge_result_metadata(
            metadata,
            {
                "context_tokens": LLMClient.estimate_tokens(messages),
                "cumulative_prompt_tokens": prompt_tokens,
                "cumulative_completion_tokens": completion_tokens,
                "iterations": 1,
                "api_call_count": 0,  # 请求发出前已计数，失败也算一次。
            },
        )
        metadata["cumulative_total_tokens"] = (
            metadata["cumulative_prompt_tokens"] + metadata["cumulative_completion_tokens"]
        )
        metadata["validator_provider_model"] = str(response.get("model") or "")
        metadata["validator_final_tool_call_count"] += sum(
            isinstance(call, dict)
            and isinstance(call.get("function"), dict)
            and call["function"].get("name") == "emit_validator_result_v3"
            for call in message.get("tool_calls") or []
        )

    @staticmethod
    def _v3_uncertain_result(
        candidate_uid: str,
        cluster_uid: str,
        validation_pass: str,
        *,
        stop_reason: str,
        reasoning: str,
    ) -> Dict[str, Any]:
        return ValidatorResultV3(
            candidate_uid=candidate_uid or "unknown-candidate",
            validation_cluster_uid=cluster_uid or "unknown-cluster",
            validation_pass=validation_pass,
            verdict="uncertain",
            reasoning=reasoning,
            positive_evidence=(),
            negative_evidence=(),
            evidence_refs=(),
            blocking_negative_evidence=False,
            missing_fact_request=None,
            stop_reason=stop_reason,
        ).to_dict()

    @classmethod
    def _validation_json_output_spec_v3(
        cls,
        *,
        allowed_missing_fact_kinds: Optional[set[str]] = None,
        allowed_evidence_refs: Optional[set[str]] = None,
    ) -> JsonOutputSpec:
        schema = validator_decision_schema_v3(
            allowed_missing_fact_kinds=allowed_missing_fact_kinds,
            allowed_evidence_refs=allowed_evidence_refs,
        )
        return JsonOutputSpec(
            type_name="validator_decision_v3",
            schema=schema,
            final_tool_name="emit_validator_result_v3",
            final_tool_description="Emit the decision; the runtime supplies identity and stop metadata.",
            validator=lambda data: validate_function_arguments(schema, data) is None,
            metadata_prefix="validator",
        )

    def investigate(
        self,
        input_data: Dict[str, Any],
        *,
        max_iterations: int = 50,
        pass_kind: str = "investigation_synthesis",
    ) -> AgentResponse:
        """在限定轮数内查代码。若先前排除了一条告警却缺少证明，也可在这里独立复查。"""
        if pass_kind not in VALIDATOR_PASSES:
            return AgentResponse(
                success=False, data={}, error=f"Unsupported validation pass: {pass_kind}"
            )

        evidence_slice = input_data.get("evidence_slice")
        if not isinstance(evidence_slice, dict):
            return AgentResponse(
                success=False, data={}, error="Missing Validator v3 evidence slice."
            )
        iteration_limit = max(1, min(50, int(max_iterations or 50)))
        session = InvestigationSession(
            input_data,
            execute_tool=self._tool_executor,
            tools_schema=self.tools_schema,
            pass_kind=pass_kind,
        )
        aggregate = self._new_metadata(input_data)
        spec = self._validation_json_output_spec_v3(
            allowed_missing_fact_kinds=session.allowed_fact_kinds
        )
        terminal_schema = self._final_json_tool_schema(spec)
        if not session.review_enabled:
            session.terminal_schema = terminal_schema
        if session.review_enabled:
            from ...core.validation.review_protocol import review_result_schema

            review_schema = review_result_schema()
            del review_schema["properties"]["schema_version"]
            review_schema["required"].remove("schema_version")
            review_schema["properties"]["decision"] = spec.schema
            terminal_schema["function"]["parameters"] = review_schema
        messages = self._messages(input_data, session.prompt(iteration_limit))
        try:
            session.replay_queries(messages)
            trace_prefix = (
                "validator_v3_investigation; call_kind=targeted_investigation; "
                if session.pass_kind == "investigation_synthesis"
                else "validator_v2b_adjudication; call_kind=v2b_adjudication; "
            )
            result = self._run_tool_conversation(
                messages,
                max_iterations=iteration_limit,
                trace_label=(
                    trace_prefix
                    + f"candidate_uid={session.candidate_uid[:120]}; "
                    + f"validation_cluster_uid={session.cluster_uid[:120]}"
                ),
                additional_tools_schema=[
                    session.fact_tool_schema,
                    *session.review_schemas,
                    terminal_schema,
                ],
                terminal_tool_name=spec.final_tool_name,
                terminal_tool_handler=session.accept_result,
                terminal_tool_json_decoder=decode_validator_json,
                terminal_tool_required=True,
                tool_executor=session,
                preserve_reasoning_metadata=True,
            )
        except CancellationError:
            raise
        except Exception as exc:
            logger.warning("Validator V3 investigation failed: %s", type(exc).__name__)
            result = {"validator_error_type": type(exc).__name__, "finish_reason": "error"}
            aggregate["validator_error_type"] = type(exc).__name__
        return self._finish_investigation(session, result, aggregate)

    def _finish_investigation(
        self,
        session: InvestigationSession,
        result: Dict[str, Any],
        aggregate: Dict[str, Any],
    ) -> AgentResponse:
        """调查即使停在“待查”，也要留下已经查到的材料和模型用量。"""
        output = session.terminal_output
        if output is None:
            # 有些客户端只返回对话。此时从本轮公开回答取结论，避免误用旧答案或未经检查的结果。
            output = DecisionOutput.from_result(result)
            if output.payload is not None:
                session.accept_result(output)
        parsed = None if is_incomplete(result) else session.accepted_result
        self._merge_result_metadata(aggregate, result)
        aggregate["tool_call_count"] += session.query_reuse["replayed_queries"]
        session.query_reuse["model_tasks"] = int(aggregate["validator_api_call_count"] > 0)
        session.query_reuse["tokens"] = int(aggregate.get("cumulative_total_tokens", 0))
        aggregate["validator_query_reuse"] = session.query_reuse
        aggregate["validator_observed_queries"] = session.observed_queries
        if session.conditions is not None:
            table = session.conditions.snapshot()
            aggregate["validator_condition_table"] = table
            aggregate["validator_condition_plan"] = session.conditions.export(
                session.observed_queries
            )
            session.query_reuse.update(table["metrics"])
        window_exceeded = result.get("finish_reason") == "context_window_exceeded"
        if window_exceeded:
            aggregate["validator_context_window_exceeded"] = True
            aggregate["finish_reason"] = "context_window_exceeded"
        aggregate["validator_investigation_trajectory_count"] = 1
        aggregate["validator_investigation_facts"] = session.investigation_facts
        aggregate["validator_tool_fact_catalog"] = session.tool_fact_catalog
        aggregate["validator_investigation_tool_fact_count"] = len(session.tool_fact_catalog)
        aggregate["new_fact_count"] = len(session.investigation_facts)
        aggregate["consecutive_no_new_evidence_fact_iterations"] = (
            session.consecutive_no_evidence_fact_iterations
        )
        aggregate["validator_no_new_evidence_fact_stop"] = session.no_new_evidence_fact_stop
        if session.review_enabled or session.review_session is not None:
            aggregate["review_tool_results"] = session.review_tool_results
        if session.review_enabled:
            aggregate["review_adjudication"] = session.accepted_review.get("envelope", {})
            aggregate["review_disposition_reason"] = session.accepted_review.get(
                "reason", "invalid_review_envelope"
            )
        self._finalize_slice_metadata(aggregate)
        aggregate["validator_protocol_audit"] = output.audit(
            parsed is not None, result.get("finish_reason") or ""
        )
        if parsed is None:
            parsed = self._v3_uncertain_result(
                session.candidate_uid,
                session.cluster_uid,
                session.pass_kind,
                stop_reason="investigation_exhausted",
                reasoning=(
                    "Required context could not fit the configured model windows; "
                    "investigation evidence was retained without a terminal decision."
                    if window_exceeded
                    else "Targeted investigation ended without a valid terminal decision."
                ),
            )
        return AgentResponse(success=True, data=parsed, metadata=aggregate)

    def _run_evidence_slice_protocol(
        self,
        input_data: Dict[str, Any],
    ) -> AgentResponse:
        """只看已有材料回答，必要时再给一次改正答案格式的机会。"""

        evidence_slice = input_data["evidence_slice"]
        finding_uid = str(input_data.get("finding_uid") or "unknown")
        prompt = (
            "ValidatorEvidenceSlice v2:\n"
            + json.dumps(evidence_slice, ensure_ascii=False, separators=(",", ":"))
            + "\n\nReturn exactly one validation_result JSON object. Do not request "
            "code-browsing tools. If one decisive deterministic fact is absent, "
            "return verdict=uncertain and one missing_fact_request whose fact_kind "
            "is chosen from the slice contract."
        )
        messages = self._legacy_messages(input_data, prompt)
        token_metadata = self._new_metadata(input_data, validator_fast_path_attempted=1)
        try:
            parsed, error = self._legacy_attempt(
                messages,
                {"id": finding_uid},
                token_metadata,
                attempt=1,
                max_retries=1,
                max_iterations=1,
                trace_label=f"evidence_slice_v2; finding={finding_uid[:120]}",
            )
            if parsed:
                token_metadata["validator_fast_path_accepted"] = int(not error)
            else:
                parsed = {
                    "type": "validation_result",
                    "issue_id": finding_uid,
                    "verdict": "uncertain",
                    "finding_kind": "audit_observation",
                    "is_valid": False,
                    "confidence_score": 0.0,
                    "reasoning": (
                        "Validator output did not satisfy the structured v2 contract; "
                        "the candidate remains reviewable and was not discarded."
                    ),
                    "positive_evidence": [],
                    "negative_evidence": [],
                    "blocking_negative_evidence": False,
                    "missing_context": ["validator_protocol_output"],
                    "protocol_exhausted": True,
                }
            return AgentResponse(success=True, data=parsed, metadata=dict(token_metadata))
        except CancellationError:
            raise
        except Exception as exc:
            return AgentResponse(
                success=False,
                data={},
                error=f"Validator v2 completion failed: {type(exc).__name__}",
                metadata=dict(token_metadata, validator_error_type=type(exc).__name__),
            )

    @staticmethod
    def _finalize_slice_metadata(metadata: Dict[str, Any]) -> None:
        turns = int(metadata.get("iterations", 0) or 0)
        metadata["multi_turn_outlier_count"] = int(turns > 2)
        metadata["validator_turn_count"] = turns

    def _run_fast_path(
        self,
        messages: List[Dict[str, Any]],
        finding: Any,
        token_metadata: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """先用手头的材料问一次，省去查询代码的开销。"""
        fast_messages = list(messages)
        fast_messages.append(
            {
                "role": "user",
                "content": (
                    "Fast-path validation: use only the suspected finding and Compact Evidence Pack. "
                    "Do not ask for tools. Return exactly one validation_result JSON block. "
                    "Use `uncertain` if a decisive fact requires code not present in the pack."
                ),
            }
        )
        token_metadata["validator_fast_path_attempted"] += 1
        try:
            result = self._run_tool_conversation(
                fast_messages,
                max_iterations=1,
                trace_label=f"fast_path; finding={str(finding)[:120]}",
            )
        except CancellationError:
            raise
        except Exception as exc:
            logger.debug("Validator fast path failed before fallback: %s", type(exc).__name__)
            return None

        self._merge_result_metadata(token_metadata, result)
        parsed = self._extract_validation_payload(
            str(result.get("content") or ""),
            result,
            result.get("conversation", []),
        )
        if parsed is None:
            return None
        token_metadata["validator_fast_path_accepted"] += 1
        parsed["validator_fast_path"] = True
        return parsed

    def _run_json_repair(
        self,
        messages: List[Dict[str, Any]],
        result: Dict[str, Any],
        *,
        error_type: str,
        attempt: int,
        finding: Any,
        token_metadata: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """给模型最后一次按格式重写答案的机会，只用已有材料。"""
        if result.get("finish_reason") == "context_window_exceeded":
            return None
        repair_seed = dict(result)
        for key in (
            *_RESULT_COUNTERS,
            "final_tool_call_count",
            "api_call_count",
            "terminal_tool_call_count",
            "validator_final_tool_call_count",
        ):
            repair_seed[key] = 0
        response = self._run_json_final_repair(
            messages,
            repair_seed,
            json_output_spec=LegacyResult.output_spec(),
            extractor=self._extract_validation_payload,
            trace_label=f"attempt={attempt}; finding={str(finding)[:120]}",
            parse_label="validation_result JSON",
            error_type=error_type,
            max_json_retries=1,
            post_process=LegacyResult.with_validity,
        )
        self._merge_result_metadata(token_metadata, response.metadata or {})
        if response.success:
            return response.data
        logger.warning(
            "Validator repair failed: issue_id=%s phase=repair error_type=%s error=%s",
            self._issue_id_from_finding(finding),
            error_type,
            response.error,
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
        # 只从本次回答找格式问题，翻看更早的对话可能会误取旧答案。
        payload = terminal_payload(result, json_output_spec.final_tool_name)
        diagnostics = {"error_type": error_type, "finish_reason": result.get("finish_reason")}
        if payload is not None:
            diagnostics["schema_error"] = validate_function_arguments(
                json_output_spec.schema, payload
            )
        if json_output_spec.validation_error:
            diagnostics["validation_error"] = json_output_spec.validation_error()
        return (
            f"Final JSON repair for {parse_label}. Use the supplied task context; do not request more tools. "
            f"Emit exactly one complete {json_output_spec.type_name} using {json_output_spec.final_tool_name}. "
            f"Diagnostics: {json.dumps(diagnostics, ensure_ascii=False)}"
        )

    @staticmethod
    def _merge_result_metadata(target: Dict[str, Any], result: Dict[str, Any]) -> None:
        deltas = {key: result.get(key, 0) for key in _RESULT_COUNTERS}
        deltas["validator_api_call_count"] = result.get(
            "api_call_count", result.get("iterations", 0)
        )
        # 这两个名称统计的是同一批提交答案的操作，只能计一次。
        deltas["validator_final_tool_call_count"] = result.get(
            "validator_final_tool_call_count", result.get("final_tool_call_count", 0)
        )
        for key, value in deltas.items():
            target[key] = int(target.get(key, 0) or 0) + int(value or 0)

    @staticmethod
    def _issue_id_from_finding(finding: Any) -> str:
        if isinstance(finding, str):
            try:
                finding = json.loads(finding)
            except ValueError:
                return "unknown"
        if isinstance(finding, dict):
            return str(finding.get("id") or finding.get("issue_id") or "unknown")
        return "unknown"

    def _extract_validation_payload(
        self,
        content: str,
        result: Dict[str, Any],
        conversation: Iterable[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        payload = terminal_payload(
            {**result, "content": content, "conversation": list(conversation)},
            "emit_validation_result",
        )
        return LegacyResult.parse(payload)

    def _json_candidate_count(
        self,
        content: str,
        result: Dict[str, Any],
        conversation: Iterable[Dict[str, Any]],
        *,
        json_output_spec: Optional[JsonOutputSpec] = None,
    ) -> int:
        spec = json_output_spec or LegacyResult.output_spec()
        payload = terminal_payload(
            {**result, "content": content, "conversation": list(conversation)},
            spec.final_tool_name,
        )
        return int(payload is not None)

    @staticmethod
    def _text_sources(
        content: str, result: Dict[str, Any], conversation: Iterable[Dict[str, Any]]
    ) -> List[str]:
        """查格式问题时只取本轮公开回答，避免带入旧答案或模型的内部推理。"""
        text = current_message(
            {**result, "content": content, "conversation": list(conversation)}
        ).get("content")
        return [text] if isinstance(text, str) and text else []

    def _extract_structured_json_payload(
        self,
        content: str,
        result: Dict[str, Any],
        conversation: Iterable[Dict[str, Any]],
        json_output_spec: JsonOutputSpec,
    ) -> Any:
        payload = terminal_payload(
            {**result, "content": content, "conversation": list(conversation)},
            json_output_spec.final_tool_name,
        )
        return self._coerce_payload_for_spec(payload, json_output_spec)
