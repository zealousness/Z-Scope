import hashlib
import json
import logging
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from ..base import JsonOutputSpec, JsonToolAgent
from ...tools.policy import ToolPolicy
from ...framework.base import AgentResponse
from ...framework.llm_client import LLMClient
from ...common.utils import extract_json_blocks
from ...common.validator_protocol import (
    VALIDATOR_PASSES,
    VALIDATOR_PROTOCOL_VERSION as VALIDATOR_PROTOCOL_V3,
    VALIDATOR_RESULT_VERSION,
    ValidatorResultV3,
    parse_validator_result_v3,
    validator_result_schema_v3,
)

logger = logging.getLogger(__name__)

_NON_EVIDENCE_TOOL_RESULT_KEYS = frozenset(
    {
        "args",
        "arguments",
        "duration",
        "duration_ms",
        "elapsed",
        "elapsed_ms",
        "error",
        "message",
        "metadata",
        "query",
        "request",
        "success",
        "timestamp",
        "tool",
        "tool_name",
        "trace",
    }
)


def _tool_result_evidence_atoms(value: Any, path: Tuple[str, ...] = ()) -> set[str]:
    """Return stable evidence leaves while ignoring request echoes/telemetry.

    V3 may stop after two completed model rounds contribute neither new tool
    evidence nor an obligation-closing fact.  Comparing whole response hashes
    is insufficient because a provider may echo a new query or timestamp
    around the same empty payload.  Atomic evidence leaves make that progress
    check semantic enough to catch empty and rewrapped duplicate results
    without interpreting the evidence itself.
    """

    atoms: set[str] = set()
    if isinstance(value, Mapping):
        if value.get("success") is False:
            return atoms
        for raw_key, nested in value.items():
            key = str(raw_key).strip().lower().replace("-", "_")
            if key in _NON_EVIDENCE_TOOL_RESULT_KEYS:
                continue
            atoms.update(_tool_result_evidence_atoms(nested, (*path, key)))
        return atoms
    if isinstance(value, (list, tuple, set, frozenset)):
        for nested in value:
            atoms.update(_tool_result_evidence_atoms(nested, path))
        return atoms
    if isinstance(value, str):
        text = " ".join(value.strip().split())
        if not text or text.lower() in {"none", "null", "not found", "no results", "unknown"}:
            return atoms
        payload = "/".join(path) + "=" + text
        atoms.add(hashlib.sha256(payload.encode("utf-8")).hexdigest())
        return atoms
    if isinstance(value, bool) or value is None:
        return atoms
    if isinstance(value, (int, float)) and value != 0:
        leaf = path[-1] if path else ""
        if leaf in {"line", "column", "start_line", "end_line", "address", "offset"}:
            payload = "/".join(path) + "=" + str(value)
            atoms.add(hashlib.sha256(payload.encode("utf-8")).hexdigest())
    return atoms


class ValidatorAgent(JsonToolAgent):
    """Agent for verifying and triaging findings."""

    @staticmethod
    def _execution_context_metadata() -> Dict[str, Any]:
        """The precise build/entry scope this agent run executes under.

        Captured from the live scope bindings at run time — never from the
        candidate's self-reported data — so every validator decision's
        metadata carries the exact compilation instance and the analyzed
        function's native identity for audit and downstream verification.
        """

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

    def run(self, input_data: Dict[str, Any], max_retries: int = 2) -> AgentResponse:
        if isinstance(input_data.get("evidence_slice"), dict):
            if input_data["evidence_slice"].get("protocol_version") == VALIDATOR_PROTOCOL_V3:
                return self._run_validator_v3_protocol(input_data)
            return self._run_evidence_slice_protocol(input_data)

        finding = input_data.get("finding")
        context_code = input_data.get("context_code")
        evidence_pack = input_data.get("evidence_pack")
        evidence_text = ""
        if evidence_pack:
            evidence_text = "\n\nCompact Evidence Pack:\n" + json.dumps(
                evidence_pack, ensure_ascii=False, indent=2
            )
        prompt = (
            f"Suspected Finding:\n{finding}"
            f"{evidence_text}"
            f"\n\nRelevant Code Context:\n{context_code}"
        )
        last_error = ""
        token_metadata = {
            "context_tokens": 0,
            "cumulative_prompt_tokens": 0,
            "cumulative_completion_tokens": 0,
            "cumulative_total_tokens": 0,
            "iterations": 0,
            "tool_call_count": 0,
            "validator_fast_path_attempted": 0,
            "validator_fast_path_accepted": 0,
            "validator_repair_attempted": 0,
            "validator_repair_accepted": 0,
            "validator_final_tool_call_count": 0,
            **self._execution_context_metadata(),
        }

        for attempt in range(1, max_retries + 1):
            messages = self._messages(input_data, prompt)
            if attempt == 1 and evidence_pack:
                fast_data = self._run_fast_path(messages, finding, token_metadata)
                if fast_data:
                    return AgentResponse(
                        success=True,
                        data=fast_data,
                        metadata=dict(token_metadata),
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
                result = self._run_tool_conversation(
                    messages,
                    trace_label=f"attempt={attempt}; finding={str(finding)[:120]}",
                )
                self._merge_result_metadata(token_metadata, result)
                parsed = self._extract_validation_payload(
                    str(result.get("content") or ""),
                    result,
                    result.get("conversation", []),
                )
                if parsed:
                    return AgentResponse(
                        success=True,
                        data=parsed,
                        metadata=dict(token_metadata),
                    )

                last_error, json_blocks_found = self._classify_invalid_result(
                    str(result.get("content") or ""),
                    result,
                    result.get("conversation", []),
                )
                self._log_invalid_result(
                    attempt,
                    max_retries,
                    last_error,
                    phase="evidence_gathering",
                    finding=finding,
                    result=result,
                    content=str(result.get("content") or ""),
                    json_blocks_found=json_blocks_found,
                )
                repaired = self._run_json_repair(
                    messages,
                    result,
                    error_type=last_error,
                    attempt=attempt,
                    finding=finding,
                    token_metadata=token_metadata,
                )
                if repaired:
                    return AgentResponse(
                        success=True,
                        data=repaired,
                        metadata=dict(token_metadata),
                    )
            except Exception as exc:
                last_error = str(exc)
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

    def _run_validator_v3_protocol(self, input_data: Dict[str, Any]) -> AgentResponse:
        """Run V1/V2 as one direct, strict structured completion.

        This path deliberately bypasses ``run_conversation_with_tools``.  The
        single-turn protocol must not inherit the generic loop's final-turn
        injection, history continuation, or open-ended tool behavior.
        """

        evidence_slice = input_data["evidence_slice"]
        obligation = evidence_slice.get("obligation")
        obligation = obligation if isinstance(obligation, dict) else {}
        candidate_uid = str(input_data.get("finding_uid") or obligation.get("candidate_uid") or "")
        cluster_uid = str(
            input_data.get("validation_cluster_uid")
            or obligation.get("validation_cluster_uid")
            or ""
        )
        expected_pass = str(
            input_data.get("validation_pass") or evidence_slice.get("validation_pass") or "initial"
        )
        catalog = evidence_slice.get("evidence_ref_catalog")
        allowed_refs = list(catalog) if isinstance(catalog, dict) else []
        token_metadata: Dict[str, Any] = {
            "context_tokens": 0,
            "cumulative_prompt_tokens": 0,
            "cumulative_completion_tokens": 0,
            "cumulative_total_tokens": 0,
            "iterations": 0,
            "tool_call_count": 0,
            "validator_session_count": 1,
            "validator_api_call_count": 0,
            "validator_turn_count": 0,
            "validator_repair_attempted": 0,
            "validator_repair_accepted": 0,
            "validator_length_retry_count": 0,
            "evidence_slice_token_count": int(input_data.get("evidence_slice_token_count") or 0),
            **self._execution_context_metadata(),
        }
        prompt = self._validator_v3_prompt(evidence_slice, expected_pass)
        messages = self._messages(input_data, prompt)
        evidence_delta = evidence_slice.get("evidence_delta")
        new_fact_count = self._v3_evidence_delta_count(evidence_delta)

        response, result = self._direct_v3_completion(
            messages,
            trace_label=(
                f"validator_v3; pass={expected_pass}; call_kind={expected_pass}; "
                f"candidate_uid={candidate_uid[:120]}; "
                f"validation_cluster_uid={cluster_uid[:120]}; "
                f"new_fact_count={new_fact_count}"
            ),
        )
        if response is None or result is None:
            self._finalize_slice_metadata(token_metadata)
            return AgentResponse(
                success=False,
                data={},
                error="Validator v3 direct structured completion failed.",
                metadata=token_metadata,
            )
        self._merge_v3_response_metadata(token_metadata, response, messages, result)

        if str(result.get("finish_reason") or "") == "length":
            # The provider output limit truncated the structured result before
            # the strict schema could complete.  Retry once with a doubled
            # ceiling so a long-but-valid verdict is not systematically
            # degraded to uncertain/output_truncated.
            retry_cap = self._v3_length_retry_max_tokens()
            token_metadata["validator_length_retry_count"] = 1
            logger.info(
                "Validator v3 output truncated by provider limit; retrying once "
                "with max_tokens=%d (candidate_uid=%s, pass=%s)",
                retry_cap,
                candidate_uid[:120],
                expected_pass,
            )
            retry_response, retry_result = self._direct_v3_completion(
                messages,
                trace_label=(
                    f"validator_v3; pass={expected_pass}; call_kind={expected_pass}; "
                    f"candidate_uid={candidate_uid[:120]}; "
                    f"validation_cluster_uid={cluster_uid[:120]}; "
                    f"new_fact_count={new_fact_count}; length_retry=1"
                ),
                max_tokens=retry_cap,
            )
            if retry_response is not None and retry_result is not None:
                self._merge_v3_response_metadata(
                    token_metadata, retry_response, messages, retry_result
                )
                response, result = retry_response, retry_result
        parsed = self._extract_v3_result(
            result,
            candidate_uid=candidate_uid,
            cluster_uid=cluster_uid,
            expected_pass=expected_pass,
            allowed_refs=allowed_refs,
        )
        finish_reason = str(result.get("finish_reason") or "")
        if parsed is not None:
            self._finalize_slice_metadata(token_metadata)
            token_metadata["validator_protocol"] = VALIDATOR_PROTOCOL_V3
            token_metadata["validator_pass"] = expected_pass
            token_metadata["finish_reason"] = finish_reason
            return AgentResponse(success=True, data=parsed, metadata=token_metadata)

        stop_reason = "output_truncated" if finish_reason == "length" else "malformed_output"
        fallback = self._v3_uncertain_result(
            candidate_uid,
            cluster_uid,
            expected_pass,
            stop_reason=stop_reason,
            reasoning=(
                "The single Validator pass reached the provider output limit; targeted "
                "investigation may recover from structured evidence."
                if stop_reason == "output_truncated"
                else "The single Validator pass did not satisfy the strict v3 schema; "
                "targeted investigation may recover from structured evidence."
            ),
        )
        token_metadata["validator_protocol_exhausted"] = 1
        token_metadata["validator_stop_reason"] = stop_reason.upper()
        token_metadata["finish_reason"] = finish_reason
        self._finalize_slice_metadata(token_metadata)
        return AgentResponse(success=True, data=fallback, metadata=token_metadata)

    @staticmethod
    def _v3_evidence_delta_count(value: Any) -> int:
        if not isinstance(value, dict) or not value:
            return 0
        count = 0
        for key in ("facts", "decision_facts", "proofs", "path_edges", "semantic_claims"):
            items = value.get(key)
            if isinstance(items, list):
                count += len(items)
            elif isinstance(items, dict):
                count += len(items)
        return count or 1

    @staticmethod
    def _validator_v3_prompt(
        evidence_slice: Dict[str, Any],
        validation_pass: str,
        *,
        compact: bool = False,
    ) -> str:
        directive = (
            "Return the smallest valid object; keep reasoning under 600 characters. "
            if compact
            else ""
        )
        return (
            f"Validator v3 pass={validation_pass}. Use only the supplied evidence. "
            "Every evidence_refs value must be a key in evidence_ref_catalog. Return "
            "uncertain with at most one missing_fact_request when one supported fact "
            "would decide the obligation. Do not invent a fact, candidate, or cluster UID. "
            f"{directive}Return exactly one object matching schema_version="
            f"{VALIDATOR_RESULT_VERSION}.\n\n"
            + json.dumps(evidence_slice, ensure_ascii=False, separators=(",", ":"))
        )

    def _direct_v3_completion(
        self,
        messages: List[Dict[str, Any]],
        *,
        trace_label: str,
        max_tokens: Optional[int] = None,
    ) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        chat_completion = getattr(self.llm_client, "chat_completion", None)
        if not callable(chat_completion):
            # Compatibility for test/third-party clients that predate the
            # direct API. Product LLMClient always takes the branch above.
            try:
                legacy = self._run_tool_conversation(
                    messages,
                    max_iterations=1,
                    trace_label=f"{trace_label}; compatibility_adapter=1",
                    additional_tools_schema=[
                        self._final_json_tool_schema(self._validation_json_output_spec_v3())
                    ],
                    terminal_tool_name="emit_validator_result_v3",
                    terminal_tool_required=True,
                )
            except Exception:
                return None, None
            synthetic_message = legacy.get("message") or {
                "role": "assistant",
                "content": legacy.get("content", ""),
            }
            synthetic = {
                "choices": [
                    {
                        "finish_reason": legacy.get("finish_reason"),
                        "message": synthetic_message,
                    }
                ],
                "usage": {
                    "prompt_tokens": legacy.get("cumulative_prompt_tokens", 0),
                    "completion_tokens": legacy.get("cumulative_completion_tokens", 0),
                },
            }
            return synthetic, {
                **legacy,
                "message": synthetic_message,
            }

        spec = self._validation_json_output_spec_v3()
        response_format = (
            self._json_response_format(spec)
            if bool(getattr(self.llm_client, "supports_structured_output", False))
            else None
        )
        if response_format:
            response_format["json_schema"]["strict"] = True
        tool = self._final_json_tool_schema(spec)
        # Pure config semantics: like every other stage, the request carries no
        # explicit max_tokens unless a caller overrides it, so the configured
        # llm.max_tokens request ceiling applies unchanged.
        kwargs: Dict[str, Any] = {
            "trace_agent": self.name,
            "trace_label": trace_label,
            "trace_iteration": 1,
        }
        if max_tokens is not None:
            kwargs["max_tokens"] = max_tokens
        if response_format:
            kwargs["response_format"] = response_format
        else:
            kwargs["tools"] = [tool]
            # Strict OpenAI-compatible gateways (e.g. InferHub serving GLM)
            # reject the named-function tool_choice object with HTTP 400 and
            # only accept "auto" / "none" / "required".  This request carries
            # exactly one tool, so "required" forces the same terminal call.
            kwargs["tool_choice"] = "required"
        try:
            response = chat_completion(messages, **kwargs)
        except Exception as exc:
            # Provider capability selection is fixed before the call.  A
            # profile that declares native JSON-schema support must not turn a
            # failed V1/V2 attempt into an unplanned second HTTP attempt.  A
            # provider without that capability already takes the one-terminal-
            # tool branch above.  The failing wire mode (structured output vs.
            # named terminal tool) is logged so provider 400s can be attributed
            # to the exact request variant; LLM-4xx-DIAG carries the payload.
            logger.warning(
                "Validator v3 direct completion failed: %s | "
                "structured_output=%s response_format=%s tool_choice=%s max_tokens=%s",
                exc,
                bool(response_format),
                (response_format.get("type") if isinstance(response_format, dict) else None),
                (
                    tool_choice
                    if (tool_choice := kwargs.get("tool_choice")) is not None
                    else "auto(default)"
                ),
                kwargs.get("max_tokens"),
            )
            return None, None
        choices = response.get("choices") or []
        if not choices or not isinstance(choices[0], dict):
            return response, None
        choice = choices[0]
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

    def _v3_length_retry_max_tokens(self) -> int:
        """Doubled output ceiling for the single v3 length-truncation retry."""

        configured = getattr(self.llm_client, "max_tokens", None)
        try:
            configured = int(configured or 0)
        except (TypeError, ValueError):
            configured = 0
        if configured <= 0:
            # Mirrors the LLMClient/LLMConfig default output ceiling.
            configured = 4096
        return max(2 * configured, 8192)

    def _extract_v3_result(
        self,
        result: Dict[str, Any],
        *,
        candidate_uid: str,
        cluster_uid: str,
        expected_pass: str,
        allowed_refs: List[str],
    ) -> Optional[Dict[str, Any]]:
        spec = self._validation_json_output_spec_v3()
        values: List[Any] = list(
            self._final_tool_payloads(result, result.get("conversation", []), spec)
        )
        # Provider reasoning metadata is deliberately excluded from the
        # terminal protocol.  It may be preserved in-memory between bounded
        # V3 turns, but only public assistant content or the required terminal
        # tool may become a ValidatorResult.
        text_sources = [str(result.get("content") or "")]
        for message in reversed(list(result.get("conversation", []))):
            if isinstance(message, dict) and message.get("role") == "assistant":
                text_sources.append(str(message.get("content") or ""))
        for text in (value for value in text_sources if value):
            values.extend(extract_json_blocks(text))
        for value in values:
            parsed = parse_validator_result_v3(
                value,
                candidate_uid=candidate_uid,
                validation_cluster_uid=cluster_uid,
                expected_pass=expected_pass,
                allowed_evidence_refs=allowed_refs,
            )
            if parsed is not None:
                return parsed.to_dict()
        return None

    @staticmethod
    def _merge_v3_response_metadata(
        metadata: Dict[str, Any],
        response: Dict[str, Any],
        messages: List[Dict[str, Any]],
        result: Dict[str, Any],
    ) -> None:
        message = result.get("message")
        message = message if isinstance(message, dict) else {}
        ValidatorAgent._merge_chat_response_metadata(metadata, response, messages, message)
        metadata["validator_api_call_count"] = (
            int(metadata.get("validator_api_call_count", 0) or 0) + 1
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
    def _validation_json_output_spec_v3(cls) -> JsonOutputSpec:
        return JsonOutputSpec(
            type_name="validator_result_v3",
            schema=validator_result_schema_v3(),
            final_tool_name="emit_validator_result_v3",
            final_tool_description="Emit the strict Z-Scope ValidatorResult v3 object.",
            validator=lambda data: parse_validator_result_v3(data) is not None,
            metadata_prefix="validator",
        )

    def investigate(
        self,
        input_data: Dict[str, Any],
        *,
        max_iterations: int = 50,
        pass_kind: str = "investigation_synthesis",
    ) -> AgentResponse:
        """Run one continuous, tool-backed V3 investigation session.

        ``pass_kind="v2b_adjudication"`` selects the R3 adjudication variant:
        an adversarial audit of a prior rejection that would otherwise park as
        model_rejected_unproven (plan M5 R3 rung).
        """
        if pass_kind not in VALIDATOR_PASSES:
            return AgentResponse(
                success=False, data={}, error=f"Unsupported validation pass: {pass_kind}"
            )

        evidence_slice = input_data.get("evidence_slice")
        if not isinstance(evidence_slice, dict):
            return AgentResponse(
                success=False, data={}, error="Missing Validator v3 evidence slice."
            )
        obligation = evidence_slice.get("obligation")
        obligation = obligation if isinstance(obligation, dict) else {}
        candidate_uid = str(input_data.get("finding_uid") or obligation.get("candidate_uid") or "")
        cluster_uid = str(
            input_data.get("validation_cluster_uid")
            or obligation.get("validation_cluster_uid")
            or ""
        )
        catalog = evidence_slice.get("evidence_ref_catalog")
        allowed_refs = set(catalog) if isinstance(catalog, dict) else set()
        decision_facts = evidence_slice.get("decision_facts")
        decision_facts = decision_facts if isinstance(decision_facts, dict) else {}
        raw_missing = decision_facts.get("missing_fact_kinds")
        allowed_fact_kinds = {
            str(value).strip().lower()
            for value in (raw_missing if isinstance(raw_missing, list) else [])
            if str(value).strip()
        }
        if not allowed_fact_kinds:
            allowed_fact_kinds = {
                "guard_dominance",
                "caller_contract",
                "source_controllability",
                "ownership_transfer",
                "cleanup_coverage",
                "lockset",
                "happens_before",
                "object_identity",
                "value_range",
                "source_sink_reachability",
                "signal_context",
                "container_reachability",
                "type_layout",
            }
        iteration_limit = max(1, min(50, int(max_iterations or 50)))
        aggregate: Dict[str, Any] = {
            "context_tokens": 0,
            "cumulative_prompt_tokens": 0,
            "cumulative_completion_tokens": 0,
            "cumulative_total_tokens": 0,
            "iterations": 0,
            "tool_call_count": 0,
            "validator_session_count": 1,
            "validator_api_call_count": 0,
            "validator_turn_count": 0,
            "validator_investigation_trajectory_count": 0,
        }
        spec = self._validation_json_output_spec_v3()
        terminal_schema = self._final_json_tool_schema(spec)
        review_enabled = input_data.get("review_protocol_enabled") is True
        review_session = input_data.get("_review_session")
        review_schemas = review_session.schemas() if review_session is not None else []
        review_tools = {value["function"]["name"] for value in review_schemas}
        accepted_review: Dict[str, Any] = {}
        if review_enabled:
            from ...core.validation.review_protocol import review_result_schema

            terminal_schema["function"]["parameters"] = review_result_schema()
        fact_tool_name = "record_validator_investigation_fact"
        fact_tool_schema = {
            "type": "function",
            "function": {
                "name": fact_tool_name,
                "description": (
                    "Record one evidence-backed fact resolved by prior read-only tool results. "
                    "This only updates the current Validator session."
                ),
                "parameters": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "fact_kind": {
                            "type": "string",
                            "enum": sorted(allowed_fact_kinds),
                        },
                        "evidence_refs": {
                            "type": "array",
                            "minItems": 1,
                            "maxItems": 8,
                            "items": {"type": "string"},
                        },
                        "summary": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 1000,
                            "description": (
                                "Evidence-backed fact summary written in Simplified Chinese."
                            ),
                        },
                    },
                    "required": ["fact_kind", "evidence_refs", "summary"],
                },
            },
        }
        if pass_kind == "v2b_adjudication":
            session_directive = (
                "Validator V2b adjudication (R3 rung). A prior validator pass REJECTED this "
                "candidate without deterministic proof; your job is to adversarially audit "
                "that rejection. Actively hunt counter-evidence with the read-only repository "
                "tools: missed cleanup or release paths, guard dominance, ownership transfer, "
                "reachability or lock-coverage constraints, and any fact that makes the "
                "rejection wrong. Overturn (verdict=verified) only with concrete, tool-backed "
                "confirmation-grade evidence. Uphold (verdict=rejected) only when you can cite "
                "blocking negative evidence; otherwise verdict=uncertain. There is no "
                "independent tool-query quota, but the entire session has at most "
                f"{iteration_limit} model iterations. Every useful repository result returns a "
                "TOOLFACT evidence_ref; resolved facts must be recorded via "
                f"{fact_tool_name} with that TOOLFACT ref before the final decision, and the "
                "final evidence_refs must cite recorded FACT refs or supplied catalog refs. "
                "Finish with one strict v2b_adjudication result. The end user reads reports "
                "in Chinese: write every free-text field (reasoning, evidence items, fact "
                "summaries, missing-fact reasons) in Simplified Chinese while keeping file "
                "paths, symbols, and evidence ref UIDs unchanged.\n\n"
            )
        else:
            session_directive = (
                "Targeted Validator V3 investigation. Use only the supplied read-only repository "
                "tools. There is no independent tool-query quota, but the entire session has at "
                f"most {iteration_limit} model iterations. Every useful repository result returns "
                "a TOOLFACT evidence_ref (raw evidence progress, not an obligation-closing fact). "
                "When it resolves a required fact, call "
                f"{fact_tool_name} with that TOOLFACT ref before the final decision. The final "
                "evidence_refs must cite recorded FACT_V3 refs or supplied catalog refs. A rejected "
                "verdict requires blocking evidence; missing context is uncertain. Finish with one "
                "strict investigation_synthesis result. The end user reads reports in Chinese: "
                "write every free-text field (reasoning, evidence items, fact summaries, "
                "missing-fact reasons) in Simplified Chinese while keeping file paths, symbols, "
                "and evidence ref UIDs unchanged.\n\n"
            )
        if review_enabled:
            session_directive += (
                "The final tool now requires a versioned review envelope containing decision, prior_rejection, and defect_case. "
                "Audit facts AND inference/scope separately. Refuting a rejection never proves a defect. "
                "A supported defect_case must identify the actual subject, source, sink, feasible path, trigger, and guard analysis, "
                "cite recorded tool evidence, and have no missing conditions. Otherwise keep uncertain. "
                "Only check_validation_claim can issue a program counterproof; summaries and complete=true are not proof authority. "
                "Current-build facts do not confirm a different macro configuration. Query further only for a specific missing fact or conflict.\n\n"
            )
        if input_data.get("review_positive_case") is True:
            session_directive += (
                "Positive-case experiment: prioritize the uncertain candidate's missing conditions. Construct one concrete defect witness "
                "and test each condition against tools; preserve uncertain when the witness does not close. Do not lower confidence thresholds.\n\n"
            )
        prompt = session_directive + json.dumps(
            evidence_slice, ensure_ascii=False, separators=(",", ":")
        )
        messages = self._messages(input_data, prompt)
        tool_result_hashes: set[str] = set()
        tool_call_signatures: set[str] = set()
        evidence_atoms: set[str] = set()
        tool_fact_catalog: Dict[str, Dict[str, Any]] = {}
        review_tool_results: List[Dict[str, Any]] = []
        investigation_facts: List[Dict[str, Any]] = []
        consecutive_no_evidence_fact_iterations = 0
        current_model_iteration = 0
        last_started_iteration = 0
        evidence_facts_at_iteration_start = 0
        no_new_evidence_fact_stop = False

        def evidence_location(args: Any, result: Dict[str, Any]) -> Dict[str, Any]:
            arguments = args if isinstance(args, dict) else {}
            data = result.get("data") if isinstance(result, dict) else None
            data = data if isinstance(data, dict) else {}
            return {
                "file": str(arguments.get("file_path") or data.get("file_path") or ""),
                "function": str(arguments.get("func_name") or data.get("function") or ""),
                "start_line": arguments.get("start_line") or data.get("start_line"),
                "end_line": arguments.get("end_line") or data.get("end_line"),
            }

        def session_executor(name: str, args: Any) -> Dict[str, Any]:
            nonlocal no_new_evidence_fact_stop
            if name == fact_tool_name:
                if not isinstance(args, dict):
                    return {"success": False, "error": "fact arguments must be an object"}
                fact_kind = str(args.get("fact_kind") or "").strip().lower()
                refs = args.get("evidence_refs")
                refs = [str(value) for value in refs] if isinstance(refs, list) else []
                if fact_kind not in allowed_fact_kinds:
                    return {"success": False, "error": "unsupported investigation fact kind"}
                if not refs or any(ref not in tool_fact_catalog for ref in refs):
                    return {
                        "success": False,
                        "error": "investigation facts must cite prior TOOLFACT refs",
                    }
                summary = str(args.get("summary") or "").strip()
                if not summary or len(summary) > 1000:
                    return {"success": False, "error": "fact summary is invalid"}
                backing = [tool_fact_catalog[ref] for ref in refs]
                payload = {
                    "cluster": cluster_uid,
                    "fact_kind": fact_kind,
                    "evidence_refs": sorted(refs),
                    "summary": summary,
                    "dependency_hashes": sorted(
                        {str(value.get("dependency_code_hash") or "") for value in backing}
                    ),
                }
                fact_uid = (
                    "FACT_V3_"
                    + hashlib.sha256(
                        json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
                    ).hexdigest()[:32]
                )
                fact = {
                    "fact_uid": fact_uid,
                    "fact_kind": fact_kind,
                    "summary": summary,
                    "evidence_refs": sorted(refs),
                    "producer_engine": "validator_readonly_tool_session",
                    "dependency_code_hash": hashlib.sha256(
                        "\n".join(payload["dependency_hashes"]).encode("utf-8")
                    ).hexdigest(),
                    "locations": [value.get("location") for value in backing],
                    "origin": "validator_tool_evidence",
                }
                if not any(value.get("fact_uid") == fact_uid for value in investigation_facts):
                    investigation_facts.append(fact)
                allowed_refs.add(fact_uid)
                if review_session is not None:
                    review_session.record_result(name, args, {"success": True, "fact": fact})
                return {"success": True, "fact": fact}

            stable_args = json.dumps(args, ensure_ascii=False, sort_keys=True, default=str)
            signature = hashlib.sha256(f"{name}:{stable_args}".encode("utf-8")).hexdigest()
            if signature in tool_call_signatures:
                return {
                    "success": False,
                    "error": "validator_v3_duplicate_tool_query",
                }
            tool_call_signatures.add(signature)
            if no_new_evidence_fact_stop:
                return {
                    "success": False,
                    "error": "validator_v3_no_new_evidence_fact_stop; emit the final result",
                }
            if name == "propose_related_candidate":
                refs = args.get("evidence_refs", []) if isinstance(args, dict) else []
                if not refs or any(
                    ref not in tool_fact_catalog
                    and ref not in {f["fact_uid"] for f in investigation_facts}
                    for ref in refs
                ):
                    return {
                        "success": False,
                        "error": "related proposal requires recorded tool evidence",
                    }
            tool_result = (
                review_session.execute(name, args)
                if review_session is not None and name in review_tools
                else self._tool_executor(name, args)
            )
            if review_enabled or review_session is not None:
                review_tool_results.append({"name": name, "arguments": args, "result": tool_result})
            stable_result = json.dumps(
                tool_result,
                ensure_ascii=False,
                sort_keys=True,
                default=str,
                separators=(",", ":"),
            )
            fingerprint = hashlib.sha256(stable_result.encode("utf-8")).hexdigest()
            result_atoms = _tool_result_evidence_atoms(tool_result)
            new_atoms = result_atoms - evidence_atoms
            if fingerprint in tool_result_hashes or not new_atoms:
                result = dict(tool_result) if isinstance(tool_result, dict) else {}
                result["validator_new_evidence"] = False
                result["instruction"] = (
                    "This result is only an observation. Record a structured fact if it closes "
                    "an obligation gap; otherwise synthesize from existing facts."
                )
                if review_session is not None:
                    review_session.record_result(name, args, result)
                return result
            tool_result_hashes.add(fingerprint)
            evidence_atoms.update(new_atoms)
            ref = (
                "TOOLFACT_"
                + hashlib.sha256(
                    f"{cluster_uid}:{name}:{stable_args}:{fingerprint}".encode("utf-8")
                ).hexdigest()[:32]
            )
            record = {
                "evidence_ref": ref,
                "tool_name": name,
                "arguments_hash": hashlib.sha256(stable_args.encode("utf-8")).hexdigest(),
                "result_hash": fingerprint,
                "dependency_code_hash": fingerprint,
                "location": evidence_location(args, tool_result),
            }
            tool_fact_catalog[ref] = record
            allowed_refs.add(ref)
            result = dict(tool_result) if isinstance(tool_result, dict) else {"data": tool_result}
            result["evidence_ref"] = ref
            result["validator_new_evidence"] = True
            result["instruction"] = (
                f"If this resolves a required fact, call {fact_tool_name} citing {ref}."
            )
            if review_session is not None:
                review_session.record_result(name, args, result)
            return result

        def set_model_iteration(iteration: int) -> None:
            nonlocal current_model_iteration
            current_model_iteration = max(0, int(iteration or 0))

        def start_model_iteration(iteration: int) -> bool:
            """Stop only after two rounds add no structured tool/final fact.

            A repository tool result with a stable source and evidence record
            is a fact for investigation-progress purposes.  It is not by
            itself an obligation-closing promotion fact; that still requires
            a ``FACT_V3`` record with an allowed fact kind.
            """

            nonlocal consecutive_no_evidence_fact_iterations
            nonlocal current_model_iteration
            nonlocal evidence_facts_at_iteration_start
            nonlocal last_started_iteration
            nonlocal no_new_evidence_fact_stop
            normalized = max(1, int(iteration or 1))
            if normalized <= last_started_iteration:
                return no_new_evidence_fact_stop
            current_evidence_fact_count = len(tool_fact_catalog) + len(investigation_facts)
            if last_started_iteration:
                if current_evidence_fact_count > evidence_facts_at_iteration_start:
                    consecutive_no_evidence_fact_iterations = 0
                else:
                    consecutive_no_evidence_fact_iterations += 1
                evidence_facts_at_iteration_start = current_evidence_fact_count
            else:
                evidence_facts_at_iteration_start = current_evidence_fact_count
            last_started_iteration = normalized
            current_model_iteration = normalized
            no_new_evidence_fact_stop = consecutive_no_evidence_fact_iterations >= 2
            return no_new_evidence_fact_stop

        setattr(session_executor, "_zscope_set_iteration", set_model_iteration)
        setattr(session_executor, "_zscope_start_iteration", start_model_iteration)

        def terminal_handler(payload: Dict[str, Any]) -> Dict[str, Any]:
            if review_enabled:
                from ...core.validation.review_protocol import (
                    parse_review_result,
                    adjudicate_review,
                )

                envelope = parse_review_result(
                    payload,
                    candidate_uid=candidate_uid,
                    cluster_uid=cluster_uid,
                    expected_pass=pass_kind,
                    allowed_refs=allowed_refs,
                    rejection_expected=input_data.get("review_rejection_expected") is True,
                )
                if envelope is None:
                    return {"valid": False, "error": "invalid versioned review envelope"}
                backed = set(tool_fact_catalog) | {f["fact_uid"] for f in investigation_facts}
                decision, reason = adjudicate_review(envelope, backed_refs=backed)
                accepted_review.update(envelope=envelope, decision=decision, reason=reason)
                return {"valid": True, "payload": decision}
            parsed = parse_validator_result_v3(
                payload,
                candidate_uid=candidate_uid,
                validation_cluster_uid=cluster_uid,
                expected_pass=pass_kind,
                allowed_evidence_refs=sorted(allowed_refs),
            )
            if parsed is None:
                return {"valid": False, "error": "invalid ValidatorResult v3 payload"}
            return {"valid": True, "payload": parsed.to_dict()}

        try:
            trace_prefix = (
                "validator_v3_investigation; call_kind=targeted_investigation; "
                if pass_kind == "investigation_synthesis"
                else "validator_v2b_adjudication; call_kind=v2b_adjudication; "
            )
            result = self._run_tool_conversation(
                messages,
                max_iterations=iteration_limit,
                trace_label=(
                    trace_prefix
                    + f"candidate_uid={candidate_uid[:120]}; "
                    + f"validation_cluster_uid={cluster_uid[:120]}"
                ),
                additional_tools_schema=[fact_tool_schema, *review_schemas, terminal_schema],
                terminal_tool_name=spec.final_tool_name,
                terminal_tool_handler=terminal_handler,
                terminal_tool_required=True,
                tool_executor=session_executor,
                preserve_reasoning_metadata=True,
            )
        except Exception as exc:
            logger.warning("Validator V3 investigation failed: %s", exc)
            result = {}
        self._merge_result_metadata(aggregate, result)
        aggregate["validator_api_call_count"] = int(aggregate.get("iterations", 0) or 0)
        aggregate["validator_investigation_trajectory_count"] = 1
        aggregate["validator_investigation_facts"] = investigation_facts
        aggregate["validator_tool_fact_catalog"] = tool_fact_catalog
        aggregate["validator_investigation_tool_fact_count"] = len(tool_fact_catalog)
        aggregate["new_fact_count"] = len(investigation_facts)
        aggregate["consecutive_no_new_evidence_fact_iterations"] = (
            consecutive_no_evidence_fact_iterations
        )
        aggregate["validator_no_new_evidence_fact_stop"] = no_new_evidence_fact_stop
        if review_enabled or review_session is not None:
            aggregate["review_tool_results"] = review_tool_results
        if review_enabled:
            aggregate["review_adjudication"] = accepted_review.get("envelope", {})
            aggregate["review_disposition_reason"] = accepted_review.get(
                "reason", "invalid_review_envelope"
            )
        parsed = self._extract_v3_result(
            result,
            candidate_uid=candidate_uid,
            cluster_uid=cluster_uid,
            expected_pass=pass_kind,
            allowed_refs=sorted(allowed_refs),
        )
        self._finalize_slice_metadata(aggregate)
        if review_enabled:
            parsed = accepted_review.get("decision")
        if parsed is None:
            return AgentResponse(
                success=True,
                data=self._v3_uncertain_result(
                    candidate_uid,
                    cluster_uid,
                    pass_kind,
                    stop_reason="investigation_exhausted",
                    reasoning="Targeted investigation ended without a valid terminal decision.",
                ),
                metadata=aggregate,
            )
        return AgentResponse(success=True, data=parsed, metadata=aggregate)

    def _run_evidence_slice_protocol(
        self,
        input_data: Dict[str, Any],
    ) -> AgentResponse:
        """Close one Validator session in at most two no-browsing responses."""

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
        messages = self._messages(input_data, prompt)
        token_metadata: Dict[str, Any] = {
            "context_tokens": 0,
            "cumulative_prompt_tokens": 0,
            "cumulative_completion_tokens": 0,
            "cumulative_total_tokens": 0,
            "iterations": 0,
            "tool_call_count": 0,
            "validator_fast_path_attempted": 1,
            "validator_fast_path_accepted": 0,
            "validator_repair_attempted": 0,
            "validator_repair_accepted": 0,
            **self._execution_context_metadata(),
            "validator_final_tool_call_count": 0,
            "validator_session_count": 1,
            "validator_api_call_count": 0,
            "multi_turn_outlier_count": 0,
            "evidence_slice_token_count": int(input_data.get("evidence_slice_token_count") or 0),
        }
        try:
            result = self._run_tool_conversation(
                messages,
                max_iterations=1,
                trace_label=f"evidence_slice_v2; finding={finding_uid[:120]}",
            )
            self._merge_result_metadata(token_metadata, result)
            parsed = self._extract_validation_payload(
                str(result.get("content") or ""),
                result,
                result.get("conversation", []),
            )
            if parsed:
                token_metadata["validator_fast_path_accepted"] = 1
                self._finalize_slice_metadata(token_metadata)
                return AgentResponse(
                    success=True,
                    data=parsed,
                    metadata=dict(token_metadata),
                )

            error_type, _json_blocks = self._classify_invalid_result(
                str(result.get("content") or ""),
                result,
                result.get("conversation", []),
            )
            repaired = self._run_json_repair(
                messages,
                result,
                error_type=error_type,
                attempt=1,
                finding={"id": finding_uid},
                token_metadata=token_metadata,
            )
            if repaired:
                self._finalize_slice_metadata(token_metadata)
                return AgentResponse(
                    success=True,
                    data=repaired,
                    metadata=dict(token_metadata),
                )

            self._finalize_slice_metadata(token_metadata)
            return AgentResponse(
                success=True,
                data={
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
                },
                metadata=dict(token_metadata),
            )
        except Exception as exc:
            self._finalize_slice_metadata(token_metadata)
            return AgentResponse(
                success=False,
                data={},
                error=str(exc),
                metadata=dict(token_metadata),
            )

    @staticmethod
    def _finalize_slice_metadata(metadata: Dict[str, Any]) -> None:
        turns = int(metadata.get("iterations", 0) or 0)
        metadata["validator_api_call_count"] = turns
        metadata["multi_turn_outlier_count"] = 1 if turns > 2 else 0
        metadata["validator_turn_count"] = turns

    def _run_fast_path(
        self,
        messages: List[Dict[str, Any]],
        finding: Any,
        token_metadata: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Try one no-tool validation pass from the compact evidence pack."""
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
        token_metadata["validator_fast_path_attempted"] = (
            int(token_metadata.get("validator_fast_path_attempted", 0) or 0) + 1
        )
        try:
            result = self._run_tool_conversation(
                fast_messages,
                max_iterations=1,
                trace_label=f"fast_path; finding={str(finding)[:120]}",
            )
        except Exception as exc:
            logger.debug("Validator fast path failed before fallback: %s", exc)
            return None

        self._merge_result_metadata(token_metadata, result)
        parsed = self._extract_validation_payload(
            str(result.get("content") or ""),
            result,
            result.get("conversation", []),
        )
        if not parsed or not self._accept_fast_path_result(parsed):
            return None
        token_metadata["validator_fast_path_accepted"] = (
            int(token_metadata.get("validator_fast_path_accepted", 0) or 0) + 1
        )
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
        """Run one final no-retrieval pass whose only job is validator JSON."""
        repair_seed = dict(result)
        for key in (
            "context_tokens",
            "cumulative_prompt_tokens",
            "cumulative_completion_tokens",
            "cumulative_total_tokens",
            "iterations",
            "tool_call_count",
            "final_tool_call_count",
        ):
            repair_seed[key] = 0
        response = self._run_json_final_repair(
            messages,
            repair_seed,
            json_output_spec=self._validation_json_output_spec(),
            extractor=lambda content, repair_result, conversation: self._extract_validation_payload(
                content,
                repair_result,
                conversation,
            ),
            trace_label=f"attempt={attempt}; finding={str(finding)[:120]}",
            parse_label="validation_result JSON",
            error_type=error_type,
            max_json_retries=1,
            post_process=lambda data: self._coerce_validation_result(data) or data,
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

    @classmethod
    def _validation_json_output_spec(cls) -> JsonOutputSpec:
        return JsonOutputSpec(
            type_name="validation_result",
            schema=cls._validation_result_schema(),
            final_tool_name="emit_validation_result",
            final_tool_description="Emit the final Z-Scope validation_result object.",
            validator=lambda data: cls._coerce_validation_result(data) is not None,
            nested_keys=tuple(cls._WRAPPER_KEYS),
            metadata_prefix="validator",
        )

    @staticmethod
    def _validation_result_schema() -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "type": {"type": "string", "enum": ["validation_result"]},
                "issue_id": {"type": "string"},
                "verdict": {"type": "string", "enum": ["verified", "rejected", "uncertain"]},
                "finding_kind": {"type": "string"},
                "is_valid": {"type": "boolean"},
                "confidence_score": {"type": "number", "minimum": 0, "maximum": 1},
                "reasoning": {"type": "string"},
                "positive_evidence": {"type": "array", "items": {"type": "string"}},
                "negative_evidence": {"type": "array", "items": {"type": "string"}},
                "blocking_negative_evidence": {
                    "type": "boolean",
                    "description": "True only when a concrete guard, ownership, lock, reachability, or contract fact blocks confirmation; uncertainty alone is false.",
                },
                "missing_context": {"type": "array", "items": {"type": "string"}},
                "exploit_scenario": {"type": "string"},
                "source": {"type": "string"},
                "sink": {"type": "string"},
                "control_of_source": {"type": "string"},
                "guard_analysis": {"type": "string"},
                "missing_fact_request": {
                    "type": ["object", "null"],
                    "properties": {
                        "fact_kind": {
                            "type": "string",
                            "enum": [
                                "guard_dominance",
                                "caller_contract",
                                "source_controllability",
                                "ownership_transfer",
                                "cleanup_coverage",
                                "lockset",
                                "happens_before",
                                "object_identity",
                                "value_range",
                                "source_sink_reachability",
                                "signal_context",
                                "container_reachability",
                                "type_layout",
                            ],
                        },
                        "subject_uid": {"type": "string"},
                        "function_uid": {"type": "string"},
                        "reason": {"type": "string"},
                    },
                    "required": ["fact_kind", "reason"],
                    "additionalProperties": False,
                },
            },
            "required": ["type", "verdict", "reasoning", "blocking_negative_evidence"],
            "additionalProperties": True,
        }

    @classmethod
    def _accept_fast_path_result(cls, data: Dict[str, Any]) -> bool:
        verdict = cls._normalize_verdict_value(data.get("verdict"), data.get("is_valid"))
        # Any reasoned structured verdict closes the Validator's decision
        # obligation.  Confidence/evidence promotion belongs to the validation
        # policy layer: low-confidence ``verified`` is routed to needs-review,
        # and ``rejected`` cannot suppress a candidate without deterministic
        # proof.  Retrying either result with up to 50 retrieval turns merely
        # duplicates analysis and bypasses those centralized gates.
        return bool(
            verdict in {"verified", "rejected", "uncertain"}
            and str(data.get("reasoning") or "").strip()
        )

    @staticmethod
    def _merge_result_metadata(target: Dict[str, Any], result: Dict[str, Any]) -> None:
        for key in (
            "context_tokens",
            "cumulative_prompt_tokens",
            "cumulative_completion_tokens",
            "cumulative_total_tokens",
            "iterations",
            "tool_call_count",
            "validator_repair_attempted",
            "validator_repair_accepted",
            "validator_final_tool_call_count",
        ):
            try:
                target[key] = int(target.get(key, 0) or 0) + int(result.get(key, 0) or 0)
            except (TypeError, ValueError):
                continue
        try:
            target["validator_final_tool_call_count"] = int(
                target.get("validator_final_tool_call_count", 0) or 0
            ) + int(result.get("final_tool_call_count", 0) or 0)
        except (TypeError, ValueError):
            pass

    @staticmethod
    def _merge_chat_response_metadata(
        target: Dict[str, Any],
        response: Dict[str, Any],
        messages: List[Dict[str, Any]],
        assistant_message: Dict[str, Any],
    ) -> None:
        prompt_tokens, completion_tokens = LLMClient._response_token_usage(
            response,
            messages,
            assistant_message,
        )
        target["context_tokens"] = int(
            target.get("context_tokens", 0) or 0
        ) + LLMClient.estimate_tokens(messages)
        target["cumulative_prompt_tokens"] = (
            int(target.get("cumulative_prompt_tokens", 0) or 0) + prompt_tokens
        )
        target["cumulative_completion_tokens"] = (
            int(target.get("cumulative_completion_tokens", 0) or 0) + completion_tokens
        )
        target["cumulative_total_tokens"] = int(
            target.get("cumulative_prompt_tokens", 0) or 0
        ) + int(target.get("cumulative_completion_tokens", 0) or 0)
        target["iterations"] = int(target.get("iterations", 0) or 0) + 1

    def _classify_invalid_result(
        self,
        content: str,
        result: Dict[str, Any],
        conversation: Iterable[Dict[str, Any]],
    ) -> Tuple[str, int]:
        json_blocks_found = self._json_candidate_count(content, result, conversation)
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

    def _log_invalid_result(
        self,
        attempt: int,
        max_retries: int,
        error_type: str,
        *,
        phase: str,
        finding: Any,
        result: Dict[str, Any],
        content: str,
        json_blocks_found: int,
    ) -> None:
        logger.warning(
            "Validator attempt %d/%d failed: issue_id=%s phase=%s error_type=%s "
            "finish_reason=%s truncated=%s content_len=%d tool_call_count=%s "
            "json_blocks_found=%d provider_model=%s",
            attempt,
            max_retries,
            self._issue_id_from_finding(finding),
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
    def _issue_id_from_finding(finding: Any) -> str:
        if isinstance(finding, dict):
            return str(finding.get("id") or finding.get("issue_id") or "unknown")
        if isinstance(finding, str):
            try:
                data = json.loads(finding)
                if isinstance(data, dict):
                    return str(data.get("id") or data.get("issue_id") or "unknown")
            except Exception:
                return "unknown"
        return "unknown"

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
    def _is_validation_result(data: Any) -> bool:
        if not isinstance(data, dict):
            return False
        has_verdict = bool(
            ValidatorAgent._normalize_verdict_value(data.get("verdict"), data.get("is_valid"))
        )
        if not has_verdict:
            return False
        if data.get("type") == "validation_result" or "is_valid" in data:
            return True
        return any(key in data for key in ValidatorAgent._VALIDATION_RESULT_KEYS)

    def _extract_validation_payload(
        self,
        content: str,
        result: Dict[str, Any],
        conversation: Iterable[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Extract and normalize validator JSON, including common wrapper shapes."""
        for data in self._validation_result_tool_payloads(result, conversation):
            parsed = self._coerce_validation_result(data)
            if parsed:
                return parsed
        for text in self._text_sources(content, result, conversation):
            for data in extract_json_blocks(text):
                parsed = self._coerce_validation_result(data)
                if parsed:
                    return parsed
        return None

    def _extract_first_json(
        self,
        content: str,
        result: Dict[str, Any],
        conversation: Iterable[Dict[str, Any]],
    ) -> Any:
        for data in self._validation_result_tool_payloads(result, conversation):
            return data
        return super()._extract_first_json(content, result, conversation)

    def _json_candidate_count(
        self,
        content: str,
        result: Dict[str, Any],
        conversation: Iterable[Dict[str, Any]],
        *,
        json_output_spec: Optional[JsonOutputSpec] = None,
    ) -> int:
        # ``JsonToolAgent._run_json_final_repair`` classifies its final response
        # through the base keyword-aware interface.  Keep this Validator
        # override substitutable so a malformed/truncated response becomes a
        # bounded protocol outcome rather than an operational TypeError.
        if json_output_spec is not None:
            count = len(list(self._final_tool_payloads(result, conversation, json_output_spec)))
        else:
            count = len(list(self._validation_result_tool_payloads(result, conversation)))
        for text in self._text_sources(content, result, conversation):
            count += len(extract_json_blocks(text))
        return count

    @classmethod
    def _validation_result_tool_payloads(
        cls,
        result: Dict[str, Any],
        conversation: Iterable[Dict[str, Any]],
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
                if function.get("name") != "emit_validation_result":
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

    @classmethod
    def _coerce_validation_result(cls, data: Any) -> Optional[Dict[str, Any]]:
        if not isinstance(data, dict):
            return None

        if cls._is_validation_result(data):
            return cls._normalize_validation_result(data)

        scalar_result = data.get("validation_result")
        scalar_verdict = cls._normalize_verdict_value(scalar_result, data.get("is_valid"))
        if isinstance(scalar_result, str) and scalar_verdict:
            candidate = dict(data)
            candidate.pop("validation_result", None)
            candidate["verdict"] = scalar_verdict
            return cls._normalize_validation_result(candidate)

        for key, value in data.items():
            if cls._normalized_wrapper_key(key) not in cls._WRAPPER_KEYS:
                continue
            parsed = cls._coerce_validation_result(value)
            if parsed:
                return parsed
            if isinstance(value, list):
                for item in value:
                    parsed = cls._coerce_validation_result(item)
                    if parsed:
                        return parsed
        return None

    @staticmethod
    def _normalized_wrapper_key(key: Any) -> str:
        return "".join(ch for ch in str(key or "").lower() if ch.isalnum())

    @staticmethod
    def _normalize_validation_result(data: Dict[str, Any]) -> Dict[str, Any]:
        normalized = dict(data)
        normalized["type"] = "validation_result"
        verdict = ValidatorAgent._normalize_verdict_value(
            normalized.get("verdict"),
            normalized.get("is_valid"),
        )
        if verdict:
            normalized["verdict"] = verdict
            normalized["is_valid"] = verdict == "verified"
        return normalized

    @staticmethod
    def _normalize_verdict_value(verdict: Any, is_valid: Any = None) -> Optional[str]:
        raw_verdict = str(verdict or "").strip().lower()
        aliases = {
            "valid": "verified",
            "true": "verified",
            "confirmed": "verified",
            "true_positive": "verified",
            "tp": "verified",
            "invalid": "rejected",
            "false": "rejected",
            "reject": "rejected",
            "rejected": "rejected",
            "false_positive": "rejected",
            "fp": "rejected",
            "needs_review": "uncertain",
            "need_review": "uncertain",
            "unknown": "uncertain",
            "inconclusive": "uncertain",
            "uncertain": "uncertain",
            "verified": "verified",
        }
        normalized = aliases.get(raw_verdict, raw_verdict)
        if normalized in {"verified", "rejected", "uncertain"}:
            return normalized

        bool_value = ValidatorAgent._coerce_bool(is_valid)
        if bool_value is not None:
            return "verified" if bool_value else "rejected"
        return None

    @staticmethod
    def _coerce_bool(value: Any) -> Optional[bool]:
        if isinstance(value, bool):
            return value
        if value is None:
            return None
        if isinstance(value, (int, float)):
            return bool(value)
        text = str(value).strip().lower()
        if text in {"true", "1", "yes", "y"}:
            return True
        if text in {"false", "0", "no", "n"}:
            return False
        return None

    _WRAPPER_KEYS = {
        "answer",
        "data",
        "decision",
        "decisions",
        "output",
        "outputs",
        "payload",
        "response",
        "responses",
        "result",
        "results",
        "validation",
        "validationresult",
        "validationresults",
    }

    _VALIDATION_RESULT_KEYS = {
        "confidence_score",
        "blocking_negative_evidence",
        "control_of_source",
        "exploit_scenario",
        "finding_kind",
        "guard_analysis",
        "issue_id",
        "missing_context",
        "negative_evidence",
        "positive_evidence",
        "reasoning",
        "sink",
        "source",
    }
