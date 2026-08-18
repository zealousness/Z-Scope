import hashlib
import json
import logging
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

from ..base import JsonOutputSpec, JsonToolAgent
from ...tools.policy import ToolPolicy
from ...framework.base import AgentResponse
from ...framework.llm_client import LLMClient
from ...framework.llm_usage import llm_usage_attribution_scope
from ...common.utils import extract_json_blocks
from ...common.validator_protocol import (
    VALIDATOR_PROTOCOL_VERSION as VALIDATOR_PROTOCOL_V3,
    VALIDATOR_RESULT_VERSION,
    ValidatorResultV3,
    parse_validator_result_v3,
    validator_result_schema_v3,
)

logger = logging.getLogger(__name__)

_CLAIM_PREDICATES = {
    "guard_dominance": "guard_dominates_sink",
    "caller_contract": "caller_contract_holds",
    "source_controllability": "source_is_externally_controllable",
    "ownership_transfer": "ownership_transfer_exists",
    "cleanup_coverage": "cleanup_covers_all_exits",
    "lockset": "lock_must_hold_at_access",
    "happens_before": "happens_before_edge_exists",
    "object_identity": "same_object_identity",
    "value_range": "value_range_is_proved",
    "source_sink_reachability": "source_sink_path_exists",
    "signal_context": "signal_context_is_reachable",
    "container_reachability": "container_path_is_reachable",
    "type_layout": "type_layout_is_resolved",
}

# Historical replay only.  These tools produce observations, not proof
# certificates.  Live V3 sessions use finite EvidenceAction records instead.
_LEGACY_REPLAY_OBSERVATION_TOOLS = {
    "source_sink_reachability": (
        "get_data_flow",
        "get_call_graph",
        "get_callers",
    ),
    "guard_dominance": ("get_data_flow",),
    "lockset": ("get_data_flow", "query_pointer_alias"),
    "happens_before": ("get_data_flow", "get_call_graph"),
    "cleanup_coverage": ("get_data_flow", "get_call_graph"),
    "ownership_transfer": (
        "get_data_flow",
        "query_pointer_alias",
    ),
    "caller_contract": ("get_callers", "get_call_graph"),
    "source_controllability": (
        "get_data_flow",
        "get_callers",
        "get_call_graph",
    ),
    "object_identity": (
        "query_pointer_alias",
        "get_data_flow",
        "get_type_info",
    ),
    "value_range": ("get_data_flow", "get_type_info"),
    "type_layout": ("get_type_info",),
    "signal_context": (
        "get_callers",
        "get_call_graph",
        "find_function_pointers",
    ),
    "container_reachability": (
        "get_data_flow",
        "get_call_graph",
        "query_pointer_alias",
    ),
}

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
        }
        prompt = self._validator_v3_prompt(evidence_slice, expected_pass)
        messages = self._messages(input_data, prompt)
        evidence_delta = evidence_slice.get("evidence_delta")
        # ``new_fact_count`` is call-output telemetry, not the number of facts
        # already present in the call input.  V2 is the one exception: its
        # evidence delta was accepted into the decision slice immediately
        # before this stateless recheck, so attributing that delta to the V2
        # call is intentional.  A V3 terminal/synthesis call must start at
        # zero; ValidationRunner later assigns only the facts that its
        # programmatic verifier actually accepted during that session.
        new_fact_count = (
            self._v3_evidence_delta_count(evidence_delta)
            if expected_pass == "evidence_recheck"
            else 0
        )

        response, result = self._direct_v3_completion(
            messages,
            trace_label=(
                f"validator_v3; pass={expected_pass}; call_kind={expected_pass}; "
                f"candidate_uid={candidate_uid[:120]}; "
                f"validation_cluster_uid={cluster_uid[:120]}; "
                f"new_fact_count={new_fact_count}"
            ),
            max_tokens=8192,
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
        max_tokens: int,
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
        kwargs: Dict[str, Any] = {
            "max_tokens": max_tokens,
            "trace_agent": self.name,
            "trace_label": trace_label,
            "trace_iteration": 1,
        }
        if response_format:
            kwargs["response_format"] = response_format
        else:
            kwargs["tools"] = [tool]
            kwargs["tool_choice"] = {
                "type": "function",
                "function": {"name": spec.final_tool_name},
            }
        try:
            response = chat_completion(messages, **kwargs)
        except Exception as exc:
            # Provider capability selection is fixed before the call.  A
            # profile that declares native JSON-schema support must not turn a
            # failed V1/V2 attempt into an unplanned second HTTP attempt.  A
            # provider without that capability already takes the one-terminal-
            # tool branch above.
            logger.warning("Validator v3 direct completion failed: %s", exc)
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
        # A real tool session marks an invalid/exhausted terminal explicitly.
        # Do not recover the rejected payload by scanning conversation history.
        if "terminal_tool_valid" in result and result.get("terminal_tool_valid") is not True:
            return None
        values: List[Any] = []
        terminal_payload = result.get("terminal_tool_payload")
        if result.get("terminal_tool_valid") is True and isinstance(terminal_payload, dict):
            values.append(terminal_payload)
        else:
            # Compatibility for deterministic test/legacy adapters that
            # return a conversation without terminal-loop metadata.
            values.extend(self._final_tool_payloads(result, result.get("conversation", []), spec))
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
        claim_verifier: Optional[
            Callable[[Dict[str, Any], Mapping[str, Mapping[str, Any]]], Dict[str, Any]]
        ] = None,
        evidence_actions: Optional[Iterable[Mapping[str, Any]]] = None,
        evidence_action_executor: Optional[Callable[[str], Dict[str, Any]]] = None,
    ) -> AgentResponse:
        """Run one continuous, tool-backed V3 investigation session."""

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
        action_records = [
            dict(value) for value in evidence_actions or [] if isinstance(value, Mapping)
        ]
        action_by_id = {
            str(value.get("action_id") or ""): value
            for value in action_records
            if str(value.get("action_id") or "")
        }
        action_mode = evidence_action_executor is not None
        if not allowed_fact_kinds and not action_mode:
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
        canonical_subject_uid = str(obligation.get("subject_uid") or "")
        canonical_region_uid = str(
            obligation.get("decision_region_uid") or obligation.get("obligation_uid") or ""
        )
        authoritative_tool_guidance = {
            fact_kind: {
                "predicate": _CLAIM_PREDICATES.get(fact_kind, ""),
                "tools": list(_LEGACY_REPLAY_OBSERVATION_TOOLS.get(fact_kind, ())),
            }
            for fact_kind in sorted(allowed_fact_kinds)
            if _LEGACY_REPLAY_OBSERVATION_TOOLS.get(fact_kind)
        }
        v3_tool_names = {
            tool_name
            for fact_kind in allowed_fact_kinds
            for tool_name in _LEGACY_REPLAY_OBSERVATION_TOOLS.get(fact_kind, ())
        }
        v3_tools_schema = [
            schema
            for schema in self.tools_schema
            if str((schema.get("function") or {}).get("name") or "") in v3_tool_names
        ]
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
        claim_tool_name = "submit_validator_evidence_claim"
        claim_tool_schema = {
            "type": "function",
            "function": {
                "name": claim_tool_name,
                "description": (
                    "Submit one structured predicate over prior read-only tool results. "
                    "Z-Scope independently re-runs the predicate verifier; the model cannot "
                    "create an authoritative fact. Only the fact-kind-specific authoritative "
                    "tools listed in the investigation prompt may be cited."
                ),
                "parameters": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "fact_kind": {
                            "type": "string",
                            "enum": sorted(allowed_fact_kinds),
                        },
                        "predicate": {
                            "type": "string",
                            "enum": sorted(
                                {
                                    _CLAIM_PREDICATES[value]
                                    for value in allowed_fact_kinds
                                    if value in _CLAIM_PREDICATES
                                }
                            ),
                        },
                        "polarity": {"type": "string", "enum": ["supports", "refutes"]},
                        "subject_uid": {
                            "type": "string",
                            "enum": [canonical_subject_uid],
                            "description": "Exact canonical subject UID from the obligation.",
                        },
                        "decision_region_uid": {
                            "type": "string",
                            "enum": [canonical_region_uid],
                            "description": (
                                "Exact canonical decision region UID from the obligation."
                            ),
                        },
                        "arguments": {
                            "type": "object",
                            "description": (
                                "Exact structured key/value pairs copied from cited tool results. "
                                "Do not add prose conclusions or inferred values."
                            ),
                        },
                        "cited_evidence_refs": {
                            "type": "array",
                            "minItems": 1,
                            "maxItems": 8,
                            "items": {"type": "string"},
                        },
                    },
                    "required": [
                        "fact_kind",
                        "predicate",
                        "polarity",
                        "subject_uid",
                        "decision_region_uid",
                        "arguments",
                        "cited_evidence_refs",
                    ],
                },
            },
        }
        action_tool_name = "execute_validator_evidence_action"
        action_tool_schema = {
            "type": "function",
            "function": {
                "name": action_tool_name,
                "description": (
                    "Select one finite deterministic proof action. Z-Scope binds the subject, "
                    "decision region, parameters, code snapshot and verifier; the model cannot "
                    "supply or alter them."
                ),
                "parameters": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "action_id": {
                            "type": "string",
                            "enum": sorted(action_by_id),
                        }
                    },
                    "required": ["action_id"],
                },
            },
        }
        if action_mode:
            v3_tools_schema = []
            prompt = (
                "Targeted Validator V3 proof-action session. You may only choose one of the "
                "finite EvidenceAction records below; their subject, decision region and "
                "parameters are system-bound. There is no independent action-count quota, but "
                f"the session has at most {iteration_limit} model iterations. Select actions "
                "that can close an open clause. A certificate is authoritative only when the "
                "program returns verified_true with complete coverage. Repeated actions are "
                "rejected and two consecutive rounds without an accepted fact stop the session. "
                "A rejected verdict still requires a deterministic counterproof; otherwise use "
                "uncertain. Finish with one strict investigation_synthesis result. Actions: "
                + json.dumps(action_records, ensure_ascii=False, sort_keys=True)
                + "\n\n"
                + json.dumps(evidence_slice, ensure_ascii=False, separators=(",", ":"))
            )
        else:
            prompt = (
                "Legacy replay-only Validator V3 investigation. Use only the supplied read-only "
                "repository tools. There is no independent tool-query quota, but the entire "
                f"session has at most {iteration_limit} model iterations. Every useful repository "
                "result returns a TOOLFACT observation. Submit it through "
                f"{claim_tool_name}; the program independently verifies the predicate. "
                "Authoritative tools by fact kind are: "
                + json.dumps(authoritative_tool_guidance, ensure_ascii=False, sort_keys=True)
                + ". A rejected verdict requires blocking evidence; missing context is uncertain. "
                "Finish with one strict investigation_synthesis result.\n\n"
                + json.dumps(evidence_slice, ensure_ascii=False, separators=(",", ":"))
            )
        messages = self._messages(input_data, prompt)
        tool_result_hashes: set[str] = set()
        tool_call_signatures: set[str] = set()
        evidence_atoms: set[str] = set()
        tool_fact_catalog: Dict[str, Dict[str, Any]] = {}
        investigation_facts: List[Dict[str, Any]] = []
        investigation_claims: List[Dict[str, Any]] = []
        claim_verifications: List[Dict[str, Any]] = []
        consecutive_no_evidence_fact_iterations = 0
        current_model_iteration = 0
        last_started_iteration = 0
        progress_at_iteration_start = 0
        no_new_evidence_fact_stop = False
        programmatic_terminal_payload: Optional[Dict[str, Any]] = None

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
            nonlocal programmatic_terminal_payload
            if name == action_tool_name and action_mode:
                if not isinstance(args, dict):
                    return {
                        "success": False,
                        "error": "evidence action arguments must be an object",
                    }
                action_id = str(args.get("action_id") or "")
                if action_id not in action_by_id:
                    return {"success": False, "error": "unknown_validator_evidence_action"}
                signature = hashlib.sha256(f"action:{action_id}".encode("utf-8")).hexdigest()
                if signature in tool_call_signatures:
                    return {"success": False, "error": "validator_v3_duplicate_evidence_action"}
                tool_call_signatures.add(signature)
                if no_new_evidence_fact_stop:
                    return {
                        "success": False,
                        "error": "validator_v3_no_new_evidence_fact_stop; emit the final result",
                    }
                try:
                    outcome = (
                        evidence_action_executor(action_id) if evidence_action_executor else {}
                    )
                except Exception as exc:
                    outcome = {
                        "status": "unknown",
                        "reason_code": "evidence_action_executor_error",
                        "error": f"{type(exc).__name__}: {exc}"[:500],
                    }
                if not isinstance(outcome, dict):
                    outcome = {
                        "status": "unknown",
                        "reason_code": "evidence_action_invalid_result",
                    }
                fact = outcome.get("verified_fact")
                if (
                    str(outcome.get("status") or "") == "verified_true"
                    and isinstance(fact, dict)
                    and str(fact.get("fact_uid") or "")
                ):
                    fact_uid = str(fact["fact_uid"])
                    if not any(value.get("fact_uid") == fact_uid for value in investigation_facts):
                        investigation_facts.append(dict(fact))
                    allowed_refs.add(fact_uid)
                claim_verifications.append(dict(outcome))
                authority = outcome.get("terminal_authority")
                authority = authority if isinstance(authority, Mapping) else {}
                disposition = str(authority.get("disposition") or "")
                if authority.get("terminal") is True and disposition in {
                    "confirmed",
                    "rejected_with_proof",
                    "needs_review",
                }:
                    fact_uid = str(fact.get("fact_uid") or "") if isinstance(fact, dict) else ""
                    proof_terminal = disposition in {"confirmed", "rejected_with_proof"}
                    programmatic_terminal_payload = {
                        "schema_version": "zscope.validator-result.v3",
                        "candidate_uid": candidate_uid,
                        "validation_cluster_uid": cluster_uid,
                        "pass": "investigation_synthesis",
                        "verdict": (
                            "verified"
                            if disposition == "confirmed"
                            else (
                                "rejected" if disposition == "rejected_with_proof" else "uncertain"
                            )
                        ),
                        "reasoning": (
                            "Programmatic evidence action produced a complete deterministic "
                            "decision proof; no further model investigation is authorized."
                            if proof_terminal
                            else (
                                "Programmatic evidence action exhausted the currently executable "
                                "proof gaps. Remaining clauses require review; no further model "
                                "investigation is authorized."
                            )
                        ),
                        "positive_evidence": (
                            [fact_uid] if disposition == "confirmed" and fact_uid else []
                        ),
                        "negative_evidence": (
                            [fact_uid] if disposition == "rejected_with_proof" and fact_uid else []
                        ),
                        "evidence_refs": ([fact_uid] if fact_uid else []),
                        "blocking_negative_evidence": disposition == "rejected_with_proof",
                        "missing_fact_request": None,
                        "stop_reason": (
                            "decision_complete" if proof_terminal else "investigation_exhausted"
                        ),
                    }
                return {
                    "success": True,
                    "action_id": action_id,
                    "fact_kind": action_by_id[action_id].get("fact_kind"),
                    "status": outcome.get("status"),
                    "reason_code": outcome.get("reason_code"),
                    "verified_fact": fact if isinstance(fact, dict) else None,
                    "certificate_ref": outcome.get("certificate_ref"),
                    "terminal_authority": outcome.get("terminal_authority"),
                    "instruction": (
                        "The action was programmatically recomputed. Only a returned verified_fact "
                        "closes a clause; otherwise choose a different available action or finish "
                        "uncertain."
                    ),
                }
            if name == claim_tool_name:
                if not isinstance(args, dict):
                    return {"success": False, "error": "claim arguments must be an object"}
                fact_kind = str(args.get("fact_kind") or "").strip().lower()
                refs = args.get("cited_evidence_refs")
                refs = [str(value) for value in refs] if isinstance(refs, list) else []
                claim = dict(args)
                claim["fact_kind"] = fact_kind
                submitted_refs = sorted(set(refs))
                known_tool_refs = [ref for ref in submitted_refs if ref in tool_fact_catalog]
                claim["submitted_cited_evidence_refs"] = submitted_refs
                # Initial FACT/location/catalog refs may support the final
                # narrative, but executable claims are replayed only over
                # frozen TOOLFACT payloads. Preserve the raw list above for
                # traceability and drop unrelated context refs here.
                claim["cited_evidence_refs"] = known_tool_refs or submitted_refs
                claim.setdefault(
                    "obligation_uid", str(obligation.get("obligation_uid") or candidate_uid)
                )
                investigation_claims.append(claim)
                if claim_verifier is None:
                    verification = {
                        "schema_version": "zscope.evidence-claim-verification.v1",
                        "status": "unknown",
                        "reason_code": "claim_verifier_unavailable",
                        "verified_fact": None,
                    }
                else:
                    try:
                        verification = claim_verifier(claim, tool_fact_catalog)
                    except Exception as exc:
                        verification = {
                            "schema_version": "zscope.evidence-claim-verification.v1",
                            "status": "unknown",
                            "reason_code": "claim_verifier_error",
                            "error": f"{type(exc).__name__}: {exc}"[:500],
                            "verified_fact": None,
                        }
                if not isinstance(verification, dict):
                    verification = {
                        "schema_version": "zscope.evidence-claim-verification.v1",
                        "status": "unknown",
                        "reason_code": "claim_verifier_invalid_result",
                        "verified_fact": None,
                    }
                claim_verifications.append(dict(verification))
                fact = verification.get("verified_fact")
                if (
                    str(verification.get("status") or "") == "verified_true"
                    and isinstance(fact, dict)
                    and str(fact.get("fact_uid") or "")
                ):
                    fact_uid = str(fact["fact_uid"])
                    if not any(value.get("fact_uid") == fact_uid for value in investigation_facts):
                        investigation_facts.append(dict(fact))
                    allowed_refs.add(fact_uid)
                response: Dict[str, Any] = {
                    "success": True,
                    "claim_status": verification.get("status"),
                    "reason_code": verification.get("reason_code"),
                    "verified_fact": fact if isinstance(fact, dict) else None,
                    "instruction": (
                        "Only verified_true closes an obligation clause; unknown, false, or "
                        "conflicting claims require another executable query or needs_review."
                    ),
                }
                if str(verification.get("reason_code") or "") in {
                    "tool_not_authoritative_for_predicate",
                    "claim_protocol_invalid",
                    "unknown_evidence_ref",
                    "claim_arguments_not_replayed",
                }:
                    response.update(
                        {
                            "expected_predicate": _CLAIM_PREDICATES.get(fact_kind, ""),
                            "allowed_tools": list(
                                _LEGACY_REPLAY_OBSERVATION_TOOLS.get(fact_kind, ())
                            ),
                            "allowed_evidence_refs": sorted(tool_fact_catalog),
                            "instruction": (
                                "Use the exact expected predicate and cite a result from one "
                                "of the allowed deterministic tools. Semantic snapshots and "
                                "code snippets are observations only."
                            ),
                        }
                    )
                return response

            if name not in v3_tool_names:
                return {
                    "success": False,
                    "error": "validator_v3_tool_not_exposed_for_open_clauses",
                    "allowed_tools": sorted(v3_tool_names),
                }

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
            # Some read-only tools resolve a missing function snapshot by
            # invoking the SemanticModeler synchronously.  Preserve the
            # owning validation identity across that nested provider call so
            # its usage can be charged to and replayed with this cluster.
            with llm_usage_attribution_scope(
                validation_cluster_uid=cluster_uid,
                candidate_uid=candidate_uid,
                finding_uid=candidate_uid,
                call_kind="v3_tool_dependency",
            ):
                tool_result = self._tool_executor(name, args)
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
                "arguments": args if isinstance(args, dict) else {},
                "arguments_hash": hashlib.sha256(stable_args.encode("utf-8")).hexdigest(),
                "result_hash": fingerprint,
                "dependency_code_hash": fingerprint,
                "location": evidence_location(args, tool_result),
                "result_payload": (
                    dict(tool_result)
                    if isinstance(tool_result, dict)
                    else {"success": True, "data": tool_result}
                ),
            }
            tool_fact_catalog[ref] = record
            allowed_refs.add(ref)
            result = dict(tool_result) if isinstance(tool_result, dict) else {"data": tool_result}
            result["evidence_ref"] = ref
            result["validator_new_evidence"] = True
            result["instruction"] = (
                f"If this appears to resolve a required fact, call {claim_tool_name} citing {ref}."
            )
            return result

        def set_model_iteration(iteration: int) -> None:
            nonlocal current_model_iteration
            current_model_iteration = max(0, int(iteration or 0))

        def start_model_iteration(iteration: int) -> bool:
            """Stop after the scout window and two rounds add no evidence state."""

            nonlocal consecutive_no_evidence_fact_iterations
            nonlocal current_model_iteration
            nonlocal progress_at_iteration_start
            nonlocal last_started_iteration
            nonlocal no_new_evidence_fact_stop
            normalized = max(1, int(iteration or 1))
            if normalized <= last_started_iteration:
                return no_new_evidence_fact_stop
            # Raw tool results are observations.  Only a fact accepted by the
            # program verifier changes the obligation state and resets the
            # no-progress counter.
            current_progress = len(investigation_facts)
            if not action_mode and normalized <= 4:
                consecutive_no_evidence_fact_iterations = 0
                progress_at_iteration_start = current_progress
            elif last_started_iteration:
                if current_progress > progress_at_iteration_start:
                    consecutive_no_evidence_fact_iterations = 0
                else:
                    consecutive_no_evidence_fact_iterations += 1
                progress_at_iteration_start = current_progress
            else:
                progress_at_iteration_start = current_progress
            last_started_iteration = normalized
            current_model_iteration = normalized
            # New finite EvidenceAction sessions stop after two completed
            # no-fact rounds.  The legacy free-tool bridge retains its former
            # four-turn scout window only for historical replay compatibility.
            no_new_evidence_fact_stop = consecutive_no_evidence_fact_iterations >= 2 and (
                action_mode or normalized > 4
            )
            return no_new_evidence_fact_stop

        setattr(session_executor, "_zscope_set_iteration", set_model_iteration)
        setattr(session_executor, "_zscope_start_iteration", start_model_iteration)
        setattr(
            session_executor,
            "_zscope_programmatic_terminal_payload",
            lambda: programmatic_terminal_payload,
        )

        def terminal_handler(payload: Dict[str, Any]) -> Dict[str, Any]:
            parsed = parse_validator_result_v3(
                payload,
                candidate_uid=candidate_uid,
                validation_cluster_uid=cluster_uid,
                expected_pass="investigation_synthesis",
                allowed_evidence_refs=sorted(allowed_refs),
            )
            if parsed is None:
                return {"valid": False, "error": "invalid ValidatorResult v3 payload"}
            if parsed.verdict == "verified":
                accepted_refs = {
                    str(fact.get("fact_uid") or "")
                    for fact in investigation_facts
                    if str(fact.get("fact_uid") or "")
                }
                if not accepted_refs or not accepted_refs.intersection(parsed.evidence_refs):
                    if no_new_evidence_fact_stop:
                        # The session has already exhausted its executable
                        # evidence actions.  Continuing to reject the same
                        # unsupported verified terminal would turn the
                        # no-progress guard into an accidental 50-turn loop.
                        # Close conservatively; the policy layer will retain
                        # the candidate in needs_review.
                        terminal = self._v3_uncertain_result(
                            candidate_uid,
                            cluster_uid,
                            "investigation_synthesis",
                            stop_reason="investigation_exhausted",
                            reasoning=(
                                "V3 stopped after two consecutive model iterations produced "
                                "no program-verified evidence-state change."
                            ),
                        )
                        return {"valid": True, "payload": terminal}
                    return {
                        "valid": False,
                        "error": (
                            "A verified V3 terminal requires at least one program-verified "
                            "FACT reference. Query a read-only tool, submit the resulting "
                            "TOOLFACT through submit_validator_evidence_claim, and cite the "
                            "accepted FACT in evidence_refs; otherwise return uncertain."
                        ),
                    }
            return {"valid": True, "payload": parsed.to_dict()}

        try:
            result = self._run_tool_conversation(
                messages,
                max_iterations=iteration_limit,
                trace_label=(
                    "validator_v3_investigation; call_kind=targeted_investigation; "
                    f"candidate_uid={candidate_uid[:120]}; "
                    f"validation_cluster_uid={cluster_uid[:120]}"
                ),
                base_tools_schema=v3_tools_schema,
                additional_tools_schema=[
                    action_tool_schema if action_mode else claim_tool_schema,
                    terminal_schema,
                ],
                terminal_tool_name=spec.final_tool_name,
                terminal_tool_handler=terminal_handler,
                terminal_tool_required=True,
                tool_executor=session_executor,
                # A repeated read-only query cannot add evidence.  Reject the
                # first repeat instead of replaying it for another model turn.
                max_identical_tool_calls=1,
                replay_identical_tool_result=False,
                preserve_reasoning_metadata=True,
            )
        except Exception as exc:
            logger.warning("Validator V3 investigation failed: %s", exc)
            result = {}
        self._merge_result_metadata(aggregate, result)
        aggregate["validator_api_call_count"] = int(aggregate.get("iterations", 0) or 0)
        aggregate["validator_investigation_trajectory_count"] = 1
        aggregate["validator_investigation_facts"] = investigation_facts
        aggregate["validator_investigation_claims"] = investigation_claims
        aggregate["validator_claim_verifications"] = claim_verifications
        aggregate["validator_tool_fact_catalog"] = tool_fact_catalog
        aggregate["validator_evidence_actions"] = action_records
        aggregate["validator_evidence_action_count"] = len(action_by_id)
        aggregate["validator_evidence_action_mode"] = action_mode
        aggregate["validator_investigation_tool_fact_count"] = len(tool_fact_catalog)
        aggregate["new_fact_count"] = len(investigation_facts)
        aggregate["consecutive_no_new_evidence_fact_iterations"] = (
            consecutive_no_evidence_fact_iterations
        )
        aggregate["validator_no_new_evidence_fact_stop"] = no_new_evidence_fact_stop
        parsed = self._extract_v3_result(
            result,
            candidate_uid=candidate_uid,
            cluster_uid=cluster_uid,
            expected_pass="investigation_synthesis",
            allowed_refs=sorted(allowed_refs),
        )
        self._finalize_slice_metadata(aggregate)
        if parsed is None:
            return AgentResponse(
                success=True,
                data=self._v3_uncertain_result(
                    candidate_uid,
                    cluster_uid,
                    "investigation_synthesis",
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
                    "Fast-path validation: use only the suspected finding and "
                    "Compact Evidence Pack. "
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
                    "description": (
                        "True only when a concrete guard, ownership, lock, reachability, "
                        "or contract fact blocks confirmation; uncertainty alone is false."
                    ),
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
