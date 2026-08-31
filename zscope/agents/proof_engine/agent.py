"""Bounded P5 model adapter for the authoritative Proof Engine.

The model may summarize a frozen ValidatorResult v3 evidence slice or select
one of the finite EvidenceAction IDs supplied by the runtime. It cannot submit
facts, predicates, parameters, coverage declarations, or a terminal Candidate
disposition. Checker output and TerminalAuthority remain program-owned.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

from ..base import JsonOutputSpec, JsonToolAgent
from ...common.utils import extract_json_blocks
from ...common.validator_protocol import (
    VALIDATOR_PROTOCOL_VERSION as VALIDATOR_PROTOCOL_V3,
    VALIDATOR_RESULT_VERSION,
    ValidatorResultV3,
    parse_validator_result_v3,
    validator_result_schema_v3,
    validator_result_v3_failure_class,
)
from ...framework.base import AgentResponse
from ...framework.llm_client import LLMClient, ProviderFailureError
from ...tools.policy import ToolPolicy


logger = logging.getLogger(__name__)


class ProofEngineAgent(JsonToolAgent):
    """Evidence-only adapter with no proof or terminal authority."""

    def __init__(
        self,
        llm_client: LLMClient,
        tools: List[Any],
        tool_policy: Optional[ToolPolicy] = None,
    ) -> None:
        # ``tools`` is accepted for construction compatibility, but P5 never
        # exposes repository tools here. Only the per-session EvidenceAction
        # selector below is available to the model.
        del tools
        super().__init__(
            name="proof_engine",
            description="Selects bounded proof actions and summarizes frozen evidence.",
            llm_client=llm_client,
            tools=[],
            tool_policy=tool_policy,
        )

    def run(self, input_data: Dict[str, Any], max_retries: int = 0) -> AgentResponse:
        """Run one strict v3 completion or fail closed."""

        del max_retries
        evidence_slice = input_data.get("evidence_slice")
        if not isinstance(evidence_slice, dict):
            return AgentResponse(
                success=False,
                data={},
                error="proof_engine_requires_validator_evidence_slice_v3",
            )
        if evidence_slice.get("protocol_version") != VALIDATOR_PROTOCOL_V3:
            return AgentResponse(
                success=False,
                data={},
                error="proof_engine_rejects_legacy_validator_protocol",
            )
        return self._run_validator_v3_protocol(input_data)

    def _run_validator_v3_protocol(self, input_data: Dict[str, Any]) -> AgentResponse:
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
        metadata = self._initial_metadata(input_data)
        evidence_delta = evidence_slice.get("evidence_delta")
        new_fact_count = (
            self._v3_evidence_delta_count(evidence_delta)
            if expected_pass == "evidence_recheck"
            else 0
        )
        messages = self._messages(
            input_data,
            self._validator_v3_prompt(evidence_slice, expected_pass),
        )
        response, result = self._direct_v3_completion(
            messages,
            trace_label=(
                f"proof_engine_v3; pass={expected_pass}; call_kind={expected_pass}; "
                f"candidate_uid={candidate_uid[:120]}; "
                f"validation_cluster_uid={cluster_uid[:120]}; "
                f"new_fact_count={new_fact_count}"
            ),
            max_tokens=8192,
            candidate_uid=candidate_uid,
            cluster_uid=cluster_uid,
            expected_pass=expected_pass,
            allowed_refs=allowed_refs,
        )
        if response is None or result is None:
            self._finalize_metadata(metadata)
            return AgentResponse(
                success=False,
                data={},
                error="Proof Engine v3 direct structured completion failed.",
                metadata=metadata,
            )
        self._merge_direct_metadata(metadata, response, messages, result)
        parsed, failure_class = self._extract_v3_result(
            result,
            candidate_uid=candidate_uid,
            cluster_uid=cluster_uid,
            expected_pass=expected_pass,
            allowed_refs=allowed_refs,
        )
        finish_reason = str(result.get("finish_reason") or "")
        if parsed is None and finish_reason != "length":
            metadata["validator_repair_attempted"] = 1
            repair_messages = [
                *messages,
                {
                    "role": "user",
                    "content": (
                        "The prior response failed the fixed ValidatorResult v3 contract "
                        f"with class={failure_class}. Regenerate from the same frozen input. "
                        "Return every required schema field exactly once, no additional fields, "
                        "and obey all const, enum, evidence-reference, and cross-field bindings. "
                        "Do not repeat or discuss the prior response."
                    ),
                },
            ]
            repair_response, repair_result = self._direct_v3_completion(
                repair_messages,
                trace_label=(
                    f"proof_engine_v3; pass={expected_pass}; "
                    "call_kind=contract_regeneration; "
                    f"candidate_uid={candidate_uid[:120]}; "
                    f"validation_cluster_uid={cluster_uid[:120]}; "
                    f"failure_class={failure_class}"
                ),
                max_tokens=8192,
                candidate_uid=candidate_uid,
                cluster_uid=cluster_uid,
                expected_pass=expected_pass,
                allowed_refs=allowed_refs,
            )
            if repair_response is not None and repair_result is not None:
                self._merge_direct_metadata(
                    metadata,
                    repair_response,
                    repair_messages,
                    repair_result,
                )
                repaired, repair_failure_class = self._extract_v3_result(
                    repair_result,
                    candidate_uid=candidate_uid,
                    cluster_uid=cluster_uid,
                    expected_pass=expected_pass,
                    allowed_refs=allowed_refs,
                )
                if repaired is not None:
                    parsed = repaired
                    response = repair_response
                    result = repair_result
                    finish_reason = str(repair_result.get("finish_reason") or "")
                    failure_class = "none"
                    metadata["validator_repair_accepted"] = 1
                else:
                    failure_class = repair_failure_class
        if parsed is None:
            stop_reason = "output_truncated" if finish_reason == "length" else "malformed_output"
            parsed = self._v3_uncertain_result(
                candidate_uid,
                cluster_uid,
                expected_pass,
                stop_reason=stop_reason,
                reasoning=(
                    "The bounded Proof Engine adapter reached the provider output limit."
                    if stop_reason == "output_truncated"
                    else "The bounded Proof Engine adapter returned malformed structured output."
                ),
            )
            metadata["validator_protocol_exhausted"] = 1
            metadata["validator_stop_reason"] = stop_reason.upper()
            metadata["validator_contract_failure_class"] = failure_class
            metadata["validator_contract_failure_count"] = 1
        metadata["validator_protocol"] = VALIDATOR_PROTOCOL_V3
        metadata["validator_pass"] = expected_pass
        metadata["finish_reason"] = finish_reason
        self._finalize_metadata(metadata)
        return AgentResponse(success=True, data=parsed, metadata=metadata)

    def investigate(
        self,
        input_data: Dict[str, Any],
        *,
        max_iterations: int = 50,
        evidence_actions: Optional[Iterable[Mapping[str, Any]]] = None,
        evidence_action_executor: Optional[Callable[[str], Dict[str, Any]]] = None,
    ) -> AgentResponse:
        """Let the model select only system-bound EvidenceAction IDs."""

        evidence_slice = input_data.get("evidence_slice")
        if (
            not isinstance(evidence_slice, dict)
            or evidence_slice.get("protocol_version") != VALIDATOR_PROTOCOL_V3
        ):
            return AgentResponse(
                success=False,
                data={},
                error="proof_engine_requires_validator_evidence_slice_v3",
            )
        action_records = [
            dict(value) for value in evidence_actions or () if isinstance(value, Mapping)
        ]
        action_by_id = {
            str(value.get("action_id") or ""): value
            for value in action_records
            if str(value.get("action_id") or "")
        }
        if (
            evidence_action_executor is None
            or not action_by_id
            or len(action_by_id) != len(action_records)
        ):
            return AgentResponse(
                success=False,
                data={},
                error="proof_engine_requires_unique_system_bound_evidence_actions",
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
        iteration_limit = max(1, min(50, int(max_iterations or 50)))
        spec = self._validation_json_output_spec_v3(
            candidate_uid=candidate_uid,
            cluster_uid=cluster_uid,
            expected_pass="investigation_synthesis",
            allowed_refs=sorted(allowed_refs),
        )
        terminal_schema = self._final_json_tool_schema(spec)
        action_tool_name = "execute_proof_evidence_action"
        action_tool_schema = {
            "type": "function",
            "function": {
                "name": action_tool_name,
                "description": (
                    "Select one immutable EvidenceAction. Subject, region, predicate, "
                    "parameters, hashes and verifier are program-bound."
                ),
                "parameters": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {"action_id": {"type": "string", "enum": sorted(action_by_id)}},
                    "required": ["action_id"],
                },
            },
        }
        prompt = (
            "P5 Proof Engine action-selection session. Select only an action_id from the "
            "immutable catalog. Do not submit facts, predicates, parameters, coverage, "
            "candidate status, or a terminal disposition. The program independently runs "
            "the provider and Checker. Stop immediately when the program returns a terminal "
            "authority result; otherwise return uncertain after the available actions are "
            "exhausted. Catalog: "
            + json.dumps(action_records, ensure_ascii=False, sort_keys=True)
            + "\n\n"
            + json.dumps(evidence_slice, ensure_ascii=False, separators=(",", ":"))
        )
        messages = self._messages(input_data, prompt)
        executed: set[str] = set()
        accepted_facts: List[Dict[str, Any]] = []
        action_results: List[Dict[str, Any]] = []
        consecutive_no_fact_iterations = 0
        progress_at_iteration_start = 0
        last_started_iteration = 0
        no_progress_stop = False
        programmatic_terminal_payload: Optional[Dict[str, Any]] = None

        def session_executor(name: str, args: Any) -> Dict[str, Any]:
            nonlocal programmatic_terminal_payload
            if name != action_tool_name:
                return {
                    "success": False,
                    "error": "proof_engine_tool_not_exposed",
                    "allowed_tools": [action_tool_name, spec.final_tool_name],
                }
            if not isinstance(args, dict) or set(args) != {"action_id"}:
                return {"success": False, "error": "evidence_action_id_only"}
            action_id = str(args.get("action_id") or "")
            if action_id not in action_by_id:
                return {"success": False, "error": "unknown_evidence_action"}
            if action_id in executed:
                return {"success": False, "error": "duplicate_evidence_action"}
            if no_progress_stop:
                return {"success": False, "error": "proof_engine_no_progress_stop"}
            executed.add(action_id)
            try:
                outcome = evidence_action_executor(action_id)
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
            action_results.append(dict(outcome))
            fact = outcome.get("verified_fact")
            if (
                str(outcome.get("status") or "") == "verified_true"
                and isinstance(fact, dict)
                and str(fact.get("fact_uid") or "")
            ):
                fact_uid = str(fact["fact_uid"])
                if not any(
                    str(value.get("fact_uid") or "") == fact_uid for value in accepted_facts
                ):
                    accepted_facts.append(dict(fact))
                allowed_refs.add(fact_uid)
            authority = outcome.get("terminal_authority")
            authority = authority if isinstance(authority, Mapping) else {}
            disposition = str(authority.get("disposition") or "")
            if authority.get("terminal") is True and disposition in {
                "confirmed",
                "rejected_with_proof",
                "needs_review",
            }:
                fact_uid = str(fact.get("fact_uid") or "") if isinstance(fact, dict) else ""
                programmatic_terminal_payload = {
                    "schema_version": VALIDATOR_RESULT_VERSION,
                    "candidate_uid": candidate_uid,
                    "validation_cluster_uid": cluster_uid,
                    "pass": "investigation_synthesis",
                    "verdict": (
                        "verified"
                        if disposition == "confirmed"
                        else "rejected" if disposition == "rejected_with_proof" else "uncertain"
                    ),
                    "reasoning": (
                        "The program-owned Checker and TerminalAuthority completed the cluster; "
                        "no further model or tool call is authorized."
                    ),
                    "positive_evidence": (
                        [fact_uid] if disposition == "confirmed" and fact_uid else []
                    ),
                    "negative_evidence": (
                        [fact_uid] if disposition == "rejected_with_proof" and fact_uid else []
                    ),
                    "evidence_refs": [fact_uid] if fact_uid else [],
                    "blocking_negative_evidence": disposition == "rejected_with_proof",
                    "missing_fact_request": None,
                    "stop_reason": (
                        "decision_complete"
                        if disposition in {"confirmed", "rejected_with_proof"}
                        else "investigation_exhausted"
                    ),
                }
            return {
                "success": True,
                "action_id": action_id,
                "status": outcome.get("status"),
                "reason_code": outcome.get("reason_code"),
                "verified_fact": fact if isinstance(fact, dict) else None,
                "certificate_ref": outcome.get("certificate_ref"),
                "terminal_authority": authority,
            }

        def start_model_iteration(iteration: int) -> bool:
            nonlocal consecutive_no_fact_iterations
            nonlocal last_started_iteration
            nonlocal no_progress_stop
            nonlocal progress_at_iteration_start
            normalized = max(1, int(iteration or 1))
            if normalized <= last_started_iteration:
                return no_progress_stop
            current = len(accepted_facts)
            if last_started_iteration:
                if current > progress_at_iteration_start:
                    consecutive_no_fact_iterations = 0
                else:
                    consecutive_no_fact_iterations += 1
            progress_at_iteration_start = current
            last_started_iteration = normalized
            no_progress_stop = consecutive_no_fact_iterations >= 2
            return no_progress_stop

        setattr(session_executor, "_zscope_start_iteration", start_model_iteration)
        setattr(session_executor, "_zscope_set_iteration", lambda _iteration: None)
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
            if parsed.verdict in {"verified", "rejected"}:
                accepted_refs = {
                    str(fact.get("fact_uid") or "")
                    for fact in accepted_facts
                    if str(fact.get("fact_uid") or "")
                }
                if not accepted_refs.intersection(parsed.evidence_refs):
                    return {
                        "valid": False,
                        "error": "terminal proof result requires a program-verified FACT reference",
                    }
            return {"valid": True, "payload": parsed.to_dict()}

        try:
            result = self._run_tool_conversation(
                messages,
                max_iterations=iteration_limit,
                trace_label=(
                    "proof_engine_v3_action_selection; call_kind=targeted_investigation; "
                    f"candidate_uid={candidate_uid[:120]}; "
                    f"validation_cluster_uid={cluster_uid[:120]}"
                ),
                base_tools_schema=[],
                additional_tools_schema=[action_tool_schema, terminal_schema],
                terminal_tool_name=spec.final_tool_name,
                terminal_tool_handler=terminal_handler,
                terminal_tool_required=True,
                tool_executor=session_executor,
                max_identical_tool_calls=1,
                replay_identical_tool_result=False,
                preserve_reasoning_metadata=True,
            )
        except Exception as exc:
            logger.warning("Proof Engine action-selection session failed: %s", exc)
            result = {}
        metadata = self._initial_metadata(input_data)
        self._merge_conversation_metadata(metadata, result)
        metadata.update(
            {
                "validator_investigation_trajectory_count": 1,
                "validator_evidence_actions": action_records,
                "validator_evidence_action_count": len(action_by_id),
                "validator_evidence_action_mode": True,
                "validator_action_results": action_results,
                "validator_investigation_facts": accepted_facts,
                "new_fact_count": len(accepted_facts),
                "consecutive_no_new_evidence_fact_iterations": consecutive_no_fact_iterations,
                "validator_no_new_evidence_fact_stop": no_progress_stop,
            }
        )
        parsed, failure_class = self._extract_v3_result(
            result,
            candidate_uid=candidate_uid,
            cluster_uid=cluster_uid,
            expected_pass="investigation_synthesis",
            allowed_refs=sorted(allowed_refs),
        )
        if parsed is None:
            metadata["validator_contract_failure_class"] = failure_class
            metadata["validator_contract_failure_count"] = 1
        self._finalize_metadata(metadata)
        if parsed is None:
            parsed = self._v3_uncertain_result(
                candidate_uid,
                cluster_uid,
                "investigation_synthesis",
                stop_reason="investigation_exhausted",
                reasoning="The finite EvidenceAction session ended without Checker closure.",
            )
        return AgentResponse(success=True, data=parsed, metadata=metadata)

    @staticmethod
    def _initial_metadata(input_data: Mapping[str, Any]) -> Dict[str, Any]:
        return {
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
    def _validator_v3_prompt(evidence_slice: Dict[str, Any], validation_pass: str) -> str:
        return (
            f"Proof Engine v3 pass={validation_pass}. Use only the frozen evidence slice. "
            "Do not invent facts, references, candidate IDs, or terminal authority. Return "
            f"exactly one object matching schema_version={VALIDATOR_RESULT_VERSION}. "
            "Cross-field coherence is mandatory: when missing_fact_request is an object, "
            "verdict must be uncertain and stop_reason must be missing_fact; otherwise "
            "missing_fact_request must be null and stop_reason must not be missing_fact.\n\n"
            + json.dumps(evidence_slice, ensure_ascii=False, separators=(",", ":"))
        )

    def _direct_v3_completion(
        self,
        messages: List[Dict[str, Any]],
        *,
        trace_label: str,
        max_tokens: int,
        candidate_uid: str,
        cluster_uid: str,
        expected_pass: str,
        allowed_refs: Iterable[str],
    ) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        chat_completion = getattr(self.llm_client, "chat_completion", None)
        if not callable(chat_completion):
            return None, None
        spec = self._validation_json_output_spec_v3(
            candidate_uid=candidate_uid,
            cluster_uid=cluster_uid,
            expected_pass=expected_pass,
            allowed_refs=allowed_refs,
        )
        response_format = (
            self._json_response_format(spec)
            if bool(getattr(self.llm_client, "supports_structured_output", False))
            else None
        )
        if response_format:
            response_format["json_schema"]["strict"] = True
        kwargs: Dict[str, Any] = {
            "max_tokens": max_tokens,
            "trace_agent": self.name,
            "trace_label": trace_label,
            "trace_iteration": 1,
        }
        if response_format:
            kwargs["response_format"] = response_format
        else:
            kwargs["tools"] = [self._final_json_tool_schema(spec)]
            kwargs["tool_choice"] = {
                "type": "function",
                "function": {"name": spec.final_tool_name},
            }
        try:
            response = chat_completion(messages, **kwargs)
        except ProviderFailureError:
            raise
        except Exception as exc:
            logger.warning("Proof Engine v3 direct completion failed: %s", exc)
            return None, None
        choices = response.get("choices") or []
        if not choices or not isinstance(choices[0], dict):
            return response, None
        choice = choices[0]
        message = choice.get("message")
        if not isinstance(message, dict):
            message = {"role": "assistant", "content": ""}
        return response, {
            "content": str(message.get("content") or ""),
            "message": message,
            "conversation": [*messages, message],
            "finish_reason": choice.get("finish_reason"),
            "provider_model": response.get("model"),
        }

    def _extract_v3_result(
        self,
        result: Mapping[str, Any],
        *,
        candidate_uid: str,
        cluster_uid: str,
        expected_pass: str,
        allowed_refs: List[str],
    ) -> Tuple[Optional[Dict[str, Any]], str]:
        if "terminal_tool_valid" in result and result.get("terminal_tool_valid") is not True:
            return None, "terminal_tool_invalid"
        values: List[Any] = []
        payload = result.get("terminal_tool_payload")
        if result.get("terminal_tool_valid") is True and isinstance(payload, dict):
            values.append(payload)
        else:
            spec = self._validation_json_output_spec_v3()
            values.extend(
                self._final_tool_payloads(
                    dict(result),
                    result.get("conversation") or [],
                    spec,
                )
            )
        texts = [str(result.get("content") or "")]
        for message in reversed(list(result.get("conversation") or [])):
            if isinstance(message, dict) and message.get("role") == "assistant":
                texts.append(str(message.get("content") or ""))
        for text in (value for value in texts if value):
            values.extend(extract_json_blocks(text))
        failure_class = "structured_payload_missing"
        for value in values:
            parsed = parse_validator_result_v3(
                value,
                candidate_uid=candidate_uid,
                validation_cluster_uid=cluster_uid,
                expected_pass=expected_pass,
                allowed_evidence_refs=allowed_refs,
            )
            if parsed is not None:
                return parsed.to_dict(), "none"
            if failure_class == "structured_payload_missing":
                failure_class = validator_result_v3_failure_class(
                    value,
                    candidate_uid=candidate_uid,
                    validation_cluster_uid=cluster_uid,
                    expected_pass=expected_pass,
                    allowed_evidence_refs=allowed_refs,
                )
        return None, failure_class

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
        candidate_uid: str = "",
        cluster_uid: str = "",
        expected_pass: str = "",
        allowed_refs: Optional[Iterable[str]] = None,
    ) -> JsonOutputSpec:
        return JsonOutputSpec(
            type_name="validator_result_v3",
            schema=validator_result_schema_v3(
                candidate_uid=candidate_uid,
                validation_cluster_uid=cluster_uid,
                expected_pass=expected_pass,
                allowed_evidence_refs=allowed_refs,
            ),
            final_tool_name="emit_validator_result_v3",
            final_tool_description="Emit the strict evidence-only ValidatorResult v3 object.",
            validator=lambda data: (
                parse_validator_result_v3(
                    data,
                    candidate_uid=candidate_uid,
                    validation_cluster_uid=cluster_uid,
                    expected_pass=expected_pass,
                    allowed_evidence_refs=allowed_refs,
                )
                is not None
            ),
            metadata_prefix="validator",
        )

    @staticmethod
    def _merge_direct_metadata(
        metadata: Dict[str, Any],
        response: Dict[str, Any],
        messages: List[Dict[str, Any]],
        result: Mapping[str, Any],
    ) -> None:
        usage = response.get("usage")
        usage = usage if isinstance(usage, Mapping) else {}
        prompt = int(usage.get("prompt_tokens", 0) or 0)
        completion = int(usage.get("completion_tokens", 0) or 0)
        metadata["context_tokens"] = int(metadata.get("context_tokens", 0) or 0) + int(
            LLMClient.estimate_tokens(messages)
        )
        metadata["cumulative_prompt_tokens"] = (
            int(metadata.get("cumulative_prompt_tokens", 0) or 0) + prompt
        )
        metadata["cumulative_completion_tokens"] = (
            int(metadata.get("cumulative_completion_tokens", 0) or 0) + completion
        )
        metadata["cumulative_total_tokens"] = (
            int(metadata.get("cumulative_total_tokens", 0) or 0) + prompt + completion
        )
        metadata["iterations"] = int(metadata.get("iterations", 0) or 0) + 1
        metadata["validator_api_call_count"] = (
            int(metadata.get("validator_api_call_count", 0) or 0) + 1
        )
        metadata["validator_turn_count"] = int(metadata.get("validator_turn_count", 0) or 0) + 1
        metadata["finish_reason"] = str(result.get("finish_reason") or "")

    @staticmethod
    def _merge_conversation_metadata(metadata: Dict[str, Any], result: Mapping[str, Any]) -> None:
        for key in (
            "context_tokens",
            "cumulative_prompt_tokens",
            "cumulative_completion_tokens",
            "cumulative_total_tokens",
            "iterations",
            "tool_call_count",
        ):
            metadata[key] = int(result.get(key, 0) or 0)
        metadata["validator_api_call_count"] = int(result.get("iterations", 0) or 0)
        metadata["validator_turn_count"] = int(result.get("iterations", 0) or 0)

    @staticmethod
    def _finalize_metadata(metadata: Dict[str, Any]) -> None:
        metadata["validator_session_count"] = max(
            1, int(metadata.get("validator_session_count", 0) or 0)
        )
        metadata.setdefault("validator_repair_attempted", 0)
        metadata.setdefault("validator_repair_accepted", 0)
        metadata.setdefault("validator_length_retry_count", 0)
