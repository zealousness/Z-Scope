"""Validation runner that orchestrates Validator calls and dispositions."""

from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from ...agents.validator_agent.agent import ValidatorAgent
from ...common.issue_identity import canonical_issue_key, deduplicate_issues
from ...framework.llm_client import LLMClient
from .evidence import (
    build_validation_evidence_pack,
    compact_validation_evidence_pack,
    compact_validation_finding,
    is_entry_root_dead_code_rejection,
    trim_code,
    validation_verdict,
)
from .pipeline import ValidationPipeline

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _PreparedValidation:
    index: int
    raw_issue: Dict[str, Any]
    issue_func: str
    issue_code: str
    evidence_pack: Dict[str, Any]


@dataclass
class _ValidationWorkerResult:
    index: int
    raw_issue: Dict[str, Any]
    issue_func: str
    success: bool
    val_data: Dict[str, Any] = field(default_factory=dict)
    error: Any = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class ValidationRunner:
    """Owns validation-stage orchestration around ``ValidationPipeline``."""

    def __init__(
        self,
        *,
        config: Any,
        llm_clients: Dict[str, LLMClient],
        validation_pipeline: ValidationPipeline,
        code_index: Any,
        snapshot_store: Any,
        get_tools: Callable[[Optional[str]], List[Any]],
        tool_policy_for_agent: Callable[[Optional[str]], Any],
        attach_agent_contract: Callable[[Dict[str, Any], str], None],
        remember_validation_result: Callable[[Dict[str, Any], str], None],
        issue_key_fn: Callable[[Dict[str, Any]], str] = canonical_issue_key,
        deduplicate_issues_fn: Callable[[List[Dict[str, Any]]], List[Dict[str, Any]]] = deduplicate_issues,
        validator_agent_factory: Callable[..., Any] = ValidatorAgent,
    ):
        self.config = config
        self.llm_clients = llm_clients
        self.validation_pipeline = validation_pipeline
        self.code_index = code_index
        self.snapshot_store = snapshot_store
        self.get_tools = get_tools
        self.tool_policy_for_agent = tool_policy_for_agent
        self.attach_agent_contract = attach_agent_contract
        self.remember_validation_result = remember_validation_result
        self.issue_key_fn = issue_key_fn
        self.deduplicate_issues = deduplicate_issues_fn
        self.validator_agent_factory = validator_agent_factory

    def run(self, state: Dict[str, Any]) -> None:
        new_issues = state.get("pending_new_issues", [])
        if not new_issues:
            return

        deduped_issues = self.deduplicate_issues(new_issues)
        if len(deduped_issues) != len(new_issues):
            merged_count = len(new_issues) - len(deduped_issues)
            logger.info("Merged %d duplicate candidate issue(s) before validation.", merged_count)
            state["notes"].append(f"Merged {merged_count} duplicate candidate issue(s) before validation.")
        new_issues = deduped_issues

        if not self._validator_enabled():
            self._mark_unvalidated(state, new_issues)
            state["pending_new_issues"] = []
            return

        prepared = []
        for index, raw_issue in enumerate(new_issues):
            item = self._prepare_issue_for_validation(state, raw_issue, index)
            if item is not None:
                prepared.append(item)

        validation_workers = self._validation_worker_count(len(prepared))
        if validation_workers <= 1:
            validator_agent = self._build_validator_agent() if prepared else None
            for item in prepared:
                result = self._validate_prepared_issue(item, validator_agent=validator_agent)
                self._apply_validation_worker_result(state, result)
        elif prepared:
            logger.info(
                "Validating %d issue(s) with %d validator worker(s).",
                len(prepared),
                validation_workers,
            )
            results: Dict[int, _ValidationWorkerResult] = {}
            with ThreadPoolExecutor(
                max_workers=validation_workers,
                thread_name_prefix="zscope-validator",
            ) as executor:
                future_to_item = {
                    executor.submit(self._validate_prepared_issue, item): item
                    for item in prepared
                }
                for future in as_completed(future_to_item):
                    item = future_to_item[future]
                    try:
                        results[item.index] = future.result()
                    except Exception as exc:
                        logger.exception(
                            "Validation worker crashed for issue %s in function %s.",
                            item.raw_issue.get("id"),
                            item.issue_func,
                        )
                        results[item.index] = _ValidationWorkerResult(
                            index=item.index,
                            raw_issue=item.raw_issue,
                            issue_func=item.issue_func,
                            success=False,
                            error=str(exc),
                        )
            for item in prepared:
                self._apply_validation_worker_result(state, results[item.index])

        state["pending_new_issues"] = []

    def _validation_worker_count(self, issue_count: int) -> int:
        if issue_count <= 1:
            return 1
        analysis_cfg = getattr(self.config, "analysis", None)
        if analysis_cfg is None:
            return 1
        configured = getattr(analysis_cfg, "validation_parallel_workers", 0)
        try:
            configured_workers = int(configured or 0)
        except (TypeError, ValueError):
            configured_workers = 0
        if configured_workers > 0:
            return max(1, min(issue_count, configured_workers))

        try:
            entry_workers = int(getattr(analysis_cfg, "parallel_workers", 1) or 1)
        except (TypeError, ValueError):
            entry_workers = 1
        auto_cap = 2 if entry_workers > 1 else 4
        return max(1, min(issue_count, auto_cap))

    def _mark_unvalidated(self, state: Dict[str, Any], new_issues: List[Dict[str, Any]]) -> None:
        logger.info("Validator agent disabled, marking %d issue(s) unvalidated.", len(new_issues))
        for raw_issue in new_issues:
            issue_func = self._issue_function(raw_issue, state)
            decision = self.validation_pipeline.apply_pre_validation_feedback(raw_issue, issue_func)
            if decision:
                if decision.report_bucket:
                    state[decision.report_bucket].append(raw_issue)
                continue
            score_data = self.validation_pipeline.score_components(raw_issue, {})
            outcome = self.validation_pipeline.apply_unvalidated(raw_issue, score_data)
            if outcome.report_bucket:
                state[outcome.report_bucket].append(raw_issue)

    def _prepare_issue_for_validation(
        self,
        state: Dict[str, Any],
        raw_issue: Dict[str, Any],
        index: int,
    ) -> Optional[_PreparedValidation]:
        issue_func = self._issue_function(raw_issue, state)
        logger.info("Validating issue: %s in %s", raw_issue.get("id", "unknown"), issue_func)

        decision = self.validation_pipeline.apply_pre_validation_feedback(raw_issue, issue_func)
        if decision:
            logger.info(
                "Issue %s handled before Validator by %s (%s).",
                raw_issue.get("id"),
                decision.rejection_source,
                decision.action,
            )
            self._record_prevalidation_decision(state, raw_issue, decision)
            if decision.report_bucket:
                state[decision.report_bucket].append(raw_issue)
            return None

        issue_code = self._issue_code(issue_func, state)
        evidence_pack = self._build_evidence_pack(raw_issue, state, issue_code)
        return _PreparedValidation(
            index=index,
            raw_issue=raw_issue,
            issue_func=issue_func,
            issue_code=issue_code,
            evidence_pack=evidence_pack,
        )

    def _validate_prepared_issue(
        self,
        item: _PreparedValidation,
        *,
        validator_agent: Optional[Any] = None,
    ) -> _ValidationWorkerResult:
        validator_agent = validator_agent or self._build_validator_agent()
        token_metadata = self._empty_token_metadata()
        val_resp = validator_agent.run(
            self._validator_input(item.raw_issue, item.issue_code, item.evidence_pack)
        )
        self._merge_response_metadata(token_metadata, getattr(val_resp, "metadata", {}) or {})

        if not val_resp.success:
            return _ValidationWorkerResult(
                index=item.index,
                raw_issue=item.raw_issue,
                issue_func=item.issue_func,
                success=False,
                error=val_resp.error,
                metadata=token_metadata,
            )

        val_data = self._normalize_worker_response(
            item,
            validator_agent,
            val_resp.data,
            token_metadata,
        )
        return _ValidationWorkerResult(
            index=item.index,
            raw_issue=item.raw_issue,
            issue_func=item.issue_func,
            success=True,
            val_data=val_data,
            metadata=token_metadata,
        )

    def _apply_validation_worker_result(
        self,
        state: Dict[str, Any],
        result: _ValidationWorkerResult,
    ) -> None:
        self._accumulate_token_metadata(state, result.metadata)
        raw_issue = result.raw_issue
        if not result.success:
            self._handle_validation_failure(state, raw_issue, result.issue_func, result.error)
            return

        val_data = result.val_data
        verdict = validation_verdict(val_data)
        score_data = self.validation_pipeline.score_components(raw_issue, val_data)
        outcome = self.validation_pipeline.apply_validator_result(
            raw_issue,
            val_data,
            verdict=verdict,
            score_data=score_data,
        )
        if outcome.report_bucket:
            state[outcome.report_bucket].append(raw_issue)
        if outcome.memory_status:
            self.remember_validation_result(raw_issue, outcome.memory_status)
        self._log_validation_outcome(raw_issue, val_data, verdict, outcome.final_score)

    def _normalize_worker_response(
        self,
        item: _PreparedValidation,
        validator_agent: Any,
        val_data: Dict[str, Any],
        token_metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        if is_entry_root_dead_code_rejection(val_data, item.evidence_pack):
            val_data = self._retry_entry_root_rejection_for_worker(
                item,
                validator_agent,
                val_data,
                token_metadata,
            )
        return val_data

    def _retry_entry_root_rejection_for_worker(
        self,
        item: _PreparedValidation,
        validator_agent: Any,
        val_data: Dict[str, Any],
        token_metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        raw_issue = item.raw_issue
        logger.info(
            "Retrying validation for issue %s because rejection conflicts with entry-root evidence.",
            raw_issue.get("id"),
        )
        retry_pack = dict(item.evidence_pack)
        retry_pack["mode"] = "tri_state_exploitability_validation_entry_root_retry"
        retry_pack["prior_validator_result"] = val_data
        retry_requirements = list(retry_pack.get("validation_requirements") or [])
        retry_requirements.insert(
            0,
            "Retry directive: the previous rejection used absence of callers/main/worker above the scan root as dead-code evidence. Re-evaluate only the concrete entry-to-sink path; do not require callers above current_analysis_entry.",
        )
        retry_pack["validation_requirements"] = retry_requirements
        retry_resp = validator_agent.run(self._validator_input(raw_issue, item.issue_code, retry_pack))
        self._merge_response_metadata(token_metadata, getattr(retry_resp, "metadata", {}) or {})
        if not retry_resp.success:
            logger.warning(
                "Entry-root validation retry failed for issue %s: %s",
                raw_issue.get("id"),
                retry_resp.error,
            )
            return val_data

        retry_data = retry_resp.data
        return retry_data

    @staticmethod
    def _empty_token_metadata() -> Dict[str, int]:
        return {
            "context_tokens": 0,
            "cumulative_prompt_tokens": 0,
            "cumulative_completion_tokens": 0,
            "cumulative_total_tokens": 0,
        }

    @staticmethod
    def _merge_response_metadata(target: Dict[str, Any], metadata: Dict[str, Any]) -> None:
        if not isinstance(metadata, dict):
            return

        def token_value(key: str, fallback_key: Optional[str] = None) -> int:
            value = metadata.get(key)
            if value is None and fallback_key:
                value = metadata.get(fallback_key)
            try:
                return int(value or 0)
            except (TypeError, ValueError):
                return 0

        target["context_tokens"] = int(target.get("context_tokens", 0) or 0) + token_value("context_tokens")
        target["cumulative_prompt_tokens"] = int(
            target.get("cumulative_prompt_tokens", 0) or 0
        ) + token_value("cumulative_prompt_tokens")
        target["cumulative_completion_tokens"] = int(
            target.get("cumulative_completion_tokens", 0) or 0
        ) + token_value("cumulative_completion_tokens")
        target["cumulative_total_tokens"] = int(
            target.get("cumulative_total_tokens", 0) or 0
        ) + token_value("cumulative_total_tokens", "context_tokens")
        for key in (
            "iterations",
            "tool_call_count",
            "validator_fast_path_attempted",
            "validator_fast_path_accepted",
        ):
            target[key] = int(target.get(key, 0) or 0) + token_value(key)

    @staticmethod
    def _accumulate_token_metadata(state: Dict[str, Any], metadata: Dict[str, Any]) -> None:
        if not isinstance(metadata, dict):
            return

        def token_value(key: str, fallback_key: Optional[str] = None) -> int:
            value = metadata.get(key)
            if value is None and fallback_key:
                value = metadata.get(fallback_key)
            try:
                return int(value or 0)
            except (TypeError, ValueError):
                return 0

        context_tokens = token_value("context_tokens")
        cumulative_prompt = token_value("cumulative_prompt_tokens")
        cumulative_completion = token_value("cumulative_completion_tokens")
        cumulative_total = token_value("cumulative_total_tokens", "context_tokens")
        state["total_context_tokens"] = int(state.get("total_context_tokens", 0) or 0) + context_tokens
        state["total_cumulative_prompt_tokens"] = (
            int(state.get("total_cumulative_prompt_tokens", 0) or 0) + cumulative_prompt
        )
        state["total_cumulative_completion_tokens"] = (
            int(state.get("total_cumulative_completion_tokens", 0) or 0) + cumulative_completion
        )
        state["total_cumulative_total_tokens"] = (
            int(state.get("total_cumulative_total_tokens", 0) or 0) + cumulative_total
        )
        for source_key, state_key in (
            ("iterations", "validation_iterations"),
            ("tool_call_count", "validation_tool_call_count"),
            ("validator_fast_path_attempted", "validator_fast_path_attempted"),
            ("validator_fast_path_accepted", "validator_fast_path_accepted"),
        ):
            try:
                value = int(metadata.get(source_key, 0) or 0)
            except (TypeError, ValueError):
                value = 0
            if value:
                state[state_key] = int(state.get(state_key, 0) or 0) + value

    @staticmethod
    def _record_prevalidation_decision(
        state: Dict[str, Any],
        raw_issue: Dict[str, Any],
        decision: Any,
    ) -> None:
        state["prevalidation_decision_count"] = int(state.get("prevalidation_decision_count", 0) or 0) + 1
        if decision.action == "audit_observation":
            state["static_audit_observation_count"] = int(state.get("static_audit_observation_count", 0) or 0) + 1
        if decision.action == "suppress":
            state["static_suppressed_count"] = int(state.get("static_suppressed_count", 0) or 0) + 1
        if raw_issue.get("candidate_source") == "clang_ast_cfg":
            state["clang_prevalidation_decision_count"] = int(
                state.get("clang_prevalidation_decision_count", 0) or 0
            ) + 1

    def _handle_validation_failure(
        self,
        state: Dict[str, Any],
        raw_issue: Dict[str, Any],
        issue_func: str,
        error: Any,
    ) -> None:
        logger.warning(
            "Validation failed for issue %s in function %s: %s",
            raw_issue.get("id"),
            issue_func,
            error,
        )
        outcome = self.validation_pipeline.apply_validation_failure(raw_issue, error)
        if outcome.report_bucket:
            state[outcome.report_bucket].append(raw_issue)

    def _build_validator_agent(self) -> Any:
        val_agent_cfg = next((a for a in self.config.project.agents if a.name == "validator_agent"), None)
        val_llm_ref = val_agent_cfg.llm_ref if val_agent_cfg and val_agent_cfg.llm_ref else "default"
        val_client = self.llm_clients.get(val_llm_ref, self.llm_clients["default"])
        return self.validator_agent_factory(
            val_client,
            self.get_tools("validator_agent"),
            tool_policy=self.tool_policy_for_agent("validator_agent"),
        )

    def _validator_enabled(self) -> bool:
        return any(a.name == "validator_agent" and a.enabled for a in self.config.project.agents)

    def _issue_function(self, raw_issue: Dict[str, Any], state: Dict[str, Any]) -> str:
        return str(raw_issue.get("function", state["agent_context"]["func_name"]))

    def _issue_code(self, issue_func: str, state: Dict[str, Any]) -> str:
        issue_code = state["agent_context"]["code"]
        if issue_func != state["agent_context"]["func_name"]:
            impl = self.code_index.get_function_impl(issue_func)
            if impl:
                issue_code = impl["code"]
        return issue_code

    def _build_evidence_pack(
        self,
        raw_issue: Dict[str, Any],
        state: Dict[str, Any],
        issue_code: str,
    ) -> Dict[str, Any]:
        return build_validation_evidence_pack(
            raw_issue,
            state,
            issue_code,
            code_index=self.code_index,
            snapshot_store=self.snapshot_store,
            score_components_fn=self.validation_pipeline.score_components,
            issue_key_fn=self.issue_key_fn,
        )

    def _validator_input(
        self,
        raw_issue: Dict[str, Any],
        issue_code: str,
        evidence_pack: Dict[str, Any],
    ) -> Dict[str, Any]:
        val_input = {
            "finding": json.dumps(
                compact_validation_finding(raw_issue),
                indent=2,
                ensure_ascii=False,
            ),
            "context_code": trim_code(issue_code, max_lines=180),
            "evidence_pack": compact_validation_evidence_pack(evidence_pack),
        }
        self.attach_agent_contract(val_input, "validator_agent")
        return val_input

    @staticmethod
    def _log_validation_outcome(
        raw_issue: Dict[str, Any],
        val_data: Dict[str, Any],
        verdict: str,
        final_score: float,
    ) -> None:
        status = str(raw_issue.get("validation_status") or "")
        validator_confidence = raw_issue.get("confidence", val_data.get("confidence_score"))
        if status == "validated":
            logger.info(
                "Issue %s VALIDATED by Validator; report_bucket=issues, "
                "validator_verdict=%s, validator_confidence=%s, final_score=%.2f.",
                raw_issue.get("id"),
                verdict,
                validator_confidence,
                final_score,
            )
        elif status == "needs_review":
            logger.info(
                "Issue %s kept as NEEDS_REVIEW by Validator; report_bucket=observations, "
                "validator_verdict=%s, validator_confidence=%s, final_score=%.2f.",
                raw_issue.get("id"),
                verdict,
                validator_confidence,
                final_score,
            )
        elif status == "uncertain" and verdict == "verified":
            logger.info(
                "Issue %s verified by Validator but kept as audit observation; "
                "report_bucket=observations, validator_confidence=%s, final_score=%.2f.",
                raw_issue.get("id"),
                validator_confidence,
                final_score,
            )
        elif status == "uncertain":
            logger.info(
                "Issue %s marked UNCERTAIN by Validator; report_bucket=observations, "
                "validator_confidence=%s, final_score=%.2f.",
                raw_issue.get("id"),
                validator_confidence,
                final_score,
            )
        else:
            logger.info(
                "Issue %s REJECTED by Validator; report_bucket=discarded, "
                "validator_verdict=%s, validator_confidence=%s, final_score=%.2f. Reason: %s",
                raw_issue.get("id"),
                verdict,
                validator_confidence,
                final_score,
                str(val_data.get("reasoning") or "")[:500],
            )
