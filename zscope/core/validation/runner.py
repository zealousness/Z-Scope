"""Validation runner that orchestrates Validator calls and dispositions."""

from __future__ import annotations

import json
import logging
from typing import Any, Callable, Dict, List, Optional

from ...agents.validator_agent.agent import ValidatorAgent
from ...common.issue_identity import canonical_issue_key, deduplicate_issues
from ...framework.llm_client import LLMClient
from .evidence import (
    build_validation_evidence_pack,
    is_entry_root_contract_scope_rejection,
    is_entry_root_dead_code_rejection,
    validation_verdict,
)
from .pipeline import ValidationPipeline

logger = logging.getLogger(__name__)


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

        validator_agent = self._build_validator_agent()
        for raw_issue in new_issues:
            self._validate_one_issue(state, raw_issue, validator_agent)

        state["pending_new_issues"] = []

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

    def _validate_one_issue(self, state: Dict[str, Any], raw_issue: Dict[str, Any], validator_agent: Any) -> None:
        issue_func = self._issue_function(raw_issue, state)
        logger.info("Validating issue: %s in %s", raw_issue.get("id", "unknown"), issue_func)

        decision = self.validation_pipeline.apply_pre_validation_feedback(raw_issue, issue_func)
        if decision:
            logger.info("Issue %s suppressed by %s.", raw_issue.get("id"), decision.rejection_source)
            if decision.report_bucket:
                state[decision.report_bucket].append(raw_issue)
            return

        issue_code = self._issue_code(issue_func, state)
        evidence_pack = self._build_evidence_pack(raw_issue, state, issue_code)
        val_resp = validator_agent.run(self._validator_input(raw_issue, issue_code, evidence_pack))

        if not val_resp.success:
            self._handle_validation_failure(state, raw_issue, issue_func, val_resp.error)
            return

        val_data = self._normalize_successful_response(
            raw_issue,
            issue_code,
            evidence_pack,
            validator_agent,
            val_resp.data,
        )
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

    def _normalize_successful_response(
        self,
        raw_issue: Dict[str, Any],
        issue_code: str,
        evidence_pack: Dict[str, Any],
        validator_agent: Any,
        val_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        if is_entry_root_dead_code_rejection(val_data, evidence_pack):
            val_data = self._retry_entry_root_rejection(raw_issue, issue_code, evidence_pack, validator_agent, val_data)
        if is_entry_root_contract_scope_rejection(val_data, evidence_pack):
            val_data = dict(val_data)
            val_data["verdict"] = "uncertain"
            val_data["is_valid"] = False
            val_data["finding_kind"] = "needs_review"
            val_data["reasoning"] = (
                str(val_data.get("reasoning") or "")
                + " Validator rejection is narrower than the selected external entry contract; "
                "the concrete entry-to-sink path remains reachable, so the finding is retained "
                "as needs_review instead of being discarded."
            ).strip()
        return val_data

    def _retry_entry_root_rejection(
        self,
        raw_issue: Dict[str, Any],
        issue_code: str,
        evidence_pack: Dict[str, Any],
        validator_agent: Any,
        val_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        logger.info(
            "Retrying validation for issue %s because rejection conflicts with entry-root evidence.",
            raw_issue.get("id"),
        )
        retry_pack = dict(evidence_pack)
        retry_pack["mode"] = "tri_state_exploitability_validation_entry_root_retry"
        retry_pack["prior_validator_result"] = val_data
        retry_requirements = list(retry_pack.get("validation_requirements") or [])
        retry_requirements.insert(
            0,
            "Retry directive: the previous rejection used absence of callers/main/worker above the scan root as dead-code evidence. Re-evaluate only the concrete entry-to-sink path; do not require callers above current_analysis_entry.",
        )
        retry_pack["validation_requirements"] = retry_requirements
        retry_resp = validator_agent.run(self._validator_input(raw_issue, issue_code, retry_pack))
        if not retry_resp.success:
            logger.warning(
                "Entry-root validation retry failed for issue %s: %s",
                raw_issue.get("id"),
                retry_resp.error,
            )
            return val_data

        retry_data = retry_resp.data
        if is_entry_root_dead_code_rejection(retry_data, retry_pack):
            retry_data = dict(retry_data)
            retry_data["verdict"] = "uncertain"
            retry_data["is_valid"] = False
            retry_data["finding_kind"] = "needs_review"
            retry_data["reasoning"] = (
                str(retry_data.get("reasoning") or "")
                + " Validator rejection conflicts with header/API scan-root evidence; "
                "zero callers above the selected entry cannot by itself prove dead code, "
                "so the finding is retained as needs_review."
            ).strip()
        return retry_data

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
            "finding": json.dumps(raw_issue, indent=2, ensure_ascii=False),
            "context_code": issue_code,
            "evidence_pack": evidence_pack,
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
        if raw_issue["validation_status"] in {"validated", "needs_review"}:
            logger.info(
                "Issue %s VALIDATED with confidence %s",
                raw_issue.get("id"),
                raw_issue["confidence"],
            )
        elif raw_issue["validation_status"] == "uncertain" and verdict == "verified":
            logger.info(
                "Issue %s verified by validator but final_score %.2f is below report threshold.",
                raw_issue.get("id"),
                final_score,
            )
        elif raw_issue["validation_status"] == "uncertain":
            logger.info("Issue %s marked UNCERTAIN by Validator; kept as observation.", raw_issue.get("id"))
        else:
            logger.info(
                "Issue %s REJECTED by Validator, discarding. Reason: %s",
                raw_issue.get("id"),
                str(val_data.get("reasoning") or "")[:500],
            )
