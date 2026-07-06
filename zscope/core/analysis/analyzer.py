"""
Main analyzer logic for Z-SCOPE.
Orchestrates the analysis process using LLM, CodeIndex, and SnapshotStore.
"""

import json
import hashlib
import logging
import time
import datetime
import re
import threading
import uuid
from collections import deque
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, cast

from ...config.config import ZScopeConfig
from ...config.user_config_store import UserConfigStore
from ...retrieval.code_index import CodeIndex
from ...snapshots.store import SnapshotStore
from ..candidates.evidence import (
    SemanticOverlayCompiler,
    annotate_candidate_evidence,
    backend_profile_for_code_index,
)
from ..candidates.adapters import (
    attach_unified_secondary_evidence,
    candidate_file_line,
    candidate_function_names,
    candidate_source_name,
    candidate_symbols,
    clang_matcher_fact_to_candidate,
    clang_tooling_matcher_candidates_from_evidence,
    compact_clang_tooling_evidence,
    dedupe_rule_candidates,
    defect_class_from_clang_matcher_fact,
    defect_classes_compatible,
    merge_rule_candidate_duplicate,
    merge_unified_evidence_candidates,
    parse_location_file_line,
    rule_candidate_dedup_key,
    skill_for_matcher_defect,
    unified_candidates_may_refer_same_issue,
)
from ..candidates.backend_signals import (
    clang_pair_row_to_candidate,
    joern_rule_match_to_candidate,
    resource_release_pairs_from_overlay,
)
from ...orchestration.agent_policy import (
    agent_system_prompt,
    attach_agent_contract,
    compact_subagent_item,
    compact_subagent_items,
    compact_subagent_reports,
    route_vulnerability_skills_with_llm,
    subagent_llm_ref_for_ticket,
    tool_audit_log_path,
    tool_policy_for_agent,
)
from ..candidates.pipeline import CandidatePipeline
from ..candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
from ...retrieval.clang_tooling_evidence import ClangToolingEvidenceProvider
from ..candidates.regex import RegexCandidateGenerator
from ...semantics.models import LocalPatternSemantics
from ..candidates.graph import GraphCandidateGenerator
from ...orchestration.history_reconciler import HistoryReconciler
from ..candidates.svf_value_flow import SvfValueFlowCandidateGenerator
from ...tools.policy import ToolPolicy, deny_sensitive_paths_hook
from ...tools.runtime import ToolsRuntime
from ..validation.pipeline import ValidationPipeline, preserve_issue_location
from ..validation.runner import ValidationRunner
from ..validation.evidence import (
    build_validation_evidence_pack,
    category_validation_requirements,
    compact_snapshot,
    is_entry_root_dead_code_rejection,
    trim_code,
    validation_verdict,
)
from ...semantics.inference import (
    LocalPatternSemanticBuilder,
)
from ...semantics.user_config_context import relevant_user_config_context
from ...snapshots.policy import (
    build_lightweight_snapshot,
    build_trivial_snapshot,
    is_lightweight_snapshot_candidate,
    is_trivial_function,
    trivial_suspicious_points,
)
from ...framework.llm_client import LLMClient
from ...agents.semantic_modeler.agent import SemanticModeler
from ...agents.vulnerability_analyzer.agent import VulnerabilityAnalyzer
from ...reporting.report import FinalReport, Issue, ReportGenerator
from ...common.issue_identity import (
    canonical_issue_key,
    deduplicate_semantic_issues_programmatic,
    deduplicate_issues,
    flatten_issue_text,
    issue_call_path_signature,
    issue_resource_signature,
    issue_rank,
    issue_sink_signature,
    issues_may_share_root_cause,
    normalize_issue_category,
    normalize_issue_key_part,
    parse_issue_location,
    semantic_category_family,
    semantic_related_cluster_keys,
    semantic_root_cause_key,
    merge_duplicate_issue,
)
from ...reporting.assembler import ReportAssembler
from ...orchestration.workflow_runner import WorkflowRunner
from ...common.utils import extract_json_blocks, validate_json_schema
from ..._version import __version__
from ...orchestration.specs import SpecRegistry, WorkflowStep
from ...orchestration.workflow_executor import WorkflowExecutor, WorkflowStepHandler
from ...orchestration.subagents import SubAgentOrchestrator
from ...orchestration.candidates import CandidateLedger
from ...orchestration.budget import EffectiveBudget, RiskBudgetPlanner
from ...orchestration.skill_selection import SkillSelection, select_vulnerability_skills

logger = logging.getLogger(__name__)

DEFAULT_SCAN_STEP_IDS = (
    "premodel_reachable_callees",
    "model_entry",
    "focused_subagent_planning",
    "vulnerability_mining",
    "validate_findings",
    "persist_report",
)

class Analyzer:
    """
    Main analyzer class.
    """

    def __init__(self, config: ZScopeConfig, code_index: Optional[CodeIndex] = None,
                 snapshot_store: Optional[SnapshotStore] = None,
                 user_config: Optional[UserConfigStore] = None,
                 force_ignore_history: bool = False,
                 maintain_mode: bool = False,
                 candidate_ledger: Optional[CandidateLedger] = None,
                 shared_local_pattern_semantics: Optional[LocalPatternSemantics] = None,
                 shared_semantic_overlay: Optional[Dict[str, Any]] = None,
                 llm_clients: Optional[Dict[str, LLMClient]] = None,
                 write_root_reports: bool = True):
        self.config = config
        self.write_root_reports = write_root_reports
        self.code_index = code_index or CodeIndex(
            config.project.project_root,
            config.project.compile_commands_path,
            source_root=config.project.source_root,
            indexing_config=config.indexing,
            priority_functions=[config.project.entry_function] if config.project.entry_function else None,
            include_paths=config.project.include_paths,
            exclude_paths=config.project.exclude_paths,
            svf_entry_functions=[config.project.entry_function] if config.project.entry_function else None,
            svf_parallel_workers=config.analysis.parallel_workers,
        )
        self.snapshot_store = snapshot_store or SnapshotStore(Path(config.analysis.snapshot_dir))
        self.force_ignore_history = force_ignore_history
        self.maintain_mode = maintain_mode
        self.history_reconciler = HistoryReconciler(
            self.snapshot_store,
            force_ignore_history=self.force_ignore_history,
        )
        db_dir = Path(config.analysis.user_config_db) if config.analysis.user_config_db else Path(config.analysis.snapshot_dir)
        self.user_config = user_config or UserConfigStore(db_dir)
        self.validation_pipeline = ValidationPipeline(self.user_config)
        self.candidate_pipeline = CandidatePipeline(
            local_detector=self._detect_local_rule_candidates,
            graph_detector=self._detect_graph_rule_candidates,
            backend_detector=self._detect_backend_signal_candidates,
            unified_merger=self._merge_unified_evidence_candidates,
            budget_refresher=self._refresh_effective_budget,
            candidate_persister=self._persist_candidate_ir_records,
        )
        self._owns_llm_clients = llm_clients is None
        if llm_clients is not None:
            self.llm_clients = llm_clients
        else:
            self.llm_clients: Dict[str, LLMClient] = {}
            for name, llm_cfg in config.llms.items():
                self.llm_clients[name] = LLMClient(
                    api_key=llm_cfg.api_key,
                    base_url=getattr(llm_cfg, "base_urls", None) or llm_cfg.base_url,
                    models=llm_cfg.models,
                    timeout=llm_cfg.timeout,
                    max_retries=llm_cfg.max_retries,
                    max_tokens=llm_cfg.max_tokens,
                    base_url_rate_limit_per_minute=getattr(
                        llm_cfg, "base_url_rate_limit_per_minute", 0
                    ),
                    base_url_max_concurrent_requests=getattr(
                        llm_cfg, "base_url_max_concurrent_requests", 0
                    ),
                    supports_structured_output=getattr(
                        llm_cfg, "supports_structured_output", False
                    ),
                )
        self.validation_runner = self._make_validation_runner()
        self.report_generator = ReportGenerator(config.project.project_root)
        self.report_assembler = ReportAssembler(
            self.report_generator,
            self.snapshot_store,
            resolve_issue_locations=self._resolve_issue_locations,
            deduplicate_observations=self._deduplicate_candidate_issues,
            deduplicate_report_issues=self._deduplicate_report_issues,
            metadata_factory=self._build_workflow_metadata,
        )
        self.tools_runtime = ToolsRuntime(
            self.code_index,
            self.snapshot_store,
            self.user_config,
            tool_policy=ToolPolicy.allow_all(
                pre_hooks=[deny_sensitive_paths_hook],
                audit_log_path=self._tool_audit_log_path(),
            ),
        )
        self.spec_registry = SpecRegistry(project_root=config.project.project_root)
        self.workflow_spec = self.spec_registry.get_workflow(config.analysis.workflow_name)
        self.candidate_ledger = candidate_ledger or CandidateLedger()
        self.budget_planner = RiskBudgetPlanner(config.analysis)
        self._skill_selection_cache: Dict[str, SkillSelection] = {}
        self._local_pattern_semantics: Optional[LocalPatternSemantics] = (
            deepcopy(shared_local_pattern_semantics)
            if shared_local_pattern_semantics is not None
            else None
        )
        self._semantic_overlay: Optional[Dict[str, Any]] = (
            deepcopy(shared_semantic_overlay)
            if shared_semantic_overlay is not None
            else None
        )
        self._clang_tooling_provider: Optional[ClangToolingEvidenceProvider] = None
        self._clang_tooling_evidence_cache: Dict[tuple[str, str, int, int], Dict[str, Any]] = {}
        self._reachable_function_cache: Dict[tuple[str, int, int, int], Set[str]] = {}
        self._reachable_function_cache_lock = threading.RLock()
        self._semantic_dedup_llm_cache: Dict[str, Dict[str, Any]] = {}
        self.workflow_progress: List[Dict[str, Any]] = []
        self.current_workflow_step: Optional[str] = None
        self.workflow_step_handlers: Dict[str, WorkflowStepHandler] = (
            self._build_workflow_step_handlers()
        )
        self.workflow_executor = WorkflowExecutor(
            workflow_name=self.workflow_spec.name if self.workflow_spec else config.analysis.workflow_name,
            scope="entry",
            handlers=self.workflow_step_handlers,
            progress=self.workflow_progress,
        )
        self.workflow_executor.validate(self._selected_workflow_steps())
        self.workflow_runner = WorkflowRunner(
            workflow_name=self.workflow_spec.name if self.workflow_spec else config.analysis.workflow_name,
            state_factory=self._create_workflow_state,
            step_selector=self._selected_workflow_steps,
            executor=self.workflow_executor,
            build_final_report=self._build_final_report,
            persist_final_report=self._persist_final_report,
            finalize_returned_report=self._finalize_returned_report,
            current_step_sink=self._set_current_workflow_step,
        )
        
        self.analyzed_functions: Set[str] = set()
        self.issues: List[Issue] = []

    def run(self) -> Dict[str, Any]:
        """Run the selected workflow as executable orchestration steps."""
        return self.workflow_runner.run()

    def close(self) -> None:
        if not getattr(self, "_owns_llm_clients", False):
            return
        seen: Set[int] = set()
        for client in getattr(self, "llm_clients", {}).values():
            client_id = id(client)
            if client_id in seen:
                continue
            seen.add(client_id)
            close_client = getattr(client, "close", None)
            if callable(close_client):
                close_client()

    def _set_current_workflow_step(self, step_id: Optional[str]) -> None:
        self.current_workflow_step = step_id

    def _create_workflow_state(self) -> Dict[str, Any]:
        """Create mutable execution state shared by workflow steps."""
        entry_func = self.config.project.entry_function
        if not entry_func:
            return {"error": "No entry function configured"}
        entry_file_path = str(getattr(self.config.project, "entry_file_path", "") or "")
        self.user_config.clear_config_warnings()

        lookup_started = time.monotonic()
        logger.info("[code-index] lookup start entry=%s", entry_func)
        try:
            impl_result = self.code_index.get_function_impl(
                entry_func,
                file_path=entry_file_path,
            )
        except TypeError:
            impl_result = self.code_index.get_function_impl(entry_func)
        logger.info(
            "[code-index] lookup end entry=%s found=%s duration=%.2fs",
            entry_func,
            bool(impl_result),
            time.monotonic() - lookup_started,
        )
        if not impl_result:
            return {"error": "Entry function not found"}

        agent_context = {
            "func_name": entry_func,
            "code": impl_result["code"],
            "location": f"{impl_result['file']}:{impl_result['start_line']}",
        }

        user_config_context = relevant_user_config_context(
            self.user_config,
            entry_func,
            impl_result["code"],
            impl_result.get("file", ""),
        )
        if user_config_context:
            agent_context["user_config_context"] = user_config_context

        diff_focus = getattr(self.config.project, "entry_diff_focus", None)
        if isinstance(diff_focus, dict) and diff_focus:
            agent_context["diff_focus"] = self._build_diff_focus_agent_context(diff_focus)

        state = {
            "entry_func": entry_func,
            "run_id": uuid.uuid4().hex,
            "impl_result": impl_result,
            "agent_context": agent_context,
            "diff_focus": deepcopy(diff_focus) if isinstance(diff_focus, dict) else {},
            "notes": [],
            "issues": [],
            "observations": [],
            "pending_new_issues": [],
            "verified_hist_issues": [],
            "valid_hist_issues": [],
            "user_rejected_hist_issues": [],
            "historical_report": None,
            "needs_refresh": True,
            "refresh_reason": "no_snapshot",
            "is_code_unchanged": False,
            "history_loaded": False,
            "history_reconciled": False,
            "subagent_candidates": [],
            "subagent_ticket_plan": [],
            "subagent_unassigned_candidates": [],
            "subagent_reports": [],
            "subagent_report_summary": {},
            "candidate_ledger": self.candidate_ledger,
            "candidate_ledger_context": [],
            "candidate_ledger_summary": {},
            "total_context_tokens": 0,
            "total_cumulative_prompt_tokens": 0,
            "total_cumulative_completion_tokens": 0,
            "total_cumulative_total_tokens": 0,
            "any_failure": False,
            "failure_msg": "",
            "final_report": None,
            "final_report_dict": None,
        }
        self._refresh_effective_budget(state, "initial")
        return state

    def _build_diff_focus_agent_context(self, diff_focus: Dict[str, Any]) -> Dict[str, Any]:
        """Attach deterministic diff targets so analysis does not rely on free exploration."""
        context = deepcopy(diff_focus)
        snippets: List[Dict[str, Any]] = []
        seen = set()
        for item in context.get("changed_functions") or []:
            if not isinstance(item, dict):
                continue
            func_name = str(item.get("function_name") or "")
            file_path = str(item.get("file_path") or "")
            seen_key = (func_name, file_path)
            if not func_name or seen_key in seen:
                continue
            seen.add(seen_key)
            try:
                impl = self.code_index.get_function_impl(
                    func_name,
                    max_lines=min(200, self.config.analysis.max_function_lines),
                    include_context=False,
                    warn_missing=False,
                    file_path=file_path,
                )
            except TypeError:
                impl = self.code_index.get_function_impl(
                    func_name,
                    max_lines=min(200, self.config.analysis.max_function_lines),
                    include_context=False,
                    warn_missing=False,
                )
            if impl:
                snippets.append(
                    {
                        "function_name": func_name,
                        "file": impl.get("file", file_path),
                        "start_line": impl.get("start_line", item.get("start_line", 0)),
                        "end_line": impl.get("end_line", item.get("end_line", 0)),
                        "changed_lines": list(item.get("changed_lines") or []),
                        "code": self._trim_code(str(impl.get("code") or ""), max_lines=80),
                    }
                )
            if len(snippets) >= 12:
                context.setdefault("notes", []).append(
                    "Changed function snippets truncated to the first 12 functions."
                )
                break
        context["changed_function_snippets"] = snippets
        context["analysis_requirements"] = [
            "Inspect changed_function_snippets and affected_paths before concluding.",
            "Do not rely on caller exploration depth alone to decide whether changed code is relevant.",
            "Keep findings even when they appear pre-existing; mark diff relevance in reasoning.",
        ]
        return context

    def _refresh_effective_budget(
        self,
        state: Dict[str, Any],
        stage: str,
        *,
        rule_candidates: Optional[Sequence[Any]] = None,
        graph_candidates: Optional[Sequence[Any]] = None,
        backend_candidates: Optional[Sequence[Any]] = None,
        subagent_candidates: Optional[Sequence[Any]] = None,
    ) -> EffectiveBudget:
        """Compute and attach the current adaptive budget to workflow state."""

        budget = self.budget_planner.plan(
            state,
            rule_candidates=rule_candidates,
            graph_candidates=graph_candidates,
            backend_candidates=backend_candidates,
            subagent_candidates=subagent_candidates,
        )
        budget_dict = budget.to_dict()
        state["effective_budget"] = budget_dict
        state["budget_stage"] = stage
        state["budget_hard_caps"] = dict(budget.hard_caps)
        state["budget_scores"] = dict(budget.risk_scores)
        state["budget_reasons"] = {
            key: list(value) for key, value in budget.risk_reasons.items()
        }

        agent_context = state.get("agent_context")
        if isinstance(agent_context, dict):
            agent_context["effective_budget"] = budget_dict
            agent_context["budget_stage"] = stage
        return budget

    def _current_effective_budget(self, state: Dict[str, Any]) -> Dict[str, Any]:
        budget = state.get("effective_budget")
        if isinstance(budget, dict):
            return budget
        if not hasattr(self, "budget_planner"):
            return {}
        return self._refresh_effective_budget(state, "late_init").to_dict()

    def _selected_workflow_steps(self) -> List[WorkflowStep]:
        if self.workflow_spec and self.workflow_spec.steps:
            return self.workflow_spec.steps
        return self._default_scan_steps()

    def _default_scan_steps(self) -> List[WorkflowStep]:
        return [WorkflowStep(id=step_id) for step_id in DEFAULT_SCAN_STEP_IDS]

    def _build_workflow_step_handlers(self) -> Dict[str, WorkflowStepHandler]:
        return {
            "load_snapshot_state": self._handle_load_history_state,
            "compare_hashes": self._handle_load_history_state,
            "reuse_unchanged": self._handle_reuse_unchanged_report,
            "reconcile_changed": self._handle_reconcile_changed_issues,
            "analyze_remaining": self._handle_default_scan_subworkflow,
            "rescan_changed": self._handle_default_scan_subworkflow,
            "premodel_reachable_callees": self._handle_premodel_reachable_callees,
            "model_entry": self._handle_model_entry,
            "focused_subagent_planning": self._handle_focused_subagent_planning,
            "vulnerability_mining": self._handle_vulnerability_mining,
            "validate_findings": self._handle_validate_findings,
            "persist_report": self._handle_persist_report,
        }

    def _handle_load_history_state(
        self, state: Dict[str, Any], step: WorkflowStep
    ) -> bool:
        self._load_history_state(state)
        return False

    def _handle_reuse_unchanged_report(
        self, state: Dict[str, Any], step: WorkflowStep
    ) -> bool:
        return self._reuse_unchanged_report(state)

    def _handle_reconcile_changed_issues(
        self, state: Dict[str, Any], step: WorkflowStep
    ) -> bool:
        self._reconcile_changed_issues(state)
        return False

    def _handle_default_scan_subworkflow(
        self, state: Dict[str, Any], step: WorkflowStep
    ) -> bool:
        self._execute_default_scan_subworkflow(state)
        return True

    def _handle_premodel_reachable_callees(
        self, state: Dict[str, Any], step: WorkflowStep
    ) -> bool:
        self._step_premodel_reachable_callees(state)
        return False

    def _handle_model_entry(self, state: Dict[str, Any], step: WorkflowStep) -> bool:
        self._step_model_entry(state)
        return False

    def _handle_focused_subagent_planning(
        self, state: Dict[str, Any], step: WorkflowStep
    ) -> bool:
        self._step_focused_subagent_planning(state)
        return False

    def _handle_vulnerability_mining(
        self, state: Dict[str, Any], step: WorkflowStep
    ) -> bool:
        self._step_vulnerability_mining(state)
        return False

    def _handle_validate_findings(
        self, state: Dict[str, Any], step: WorkflowStep
    ) -> bool:
        self._step_validate_findings(state)
        return False

    def _handle_persist_report(self, state: Dict[str, Any], step: WorkflowStep) -> bool:
        self._build_final_report(state)
        return False

    def _execute_default_scan_subworkflow(self, state: Dict[str, Any]) -> None:
        if not state.get("history_loaded"):
            self._load_history_state(state)
        if not state.get("history_reconciled"):
            self._reconcile_changed_issues(state)

        self.workflow_executor.execute(state, self._default_scan_steps())

    def _load_history_state(self, state: Dict[str, Any]) -> None:
        if state.get("history_loaded"):
            return

        state.update(
            self.history_reconciler.load_state(
                state["entry_func"],
                state["impl_result"],
            )
        )

    def _reuse_unchanged_report(self, state: Dict[str, Any]) -> bool:
        if not state.get("history_loaded"):
            self._load_history_state(state)

        historical_report = state.get("historical_report")
        if self.maintain_mode and state.get("is_code_unchanged") and historical_report:
            logger.info(
                "[maintain] '%s' unchanged, reusing historical report (0 LLM tokens).",
                state["entry_func"],
            )
            state["final_report_dict"] = dict(historical_report)
            return True
        return False

    def _reconcile_changed_issues(self, state: Dict[str, Any]) -> None:
        if state.get("history_reconciled"):
            return
        if not state.get("history_loaded"):
            self._load_history_state(state)

        valid_hist_issues = state.get("valid_hist_issues", [])
        if not state.get("is_code_unchanged") and valid_hist_issues:
            entry_func = state["entry_func"]
            logger.info(
                "Code changed for %s. Verifying whether %d historical issue(s) still exist.",
                entry_func,
                len(valid_hist_issues),
            )
            recon_agent_cfg = next(
                (a for a in self.config.project.agents if a.name == "issue_reconciler_agent"),
                None,
            )
            recon_llm_ref = recon_agent_cfg.llm_ref if recon_agent_cfg and recon_agent_cfg.llm_ref else "default"
            recon_client = self.llm_clients.get(recon_llm_ref, self.llm_clients.get("default"))
            if recon_client is None:
                raise RuntimeError("No LLM client configured for issue reconciliation")

            from ...agents.issue_reconciler.agent import IssueReconcilerAgent

            reconciler_agent = IssueReconcilerAgent(
                recon_client,
                tool_policy=self._tool_policy_for_agent("issue_reconciler_agent"),
            )
            verified_hist_issues = []
            for hist_issue in valid_hist_issues:
                input_data = {
                    "mode": "verify_fix",
                    "historical_issue": hist_issue,
                    "new_code": state["impl_result"]["code"],
                }
                resp = reconciler_agent.run(input_data)
                reconciled = self.history_reconciler.reconcile_issue(hist_issue, resp)
                if reconciled.keep and reconciled.issue:
                    verified_hist_issues.append(reconciled.issue)
                if reconciled.reason == "reconciliation_failed":
                    logger.warning(
                        "Historical issue %s reconciliation failed; keeping as needs_review.",
                        hist_issue.get("id"),
                    )
                elif not reconciled.keep:
                    logger.info("Historical issue %s fixed in new code. Dropping.", hist_issue.get("id"))
            state["verified_hist_issues"] = verified_hist_issues
        else:
            state["verified_hist_issues"] = list(valid_hist_issues)

        state["history_reconciled"] = True

    def _step_premodel_reachable_callees(self, state: Dict[str, Any]) -> None:
        sm_agent_cfg = next((a for a in self.config.project.agents if a.name == "semantic_modeler"), None)
        sm_llm_ref = sm_agent_cfg.llm_ref if sm_agent_cfg and sm_agent_cfg.llm_ref else "default"
        sm_client = self.llm_clients.get(sm_llm_ref, self.llm_clients["default"])
        budget = self._refresh_effective_budget(state, "premodel")
        if budget.premodel_depth <= 0 or budget.premodel_callees <= 0:
            state["notes"].append("Premodel skipped because adaptive budget is 0.")
            return

        try:
            modeled, skipped, tokens = self._premodel_callees(
                state["entry_func"],
                sm_client,
                max_depth=budget.premodel_depth,
                max_callees=budget.premodel_callees,
            )
        except Exception as exc:
            logger.exception(
                "[premodel] Reachable callee premodeling failed for '%s'; "
                "continuing with entry analysis.",
                state["entry_func"],
            )
            state["notes"].append(
                "Premodel reachable callees skipped after retrieval error: "
                f"{exc}"
            )
            return
        state["total_context_tokens"] += tokens
        state["total_cumulative_total_tokens"] += tokens
        state["notes"].append(
            f"Premodeled {modeled} reachable callee(s), reused {skipped} snapshot(s)."
        )

    def _step_model_entry(self, state: Dict[str, Any]) -> None:
        sm_agent_cfg = next((a for a in self.config.project.agents if a.name == "semantic_modeler"), None)
        sm_llm_ref = sm_agent_cfg.llm_ref if sm_agent_cfg and sm_agent_cfg.llm_ref else "default"
        sm_client = self.llm_clients.get(sm_llm_ref, self.llm_clients["default"])
        semantic_agent = SemanticModeler(
            sm_client,
            self._get_tools("semantic_modeler", enable_on_demand_snapshots=False),
            tool_policy=self._tool_policy_for_agent("semantic_modeler"),
        )
        agent_context = state["agent_context"]

        logger.info("Running Semantic Modeler agent with '%s' LLM...", sm_llm_ref)
        self._attach_agent_contract(agent_context, "semantic_modeler")
        response = semantic_agent.run(agent_context)
        sm_tokens = response.metadata.get("context_tokens", 0) if response.metadata else 0
        state["total_context_tokens"] += sm_tokens
        self._accumulate_cumulative_token_metadata(state, response.metadata if response.metadata else {})

        if response.success:
            self.snapshot_store.save_snapshot(
                state["entry_func"],
                response.data,
                agent_context["code"],
                agent_context["location"],
            )
            logger.info(
                "Successfully modeled function: %s (ctx ≈%s tokens)",
                state["entry_func"],
                f"{sm_tokens:,}",
            )
            state["notes"].append(f"Successfully modeled function: {state['entry_func']}")
        else:
            logger.warning("Semantic modeling failed: %s (ctx ≈%s tokens)", response.error, f"{sm_tokens:,}")
            state["notes"].append(f"Semantic modeling failed: {response.error}")

    def _step_focused_subagent_planning(self, state: Dict[str, Any]) -> None:
        va_agent_cfg = next(
            (a for a in self.config.project.agents if a.enabled and a.name == "vulnerability_analyzer"),
            None,
        )
        if not va_agent_cfg:
            return

        va_llm_ref = va_agent_cfg.llm_ref if va_agent_cfg.llm_ref else "default"
        va_client = self.llm_clients.get(va_llm_ref, self.llm_clients.get("default"))
        selection = self._select_vulnerability_skills_for_config(va_agent_cfg, va_client)
        tools = self._get_tools(
            "deep_worker",
            enable_on_demand_snapshots=False,
            active_skill_names=selection.skills,
        )
        orchestrator = SubAgentOrchestrator(self.spec_registry, tools)
        ledger = state.get("candidate_ledger")
        if not isinstance(ledger, CandidateLedger):
            ledger = CandidateLedger()
            state["candidate_ledger"] = ledger

        local_records = []
        source_candidates = orchestrator.plan_candidates(
            state["entry_func"],
            state["agent_context"]["code"],
            allowed_skills=selection.skills,
        )
        for ticket in source_candidates:
            record, _ = ledger.add(
                ticket,
                source=f"source_rule:{state['entry_func']}",
                call_path=[state["entry_func"]],
            )
            local_records.append(record)
        collection_budget = self._refresh_effective_budget(state, "subagent_collect")
        snapshot_candidate_count = self._add_snapshot_candidates_to_ledger(
            ledger,
            orchestrator,
            state["entry_func"],
            selection.skills,
            local_records,
            max_depth=collection_budget.premodel_depth,
            max_callees=collection_budget.premodel_callees,
        )
        local_rule_tickets = self._detect_local_rule_tickets(state, selection.skills)
        for ticket in local_rule_tickets:
            record, _ = ledger.add(
                ticket,
                source=f"local_rule:{state['entry_func']}",
                call_path=[state["entry_func"]],
            )
            local_records.append(record)
        graph_tickets = self._detect_graph_rule_tickets(state, selection.skills)
        for ticket in graph_tickets:
            record, _ = ledger.add(
                ticket,
                source=f"graph_rule:{state['entry_func']}",
                call_path=[state["entry_func"]],
            )
            local_records.append(record)
        backend_tickets = self._detect_backend_signal_tickets(state, selection.skills)
        for ticket in backend_tickets:
            record, _ = ledger.add(
                ticket,
                source=f"static_backend_signal:{state['entry_func']}",
                call_path=[state["entry_func"]],
            )
            local_records.append(record)

        seen_local_keys = set()
        candidates = []
        for record in local_records:
            if record.dedup_key in seen_local_keys or record.status != "pending":
                continue
            seen_local_keys.add(record.dedup_key)
            candidates.append(record.to_ticket())
        planning_budget = self._refresh_effective_budget(
            state,
            "subagent_planning",
            subagent_candidates=candidates,
        )
        tickets = orchestrator.select_tickets(
            candidates,
            planning_budget.subagent_tickets,
        )
        unassigned = orchestrator.unassigned_candidates(candidates, tickets)
        ledger.mark_planned(tickets)
        ledger.mark_unassigned(unassigned)

        candidate_plan = [record.to_dict(include_context=False) for record in ledger.records()]
        ticket_plan = [ticket.to_dict() for ticket in tickets]
        unassigned_plan = [ticket.to_dict() for ticket in unassigned]
        ledger_context = ledger.to_context()
        ledger_summary = ledger.summary()

        state["subagent_candidates"] = candidate_plan
        state["agent_context"]["subagent_candidates"] = candidate_plan
        state["subagent_unassigned_candidates"] = unassigned_plan
        state["agent_context"]["subagent_unassigned_candidates"] = unassigned_plan
        state["candidate_ledger_context"] = ledger_context
        state["agent_context"]["candidate_ledger"] = ledger_context
        state["candidate_ledger_summary"] = ledger_summary
        state["agent_context"]["candidate_ledger_summary"] = ledger_summary
        state["agent_context"]["active_skills"] = selection.skills
        state["agent_context"]["skill_selection_restricted"] = selection.restricted

        if not tickets:
            if candidates:
                state["notes"].append(
                    f"Found {len(candidates)} focused subagent candidate(s), but ticket budget is 0."
                )
            else:
                state["notes"].append(
                    "Focused subagent planning produced no candidates "
                    f"for active skills: {', '.join(selection.skills) or 'none'}."
                )
                logger.info(
                    "Focused subagent planning produced no candidates for %s "
                    "(active skills: %s).",
                    state["entry_func"],
                    ", ".join(selection.skills) or "none",
                )
            return

        state["subagent_ticket_plan"] = ticket_plan
        state["agent_context"]["subagent_plan"] = ticket_plan
        state["notes"].append(
            f"Planned {len(tickets)} focused subagent ticket(s) from {len(candidates)} "
            f"pending candidate(s); merged {ledger_summary.get('duplicates_merged', 0)} "
            f"duplicate candidate source(s), including {snapshot_candidate_count} "
            f"semantic snapshot candidate(s) and {len(local_rule_tickets)} "
            f"local rule candidate(s), {len(graph_tickets)} graph/protocol "
            f"candidate(s), plus {len(backend_tickets)} backend signal candidate(s)."
        )
        if unassigned:
            state["notes"].append(
                f"Deferred {len(unassigned)} subagent candidate(s) due to ticket budget."
            )

        if not self._should_spawn_subagents(va_agent_cfg):
            state["notes"].append(
                "Focused subagent tickets were planned but worker execution is disabled "
                "by analysis.enable_subagent_workers or agent can_spawn_subagents."
            )
            return

        va_llm_ref = va_agent_cfg.llm_ref if va_agent_cfg.llm_ref else "default"
        va_client = self.llm_clients.get(va_llm_ref, self.llm_clients["default"])
        va_agent_spec = self.spec_registry.get_agent("vulnerability_analyzer")
        max_worker_cap = int(va_agent_spec.max_subagents or len(tickets)) if va_agent_spec else len(tickets)
        max_workers = max(
            1,
            min(
                len(tickets),
                int(getattr(self.config.analysis, "parallel_workers", 1) or 1),
                max_worker_cap,
            ),
        )
        subagent_max_turns = int(getattr(self.config.analysis, "subagent_max_turns", 20) or 20)
        max_turns = max(1, min(int(self.config.analysis.max_tool_iterations), subagent_max_turns))
        skill_llm_refs = dict(getattr(self.config.analysis, "subagent_skill_llm_refs", {}) or {})
        skill_efforts = dict(getattr(self.config.analysis, "subagent_skill_efforts", {}) or {})

        def llm_client_for_ticket(ticket: Any) -> LLMClient:
            ref = self._subagent_llm_ref_for_ticket(ticket, skill_llm_refs, va_llm_ref)
            return self.llm_clients.get(ref, va_client)

        def execution_policy_for_ticket(ticket: Any) -> Dict[str, Any]:
            ref = self._subagent_llm_ref_for_ticket(ticket, skill_llm_refs, va_llm_ref)
            client = self.llm_clients.get(ref, va_client)
            models = getattr(client, "models", []) or []
            return {
                "llm_ref": ref,
                "model": str(models[0]) if models else "",
                "reasoning_effort": str(
                    skill_efforts.get(getattr(ticket, "skill", ""))
                    or skill_efforts.get("*")
                    or ""
                ),
            }

        reports = orchestrator.run_tickets(
            va_client,
            tickets,
            max_iterations=max_turns,
            tool_policy=self._tool_policy_for_agent(
                "deep_worker",
                active_skill_names=selection.skills,
            ),
            max_workers=max_workers,
            ticket_timeout=float(getattr(self.config.analysis, "subagent_ticket_timeout", 0.0) or 0.0),
            agent_type="deep_worker",
            spawn_allowlist=list(getattr(self.config.analysis, "subagent_spawn_allowlist", ["deep_worker"]) or ["deep_worker"]),
            nested_spawn_allowed=False,
            llm_client_resolver=llm_client_for_ticket,
            execution_policy_resolver=execution_policy_for_ticket,
            worktree_isolation={"mode": "read_only", "snapshot_writes": False},
        )
        ledger.mark_reported(reports)
        report_summary = orchestrator.summarize_reports(reports)
        state["subagent_reports"] = reports
        state["agent_context"]["subagent_reports"] = reports
        state["subagent_report_summary"] = report_summary
        state["agent_context"]["subagent_report_summary"] = report_summary
        state["candidate_ledger_context"] = ledger.to_context()
        state["agent_context"]["candidate_ledger"] = state["candidate_ledger_context"]
        state["candidate_ledger_summary"] = ledger.summary()
        state["agent_context"]["candidate_ledger_summary"] = state["candidate_ledger_summary"]
        state["total_context_tokens"] += sum(
            int(report.get("metadata", {}).get("context_tokens", 0) or 0)
            for report in reports
        )
        for report in reports:
            self._accumulate_cumulative_token_metadata(
                state,
                report.get("metadata", {}) if isinstance(report.get("metadata"), dict) else {},
            )
        state["notes"].append(
            "Executed focused subagent ticket(s): "
            + ", ".join(f"{key}={value}" for key, value in report_summary.items())
        )

    def _add_snapshot_candidates_to_ledger(
        self,
        ledger: CandidateLedger,
        orchestrator: SubAgentOrchestrator,
        entry_func: str,
        active_skills: List[str],
        local_records: List[Any],
        *,
        max_depth: int,
        max_callees: int,
    ) -> int:
        """Add semantic-snapshot suspicious points from reachable functions to the ledger."""
        added = 0
        visited: Set[str] = set()
        queue: List[tuple[str, List[str], int]] = [(entry_func, [entry_func], 0)]

        while queue:
            func, path, depth = queue.pop(0)
            if func in visited or depth > max_depth:
                continue
            visited.add(func)

            snapshot = self.snapshot_store.load_snapshot(func)
            if snapshot:
                tickets = orchestrator.plan_snapshot_candidates(
                    func,
                    snapshot,
                    allowed_skills=active_skills,
                )
                for ticket in tickets:
                    record, _ = ledger.add(
                        ticket,
                        source=f"semantic_snapshot:{func}",
                        call_path=path,
                    )
                    local_records.append(record)
                added += len(tickets)

            if depth >= max_depth:
                continue
            try:
                callees = self.code_index.get_callees(func, limit=max_callees)
            except Exception as exc:
                logger.debug("Failed to collect snapshot callees for %s: %s", func, exc)
                continue
            for callee in callees:
                callee_name = callee.get("name") if isinstance(callee, dict) else None
                if not callee_name or callee_name in visited:
                    continue
                queue.append((callee_name, path + [callee_name], depth + 1))

        return added

    def _step_vulnerability_mining(self, state: Dict[str, Any]) -> None:
        agent_context = state["agent_context"]
        for agent_cfg in self.config.project.agents:
            if not agent_cfg.enabled or agent_cfg.name != "vulnerability_analyzer":
                continue

            logger.info("Running Vulnerability Analyzer agent for task: %s", agent_cfg.task)
            va_llm_ref = agent_cfg.llm_ref if agent_cfg.llm_ref else "default"
            va_client = self.llm_clients.get(va_llm_ref, self.llm_clients["default"])
            selection = self._select_vulnerability_skills_for_config(agent_cfg, va_client)
            analyzer_agent = VulnerabilityAnalyzer(
                va_client,
                self._get_tools("vulnerability_analyzer", active_skill_names=selection.skills),
                tool_policy=self._tool_policy_for_agent(
                    "vulnerability_analyzer",
                    active_skill_names=selection.skills,
                ),
            )

            agent_context["task"] = agent_cfg.task
            agent_context["entry_custom_prompt"] = getattr(
                agent_cfg,
                "entry_custom_prompt",
                None,
            )
            agent_context["active_skills"] = selection.skills
            agent_context["skill_selection_restricted"] = selection.restricted
            self._attach_agent_contract(
                agent_context,
                "vulnerability_analyzer",
                agent_cfg.skills,
                active_skill_names=selection.skills,
            )
            candidate_batch = self.candidate_pipeline.collect_signal_candidates(state)
            self.candidate_pipeline.accumulate_summary(state, candidate_batch)
            self.candidate_pipeline.persist(candidate_batch)
            rule_candidates = candidate_batch.local_candidates
            graph_candidates = candidate_batch.graph_candidates
            backend_candidates = candidate_batch.backend_candidates
            candidate_signals = candidate_batch.merged_candidates
            candidate_signal_summary = candidate_batch.summary_increment()
            agent_context["candidate_signal_summary"] = candidate_signal_summary
            agent_context["candidate_signal_candidates"] = self._compact_candidate_signal_items(
                candidate_signals,
                limit=80,
            )
            response = analyzer_agent.run(
                agent_context,
                max_iterations=self.config.analysis.max_tool_iterations,
            )

            if response.success:
                raw_new_issues = response.data.get("issues", [])
                coverage = self._normalize_candidate_coverage(
                    response.data.get("candidate_coverage")
                )
                if coverage:
                    state["va_candidate_coverage_summary"] = self._candidate_coverage_summary(coverage)
                if candidate_signals:
                    self._mark_va_unreviewed_candidates(candidate_signals, coverage)
                    raw_new_issues = list(raw_new_issues) + candidate_signals
                    state["notes"].append(candidate_batch.note())
                va_ctx_tokens = response.metadata.get("context_tokens", 0) if response.metadata else 0
                state["total_context_tokens"] += va_ctx_tokens
                self._accumulate_cumulative_token_metadata(state, response.metadata if response.metadata else {})
                logger.info(
                    "Vulnerability Analyzer found %d issue(s) for task: %s (ctx ≈%s tokens)",
                    len(raw_new_issues),
                    agent_cfg.task,
                    f"{va_ctx_tokens:,}",
                )

                new_issues = self._deduplicate_against_history(raw_new_issues, state)
                state["pending_new_issues"].extend(new_issues)
                state["notes"].append(f"Analyzed task: {agent_cfg.task}")
                if agent_context.get("entry_custom_prompt"):
                    state["notes"].append(
                        f"Entry custom prompt: {agent_context['entry_custom_prompt']}"
                    )
            else:
                logger.error("Vulnerability analysis failed: %s", response.error)
                state["notes"].append(f"Vulnerability analysis failed: {response.error}")
                if candidate_signals:
                    new_issues = self._deduplicate_against_history(candidate_signals, state)
                    state["pending_new_issues"].extend(new_issues)
                    state["notes"].append(
                        f"Retained {len(new_issues)} local/backend candidate(s) "
                        "despite vulnerability analyzer failure."
                    )
                state["any_failure"] = True
                state["failure_msg"] = response.error

    def _deduplicate_against_history(
        self,
        raw_new_issues: List[Dict[str, Any]],
        state: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        dedup_reference_issues = (
            state.get("verified_hist_issues", [])
            + state.get("user_rejected_hist_issues", [])
        )
        if not raw_new_issues or not dedup_reference_issues:
            return raw_new_issues

        logger.info(
            "Deduplicating %d new issue(s) against %d reference issue(s).",
            len(raw_new_issues),
            len(dedup_reference_issues),
        )
        recon_agent_cfg = next(
            (a for a in self.config.project.agents if a.name == "issue_reconciler_agent"),
            None,
        )
        recon_llm_ref = recon_agent_cfg.llm_ref if recon_agent_cfg and recon_agent_cfg.llm_ref else "default"
        recon_client = self.llm_clients.get(recon_llm_ref, self.llm_clients.get("default"))
        if recon_client is None:
            raise RuntimeError("No LLM client configured for issue reconciliation")

        from ...agents.issue_reconciler.agent import IssueReconcilerAgent

        reconciler_agent = IssueReconcilerAgent(
            recon_client,
            tool_policy=self._tool_policy_for_agent("issue_reconciler_agent"),
        )
        user_rejected_hist_issues = state.get("user_rejected_hist_issues", [])
        new_issues = []
        for raw_issue in raw_new_issues:
            input_data = {
                "mode": "deduplicate",
                "historical_issues": dedup_reference_issues,
                "new_issue": raw_issue,
            }
            resp = reconciler_agent.run(input_data)
            if resp.success and resp.data.get("is_duplicate"):
                matched_id = resp.data.get("matched_historical_id")
                matched_user_rejected = any(
                    iss.get("id") == matched_id and iss.get("rejection_source") == "user"
                    for iss in user_rejected_hist_issues
                )
                if matched_user_rejected:
                    logger.info("New issue matches user-rejected issue %s. Auto-suppressing.", matched_id)
                else:
                    logger.info("New issue corresponds to historical issue %s. Skipping validation.", matched_id)
            else:
                new_issues.append(raw_issue)
        return new_issues

    def _detect_local_rule_candidates(self, state: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Seed backend-appropriate local candidates before LLM validation."""
        entry_func = state["entry_func"]
        impl = state.get("impl_result") or {}
        code = str(impl.get("code") or "")
        file_path = str(impl.get("file") or "")
        profile = self._candidate_backend_profile()
        callee_scan = self._direct_callee_rule_scan_budget(state)
        issues: List[Dict[str, Any]] = []
        if profile == "regex":
            generator = RegexCandidateGenerator(self._get_local_pattern_semantics())
            issues.extend(generator.generate_issues(entry_func, code, file_path))
            issues.extend(
                self._detect_direct_callee_rule_candidates(
                    impl,
                    generator,
                    entry_func=entry_func,
                    **callee_scan,
                )
            )
        if profile in {"clang", "unified"}:
            clang_generator = ClangAstCfgCandidateGenerator(
                self._get_local_pattern_semantics(),
                semantic_overlay=self._get_semantic_overlay(),
                tooling_evidence_provider=self._clang_tooling_evidence_for,
            )
            issues.extend(clang_generator.generate_issues(entry_func, code, file_path))
            issues.extend(
                self._clang_tooling_matcher_candidates_from_evidence(
                    entry_func,
                    file_path,
                    self._clang_tooling_evidence_for(
                        func_name=entry_func,
                        file_path=file_path,
                        start_line=int(impl.get("start_line") or 0),
                        end_line=int(impl.get("end_line") or 0),
                    ),
                )
            )
            issues.extend(
                self._detect_direct_callee_rule_candidates(
                    impl,
                    clang_generator,
                    entry_func=entry_func,
                    **callee_scan,
                )
            )
        issues = dedupe_rule_candidates(issues)
        issues = self._apply_candidate_validation_budget(issues)
        return self._annotate_candidate_issues(
            issues,
            checker=self._local_candidate_checker(),
            path_kind="local_memory_concurrency",
        )

    def _detect_graph_rule_candidates(self, state: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Seed cross-function graph/protocol candidates before LLM validation."""
        entry_func = state["entry_func"]
        impl = state.get("impl_result") or {}
        budget = self._current_effective_budget(state)
        graph_depth = int(budget.get("graph_depth", 0) or 0)
        graph_functions = int(budget.get("graph_functions", 0) or 0)
        if graph_depth <= 0 or graph_functions <= 0:
            return []
        generator = GraphCandidateGenerator(
            self.code_index,
            self._get_local_pattern_semantics(),
            semantic_overlay=self._get_semantic_overlay(),
        )
        issues = generator.generate_for_entry(
            entry_func,
            impl,
            max_depth=graph_depth,
            max_functions=graph_functions,
        )
        issues = dedupe_rule_candidates(issues)
        return self._annotate_candidate_issues(
            issues,
            checker=self._graph_candidate_checker(),
            path_kind="cross_function_protocol",
        )

    def _detect_graph_rule_tickets(
        self,
        state: Dict[str, Any],
        allowed_skills: Optional[List[str]] = None,
    ) -> List[Any]:
        generator = GraphCandidateGenerator(
            self.code_index,
            self._get_local_pattern_semantics(),
            semantic_overlay=self._get_semantic_overlay(),
        )
        tickets = [
            generator.issue_to_ticket(issue)
            for issue in self._detect_graph_rule_candidates(state)
        ]
        if allowed_skills is None:
            return tickets
        allowed = set(allowed_skills)
        return [ticket for ticket in tickets if ticket.skill in allowed]

    def _detect_local_rule_tickets(
        self,
        state: Dict[str, Any],
        allowed_skills: Optional[List[str]] = None,
    ) -> List[Any]:
        """Create backend-appropriate local candidates as focused subagent tickets."""
        entry_func = state["entry_func"]
        impl = state.get("impl_result") or {}
        profile = self._candidate_backend_profile()
        callee_scan = self._direct_callee_rule_scan_budget(state)
        generator: Optional[RegexCandidateGenerator] = None
        clang_generator: Optional[ClangAstCfgCandidateGenerator] = None
        issues: List[Dict[str, Any]] = []
        if profile == "regex":
            generator = RegexCandidateGenerator(self._get_local_pattern_semantics())
            issues.extend(
                generator.generate_issues(
                    entry_func,
                    str(impl.get("code") or ""),
                    str(impl.get("file") or ""),
                    allowed_skills=allowed_skills,
                )
            )
            issues.extend(
                self._detect_direct_callee_rule_candidates(
                    impl,
                    generator,
                    entry_func=entry_func,
                    allowed_skills=allowed_skills,
                    **callee_scan,
                )
            )
        if profile in {"clang", "unified"}:
            clang_generator = ClangAstCfgCandidateGenerator(
                self._get_local_pattern_semantics(),
                semantic_overlay=self._get_semantic_overlay(),
                tooling_evidence_provider=self._clang_tooling_evidence_for,
            )
            issues.extend(
                clang_generator.generate_issues(
                    entry_func,
                    str(impl.get("code") or ""),
                    str(impl.get("file") or ""),
                    allowed_skills=allowed_skills,
                )
            )
            issues.extend(
                self._clang_tooling_matcher_candidates_from_evidence(
                    entry_func,
                    str(impl.get("file") or ""),
                    self._clang_tooling_evidence_for(
                        func_name=entry_func,
                        file_path=str(impl.get("file") or ""),
                        start_line=int(impl.get("start_line") or 0),
                        end_line=int(impl.get("end_line") or 0),
                    ),
                    allowed_skills=allowed_skills,
                )
            )
            issues.extend(
                self._detect_direct_callee_rule_candidates(
                    impl,
                    clang_generator,
                    entry_func=entry_func,
                    allowed_skills=allowed_skills,
                    **callee_scan,
                )
            )
        if not issues:
            return []
        issues = dedupe_rule_candidates(issues)
        issues = self._apply_candidate_validation_budget(issues)
        issues = self._annotate_candidate_issues(
            issues,
            checker=self._local_candidate_checker(),
            path_kind="local_memory_concurrency",
        )
        return [
            clang_generator.issue_to_ticket(issue)
            if issue.get("candidate_source") == "clang_ast_cfg" and clang_generator is not None
            else (generator or RegexCandidateGenerator(self._get_local_pattern_semantics())).issue_to_ticket(issue)
            for issue in issues
            if issue.get("validation_required") is not False
            and str(issue.get("finding_kind") or "").lower() != "audit_observation"
        ]

    @staticmethod
    def _apply_candidate_validation_budget(issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Keep exact sink candidates ahead of broad audit-style rules."""
        generic_categories = {
            "integer_overflow",
            "protocol_validation",
            "resource_allocation_without_limits",
            "version_filtering",
        }
        per_function_category_limit = 2
        counters: Dict[tuple[str, str], int] = {}
        ordered = sorted(issues, key=Analyzer._candidate_validation_sort_key)
        for issue in ordered:
            category = str(
                issue.get("defect_class") or issue.get("category") or issue.get("subcategory") or ""
            ).replace("-", "_").lower()
            budget_class = str(issue.get("validation_budget_class") or "").lower()
            if category not in generic_categories and budget_class != "generic":
                continue
            if Analyzer._is_tp_sensitive_generic_candidate(issue):
                issue["validation_budget_class"] = "quota_lifetime_sensitive_generic"
                pack = issue.get("evidence_pack")
                if isinstance(pack, dict):
                    pack["validation_budget_class"] = "quota_lifetime_sensitive_generic"
                continue
            function = str(issue.get("function") or issue.get("func_name") or "")
            key = (function, category)
            count = counters.get(key, 0)
            counters[key] = count + 1
            if count < per_function_category_limit:
                continue
            issue["validation_required"] = False
            issue["finding_kind"] = "audit_observation"
            issue["validation_budget_class"] = "generic_deferred"
            reason = (
                "Deferred broad static candidate after the per-function generic validation budget; "
                "exact sink candidates retain validator priority."
            )
            issue["audit_observation_reason"] = reason
            pack = issue.get("evidence_pack")
            if isinstance(pack, dict):
                pack["validation_required"] = False
                pack["audit_observation_reason"] = reason
                pack["validation_budget_class"] = "generic_deferred"
        return ordered

    @staticmethod
    def _is_tp_sensitive_generic_candidate(issue: Dict[str, Any]) -> bool:
        category = str(
            issue.get("defect_class") or issue.get("category") or issue.get("subcategory") or ""
        ).replace("-", "_").lower()
        if category != "resource_allocation_without_limits":
            return False
        text = Analyzer._flatten_candidate_text(issue).lower()
        if not re.search(
            r"\b(?:quota|limit|reserve|reserved|segment|window|cache|tls|thread|pool|"
            r"global|session|client|wire|header|packet|frame|record|payload|map|mmap|"
            r"error path|cleanup|owner|field|g_[a-z0-9_]+)\b",
            text,
        ):
            return False
        return bool(
            re.search(r"\b(?:malloc|calloc|alloc|realloc|_safe_malloc|_safe_calloc)\b", text)
            or re.search(r"\b(?:allocation|allocate|heap|resource)\b", text)
        )

    @staticmethod
    def _flatten_candidate_text(value: Any) -> str:
        if isinstance(value, dict):
            return " ".join(Analyzer._flatten_candidate_text(item) for item in value.values())
        if isinstance(value, list):
            return " ".join(Analyzer._flatten_candidate_text(item) for item in value)
        if value is None:
            return ""
        return str(value)

    @staticmethod
    def _candidate_validation_sort_key(issue: Dict[str, Any]) -> tuple[int, int, float, str]:
        group = str(issue.get("candidate_priority_group") or "")
        category = str(issue.get("defect_class") or issue.get("category") or "")
        group_order = {
            "exact_sink": 0,
            "semantic_suspicious_point": 1,
            "graph_structural": 2,
            "generic_audit": 3,
        }.get(group, 2)
        generic_categories = {
            "integer_overflow",
            "protocol_validation",
            "resource_allocation_without_limits",
            "version_filtering",
        }
        generic_penalty = 1 if category in generic_categories else 0
        try:
            confidence = float(issue.get("rule_confidence") or issue.get("confidence") or 0.0)
        except (TypeError, ValueError):
            confidence = 0.0
        return (group_order, generic_penalty, -confidence, str(issue.get("candidate_id") or issue.get("id") or ""))

    def _direct_callee_rule_scan_budget(self, state: Dict[str, Any]) -> Dict[str, int]:
        budget = self._current_effective_budget(state)
        hard_caps = budget.get("hard_caps") if isinstance(budget.get("hard_caps"), dict) else {}
        analysis_config = getattr(getattr(self, "config", None), "analysis", None)
        configured_breadth = int(
            budget.get("premodel_callees")
            or hard_caps.get("max_premodel_callees")
            or getattr(analysis_config, "max_premodel_callees", 16)
            or 16
        )
        configured_depth = int(
            budget.get("premodel_depth")
            or hard_caps.get("max_premodel_depth")
            or getattr(analysis_config, "max_premodel_depth", 2)
            or 2
        )
        limit = max(16, min(64, configured_breadth))
        max_depth = max(2, min(4, configured_depth))
        total_limit = max(80, min(256, limit * max_depth * 4))
        return {"limit": limit, "max_depth": max_depth, "total_limit": total_limit}

    def _detect_direct_callee_rule_candidates(
        self,
        impl: Dict[str, Any],
        generator: Any,
        *,
        entry_func: Optional[str] = None,
        allowed_skills: Optional[List[str]] = None,
        limit: int = 16,
        max_depth: int = 2,
        total_limit: int = 80,
    ) -> List[Dict[str, Any]]:
        """Run local candidate rules on project callees of thin public facades."""
        issues: List[Dict[str, Any]] = []
        root = str(entry_func or impl.get("function") or impl.get("name") or "").strip()
        queued: List[tuple[str, int, List[str]]] = []
        for item in impl.get("callees", []):
            name = self._callee_item_name(item)
            if not name or name == root:
                continue
            queued.append((name, 1, [root, name] if root else [name]))
        queued = self._balanced_callee_queue(queued, limit)
        impl_cache: Dict[str, Dict[str, Any]] = {root: impl} if root else {}
        visited: Set[str] = set()
        analyzed = 0
        while queued and analyzed < total_limit:
            callee, depth, call_path = queued.pop(0)
            if callee in visited:
                continue
            visited.add(callee)
            try:
                callee_impl = self.code_index.get_function_impl(callee, warn_missing=False)
            except Exception as exc:
                logger.warning(
                    "Skipping direct callee candidate scan for '%s': %s",
                    callee,
                    exc,
                    exc_info=True,
                )
                continue
            if not callee_impl:
                continue
            impl_cache[callee] = callee_impl
            analyzed += 1
            callee_code = str(callee_impl.get("code") or "")
            callee_file = str(callee_impl.get("file") or "")
            callee_issues = generator.generate_issues(
                callee,
                callee_code,
                callee_file,
                allowed_skills=allowed_skills,
            )
            if isinstance(generator, ClangAstCfgCandidateGenerator):
                callee_issues.extend(
                    self._clang_tooling_matcher_candidates_from_evidence(
                        callee,
                        callee_file,
                        self._clang_tooling_evidence_for(
                            func_name=callee,
                            file_path=callee_file,
                            start_line=int(callee_impl.get("start_line") or 0),
                            end_line=int(callee_impl.get("end_line") or 0),
                        ),
                        allowed_skills=allowed_skills,
                    )
                )
            issues.extend(
                self._lift_internal_sink_candidate(
                    issue,
                    entry_func=root,
                    call_path=call_path,
                    call_path_edges=self._call_path_argument_evidence(call_path, impl_cache),
                )
                for issue in callee_issues
            )
            expand_dispatcher_siblings = (
                depth >= max_depth
                and (
                    self._looks_like_dispatcher_function(callee, callee_impl)
                    or self._looks_like_boundary_fanout_function(callee, callee_impl)
                )
            )
            if depth >= max_depth and not expand_dispatcher_siblings:
                continue
            nested_queue: List[tuple[str, int, List[str]]] = []
            for nested in callee_impl.get("callees", []):
                nested_name = self._callee_item_name(nested)
                if nested_name and nested_name not in visited and nested_name not in call_path:
                    nested_queue.append((nested_name, depth + 1, call_path + [nested_name]))
            queued.extend(self._balanced_callee_queue(nested_queue, limit))
            queued = self._order_callee_work_queue(queued)
        return issues

    @staticmethod
    def _balanced_callee_queue(
        queue: List[tuple[str, int, List[str]]],
        limit: int,
    ) -> List[tuple[str, int, List[str]]]:
        if limit <= 0 or len(queue) <= limit:
            return list(queue)
        original_quota = max(1, min(len(queue), limit // 2))
        selected = list(queue[:original_quota])
        selected_names = {item[0] for item in selected}
        remaining = [item for item in queue[original_quota:] if item[0] not in selected_names]
        selected.extend(Analyzer._prioritize_callee_queue(remaining)[: max(0, limit - len(selected))])
        return selected

    @staticmethod
    def _order_callee_work_queue(queue: List[tuple[str, int, List[str]]]) -> List[tuple[str, int, List[str]]]:
        return sorted(queue, key=lambda item: item[1])

    @staticmethod
    def _prioritize_callee_queue(queue: List[tuple[str, int, List[str]]]) -> List[tuple[str, int, List[str]]]:
        """Prefer callees whose names hint at memory, descriptor, lock, parser, or quota primitives."""
        return sorted(
            queue,
            key=lambda item: (
                item[1],
                -Analyzer._callee_danger_score(item[0]),
                item[0],
            ),
        )

    @staticmethod
    def _callee_danger_score(name: str) -> int:
        text = str(name or "").lower()
        score = 0
        patterns = {
            r"(?:alloc|calloc|malloc|realloc|free|release|destroy|cleanup|unload|detach|unlink)": 5,
            r"(?:open|close|socket|accept|dup|fd|descriptor|journal|segment)": 4,
            r"(?:lock|unlock|mutex|rwlock|cache|callback|handler)": 4,
            r"(?:copy|memcpy|memmove|parse|decode|serialize|packet|frame|wire|header|offset|cursor)": 4,
            r"(?:count|size|quota|limit|window|batch|stream|replay)": 3,
            r"(?:commit|abort|reset|flush|dispatch|process|handle)": 2,
        }
        for pattern, weight in patterns.items():
            if re.search(pattern, text):
                score += weight
        if text.startswith("_"):
            score += 1
        return score

    @staticmethod
    def _callee_item_name(item: Any) -> str:
        if isinstance(item, dict):
            return str(item.get("name") or item.get("callee_name") or item.get("function") or "").strip()
        return str(item or "").strip()

    @staticmethod
    def _looks_like_dispatcher_function(func_name: str, impl: Dict[str, Any]) -> bool:
        """Return True for switch/fanout functions whose sibling callees deserve one extra scan."""
        code = str(impl.get("code") or "")
        callees = impl.get("callees") or []
        if len(callees) < 3:
            return False
        name_hint = re.search(r"(?:dispatch|handle|process|message|protocol|router|route)", func_name, re.I)
        switch_hint = "switch" in code or len(re.findall(r"\bcase\b|\bdefault\s*:", code)) >= 2
        branch_hint = len(re.findall(r"\b(?:if|else\s+if)\s*\(", code)) >= 3
        return bool(switch_hint or (name_hint and branch_hint))

    @staticmethod
    def _looks_like_boundary_fanout_function(func_name: str, impl: Dict[str, Any]) -> bool:
        code = str(impl.get("code") or "")
        callees = impl.get("callees") or []
        if not callees:
            return False
        if len(callees) == 1 and re.search(r"\breturn\s+[A-Za-z_]\w+\s*\(", code):
            return True
        call_statements = len(
            [
                token
                for token in re.findall(r"\b([A-Za-z_]\w*)\s*\(", code)
                if token not in {"if", "for", "while", "switch", "return", "sizeof"}
            ]
        )
        if len(callees) >= 3 and call_statements >= 3:
            return True
        name_hint = re.search(
            r"(?:apply|configure|publish|schedule|refresh|accept|cycle|plan|record|maintenance|cases|worker|runtime)",
            func_name,
            re.I,
        )
        return bool(name_hint and len(callees) >= 2 and call_statements >= 2)

    @staticmethod
    def _lift_internal_sink_candidate(
        issue: Dict[str, Any],
        *,
        entry_func: str,
        call_path: List[str],
        call_path_edges: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        if not entry_func or not call_path:
            return issue
        normalized_path = [str(item).strip() for item in call_path if str(item).strip()]
        if not normalized_path:
            return issue
        sink_func = str(issue.get("function") or normalized_path[-1] or "").strip()
        issue["analyzed_from"] = entry_func
        issue["entry_function"] = entry_func
        issue["reachable_from_entry"] = True
        issue["internal_sink_lifted"] = bool(sink_func and sink_func != entry_func)
        issue["call_path"] = normalized_path

        positive = issue.setdefault("positive_evidence", [])
        if isinstance(positive, list):
            path_text = " -> ".join(normalized_path)
            message = f"Entry `{entry_func}` reaches internal sink `{sink_func}` through call path `{path_text}`."
            if message not in positive:
                positive.append(message)

        pack = issue.get("evidence_pack")
        if not isinstance(pack, dict):
            pack = {}
            issue["evidence_pack"] = pack
        pack["entry_function"] = entry_func
        pack["sink_function"] = sink_func
        pack["call_path"] = normalized_path
        if call_path_edges:
            pack["call_path_edges"] = call_path_edges
        pack["internal_sink_lifted"] = issue["internal_sink_lifted"]

        path = pack.get("path")
        if not isinstance(path, dict):
            path = {}
        path.update(
            {
                "entry_function": entry_func,
                "sink_function": sink_func,
                "target_function": sink_func,
                "call_path": normalized_path,
                "complete_to_entry": True,
                "lifted_internal_sink": issue["internal_sink_lifted"],
                "path_kind": "entry_to_internal_sink",
            }
        )
        if call_path_edges:
            path["call_edges"] = call_path_edges
        pack["path"] = path
        return issue

    def _call_path_argument_evidence(
        self,
        call_path: List[str],
        impl_cache: Dict[str, Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        normalized = [str(item).strip() for item in call_path if str(item).strip()]
        edges: List[Dict[str, Any]] = []
        for caller, callee in zip(normalized, normalized[1:]):
            caller_impl = impl_cache.get(caller) or {}
            callee_impl = impl_cache.get(callee) or {}
            caller_params = self._function_param_names(str(caller_impl.get("code") or ""), caller)
            callee_params = self._function_param_names(str(callee_impl.get("code") or ""), callee)
            callsite = (
                self._clang_callsite_argument_refs(caller, callee, caller_impl)
                or self._source_callsite_argument_refs(str(caller_impl.get("code") or ""), callee)
            )
            actuals = [str(item) for item in callsite.get("arguments") or [] if str(item)]
            mappings = []
            for idx, actual in enumerate(actuals):
                mapping = {
                    "arg_index": idx,
                    "actual": actual,
                    "formal": callee_params[idx] if idx < len(callee_params) else "",
                }
                if actual in caller_params:
                    mapping["source_parameter"] = actual
                mappings.append(mapping)
            edge = {
                "caller": caller,
                "callee": callee,
                "call_line": callsite.get("line") or 0,
                "arguments": actuals,
                "parameter_mapping": mappings,
                "caller_parameters": caller_params,
                "callee_parameters": callee_params,
                "guard_summary": {
                    "caller_side": self._guard_summary_for_symbols(
                        str(caller_impl.get("code") or ""),
                        actuals,
                        before_line=int(callsite.get("line") or 0),
                        window=12,
                    ),
                    "callee_entry": self._guard_summary_for_symbols(
                        str(callee_impl.get("code") or ""),
                        callee_params,
                        entry_window=12,
                    ),
                },
                "evidence_source": callsite.get("source") or "source_text_best_effort",
            }
            if not actuals:
                edge["notes"] = ["Callsite arguments were not extracted for this edge."]
            edges.append(edge)
        return edges

    @classmethod
    def _guard_summary_for_symbols(
        cls,
        code: str,
        symbols: List[str],
        *,
        before_line: int = 0,
        window: int = 12,
        entry_window: int = 0,
    ) -> Dict[str, Any]:
        tokens = cls._guard_symbol_tokens(symbols)
        summary: Dict[str, Any] = {
            "symbols": tokens,
            "checks": [],
            "evidence_source": "source_text_guard_scan",
            "is_conclusive": False,
        }
        if not code or not tokens:
            summary["notes"] = ["No symbols available for guard scan."]
            return summary

        records = cls._source_line_records(code)
        if not records:
            summary["notes"] = ["No source lines available for guard scan."]
            return summary
        if entry_window > 0:
            scoped = records[:entry_window]
        elif before_line > 0:
            scoped = [
                row
                for row in records
                if row["line"] and before_line - window <= int(row["line"]) <= before_line
            ]
            if not scoped:
                call_index = next(
                    (idx for idx, row in enumerate(records) if int(row.get("line") or 0) == before_line),
                    len(records),
                )
                scoped = records[max(0, call_index - window) : call_index + 1]
        else:
            scoped = records[:window]

        for row in scoped:
            text = str(row.get("text") or "")
            matched = [token for token in tokens if cls._contains_symbol_token(text, token)]
            if not matched or not cls._looks_like_guard_text(text):
                continue
            summary["checks"].append(
                {
                    "line": row.get("line") or 0,
                    "text": text.strip(),
                    "symbols": matched,
                    "guard_kind": cls._classify_guard_text(text),
                }
            )
        if not summary["checks"]:
            summary["notes"] = [
                "No nearby guard-like condition, assertion, or validation call was observed for the mapped symbols."
            ]
        return summary

    @classmethod
    def _guard_symbol_tokens(cls, symbols: List[str]) -> List[str]:
        tokens: List[str] = []
        seen: Set[str] = set()
        for symbol in symbols:
            for token in re.findall(r"[A-Za-z_]\w*", str(symbol or "")):
                if token in {"NULL", "sizeof", "return", "if", "while"}:
                    continue
                if token not in seen:
                    seen.add(token)
                    tokens.append(token)
        return tokens[:12]

    @staticmethod
    def _contains_symbol_token(text: str, token: str) -> bool:
        return bool(re.search(rf"\b{re.escape(token)}\b", str(text or "")))

    @staticmethod
    def _looks_like_guard_text(text: str) -> bool:
        lowered = str(text or "").lower()
        if re.search(r"\b(?:if|while|assert|static_assert)\s*\(", lowered):
            return True
        if re.search(r"\b(?:bug_on|warn_on|check|validate|verify|bound|range|limit|max|min)\w*\s*\(", lowered):
            return True
        return bool(re.search(r"(?:<=|>=|==|!=|<|>|\bnull\b|\bsize_max\b|\bsizeof\b)", lowered))

    @staticmethod
    def _classify_guard_text(text: str) -> str:
        lowered = str(text or "").lower()
        if "null" in lowered or re.search(r"!\s*[A-Za-z_]\w*", lowered):
            return "null_or_presence_check"
        if "size_max" in lowered or "uint_max" in lowered or "/" in lowered and "max" in lowered:
            return "overflow_or_range_check"
        if "sizeof" in lowered or re.search(r"(?:<=|<|>=|>|==|!=)", lowered):
            return "bounds_or_range_check"
        if re.search(r"\b(?:check|validate|verify)\w*\s*\(", lowered):
            return "validation_call"
        if "assert" in lowered or "bug_on" in lowered or "warn_on" in lowered:
            return "assertion"
        return "condition"

    @classmethod
    def _source_line_records(cls, code: str) -> List[Dict[str, Any]]:
        records: List[Dict[str, Any]] = []
        synthetic = 1
        for raw in str(code or "").splitlines():
            text = cls._strip_numbered_line_prefix(raw).strip()
            if not text:
                synthetic += 1
                continue
            records.append({"line": cls._numbered_line(raw) or synthetic, "text": text})
            synthetic += 1
        return records

    def _clang_callsite_argument_refs(
        self,
        caller: str,
        callee: str,
        caller_impl: Dict[str, Any],
    ) -> Dict[str, Any]:
        caller_file = str(caller_impl.get("file") or "")
        if not caller_file:
            return {}
        evidence = self._clang_tooling_evidence_for(
            func_name=caller,
            file_path=caller_file,
            start_line=int(caller_impl.get("start_line") or 0),
            end_line=int(caller_impl.get("end_line") or 0),
        )
        ast_dump = evidence.get("ast_dump") if isinstance(evidence, dict) else {}
        ast_summary = ast_dump.get("summary") if isinstance(ast_dump, dict) else {}
        target = ast_summary.get("target_function") if isinstance(ast_summary, dict) else {}
        if not isinstance(target, dict):
            return {}
        for call in target.get("call_exprs") or []:
            if not isinstance(call, dict) or str(call.get("callee") or "") != callee:
                continue
            actuals: List[str] = []
            for refs in call.get("argument_refs") or []:
                if isinstance(refs, list) and refs:
                    actuals.append(".".join(str(ref) for ref in refs if str(ref)))
                else:
                    actuals.append("")
            return {
                "source": "clang_ast_call_expr",
                "line": int(call.get("line") or 0),
                "arguments": actuals,
            }
        return {}

    @classmethod
    def _source_callsite_argument_refs(cls, code: str, callee: str) -> Dict[str, Any]:
        if not code or not callee:
            return {}
        pattern = re.compile(rf"\b{re.escape(callee)}\s*\((?P<args>[^;{{}}]*)\)")
        for raw in code.splitlines():
            text = cls._strip_numbered_line_prefix(raw)
            match = pattern.search(text)
            if not match:
                continue
            return {
                "source": "source_text_best_effort",
                "line": cls._numbered_line(raw),
                "arguments": cls._split_c_arguments(match.group("args")),
            }
        return {}

    @classmethod
    def _function_param_names(cls, code: str, func_name: str) -> List[str]:
        if not code or not func_name:
            return []
        text = "\n".join(cls._strip_numbered_line_prefix(line) for line in code.splitlines())
        match = re.search(rf"\b{re.escape(func_name)}\s*\((?P<params>[^)]*)\)", text, re.DOTALL)
        if not match:
            return []
        params = cls._split_c_arguments(match.group("params"))
        names = []
        for param in params:
            cleaned = re.sub(r"/\*.*?\*/", " ", param).strip()
            if not cleaned or cleaned == "void":
                continue
            cleaned = cleaned.split("=")[0].strip()
            name_match = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", cleaned)
            if name_match:
                names.append(name_match.group(1))
        return names

    @staticmethod
    def _split_c_arguments(args: str) -> List[str]:
        result: List[str] = []
        current: List[str] = []
        depth = 0
        for ch in str(args or ""):
            if ch in "([{":
                depth += 1
            elif ch in ")]}" and depth > 0:
                depth -= 1
            if ch == "," and depth == 0:
                item = "".join(current).strip()
                if item:
                    result.append(item)
                current = []
                continue
            current.append(ch)
        item = "".join(current).strip()
        if item:
            result.append(item)
        return result

    @staticmethod
    def _strip_numbered_line_prefix(line: str) -> str:
        return re.sub(r"^\s*\d+\s*\|\s?", "", str(line or ""))

    @staticmethod
    def _numbered_line(line: str) -> int:
        match = re.match(r"^\s*(\d+)\s*\|", str(line or ""))
        return int(match.group(1)) if match else 0

    def _clang_tooling_evidence_for(
        self,
        *,
        func_name: str,
        file_path: str,
        start_line: int = 0,
        end_line: int = 0,
    ) -> Dict[str, Any]:
        if self._candidate_backend_profile() not in {"clang", "unified"}:
            return {}
        compile_commands_path = getattr(self.code_index, "compile_commands_path", None)
        if not compile_commands_path:
            return {}
        cache_key = (func_name, file_path, int(start_line or 0), int(end_line or 0))
        cache = getattr(self, "_clang_tooling_evidence_cache", None)
        if isinstance(cache, dict) and cache_key in cache:
            return cache[cache_key]
        provider = getattr(self, "_clang_tooling_provider", None)
        provider_path = getattr(provider, "compile_commands_path", None)
        if provider is None or str(provider_path) != str(compile_commands_path):
            provider = ClangToolingEvidenceProvider(Path(compile_commands_path))
            try:
                self._clang_tooling_provider = provider
            except Exception:
                pass
        try:
            evidence = provider.collect_for_function(
                func_name=func_name,
                file_path=file_path,
                start_line=start_line,
                end_line=end_line,
            )
            if isinstance(cache, dict):
                cache[cache_key] = evidence
            return evidence
        except Exception as exc:
            logger.debug("Unable to collect clang tooling evidence for %s: %s", func_name, exc)
            return {}

    @staticmethod
    def _clang_tooling_matcher_candidates_from_evidence(
        func_name: str,
        file_path: str,
        tooling_evidence: Dict[str, Any],
        *,
        allowed_skills: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        return clang_tooling_matcher_candidates_from_evidence(
            func_name,
            file_path,
            tooling_evidence,
            allowed_skills=allowed_skills,
        )

    @staticmethod
    def _defect_class_from_clang_matcher_fact(fact: Dict[str, Any]) -> str:
        return defect_class_from_clang_matcher_fact(fact)

    @staticmethod
    def _skill_for_matcher_defect(defect_class: str) -> str:
        return skill_for_matcher_defect(defect_class)

    @staticmethod
    def _clang_matcher_fact_to_candidate(
        func_name: str,
        file_path: str,
        fact: Dict[str, Any],
        defect_class: str,
        tooling_evidence: Dict[str, Any],
    ) -> Dict[str, Any]:
        return clang_matcher_fact_to_candidate(
            func_name,
            file_path,
            fact,
            defect_class,
            tooling_evidence,
        )

    @staticmethod
    def _compact_clang_tooling_evidence(tooling_evidence: Dict[str, Any]) -> Dict[str, Any]:
        return compact_clang_tooling_evidence(tooling_evidence)

    @staticmethod
    def _rule_candidate_dedup_key(issue: Dict[str, Any]) -> str:
        return rule_candidate_dedup_key(issue)

    @staticmethod
    def _merge_rule_candidate_duplicate(primary: Dict[str, Any], duplicate: Dict[str, Any]) -> None:
        merge_rule_candidate_duplicate(primary, duplicate)

    def _detect_backend_signal_candidates(self, state: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Convert KnowledgeDB/SVF/Saber findings into normal candidates."""
        scan_started = time.time()
        candidates: List[Dict[str, Any]] = []
        db = self._get_knowledge_db()
        entry_func = str(state.get("entry_func") or "")
        profile = self._candidate_backend_profile()
        db_cache_before = self._knowledge_db_callgraph_cache_stats(db)
        reachable_started = time.time()
        reachable_funcs: Set[str] = set()
        if db is not None:
            reachable_funcs = self._reachable_function_names_from_entry(entry_func)
        reachable_duration = time.time() - reachable_started
        scope_reachable_funcs = (
            self._reachable_function_names_from_entry(
                entry_func,
                max_depth=4,
                max_nodes=200,
                callee_limit=80,
            )
            if profile == "joern" or (db is not None and profile in {"clang", "unified"})
            else reachable_funcs
        )
        if db is not None:
            try:
                bugs = db.get_enriched_taint_bugs(
                    func_names=sorted(reachable_funcs),
                    limit=50,
                )
            except TypeError:
                bugs = db.get_enriched_taint_bugs(func_name=entry_func, limit=50)
            except Exception as exc:
                logger.debug("Unable to read backend taint bugs: %s", exc)
                bugs = []

            svf_candidates = (
                SvfValueFlowCandidateGenerator(
                    source_path_resolver=self._reconstruct_svf_source_path,
                ).generate_issues(
                    bugs,
                    entry_func=entry_func,
                )
            )
            if bugs or svf_candidates:
                logger.info(
                    "Backend Saber signal candidates for entry '%s': reachable=%d, bugs=%d, candidates=%d",
                    entry_func,
                    len(reachable_funcs),
                    len(bugs),
                    len(svf_candidates),
                )
            candidates.extend(svf_candidates)
        candidates.extend(
            self._detect_clang_knowledgedb_candidates(
                state,
                db,
                reachable_funcs=scope_reachable_funcs,
            )
        )
        candidates.extend(
            self._detect_joern_cpg_candidates(
                state,
                reachable_funcs=scope_reachable_funcs,
            )
        )
        candidates = dedupe_rule_candidates(candidates)
        annotation_started = time.time()
        annotated = self._annotate_candidate_issues(
            candidates,
            checker=self._backend_signal_checker(),
            path_kind="backend_signal",
        )
        annotation_duration = time.time() - annotation_started
        db_cache_delta = self._callgraph_cache_stat_delta(
            db_cache_before,
            self._knowledge_db_callgraph_cache_stats(db),
        )
        logger.info(
            "Backend signal scan end entry='%s' profile=%s reachable=%d scope_reachable=%d "
            "candidates=%d duration=%.2fs reachable_duration=%.2fs evidence_annotation_duration=%.2fs "
            "db_cache_delta=%s",
            entry_func,
            profile,
            len(reachable_funcs),
            len(scope_reachable_funcs),
            len(annotated),
            time.time() - scan_started,
            reachable_duration,
            annotation_duration,
            db_cache_delta,
        )
        return annotated

    def _merge_unified_evidence_candidates(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return merge_unified_evidence_candidates(
            candidates,
            enabled=self._candidate_backend_profile() == "unified",
        )

    @classmethod
    def _unified_candidates_may_refer_same_issue(
        cls,
        left: Dict[str, Any],
        right: Dict[str, Any],
    ) -> bool:
        return unified_candidates_may_refer_same_issue(left, right)

    @staticmethod
    def _candidate_source_name(issue: Dict[str, Any]) -> str:
        return candidate_source_name(issue)

    @staticmethod
    def _defect_classes_compatible(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
        return defect_classes_compatible(left, right)

    @classmethod
    def _candidate_file_line(cls, issue: Dict[str, Any]) -> tuple[str, int]:
        return candidate_file_line(issue)

    @staticmethod
    def _parse_location_file_line(location: str) -> tuple[str, int]:
        return parse_location_file_line(location)

    @classmethod
    def _candidate_function_names(cls, issue: Dict[str, Any]) -> Set[str]:
        return candidate_function_names(issue)

    @staticmethod
    def _candidate_symbols(issue: Dict[str, Any]) -> Set[str]:
        return candidate_symbols(issue)

    @staticmethod
    def _attach_unified_secondary_evidence(primary: Dict[str, Any], secondary: Dict[str, Any]) -> None:
        attach_unified_secondary_evidence(primary, secondary)

    def _detect_clang_knowledgedb_candidates(
        self,
        state: Dict[str, Any],
        db: Optional[Any],
        *,
        reachable_funcs: Optional[Set[str]] = None,
    ) -> List[Dict[str, Any]]:
        if db is None or self._candidate_backend_profile() not in {"clang", "unified"}:
            return []
        find_missing = getattr(db, "find_callers_without_callee", None)
        if not callable(find_missing):
            return []
        entry_func = str(state.get("entry_func") or "")
        pairs = self._resource_release_pairs_from_overlay()
        scan_started = time.time()
        if reachable_funcs is None:
            reachable_funcs = self._reachable_function_names_from_entry(
                entry_func,
                max_depth=4,
                max_nodes=200,
                callee_limit=80,
            )
        candidates: List[Dict[str, Any]] = []
        rows_seen = 0
        for acquire, release, pair_source in pairs:
            try:
                rows = find_missing(acquire, release, limit=100)
            except Exception as exc:
                logger.debug("Unable to query KnowledgeDB pair %s/%s: %s", acquire, release, exc)
                continue
            rows_seen += len(rows)
            for row in rows:
                func = str(row.get("function") or "")
                if not self._target_in_reachable_functions(func, reachable_funcs):
                    continue
                candidates.append(
                    self._clang_pair_row_to_candidate(
                        row,
                        entry_func=entry_func,
                        pair_source=pair_source,
                    )
                )
        logger.info(
            "Backend Clang KnowledgeDB signal scan entry='%s': pairs=%d rows=%d reachable=%d "
            "candidates=%d duration=%.2fs",
            entry_func,
            len(pairs),
            rows_seen,
            len(reachable_funcs),
            len(candidates),
            time.time() - scan_started,
        )
        return candidates

    def _resource_release_pairs_from_overlay(self) -> List[tuple[str, str, str]]:
        return resource_release_pairs_from_overlay(self._get_semantic_overlay())

    def _clang_pair_row_to_candidate(
        self,
        row: Dict[str, Any],
        *,
        entry_func: str,
        pair_source: str,
    ) -> Dict[str, Any]:
        return clang_pair_row_to_candidate(
            row,
            entry_func=entry_func,
            pair_source=pair_source,
        )

    def _detect_joern_cpg_candidates(
        self,
        state: Dict[str, Any],
        *,
        reachable_funcs: Optional[Set[str]] = None,
    ) -> List[Dict[str, Any]]:
        if self._candidate_backend_profile() != "joern":
            return []
        backend_attr = getattr(self.code_index, "backend", None)
        backend = backend_attr() if callable(backend_attr) else backend_attr
        joern_client = getattr(backend, "joern_client", None)
        if joern_client is None:
            return []
        try:
            from ...rules.engine import RuleEngine

            engine = RuleEngine(joern_client, self.user_config)
            matches = engine.run_builtin_scan()
            matches.extend(engine.run_semantic_cpg_rule_library())
            matches.extend(engine.run_paired_function_checks())
            matches.extend(engine.run_configured_data_flow_checks())
        except Exception as exc:
            logger.debug("Unable to run Joern CPG candidate checks: %s", exc)
            return []
        entry_func = str(state.get("entry_func") or "")
        if reachable_funcs is None:
            reachable_funcs = self._reachable_function_names_from_entry(
                entry_func,
                max_depth=4,
                max_nodes=200,
                callee_limit=80,
            )
        scoped = [
            match
            for match in matches
            if self._target_in_reachable_functions(str(getattr(match, "func_name", "")), reachable_funcs)
        ]
        return [self._joern_rule_match_to_candidate(match, entry_func) for match in scoped]

    def _match_reachable_from_entry(
        self,
        entry_func: str,
        target_func: str,
        *,
        max_depth: int = 4,
        max_nodes: int = 200,
    ) -> bool:
        if not entry_func or not target_func:
            return False
        if self._function_names_may_match(entry_func, target_func):
            return True
        reachable_funcs = self._reachable_function_names_from_entry(
            entry_func,
            max_depth=max_depth,
            max_nodes=max_nodes,
            callee_limit=80,
        )
        return self._target_in_reachable_functions(target_func, reachable_funcs)

    def _reachable_cache_state(self) -> tuple[Dict[tuple[str, int, int, int], Set[str]], threading.RLock]:
        cache = getattr(self, "_reachable_function_cache", None)
        lock = getattr(self, "_reachable_function_cache_lock", None)
        if cache is None:
            cache = {}
            self._reachable_function_cache = cache
        if lock is None:
            lock = threading.RLock()
            self._reachable_function_cache_lock = lock
        return cache, lock

    def _target_in_reachable_functions(self, target_func: str, reachable_funcs: Set[str]) -> bool:
        if not target_func:
            return False
        return any(
            self._function_names_may_match(name, target_func)
            for name in reachable_funcs
        )

    def _find_call_path_from_entry(
        self,
        entry_func: str,
        target_func: str,
        *,
        max_depth: int = 5,
        max_nodes: int = 300,
    ) -> List[str]:
        if not entry_func or not target_func:
            return []
        if self._function_names_may_match(entry_func, target_func):
            return [entry_func]
        get_callees = getattr(self.code_index, "get_callees", None)
        if not callable(get_callees):
            return []
        seen = {entry_func}
        queue: List[tuple[str, int, List[str]]] = [(entry_func, 0, [entry_func])]
        while queue and len(seen) < max_nodes:
            current, depth, path = queue.pop(0)
            if depth >= max_depth:
                continue
            try:
                callees = get_callees(current, limit=100)
            except Exception:
                continue
            for item in callees or []:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name") or item.get("callee_name") or "").strip()
                if not name or name in seen:
                    continue
                next_path = path + [name]
                if self._function_names_may_match(name, target_func):
                    return next_path
                seen.add(name)
                queue.append((name, depth + 1, next_path))
        return []

    def _reachable_function_names_from_entry(
        self,
        entry_func: str,
        *,
        max_depth: int = 5,
        max_nodes: int = 300,
        callee_limit: int = 100,
    ) -> Set[str]:
        if not entry_func:
            return set()
        cache_key = (entry_func, int(max_depth), int(max_nodes), int(callee_limit))
        cache, lock = self._reachable_cache_state()
        with lock:
            cached = cache.get(cache_key)
            if cached is not None:
                return set(cached)
        reachable: Set[str] = {entry_func}
        get_callees = getattr(self.code_index, "get_callees", None)
        if not callable(get_callees):
            with lock:
                cache[cache_key] = set(reachable)
            return reachable
        queue: deque[tuple[str, int]] = deque([(entry_func, 0)])
        while queue and len(reachable) < max_nodes:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue
            try:
                callees = get_callees(current, limit=callee_limit)
            except Exception:
                continue
            for item in callees or []:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name") or item.get("callee_name") or "").strip()
                if not name or name in reachable:
                    continue
                reachable.add(name)
                queue.append((name, depth + 1))
                if len(reachable) >= max_nodes:
                    break
        with lock:
            cache[cache_key] = set(reachable)
        return reachable

    def _reconstruct_svf_source_path(self, bug: Dict[str, Any], entry_func: str) -> Dict[str, Any]:
        target_func = str(bug.get("func_name") or bug.get("source_func") or entry_func or "")
        source_func = str(bug.get("source_func") or "")
        sink_func = str(bug.get("sink_func") or "")
        file_path = str(bug.get("file_path") or "")
        line = int(bug.get("line") or bug.get("func_start") or 0)
        call_path = self._find_call_path_from_entry(entry_func, target_func)
        reported_snippet = self._source_snippet(file_path, line, radius=4)
        target_impl = self._compact_function_impl(target_func)
        source_impl = self._compact_function_impl(source_func) if source_func and source_func != target_func else {}
        sink_impl = self._compact_function_impl(sink_func) if sink_func and sink_func not in {target_func, source_func} else {}
        source_level_flow = self._svf_source_level_flow_events(
            bug,
            target_impl=target_impl,
            source_impl=source_impl,
            sink_impl=sink_impl,
            file_path=file_path,
            line=line,
            reported_snippet=reported_snippet,
        )
        notes = [
            "Source-level reconstruction uses CodeIndex call graph and source snippets.",
            "SVF/Saber source and sink names may be LLVM-level summaries and still require Validator confirmation.",
        ]
        if not call_path:
            notes.append("Entry-to-target call path was not proven by CodeIndex within the bounded search.")
        if not reported_snippet:
            notes.append("No source snippet could be read for the reported SVF location.")
        return {
            "entry_function": entry_func,
            "target_function": target_func,
            "source_function": source_func,
            "sink_function": sink_func,
            "call_path": call_path,
            "complete_to_entry": bool(call_path),
            "reported_location": {"file": file_path, "line": line},
            "reported_snippet": reported_snippet,
            "source_level_flow": source_level_flow,
            "target_function_context": target_impl,
            "source_function_context": source_impl,
            "sink_function_context": sink_impl,
            "reconstruction_notes": notes,
        }

    def _svf_source_level_flow_events(
        self,
        bug: Dict[str, Any],
        *,
        target_impl: Dict[str, Any],
        source_impl: Dict[str, Any],
        sink_impl: Dict[str, Any],
        file_path: str,
        line: int,
        reported_snippet: str,
    ) -> Dict[str, Any]:
        source_symbol = str(
            bug.get("source_symbol")
            or bug.get("source_func")
            or bug.get("source")
            or ""
        )
        sink_symbol = str(
            bug.get("sink_symbol")
            or bug.get("sink_func")
            or bug.get("sink")
            or bug.get("bug_type")
            or ""
        )
        contexts = [
            ctx
            for ctx in (target_impl, source_impl, sink_impl)
            if isinstance(ctx, dict) and (ctx.get("function") or ctx.get("code_excerpt"))
        ]
        object_symbols = self._infer_svf_object_symbols(bug, reported_snippet, contexts)
        events: List[Dict[str, Any]] = []
        source_event = self._find_svf_symbol_event("source", source_symbol, contexts)
        sink_event = self._find_svf_symbol_event("sink", sink_symbol, contexts)
        if source_event:
            events.append(source_event)
        if reported_snippet:
            events.append(
                {
                    "role": "reported_location",
                    "symbol": str(bug.get("bug_type") or ""),
                    "function": str(target_impl.get("function") or bug.get("func_name") or ""),
                    "file": file_path,
                    "line": line,
                    "code": self._one_line_source(reported_snippet),
                    "match_kind": "reported_svf_location",
                }
            )
        if sink_event:
            events.append(sink_event)
        for event in events:
            code = str(event.get("code") or "")
            event["object_mentions"] = [
                symbol
                for symbol in object_symbols
                if re.search(rf"\b{re.escape(symbol)}\b", code)
            ][:8]
        notes = []
        if source_symbol and not source_event:
            notes.append(f"Source symbol `{source_symbol}` was not found in compact source contexts.")
        if sink_symbol and not sink_event:
            notes.append(f"Sink symbol `{sink_symbol}` was not found in compact source contexts.")
        return {
            "schema": "svf_source_level_flow_v1",
            "source_symbol": source_symbol,
            "sink_symbol": sink_symbol,
            "object_symbols": object_symbols,
            "events": events,
            "expression_edges": self._svf_expression_edges(events),
            "complete_source_to_sink": bool(source_event and sink_event),
            "notes": notes,
        }

    def _infer_svf_object_symbols(
        self,
        bug: Dict[str, Any],
        reported_snippet: str,
        contexts: Sequence[Dict[str, Any]],
    ) -> List[str]:
        symbols: List[str] = []
        for key in (
            "object_symbol",
            "object",
            "value",
            "value_symbol",
            "pointer",
            "ptr",
            "source_var",
            "sink_var",
        ):
            value = str(bug.get(key) or "").strip()
            if self._looks_like_c_identifier(value):
                symbols.append(value)
        for code in [reported_snippet] + [str(ctx.get("code_excerpt") or "") for ctx in contexts]:
            for name in self._names_from_memory_expression(code):
                symbols.append(name)
        result: List[str] = []
        for symbol in symbols:
            if symbol not in result and not self._is_common_c_token(symbol):
                result.append(symbol)
        return result[:12]

    @classmethod
    def _names_from_memory_expression(cls, code: str) -> List[str]:
        names: List[str] = []
        text = str(code or "")
        for match in re.finditer(
            r"\b(?:free|delete|memcpy|memmove|strcpy|strncpy|malloc|calloc|realloc)\s*\((?P<args>[^)]*)\)",
            text,
        ):
            args = [part.strip() for part in match.group("args").split(",")]
            for arg in args[:3]:
                name = re.match(r"(?:&|\*)?\s*(?P<name>[A-Za-z_]\w*)\b", arg)
                if name and cls._looks_like_c_identifier(name.group("name")):
                    names.append(name.group("name"))
        return names

    @staticmethod
    def _svf_expression_edges(events: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
        edges: List[Dict[str, Any]] = []
        previous: Optional[Dict[str, Any]] = None
        for event in events:
            if previous is None:
                previous = event
                continue
            prev_mentions = set(previous.get("object_mentions") or [])
            cur_mentions = set(event.get("object_mentions") or [])
            shared = sorted(prev_mentions & cur_mentions)
            edges.append(
                {
                    "from_role": previous.get("role"),
                    "to_role": event.get("role"),
                    "shared_object_symbols": shared,
                    "reason": "shared_object_symbol" if shared else "svf_reported_order",
                }
            )
            previous = event
        return edges

    @staticmethod
    def _looks_like_c_identifier(value: str) -> bool:
        return bool(re.fullmatch(r"[A-Za-z_]\w*", str(value or "")))

    @staticmethod
    def _is_common_c_token(value: str) -> bool:
        return str(value or "") in {
            "if",
            "return",
            "NULL",
            "sizeof",
            "free",
            "malloc",
            "calloc",
            "realloc",
            "memcpy",
            "memmove",
            "strcpy",
            "strncpy",
        }

    def _find_svf_symbol_event(
        self,
        role: str,
        symbol: str,
        contexts: Sequence[Dict[str, Any]],
    ) -> Dict[str, Any]:
        if not symbol:
            return {}
        for context in contexts:
            function = str(context.get("function") or "")
            if self._function_names_may_match(function, symbol):
                first_line = self._first_code_line(str(context.get("code_excerpt") or ""))
                return {
                    "role": role,
                    "symbol": symbol,
                    "function": function,
                    "file": str(context.get("file") or ""),
                    "line": int(context.get("start_line") or 0),
                    "code": first_line or str(context.get("signature") or ""),
                    "match_kind": "function_context",
                }
        call_re = re.compile(rf"\b{re.escape(symbol)}\s*\(")
        for context in contexts:
            for raw in str(context.get("code_excerpt") or "").splitlines():
                line_number, text = self._numbered_source_line(raw)
                if call_re.search(text):
                    return {
                        "role": role,
                        "symbol": symbol,
                        "function": str(context.get("function") or ""),
                        "file": str(context.get("file") or ""),
                        "line": line_number or int(context.get("start_line") or 0),
                        "code": text.strip(),
                        "match_kind": "call_expression",
                    }
        return {}

    @staticmethod
    def _numbered_source_line(raw: str) -> tuple[int, str]:
        match = re.match(r"^\s*(\d+)\s*\|\s?(.*)$", str(raw or ""))
        if match:
            return int(match.group(1)), match.group(2)
        return 0, str(raw or "")

    @classmethod
    def _first_code_line(cls, code: str) -> str:
        for raw in str(code or "").splitlines():
            _, text = cls._numbered_source_line(raw)
            text = text.strip()
            if text:
                return text
        return ""

    @staticmethod
    def _one_line_source(code: str, *, limit: int = 220) -> str:
        return " ".join(str(code or "").split())[:limit]

    def _source_snippet(self, file_path: str, line: int, *, radius: int = 3) -> str:
        if not file_path or line <= 0:
            return ""
        get_file_snippet = getattr(self.code_index, "get_file_snippet", None)
        if not callable(get_file_snippet):
            return ""
        try:
            snippet = get_file_snippet(file_path, max(1, line - radius), line + radius)
        except Exception:
            return ""
        if not isinstance(snippet, dict):
            return ""
        return str(snippet.get("code") or "")

    def _compact_function_impl(self, func_name: str, *, max_lines: int = 40) -> Dict[str, Any]:
        if not func_name:
            return {}
        get_impl = getattr(self.code_index, "get_function_impl", None)
        if not callable(get_impl):
            return {}
        try:
            impl = get_impl(func_name, max_lines=max_lines, warn_missing=False)
        except TypeError:
            try:
                impl = get_impl(func_name, warn_missing=False)
            except Exception:
                return {}
        except Exception:
            return {}
        if not isinstance(impl, dict):
            return {}
        code = str(impl.get("code") or "")
        return {
            "function": func_name,
            "file": str(impl.get("file") or ""),
            "start_line": int(impl.get("start_line") or 0),
            "end_line": int(impl.get("end_line") or 0),
            "signature": str(impl.get("signature") or ""),
            "code_excerpt": "\n".join(code.splitlines()[:max_lines]),
            "truncated": bool(impl.get("truncated")) or len(code.splitlines()) > max_lines,
        }

    @staticmethod
    def _function_names_may_match(left: str, right: str) -> bool:
        left = str(left or "").strip()
        right = str(right or "").strip()
        if not left or not right:
            return False
        if left == right:
            return True
        left_tail = re.split(r"[:.]", left)[-1]
        right_tail = re.split(r"[:.]", right)[-1]
        return bool(left_tail and right_tail and left_tail == right_tail)

    def _joern_rule_match_to_candidate(self, match: Any, entry_func: str = "") -> Dict[str, Any]:
        return joern_rule_match_to_candidate(match, entry_func)

    def _candidate_backend_profile(self) -> str:
        return backend_profile_for_code_index(self.code_index)

    def _get_semantic_overlay(self) -> Dict[str, Any]:
        if self._semantic_overlay is None:
            self._semantic_overlay = SemanticOverlayCompiler(self.user_config).compile()
        return self._semantic_overlay

    def _annotate_candidate_issues(
        self,
        issues: List[Dict[str, Any]],
        *,
        checker: str,
        path_kind: str,
    ) -> List[Dict[str, Any]]:
        profile = self._candidate_backend_profile()
        overlay = self._get_semantic_overlay()
        for issue in issues:
            evidence_pack = issue.get("evidence_pack") if isinstance(issue.get("evidence_pack"), dict) else {}
            issue_checker = str(issue.get("evidence_checker") or evidence_pack.get("checker") or checker)
            annotate_candidate_evidence(
                issue,
                backend_profile=profile,
                checker=issue_checker,
                overlay=overlay,
                path_kind=path_kind,
            )
        return issues

    def _local_candidate_checker(self) -> str:
        return {
            "regex": "regex_local_pattern_checker",
            "clang": "clang_indexed_local_pattern_checker",
            "joern": "joern_indexed_local_pattern_checker",
            "unified": "unified_clang_svf_local_pattern_checker",
        }.get(self._candidate_backend_profile(), "regex_local_pattern_checker")

    def _graph_candidate_checker(self) -> str:
        return {
            "regex": "regex_callgraph_protocol_checker",
            "clang": "clang_callgraph_protocol_checker",
            "joern": "joern_cpg_protocol_graph_checker",
            "unified": "unified_callgraph_svf_protocol_checker",
        }.get(self._candidate_backend_profile(), "regex_callgraph_protocol_checker")

    def _backend_signal_checker(self) -> str:
        return {
            "regex": "knowledge_db_backend_signal_adapter",
            "clang": "clang_knowledgedb_signal_adapter",
            "joern": "joern_backend_signal_adapter",
            "unified": "svf_saber_backend_signal_adapter",
        }.get(self._candidate_backend_profile(), "knowledge_db_backend_signal_adapter")

    def _detect_backend_signal_tickets(
        self,
        state: Dict[str, Any],
        allowed_skills: Optional[List[str]] = None,
    ) -> List[Any]:
        generator = RegexCandidateGenerator(self._get_local_pattern_semantics())
        tickets = [
            generator.issue_to_ticket(issue)
            for issue in self._detect_backend_signal_candidates(state)
        ]
        if allowed_skills is None:
            return tickets
        allowed = set(allowed_skills)
        return [ticket for ticket in tickets if ticket.skill in allowed]

    def _get_local_pattern_semantics(self) -> LocalPatternSemantics:
        """Build once-per-run local-pattern aliases and project API semantics."""
        if self._local_pattern_semantics is None:
            self._local_pattern_semantics = LocalPatternSemanticBuilder(
                self.code_index,
                self.user_config,
                self.snapshot_store,
                self.config.project.exclude_paths,
            ).build()
        return self._local_pattern_semantics

    def _get_knowledge_db(self) -> Optional[Any]:
        backend = getattr(self.code_index, "_backend", None)
        if backend is None:
            return None
        db = getattr(backend, "db", None)
        if db is not None:
            return db
        return getattr(backend, "_db", None)

    @staticmethod
    def _knowledge_db_callgraph_cache_stats(db: Optional[Any]) -> Dict[str, int]:
        if db is None:
            return {}
        stats = getattr(db, "callgraph_cache_stats", None)
        if not callable(stats):
            return {}
        try:
            raw = stats()
        except Exception:
            return {}
        if not isinstance(raw, dict):
            return {}
        return {str(key): int(value) for key, value in raw.items() if isinstance(value, int)}

    @staticmethod
    def _callgraph_cache_stat_delta(before: Dict[str, int], after: Dict[str, int]) -> Dict[str, int]:
        keys = set(before) | set(after)
        return {
            key: int(after.get(key, 0)) - int(before.get(key, 0))
            for key in sorted(keys)
            if int(after.get(key, 0)) != int(before.get(key, 0))
        }

    def _persist_candidate_ir_records(self, issues: List[Dict[str, Any]]) -> None:
        """Persist compact candidate evidence into KnowledgeDB inspection IR tables."""
        if not issues:
            return
        db = self._get_knowledge_db()
        if db is None:
            return

        for issue in issues:
            try:
                candidate_id = str(issue.get("candidate_id") or issue.get("id") or "")
                if not candidate_id:
                    continue
                issue_func = str(issue.get("function") or "")
                location = str(issue.get("location") or "")
                file_path, line = self._parse_issue_location(location)
                if not file_path:
                    file_path = location.split(":")[0] if ":" in location else ""
                if not line:
                    line = 0
                defect_class = str(issue.get("defect_class") or issue.get("subcategory") or "")
                source_text = str(issue.get("source") or "")
                sink_text = str(issue.get("sink") or "")
                source_stmt = db.upsert_ir_statement(
                    file_path,
                    line,
                    issue_func,
                    kind="candidate_source",
                    normalized_code=source_text or str(issue.get("description") or ""),
                    ast_kind=defect_class,
                )
                sink_stmt = db.upsert_ir_statement(
                    file_path,
                    line,
                    issue_func,
                    kind="candidate_sink",
                    normalized_code=sink_text or str(issue.get("description") or ""),
                    ast_kind=defect_class,
                )
                score_components = self._score_components(issue, {})
                path_id = db.upsert_ir_path_slice(
                    candidate_id,
                    issue_func,
                    source_stmt=source_stmt,
                    sink_stmt=sink_stmt,
                    path_summary=json.dumps(
                        (issue.get("evidence_pack") or {}).get("path") or {},
                        ensure_ascii=False,
                    ),
                    guards=json.dumps(issue.get("negative_evidence") or [], ensure_ascii=False),
                    contradictions=json.dumps(issue.get("negative_evidence") or [], ensure_ascii=False),
                    score_components=json.dumps(score_components, ensure_ascii=False),
                )
                refs = [f"ir_path_slices:{path_id}"] if path_id else []
                confidence = float(issue.get("rule_confidence") or issue.get("confidence") or 0.5)
                if defect_class in {
                    "memory_leak",
                    "double_free",
                    "invalid_free",
                    "use_after_free",
                    "realloc_misuse",
                    "stack_escape",
                    "stale_fd",
                    "type_confusion",
                    "bounds",
                    "integer_overflow",
                    "infinite_loop",
                    "log_amplification",
                    "key_truncation",
                }:
                    event_id = db.insert_ir_resource_event(
                        candidate_id,
                        source_text or sink_text or defect_class,
                        defect_class,
                        str(issue.get("rule") or ""),
                        file_path,
                        line,
                        issue_func,
                        confidence=confidence,
                    )
                    refs.append(f"ir_resource_events:{event_id}")
                if defect_class in {
                    "deadlock",
                    "missing_unlock",
                    "held_lock_callback",
                    "lost_wakeup",
                    "double_checked_locking",
                    "deadlock",
                }:
                    event_id = db.insert_ir_lock_event(
                        candidate_id,
                        source_text or sink_text or "lock",
                        defect_class,
                        file_path,
                        line,
                        issue_func,
                        confidence=confidence,
                    )
                    refs.append(f"ir_lock_events:{event_id}")
                if defect_class in {
                    "race",
                    "refcount_race",
                    "object_publication",
                    "double_checked_locking",
                    "toctou",
                    "stale_fd",
                }:
                    event_id = db.insert_ir_shared_access(
                        candidate_id,
                        source_text or sink_text or defect_class,
                        "",
                        defect_class,
                        file_path,
                        line,
                        issue_func,
                        confidence=confidence,
                    )
                    refs.append(f"ir_shared_accesses:{event_id}")

                issue.setdefault("evidence_refs", [])
                for ref in refs:
                    if ref not in issue["evidence_refs"]:
                        issue["evidence_refs"].append(ref)
                evidence_pack = issue.setdefault("evidence_pack", {})
                evidence_refs = evidence_pack.setdefault("evidence_refs", [])
                for ref in refs:
                    if ref not in evidence_refs:
                        evidence_refs.append(ref)
            except Exception as exc:
                logger.debug("Failed to persist candidate IR for %s: %s", issue.get("id"), exc)
        try:
            db.commit()
        except Exception:
            pass

    def _step_validate_findings(self, state: Dict[str, Any]) -> None:
        runner = getattr(self, "validation_runner", None)
        if runner is None:
            runner = self._make_validation_runner()
            self.validation_runner = runner
        runner.run(state)

    def _make_validation_runner(self) -> ValidationRunner:
        return ValidationRunner(
            config=self.config,
            llm_clients=getattr(self, "llm_clients", {}),
            validation_pipeline=self.validation_pipeline,
            code_index=getattr(self, "code_index", None),
            snapshot_store=getattr(self, "snapshot_store", None),
            get_tools=self._get_tools,
            tool_policy_for_agent=self._tool_policy_for_agent,
            attach_agent_contract=self._attach_agent_contract,
            remember_validation_result=self._remember_validation_result,
            issue_key_fn=self._canonical_issue_key,
            deduplicate_issues_fn=self._deduplicate_candidate_issues,
        )

    def _remember_validation_result(self, issue: Dict[str, Any], status: str) -> None:
        """Persist validator disposition as review memory for later scans."""
        dedup_key = str(issue.get("dedup_key") or self._canonical_issue_key(issue))
        if not dedup_key:
            return
        status_key = str(status or "").lower()
        if status_key == "rejected":
            # Validator rejections are often context-sensitive.  Persisting them
            # as broad dedup-key baselines can suppress stronger evidence for
            # the same root cause later in the same scan or a future run.  User
            # false-positive feedback is still handled by explicit suppressions.
            return
        memory_status = {
            "validated": "verified",
            "needs_review": "uncertain",
            "uncertain": "uncertain",
            "rejected": "rejected",
        }.get(status_key, status_key or "unknown")
        try:
            review_memory = getattr(self.validation_pipeline, "review_memory", None)
            if review_memory is not None:
                review_memory.record_validator_memory(dedup_key, memory_status, issue)
            else:
                self.user_config.upsert_finding_baseline(dedup_key, memory_status, issue)
        except Exception as exc:
            logger.debug("Failed to persist validation memory for %s: %s", issue.get("id"), exc)

    def _score_components(self, issue: Dict[str, Any], val_data: Dict[str, Any]) -> Dict[str, float]:
        pipeline = getattr(self, "validation_pipeline", None)
        if pipeline is None:
            user_config = getattr(self, "user_config", None)
            if user_config is None:
                class EmptyUserConfig:
                    def get_finding_baseline(self, _dedup_key: str) -> None:
                        return None

                user_config = EmptyUserConfig()
            pipeline = ValidationPipeline(user_config, issue_key_fn=self._canonical_issue_key)
        return pipeline.score_components(issue, val_data)

    def _finding_baseline_for_issue(self, issue: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        pipeline = getattr(self, "validation_pipeline", None)
        if pipeline is not None:
            return pipeline.find_baseline(issue)
        dedup_key = str(issue.get("dedup_key") or self._canonical_issue_key(issue))
        lookup = getattr(self.user_config, "get_finding_baseline_for_issue", None)
        if callable(lookup):
            return lookup(issue, dedup_key)
        return self.user_config.get_finding_baseline(dedup_key)

    @staticmethod
    def _validation_verdict(val_data: Dict[str, Any]) -> str:
        return validation_verdict(val_data)

    @classmethod
    def _is_entry_root_dead_code_rejection(
        cls,
        val_data: Dict[str, Any],
        evidence_pack: Dict[str, Any],
    ) -> bool:
        return is_entry_root_dead_code_rejection(val_data, evidence_pack)

    def _deduplicate_candidate_issues(
        self, issues: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Merge candidate findings that point at the same root-cause sink."""
        deduped, _summary = deduplicate_semantic_issues_programmatic(issues)
        return deduped

    def _deduplicate_report_issues(
        self,
        issues: List[Dict[str, Any]],
        state: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Apply final-report semantic dedup before report views are built."""
        semantic_cfg = getattr(getattr(self.config, "reporting", None), "semantic_dedup", None)
        if semantic_cfg is None or not getattr(semantic_cfg, "enabled", True):
            deduped = deduplicate_issues(issues)
            state["semantic_dedup_summary"] = {
                "enabled": False,
                "input_issue_count": len(issues),
                "output_issue_count": len(deduped),
            }
            return deduped

        deduped, summary = deduplicate_semantic_issues_programmatic(issues)
        summary.update(
            {
                "enabled": True,
                "llm_enabled": bool(getattr(semantic_cfg, "llm_enabled", False)),
                "input_issue_count": len(issues),
                "after_programmatic_issue_count": len(deduped),
            }
        )
        if getattr(semantic_cfg, "llm_enabled", False):
            deduped, llm_summary = self._deduplicate_report_clusters_with_llm(
                deduped,
                semantic_cfg=semantic_cfg,
            )
            summary.update(llm_summary)
        summary["output_issue_count"] = len(deduped)
        state["semantic_dedup_summary"] = summary
        return deduped

    def _deduplicate_report_clusters_with_llm(
        self,
        issues: List[Dict[str, Any]],
        *,
        semantic_cfg: Any,
    ) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
        max_cluster_size = max(2, int(getattr(semantic_cfg, "max_cluster_size", 8) or 8))
        threshold = float(getattr(semantic_cfg, "llm_confidence_threshold", 0.85) or 0.85)
        clusters: Dict[str, List[Dict[str, Any]]] = {}
        for issue in issues:
            for key in semantic_related_cluster_keys(issue):
                clusters.setdefault(key, []).append(issue)

        candidate_clusters: List[List[Dict[str, Any]]] = []
        seen_cluster_sets: Set[tuple[int, ...]] = set()
        prefilter_skipped = 0
        for group in clusters.values():
            for candidate_group in self._split_semantic_dedup_cluster(group, max_cluster_size):
                if len(candidate_group) < 2:
                    continue
                if not self._semantic_dedup_cluster_needs_llm(candidate_group):
                    prefilter_skipped += 1
                    continue
                cluster_ids = tuple(sorted(id(issue) for issue in candidate_group))
                if cluster_ids in seen_cluster_sets:
                    continue
                seen_cluster_sets.add(cluster_ids)
                candidate_clusters.append(candidate_group)
        summary: Dict[str, Any] = {
            "llm_candidate_cluster_count": len(candidate_clusters),
            "llm_clusters_called": 0,
            "llm_cache_hits": 0,
            "llm_merge_count": 0,
            "llm_rejected_merge_count": 0,
            "llm_failed_cluster_count": 0,
            "llm_prefilter_skipped_count": prefilter_skipped,
        }
        if not candidate_clusters:
            return issues, summary

        recon_agent = self._make_issue_reconciler_agent()
        if recon_agent is None:
            summary["llm_disabled_reason"] = "no_issue_reconciler_llm_client"
            return issues, summary

        by_issue_id: Dict[str, Dict[str, Any]] = {}
        issue_order: List[str] = []
        issue_indices = {id(issue): index for index, issue in enumerate(issues)}
        for index, issue in enumerate(issues):
            issue_id = self._semantic_dedup_issue_id(issue, index)
            by_issue_id[issue_id] = issue
            issue_order.append(issue_id)

        removed: Set[str] = set()
        for cluster in candidate_clusters:
            active_cluster = [
                issue
                for issue in cluster
                if self._semantic_dedup_issue_id(issue, issue_indices.get(id(issue), 0)) not in removed
            ]
            if len(active_cluster) < 2:
                continue
            cluster_payload = self._semantic_dedup_cluster_payload(active_cluster, issue_indices)
            cluster_fingerprint = self._semantic_dedup_cluster_fingerprint(cluster_payload)
            decision = self._semantic_dedup_llm_cache.get(cluster_fingerprint)
            if decision is not None:
                summary["llm_cache_hits"] += 1
            else:
                response = recon_agent.run(cluster_payload)
                summary["llm_clusters_called"] += 1
                if not response.success or not isinstance(response.data, dict):
                    summary["llm_failed_cluster_count"] += 1
                    continue
                decision = response.data
                self._semantic_dedup_llm_cache[cluster_fingerprint] = decision

            applied, rejected = self._apply_llm_dedup_decision(
                decision,
                by_issue_id,
                removed,
                threshold=threshold,
            )
            summary["llm_merge_count"] += applied
            summary["llm_rejected_merge_count"] += rejected

        return [issue for issue_id, issue in zip(issue_order, issues) if issue_id not in removed], summary

    @staticmethod
    def _semantic_dedup_cluster_needs_llm(group: List[Dict[str, Any]]) -> bool:
        for left_index, left in enumerate(group):
            for right in group[left_index + 1 :]:
                if Analyzer._semantic_dedup_pair_needs_llm(left, right):
                    return True
        return False

    @staticmethod
    def _semantic_dedup_pair_needs_llm(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
        left_file, _ = parse_issue_location(str(left.get("location") or left.get("file") or ""))
        right_file, _ = parse_issue_location(str(right.get("location") or right.get("file") or ""))
        same_file = bool(left_file and right_file and normalize_issue_key_part(left_file) == normalize_issue_key_part(right_file))
        left_funcs = {
            normalize_issue_key_part(str(value or ""))
            for value in (left.get("function"), left.get("sink_function"), left.get("entry_function"))
            if value
        }
        right_funcs = {
            normalize_issue_key_part(str(value or ""))
            for value in (right.get("function"), right.get("sink_function"), right.get("entry_function"))
            if value
        }
        same_function = bool(left_funcs & right_funcs)
        same_family = semantic_category_family(
            normalize_issue_category(str(left.get("category") or left.get("defect_class") or left.get("subcategory") or ""))
        ) == semantic_category_family(
            normalize_issue_category(str(right.get("category") or right.get("defect_class") or right.get("subcategory") or ""))
        )
        shared_resource_or_sink = bool(
            issue_resource_signature(left)
            and issue_resource_signature(left) == issue_resource_signature(right)
        ) or bool(issue_sink_signature(left) and issue_sink_signature(left) == issue_sink_signature(right))
        return bool(same_family and ((same_file and same_function) or shared_resource_or_sink))

    @staticmethod
    def _split_semantic_dedup_cluster(
        group: List[Dict[str, Any]],
        max_cluster_size: int,
    ) -> List[List[Dict[str, Any]]]:
        if len(group) <= max_cluster_size:
            return [group]

        buckets: Dict[str, List[Dict[str, Any]]] = {}
        for issue in group:
            bucket_key = (
                issue_resource_signature(issue)
                or issue_sink_signature(issue)
                or semantic_root_cause_key(issue)
                or str(issue.get("function") or issue.get("func_name") or "")
                or "fallback"
            )
            buckets.setdefault(bucket_key, []).append(issue)

        split: List[List[Dict[str, Any]]] = []
        for bucket in buckets.values():
            for start in range(0, len(bucket), max_cluster_size):
                chunk = bucket[start : start + max_cluster_size]
                if len(chunk) > 1:
                    split.append(chunk)
        return split

    def _make_issue_reconciler_agent(self) -> Any:
        recon_agent_cfg = next(
            (a for a in self.config.project.agents if a.name == "issue_reconciler_agent"),
            None,
        )
        recon_llm_ref = recon_agent_cfg.llm_ref if recon_agent_cfg and recon_agent_cfg.llm_ref else "default"
        recon_client = self.llm_clients.get(recon_llm_ref, self.llm_clients.get("default"))
        if recon_client is None:
            logger.warning("Semantic LLM dedup requested but no issue_reconciler_agent LLM client is configured.")
            return None
        from ...agents.issue_reconciler.agent import IssueReconcilerAgent

        return IssueReconcilerAgent(
            recon_client,
            tool_policy=self._tool_policy_for_agent("issue_reconciler_agent"),
        )

    @staticmethod
    def _semantic_dedup_issue_id(issue: Dict[str, Any], index: int) -> str:
        return str(
            issue.get("id")
            or issue.get("candidate_id")
            or issue.get("dedup_key")
            or f"semantic_issue_{index}"
        )

    def _semantic_dedup_cluster_payload(
        self,
        cluster: List[Dict[str, Any]],
        issue_indices: Dict[int, int],
    ) -> Dict[str, Any]:
        compact_issues = []
        files = set()
        functions = set()
        resources = set()
        families = set()
        for issue in cluster:
            issue_id = self._semantic_dedup_issue_id(issue, issue_indices.get(id(issue), 0))
            compact = self._compact_issue_for_semantic_dedup(issue, issue_id)
            compact_issues.append(compact)
            if compact.get("file"):
                files.add(compact["file"])
            if compact.get("function"):
                functions.add(compact["function"])
            if compact.get("resource_signature"):
                resources.add(compact["resource_signature"])
            if compact.get("category_family"):
                families.add(compact["category_family"])
        cluster_id = self._semantic_dedup_cluster_fingerprint(
            {"issues": compact_issues, "mode": "deduplicate_cluster"}
        )
        return {
            "mode": "deduplicate_cluster",
            "cluster_id": cluster_id,
            "issues": compact_issues,
            "deterministic_hints": {
                "category_families": sorted(families),
                "same_file": len(files) <= 1,
                "same_function": len(functions) <= 1,
                "resource_signatures": sorted(resources),
            },
        }

    @staticmethod
    def _compact_issue_for_semantic_dedup(issue: Dict[str, Any], issue_id: str) -> Dict[str, Any]:
        location = str(issue.get("location") or issue.get("file") or "")
        file_path, _line = parse_issue_location(location)
        category = str(issue.get("category") or issue.get("subcategory") or "")
        return {
            "id": issue_id,
            "category": category,
            "category_family": semantic_category_family(category),
            "function": issue.get("function") or issue.get("func_name"),
            "file": file_path,
            "location": location,
            "root_cause": issue.get("root_cause"),
            "description": issue.get("description"),
            "positive_evidence": issue.get("positive_evidence"),
            "candidate_source": issue.get("candidate_source") or issue.get("finding_kind"),
            "resource_signature": issue_resource_signature(issue),
            "root_cause_key": semantic_root_cause_key(issue),
            "source": issue.get("source"),
            "sink": issue.get("sink") or issue.get("sink_function"),
            "call_path": issue.get("call_path"),
            "call_path_signature": issue_call_path_signature(issue),
            "sink_signature": issue_sink_signature(issue),
        }

    @staticmethod
    def _semantic_dedup_cluster_fingerprint(payload: Dict[str, Any]) -> str:
        stable = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
        return hashlib.sha256(stable.encode("utf-8")).hexdigest()[:16]

    @staticmethod
    def _apply_llm_dedup_decision(
        decision: Dict[str, Any],
        by_issue_id: Dict[str, Dict[str, Any]],
        removed: Set[str],
        *,
        threshold: float,
    ) -> tuple[int, int]:
        applied = 0
        rejected = 0
        keep_distinct = {
            str(issue_id)
            for issue_id in decision.get("must_keep_distinct_issue_ids", [])
            if issue_id
        }
        groups = decision.get("duplicate_groups")
        if not isinstance(groups, list):
            return 0, 0
        for group in groups:
            if not isinstance(group, dict):
                continue
            primary_id = str(group.get("primary_issue_id") or "")
            primary = by_issue_id.get(primary_id)
            if primary is None or primary_id in removed:
                rejected += 1
                continue
            try:
                confidence = float(group.get("confidence", 0) or 0)
            except (TypeError, ValueError):
                confidence = 0.0
            for duplicate_id in group.get("duplicate_issue_ids", []) or []:
                duplicate_id = str(duplicate_id or "")
                duplicate = by_issue_id.get(duplicate_id)
                if (
                    not duplicate_id
                    or duplicate is None
                    or duplicate_id == primary_id
                    or duplicate_id in removed
                    or duplicate_id in keep_distinct
                    or primary_id in keep_distinct
                ):
                    rejected += 1
                    continue
                if not issues_may_share_root_cause(
                    primary,
                    duplicate,
                    confidence=confidence,
                    threshold=threshold,
                    allow_cross_function_root=True,
                ):
                    rejected += 1
                    continue
                root_key = str(group.get("root_cause_key") or "") or semantic_root_cause_key(primary)
                merge_duplicate_issue(
                    primary,
                    duplicate,
                    dedup_key=root_key,
                    decision={
                        "method": "issue_reconciler_agent",
                        "root_cause_key": root_key,
                        "confidence": confidence,
                        "reasoning": group.get("reasoning"),
                    },
                )
                removed.add(duplicate_id)
                applied += 1
        return applied, rejected

    def _build_validation_evidence_pack(
        self,
        issue: Dict[str, Any],
        state: Dict[str, Any],
        issue_code: str,
    ) -> Dict[str, Any]:
        return build_validation_evidence_pack(
            issue,
            state,
            issue_code,
            code_index=self.code_index,
            snapshot_store=self.snapshot_store,
            score_components_fn=self._score_components,
            issue_key_fn=self._canonical_issue_key,
        )

    @staticmethod
    def _category_validation_requirements(issue: Dict[str, Any]) -> List[str]:
        return category_validation_requirements(issue)

    @staticmethod
    def _issue_rank(issue: Dict[str, Any]) -> tuple[int, float, int]:
        return issue_rank(issue)

    @classmethod
    def _canonical_issue_key(cls, issue: Dict[str, Any]) -> str:
        return canonical_issue_key(issue)

    @staticmethod
    def _normalize_issue_category(value: str) -> str:
        return normalize_issue_category(value)

    @staticmethod
    def _normalize_issue_key_part(value: Any) -> str:
        return normalize_issue_key_part(value)

    @classmethod
    def _flatten_issue_text(cls, value: Any) -> str:
        return flatten_issue_text(value)

    @staticmethod
    def _parse_issue_location(location: str) -> tuple[str, Optional[int]]:
        return parse_issue_location(location)

    @staticmethod
    def _trim_code(code: str, max_lines: int = 140) -> str:
        return trim_code(code, max_lines=max_lines)

    @staticmethod
    def _compact_snapshot(snapshot: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        return compact_snapshot(snapshot)

    def _build_final_report(self, state: Dict[str, Any]) -> None:
        self.report_assembler.build(state)

    def _build_workflow_metadata(self, state: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "timestamp": datetime.datetime.now().isoformat(),
            "run_id": state.get("run_id", ""),
            "repo": str(self.config.project.project_root),
            "source_root": str(self.config.project.source_root),
            "commit_sha": self._git_commit_sha(self.config.project.project_root),
            "version": __version__,
            "knowledge_db_version": self._knowledge_db_version(),
            "snapshot_schema_version": "semantic_snapshot_v1",
            "context_tokens": state.get("total_context_tokens", 0),
            "cumulative_prompt_tokens": state.get("total_cumulative_prompt_tokens", 0),
            "cumulative_completion_tokens": state.get("total_cumulative_completion_tokens", 0),
            "cumulative_total_tokens": state.get("total_cumulative_total_tokens", 0)
            or state.get("total_context_tokens", 0),
            "workflow": self.workflow_spec.name if self.workflow_spec else self.config.analysis.workflow_name,
            "workflow_mode": self.workflow_spec.mode if self.workflow_spec else self.config.analysis.workflow_name,
            "workflow_progress": list(self.workflow_progress),
            "current_workflow_step": self.workflow_executor.current_step,
            "subagent_candidate_count": len(state.get("subagent_candidates", [])),
            "subagent_ticket_count": len(state.get("subagent_ticket_plan", [])),
            "subagent_unassigned_count": len(state.get("subagent_unassigned_candidates", [])),
            "subagent_reports_count": len(state.get("subagent_reports", [])),
            "subagent_report_summary": dict(state.get("subagent_report_summary", {})),
            "subagent_ticket_plan": self._compact_subagent_items(state.get("subagent_ticket_plan", [])),
            "subagent_unassigned_candidates": self._compact_subagent_items(
                state.get("subagent_unassigned_candidates", [])
            ),
            "subagent_reports": self._compact_subagent_reports(state.get("subagent_reports", [])),
            "candidate_ledger_summary": dict(state.get("candidate_ledger_summary", {})),
            "candidate_signal_summary": dict(state.get("candidate_signal_summary", {})),
            "va_candidate_coverage_summary": dict(state.get("va_candidate_coverage_summary", {})),
            "validation_performance": {
                "iterations": int(state.get("validation_iterations", 0) or 0),
                "tool_call_count": int(state.get("validation_tool_call_count", 0) or 0),
                "validator_fast_path_attempted": int(state.get("validator_fast_path_attempted", 0) or 0),
                "validator_fast_path_accepted": int(state.get("validator_fast_path_accepted", 0) or 0),
                "prevalidation_decision_count": int(state.get("prevalidation_decision_count", 0) or 0),
                "clang_prevalidation_decision_count": int(state.get("clang_prevalidation_decision_count", 0) or 0),
                "static_audit_observation_count": int(state.get("static_audit_observation_count", 0) or 0),
                "static_suppressed_count": int(state.get("static_suppressed_count", 0) or 0),
            },
            "semantic_dedup_summary": dict(state.get("semantic_dedup_summary", {})),
            "budget_stage": state.get("budget_stage", ""),
            "budget_hard_caps": dict(state.get("budget_hard_caps", {})),
            "effective_budget": dict(state.get("effective_budget", {})),
            "budget_scores": dict(state.get("budget_scores", {})),
            "budget_reasons": dict(state.get("budget_reasons", {})),
            "diff_focus": dict(state.get("diff_focus", {})),
            "audit_observation_count": len(state.get("observations", [])),
            "audit_observations": list(state.get("observations", [])),
        }

    @staticmethod
    def _accumulate_cumulative_token_metadata(
        state: Dict[str, Any],
        metadata: Dict[str, Any],
    ) -> None:
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

        state["total_cumulative_prompt_tokens"] = int(
            state.get("total_cumulative_prompt_tokens", 0) or 0
        ) + token_value("cumulative_prompt_tokens")
        state["total_cumulative_completion_tokens"] = int(
            state.get("total_cumulative_completion_tokens", 0) or 0
        ) + token_value("cumulative_completion_tokens")
        state["total_cumulative_total_tokens"] = int(
            state.get("total_cumulative_total_tokens", 0) or 0
        ) + token_value("cumulative_total_tokens", "context_tokens")

    @staticmethod
    def _git_commit_sha(project_root: Path) -> str:
        git_dir = project_root / ".git"
        head_path = git_dir / "HEAD"
        try:
            head = head_path.read_text(encoding="utf-8").strip()
            if head.startswith("ref:"):
                ref_path = git_dir / head.split(":", 1)[1].strip()
                if ref_path.exists():
                    return ref_path.read_text(encoding="utf-8").strip()
            return head
        except OSError:
            return ""

    def _knowledge_db_version(self) -> str:
        db = self._get_knowledge_db()
        version = getattr(db, "SCHEMA_VERSION", "") if db is not None else ""
        return str(version or "")

    def _persist_final_report(self, state: Dict[str, Any]) -> Dict[str, Any]:
        return self.report_assembler.persist(
            state,
            write_root_reports=self.write_root_reports,
        )

    def _finalize_returned_report(self, state: Dict[str, Any]) -> Dict[str, Any]:
        return self.report_assembler.finalize_returned_report(state)

    def _attach_agent_contract(
        self,
        context: Dict[str, Any],
        agent_name: str,
        extra_skills: Optional[List[str]] = None,
        active_skill_names: Optional[List[str]] = None,
        visible_tool_names: Optional[Sequence[str]] = None,
    ) -> None:
        if visible_tool_names is None:
            visible_tool_names = self._visible_prompt_tool_names(
                agent_name,
                active_skill_names=active_skill_names,
            )
        attach_agent_contract(
            context,
            agent_name,
            self.spec_registry,
            extra_skills=extra_skills,
            active_skill_names=active_skill_names,
            visible_tool_names=visible_tool_names,
        )

    def _visible_prompt_tool_names(
        self,
        agent_name: str,
        *,
        active_skill_names: Optional[List[str]] = None,
    ) -> Optional[List[str]]:
        try:
            return [
                str(tool.name)
                for tool in self._get_tools(
                    agent_name,
                    active_skill_names=active_skill_names,
                )
            ]
        except Exception:
            return None

    def _agent_system_prompt(
        self,
        agent_name: str,
        *,
        active_skill_names: Optional[List[str]] = None,
        substitutions: Optional[Dict[str, Any]] = None,
        visible_tool_names: Optional[Sequence[str]] = None,
    ) -> str:
        return agent_system_prompt(
            agent_name,
            self.spec_registry,
            active_skill_names=active_skill_names,
            substitutions=substitutions,
            visible_tool_names=visible_tool_names,
        )

    def _select_vulnerability_skills_for_config(
        self,
        agent_cfg: Any,
        llm_client: Optional[LLMClient] = None,
    ) -> SkillSelection:
        """Select active vulnerability skills from the configured analyzer task."""
        available = [
            skill.name
            for skill in self.spec_registry.skills_for_agent(
                "vulnerability_analyzer",
                extra=getattr(agent_cfg, "skills", None),
            )
        ]
        task = getattr(agent_cfg, "task", None)
        semantic_router = None
        if llm_client is not None:
            semantic_router = lambda task_text, skill_names: self._route_vulnerability_skills_with_llm(
                task_text,
                skill_names,
                llm_client,
            )
        selection = select_vulnerability_skills(task, available, semantic_router=semantic_router)
        if selection.restricted:
            logger.info(
                "Task-selected vulnerability skills for '%s': %s (source=%s, confidence=%.2f)",
                task or "",
                ", ".join(selection.skills) or "none",
                selection.source,
                selection.confidence,
            )
        return selection

    def _route_vulnerability_skills_with_llm(
        self,
        task: str,
        available_skill_names: Sequence[str],
        llm_client: LLMClient,
    ) -> Dict[str, Any]:
        return route_vulnerability_skills_with_llm(
            task,
            available_skill_names,
            llm_client,
            self._skill_selection_cache,
        )

    def _should_spawn_subagents(self, agent_cfg: Any) -> bool:
        """Decide whether focused deep-worker LLM calls are enabled for this run."""
        if not self.config.analysis.enable_subagent_workers:
            return False
        explicit = getattr(agent_cfg, "can_spawn_subagents", None)
        if explicit is not None:
            return bool(explicit)
        agent_spec = self.spec_registry.get_agent("vulnerability_analyzer")
        return bool(agent_spec and agent_spec.can_spawn_subagents)

    @staticmethod
    def _subagent_llm_ref_for_ticket(
        ticket: Any,
        skill_llm_refs: Dict[str, str],
        fallback_ref: str,
    ) -> str:
        return subagent_llm_ref_for_ticket(ticket, skill_llm_refs, fallback_ref)

    @classmethod
    def _compact_subagent_items(cls, items: Any, *, limit: int = 50) -> List[Dict[str, Any]]:
        return compact_subagent_items(items, limit=limit)

    @staticmethod
    def _compact_candidate_signal_items(items: Any, *, limit: int = 80) -> List[Dict[str, Any]]:
        compact: List[Dict[str, Any]] = []
        if not isinstance(items, list):
            return compact
        for item in items[:limit]:
            if not isinstance(item, dict):
                continue
            evidence_pack = item.get("evidence_pack") if isinstance(item.get("evidence_pack"), dict) else {}
            compact.append(
                {
                    "candidate_id": item.get("candidate_id") or item.get("id") or evidence_pack.get("candidate_id"),
                    "function": item.get("function"),
                    "location": item.get("location"),
                    "defect_class": item.get("defect_class") or item.get("subcategory") or item.get("category"),
                    "rule": item.get("rule") or evidence_pack.get("rule"),
                    "candidate_source": item.get("candidate_source") or evidence_pack.get("candidate_source"),
                    "confidence": item.get("confidence") or item.get("rule_confidence"),
                    "source": item.get("source") or evidence_pack.get("source"),
                    "sink": item.get("sink") or evidence_pack.get("sink"),
                    "validation_required": item.get("validation_required", evidence_pack.get("validation_required", True)),
                    "positive_evidence": (item.get("positive_evidence") or evidence_pack.get("positive_evidence") or [])[:4],
                    "negative_evidence": (item.get("negative_evidence") or evidence_pack.get("negative_evidence") or [])[:4],
                }
            )
        if len(items) > limit:
            compact.append({"truncated": True, "omitted_count": len(items) - limit})
        return compact

    @staticmethod
    def _normalize_candidate_coverage(raw: Any) -> Dict[str, Dict[str, Any]]:
        if not isinstance(raw, list):
            return {}
        coverage: Dict[str, Dict[str, Any]] = {}
        for item in raw:
            if not isinstance(item, dict):
                continue
            candidate_id = str(item.get("candidate_id") or item.get("id") or "").strip()
            if not candidate_id:
                continue
            coverage[candidate_id] = {
                "status": str(item.get("status") or "").strip(),
                "reason": item.get("reason"),
                "issue_id": item.get("issue_id"),
            }
        return coverage

    @staticmethod
    def _candidate_coverage_summary(coverage: Dict[str, Dict[str, Any]]) -> Dict[str, int]:
        summary: Dict[str, int] = {"total": len(coverage)}
        for item in coverage.values():
            status = str(item.get("status") or "unknown")
            summary[status] = summary.get(status, 0) + 1
        return summary

    @staticmethod
    def _mark_va_unreviewed_candidates(
        candidates: List[Dict[str, Any]],
        coverage: Dict[str, Dict[str, Any]],
    ) -> None:
        covered_ok = {"reported", "rejected_by_evidence"}
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            evidence_pack = candidate.get("evidence_pack") if isinstance(candidate.get("evidence_pack"), dict) else {}
            candidate_id = str(candidate.get("candidate_id") or candidate.get("id") or evidence_pack.get("candidate_id") or "")
            status = str((coverage.get(candidate_id) or {}).get("status") or "")
            if status not in covered_ok:
                candidate["va_unreviewed"] = True
                evidence_pack["va_unreviewed"] = True
                if evidence_pack:
                    candidate["evidence_pack"] = evidence_pack

    @staticmethod
    def _compact_subagent_item(item: Any) -> Dict[str, Any]:
        return compact_subagent_item(item)

    @classmethod
    def _compact_subagent_reports(cls, reports: Any, *, limit: int = 50) -> List[Dict[str, Any]]:
        return compact_subagent_reports(reports, limit=limit)

    def _get_tools(
        self,
        agent_name: Optional[str] = None,
        *,
        enable_on_demand_snapshots: bool = True,
        active_skill_names: Optional[List[str]] = None,
    ) -> List[Any]:
        """Initialize and return the set of tools."""
        from ...tools.code_retrieval import GetFunctionImplTool
        from ...tools.snapshot_tool import GetFunctionSnapshotTool
        from ...tools.utils import (
            ListFunctionsTool,
            GetFileSnippetTool,
            GetCallersTool,
            GetTypeInfoTool,
            GetCallGraphTool,
            GetDataFlowTool,
            FindFunctionPointersTool,
            QueryPointerAliasTool,
            VerifyTaintReachabilityTool,
            GetDeepCallContextTool,
        )

        # Base tools universally supported by all backends (including regex/clangd)
        snapshot_resolver = (
            self._get_or_build_snapshot if enable_on_demand_snapshots else None
        )
        tools = [
            GetFunctionImplTool(self.code_index, self.user_config),
            GetFunctionSnapshotTool(self.snapshot_store, resolver=snapshot_resolver),
            ListFunctionsTool(self.code_index),
            GetFileSnippetTool(self.code_index),
            GetCallersTool(self.code_index),
            GetTypeInfoTool(self.code_index),
        ]
        
        # Heavy CPG tools only supported by advanced graph backends
        advanced_backends = ["joern", "svf", "unified"]
        if hasattr(self.code_index, "backend_name") and self.code_index.backend_name in advanced_backends:
            tools.extend([
                GetCallGraphTool(self.code_index),
                GetDataFlowTool(self.code_index),
                FindFunctionPointersTool(self.code_index),
                QueryPointerAliasTool(self.code_index),
                VerifyTaintReachabilityTool(self.code_index),
                GetDeepCallContextTool(self.code_index),
            ])
        if agent_name:
            agent_spec = self.spec_registry.get_agent(agent_name)
            allowed = set(agent_spec.tools) if agent_spec else set()
            if allowed:
                tools = [tool for tool in tools if tool.name in allowed]
            tool_policy = self._tool_policy_for_agent(
                agent_name,
                active_skill_names=active_skill_names,
            )
            tools = [tool for tool in tools if tool_policy.is_tool_visible(tool.name)]

        return tools

    def _tool_policy_for_agent(
        self,
        agent_name: Optional[str],
        *,
        active_skill_names: Optional[List[str]] = None,
    ) -> ToolPolicy:
        return tool_policy_for_agent(
            self.spec_registry,
            getattr(self, "config", None),
            agent_name,
            active_skill_names=active_skill_names,
        )

    def _tool_audit_log_path(self) -> Optional[Path]:
        return tool_audit_log_path(getattr(self, "config", None))

    def _get_or_build_snapshot(
        self, func_name: str, file_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """Load a snapshot, or build and persist one under the snapshot lock."""
        existing = self.snapshot_store.load_snapshot(func_name, file_path=file_path)
        if existing is not None:
            impl_for_refresh = self.code_index.get_function_impl(func_name, warn_missing=False)
            if not impl_for_refresh:
                return {"success": True, "data": existing}
            impl_file_for_refresh = str(impl_for_refresh.get("file") or "unknown")
            if file_path and impl_file_for_refresh != file_path:
                return {"success": True, "data": existing}
            refresh_file = file_path or impl_file_for_refresh
            needs_refresh, reason = self.snapshot_store.needs_refresh(
                func_name,
                str(impl_for_refresh.get("code") or ""),
                refresh_file,
            )
            if not needs_refresh:
                return {
                    "success": True,
                    "data": existing,
                    "message": (
                        f"Snapshot is current ({reason})."
                        if reason
                        else "Snapshot is current."
                    ),
                }
            self.snapshot_store.lock_manager.invalidate(func_name)

        lock_started = time.monotonic()
        logger.info(
            "[snapshot-lock] waiting context=on_demand func=%s file=%s",
            func_name,
            file_path or "",
        )
        status = self.snapshot_store.lock_manager.acquire(func_name, timeout=120.0)
        lock_wait = time.monotonic() - lock_started
        logger.info(
            "[snapshot-lock] outcome context=on_demand func=%s file=%s status=%s waited=%.2fs",
            func_name,
            file_path or "",
            status,
            lock_wait,
        )
        if status == "done":
            snapshot = self.snapshot_store.load_snapshot(func_name, file_path=file_path)
            return {
                "success": True,
                "data": snapshot,
                "message": (
                    "Snapshot was built concurrently by another worker."
                    if snapshot is not None
                    else f"No snapshot exists for '{func_name}'"
                ),
            }
        if status == "timeout":
            return {
                "success": False,
                "error": f"Timed out waiting for snapshot build of '{func_name}'",
            }

        try:
            snapshot = self.snapshot_store.load_snapshot(func_name, file_path=file_path)
            impl = self.code_index.get_function_impl(func_name, warn_missing=False)
            if not impl:
                self.snapshot_store.lock_manager.release(
                    func_name, success=snapshot is not None
                )
                if snapshot is not None:
                    return {"success": True, "data": snapshot}
                return {
                    "success": True,
                    "data": None,
                    "message": (
                        f"No snapshot exists for '{func_name}' and implementation was not found"
                    ),
                }

            impl_file = str(impl.get("file") or "unknown")
            if file_path and impl_file != file_path:
                self.snapshot_store.lock_manager.release(
                    func_name, success=snapshot is not None
                )
                if snapshot is not None:
                    return {"success": True, "data": snapshot}
                return {
                    "success": True,
                    "data": None,
                    "message": (
                        f"No snapshot exists for '{func_name}' at '{file_path}'. "
                        f"Indexed implementation is at '{impl_file}'."
                    ),
                }

            if snapshot is not None:
                needs_refresh, reason = self.snapshot_store.needs_refresh(
                    func_name,
                    str(impl.get("code") or ""),
                    file_path or impl_file,
                )
                if not needs_refresh:
                    self.snapshot_store.lock_manager.release(func_name, success=True)
                    return {
                        "success": True,
                        "data": snapshot,
                        "message": (
                            f"Snapshot is current ({reason})."
                            if reason
                            else "Snapshot is current."
                        ),
                    }

            location = f"{impl_file}:{impl.get('start_line', 0)}"
            if self._is_lightweight_snapshot_candidate(func_name, impl):
                snapshot = self._build_lightweight_snapshot(func_name, impl, location)
                self.snapshot_store.save_snapshot(
                    func_name,
                    snapshot,
                    str(impl.get("code") or ""),
                    location,
                )
                self.snapshot_store.lock_manager.release(func_name, success=True)
                return {
                    "success": True,
                    "data": snapshot,
                    "message": "Generated and saved lightweight static snapshot.",
                }

            if self._is_trivial_function(
                str(impl.get("code") or ""),
                self.config.analysis.trivial_function_max_lines,
            ):
                snapshot = self._build_trivial_snapshot(func_name, impl, location)
                self.snapshot_store.save_snapshot(
                    func_name,
                    snapshot,
                    str(impl.get("code") or ""),
                    location,
                )
                self.snapshot_store.lock_manager.release(func_name, success=True)
                return {
                    "success": True,
                    "data": snapshot,
                    "message": "Generated and saved syntactic snapshot for trivial function.",
                }

            sm_agent_cfg = next(
                (a for a in self.config.project.agents if a.name == "semantic_modeler"),
                None,
            )
            sm_llm_ref = sm_agent_cfg.llm_ref if sm_agent_cfg and sm_agent_cfg.llm_ref else "default"
            sm_client = self.llm_clients.get(sm_llm_ref, self.llm_clients.get("default"))
            if sm_client is None:
                self.snapshot_store.lock_manager.release(func_name, success=False)
                return {"success": False, "error": "No LLM client configured for snapshot build"}

            semantic_agent = SemanticModeler(
                sm_client,
                self._get_tools("semantic_modeler", enable_on_demand_snapshots=False),
                tool_policy=self._tool_policy_for_agent("semantic_modeler"),
            )
            context = {
                "func_name": func_name,
                "code": impl["code"],
                "location": location,
            }
            self._attach_agent_contract(context, "semantic_modeler")
            logger.info("[snapshot] On-demand modeling function '%s' ...", func_name)
            response = semantic_agent.run(context)
            if response.success:
                self.snapshot_store.save_snapshot(
                    func_name,
                    response.data,
                    impl["code"],
                    location,
                )
                self.snapshot_store.lock_manager.release(func_name, success=True)
                return {
                    "success": True,
                    "data": response.data,
                    "metadata": response.metadata,
                    "message": "Generated and saved semantic snapshot on demand.",
                }

            self.snapshot_store.lock_manager.release(func_name, success=False)
            return {
                "success": False,
                "error": f"On-demand snapshot build failed for '{func_name}': {response.error}",
                "metadata": response.metadata,
            }
        except Exception as exc:
            self.snapshot_store.lock_manager.release(func_name, success=False)
            logger.exception("On-demand snapshot build failed for '%s'", func_name)
            return {"success": False, "error": str(exc)}

    @staticmethod
    def _build_trivial_snapshot(
        func_name: str, impl: Dict[str, Any], location: str
    ) -> Dict[str, Any]:
        return build_trivial_snapshot(func_name, impl, location)

    @staticmethod
    def _trivial_suspicious_points(
        func_name: str,
        impl: Dict[str, Any],
        location: str,
    ) -> List[Dict[str, Any]]:
        return trivial_suspicious_points(func_name, impl, location)

    @staticmethod
    def _is_lightweight_snapshot_candidate(func_name: str, impl: Dict[str, Any]) -> bool:
        return is_lightweight_snapshot_candidate(func_name, impl)

    @staticmethod
    def _build_lightweight_snapshot(
        func_name: str, impl: Dict[str, Any], location: str
    ) -> Dict[str, Any]:
        return build_lightweight_snapshot(func_name, impl, location)

    def _premodel_callees(self, entry_func: str, sm_client: 'LLMClient',
                          max_depth: int = 3, max_callees: int = 20) -> tuple[int, int, int]:
        """
        Recursively pre-model reachable callees for an entry function.
        Returns:
            (modeled_count, skipped_count, total_context_tokens)
        """
        # 1. BFS 閺€鍫曟肠閸欘垵鎻?callee 閸?
        callee_graph: Dict[str, List[str]] = {}
        visited: Set[str] = set()
        scheduled: Set[str] = {entry_func}
        queue = deque([(entry_func, 0)])
        expanded_by_depth: Dict[int, int] = {}
        capped_depths: Set[int] = set()
        impl_cache: Dict[str, Any] = {}
        last_progress_log = time.monotonic()

        logger.info(
            "[premodel] Collecting reachable callees for '%s' (depth<=%s, per-level<=%s)",
            entry_func,
            max_depth,
            max_callees,
        )

        while queue:
            func, depth = queue.popleft()
            if func in visited or depth > max_depth:
                continue
            visited.add(func)
            if depth >= max_depth:
                callee_graph.setdefault(func, [])
                continue

            try:
                callees_raw = self.code_index.get_callees(func, limit=max_callees)
            except Exception as exc:
                logger.warning(
                    "[premodel] Failed to retrieve callees for '%s'; "
                    "continuing without this branch: %s",
                    func,
                    exc,
                    exc_info=True,
                )
                callee_graph[func] = []
                continue
            callee_names = [c["name"] for c in callees_raw if c.get("name")]

            # Only premodel callees with source implementations.
            resolvable = []
            next_depth = depth + 1
            for c in callee_names:
                if c in visited or c in scheduled:
                    continue
                if expanded_by_depth.get(next_depth, 0) >= max_callees:
                    capped_depths.add(next_depth)
                    continue
                try:
                    impl = self.code_index.get_function_impl(
                        c,
                        warn_missing=False,
                        include_context=False,
                    )
                except Exception as exc:
                    logger.warning(
                        "[premodel] Failed to resolve callee '%s'; skipping: %s",
                        c,
                        exc,
                        exc_info=True,
                    )
                    continue
                if impl is not None:
                    impl_cache[c] = impl
                    resolvable.append(c)
                    scheduled.add(c)
                    expanded_by_depth[next_depth] = expanded_by_depth.get(next_depth, 0) + 1
                    if not self._is_lightweight_snapshot_candidate(c, impl):
                        queue.append((c, next_depth))
                else:
                    logger.debug("[premodel] Skipping unresolved callee '%s'", c)

            callee_graph[func] = resolvable
            now = time.monotonic()
            if now - last_progress_log >= 30.0:
                logger.info(
                    "[premodel] Still collecting callees for '%s': visited=%s queued=%s",
                    entry_func,
                    len(visited),
                    len(queue),
                )
                last_progress_log = now

        # 2. 逆拓扑排序：叶子函数优先
        if capped_depths:
            logger.info(
                "[premodel] Breadth cap reached for '%s' at depth(s): %s",
                entry_func,
                ", ".join(str(d) for d in sorted(capped_depths)),
            )

        order = self._topo_sort(callee_graph, entry_func)
        # 过滤掉入口函数本身（由主流程建模）
        order = [f for f in order if f != entry_func]

        if not order:
            return 0, 0, 0

        logger.info(f"[premodel] {len(order)} reachable callees to pre-model for '{entry_func}'")

        # 3. 逐个建模
        semantic_agent = SemanticModeler(
            sm_client,
            self._get_tools("semantic_modeler", enable_on_demand_snapshots=False),
            tool_policy=self._tool_policy_for_agent("semantic_modeler"),
        )
        modeled = 0
        skipped = 0
        total_tokens = 0

        for func in order:
            # 快速检查：已有快照则跳过
            existing = self.snapshot_store.load_snapshot(func)
            if existing is not None:
                skipped += 1
                continue

            # 跨线程锁保护
            lock_started = time.monotonic()
            logger.info(
                "[snapshot-lock] waiting context=premodel entry=%s func=%s",
                entry_func,
                func,
            )
            status = self.snapshot_store.lock_manager.acquire(func, timeout=120.0)
            lock_wait = time.monotonic() - lock_started
            logger.info(
                "[snapshot-lock] outcome context=premodel entry=%s func=%s status=%s waited=%.2fs",
                entry_func,
                func,
                status,
                lock_wait,
            )
            if status == "done":
                skipped += 1
                continue
            if status == "timeout":
                logger.warning(f"[premodel] Timeout waiting for '{func}', skipping.")
                continue

            # status == "acquired"：由当前 Worker 建模
            try:
                impl = impl_cache.get(func) or self.code_index.get_function_impl(
                    func,
                    warn_missing=False,
                    include_context=False,
                )
                if not impl:
                    self.snapshot_store.lock_manager.release(func, success=False)
                    continue

                location = f"{impl['file']}:{impl['start_line']}"

                if self._is_lightweight_snapshot_candidate(func, impl):
                    logger.info(f"[premodel] Auto-summarizing lightweight helper '{func}'")
                    snapshot = self._build_lightweight_snapshot(func, impl, location)
                    self.snapshot_store.save_snapshot(func, snapshot, impl["code"], location)
                    self.snapshot_store.lock_manager.release(func, success=True)
                    modeled += 1
                    continue

                # 高效拦截：平凡函数不需要让大模型看
                if self._is_trivial_function(impl["code"], self.config.analysis.trivial_function_max_lines):
                    logger.info(f"[premodel] Auto-summarizing trivial function '{func}'")
                    snapshot = self._build_trivial_snapshot(func, impl, location)
                    self.snapshot_store.save_snapshot(func, snapshot, impl["code"], location)
                    self.snapshot_store.lock_manager.release(func, success=True)
                    modeled += 1
                    continue

                impl = self.code_index.get_function_impl(
                    func,
                    warn_missing=False,
                    include_context=True,
                ) or impl
                location = f"{impl['file']}:{impl['start_line']}"

                context = {
                    "func_name": func,
                    "code": impl["code"],
                    "location": location,
                }
                self._attach_agent_contract(context, "semantic_modeler")

                logger.info(f"[premodel] Modeling callee '{func}' ...")
                resp = semantic_agent.run(context)
                call_tokens = resp.metadata.get("context_tokens", 0) if resp.metadata else 0
                total_tokens += call_tokens

                if resp.success:
                    self.snapshot_store.save_snapshot(
                        func, resp.data, impl["code"], location
                    )
                    self.snapshot_store.lock_manager.release(func, success=True)
                    modeled += 1
                else:
                    self.snapshot_store.lock_manager.release(func, success=False)
                    logger.warning(f"[premodel] Failed to model '{func}': {resp.error}")
            except Exception as e:
                self.snapshot_store.lock_manager.release(func, success=False)
                logger.error(f"[premodel] Error modeling '{func}': {e}")

        logger.info(f"[premodel] Done: {modeled} modeled, {skipped} reused from cache (ctx ≈{total_tokens:,} tokens)")
        return modeled, skipped, total_tokens

    @staticmethod
    def _is_trivial_function(code: str, max_lines_threshold: int) -> bool:
        return is_trivial_function(code, max_lines_threshold)

    @staticmethod
    def _topo_sort(graph: Dict[str, List[str]], root: str) -> list:
        """Return a leaf-first DFS order for pre-modeling."""
        visited: Set[str] = set()
        order: list = []

        def dfs(node: str):
            if node in visited:
                return
            visited.add(node)
            for child in graph.get(node, []):
                dfs(child)
            order.append(node)

        dfs(root)
        return order

    def _tool_executor_wrapper(self, tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Wrapper to intercept tool execution for snapshot logic."""
        
        # Intercept get_function_impl to check for snapshot refresh
        if tool_name == "get_function_impl" and self.config.analysis.enable_snapshot_cache:
            func_name = str(args.get("func_name") or "")
            return self._smart_get_implementation(func_name, args)

        return self.tools_runtime.execute_tool(tool_name, args)

    def _smart_get_implementation(self, func_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """
        Smart implementation retrieval:
        1. Get current code.
        2. Check if snapshot exists.
        3. If snapshot exists, check if code changed (hash check).
        4. If code changed, ask LLM if refresh is needed.
        """
        # 1. Get real implementation
        impl_result = self.tools_runtime.execute_tool("get_function_impl", args)
        if not impl_result.get("success"):
            return impl_result
        
        current_code = impl_result["data"]["code"]
        file_path = impl_result["data"]["file"]  # Extract file path
        
        # 2. Check snapshot status with file_path
        needs_refresh, reason = self.snapshot_store.needs_refresh(func_name, current_code, file_path)
        
        if not needs_refresh and reason != "no_snapshot":
            # Snapshot is valid and up to date (or only cosmetic changes)
            logger.info(f"Using cached snapshot for '{func_name}' in '{file_path}' (reason: {reason})")
            snapshot = self.snapshot_store.load_snapshot(func_name, file_path)
            return {
                "success": True, 
                "data": impl_result["data"], 
                "snapshot": snapshot, 
                "note": "Snapshot allows skipping deep analysis if irrelevant."
            }

        if reason == "code_changed":
            # 3. Ask LLM if we really need to refresh (semantic check)
            # This requires a mini-LLM call.
            logger.info(f"Code changed for '{func_name}' in '{file_path}', checking with LLM if refresh needed...")
            snapshot = self.snapshot_store.load_snapshot(func_name, file_path)
            decision = self._ask_refresh_decision(func_name, snapshot or {}, current_code)
            
            if not decision.get("refresh_needed"):
                logger.info(f"LLM decided refresh NOT needed for '{func_name}'")
                return {
                    "success": True,
                    "data": impl_result["data"],
                    "snapshot": snapshot,
                    "note": "Code changed but LLM deemed snapshot still valid."
                }
            
            logger.info(f"Refresh needed for '{func_name}': {decision.get('reason')}")

        # If we are here, we return the code and expect the LLM to analyze it and produce a new snapshot
        return impl_result

    def _default_llm_client(self) -> LLMClient:
        client = self.llm_clients.get("default")
        if client is None:
            try:
                client = next(iter(self.llm_clients.values()))
            except StopIteration as exc:
                raise RuntimeError("No LLM clients configured") from exc
        return client

    def _ask_refresh_decision(self, func_name: str, old_snapshot: Dict[str, Any], new_code: str) -> Dict[str, Any]:
        """Ask LLM if snapshot needs refresh."""
        prompt = (
            f"Function '{func_name}' has changed.\n"
            f"Old Snapshot Summary: {old_snapshot.get('summary')}\n"
            f"Old Fingerprint: {old_snapshot.get('semantic_fingerprint')}\n\n"
            "New Code:\n"
            "```c\n"
            f"{new_code}\n"
            "```\n\n"
            "Determine if the semantic contract/behavior relevant to defect attributes "
            "(resources, errors, concurrency) has changed. Output only JSON of type "
            "'snapshot_refresh_decision'."
        )
        messages = [
            {
                "role": "system",
                "content": self._snapshot_refresh_decision_system_prompt(),
            },
            {"role": "user", "content": prompt}
        ]
        
        # Use a separate simpler call (no tools)
        try:
            response = self._default_llm_client().chat_completion(
                messages,
                max_tokens=500,
                trace_agent="snapshot_refresh_decision",
                trace_label=f"function={func_name}",
                trace_iteration=1,
            )
            content = response["choices"][0]["message"]["content"]
            decision = self._extract_json_block(content, "snapshot_refresh_decision")
            return decision or {"refresh_needed": True, "reason": "Failed to parse decision"}
        except Exception as e:
            logger.error(f"Failed to get refresh decision: {e}")
            return {"refresh_needed": True, "reason": "Error calling LLM"}

    def _snapshot_refresh_decision_system_prompt(self) -> str:
        skill = self.spec_registry.get_skill("snapshot_refresh_decision")
        skill_contract = (
            skill.to_prompt_block(
                allowed_tools=[],
                allowed_mcp_tools=[],
                allowed_mcp_resources=[],
            )
            if skill
            else (
                "## Skill: snapshot_refresh_decision\n"
                "Determine whether an existing function snapshot must be refreshed after code changes.\n"
                "Return exactly one JSON object with type=snapshot_refresh_decision."
            )
        )
        return (
            "You are the Z-SCOPE snapshot refresh decision reviewer. Decide whether "
            "the old semantic snapshot still captures defect-relevant behavior in the "
            "new implementation. No tools or MCP resources are available in this call.\n\n"
            "[Loaded Skill Contract]\n"
            f"{skill_contract}"
        )

    def _extract_final_report(self, text: str) -> Optional[FinalReport]:
        """Parse final report from text."""
        data = self._extract_json_block(text, "final_report")
        if not data:
            return None
            
        try:
            issues = [Issue.from_dict(i, context_function=data.get("entry_function", "unknown"), issue_index=idx+1) for idx, i in enumerate(data.get("issues", []))]
            return FinalReport(
                entry_function=data.get("entry_function", ""),
                overall_verdict=data.get("overall_verdict", "insufficient_info"),
                issues=issues,
                notes=data.get("notes", [])
            )
        except Exception as e:
            logger.error(f"Failed to parse FinalReport object: {e}")
            return None

    def _extract_json_block(self, text: str, type_hint: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Extract JSON block from text using robust utility.
        """
        from ...common.utils import extract_json_blocks
        
        candidates = extract_json_blocks(text)
        
        for data in candidates:
            if type_hint:
                if data.get("type") == type_hint:
                    return data
                # Handle nested wrap
                if type_hint in data and isinstance(data[type_hint], dict) and data[type_hint].get("type") == type_hint:
                    return cast(Dict[str, Any], data[type_hint])
            else:
                # If no hint, return the first dictionary found
                return data
                
        return None
            
        return None

    def _save_snapshot_from_llm(self, snapshot_data: Dict[str, Any]) -> None:
        """Save a snapshot emitted by LLM."""
        func_name = snapshot_data.get("func_name")
        if not func_name:
            return
            
        # We need the code implementation to calculate hash for the snapshot
        # Since we might be inside the analysis loop, we can fetch it again from index
        impl = self.code_index.get_function_impl(func_name)
        if impl:
            self.snapshot_store.save_snapshot(
                func_name=func_name,
                snapshot=snapshot_data,
                code=impl["code"],
                location=f"{impl['file']}:{impl['start_line']}"
            )

    def _resolve_issue_locations(self, issues: List[Dict[str, Any]]) -> None:
        """Format absolute line numbers outputted by LLM into standard file:line format."""
        for issue in issues:
            if not isinstance(issue, dict):
                continue

            preserve_issue_location(issue)
            raw_location = str(issue.get("location", ""))
            file_path, parsed_line = parse_issue_location(raw_location)
            if file_path and parsed_line:
                if not issue.get("file"):
                    issue["file"] = file_path
                if not issue.get("line"):
                    issue["line"] = parsed_line
                if not issue.get("start_line"):
                    issue["start_line"] = parsed_line
                end_line = issue.get("end_line")
                if isinstance(end_line, int) and end_line != parsed_line:
                    issue["location"] = f"{file_path}:{parsed_line}-{end_line}"
                else:
                    issue["location"] = f"{file_path}:{parsed_line}"
                continue

            func_name = issue.get("function")
            if not func_name:
                continue

            # Try to find the file from the function name.
            try:
                func_info = self.code_index.get_function_impl(str(func_name), warn_missing=False)
            except TypeError:
                func_info = self.code_index.get_function_impl(str(func_name))
            except Exception as exc:
                logger.debug("Failed to resolve issue location for %s: %s", func_name, exc)
                func_info = None
            
            # Extract line number/range from LLM output (e.g., "142" or "142-145" or "cache_get:142")
            nums = re.findall(r"\d+", raw_location)
            line_suffix = "unknown"
            start_line: Optional[int] = None
            end_line: Optional[int] = None
            if len(nums) >= 2:
                line_suffix = f"{nums[0]}-{nums[1]}"
                start_line = int(nums[0])
                end_line = int(nums[1])
            elif len(nums) == 1:
                line_suffix = f"{nums[0]}"
                start_line = int(nums[0])
            elif func_info and func_info.get("start_line"):
                line_suffix = str(func_info["start_line"])
                start_line = int(func_info["start_line"])

            if not func_info:
                issue["location"] = f"unknown_file:{line_suffix}"
                if start_line is not None:
                    if not issue.get("line"):
                        issue["line"] = start_line
                    if not issue.get("start_line"):
                        issue["start_line"] = start_line
                if end_line is not None:
                    if not issue.get("end_line"):
                        issue["end_line"] = end_line
                continue

            relative_file = func_info["file"]
            issue["location"] = f"{relative_file}:{line_suffix}"
            if not issue.get("file"):
                issue["file"] = relative_file
            if start_line is not None:
                if not issue.get("line"):
                    issue["line"] = start_line
                if not issue.get("start_line"):
                    issue["start_line"] = start_line
            if end_line is not None:
                if not issue.get("end_line"):
                    issue["end_line"] = end_line




