"""
Main analyzer logic for Z-SCOPE.
Orchestrates the analysis process using LLM, CodeIndex, and SnapshotStore.
"""

import json
import logging
import time
import datetime
import re
import fnmatch
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, cast

from ..config.config import ZScopeConfig
from ..config.user_config_store import UserConfigStore
from ..retrieval.code_index import CodeIndex
from .snapshot_store import SnapshotStore
from .candidate_evidence import (
    SemanticOverlayCompiler,
    annotate_candidate_evidence,
    backend_profile_for_code_index,
)
from .clang_ast_cfg_candidates import ClangAstCfgCandidateGenerator
from .clang_tooling_evidence import ClangToolingEvidenceProvider
from .regex_candidates import RegexCandidateGenerator, LocalPatternSemantics
from .graph_candidates import GraphCandidateGenerator
from .svf_value_flow_candidates import SvfValueFlowCandidateGenerator
from .tools_runtime import ToolsRuntime
from ..framework.llm_client import LLMClient
from ..agents.semantic_modeler.agent import SemanticModeler
from ..agents.semantic_modeler.schema import DEFAULT_FUNCTION_SNAPSHOT_SCHEMA
from ..agents.vulnerability_analyzer.agent import VulnerabilityAnalyzer
from ..agents.validator_agent.agent import ValidatorAgent
from .report import FinalReport, Issue, ReportGenerator
from .issue_dedup import (
    canonical_issue_key,
    deduplicate_issues,
    flatten_issue_text,
    issue_rank,
    normalize_issue_category,
    normalize_issue_key_part,
    parse_issue_location,
)
from .report_views import build_report_views, report_view_summary
from ..common.utils import extract_json_blocks, validate_json_schema
from .._version import __version__
from ..orchestration.specs import SpecRegistry, WorkflowStep
from ..orchestration.workflow_executor import WorkflowExecutor, WorkflowStepHandler
from ..orchestration.subagents import SubAgentOrchestrator
from ..orchestration.candidates import CandidateLedger
from ..orchestration.budget import EffectiveBudget, RiskBudgetPlanner
from ..orchestration.skill_selection import SkillSelection, select_vulnerability_skills

logger = logging.getLogger(__name__)

DEFAULT_SCAN_STEP_IDS = (
    "premodel_reachable_callees",
    "model_entry",
    "focused_subagent_planning",
    "vulnerability_mining",
    "validate_findings",
    "persist_report",
)

LIGHTWEIGHT_MACRO_RE = re.compile(
    r"^(?:LOG_(?:DEBUG|INFO|WARN|ERROR)|LOCK(?:_READ|_WRITE)?|UNLOCK|"
    r"ARRAY_SIZE|OFFSET_OF|RETURN_IF_(?:NULL|ERR)|GOTO_IF_(?:NULL|ERR)|"
    r"MIN|MAX|CLAMP|STR_LEN|STR_EQ|STR_EMPTY|LIKELY|UNLIKELY)$"
)
LIGHTWEIGHT_WRAPPER_RE = re.compile(
    r"^_(?:log|lock|unlock|lock_read|lock_write)_wrapper$"
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
                 candidate_ledger: Optional[CandidateLedger] = None):
        self.config = config
        self.code_index = code_index or CodeIndex(
            config.project.project_root,
            config.project.compile_commands_path,
            source_root=config.project.source_root,
            indexing_config=config.indexing,
            priority_functions=[config.project.entry_function] if config.project.entry_function else None,
            include_paths=config.project.include_paths,
            exclude_paths=config.project.exclude_paths,
            svf_entry_functions=[config.project.entry_function] if config.project.entry_function else None,
        )
        self.snapshot_store = snapshot_store or SnapshotStore(Path(config.analysis.snapshot_dir))
        db_dir = Path(config.analysis.user_config_db) if config.analysis.user_config_db else Path(config.analysis.snapshot_dir)
        self.user_config = user_config or UserConfigStore(db_dir)
        self.llm_clients: Dict[str, LLMClient] = {}
        for name, llm_cfg in config.llms.items():
            self.llm_clients[name] = LLMClient(
                api_key=llm_cfg.api_key,
                base_url=llm_cfg.base_url,
                models=llm_cfg.models,
                timeout=llm_cfg.timeout,
                max_retries=llm_cfg.max_retries,
                max_tokens=llm_cfg.max_tokens
            )
        self.report_generator = ReportGenerator(config.project.project_root)
        self.tools_runtime = ToolsRuntime(self.code_index, self.snapshot_store, self.user_config)
        self.spec_registry = SpecRegistry(project_root=config.project.project_root)
        self.workflow_spec = self.spec_registry.get_workflow(config.analysis.workflow_name)
        self.force_ignore_history = force_ignore_history
        self.maintain_mode = maintain_mode
        self.candidate_ledger = candidate_ledger or CandidateLedger()
        self.budget_planner = RiskBudgetPlanner(config.analysis)
        self._skill_selection_cache: Dict[str, SkillSelection] = {}
        self._local_pattern_semantics: Optional[LocalPatternSemantics] = None
        self._semantic_overlay: Optional[Dict[str, Any]] = None
        self._clang_tooling_provider: Optional[ClangToolingEvidenceProvider] = None
        self._clang_tooling_evidence_cache: Dict[tuple[str, str, int, int], Dict[str, Any]] = {}
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
        
        self.analyzed_functions: Set[str] = set()
        self.issues: List[Issue] = []

    def run(self) -> Dict[str, Any]:
        """Run the selected workflow as executable orchestration steps."""
        state = self._create_workflow_state()
        if state.get("error"):
            return {"error": state["error"]}

        workflow_name = self.workflow_spec.name if self.workflow_spec else self.config.analysis.workflow_name
        logger.info(
            "Starting workflow '%s' on entry function: %s",
            workflow_name,
            state["entry_func"],
        )

        steps = self._selected_workflow_steps()
        self.workflow_executor.execute(state, steps)
        self.current_workflow_step = self.workflow_executor.current_step

        if state.get("final_report_dict"):
            return self._finalize_returned_report(state)

        if not state.get("final_report"):
            self._build_final_report(state)

        return self._persist_final_report(state)

    def _create_workflow_state(self) -> Dict[str, Any]:
        """Create mutable execution state shared by workflow steps."""
        entry_func = self.config.project.entry_function
        if not entry_func:
            return {"error": "No entry function configured"}
        self.user_config.clear_config_warnings()

        impl_result = self.code_index.get_function_impl(entry_func)
        if not impl_result:
            return {"error": "Entry function not found"}

        agent_context = {
            "func_name": entry_func,
            "code": impl_result["code"],
            "location": f"{impl_result['file']}:{impl_result['start_line']}",
        }

        user_config_context = self._relevant_user_config_context(
            entry_func,
            impl_result["code"],
            impl_result.get("file", ""),
        )
        if user_config_context:
            agent_context["user_config_context"] = user_config_context

        state = {
            "entry_func": entry_func,
            "run_id": uuid.uuid4().hex,
            "impl_result": impl_result,
            "agent_context": agent_context,
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
            "any_failure": False,
            "failure_msg": "",
            "final_report": None,
            "final_report_dict": None,
        }
        self._refresh_effective_budget(state, "initial")
        return state

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
        return self._refresh_effective_budget(state, "late_init").to_dict()

    def _relevant_user_config_context(self, entry_func: str, code: str, file_path: str = "") -> str:
        """Return only user-config rows referenced by the current function."""

        identifiers = set(re.findall(r"\b[A-Za-z_]\w*\b", code or ""))
        identifiers.add(entry_func)
        parts: List[str] = []

        external_lines = []
        for item in self.user_config.list_external_functions():
            name = str(item.get("func_name") or "")
            if name not in identifiers:
                continue
            summary = str(item.get("description") or "").strip()
            memory = str(item.get("memory_behavior") or "").strip()
            concurrency = str(item.get("concurrency_behavior") or "").strip()
            details = ", ".join(part for part in (summary, memory, concurrency) if part)
            external_lines.append(f"  {name}: {details}" if details else f"  {name}")
        if external_lines:
            parts.append("[Relevant user-config API semantics]\n" + "\n".join(external_lines))

        pair_lines = []
        for pair in self.user_config.list_paired_functions():
            acquire = str(pair.get("acquire_func") or "")
            release = str(pair.get("release_func") or "")
            if acquire not in identifiers and release not in identifiers:
                continue
            desc = str(pair.get("description") or "").strip()
            suffix = f" ({desc})" if desc else ""
            pair_lines.append(
                f"  {pair.get('category', 'pair')}: {acquire} <-> {release}{suffix}"
            )
        if pair_lines:
            parts.append("[Relevant user-config pairs]\n" + "\n".join(pair_lines))

        pointer_lines = []
        for target in self.user_config.get_pointer_targets():
            if not Analyzer._user_config_scope_matches(str(target.get("scope") or "*"), file_path):
                continue
            pointer_location = str(target.get("pointer_location") or "")
            target_functions = Analyzer._parse_user_config_list(target.get("target_functions"))
            if (
                pointer_location not in code
                and pointer_location not in identifiers
                and not identifiers.intersection(target_functions)
            ):
                continue
            pointer_lines.append(
                f"  {pointer_location} -> {', '.join(target_functions)}"
                + (f" (scope: {target.get('scope')})" if target.get("scope") else "")
            )
        if pointer_lines:
            parts.append("[Relevant user-config function pointers]\n" + "\n".join(pointer_lines))

        dispatcher_lines = []
        list_dispatchers = getattr(self.user_config, "list_dispatchers", None)
        if callable(list_dispatchers):
            for row in list_dispatchers():
                if not Analyzer._user_config_scope_matches(str(row.get("file_path") or "*"), file_path):
                    continue
                dispatcher = str(row.get("dispatcher_name") or "")
                handler = str(row.get("handler_name") or "")
                pair = str(row.get("pair") or "")
                if dispatcher not in identifiers and handler not in identifiers and pair not in identifiers:
                    continue
                fields = [
                    f"message={row.get('message_type', '')}",
                    f"handler={handler}",
                    f"kind={row.get('handler_kind', '')}",
                    f"resource={row.get('resource', '')}",
                ]
                if pair:
                    fields.append(f"pair={pair}")
                desc = str(row.get("description") or "").strip()
                dispatcher_lines.append(f"  {dispatcher}: " + ", ".join(fields) + (f" ({desc})" if desc else ""))
        if dispatcher_lines:
            parts.append("[Relevant user-config dispatcher branches]\n" + "\n".join(dispatcher_lines))

        lifecycle_lines = []
        list_module_lifecycle = getattr(self.user_config, "list_module_lifecycle", None)
        if callable(list_module_lifecycle):
            for row in list_module_lifecycle():
                if not Analyzer._user_config_scope_matches(str(row.get("file_path") or "*"), file_path):
                    continue
                name = str(row.get("symbol_name") or "")
                pair = str(row.get("pair") or "")
                if name not in identifiers and pair not in identifiers:
                    continue
                lifecycle_lines.append(
                    f"  {name}: kind={row.get('kind', '')}, pair={pair}, "
                    f"needs_finit={row.get('needs_finit', '')}, "
                    f"error_path_cleanup_required={row.get('error_path_cleanup_required', '')}, "
                    f"description={row.get('description', '')}"
                )
        if lifecycle_lines:
            parts.append("[Relevant user-config module lifecycle]\n" + "\n".join(lifecycle_lines))

        intent_ctx = self.user_config.get_function_intent_context(entry_func, file_path)
        if intent_ctx:
            parts.append(intent_ctx)

        return "\n".join(parts)

    @staticmethod
    def _user_config_scope_matches(scope: str, file_path: str) -> bool:
        scope = (scope or "*").replace("\\", "/").strip()
        if scope in {"", "*"}:
            return True
        normalized = str(file_path or "").replace("\\", "/")
        candidates = [normalized, "/" + normalized.lstrip("/")]
        return any(fnmatch.fnmatch(candidate, scope) for candidate in candidates)

    @staticmethod
    def _parse_user_config_list(value: Any) -> List[str]:
        if isinstance(value, list):
            return [str(item) for item in value if item]
        if not value:
            return []
        try:
            parsed = json.loads(str(value))
        except json.JSONDecodeError:
            return [item.strip() for item in str(value).split(",") if item.strip()]
        if isinstance(parsed, list):
            return [str(item) for item in parsed if item]
        return [str(parsed)]

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

        entry_func = state["entry_func"]
        impl_result = state["impl_result"]
        historical_report = None
        if self.snapshot_store and not self.force_ignore_history:
            historical_report = self.snapshot_store.load_final_report(entry_func, impl_result["file"])

        hist_issues = historical_report.get("issues", []) if historical_report else []
        valid_hist_issues = [
            iss for iss in hist_issues
            if iss.get("validation_status") in ("validated", "pending")
        ]
        user_rejected_hist_issues = [
            iss for iss in hist_issues
            if iss.get("validation_status") == "rejected"
            and iss.get("rejection_source") == "user"
        ]

        needs_refresh = True
        reason = "no_snapshot"
        if self.snapshot_store and not self.force_ignore_history:
            needs_refresh, reason_value = self.snapshot_store.needs_refresh(
                entry_func,
                impl_result["code"],
                impl_result["file"],
            )
            reason = str(reason_value)

        state.update(
            {
                "historical_report": historical_report,
                "valid_hist_issues": valid_hist_issues,
                "user_rejected_hist_issues": user_rejected_hist_issues,
                "needs_refresh": needs_refresh,
                "refresh_reason": reason,
                "is_code_unchanged": (not needs_refresh and reason != "no_snapshot"),
                "history_loaded": True,
            }
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

            from ..agents.issue_reconciler.agent import IssueReconcilerAgent

            reconciler_agent = IssueReconcilerAgent(recon_client)
            verified_hist_issues = []
            for hist_issue in valid_hist_issues:
                input_data = {
                    "mode": "verify_fix",
                    "historical_issue": hist_issue,
                    "new_code": state["impl_result"]["code"],
                }
                resp = reconciler_agent.run(input_data)
                if resp.success and resp.data.get("still_exists"):
                    hist_issue["location"] = resp.data.get("new_location", hist_issue.get("location"))
                    verified_hist_issues.append(hist_issue)
                else:
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
        )
        agent_context = state["agent_context"]

        logger.info("Running Semantic Modeler agent with '%s' LLM...", sm_llm_ref)
        self._attach_agent_contract(agent_context, "semantic_modeler")
        response = semantic_agent.run(agent_context)
        sm_tokens = response.metadata.get("context_tokens", 0) if response.metadata else 0
        state["total_context_tokens"] += sm_tokens

        if response.success:
            self.snapshot_store.save_snapshot(
                state["entry_func"],
                response.data,
                agent_context["code"],
                agent_context["location"],
            )
            logger.info(
                "Successfully modeled function: %s (ctx 鈮?%s tokens)",
                state["entry_func"],
                f"{sm_tokens:,}",
            )
            state["notes"].append(f"Successfully modeled function: {state['entry_func']}")
        else:
            logger.warning("Semantic modeling failed: %s (ctx 鈮?%s tokens)", response.error, f"{sm_tokens:,}")
            state["notes"].append(f"Semantic modeling failed: {response.error}")

    def _step_focused_subagent_planning(self, state: Dict[str, Any]) -> None:
        va_agent_cfg = next(
            (a for a in self.config.project.agents if a.enabled and a.name == "vulnerability_analyzer"),
            None,
        )
        if not va_agent_cfg:
            return

        tools = self._get_tools("deep_worker")
        orchestrator = SubAgentOrchestrator(self.spec_registry, tools)
        va_llm_ref = va_agent_cfg.llm_ref if va_agent_cfg.llm_ref else "default"
        va_client = self.llm_clients.get(va_llm_ref, self.llm_clients.get("default"))
        selection = self._select_vulnerability_skills_for_config(va_agent_cfg, va_client)
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
        reports = orchestrator.run_tickets(
            va_client,
            tickets,
            max_iterations=min(self.config.analysis.max_tool_iterations, 20),
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
            analyzer_agent = VulnerabilityAnalyzer(
                va_client,
                self._get_tools("vulnerability_analyzer"),
            )
            selection = self._select_vulnerability_skills_for_config(agent_cfg, va_client)

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
            rule_candidates = self._detect_local_rule_candidates(state)
            graph_candidates = self._detect_graph_rule_candidates(state)
            backend_candidates = self._detect_backend_signal_candidates(state)
            candidate_signals = self._merge_unified_evidence_candidates(
                rule_candidates + graph_candidates + backend_candidates
            )
            self._refresh_effective_budget(
                state,
                "candidate_signals",
                rule_candidates=rule_candidates,
                graph_candidates=graph_candidates,
                backend_candidates=backend_candidates,
            )
            signal_summary = state.setdefault(
                "candidate_signal_summary",
                {"regex": 0, "clang_ast_cfg": 0, "svf_value_flow": 0, "graph": 0, "backend": 0, "total": 0},
            )
            for key in ("regex", "clang_ast_cfg", "svf_value_flow", "graph", "backend", "total"):
                signal_summary.setdefault(key, 0)
            signal_summary["regex"] += sum(
                1 for item in rule_candidates if item.get("candidate_source") == "regex_local_rule"
            )
            signal_summary["clang_ast_cfg"] += sum(
                1 for item in rule_candidates if item.get("candidate_source") == "clang_ast_cfg"
            )
            signal_summary["graph"] += len(graph_candidates)
            signal_summary["svf_value_flow"] += sum(
                1 for item in backend_candidates if item.get("candidate_source") == "svf_value_flow"
            )
            signal_summary["backend"] += len(backend_candidates)
            signal_summary["total"] += len(candidate_signals)
            self._persist_candidate_ir_records(candidate_signals)
            response = analyzer_agent.run(
                agent_context,
                max_iterations=self.config.analysis.max_tool_iterations,
            )

            if response.success:
                raw_new_issues = response.data.get("issues", [])
                if candidate_signals:
                    raw_new_issues = list(raw_new_issues) + candidate_signals
                    state["notes"].append(
                        f"Added {len(rule_candidates)} local backend candidate(s), "
                        f"{len(graph_candidates)} graph/protocol candidate(s), "
                        f"and {len(backend_candidates)} backend signal candidate(s)."
                    )
                va_ctx_tokens = response.metadata.get("context_tokens", 0) if response.metadata else 0
                state["total_context_tokens"] += va_ctx_tokens
                logger.info(
                    "Vulnerability Analyzer found %d issue(s) for task: %s (ctx 鈮?%s tokens)",
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

        from ..agents.issue_reconciler.agent import IssueReconcilerAgent

        reconciler_agent = IssueReconcilerAgent(recon_client)
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
        issues: List[Dict[str, Any]] = []
        if profile == "regex":
            generator = RegexCandidateGenerator(self._get_local_pattern_semantics())
            issues.extend(generator.generate_issues(entry_func, code, file_path))
            issues.extend(self._detect_direct_callee_rule_candidates(impl, generator, entry_func=entry_func))
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
            issues.extend(self._detect_direct_callee_rule_candidates(impl, clang_generator, entry_func=entry_func))
        issues = self._dedupe_rule_candidates(issues)
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
        issues = self._dedupe_rule_candidates(issues)
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
                )
            )
        if not issues:
            return []
        issues = self._dedupe_rule_candidates(issues)
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
        ]

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
        for item in impl.get("callees", [])[:limit]:
            name = self._callee_item_name(item)
            if not name or name == root:
                continue
            queued.append((name, 1, [root, name] if root else [name]))
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
            if depth >= max_depth:
                continue
            for nested in callee_impl.get("callees", [])[:limit]:
                nested_name = self._callee_item_name(nested)
                if nested_name and nested_name not in visited and nested_name not in call_path:
                    queued.append((nested_name, depth + 1, call_path + [nested_name]))
        return issues

    @staticmethod
    def _callee_item_name(item: Any) -> str:
        if isinstance(item, dict):
            return str(item.get("name") or item.get("callee_name") or item.get("function") or "").strip()
        return str(item or "").strip()

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
        ast_dump = tooling_evidence.get("ast_dump") if isinstance(tooling_evidence, dict) else {}
        ast_summary = ast_dump.get("summary") if isinstance(ast_dump, dict) else {}
        target = ast_summary.get("target_function") if isinstance(ast_summary, dict) else {}
        facts = target.get("matcher_facts") if isinstance(target, dict) else []
        if not isinstance(facts, list):
            return []
        allowed = set(allowed_skills) if allowed_skills is not None else None
        issues: List[Dict[str, Any]] = []
        for fact in facts:
            if not isinstance(fact, dict):
                continue
            defect_class = Analyzer._defect_class_from_clang_matcher_fact(fact)
            if not defect_class:
                continue
            skill = Analyzer._skill_for_matcher_defect(defect_class)
            if allowed is not None and skill not in allowed:
                continue
            issues.append(
                Analyzer._clang_matcher_fact_to_candidate(
                    func_name,
                    file_path,
                    fact,
                    defect_class,
                    tooling_evidence,
                )
            )
        return issues

    @staticmethod
    def _defect_class_from_clang_matcher_fact(fact: Dict[str, Any]) -> str:
        rule = str(fact.get("rule_id") or "")
        category = str(fact.get("category") or "")
        if rule == "clang_ast_resource_balance_summary":
            acquires = int(fact.get("acquire_call_count") or 0)
            releases = int(fact.get("release_call_count") or 0)
            return "memory_leak" if acquires > releases else ""
        if category in {"double_free", "use_after_free"}:
            return category
        if category in {"bounds", "format_string", "command_injection"}:
            return category
        return ""

    @staticmethod
    def _skill_for_matcher_defect(defect_class: str) -> str:
        return {
            "bounds": "bounds_and_integer",
            "format_string": "string_and_format",
            "command_injection": "string_and_format",
            "memory_leak": "resource_lifecycle",
            "double_free": "temporal_memory",
            "use_after_free": "temporal_memory",
        }.get(defect_class, "resource_lifecycle")

    @staticmethod
    def _clang_matcher_fact_to_candidate(
        func_name: str,
        file_path: str,
        fact: Dict[str, Any],
        defect_class: str,
        tooling_evidence: Dict[str, Any],
    ) -> Dict[str, Any]:
        rule = str(fact.get("rule_id") or "clang_ast_matcher_fact")
        line = int(fact.get("line") or 0)
        if not line:
            line = int(((tooling_evidence.get("range") or {}) if isinstance(tooling_evidence, dict) else {}).get("start_line") or 0)
        callee = str(fact.get("callee") or fact.get("resource_symbol") or rule)
        candidate_id = f"CLANG_AST_MATCHER_{defect_class.upper()}_{func_name}_{line}_{uuid.uuid5(uuid.NAMESPACE_URL, rule + callee).hex[:8]}"
        location = f"{file_path}:{line}" if file_path else f"{func_name}:{line}"
        positive = [
            f"Clang AST matcher fact `{rule}` matched `{callee}` in `{func_name}` at {location}",
        ]
        if rule == "clang_ast_resource_balance_summary":
            positive.append(
                f"Resource balance summary: acquire={fact.get('acquire_call_count', 0)}, "
                f"release={fact.get('release_call_count', 0)}"
            )
        if fact.get("resource_symbol"):
            positive.append(f"Resource symbol involved: `{fact.get('resource_symbol')}`")
        negative = [
            "AST matcher evidence is syntactic; Validator must confirm data/control feasibility and semantic ownership.",
        ]
        evidence = {
            "candidate_id": candidate_id,
            "candidate_source": "clang_ast_matcher",
            "checker": "clang_ast_matcher_checker",
            "defect_class": defect_class,
            "rule": rule,
            "source": {"expression": callee, "file": file_path, "line": line},
            "sink": {"operation": callee, "file": file_path, "line": line},
            "path": {
                "function": func_name,
                "backend": "Clang AST matcher facts",
                "complete_in_function": False,
                "path_constraints": [
                    "AST matcher fact is path-insensitive",
                    "validator must check guards, ownership transfer, aliases, and reachability",
                ],
            },
            "clang_matcher_fact": fact,
            "clang_tooling": Analyzer._compact_clang_tooling_evidence(tooling_evidence),
            "positive_evidence": positive,
            "negative_evidence": negative,
            "evidence_refs": [],
        }
        return {
            "id": candidate_id,
            "candidate_id": candidate_id,
            "function": func_name,
            "location": location,
            "category": defect_class,
            "subcategory": defect_class,
            "defect_class": defect_class,
            "finding_kind": "clang_ast_matcher_candidate",
            "candidate_source": "clang_ast_matcher",
            "evidence_checker": "clang_ast_matcher_checker",
            "rule": rule,
            "description": f"Clang AST matcher fact `{rule}` identified `{callee}` in `{func_name}`.",
            "root_cause": "Clang AST tooling produced a syntactic matcher fact requiring semantic validation.",
            "suggested_fix": "Validate the fact against concrete data/control flow before changing code.",
            "confidence": 0.64 if defect_class != "memory_leak" else 0.58,
            "rule_confidence": 0.64 if defect_class != "memory_leak" else 0.58,
            "impact_level": "high" if defect_class in {"command_injection", "double_free", "use_after_free"} else "medium",
            "reasoning": "Clang AST matcher fact normalized into an evidence-only candidate for Validator review.",
            "source": callee,
            "sink": callee,
            "dedup_key": "|".join([defect_class, file_path.replace("\\", "/").lower(), str(line), rule, callee]),
            "positive_evidence": positive,
            "negative_evidence": negative,
            "evidence_pack": evidence,
            "evidence_refs": [],
        }

    @staticmethod
    def _compact_clang_tooling_evidence(tooling_evidence: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(tooling_evidence, dict):
            return {}
        ast_dump = tooling_evidence.get("ast_dump") if isinstance(tooling_evidence.get("ast_dump"), dict) else {}
        cfg_dump = tooling_evidence.get("cfg_dump") if isinstance(tooling_evidence.get("cfg_dump"), dict) else {}
        ast_summary = ast_dump.get("summary") if isinstance(ast_dump.get("summary"), dict) else {}
        cfg_summary = cfg_dump.get("summary") if isinstance(cfg_dump.get("summary"), dict) else {}
        target = ast_summary.get("target_function") if isinstance(ast_summary.get("target_function"), dict) else {}
        return {
            "schema": tooling_evidence.get("schema"),
            "status": tooling_evidence.get("status"),
            "execution_enabled": tooling_evidence.get("execution_enabled"),
            "compile_command_found": tooling_evidence.get("compile_command_found"),
            "range": tooling_evidence.get("range"),
            "ast_target_function": {
                "name": target.get("name"),
                "line": target.get("line"),
                "type": target.get("type"),
                "matcher_facts": target.get("matcher_facts", [])[:16],
            },
            "cfg_summary": {
                "parse_ok": cfg_summary.get("parse_ok"),
                "block_count": cfg_summary.get("block_count"),
                "edge_count": cfg_summary.get("edge_count"),
                "entry_blocks": cfg_summary.get("entry_blocks", []),
                "exit_blocks": cfg_summary.get("exit_blocks", []),
            },
        }

    @staticmethod
    def _dedupe_rule_candidates(issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        deduped: Dict[str, Dict[str, Any]] = {}
        for issue in issues:
            key = Analyzer._rule_candidate_dedup_key(issue)
            existing = deduped.get(key)
            if existing is None:
                deduped[key] = issue
            else:
                Analyzer._merge_rule_candidate_duplicate(existing, issue)
        return list(deduped.values())

    @staticmethod
    def _rule_candidate_dedup_key(issue: Dict[str, Any]) -> str:
        evidence = issue.get("evidence_pack") if isinstance(issue.get("evidence_pack"), dict) else {}
        if issue.get("internal_sink_lifted") or evidence.get("internal_sink_lifted"):
            sink_func = str(evidence.get("sink_function") or issue.get("function") or "")
            location = str(issue.get("location") or "").replace("\\", "/").lower()
            return "|".join(
                [
                    "lifted_internal_sink",
                    str(issue.get("defect_class") or issue.get("category") or ""),
                    sink_func,
                    location,
                    str(issue.get("rule") or ""),
                    str(issue.get("source") or ""),
                    str(issue.get("sink") or ""),
                ]
            )
        return str(
            issue.get("dedup_key")
            or issue.get("candidate_id")
            or issue.get("id")
            or (
                issue.get("function"),
                issue.get("defect_class"),
                issue.get("rule"),
                issue.get("file") or issue.get("file_path"),
                issue.get("line"),
            )
        )

    @staticmethod
    def _merge_rule_candidate_duplicate(primary: Dict[str, Any], duplicate: Dict[str, Any]) -> None:
        primary_sources = primary.setdefault("duplicate_sources", [])
        if not isinstance(primary_sources, list):
            primary_sources = []
            primary["duplicate_sources"] = primary_sources
        entry = {
            "candidate_id": duplicate.get("candidate_id") or duplicate.get("id"),
            "entry_function": duplicate.get("entry_function") or duplicate.get("analyzed_from"),
            "analyzed_from": duplicate.get("analyzed_from"),
            "call_path": duplicate.get("call_path") or [],
            "location": duplicate.get("location"),
            "candidate_source": duplicate.get("candidate_source"),
        }
        if entry not in primary_sources:
            primary_sources.append(entry)

        for field in ("positive_evidence", "negative_evidence", "evidence_refs"):
            current = primary.setdefault(field, [])
            incoming = duplicate.get(field) or []
            if not isinstance(current, list) or not isinstance(incoming, list):
                continue
            for item in incoming:
                if item not in current:
                    current.append(item)

        primary_path = primary.get("call_path")
        duplicate_path = duplicate.get("call_path")
        if duplicate_path and primary_path != duplicate_path:
            paths = primary.setdefault("call_paths", [])
            if isinstance(paths, list):
                if primary_path and primary_path not in paths:
                    paths.append(primary_path)
                if duplicate_path not in paths:
                    paths.append(duplicate_path)

        primary_pack = primary.get("evidence_pack") if isinstance(primary.get("evidence_pack"), dict) else {}
        duplicate_pack = duplicate.get("evidence_pack") if isinstance(duplicate.get("evidence_pack"), dict) else {}
        if not primary_pack:
            primary["evidence_pack"] = primary_pack
        if duplicate_pack:
            pack_sources = primary_pack.setdefault("duplicate_sources", [])
            if isinstance(pack_sources, list) and entry not in pack_sources:
                pack_sources.append(entry)
            duplicate_edges = duplicate_pack.get("call_path_edges") or []
            if duplicate_edges:
                edge_sets = primary_pack.setdefault("duplicate_call_path_edges", [])
                if isinstance(edge_sets, list) and duplicate_edges not in edge_sets:
                    edge_sets.append(duplicate_edges)

    def _detect_backend_signal_candidates(self, state: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Convert KnowledgeDB/SVF/Saber findings into normal candidates."""
        candidates: List[Dict[str, Any]] = []
        db = self._get_knowledge_db()
        entry_func = str(state.get("entry_func") or "")
        if db is not None:
            try:
                bugs = db.get_enriched_taint_bugs(func_name=entry_func, limit=50)
            except Exception as exc:
                logger.debug("Unable to read backend taint bugs: %s", exc)
                bugs = []

            candidates.extend(
                SvfValueFlowCandidateGenerator(
                    source_path_resolver=self._reconstruct_svf_source_path,
                ).generate_issues(
                    bugs,
                    entry_func=entry_func,
                )
            )
        candidates.extend(self._detect_clang_knowledgedb_candidates(state, db))
        candidates.extend(self._detect_joern_cpg_candidates(state))
        candidates = self._dedupe_rule_candidates(candidates)
        return self._annotate_candidate_issues(
            candidates,
            checker=self._backend_signal_checker(),
            path_kind="backend_signal",
        )

    def _merge_unified_evidence_candidates(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Merge Clang and SVF evidence for the same issue in unified mode."""
        if self._candidate_backend_profile() != "unified":
            return candidates
        merged: List[Dict[str, Any]] = []
        for candidate in candidates:
            match = next(
                (
                    existing
                    for existing in merged
                    if self._unified_candidates_may_refer_same_issue(existing, candidate)
                ),
                None,
            )
            if match is None:
                merged.append(candidate)
                continue
            self._attach_unified_secondary_evidence(match, candidate)
        return merged

    @classmethod
    def _unified_candidates_may_refer_same_issue(
        cls,
        left: Dict[str, Any],
        right: Dict[str, Any],
    ) -> bool:
        left_source = cls._candidate_source_name(left)
        right_source = cls._candidate_source_name(right)
        if not {left_source, right_source} & {"svf_value_flow"}:
            return False
        if not ({left_source, right_source} & {"clang_ast_cfg", "clang_ast_matcher", "clang_knowledgedb_call_edges"}):
            return False
        if not cls._defect_classes_compatible(left, right):
            return False
        left_file, left_line = cls._candidate_file_line(left)
        right_file, right_line = cls._candidate_file_line(right)
        if left_file and right_file and left_file != right_file:
            return False
        left_funcs = cls._candidate_function_names(left)
        right_funcs = cls._candidate_function_names(right)
        if left_funcs and right_funcs and left_funcs.isdisjoint(right_funcs):
            return False
        if left_line and right_line and abs(left_line - right_line) <= 8:
            return True
        return bool(cls._candidate_symbols(left) & cls._candidate_symbols(right))

    @staticmethod
    def _candidate_source_name(issue: Dict[str, Any]) -> str:
        pack = issue.get("evidence_pack") if isinstance(issue.get("evidence_pack"), dict) else {}
        return str(pack.get("candidate_source") or issue.get("candidate_source") or issue.get("finding_kind") or "")

    @staticmethod
    def _defect_classes_compatible(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
        left_cls = str(left.get("defect_class") or left.get("category") or "")
        right_cls = str(right.get("defect_class") or right.get("category") or "")
        if left_cls == right_cls:
            return True
        return "memory_safety" in {left_cls, right_cls} and bool(left_cls and right_cls)

    @classmethod
    def _candidate_file_line(cls, issue: Dict[str, Any]) -> tuple[str, int]:
        file_path, line = cls._parse_location_file_line(str(issue.get("location") or ""))
        pack = issue.get("evidence_pack") if isinstance(issue.get("evidence_pack"), dict) else {}
        for key in ("source_path", "value_flow", "path"):
            data = pack.get(key) if isinstance(pack.get(key), dict) else {}
            reported = data.get("reported_location") if isinstance(data.get("reported_location"), dict) else {}
            if not file_path:
                file_path = str(data.get("file") or reported.get("file") or "")
            if not line:
                line = int(data.get("line") or reported.get("line") or 0)
        return file_path.replace("\\", "/").lower(), line

    @staticmethod
    def _parse_location_file_line(location: str) -> tuple[str, int]:
        match = re.match(r"^(?P<file>.*?):(?P<line>\d+)(?:-\d+)?$", str(location or ""))
        if not match:
            return "", 0
        return match.group("file").replace("\\", "/").lower(), int(match.group("line"))

    @classmethod
    def _candidate_function_names(cls, issue: Dict[str, Any]) -> Set[str]:
        names = {
            str(issue.get("function") or ""),
            str(issue.get("entry_function") or ""),
            str(issue.get("analyzed_from") or ""),
        }
        pack = issue.get("evidence_pack") if isinstance(issue.get("evidence_pack"), dict) else {}
        for key in ("path", "source_path", "value_flow"):
            data = pack.get(key) if isinstance(pack.get(key), dict) else {}
            names.update(
                str(data.get(field) or "")
                for field in (
                    "function",
                    "target_function",
                    "entry_function",
                    "source_function",
                    "source_func",
                    "sink_function",
                    "sink_func",
                )
            )
            names.update(str(item) for item in data.get("call_path") or [] if str(item))
        return {name for name in names if name}

    @staticmethod
    def _candidate_symbols(issue: Dict[str, Any]) -> Set[str]:
        fields = [
            issue.get("source"),
            issue.get("sink"),
            issue.get("description"),
            issue.get("root_cause"),
            issue.get("positive_evidence"),
            issue.get("evidence_pack"),
        ]
        text = "\n".join(json.dumps(field, ensure_ascii=False, default=str) for field in fields if field)
        tokens = {
            token
            for token in re.findall(r"[A-Za-z_]\w*", text)
            if len(token) >= 3
            and token.lower()
            not in {
                "src",
                "line",
                "file",
                "candidate",
                "source",
                "sink",
                "function",
                "validator",
                "clang",
                "saber",
                "value",
                "flow",
            }
        }
        return tokens

    @staticmethod
    def _attach_unified_secondary_evidence(primary: Dict[str, Any], secondary: Dict[str, Any]) -> None:
        primary_pack = primary.get("evidence_pack") if isinstance(primary.get("evidence_pack"), dict) else {}
        if not primary_pack:
            primary["evidence_pack"] = primary_pack
        secondary_pack = secondary.get("evidence_pack") if isinstance(secondary.get("evidence_pack"), dict) else {}
        compact = {
            "candidate_id": secondary.get("candidate_id") or secondary.get("id"),
            "candidate_source": Analyzer._candidate_source_name(secondary),
            "checker": secondary.get("evidence_checker") or secondary_pack.get("checker"),
            "function": secondary.get("function"),
            "location": secondary.get("location"),
            "defect_class": secondary.get("defect_class") or secondary.get("category"),
            "rule": secondary.get("rule"),
            "source": secondary.get("source"),
            "sink": secondary.get("sink"),
            "evidence_pack": secondary_pack,
        }
        merged = primary_pack.setdefault("merged_backend_evidence", [])
        if isinstance(merged, list) and compact not in merged:
            merged.append(compact)
        sources = primary.setdefault("merged_candidate_sources", [])
        if isinstance(sources, list):
            for source in (Analyzer._candidate_source_name(primary), compact["candidate_source"]):
                if source and source not in sources:
                    sources.append(source)
        primary_pack["merged_candidate_sources"] = list(primary.get("merged_candidate_sources") or [])
        primary_pack["unified_backend_components"] = ["clang", "svf"]
        primary["unified_evidence_merged"] = True
        primary["validation_required"] = True
        primary["must_validate"] = True

        for field in ("positive_evidence", "negative_evidence", "evidence_refs"):
            current = primary.setdefault(field, [])
            incoming = secondary.get(field) or []
            if not isinstance(current, list) or not isinstance(incoming, list):
                continue
            for item in incoming:
                if item not in current:
                    current.append(item)
        note = (
            f"Unified evidence merge attached `{compact['candidate_source']}` "
            f"candidate `{compact['candidate_id']}` for Validator correlation."
        )
        positive = primary.setdefault("positive_evidence", [])
        if isinstance(positive, list) and note not in positive:
            positive.append(note)

    def _detect_clang_knowledgedb_candidates(
        self,
        state: Dict[str, Any],
        db: Optional[Any],
    ) -> List[Dict[str, Any]]:
        if db is None or self._candidate_backend_profile() not in {"clang", "unified"}:
            return []
        find_missing = getattr(db, "find_callers_without_callee", None)
        if not callable(find_missing):
            return []
        entry_func = str(state.get("entry_func") or "")
        pairs = self._resource_release_pairs_from_overlay()
        candidates: List[Dict[str, Any]] = []
        for acquire, release, pair_source in pairs:
            try:
                rows = find_missing(acquire, release, limit=100)
            except Exception as exc:
                logger.debug("Unable to query KnowledgeDB pair %s/%s: %s", acquire, release, exc)
                continue
            for row in rows:
                func = str(row.get("function") or "")
                if not self._match_reachable_from_entry(entry_func, func):
                    continue
                candidates.append(
                    self._clang_pair_row_to_candidate(
                        row,
                        entry_func=entry_func,
                        pair_source=pair_source,
                    )
                )
        return candidates

    def _resource_release_pairs_from_overlay(self) -> List[tuple[str, str, str]]:
        overlay = self._get_semantic_overlay()
        pairs: List[tuple[str, str, str]] = []
        for row in overlay.get("resource_models", []) if isinstance(overlay, dict) else []:
            if not isinstance(row, dict):
                continue
            kind = str(row.get("kind") or "").lower()
            if kind not in {"allocator", "calloc", "reallocator", "resource", "resource_acquire"}:
                continue
            acquire = str(row.get("name") or "").strip()
            for pair in self._split_config_pair_names(row.get("pair")):
                if acquire and pair:
                    pairs.append((acquire, pair, str(row.get("source") or "user_config")))
        seen = set()
        deduped = []
        for item in pairs:
            key = (item[0], item[1])
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item)
        return deduped

    @staticmethod
    def _split_config_pair_names(value: Any) -> List[str]:
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        return [part.strip() for part in str(value or "").split(",") if part.strip()]

    def _clang_pair_row_to_candidate(
        self,
        row: Dict[str, Any],
        *,
        entry_func: str,
        pair_source: str,
    ) -> Dict[str, Any]:
        func = str(row.get("function") or "")
        file_path = str(row.get("file_path") or "")
        line = int(row.get("line") or 0)
        acquire = str(row.get("acquire_func") or "")
        release = str(row.get("release_func") or "")
        candidate_id = f"CLANG_PAIR_MEMORY_LEAK_{func}_{line}_{uuid.uuid5(uuid.NAMESPACE_URL, acquire + release).hex[:8]}"
        positive = [
            f"Clang/KnowledgeDB call graph shows `{func}` calls `{acquire}` at {file_path}:{line}",
            f"No same-function call to configured release `{release}` was found in Clang call_edges",
            f"Pair source: {pair_source}",
        ]
        evidence = {
            "candidate_id": candidate_id,
            "candidate_source": "clang_knowledgedb_call_edges",
            "defect_class": "memory_leak",
            "rule": "configured_acquire_without_release",
            "source": {"expression": acquire, "file": file_path, "line": line},
            "sink": {"operation": f"missing {release}", "file": file_path, "line": line},
            "path": {
                "function": func,
                "entry_function": entry_func,
                "backend": "Clang KnowledgeDB call_edges",
                "complete_in_function": False,
                "path_constraints": [
                    "same function lacks configured release call",
                    "validator must check ownership transfer and caller-side cleanup",
                ],
            },
            "positive_evidence": positive,
            "negative_evidence": ["ownership transfer or caller-side release has not been ruled out"],
            "resource_pair": {"acquire": acquire, "release": release, "source": pair_source},
        }
        return {
            "id": candidate_id,
            "candidate_id": candidate_id,
            "function": func,
            "location": f"{file_path}:{line}" if file_path else f"{func}:{line}",
            "category": "memory_leak",
            "subcategory": "memory_leak",
            "defect_class": "memory_leak",
            "finding_kind": "clang_callgraph_candidate",
            "candidate_source": "clang_knowledgedb_call_edges",
            "rule": "configured_acquire_without_release",
            "description": f"`{func}` calls configured acquire `{acquire}` without same-function `{release}` in Clang call graph.",
            "root_cause": "Configured resource acquisition has no matching release in the same extracted function body.",
            "suggested_fix": "Release the resource on all paths or document/validate ownership transfer to another owner.",
            "confidence": 0.68,
            "rule_confidence": 0.68,
            "impact_level": "medium",
            "reasoning": "Clang KnowledgeDB call-edge candidate normalized into Z-SCOPE evidence pack.",
            "source": acquire,
            "sink": f"missing {release}",
            "positive_evidence": positive,
            "negative_evidence": evidence["negative_evidence"],
            "evidence_pack": evidence,
        }

    def _detect_joern_cpg_candidates(self, state: Dict[str, Any]) -> List[Dict[str, Any]]:
        if self._candidate_backend_profile() != "joern":
            return []
        backend_attr = getattr(self.code_index, "backend", None)
        backend = backend_attr() if callable(backend_attr) else backend_attr
        joern_client = getattr(backend, "joern_client", None)
        if joern_client is None:
            return []
        try:
            from .rule_engine import RuleEngine

            engine = RuleEngine(joern_client, self.user_config)
            matches = engine.run_builtin_scan()
            matches.extend(engine.run_semantic_cpg_rule_library())
            matches.extend(engine.run_paired_function_checks())
            matches.extend(engine.run_configured_data_flow_checks())
        except Exception as exc:
            logger.debug("Unable to run Joern CPG candidate checks: %s", exc)
            return []
        entry_func = str(state.get("entry_func") or "")
        scoped = [
            match
            for match in matches
            if self._match_reachable_from_entry(entry_func, str(getattr(match, "func_name", "")))
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
        get_callees = getattr(self.code_index, "get_callees", None)
        if not callable(get_callees):
            return False
        seen = {entry_func}
        queue: List[tuple[str, int]] = [(entry_func, 0)]
        while queue and len(seen) < max_nodes:
            current, depth = queue.pop(0)
            if depth >= max_depth:
                continue
            try:
                callees = get_callees(current, limit=80)
            except Exception:
                continue
            for item in callees or []:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name") or item.get("callee_name") or "").strip()
                if not name or name in seen:
                    continue
                if self._function_names_may_match(name, target_func):
                    return True
                seen.add(name)
                queue.append((name, depth + 1))
        return False

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
        data = match.to_dict() if hasattr(match, "to_dict") else dict(match)
        rule_id = str(data.get("rule_id") or data.get("rule") or "joern_rule")
        func = str(data.get("function") or data.get("func_name") or entry_func)
        file_path = str(data.get("file_path") or data.get("filename") or "")
        line = int(data.get("line_number") or data.get("lineNumber") or 0)
        defect_class = self._class_from_joern_category(str(data.get("category") or rule_id))
        candidate_id = f"JOERN_{defect_class.upper()}_{func}_{line}_{uuid.uuid5(uuid.NAMESPACE_URL, rule_id).hex[:8]}"
        source = str(data.get("rule_name") or rule_id)
        sink = str(data.get("code_snippet") or data.get("code") or rule_id)
        evidence_items = data.get("evidence") if isinstance(data.get("evidence"), list) else []
        positive = [f"Joern CPG rule `{rule_id}` matched `{func}` at {file_path}:{line}"]
        for item in evidence_items[:6]:
            positive.append(json.dumps(item, ensure_ascii=False, default=str))
        evidence = {
            "candidate_id": candidate_id,
            "candidate_source": "joern_cpg",
            "defect_class": defect_class,
            "rule": rule_id,
            "source": {"expression": source, "file": file_path, "line": line},
            "sink": {"operation": sink, "file": file_path, "line": line},
            "path": {
                "function": func,
                "entry_function": entry_func,
                "backend": "Joern CPG",
                "complete_in_function": False,
            },
            "positive_evidence": positive,
            "negative_evidence": [],
            "raw_match": data,
        }
        confidence = max(0.0, min(1.0, float(data.get("score") or 6.0) / 10.0))
        return {
            "id": candidate_id,
            "candidate_id": candidate_id,
            "function": func,
            "location": f"{file_path}:{line}" if file_path else f"{func}:{line}",
            "category": defect_class,
            "subcategory": defect_class,
            "defect_class": defect_class,
            "finding_kind": "joern_cpg_candidate",
            "candidate_source": "joern_cpg",
            "rule": rule_id,
            "description": f"Joern CPG rule `{rule_id}` reported `{source}` in `{func}`.",
            "root_cause": "Joern CPG query found a configured resource/protocol pattern requiring validation.",
            "suggested_fix": "Validate the CPG path and repair the missing release, lifetime, or protocol operation.",
            "confidence": confidence,
            "rule_confidence": confidence,
            "impact_level": "high" if defect_class in {"use_after_free", "double_free", "memory_leak"} else "medium",
            "reasoning": "Joern CPG candidate normalized into Z-SCOPE evidence pack.",
            "source": source,
            "sink": sink,
            "positive_evidence": positive,
            "negative_evidence": [],
            "evidence_pack": evidence,
        }

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

        if self._local_pattern_semantics is not None:
            return self._local_pattern_semantics
        semantics = LocalPatternSemantics()
        semantics.merge(self._scan_typedef_aliases())
        semantics.merge(self._semantics_from_user_config())
        semantics.merge(self._semantics_from_snapshots())
        semantics.merge(self._semantics_from_function_names())
        self._local_pattern_semantics = semantics
        logger.info(
            "Local pattern semantics: %d typedef alias(es), %d allocator(s), %d deallocator(s), "
            "%d reallocator(s), %d copy sink(s), %d lock API(s), %d unlock API(s).",
            len(semantics.type_aliases),
            len(semantics.allocators) + len(semantics.calloc_allocators),
            len(semantics.deallocators),
            len(semantics.reallocators),
            len(semantics.copy_sinks),
            len(semantics.lock_apis),
            len(semantics.unlock_apis),
        )
        return semantics

    def _scan_typedef_aliases(self) -> LocalPatternSemantics:
        semantics = LocalPatternSemantics()
        roots = [self.code_index.source_root]
        if self.code_index.project_root not in roots:
            roots.append(self.code_index.project_root)
        suffixes = {".h", ".hh", ".hpp", ".c", ".cc", ".cpp"}
        base_pattern = (
            r"(?:size_t|u?int(?:8|16|32|64)_t|"
            r"(?:unsigned|signed)?\s*(?:char|short|int|long|long\s+long))"
        )
        typedef_re = re.compile(
            rf"\btypedef\s+(?P<base>{base_pattern})\s+(?P<alias>[A-Za-z_]\w*)\s*;",
            re.MULTILINE,
        )
        define_re = re.compile(
            rf"^\s*#\s*define\s+(?P<alias>[A-Za-z_]\w*)\s+(?P<base>{base_pattern})\s*$",
            re.MULTILINE,
        )
        for root in roots:
            if not root.exists():
                continue
            for path in root.rglob("*"):
                if self._skip_semantic_source_scan_path(path):
                    continue
                if not path.is_file() or path.suffix.lower() not in suffixes:
                    continue
                try:
                    if path.stat().st_size > 1_000_000:
                        continue
                    text = path.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                for match in list(typedef_re.finditer(text)) + list(define_re.finditer(text)):
                    alias = match.group("alias")
                    if alias not in {"size_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t"}:
                        semantics.type_aliases[alias] = re.sub(r"\s+", " ", match.group("base")).strip()
        return semantics

    def _skip_semantic_source_scan_path(self, path: Path) -> bool:
        ignored_parts = {
            ".git",
            ".venv",
            ".mypy_cache",
            ".pytest_cache",
            ".zscope_snapshots",
            "zscope.egg-info",
            "build",
            "tmp",
        }
        if any(part in ignored_parts for part in path.parts):
            return True
        try:
            resolved = path.resolve()
        except OSError:
            return True
        return any(
            resolved == excluded or excluded in resolved.parents
            for excluded in self.config.project.exclude_paths
        )

    def _semantics_from_user_config(self) -> LocalPatternSemantics:
        semantics = LocalPatternSemantics()
        for ext in self.user_config.list_external_functions():
            name = str(ext.get("func_name") or "")
            kind = str(ext.get("kind") or "").lower()
            if kind in {"allocator", "resource_acquire"}:
                semantics.add_api("allocator", name, "user_config")
            elif kind == "calloc":
                semantics.add_api("calloc", name, "user_config")
            elif kind == "reallocator":
                semantics.add_api("reallocator", name, "user_config")
            elif kind in {"deallocator", "resource_release"}:
                semantics.add_api("deallocator", name, "user_config")
            elif kind == "copy":
                semantics.add_api("copy", name, "user_config")
            elif kind == "lock":
                semantics.add_api("lock", name, "user_config")
            elif kind == "unlock":
                semantics.add_api("unlock", name, "user_config")
            memory = self._parse_jsonish(ext.get("memory_behavior"))
            concurrency = self._parse_jsonish(ext.get("concurrency_behavior"))
            text = " ".join(
                [
                    str(ext.get("description") or ""),
                    str(ext.get("return_semantics") or ""),
                    json.dumps(memory, ensure_ascii=False),
                    json.dumps(concurrency, ensure_ascii=False),
                ]
            ).lower()
            self._add_api_from_semantic_text(semantics, name, text, "user_config")

        for pair in self.user_config.list_paired_functions():
            category = str(pair.get("category") or "").lower()
            acquire = str(pair.get("acquire_func") or "")
            release = str(pair.get("release_func") or "")
            if any(word in category for word in ("lock", "mutex", "rwlock", "spin", "sync", "concurrency")):
                semantics.add_api("lock", acquire, "user_config:paired_functions")
                semantics.add_api("unlock", release, "user_config:paired_functions")
            elif any(word in category for word in ("memory", "resource", "alloc", "鐢熷懡鍛ㄦ湡", "璧勬簮", "鍐呭瓨")):
                semantics.add_api("allocator", acquire, "user_config:paired_functions")
                semantics.add_api("deallocator", release, "user_config:paired_functions")
            else:
                self._add_api_by_name_heuristic(semantics, acquire, "user_config:paired_functions")
                self._add_api_by_name_heuristic(semantics, release, "user_config:paired_functions")
        return semantics

    def _semantics_from_snapshots(self) -> LocalPatternSemantics:
        semantics = LocalPatternSemantics()
        snapshot_dir = self.snapshot_store.snapshot_dir
        if not snapshot_dir.exists():
            return semantics
        for path in snapshot_dir.glob("*.json"):
            if path.name.endswith("_final.json"):
                continue
            try:
                snapshot = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(snapshot, dict):
                continue
            name = str(snapshot.get("func_name") or "")
            if not name:
                continue
            text = self._snapshot_contract_text(snapshot)
            self._add_api_from_semantic_text(semantics, name, text, "semantic_snapshot")
        return semantics

    def _semantics_from_function_names(self) -> LocalPatternSemantics:
        semantics = LocalPatternSemantics()
        for name in self.code_index.list_functions(limit=100000):
            self._add_api_by_name_heuristic(semantics, name, "name_heuristic")
        return semantics

    @staticmethod
    def _parse_jsonish(value: Any) -> Dict[str, Any]:
        if isinstance(value, dict):
            return value
        if not value:
            return {}
        try:
            parsed = json.loads(str(value))
        except json.JSONDecodeError:
            return {"text": str(value)}
        return parsed if isinstance(parsed, dict) else {"value": parsed}

    @staticmethod
    def _snapshot_contract_text(snapshot: Dict[str, Any]) -> str:
        fields = [
            snapshot.get("summary"),
            snapshot.get("role"),
            snapshot.get("outputs"),
            snapshot.get("key_semantics"),
            snapshot.get("semantic_fingerprint"),
        ]
        if snapshot.get("snapshot_kind") == "lightweight":
            fields.extend([snapshot.get("resources"), snapshot.get("concurrency")])
        return " ".join(json.dumps(field, ensure_ascii=False) for field in fields if field).lower()

    @staticmethod
    def _add_api_by_name_heuristic(
        semantics: LocalPatternSemantics,
        name: str,
        source: str,
    ) -> None:
        category = RegexCandidateGenerator._classify_api_name(name)
        if category:
            semantics.add_api(category, name, source)

    def _add_api_from_semantic_text(
        self,
        semantics: LocalPatternSemantics,
        name: str,
        text: str,
        source: str,
    ) -> None:
        if not name:
            return
        if source == "semantic_snapshot":
            # Snapshot text describes a function's internal behavior.  Generic
            # fields such as "locks", "release_line", or cleanup notes must not
            # turn the described function itself into a lock/free/copy API.
            self._add_api_by_name_heuristic(semantics, name, source)
            return
        lower = text.lower()
        if "realloc" in lower or "閲嶆柊鍒嗛厤" in lower:
            semantics.add_api("reallocator", name, source)
        if any(word in lower for word in ("calloc", "zeroed allocation", "娓呴浂鍒嗛厤")):
            semantics.add_api("calloc", name, source)
        if any(word in lower for word in ("allocate", "allocates", "allocation", "returns allocated", "鍒嗛厤", "鐢宠鍐呭瓨")):
            semantics.add_api("allocator", name, source)
        if any(word in lower for word in ("free", "deallocate", "release memory", "閲婃斁", "閲婃斁鍐呭瓨")):
            semantics.add_api("deallocator", name, source)
        if any(word in lower for word in ("copy", "memcpy", "memmove", "buffer_bounds", "鎷疯礉", "澶嶅埗")):
            semantics.add_api("copy", name, source)
        if any(word in lower for word in ("acquire lock", "lock acquisition", "locks", "lock acquire")):
            semantics.add_api("lock", name, source)
        if any(word in lower for word in ("unlock", "release lock", "lock release")):
            semantics.add_api("unlock", name, source)
        self._add_api_by_name_heuristic(semantics, name, source)

    @staticmethod
    def _class_from_backend_bug(bug_type: str) -> str:
        text = bug_type.replace("_", " ").replace("-", " ").lower()
        if any(word in text for word in ("double", "dfree")):
            return "double_free"
        if any(word in text for word in ("uaf", "use after", "dangling")):
            return "use_after_free"
        if "leak" in text:
            return "memory_leak"
        if any(word in text for word in ("overflow", "bounds", "oob")):
            return "bounds"
        if "race" in text:
            return "race"
        return "backend_signal"

    @staticmethod
    def _class_from_joern_category(category: str) -> str:
        text = category.replace("_", " ").replace("-", " ").lower()
        if any(word in text for word in ("double", "dfree")):
            return "double_free"
        if any(word in text for word in ("uaf", "use after", "dangling")):
            return "use_after_free"
        if any(word in text for word in ("null", "deref")):
            return "null_pointer_dereference"
        if any(word in text for word in ("path traversal", "directory traversal")):
            return "path_traversal"
        if any(word in text for word in ("integer", "divide", "division", "modulo", "shift", "wrap", "trunc")):
            return "integer_overflow"
        if any(word in text for word in ("leak", "resource", "alloc", "memory")):
            return "memory_leak"
        if any(word in text for word in ("bounds", "overflow", "buffer", "oob")):
            return "bounds"
        if any(word in text for word in ("format", "printf")):
            return "format_string"
        if any(word in text for word in ("command", "system", "shell")):
            return "command_injection"
        if any(word in text for word in ("lock", "deadlock", "mutex")):
            return "deadlock"
        if any(word in text for word in ("race", "concurrency")):
            return "race"
        return "backend_signal"

    def _get_knowledge_db(self) -> Optional[Any]:
        backend = getattr(self.code_index, "_backend", None)
        if backend is None:
            return None
        db = getattr(backend, "db", None)
        if db is not None:
            return db
        return getattr(backend, "_db", None)

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
        new_issues = state.get("pending_new_issues", [])
        if not new_issues:
            return
        deduped_issues = self._deduplicate_candidate_issues(new_issues)
        if len(deduped_issues) != len(new_issues):
            logger.info(
                "Merged %d duplicate candidate issue(s) before validation.",
                len(new_issues) - len(deduped_issues),
            )
            state["notes"].append(
                f"Merged {len(new_issues) - len(deduped_issues)} duplicate candidate issue(s) before validation."
            )
        new_issues = deduped_issues

        validator_enabled = any(
            a.name == "validator_agent" and a.enabled
            for a in self.config.project.agents
        )
        if not validator_enabled:
            logger.info("Validator agent disabled, marking %d issue(s) unvalidated.", len(new_issues))
            for raw_issue in new_issues:
                issue_func = raw_issue.get("function", state["agent_context"]["func_name"])
                suppression_category = str(
                    raw_issue.get("defect_class")
                    or raw_issue.get("subcategory")
                    or raw_issue.get("category")
                    or ""
                )
                if self.user_config.is_false_positive(
                    str(issue_func),
                    str(raw_issue.get("location") or ""),
                    suppression_category,
                ):
                    raw_issue["validation_status"] = "rejected"
                    raw_issue["finding_kind"] = "suppressed_false_positive"
                    raw_issue["rejection_source"] = "user_config"
                    continue
                baseline = self.user_config.get_finding_baseline(
                    str(raw_issue.get("dedup_key") or self._canonical_issue_key(raw_issue))
                )
                if baseline and str(baseline.get("status") or "").lower() in {
                    "false_positive",
                    "rejected",
                    "suppressed",
                }:
                    raw_issue["validation_status"] = "rejected"
                    raw_issue["finding_kind"] = "suppressed_baseline"
                    raw_issue["rejection_source"] = "finding_baseline"
                    continue
                raw_issue["validation_status"] = "unvalidated"
                raw_issue.setdefault("finding_kind", "unvalidated_candidate")
                score_data = self._score_components(raw_issue, {})
                raw_issue["score_components"] = score_data
                raw_issue["final_score"] = score_data["final_score"]
                state["issues"].append(raw_issue)
            state["pending_new_issues"] = []
            return

        val_agent_cfg = next((a for a in self.config.project.agents if a.name == "validator_agent"), None)
        val_llm_ref = val_agent_cfg.llm_ref if val_agent_cfg and val_agent_cfg.llm_ref else "default"
        val_client = self.llm_clients.get(val_llm_ref, self.llm_clients["default"])
        validator_agent = ValidatorAgent(val_client, self._get_tools("validator_agent"))

        for raw_issue in new_issues:
            issue_func = raw_issue.get("function", state["agent_context"]["func_name"])
            logger.info("Validating issue: %s in %s", raw_issue.get("id", "unknown"), issue_func)
            suppression_category = str(
                raw_issue.get("defect_class")
                or raw_issue.get("subcategory")
                or raw_issue.get("category")
                or ""
            )
            if self.user_config.is_false_positive(
                str(issue_func),
                str(raw_issue.get("location") or ""),
                suppression_category,
            ):
                raw_issue["validation_status"] = "rejected"
                raw_issue["finding_kind"] = "suppressed_false_positive"
                raw_issue["rejection_source"] = "user_config"
                logger.info("Issue %s suppressed by user configuration.", raw_issue.get("id"))
                continue
            baseline = self.user_config.get_finding_baseline(
                str(raw_issue.get("dedup_key") or self._canonical_issue_key(raw_issue))
            )
            if baseline and str(baseline.get("status") or "").lower() in {
                "false_positive",
                "rejected",
                "suppressed",
            }:
                raw_issue["validation_status"] = "rejected"
                raw_issue["finding_kind"] = "suppressed_baseline"
                raw_issue["rejection_source"] = "finding_baseline"
                logger.info("Issue %s suppressed by finding baseline.", raw_issue.get("id"))
                continue

            issue_code = state["agent_context"]["code"]
            if issue_func != state["agent_context"]["func_name"]:
                impl = self.code_index.get_function_impl(issue_func)
                if impl:
                    issue_code = impl["code"]

            val_input = {
                "finding": json.dumps(raw_issue, indent=2, ensure_ascii=False),
                "context_code": issue_code,
                "evidence_pack": self._build_validation_evidence_pack(
                    raw_issue,
                    state,
                    issue_code,
                ),
            }
            self._attach_agent_contract(val_input, "validator_agent")
            val_resp = validator_agent.run(val_input)

            if val_resp.success:
                val_data = val_resp.data
                verdict = self._validation_verdict(val_data)
                score_data = self._score_components(raw_issue, val_data)
                raw_issue["score_components"] = score_data
                raw_issue["final_score"] = score_data["final_score"]
                raw_issue["validator_verdict"] = verdict
                if verdict == "verified" and raw_issue["final_score"] >= 0.6:
                    if raw_issue["final_score"] >= 0.8:
                        raw_issue["validation_status"] = "validated"
                        raw_issue["finding_kind"] = val_data.get("finding_kind") or "verified_vulnerability"
                        report_issue = True
                    else:
                        raw_issue["validation_status"] = "needs_review"
                        raw_issue["finding_kind"] = "needs_review"
                        report_issue = False
                    raw_issue["validation_reasoning"] = val_data.get("reasoning")
                    raw_issue["confidence"] = val_data.get(
                        "confidence_score",
                        raw_issue.get("confidence", 0.5),
                    )
                    for field in (
                        "exploit_scenario",
                        "source",
                        "sink",
                        "control_of_source",
                        "guard_analysis",
                        "positive_evidence",
                        "negative_evidence",
                    ):
                        if field in val_data and val_data.get(field) not in (None, ""):
                            raw_issue[field] = val_data.get(field)
                    logger.info(
                        "Issue %s VALIDATED with confidence %s",
                        raw_issue.get("id"),
                        raw_issue["confidence"],
                    )
                    if report_issue:
                        state["issues"].append(raw_issue)
                    else:
                        state["observations"].append(raw_issue)
                    self._remember_validation_result(raw_issue, raw_issue["validation_status"])
                elif verdict == "verified":
                    raw_issue["validation_status"] = "uncertain"
                    raw_issue["finding_kind"] = "audit_observation"
                    raw_issue["validation_reasoning"] = val_data.get("reasoning")
                    state["observations"].append(raw_issue)
                    self._remember_validation_result(raw_issue, "uncertain")
                    logger.info(
                        "Issue %s verified by validator but final_score %.2f is below report threshold.",
                        raw_issue.get("id"),
                        raw_issue["final_score"],
                    )
                elif verdict == "uncertain":
                    raw_issue["validation_status"] = "uncertain"
                    raw_issue["finding_kind"] = val_data.get("finding_kind") or "audit_observation"
                    raw_issue["validation_reasoning"] = val_data.get("reasoning")
                    state["observations"].append(raw_issue)
                    self._remember_validation_result(raw_issue, "uncertain")
                    logger.info(
                        "Issue %s marked UNCERTAIN by Validator; kept as observation.",
                        raw_issue.get("id"),
                    )
                else:
                    raw_issue["validation_status"] = "rejected"
                    raw_issue["finding_kind"] = "rejected"
                    raw_issue["rejection_source"] = "validator"
                    raw_issue["validation_reasoning"] = val_data.get("reasoning")
                    self._remember_validation_result(raw_issue, "rejected")
                    logger.info("Issue %s REJECTED by Validator, discarding.", raw_issue.get("id"))
            else:
                logger.warning(
                    "Validation failed for issue %s in function %s: %s",
                    raw_issue.get("id"),
                    issue_func,
                    val_resp.error,
                )
                raw_issue["validation_status"] = "pending"
                raw_issue.setdefault("finding_kind", "validation_pending")
                raw_issue["validation_error"] = val_resp.error
                state["observations"].append(raw_issue)

        state["pending_new_issues"] = []

    def _remember_validation_result(self, issue: Dict[str, Any], status: str) -> None:
        """Persist validator disposition as review memory for later scans."""
        dedup_key = str(issue.get("dedup_key") or self._canonical_issue_key(issue))
        if not dedup_key:
            return
        memory_status = {
            "validated": "verified",
            "needs_review": "uncertain",
            "uncertain": "uncertain",
            "rejected": "rejected",
        }.get(str(status or "").lower(), str(status or "unknown").lower())
        try:
            self.user_config.upsert_finding_baseline(dedup_key, memory_status, issue)
        except Exception as exc:
            logger.debug("Failed to persist validation memory for %s: %s", issue.get("id"), exc)

    def _enrich_auto_accepted_reasoning(
        self,
        issue: Dict[str, Any],
        state: Dict[str, Any],
        issue_code: str,
        validator_agent: ValidatorAgent,
    ) -> None:
        """Legacy hook for old auto-accepted candidates; no current candidate uses it."""
        fallback_reasoning = str(
            issue.get("reasoning")
            or "本地候选证据完整且置信度较高；详细证据见 positive_evidence 和 evidence_pack。"
        ).strip()

        evidence_pack = self._build_validation_evidence_pack(issue, state, issue_code)
        evidence_pack["mode"] = "legacy_auto_accept_reasoning"
        requirements = list(evidence_pack.get("validation_requirements") or [])
        requirements.extend(
            [
                "This finding has already passed a legacy auto-acceptance path; use the evidence to write a human-readable Chinese audit reasoning.",
                "reasoning 必须使用中文，并说明触发路径、输入来源、危险操作、缺失保护以及为什么该问题可达。",
                "Do not output a generic rule-candidate placeholder as reasoning.",
            ]
        )
        evidence_pack["validation_requirements"] = requirements

        val_input = {
            "finding": json.dumps(issue, indent=2, ensure_ascii=False),
            "context_code": issue_code,
            "evidence_pack": evidence_pack,
        }
        try:
            self._attach_agent_contract(val_input, "validator_agent")
            val_resp = validator_agent.run(val_input)
        except Exception as exc:
            issue.setdefault("reasoning", fallback_reasoning)
            issue.setdefault("validation_reasoning", fallback_reasoning)
            issue["reasoning_source"] = "local_rule_fallback"
            issue["llm_reasoning_error"] = str(exc)
            logger.warning(
                "LLM reasoning enrichment failed for auto-accepted issue %s: %s",
                issue.get("id"),
                exc,
            )
            return

        if not val_resp.success:
            issue.setdefault("reasoning", fallback_reasoning)
            issue.setdefault("validation_reasoning", fallback_reasoning)
            issue["reasoning_source"] = "local_rule_fallback"
            issue["llm_reasoning_error"] = val_resp.error
            return

        val_data = val_resp.data or {}
        llm_reasoning = str(val_data.get("reasoning") or "").strip()
        verdict = self._validation_verdict(val_data)
        if llm_reasoning:
            issue["llm_reasoning"] = llm_reasoning
            issue["llm_reasoning_verdict"] = verdict

        if llm_reasoning and verdict == "verified":
            issue["reasoning"] = llm_reasoning
            issue["validation_reasoning"] = llm_reasoning
            issue["reasoning_source"] = "validator_agent_llm"
            for field in (
                "exploit_scenario",
                "source",
                "sink",
                "control_of_source",
                "guard_analysis",
                "positive_evidence",
                "negative_evidence",
            ):
                if field in val_data and val_data.get(field) not in (None, ""):
                    issue[field] = val_data.get(field)
            return

        issue.setdefault("reasoning", fallback_reasoning)
        issue.setdefault("validation_reasoning", fallback_reasoning)
        issue["reasoning_source"] = "local_rule_fallback"
        if llm_reasoning:
            issue["validation_reasoning"] = (
                f"{fallback_reasoning}\n\nLLM 审计补充（未作为自动确认结论采纳，verdict={verdict}）：{llm_reasoning}"
            )

    def _should_auto_accept_candidate(self, issue: Dict[str, Any]) -> bool:
        """Legacy compatibility hook; candidates are never final without validation."""
        return False

    def _score_components(self, issue: Dict[str, Any], val_data: Dict[str, Any]) -> Dict[str, float]:
        rule_confidence = self._coerce_score(
            issue.get("rule_confidence", issue.get("confidence", 0.5)),
            default=0.5,
        )
        path_completeness = self._path_completeness_score(issue, val_data)
        contract_consistency = self._contract_consistency_score(issue, val_data)
        validation_confidence = self._coerce_score(
            val_data.get("confidence_score", issue.get("confidence", 0.5)),
            default=0.5,
        )
        history_feedback = self._history_feedback_score(issue)
        final_score = (
            0.25 * rule_confidence
            + 0.25 * path_completeness
            + 0.20 * contract_consistency
            + 0.20 * validation_confidence
            + 0.10 * history_feedback
        )
        return {
            "rule_confidence": round(rule_confidence, 4),
            "path_completeness": round(path_completeness, 4),
            "contract_consistency": round(contract_consistency, 4),
            "validation_confidence": round(validation_confidence, 4),
            "history_feedback": round(history_feedback, 4),
            "final_score": round(final_score, 4),
        }

    @staticmethod
    def _coerce_score(value: Any, default: float = 0.5) -> float:
        try:
            score = float(value)
        except (TypeError, ValueError):
            score = default
        return max(0.0, min(1.0, score))

    def _path_completeness_score(
        self,
        issue: Dict[str, Any],
        val_data: Optional[Dict[str, Any]] = None,
    ) -> float:
        val_data = val_data or {}
        evidence = issue.get("evidence_pack") if isinstance(issue.get("evidence_pack"), dict) else {}
        path = evidence.get("path") if isinstance(evidence.get("path"), dict) else {}
        if path.get("complete") is True or path.get("complete_in_function") is True:
            return 1.0
        if (issue.get("source") or val_data.get("source")) and (issue.get("sink") or val_data.get("sink")):
            return 0.75
        if issue.get("evidence_refs"):
            return 0.7
        return 0.5

    def _contract_consistency_score(self, issue: Dict[str, Any], val_data: Dict[str, Any]) -> float:
        negative = issue.get("negative_evidence") or val_data.get("negative_evidence") or []
        if negative:
            return 0.55
        if (issue.get("source") or val_data.get("source")) and (issue.get("sink") or val_data.get("sink")):
            return 0.8
        if issue.get("finding_kind") == "backend_signal":
            return 0.7
        return 0.6

    def _history_feedback_score(self, issue: Dict[str, Any]) -> float:
        dedup_key = str(issue.get("dedup_key") or self._canonical_issue_key(issue))
        try:
            baseline = self.user_config.get_finding_baseline(dedup_key)
        except Exception:
            baseline = None
        if not baseline:
            return 0.5
        status = str(baseline.get("status") or "").lower()
        if status in {"accepted", "verified", "true_positive"}:
            return 1.0
        if status in {"false_positive", "rejected", "suppressed"}:
            return 0.0
        return 0.5

    @staticmethod
    def _validation_verdict(val_data: Dict[str, Any]) -> str:
        """Normalize old boolean validator output and new tri-state verdicts."""
        verdict = str(val_data.get("verdict") or "").strip().lower()
        aliases = {
            "valid": "verified",
            "true": "verified",
            "confirmed": "verified",
            "invalid": "rejected",
            "false": "rejected",
            "reject": "rejected",
            "needs_review": "uncertain",
            "unknown": "uncertain",
        }
        if not verdict and "is_valid" in val_data:
            return "verified" if bool(val_data.get("is_valid")) else "rejected"
        verdict = aliases.get(verdict, verdict)
        if verdict in {"verified", "rejected", "uncertain"}:
            return verdict
        return "rejected"

    def _deduplicate_candidate_issues(
        self, issues: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Merge candidate findings that point at the same root-cause sink."""
        return deduplicate_issues(issues)

    def _build_validation_evidence_pack(
        self,
        issue: Dict[str, Any],
        state: Dict[str, Any],
        issue_code: str,
    ) -> Dict[str, Any]:
        """Build compact candidate evidence so the validator starts from facts."""
        issue_func = str(issue.get("function") or state["agent_context"]["func_name"])
        location = str(issue.get("location") or "")
        file_path, line = self._parse_issue_location(location)
        snippet = None
        if file_path and line:
            snippet = self.code_index.get_file_snippet(
                file_path,
                max(1, line - 12),
                line + 12,
            )

        snapshot = self.snapshot_store.load_snapshot(issue_func)
        try:
            callers = self.code_index.get_callers(issue_func, limit=8)
        except Exception:
            callers = []
        try:
            callees = self.code_index.get_callees(issue_func, limit=12)
        except Exception:
            callees = []

        candidate_evidence = issue.get("evidence_pack") if isinstance(issue.get("evidence_pack"), dict) else {}
        return {
            "mode": "tri_state_exploitability_validation",
            "dedup_key": issue.get("dedup_key") or self._canonical_issue_key(issue),
            "candidate_id": issue.get("candidate_id") or issue.get("id"),
            "candidate_role": issue.get("candidate_role") or "evidence_only",
            "candidate_is_conclusion": False,
            "validation_required": True,
            "backend_profile": issue.get("backend_profile") or candidate_evidence.get("backend_profile"),
            "evidence_checker": issue.get("evidence_checker") or candidate_evidence.get("checker"),
            "evidence_engines": issue.get("evidence_engines") or candidate_evidence.get("evidence_engines") or [],
            "semantic_overlays": issue.get("semantic_overlays") or candidate_evidence.get("semantic_overlays") or {},
            "semantic_overlay_evidence": issue.get("semantic_overlay_evidence") or candidate_evidence.get("semantic_overlay_evidence") or {},
            "finding_kind": issue.get("finding_kind"),
            "defect_class": issue.get("defect_class") or issue.get("subcategory"),
            "rule_confidence": issue.get("rule_confidence"),
            "score_components": issue.get("score_components") or self._score_components(issue, {}),
            "evidence_refs": issue.get("evidence_refs") or candidate_evidence.get("evidence_refs") or [],
            "finding_summary": {
                "id": issue.get("id"),
                "function": issue_func,
                "location": location,
                "category": issue.get("category"),
                "subcategory": issue.get("subcategory"),
                "confidence": issue.get("confidence"),
                "description": issue.get("description"),
                "source": issue.get("source"),
                "sink": issue.get("sink"),
                "cwe": issue.get("cwe"),
            },
            "candidate_evidence": candidate_evidence,
            "positive_evidence": issue.get("positive_evidence") or candidate_evidence.get("positive_evidence") or [],
            "negative_evidence": issue.get("negative_evidence") or candidate_evidence.get("negative_evidence") or [],
            "primary_location_snippet": snippet,
            "function_context": {
                "code": self._trim_code(issue_code, max_lines=140),
                "snapshot_summary": self._compact_snapshot(snapshot),
                "callers": callers,
                "callees": callees,
            },
            "validation_requirements": [
                "Treat every candidate as evidence only; do not accept it solely because a regex, graph, or backend rule emitted it.",
                "Independently audit semantic overlay assumptions from user_config, including custom alloc/free/lock/macros and pointer target models.",
                "Return verdict=verified only if there is a concrete public/API or caller-controlled trigger path.",
                "Return verdict=rejected when local evidence or guards disprove the candidate.",
                "Return verdict=uncertain only when the candidate is plausible but decisive context is missing.",
                "Identify source, sink, source controllability, and the missing/insufficient guard.",
                "Reject hardening/style/theoretical findings without a source-to-sink path.",
                "For integer overflow, multiplication/addition must be checked before the operation or by a proven bounded operand.",
            ],
        }

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
        lines = str(code or "").splitlines()
        if len(lines) <= max_lines:
            return code
        head = max_lines // 2
        tail = max_lines - head
        return "\n".join(lines[:head] + ["/* ... trimmed for validator evidence pack ... */"] + lines[-tail:])

    @staticmethod
    def _compact_snapshot(snapshot: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not isinstance(snapshot, dict):
            return None
        return {
            "summary": snapshot.get("summary"),
            "resources": snapshot.get("resources"),
            "error_handling": snapshot.get("error_handling"),
            "concurrency": snapshot.get("concurrency"),
            "suspicious_points": snapshot.get("suspicious_points"),
            "semantic_fingerprint": snapshot.get("semantic_fingerprint"),
        }

    def _build_final_report(self, state: Dict[str, Any]) -> None:
        all_issues = state.get("issues", []) + state.get("verified_hist_issues", [])
        self._resolve_issue_locations(all_issues)
        observations = state.get("observations", [])
        self._resolve_issue_locations(observations)
        if observations:
            state["observations"] = self._deduplicate_candidate_issues(observations)
        if state.get("observations"):
            state["notes"].append(
                f"Validator kept {len(state.get('observations', []))} uncertain candidate(s) "
                "as audit observations; they are excluded from the default vulnerability report."
            )

        if state.get("any_failure") and not all_issues:
            verdict = "error"
            state["notes"].append(
                f"Analysis incomplete due to agent failure: {state.get('failure_msg', '')}"
            )
        else:
            verdict = "issues_found" if all_issues else "no_issue_found"

        final_report = FinalReport(
            entry_function=state["entry_func"],
            overall_verdict=verdict,
            issues=[
                Issue.from_dict(i, context_function=state["entry_func"], issue_index=idx + 1)
                for idx, i in enumerate(all_issues)
                if isinstance(i, dict)
            ] or [i for i in all_issues if isinstance(i, Issue)],
            notes=state["notes"],
        )
        final_report.report_views = build_report_views(
            all_issues,
            state.get("observations", []),
        )
        final_report.metadata = self._build_workflow_metadata(state)
        final_report.metadata["report_view_summary"] = report_view_summary(final_report.to_dict())
        state["final_report"] = final_report

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
            "workflow": self.workflow_spec.name if self.workflow_spec else self.config.analysis.workflow_name,
            "workflow_mode": self.workflow_spec.mode if self.workflow_spec else self.config.analysis.workflow_name,
            "workflow_progress": list(self.workflow_progress),
            "current_workflow_step": self.workflow_executor.current_step,
            "subagent_candidate_count": len(state.get("subagent_candidates", [])),
            "subagent_ticket_count": len(state.get("subagent_ticket_plan", [])),
            "subagent_unassigned_count": len(state.get("subagent_unassigned_candidates", [])),
            "subagent_reports_count": len(state.get("subagent_reports", [])),
            "subagent_report_summary": dict(state.get("subagent_report_summary", {})),
            "candidate_ledger_summary": dict(state.get("candidate_ledger_summary", {})),
            "candidate_signal_summary": dict(state.get("candidate_signal_summary", {})),
            "budget_stage": state.get("budget_stage", ""),
            "budget_hard_caps": dict(state.get("budget_hard_caps", {})),
            "effective_budget": dict(state.get("effective_budget", {})),
            "budget_scores": dict(state.get("budget_scores", {})),
            "budget_reasons": dict(state.get("budget_reasons", {})),
            "audit_observation_count": len(state.get("observations", [])),
            "audit_observations": list(state.get("observations", [])),
        }

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
        final_report = state["final_report"]
        final_report.metadata = self._build_workflow_metadata(state)
        if not final_report.report_views:
            final_report.report_views = build_report_views(
                state.get("issues", []) + state.get("verified_hist_issues", []),
                state.get("observations", []),
            )
        final_report.metadata["report_view_summary"] = report_view_summary(final_report.to_dict())
        self.report_generator.save_json_report(final_report)
        self.report_generator.save_markdown_report(final_report)

        report_dict = cast(Dict[str, Any], final_report.to_dict())
        if self.snapshot_store:
            self.snapshot_store.save_final_report(
                state["entry_func"],
                report_dict,
                state["agent_context"]["location"],
            )
        return report_dict

    def _finalize_returned_report(self, state: Dict[str, Any]) -> Dict[str, Any]:
        report_dict = dict(state["final_report_dict"])
        metadata = dict(report_dict.get("metadata") or {})
        metadata.update(self._build_workflow_metadata(state))
        report_dict["metadata"] = metadata
        return report_dict

    def _attach_agent_contract(
        self,
        context: Dict[str, Any],
        agent_name: str,
        extra_skills: Optional[List[str]] = None,
        active_skill_names: Optional[List[str]] = None,
    ) -> None:
        """Attach agent/skill contracts to a single agent invocation."""
        agent_spec = self.spec_registry.get_agent(agent_name)
        if agent_spec:
            context["agent_contract"] = agent_spec.to_prompt_block(active_skills=active_skill_names)
        else:
            context.pop("agent_contract", None)

        skills = self.spec_registry.skills_for_agent(
            agent_name,
            extra=extra_skills,
            only=active_skill_names,
        )
        if skills:
            context["skill_contracts"] = "\n\n".join(skill.to_prompt_block() for skill in skills)
        else:
            context.pop("skill_contracts", None)

    def _agent_system_prompt(
        self,
        agent_name: str,
        *,
        active_skill_names: Optional[List[str]] = None,
        substitutions: Optional[Dict[str, Any]] = None,
    ) -> str:
        agent_spec = self.spec_registry.get_agent(agent_name)
        prompt = (
            agent_spec.to_prompt_block(active_skills=active_skill_names)
            if agent_spec
            else agent_name
        )
        for key, value in (substitutions or {}).items():
            prompt = prompt.replace("{" + key + "}", str(value))
        return prompt

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
        """Ask the analyzer model for a tiny structured skill-routing decision."""

        available = list(dict.fromkeys(available_skill_names))
        cache_key = json.dumps(
            {
                "task": task,
                "available": available,
                "models": getattr(llm_client, "models", []),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
        if cache_key in self._skill_selection_cache:
            cached = self._skill_selection_cache[cache_key]
            return {
                "skills": cached.skills,
                "restricted": cached.restricted,
                "confidence": cached.confidence,
                "reasons": cached.reasons,
            }

        skill_descriptions = {
            "resource_lifecycle": "allocation, ownership, cleanup, leaks, missing release",
            "bounds_and_integer": "buffer bounds, length validation, integer overflow/truncation",
            "null_and_failure": "null dereference, unchecked return, failure/error paths",
            "temporal_memory": "use-after-free, double free, invalid free, stale pointer",
            "concurrency_lock_order": "deadlock, lock balance, lock-order problems",
            "shared_state_race": "data race, TOCTOU, shared mutable state",
            "stack_escape": "stack address escaping, async lifetime of locals",
            "ownership_contract": "API ownership contracts, caller/callee responsibility",
            "string_and_format": "format strings, string termination, printf-like misuse",
        }
        catalog = {name: skill_descriptions.get(name, name) for name in available}
        messages = [
            {
                "role": "system",
                "content": (
                    "Classify a vulnerability-analysis task into the provided skill names. "
                    "Return only JSON with keys: skills (array), restricted (boolean), "
                    "confidence (0..1), reasons (array of short strings). "
                    "Use restricted=false when the task is broad, ambiguous, or asks for a general audit. "
                    "Prefer widening over missing a relevant vulnerability family."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "task": task,
                        "available_skills": catalog,
                    },
                    ensure_ascii=False,
                ),
            },
        ]
        response = llm_client.chat_completion(
            messages,
            temperature=0.0,
            max_tokens=300,
            trace_agent="skill_selection",
            trace_label=str(task)[:120],
        )
        content = str(
            ((response.get("choices") or [{}])[0].get("message") or {}).get("content")
            or ""
        )
        blocks = extract_json_blocks(content)
        parsed = blocks[0] if blocks else json.loads(content)
        if not isinstance(parsed, dict):
            raise ValueError("skill router returned non-object JSON")

        try:
            confidence = float(parsed.get("confidence") or 0.0)
        except (TypeError, ValueError):
            confidence = 0.0
        selection = SkillSelection(
            skills=[name for name in available if name in {str(item) for item in parsed.get("skills", [])}],
            restricted=bool(parsed.get("restricted")),
            source="semantic_cache",
            confidence=max(0.0, min(1.0, confidence)),
            reasons=[str(item) for item in parsed.get("reasons", [])]
            if isinstance(parsed.get("reasons"), list)
            else [],
        )
        self._skill_selection_cache[cache_key] = selection
        return parsed

    def _should_spawn_subagents(self, agent_cfg: Any) -> bool:
        """Decide whether focused deep-worker LLM calls are enabled for this run."""
        if not self.config.analysis.enable_subagent_workers:
            return False
        explicit = getattr(agent_cfg, "can_spawn_subagents", None)
        if explicit is not None:
            return bool(explicit)
        agent_spec = self.spec_registry.get_agent("vulnerability_analyzer")
        return bool(agent_spec and agent_spec.can_spawn_subagents)

    def _get_tools(
        self,
        agent_name: Optional[str] = None,
        *,
        enable_on_demand_snapshots: bool = True,
    ) -> List[Any]:
        """Initialize and return the set of tools."""
        from ..tools.code_retrieval import GetFunctionImplTool
        from ..tools.snapshot_tool import GetFunctionSnapshotTool
        from ..tools.utils import (
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

        return tools

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

        status = self.snapshot_store.lock_manager.acquire(func_name, timeout=120.0)
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
        """Create a persisted syntactic snapshot for a short function."""
        return {
            "type": "function_snapshot",
            "func_name": func_name,
            "location": location,
            "file_path": impl.get("file"),
            "start_line": impl.get("start_line"),
            "end_line": impl.get("end_line"),
            "signature": impl.get("signature"),
            "summary": "Short function stored verbatim without LLM semantic modeling.",
            "snapshot_kind": "syntactic",
            "is_trivial": True,
            "code": impl.get("code", ""),
            "inputs": [],
            "outputs": [],
            "resources": {},
            "error_handling": {},
            "concurrency": {},
            "semantic_fingerprint": {
                "key_semantics": ["short function source is embedded in snapshot"]
            },
            "suspicious_points": [],
            "callees": impl.get("callees", []),
        }

    @staticmethod
    def _is_lightweight_snapshot_candidate(func_name: str, impl: Dict[str, Any]) -> bool:
        """Return true for macros/wrappers that can be summarized without an LLM call."""
        if impl.get("is_macro"):
            if LIGHTWEIGHT_MACRO_RE.match(func_name):
                return True
            code = str(impl.get("code") or "")
            return bool(
                re.search(r"#\s*define\s+\w+\s+\(?[0-9A-Za-z_+\-*/<>=&| ]+\)?\s*$", code)
                and len(code.splitlines()) <= 3
            )
        if LIGHTWEIGHT_WRAPPER_RE.match(func_name):
            return True
        return False

    @staticmethod
    def _build_lightweight_snapshot(
        func_name: str, impl: Dict[str, Any], location: str
    ) -> Dict[str, Any]:
        """Create a lightweight static snapshot for common macros and tiny wrapper APIs."""
        code = str(impl.get("code") or "")
        upper = func_name.upper()
        key_semantics: List[str] = ["lightweight static snapshot; no LLM call"]
        resources: Dict[str, Any] = {}
        concurrency: Dict[str, Any] = {}
        error_handling: Dict[str, Any] = {}
        summary = "Lightweight macro/wrapper summarized without LLM semantic modeling."

        if upper.startswith("LOG_") or func_name == "_log_wrapper":
            summary = (
                "Logging helper. Validate format-string safety at the call site where "
                "the format argument is chosen; this helper alone is not a vulnerability."
            )
            key_semantics.append("logging side effect")
        elif upper.startswith("LOCK") or upper == "UNLOCK" or "lock" in func_name:
            summary = (
                "Locking helper. Treat calls as acquiring or releasing the referenced "
                "mutex/rwlock at the call site; inspect caller ordering for deadlocks."
            )
            concurrency = {"lock_effect": "call-site lock/unlock wrapper"}
            key_semantics.append("synchronization wrapper")
        elif upper in {"MIN", "MAX", "CLAMP", "ARRAY_SIZE", "OFFSET_OF"}:
            summary = "Pure expression macro. Analyze bounds at the caller expression."
            key_semantics.append("pure expression macro")
        elif upper.startswith(("RETURN_IF_", "GOTO_IF_")):
            summary = "Guard/control-flow macro. Analyze the caller's guarded path."
            error_handling = {"control_flow": "guard macro expands to return/goto"}
            key_semantics.append("guard macro")

        return {
            "type": "function_snapshot",
            "func_name": func_name,
            "location": location,
            "file_path": impl.get("file"),
            "start_line": impl.get("start_line"),
            "end_line": impl.get("end_line"),
            "signature": impl.get("signature"),
            "summary": summary,
            "snapshot_kind": "lightweight",
            "is_trivial": True,
            "is_macro": bool(impl.get("is_macro")),
            "code": code,
            "inputs": [],
            "outputs": [],
            "resources": resources,
            "error_handling": error_handling,
            "concurrency": concurrency,
            "semantic_fingerprint": {"key_semantics": key_semantics},
            "suspicious_points": [],
            "callees": impl.get("callees", []),
        }

    def _premodel_callees(self, entry_func: str, sm_client: 'LLMClient',
                          max_depth: int = 3, max_callees: int = 20) -> tuple[int, int, int]:
        """
        Recursively pre-model reachable callees for an entry function.
        Returns:
            (modeled_count, skipped_count, total_context_tokens)
        """
        # 1. BFS 鏀堕泦鍙揪 callee 鍥?
        callee_graph: Dict[str, List[str]] = {}
        visited: Set[str] = set()
        queue: list = [(entry_func, 0)]
        impl_cache: Dict[str, Any] = {}  # 缂撳瓨 get_function_impl 缁撴灉

        while queue:
            func, depth = queue.pop(0)
            if func in visited or depth > max_depth:
                continue
            visited.add(func)

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
            for c in callee_names:
                if c in visited:
                    continue
                try:
                    impl = self.code_index.get_function_impl(c, warn_missing=False)
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
                    if not self._is_lightweight_snapshot_candidate(c, impl):
                        queue.append((c, depth + 1))
                else:
                    logger.debug("[premodel] Skipping unresolved callee '%s'", c)

            callee_graph[func] = resolvable

        # 2. 閫嗘嫇鎵戞帓搴忥細鍙跺瓙鍑芥暟浼樺厛
        order = self._topo_sort(callee_graph, entry_func)
        # 杩囨护鎺夊叆鍙ｅ嚱鏁版湰韬紙鐢变富娴佺▼寤烘ā锛?
        order = [f for f in order if f != entry_func]

        if not order:
            return 0, 0, 0

        logger.info(f"[premodel] {len(order)} reachable callees to pre-model for '{entry_func}'")

        # 3. 閫愪釜寤烘ā
        semantic_agent = SemanticModeler(
            sm_client,
            self._get_tools("semantic_modeler", enable_on_demand_snapshots=False),
        )
        modeled = 0
        skipped = 0
        total_tokens = 0

        for func in order:
            # 蹇€熸鏌ワ細宸叉湁蹇収鍒欒烦杩?
            existing = self.snapshot_store.load_snapshot(func)
            if existing is not None:
                skipped += 1
                continue

            # 璺ㄧ嚎绋嬮攣淇濇姢
            status = self.snapshot_store.lock_manager.acquire(func, timeout=120.0)
            if status == "done":
                skipped += 1
                continue
            if status == "timeout":
                logger.warning(f"[premodel] Timeout waiting for '{func}', skipping.")
                continue

            # status == "acquired"锛氱敱褰撳墠 Worker 寤烘ā
            try:
                impl = impl_cache.get(func) or self.code_index.get_function_impl(
                    func, warn_missing=False
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

                # 楂樻晥鎷︽埅锛氬钩鍑″嚱鏁颁笉闇€瑕佽澶фā鍨嬬湅
                if self._is_trivial_function(impl["code"], self.config.analysis.trivial_function_max_lines):
                    logger.info(f"[premodel] Auto-skipping trivial function '{func}'")
                    fake_snapshot = {
                        "type": "function_snapshot",
                        "func_name": func,
                        "location": location,
                        "summary": "[Auto-Skipped] Trivial Function (鏋佺畝鐩撮€氱粨鏋勶紝鏈皟鐢?LLM)",
                        "inputs": [],
                        "outputs": [],
                        "resources": {},
                        "error_handling": {},
                        "concurrency": {},
                        "semantic_fingerprint": {"key_semantics": ["trivial representation"]},
                        "suspicious_points": [],
                        "callees": impl.get("callees", []),
                        "is_trivial": True
                    }
                    fake_snapshot = self._build_trivial_snapshot(func, impl, location)
                    self.snapshot_store.save_snapshot(func, fake_snapshot, impl["code"], location)
                    self.snapshot_store.lock_manager.release(func, success=True)
                    modeled += 1
                    continue

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

        logger.info(f"[premodel] Done: {modeled} modeled, {skipped} reused from cache (ctx 鈮?{total_tokens:,} tokens)")
        return modeled, skipped, total_tokens

    @staticmethod
    def _is_trivial_function(code: str, max_lines_threshold: int) -> bool:
        """
        Decide whether a function is too simple for deep semantic modeling.
        """
        if max_lines_threshold <= 0:
            return False

        # 1. 绮楃暐娓呮礂娉ㄩ噴鍜屽乏渚ц鍙峰墠缂€
        import re
        lines = code.split("\n")
        clean_lines = []
        in_block_comment = False
        for line in lines:
            line = line.strip()
            # Remove line numbers inserted by `get_function_impl`: "123 | int foo() {" -> "int foo() {"
            line = re.sub(r"^\d+\s*\|\s*", "", line)
            if not line:
                continue

            if in_block_comment:
                if "*/" in line:
                    in_block_comment = False
                    line = line[line.find("*/") + 2:].strip()
                else:
                    continue

            if "/*" in line:
                if "*/" in line:
                    line = re.sub(r"/\*.*?\*/", "", line).strip()
                else:
                    in_block_comment = True
                    line = line[:line.find("/*")].strip()

            if "//" in line:
                line = line[:line.find("//")].strip()

            if line:
                clean_lines.append(line)

        # Count meaningful logic lines after comment and brace cleanup.
        logic_lines = [l for l in clean_lines if l not in ("{", "}")]
        # Let's say if signature is 1 line, body is N lines. We just check total clean logic lines.
        # usually 1 line signature + 1 line return + maybe brackets.
        if len(logic_lines) > max_lines_threshold + 1:  # +1 for signature roughly
            return False

        # Functions touching memory, IO, locks, or threads are not trivial.
        clean_code_body = " ".join(clean_lines).lower()
        risky_keywords = [
            r"malloc", r"calloc", r"realloc", r"free", r"alloc", r"new\s", r"delete\s",
            r"lock", r"mutex", r"mtx", r"cond", r"thread", r"spin", r"pthread",
            r"file", r"fopen", r"fclose", r"read", r"write", r"socket", r"send", r"recv", r"connect", r"open", r"close"
        ]
        
        for kw in risky_keywords:
            if re.search(kw, clean_code_body):
                return False

        return True

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
        prompt = f"""
Function '{func_name}' has changed.
Old Snapshot Summary: {old_snapshot.get('summary')}
Old Fingerprint: {old_snapshot.get('semantic_fingerprint')}

New Code:
```c
{new_code}
```

        Determine if the semantic contract/behavior relevant to defect attributes (resources, errors, concurrency) has changed.
Output a JSON of type 'snapshot_refresh_decision'.
"""
        messages = [
            {
                "role": "system",
                "content": self._agent_system_prompt(
                    "semantic_modeler",
                    substitutions={
                        "schema": json.dumps(
                            DEFAULT_FUNCTION_SNAPSHOT_SCHEMA,
                            indent=2,
                            ensure_ascii=False,
                        )
                    },
                ),
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
        from ..common.utils import extract_json_blocks
        
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

            raw_location = str(issue.get("location", ""))
            file_path, parsed_line = parse_issue_location(raw_location)
            if file_path and parsed_line:
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
            if len(nums) >= 2:
                line_suffix = f"{nums[0]}-{nums[1]}"
            elif len(nums) == 1:
                line_suffix = f"{nums[0]}"
            elif func_info and func_info.get("start_line"):
                line_suffix = str(func_info["start_line"])

            if not func_info:
                issue["location"] = f"unknown_file:{line_suffix}"
                continue

            relative_file = func_info["file"]
            issue["location"] = f"{relative_file}:{line_suffix}"




