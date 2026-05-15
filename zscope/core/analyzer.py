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
from .deterministic_candidates import DeterministicCandidateGenerator, DeterministicSemantics
from .graph_candidates import GraphCandidateGenerator
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
    r"SAFE_FREE|ARRAY_SIZE|OFFSET_OF|RETURN_IF_(?:NULL|ERR)|GOTO_IF_(?:NULL|ERR)|"
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
        self._deterministic_semantics: Optional[DeterministicSemantics] = None
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
                "Successfully modeled function: %s (ctx ≈ %s tokens)",
                state["entry_func"],
                f"{sm_tokens:,}",
            )
            state["notes"].append(f"Successfully modeled function: {state['entry_func']}")
        else:
            logger.warning("Semantic modeling failed: %s (ctx ≈ %s tokens)", response.error, f"{sm_tokens:,}")
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
        deterministic_tickets = self._detect_local_rule_tickets(state, selection.skills)
        for ticket in deterministic_tickets:
            record, _ = ledger.add(
                ticket,
                source=f"deterministic_rule:{state['entry_func']}",
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
            f"semantic snapshot candidate(s) and {len(deterministic_tickets)} "
            f"deterministic candidate(s), {len(graph_tickets)} graph/protocol "
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
            candidate_signals = rule_candidates + graph_candidates + backend_candidates
            self._refresh_effective_budget(
                state,
                "candidate_signals",
                rule_candidates=rule_candidates,
                graph_candidates=graph_candidates,
                backend_candidates=backend_candidates,
            )
            signal_summary = state.setdefault(
                "candidate_signal_summary",
                {"deterministic": 0, "graph": 0, "backend": 0, "total": 0},
            )
            signal_summary["deterministic"] += len(rule_candidates)
            signal_summary["graph"] += len(graph_candidates)
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
                        f"Added {len(rule_candidates)} deterministic rule candidate(s) "
                        f"{len(graph_candidates)} graph/protocol candidate(s), "
                        f"and {len(backend_candidates)} backend signal candidate(s)."
                    )
                va_ctx_tokens = response.metadata.get("context_tokens", 0) if response.metadata else 0
                state["total_context_tokens"] += va_ctx_tokens
                logger.info(
                    "Vulnerability Analyzer found %d issue(s) for task: %s (ctx ≈ %s tokens)",
                    len(raw_new_issues),
                    agent_cfg.task,
                    f"{va_ctx_tokens:,}",
                )

                new_issues = self._deduplicate_against_history(raw_new_issues, state)
                state["pending_new_issues"].extend(new_issues)
                state["notes"].append(f"Analyzed task: {agent_cfg.task}")
            else:
                logger.error("Vulnerability analysis failed: %s", response.error)
                state["notes"].append(f"Vulnerability analysis failed: {response.error}")
                if candidate_signals:
                    new_issues = self._deduplicate_against_history(candidate_signals, state)
                    state["pending_new_issues"].extend(new_issues)
                    state["notes"].append(
                        f"Retained {len(new_issues)} deterministic/backend candidate(s) "
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
        """Seed high-signal deterministic candidates before LLM validation."""
        entry_func = state["entry_func"]
        impl = state.get("impl_result") or {}
        code = str(impl.get("code") or "")
        file_path = str(impl.get("file") or "")
        generator = DeterministicCandidateGenerator(self._get_deterministic_semantics())
        issues = generator.generate_issues(entry_func, code, file_path)
        issues.extend(self._detect_direct_callee_rule_candidates(impl, generator))
        return self._dedupe_rule_candidates(issues)

    def _detect_graph_rule_candidates(self, state: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Seed cross-function graph/protocol candidates before LLM validation."""
        entry_func = state["entry_func"]
        impl = state.get("impl_result") or {}
        budget = self._current_effective_budget(state)
        graph_depth = int(budget.get("graph_depth", 0) or 0)
        graph_functions = int(budget.get("graph_functions", 0) or 0)
        if graph_depth <= 0 or graph_functions <= 0:
            return []
        generator = GraphCandidateGenerator(self.code_index)
        issues = generator.generate_for_entry(
            entry_func,
            impl,
            max_depth=graph_depth,
            max_functions=graph_functions,
        )
        return self._dedupe_rule_candidates(issues)

    def _detect_graph_rule_tickets(
        self,
        state: Dict[str, Any],
        allowed_skills: Optional[List[str]] = None,
    ) -> List[Any]:
        generator = GraphCandidateGenerator(self.code_index)
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
        """Create deterministic candidates as focused subagent tickets."""
        entry_func = state["entry_func"]
        impl = state.get("impl_result") or {}
        generator = DeterministicCandidateGenerator(self._get_deterministic_semantics())
        issues = generator.generate_issues(
            entry_func,
            str(impl.get("code") or ""),
            str(impl.get("file") or ""),
            allowed_skills=allowed_skills,
        )
        issues.extend(
            self._detect_direct_callee_rule_candidates(
                impl,
                generator,
                allowed_skills=allowed_skills,
            )
        )
        return [
            generator.issue_to_ticket(issue)
            for issue in self._dedupe_rule_candidates(issues)
        ]

    def _detect_direct_callee_rule_candidates(
        self,
        impl: Dict[str, Any],
        generator: DeterministicCandidateGenerator,
        *,
        allowed_skills: Optional[List[str]] = None,
        limit: int = 16,
        max_depth: int = 2,
        total_limit: int = 80,
    ) -> List[Dict[str, Any]]:
        """Run deterministic rules on project callees of thin public facades."""
        issues: List[Dict[str, Any]] = []
        queued: List[tuple[str, int]] = [
            (str(name), 1)
            for name in impl.get("callees", [])
            if str(name).startswith("_")
        ][:limit]
        visited: Set[str] = set()
        analyzed = 0
        while queued and analyzed < total_limit:
            callee, depth = queued.pop(0)
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
            analyzed += 1
            issues.extend(
                generator.generate_issues(
                    callee,
                    str(callee_impl.get("code") or ""),
                    str(callee_impl.get("file") or ""),
                    allowed_skills=allowed_skills,
                )
            )
            if depth >= max_depth:
                continue
            for nested in callee_impl.get("callees", [])[:limit]:
                nested_name = str(nested)
                if nested_name.startswith("_") and nested_name not in visited:
                    queued.append((nested_name, depth + 1))
        return issues

    @staticmethod
    def _dedupe_rule_candidates(issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        deduped: Dict[str, Dict[str, Any]] = {}
        for issue in issues:
            key = str(
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
            deduped.setdefault(key, issue)
        return list(deduped.values())

    def _detect_backend_signal_candidates(self, state: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Convert KnowledgeDB/SVF/Saber findings into normal candidates."""
        db = self._get_knowledge_db()
        if db is None:
            return []
        entry_func = str(state.get("entry_func") or "")
        try:
            bugs = db.get_enriched_taint_bugs(func_name=entry_func, limit=50)
        except Exception as exc:
            logger.debug("Unable to read backend taint bugs: %s", exc)
            return []

        candidates: List[Dict[str, Any]] = []
        for bug in bugs:
            defect_class = self._class_from_backend_bug(str(bug.get("bug_type") or ""))
            file_path = str(bug.get("file_path") or "")
            line = int(bug.get("line") or bug.get("func_start") or 0)
            func = str(bug.get("func_name") or bug.get("source_func") or entry_func)
            candidate_id = f"BACKEND_{defect_class.upper()}_{func}_{line}"
            source = str(bug.get("source_func") or bug.get("tool") or "backend")
            sink = str(bug.get("sink_func") or bug.get("bug_type") or defect_class)
            evidence = {
                "candidate_id": candidate_id,
                "candidate_source": str(bug.get("tool") or "knowledge_db"),
                "defect_class": defect_class,
                "rule": "backend_taint_signature",
                "source": {"expression": source, "file": file_path, "line": line},
                "sink": {"operation": sink, "file": file_path, "line": line},
                "path": {
                    "function": func,
                    "complete_in_function": False,
                    "backend": "SVF/Saber/KnowledgeDB",
                },
                "positive_evidence": [
                    f"{bug.get('tool') or 'backend'} reported {bug.get('bug_type')} at {file_path}:{line}",
                ],
                "negative_evidence": [],
            }
            candidates.append(
                {
                    "id": candidate_id,
                    "candidate_id": candidate_id,
                    "function": func,
                    "location": f"{file_path}:{line}" if file_path else f"{func}:{line}",
                    "category": defect_class,
                    "subcategory": defect_class,
                    "defect_class": defect_class,
                    "finding_kind": "backend_signal",
                    "rule": "backend_taint_signature",
                    "description": f"Static backend reported `{bug.get('bug_type')}` for `{func}`.",
                    "root_cause": "External static analysis backend produced a memory/concurrency signal.",
                    "suggested_fix": "Validate the backend source/sink path and repair the reported lifetime or bounds issue.",
                    "confidence": 0.72,
                    "rule_confidence": 0.72,
                    "impact_level": "high" if defect_class in {"use_after_free", "double_free"} else "medium",
                    "reasoning": "Backend signal normalized into Z-SCOPE candidate/evidence pack.",
                    "source": source,
                    "sink": sink,
                    "positive_evidence": evidence["positive_evidence"],
                    "negative_evidence": [],
                    "evidence_pack": evidence,
                }
            )
        return candidates

    def _detect_backend_signal_tickets(
        self,
        state: Dict[str, Any],
        allowed_skills: Optional[List[str]] = None,
    ) -> List[Any]:
        generator = DeterministicCandidateGenerator(self._get_deterministic_semantics())
        tickets = [
            generator.issue_to_ticket(issue)
            for issue in self._detect_backend_signal_candidates(state)
        ]
        if allowed_skills is None:
            return tickets
        allowed = set(allowed_skills)
        return [ticket for ticket in tickets if ticket.skill in allowed]

    def _get_deterministic_semantics(self) -> DeterministicSemantics:
        """Build once-per-run deterministic aliases and project API semantics."""

        if self._deterministic_semantics is not None:
            return self._deterministic_semantics
        semantics = DeterministicSemantics()
        semantics.merge(self._scan_typedef_aliases())
        semantics.merge(self._semantics_from_user_config())
        semantics.merge(self._semantics_from_snapshots())
        semantics.merge(self._semantics_from_function_names())
        self._deterministic_semantics = semantics
        logger.info(
            "Deterministic semantics: %d typedef alias(es), %d allocator(s), %d deallocator(s), "
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

    def _scan_typedef_aliases(self) -> DeterministicSemantics:
        semantics = DeterministicSemantics()
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

    def _semantics_from_user_config(self) -> DeterministicSemantics:
        semantics = DeterministicSemantics()
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
            if any(word in category for word in ("lock", "mutex", "rwlock", "spin", "sync", "并发", "锁")):
                semantics.add_api("lock", acquire, "user_config:paired_functions")
                semantics.add_api("unlock", release, "user_config:paired_functions")
            elif any(word in category for word in ("memory", "resource", "alloc", "生命周期", "资源", "内存")):
                semantics.add_api("allocator", acquire, "user_config:paired_functions")
                semantics.add_api("deallocator", release, "user_config:paired_functions")
            else:
                self._add_api_by_name_heuristic(semantics, acquire, "user_config:paired_functions")
                self._add_api_by_name_heuristic(semantics, release, "user_config:paired_functions")
        return semantics

    def _semantics_from_snapshots(self) -> DeterministicSemantics:
        semantics = DeterministicSemantics()
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

    def _semantics_from_function_names(self) -> DeterministicSemantics:
        semantics = DeterministicSemantics()
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
        semantics: DeterministicSemantics,
        name: str,
        source: str,
    ) -> None:
        category = DeterministicCandidateGenerator._classify_api_name(name)
        if category:
            semantics.add_api(category, name, source)

    def _add_api_from_semantic_text(
        self,
        semantics: DeterministicSemantics,
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
        if "realloc" in lower or "重新分配" in lower:
            semantics.add_api("reallocator", name, source)
        if any(word in lower for word in ("calloc", "zeroed allocation", "清零分配")):
            semantics.add_api("calloc", name, source)
        if any(word in lower for word in ("allocate", "allocates", "allocation", "returns allocated", "分配", "申请内存")):
            semantics.add_api("allocator", name, source)
        if any(word in lower for word in ("free", "deallocate", "release memory", "释放", "释放内存")):
            semantics.add_api("deallocator", name, source)
        if any(word in lower for word in ("copy", "memcpy", "memmove", "buffer_bounds", "拷贝", "复制")):
            semantics.add_api("copy", name, source)
        if any(word in lower for word in ("acquire lock", "lock acquisition", "locks", "加锁", "获取锁")):
            semantics.add_api("lock", name, source)
        if any(word in lower for word in ("unlock", "release lock", "解锁", "释放锁")):
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

            if self._should_auto_accept_deterministic_candidate(raw_issue):
                issue_code = state["agent_context"]["code"]
                if issue_func != state["agent_context"]["func_name"]:
                    impl = self.code_index.get_function_impl(issue_func)
                    if impl:
                        issue_code = impl["code"]

                score_data = self._score_components(
                    raw_issue,
                    {
                        "verdict": "verified",
                        "confidence_score": max(
                            self._coerce_score(
                                raw_issue.get("rule_confidence", raw_issue.get("confidence", 0.82)),
                                default=0.82,
                            ),
                            0.82,
                        ),
                    },
                )
                raw_issue["score_components"] = score_data
                raw_issue["final_score"] = score_data["final_score"]
                raw_issue["validation_status"] = "validated"
                raw_issue["validator_verdict"] = "verified"
                raw_issue["finding_kind"] = "verified_vulnerability"
                self._enrich_auto_accepted_reasoning(
                    raw_issue,
                    state,
                    issue_code,
                    validator_agent,
                )
                logger.info(
                    "Issue %s auto-accepted as deterministic evidence-backed finding.",
                    raw_issue.get("id"),
                )
                state["issues"].append(raw_issue)
                self._remember_validation_result(raw_issue, "validated")
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
        """Ask the validator LLM to write Chinese reasoning for deterministic auto-accepts."""
        fallback_reasoning = str(
            issue.get("reasoning")
            or "确定性规则证据完整且置信度达到自动确认阈值，已按本地代码事实直接确认；详细证据见 positive_evidence 和 evidence_pack。"
        ).strip()

        evidence_pack = self._build_validation_evidence_pack(issue, state, issue_code)
        evidence_pack["mode"] = "deterministic_auto_accept_reasoning"
        requirements = list(evidence_pack.get("validation_requirements") or [])
        requirements.extend(
            [
                "This finding has already passed deterministic auto-acceptance; use the evidence to write a human-readable Chinese audit reasoning.",
                "reasoning 必须使用中文，并说明触发路径/输入来源、危险操作、缺失保护以及为什么该问题可达。",
                "Do not output the generic deterministic-candidate placeholder as reasoning.",
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
            issue["reasoning_source"] = "deterministic_fallback"
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
            issue["reasoning_source"] = "deterministic_fallback"
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
        issue["reasoning_source"] = "deterministic_fallback"
        if llm_reasoning:
            issue["validation_reasoning"] = (
                f"{fallback_reasoning}\n\nLLM 审计补充（未作为自动确认结论采纳，verdict={verdict}）：{llm_reasoning}"
            )

    def _should_auto_accept_deterministic_candidate(self, issue: Dict[str, Any]) -> bool:
        """Return whether a deterministic local-rule candidate is report-ready."""
        evidence = issue.get("evidence_pack") if isinstance(issue.get("evidence_pack"), dict) else {}
        candidate_source = str(
            evidence.get("candidate_source")
            or issue.get("candidate_source")
            or issue.get("finding_kind")
            or ""
        )
        issue_id = str(issue.get("id") or issue.get("candidate_id") or "")
        if "deterministic" not in candidate_source and not issue_id.startswith("RULE_"):
            return False

        defect_class = str(
            evidence.get("defect_class")
            or issue.get("defect_class")
            or issue.get("subcategory")
            or ""
        )
        confidence = self._coerce_score(
            issue.get("rule_confidence", issue.get("confidence", 0.0)),
            default=0.0,
        )
        min_confidence = {
            "race": 0.68,
            "stale_fd": 0.62,
            "use_after_free": 0.70,
        }.get(defect_class, 0.72)
        if confidence < min_confidence:
            return False

        positive = issue.get("positive_evidence") or evidence.get("positive_evidence") or []
        if not positive:
            return False

        negative = issue.get("negative_evidence") or evidence.get("negative_evidence") or []
        if negative:
            return False

        path = evidence.get("path") if isinstance(evidence.get("path"), dict) else {}
        return bool(path.get("complete") is True or path.get("complete_in_function") is True)

    def _score_components(self, issue: Dict[str, Any], val_data: Dict[str, Any]) -> Dict[str, float]:
        rule_confidence = self._coerce_score(
            issue.get("rule_confidence", issue.get("confidence", 0.5)),
            default=0.5,
        )
        path_completeness = self._path_completeness_score(issue)
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

    def _path_completeness_score(self, issue: Dict[str, Any]) -> float:
        evidence = issue.get("evidence_pack") if isinstance(issue.get("evidence_pack"), dict) else {}
        path = evidence.get("path") if isinstance(evidence.get("path"), dict) else {}
        if path.get("complete") is True or path.get("complete_in_function") is True:
            return 1.0
        if issue.get("source") and issue.get("sink"):
            return 0.75
        if issue.get("evidence_refs"):
            return 0.7
        return 0.5

    def _contract_consistency_score(self, issue: Dict[str, Any], val_data: Dict[str, Any]) -> float:
        negative = issue.get("negative_evidence") or val_data.get("negative_evidence") or []
        if negative:
            return 0.55
        if issue.get("source") and issue.get("sink"):
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
        """Build compact deterministic evidence so the validator starts from facts."""
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
                    "message": "Generated and saved deterministic lightweight snapshot.",
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
        """Return true for macros/wrappers that can be summarized deterministically."""
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
        """Create a deterministic snapshot for common macros and tiny wrapper APIs."""
        code = str(impl.get("code") or "")
        upper = func_name.upper()
        key_semantics: List[str] = ["deterministic lightweight snapshot; no LLM call"]
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
        elif upper in {"SAFE_FREE"}:
            summary = "SAFE_FREE-style macro: frees a non-null pointer and nulls the lvalue."
            resources = {"memory": "conditional free and null assignment"}
            key_semantics.append("conditional release")
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
        递归预建模入口函数的所有可达 callee（逆拓扑序）。
        Returns:
            (modeled_count, skipped_count, total_context_tokens)
        """
        # 1. BFS 收集可达 callee 图
        callee_graph: Dict[str, List[str]] = {}
        visited: Set[str] = set()
        queue: list = [(entry_func, 0)]
        impl_cache: Dict[str, Any] = {}  # 缓存 get_function_impl 结果

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

            # 过滤掉无源码的函数（标准库等）
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

        # 2. 逆拓扑排序：叶子函数优先
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
            status = self.snapshot_store.lock_manager.acquire(func, timeout=120.0)
            if status == "done":
                skipped += 1
                continue
            if status == "timeout":
                logger.warning(f"[premodel] Timeout waiting for '{func}', skipping.")
                continue

            # status == "acquired"：由当前 Worker 建模
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

                # 高效拦截：平凡函数不需要让大模型看
                if self._is_trivial_function(impl["code"], self.config.analysis.trivial_function_max_lines):
                    logger.info(f"[premodel] Auto-skipping trivial function '{func}'")
                    fake_snapshot = {
                        "type": "function_snapshot",
                        "func_name": func,
                        "location": location,
                        "summary": "[Auto-Skipped] Trivial Function (极简直通结构，未调用 LLM)",
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

        logger.info(f"[premodel] Done: {modeled} modeled, {skipped} reused from cache (ctx ≈ {total_tokens:,} tokens)")
        return modeled, skipped, total_tokens

    @staticmethod
    def _is_trivial_function(code: str, max_lines_threshold: int) -> bool:
        """
        判断一个函数是否过于简单，不需要经过大模型做深度语义分析。
        1. 去除注释和空行后，行数 <= max_lines_threshold
        2. 代码体内不含有锁、内存分配、IO等高危关键字（无涉安全）
        """
        if max_lines_threshold <= 0:
            return False

        # 1. 粗略清洗注释和左侧行号前缀
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

        # 除了大括号和函数签名之外的有效逻辑行
        logic_lines = [l for l in clean_lines if l not in ("{", "}")]
        # Let's say if signature is 1 line, body is N lines. We just check total clean logic lines.
        # usually 1 line signature + 1 line return + maybe brackets.
        if len(logic_lines) > max_lines_threshold + 1:  # +1 for signature roughly
            return False

        # 2. 验证风险关键字
        # 不区分大小写匹配敏感操作
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
        """逆拓扑排序：返回叶子优先的建模顺序。"""
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
        return order  # 天然是逆拓扑序（叶子在前）

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


