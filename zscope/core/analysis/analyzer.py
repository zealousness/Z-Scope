"""
Main analyzer logic for Z-SCOPE.
Orchestrates the analysis process using LLM, CodeIndex, and SnapshotStore.
"""

import json
import hashlib
import logging
import time
import datetime
import inspect
import re
import subprocess
import threading
import uuid
from collections import deque
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, cast

from ...config.config import ZScopeConfig, minimum_optional_positive_seconds
from ...config.function_entry import FunctionEntry
from ...config.user_config_store import UserConfigStore
from ...common.utils import normalize_path
from ...retrieval.code_index import CodeIndex
from ...snapshots.store import SnapshotStore
from ...snapshots.modeling_input import (
    SemanticModelInputError,
    build_semantic_model_input,
    hydrate_project_callee_summaries,
    resolve_function_info,
)
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
    java_provider_signal_to_candidate,
    joern_rule_match_to_candidate,
    resource_release_pairs_from_overlay,
)
from ..candidates.java_evidence import merge_java_evidence_candidates
from ...orchestration.agent_policy import (
    agent_system_prompt,
    attach_agent_contract,
    tool_audit_log_path,
    tool_policy_for_agent,
)
from ..candidates.pipeline import CandidatePipeline
from ..candidates.java_active_audit import JavaActiveAuditNormalizer
from ..candidates.decision_facts import DecisionFactGraphCache
from ..candidates.clang_ast_cfg import ClangAstCfgCandidateGenerator
from ...retrieval.clang_tooling_evidence import ClangToolingEvidenceProvider
from ..candidates.regex import RegexCandidateGenerator
from ..candidates.java_rules import JavaRuleCandidateGenerator
from ...rules.extensions import RuleContext, preflight_rules
from ...rules.catalog import serialize_effective_rules
from ...semantics.models import LocalPatternSemantics
from ...semantics.security_map import SQLiteSecurityMapStore, ZeroLLMSecurityMapBuilder
from ..candidates.graph import GraphCandidateGenerator
from ...orchestration.history_reconciler import HistoryReconciler
from ..candidates.svf_value_flow import SvfValueFlowCandidateGenerator
from ...tools.policy import ToolPolicy, deny_sensitive_paths_hook
from ...tools.runtime import ToolsRuntime
from ..validation.pipeline import ValidationPipeline, preserve_issue_location
from ..validation.runner import ValidationResultCache, ValidationRunner
from ..validation.evidence import (
    build_validation_evidence_pack,
    category_validation_requirements,
    compact_snapshot,
    is_entry_root_dead_code_rejection,
    trim_code,
    validation_verdict,
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
from ...framework.llm_usage import (
    ensure_scan_token_usage_ledger,
    scan_token_usage_snapshot,
)
from ...reporting.report import FinalReport, Issue, ReportGenerator
from ...common.issue_identity import (
    canonical_issue_key,
    deduplicate_semantic_issues_programmatic,
    flatten_issue_text,
    issue_rank,
    normalize_issue_category,
    normalize_issue_key_part,
    parse_issue_location,
)
from ...reporting.assembler import ReportAssembler
from ...common.cancellation import CancellationToken, bind_cancellation_token
from ...orchestration.workflow_runner import WorkflowRunner
from ...common.utils import extract_json_blocks, validate_json_schema
from ..._version import __version__
from ...orchestration.specs import SpecRegistry, WorkflowStep
from ...orchestration.workflow_executor import WorkflowExecutor, WorkflowStepHandler
from ...orchestration.rollout import rollout_runtime_policy
from ...orchestration.candidates import CandidateLedger, CandidateRegistrar, CandidateTicket
from ...orchestration.hunting_profile import resolve_hunting_profile
from ...orchestration.hypothesis_hunter import (
    HypothesisArtifactStore,
    HypothesisHunterAgent,
    HypothesisHunterRuntime,
    HypothesisProofCatalog,
)
from ...orchestration.runtime_authority import build_runtime_authority_manifest
from ..validation.fact_capabilities import FunctionIRFactService
from ...semantics.security_specs.compiler import SecuritySpecCompiler
from ...semantics.security_specs.qualification import load_builtin_qualification
from ...semantics.security_specs.runtime import SecuritySpecRuntime
from ...semantics.security_specs.store import SecuritySpecStore
from ...orchestration.decision_trace import ensure_decision_trace_store
from ...orchestration.candidate_envelope import (
    CANDIDATE_SCHEMA_VERSION,
    annotate_issue_identity,
)
from ...orchestration.scheduler import ScanScheduler
from ...orchestration.budget import EffectiveBudget, RiskBudgetPlanner
from ...orchestration.skill_selection import SkillSelection
from ...reporting.schema import report_reuse_blockers

logger = logging.getLogger(__name__)

DEFAULT_SCAN_STEP_IDS = (
    "collect_candidates",
    "validate_candidates",
    "persist_report",
)


def _as_dict(value: Any) -> Dict[str, Any]:
    """Narrow an untyped runtime payload to the mutable mapping we expect."""
    return cast(Dict[str, Any], value) if isinstance(value, dict) else {}


def _as_list(value: Any) -> List[Any]:
    """Narrow an untyped runtime payload to a list without copying it."""
    return cast(List[Any], value) if isinstance(value, list) else []


class Analyzer:
    """
    Main analyzer class.
    """

    def __init__(
        self,
        config: ZScopeConfig,
        code_index: Optional[CodeIndex] = None,
        snapshot_store: Optional[SnapshotStore] = None,
        user_config: Optional[UserConfigStore] = None,
        force_ignore_history: bool = False,
        maintain_mode: bool = False,
        candidate_ledger: Optional[CandidateLedger] = None,
        shared_local_pattern_semantics: Optional[LocalPatternSemantics] = None,
        shared_semantic_overlay: Optional[Dict[str, Any]] = None,
        llm_clients: Optional[Dict[str, LLMClient]] = None,
        validation_result_cache: Optional[ValidationResultCache] = None,
        cancellation_token: Optional[CancellationToken] = None,
        scheduler: Optional[ScanScheduler] = None,
        candidate_ir_persistence_lock: Optional[Any] = None,
        decision_fact_cache: Optional[DecisionFactGraphCache] = None,
        write_root_reports: bool = True,
        defer_validation_to_scan: bool = False,
    ):
        self.config = config
        # Defensive preflight for third-party callers that construct an
        # Analyzer from an in-memory config instead of going through
        # ConfigLoader.  It is intentionally before CodeIndex/external tools.
        self.spec_registry = SpecRegistry(project_root=config.project.project_root)
        self.effective_rules = preflight_rules(config, spec_registry=self.spec_registry)
        self.rule_policy = self.effective_rules.policy
        self.cancellation_token = cancellation_token
        self.scheduler = scheduler
        # A batch shares one KnowledgeDB connection between entry workers.
        # Candidate IR persistence performs several writes followed by a
        # commit, so it must be one critical section rather than independent
        # SQLite writes from each entry thread.
        self._candidate_ir_persistence_lock = candidate_ir_persistence_lock
        # Scope this bounded cache to one scan.  It is never a class-level
        # cache, so facts cannot leak across revisions or projects.
        self.decision_fact_cache = decision_fact_cache or DecisionFactGraphCache()
        # Java project-file rules can be reached concurrently by entry
        # workers. Keep their scan-local cache and synchronization primitive
        # on every Analyzer instance before the candidate pipeline runs.
        self._java_project_file_rule_cache: Optional[List[Dict[str, Any]]] = None
        self._java_project_file_rule_cache_lock = threading.RLock()
        self._java_project_file_rule_emitted = False
        self.write_root_reports = write_root_reports
        # Parallel batch execution owns validation at scan scope.  A standalone
        # Analyzer still validates locally, preserving the existing public
        # facade and avoiding an incomplete one-entry report.
        self.defer_validation_to_scan = bool(defer_validation_to_scan)
        self.code_index = code_index or CodeIndex(
            config.project.project_root,
            config.project.compile_commands_path,
            source_root=config.project.source_root,
            indexing_config=config.indexing,
            priority_functions=(
                [config.project.entry_function] if config.project.entry_function else None
            ),
            include_paths=config.project.include_paths,
            exclude_paths=config.project.exclude_paths,
            svf_entry_functions=(
                [config.project.entry_function] if config.project.entry_function else None
            ),
            svf_parallel_workers=(
                config.concurrency.svf_workers or config.concurrency.index_workers
            ),
        )
        self.snapshot_store = snapshot_store or SnapshotStore.from_config(config)
        self.force_ignore_history = force_ignore_history
        self.maintain_mode = maintain_mode
        self.history_reconciler = HistoryReconciler(
            self.snapshot_store,
            force_ignore_history=self.force_ignore_history,
        )
        db_dir = (
            Path(config.analysis.user_config_db)
            if config.analysis.user_config_db
            else Path(config.analysis.snapshot_dir)
        )
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
        self.validation_result_cache = validation_result_cache
        self.llm_clients: Dict[str, LLMClient]
        if llm_clients is not None:
            self.llm_clients = llm_clients
        else:
            self.llm_clients = {}
            token_usage_ledger = ensure_scan_token_usage_ledger(config)
            for name, llm_cfg in config.llms.items():
                self.llm_clients[name] = LLMClient(
                    api_key=llm_cfg.api_key,
                    base_url=getattr(llm_cfg, "base_urls", None) or llm_cfg.base_url,
                    models=llm_cfg.models,
                    timeout=minimum_optional_positive_seconds(
                        llm_cfg.timeout,
                        getattr(
                            config.analysis,
                            "request_deadline_seconds",
                            None,
                        ),
                    ),
                    max_retries=llm_cfg.max_retries,
                    retry_until_available=getattr(llm_cfg, "retry_until_available", False),
                    max_tokens=llm_cfg.max_tokens,
                    base_url_rate_limit_per_minute=getattr(
                        llm_cfg, "base_url_rate_limit_per_minute", 0
                    ),
                    base_url_max_concurrent_requests=getattr(
                        llm_cfg, "base_url_max_concurrent_requests", 0
                    ),
                    global_max_concurrent_requests=config.concurrency.llm_max_inflight,
                    supports_structured_output=getattr(
                        llm_cfg, "supports_structured_output", False
                    ),
                    require_exact_response_model=getattr(
                        llm_cfg, "require_exact_response_model", False
                    ),
                    token_usage_ledger=token_usage_ledger,
                    llm_ref=name,
                )
        self.validation_runner = self._make_validation_runner()
        self.report_generator = ReportGenerator(config.project.project_root)
        self.report_assembler = ReportAssembler(
            self.report_generator,
            self.snapshot_store,
            resolve_issue_locations=self._resolve_issue_locations,
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
        self.workflow_spec = self.spec_registry.get_workflow(config.analysis.workflow_name)
        self.decision_trace_store = ensure_decision_trace_store(config)
        self.candidate_ledger = candidate_ledger or CandidateLedger(
            project_id=str(
                getattr(config.project, "project_id", "") or config.project.project_root.name
            ),
            project_root=str(config.project.project_root),
            revision=self._git_commit_sha(config.project.project_root),
            decision_trace_store=self.decision_trace_store,
        )
        if self.candidate_ledger.decision_trace_store is None:
            self.candidate_ledger.decision_trace_store = self.decision_trace_store
        self.budget_planner = RiskBudgetPlanner(config.analysis)
        self._local_pattern_semantics: Optional[LocalPatternSemantics] = (
            deepcopy(shared_local_pattern_semantics)
            if shared_local_pattern_semantics is not None
            else None
        )
        self._semantic_overlay: Optional[Dict[str, Any]] = (
            deepcopy(shared_semantic_overlay) if shared_semantic_overlay is not None else None
        )
        self._clang_tooling_provider: Optional[ClangToolingEvidenceProvider] = None
        self._clang_tooling_evidence_cache: Dict[tuple[str, str, int, int], Dict[str, Any]] = {}
        self._runtime_engine_capabilities: Dict[str, Dict[str, Any]] = {}
        self._runtime_engine_capabilities_lock = threading.RLock()
        self._reachable_function_cache: Dict[tuple[str, int, int, int], Set[str]] = {}
        self._reachable_function_cache_lock = threading.RLock()
        self.workflow_progress: List[Dict[str, Any]] = []
        self.current_workflow_step: Optional[str] = None
        self.workflow_step_handlers: Dict[str, WorkflowStepHandler] = (
            self._build_workflow_step_handlers()
        )
        self.workflow_executor = WorkflowExecutor(
            workflow_name=(
                self.workflow_spec.name if self.workflow_spec else config.analysis.workflow_name
            ),
            scope="entry",
            handlers=self.workflow_step_handlers,
            progress=self.workflow_progress,
            cancellation_token=self.cancellation_token,
        )
        self.workflow_executor.validate(self._selected_workflow_steps())
        self.workflow_runner = WorkflowRunner(
            workflow_name=(
                self.workflow_spec.name if self.workflow_spec else config.analysis.workflow_name
            ),
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
        with bind_cancellation_token(self.cancellation_token):
            if self.cancellation_token is not None:
                self.cancellation_token.raise_if_cancelled()
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

    @staticmethod
    def _entry_lookup_query(
        entry_function: str,
        entry_signature: str,
        language: str,
    ) -> str:
        """Choose the index lookup identifier for a configured entry.

        C/C++ signatures conventionally contain the callable name and remain
        the most precise lookup key. Java structure indexes instead use the
        fully-qualified ``Class.method:return(parameters)`` form while their
        stored signature is only ``return(parameters)``; using the latter
        loses the method identity.
        """
        if str(language or "").strip().lower() == "java":
            return entry_function
        return entry_signature or entry_function

    def _create_workflow_state(self) -> Dict[str, Any]:
        """Create mutable execution state shared by workflow steps."""
        entry_func = self.config.project.entry_function
        if not entry_func:
            return {
                "error": "No entry function configured",
                "reason": "entry_not_configured",
                "entry_func": "",
            }
        entry_file_path = str(getattr(self.config.project, "entry_file_path", "") or "")
        entry_signature = str(getattr(self.config.project, "entry_signature", "") or "")
        entry_lookup_query = self._entry_lookup_query(
            entry_func,
            entry_signature,
            str(getattr(self.config.project, "language", "") or ""),
        )
        self.user_config.clear_config_warnings()

        lookup_started = time.monotonic()
        logger.info("[code-index] lookup start entry=%s", entry_func)
        try:
            semantic_model_input = build_semantic_model_input(
                self.code_index,
                entry_lookup_query,
                file_path=entry_file_path,
                include_context=True,
            )
            semantic_model_input = hydrate_project_callee_summaries(
                semantic_model_input,
                self.code_index,
                self.snapshot_store,
            )
            impl_result = self.code_index.get_function_impl(
                semantic_model_input["index_name"],
                max_lines=self.config.analysis.max_function_lines,
                file_path=semantic_model_input["file_path"],
            )
        except SemanticModelInputError as exc:
            return {
                "error": str(exc),
                "reason": exc.reason,
                "llm_called": False,
                "entry_func": entry_func,
            }
        logger.info(
            "[code-index] lookup end entry=%s index_name=%s found=%s duration=%.2fs",
            entry_func,
            semantic_model_input["index_name"],
            bool(impl_result),
            time.monotonic() - lookup_started,
        )
        if not impl_result:
            return {
                "error": "Entry function not found",
                "reason": "entry_not_found",
                "entry_func": entry_func,
            }

        agent_context = {
            "func_name": semantic_model_input["func_name"],
            "code": impl_result["code"],
            "location": f"{impl_result['file']}:{impl_result['start_line']}",
        }

        user_config_context = relevant_user_config_context(
            self.user_config,
            semantic_model_input["func_name"],
            semantic_model_input["code"],
            semantic_model_input["file_path"],
        )
        if user_config_context:
            agent_context["user_config_context"] = user_config_context
            semantic_model_input["user_config_context"] = user_config_context

        diff_focus = getattr(self.config.project, "entry_diff_focus", None)
        if isinstance(diff_focus, dict) and diff_focus:
            agent_context["diff_focus"] = self._build_diff_focus_agent_context(diff_focus)
            semantic_model_input["diff_focus"] = agent_context["diff_focus"]

        state = {
            "entry_func": entry_func,
            "entry_signature": entry_signature or str(semantic_model_input.get("signature") or ""),
            "entry_file_path": str(semantic_model_input.get("file_path") or entry_file_path),
            "entry_identity": FunctionEntry(
                function_name=entry_func,
                file_path=str(semantic_model_input.get("file_path") or entry_file_path) or None,
                signature=entry_signature
                or str(semantic_model_input.get("signature") or "")
                or None,
            ).identity_key(self.config.project.project_root),
            "entry_index_name": semantic_model_input["index_name"],
            "run_id": uuid.uuid4().hex,
            "impl_result": impl_result,
            "agent_context": agent_context,
            "semantic_model_input": semantic_model_input,
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
            "candidate_ledger": self.candidate_ledger,
            "decision_trace_store": self.decision_trace_store,
            "candidate_ledger_context": [],
            "candidate_ledger_summary": {},
            "candidate_lifecycle_v3": True,
            "canonical_outcome_projection_enabled": True,
            "finding_root_projection_enabled": True,
            "budget_exhaustion_policy": str(
                getattr(self.config.analysis, "budget_exhaustion_policy", "observe") or "observe"
            ),
            "validation_queue_drained": False,
            "validator_session_count": 0,
            "validator_api_call_count": 0,
            "validator_turn_distribution": {},
            "validator_prompt_tokens_by_stage": {},
            "evidence_slice_token_count": 0,
            "multi_turn_outlier_count": 0,
            "snapshot_model_call_count": 0,
            "fact_query_cache_hit_count": 0,
            "deferred_deterministic_work": [],
            "engine_capabilities": self._engine_capabilities(),
            "total_context_tokens": 0,
            "total_cumulative_prompt_tokens": 0,
            "total_cumulative_completion_tokens": 0,
            "total_cumulative_total_tokens": 0,
            "budget_observations": [],
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
    ) -> EffectiveBudget:
        """Compute and attach the current adaptive budget to workflow state."""

        budget = self.budget_planner.plan(
            state,
            rule_candidates=rule_candidates,
            graph_candidates=graph_candidates,
            backend_candidates=backend_candidates,
        )
        budget_dict = budget.to_dict()
        state["effective_budget"] = budget_dict
        state["budget_stage"] = stage
        state["budget_hard_caps"] = dict(budget.hard_caps)
        state["budget_scores"] = dict(budget.risk_scores)
        state["budget_reasons"] = {key: list(value) for key, value in budget.risk_reasons.items()}

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
            "compare_entry_state": self._handle_load_history_state,
            "reuse_unchanged_report": self._handle_reuse_unchanged_report,
            "reconcile_history": self._handle_reconcile_changed_issues,
            "run_pending_entries": self._handle_default_scan_subworkflow,
            "run_changed_entry": self._handle_default_scan_subworkflow,
            "collect_candidates": self._handle_collect_candidates,
            "validate_candidates": self._handle_validate_findings,
            "persist_report": self._handle_persist_report,
        }

    def _handle_load_history_state(self, state: Dict[str, Any], step: WorkflowStep) -> bool:
        self._load_history_state(state)
        return False

    def _handle_reuse_unchanged_report(self, state: Dict[str, Any], step: WorkflowStep) -> bool:
        return self._reuse_unchanged_report(state)

    def _handle_reconcile_changed_issues(self, state: Dict[str, Any], step: WorkflowStep) -> bool:
        self._reconcile_changed_issues(state)
        return False

    def _handle_default_scan_subworkflow(self, state: Dict[str, Any], step: WorkflowStep) -> bool:
        self._execute_default_scan_subworkflow(state)
        return True

    def _handle_collect_candidates(self, state: Dict[str, Any], step: WorkflowStep) -> bool:
        self._step_collect_candidates(state)
        return False

    def _handle_validate_findings(self, state: Dict[str, Any], step: WorkflowStep) -> bool:
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
                state["semantic_model_input"],
            )
        )

    def _reuse_unchanged_report(self, state: Dict[str, Any]) -> bool:
        if not state.get("history_loaded"):
            self._load_history_state(state)

        historical_report = state.get("historical_report")
        if self.maintain_mode and state.get("is_code_unchanged") and historical_report:
            blockers = report_reuse_blockers(
                historical_report,
                expected_manifest={
                    "source_revision": self._git_commit_sha(self.config.project.project_root),
                    "config_hash": self._config_hash(),
                    "model_manifest_hash": self._model_manifest_hash(),
                    "knowledge_db_version": self._knowledge_db_version(),
                    "effective_rules_sha256": self._effective_rules_sha256(),
                },
            )
            if blockers:
                state["notes"].append(
                    "Historical report was not reused because it is incomplete "
                    "or incompatible: " + ", ".join(blockers)
                )
                logger.info(
                    "[maintain] '%s' report reuse blocked: %s",
                    state["entry_func"],
                    ", ".join(blockers),
                )
                return False
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
                (a for a in self.config.project.agents if a.name == "history_maintenance_agent"),
                None,
            )
            recon_llm_ref = (
                recon_agent_cfg.llm_ref
                if recon_agent_cfg and recon_agent_cfg.llm_ref
                else "default"
            )
            recon_client = self.llm_clients.get(recon_llm_ref, self.llm_clients.get("default"))
            if recon_client is None:
                raise RuntimeError("No LLM client configured for historical maintenance")

            from ...agents.history_maintenance.agent import HistoryMaintenanceAgent

            reconciler_agent = HistoryMaintenanceAgent(
                recon_client,
                tool_policy=self._tool_policy_for_agent("history_maintenance_agent"),
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
                elif reconciled.reason == "fix_suggested_needs_review":
                    logger.info(
                        "Historical issue %s may be fixed; retaining as needs_review "
                        "until deterministic refutation is available.",
                        hist_issue.get("id"),
                    )
                elif not reconciled.keep:
                    logger.info(
                        "Historical issue %s fixed in new code. Dropping.", hist_issue.get("id")
                    )
            state["verified_hist_issues"] = verified_hist_issues
        else:
            state["verified_hist_issues"] = list(valid_hist_issues)

        state["history_reconciled"] = True

    def _step_collect_candidates(self, state: Dict[str, Any]) -> None:
        if self._semantic_overlay is None or self._local_pattern_semantics is None:
            self._prepare_single_entry_security_spec_runtime(state)
        agent_context = state["agent_context"]
        active_cfg = next(
            (agent for agent in self.config.project.agents if agent.name == "hypothesis_hunter"),
            None,
        )
        task = str(
            getattr(getattr(self.config, "scan", None), "task", "")
            or getattr(active_cfg, "task", "")
            or ""
        )
        selection = self._candidate_first_skill_selection(
            list(getattr(active_cfg, "skills", []) or [])
        )
        agent_context["task"] = task
        agent_context["entry_custom_prompt"] = getattr(active_cfg, "entry_custom_prompt", None)
        agent_context["active_skills"] = selection.skills
        agent_context["skill_selection_restricted"] = False

        candidate_batch = self.candidate_pipeline.collect_signal_candidates(state)
        self.candidate_pipeline.accumulate_summary(state, candidate_batch)
        self.candidate_pipeline.persist(candidate_batch)
        candidate_signals = candidate_batch.merged_candidates
        agent_context["candidate_signal_summary"] = candidate_batch.summary_increment()
        agent_context["candidate_signal_candidates"] = self._compact_candidate_signal_items(
            candidate_signals,
            limit=80,
        )

        self._register_candidate_issues(
            state,
            candidate_signals,
            source="deterministic_candidate_discovery",
        )
        state["pending_new_issues"].extend(list(candidate_signals))
        state["notes"].append(
            "Routed structured deterministic candidates directly to the shared "
            "Candidate Ledger and validation lifecycle."
        )
        self._record_engine_capability(
            "candidate_collection",
            status="complete",
            active=True,
            reason="candidate_ledger_registration",
            candidate_count=len(candidate_signals),
        )

        if not getattr(self, "defer_validation_to_scan", False):
            self._run_single_entry_hypothesis_hunter(state)

    def _prepare_single_entry_security_spec_runtime(self, state: Dict[str, Any]) -> None:
        """Compile strict SecuritySpecs before a standalone Analyzer collects candidates."""

        profile = resolve_hunting_profile(self.config)
        entry = FunctionEntry(
            function_name=str(state.get("entry_func") or ""),
            file_path=str(state.get("entry_file_path") or "") or None,
            signature=str(state.get("entry_signature") or "") or None,
        )
        raw_overlay = SemanticOverlayCompiler(self.user_config).compile()
        semantic_map = ZeroLLMSecurityMapBuilder(
            self.code_index,
            project_id=str(
                getattr(self.config.project, "project_id", "")
                or self.config.project.project_root.name
            ),
            revision=str(getattr(self.candidate_ledger, "revision", "") or ""),
            profile=profile.name,
            semantic_overlay=raw_overlay,
            project_root=self.config.project.project_root,
            max_functions=int(
                getattr(
                    self.config.analysis,
                    "security_map_max_functions",
                    15_000 if profile.name == "deep" else 5_000,
                )
            ),
        ).build([entry])
        store = SecuritySpecStore(Path(self.config.analysis.snapshot_dir) / "security_specs")
        qualification = load_builtin_qualification()
        evidence_refs = {
            str(ref)
            for claim in semantic_map.claims
            for ref in getattr(claim, "evidence_refs", ()) or ()
        }
        dependency_hashes = {
            str(value)
            for record in semantic_map.functions
            for value in (
                record.code_hash,
                hashlib.sha256(
                    json.dumps(
                        record.backend_coverage,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest(),
            )
            if str(value)
        }
        runtime = SecuritySpecRuntime(store).run(
            semantic_map,
            qualification_hashes=[str(qualification["content_sha256"])],
            qualifications=[qualification],
            resolvable_evidence_refs=evidence_refs,
            current_dependency_hashes=dependency_hashes,
            additional_specs=store.list_specs(),
        )
        overlay = SecuritySpecCompiler.semantic_overlay(runtime["compilation"])
        self._semantic_overlay = overlay
        self._local_pattern_semantics = self._local_semantics_from_compiled_specs(overlay)
        authoritative_map = ZeroLLMSecurityMapBuilder(
            self.code_index,
            project_id=str(
                getattr(self.config.project, "project_id", "")
                or self.config.project.project_root.name
            ),
            revision=str(getattr(self.candidate_ledger, "revision", "") or ""),
            profile=profile.name,
            semantic_overlay=overlay,
            project_root=self.config.project.project_root,
            max_functions=int(
                getattr(
                    self.config.analysis,
                    "security_map_max_functions",
                    15_000 if profile.name == "deep" else 5_000,
                )
            ),
        ).build([entry])
        semantic_store = SQLiteSecurityMapStore(
            Path(self.config.analysis.snapshot_dir) / "security_map.db"
        )
        semantic_store.save_map(authoritative_map)
        semantic_store.export_json(
            authoritative_map,
            Path(self.config.analysis.snapshot_dir) / "security_semantic_map.json",
        )
        state["security_semantic_map"] = authoritative_map
        state["security_spec_runtime"] = runtime
        state["security_runtime"] = {
            "enabled": profile.name != "fast",
            "profile": profile.name,
            "status": "security_spec_compiled",
            "security_spec_runtime": runtime,
        }
        self.decision_trace_store.update_identity(
            {
                "security_spec_mode": "authoritative",
                "security_spec_root_manifest_sha256": str(
                    runtime.get("root_manifest_sha256") or ""
                ),
                "security_spec_artifact_refs": list(runtime.get("artifact_refs") or []),
                "security_spec_decision": {
                    "active_product_effect": "semantic_input",
                    "compiled_spec_count": int(runtime.get("compiled_spec_count", 0) or 0),
                    "reason_code": "security_spec_authoritative",
                },
            }
        )

    @staticmethod
    def _local_semantics_from_compiled_specs(
        overlay: Dict[str, Any],
    ) -> LocalPatternSemantics:
        semantics = LocalPatternSemantics()
        for value in overlay.get("resource_models") or []:
            if not isinstance(value, dict):
                continue
            category = {
                "resource_acquire": "allocator",
                "resource_release": "deallocator",
                "resource_transfer": "reallocator",
            }.get(str(value.get("kind") or ""))
            if category:
                semantics.add_api(category, str(value.get("name") or ""), "security_spec_compiler")
        for value in overlay.get("lock_models") or []:
            if isinstance(value, dict) and str(value.get("kind") or "") in {"lock", "unlock"}:
                semantics.add_api(
                    str(value["kind"]),
                    str(value.get("name") or ""),
                    "security_spec_compiler",
                )
        return semantics

    def _run_single_entry_hypothesis_hunter(self, state: Dict[str, Any]) -> None:
        """Run the same bounded Hunter contract used by batch scans."""

        profile = resolve_hunting_profile(self.config)
        if profile.name == "fast":
            state["security_runtime"].update(
                {
                    "enabled": False,
                    "status": "disabled_by_profile",
                    "llm_discovery_call_count": 0,
                }
            )
            return
        semantic_map = state.get("security_semantic_map")
        spec_runtime = state.get("security_spec_runtime")
        if semantic_map is None or not isinstance(spec_runtime, dict):
            raise RuntimeError("authoritative_security_spec_runtime_missing")
        compile_commands = getattr(self.code_index, "compile_commands_path", None)
        fact_service = FunctionIRFactService(
            Path(compile_commands) if compile_commands else None,
            enabled=self._project_language() == "c_cpp",
        )

        def graph_provider(record: Any, event: Any) -> Any:
            raw_path = Path(str(record.file_path))
            path = (
                raw_path if raw_path.is_absolute() else self.config.project.project_root / raw_path
            )
            line = int(event.line or record.start_line or 0)
            return fact_service.graph(
                {
                    "function": str(record.function_name),
                    "function_signature": str(record.function_name),
                    "file": str(path),
                    "line": line,
                    "source": {"line": line, "expression": str(event.expression or "")},
                    "sink": {"line": line, "expression": str(event.expression or "")},
                },
                {},
            )

        client = self._scan_role_llm_client("analysis")
        report_runner = None
        if client is not None:
            agent = HypothesisHunterAgent(client)

            def report_runner(projection: Any, unit: Any, offers: Any) -> Any:
                return agent.run(
                    {"projection": projection, "audit_unit": unit, "offers": list(offers)}
                )

        registrar = CandidateRegistrar(
            self.candidate_ledger,
            project_id=str(
                getattr(self.config.project, "project_id", "")
                or self.config.project.project_root.name
            ),
            project_root=str(self.config.project.project_root),
            revision=str(getattr(self.candidate_ledger, "revision", "") or ""),
            run_id=str(state.get("run_id") or ""),
            decision_fact_cache=self.decision_fact_cache,
        )
        result = HypothesisHunterRuntime(
            HypothesisArtifactStore(Path(self.config.analysis.snapshot_dir) / "hypothesis_hunter"),
            risk_threshold=profile.risk_threshold,
            max_units=profile.max_units,
            model_profile=profile.name,
        ).run(
            semantic_map,
            candidate_registrar=registrar,
            security_spec_runtime=spec_runtime,
            proof_bundle_provider=HypothesisProofCatalog(graph_provider).bundles,
            report_runner=report_runner,
        )
        state["security_runtime"].update(
            {
                "enabled": True,
                "status": "complete",
                "hypothesis_hunter_runtime": result,
                "hypothesis_count": int(result.get("hypothesis_count", 0) or 0),
                "llm_discovery_call_count": int(result.get("llm_call_count", 0) or 0),
            }
        )
        self.decision_trace_store.update_identity(
            {
                "hypothesis_hunter_mode": "active",
                "hypothesis_hunter_root_manifest_sha256": str(
                    result.get("root_manifest_sha256") or ""
                ),
                "hypothesis_hunter_artifact_refs": list(result.get("artifact_refs") or []),
                "hypothesis_hunter_decision": {
                    "active_product_effect": "candidate_registration_only",
                    "reason_code": "hypothesis_hunter_candidate_registration_only",
                    "coverage_summary": dict(result.get("coverage_summary") or {}),
                },
            }
        )

    def _scan_role_llm_client(self, role: str) -> Optional[LLMClient]:
        """Resolve the public P5 scan role mapping."""

        profiles = getattr(getattr(self.config, "scan", None), "llm_profiles", None)
        configured_ref = str(getattr(profiles, role, "") or "")
        if not configured_ref:
            role_names = {
                "modeling": ("security_spec_miner",),
                "analysis": ("hypothesis_hunter",),
                "validation": ("proof_engine",),
            }.get(role, ())
            configured_ref = next(
                (
                    str(getattr(item, "llm_ref", "") or "")
                    for item in self.config.project.agents
                    if str(getattr(item, "name", "") or "") in role_names
                    and bool(getattr(item, "enabled", True))
                    and str(getattr(item, "llm_ref", "") or "")
                ),
                "",
            )
        configured_ref = configured_ref or "default"
        return self.llm_clients.get(configured_ref, self.llm_clients.get("default"))

    def _security_discovery_llm_client(self) -> Optional[LLMClient]:
        return self._scan_role_llm_client("analysis")

    def _record_llm_iteration_budget(
        self,
        state: Dict[str, Any],
        response: Any,
        *,
        agent_name: str,
        outcome: str,
    ) -> bool:
        """Record a reached LLM turn budget without making it a hard failure."""

        metadata = dict(getattr(response, "metadata", {}) or {}) if response is not None else {}
        error = str(getattr(response, "error", "") or "")
        normalized_error = error.lower()
        reached = bool(metadata.get("truncated")) or any(
            marker in normalized_error
            for marker in (
                "max iterations",
                "maximum iterations",
                "iteration budget",
                "turn budget",
            )
        )
        if not reached:
            return False

        configured = max(
            1,
            int(getattr(self.config.analysis, "max_tool_iterations", 50) or 50),
        )
        try:
            observed = int(metadata.get("iterations", configured) or configured)
        except (TypeError, ValueError):
            observed = configured
        observation = {
            "kind": "llm_iteration_budget",
            "agent": str(agent_name),
            "configured_iterations": configured,
            "observed_iterations": observed,
            "budget_reached": True,
            "outcome": str(outcome),
            "hard_failure": False,
        }
        observations = state.setdefault("budget_observations", [])
        if observation not in observations:
            observations.append(observation)
        logger.warning(
            "%s reached soft LLM iteration budget: observed=%d configured=%d "
            "outcome=%s; analysis result retained.",
            agent_name,
            observed,
            configured,
            outcome,
        )
        return True

    def _detect_local_rule_candidates(self, state: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Seed backend-appropriate local candidates before LLM validation."""
        entry_func = state["entry_func"]
        impl = state.get("impl_result") or {}
        code = str(impl.get("code") or "")
        file_path = str(impl.get("file") or "")
        profile = self._candidate_backend_profile()
        callee_scan = self._direct_callee_rule_scan_budget(state)
        issues: List[Dict[str, Any]] = []
        if self._project_language() == "java":
            java_generator = JavaRuleCandidateGenerator(
                rule_policy=getattr(self, "rule_policy", None)
            )
            issues.extend(
                java_generator.generate_issues(
                    entry_func,
                    code,
                    file_path,
                    annotations=self._java_annotation_context(impl),
                )
            )
            issues.extend(
                self._detect_java_entry_field_rule_candidates(
                    java_generator,
                    entry_func=entry_func,
                    impl=impl,
                )
            )
            issues.extend(
                self._detect_direct_callee_rule_candidates(
                    impl,
                    java_generator,
                    state=state,
                    entry_func=entry_func,
                    limit=callee_scan["limit"],
                    max_depth=callee_scan["max_depth"],
                    total_limit=callee_scan["total_limit"],
                )
            )
            issues.extend(self._detect_java_project_file_rule_candidates(java_generator))
        elif profile == "regex":
            regex_generator = RegexCandidateGenerator(
                self._get_local_pattern_semantics(),
                rule_policy=getattr(self, "rule_policy", None),
            )
            issues.extend(regex_generator.generate_issues(entry_func, code, file_path))
            issues.extend(
                self._detect_direct_callee_rule_candidates(
                    impl,
                    regex_generator,
                    state=state,
                    entry_func=entry_func,
                    limit=callee_scan["limit"],
                    max_depth=callee_scan["max_depth"],
                    total_limit=callee_scan["total_limit"],
                )
            )
        if self._project_language() != "java" and profile in {"clang", "unified"}:
            clang_generator = ClangAstCfgCandidateGenerator(
                self._get_local_pattern_semantics(),
                semantic_overlay=self._get_semantic_overlay(),
                tooling_evidence_provider=self._clang_tooling_evidence_for,
                rule_policy=getattr(self, "rule_policy", None),
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
                    rule_policy=getattr(self, "rule_policy", None),
                )
            )
            issues.extend(
                self._detect_direct_callee_rule_candidates(
                    impl,
                    clang_generator,
                    state=state,
                    entry_func=entry_func,
                    limit=callee_scan["limit"],
                    max_depth=callee_scan["max_depth"],
                    total_limit=callee_scan["total_limit"],
                )
            )
        issues.extend(self._detect_extension_rule_candidates(state))
        issues = dedupe_rule_candidates(issues)
        issues = self._apply_candidate_validation_budget(issues)
        self._record_engine_capability(
            "deterministic_local_rules",
            status="complete",
            active=True,
            candidate_count=len(issues),
        )
        if self._project_language() != "java" and profile in {"clang", "unified"}:
            self._record_engine_capability(
                "clang_ast_cfg",
                status="complete",
                active=True,
                candidate_count=sum(
                    1
                    for issue in issues
                    if str(issue.get("candidate_source") or "")
                    in {"clang_ast_cfg", "clang_ast_matcher"}
                ),
            )
        return self._annotate_candidate_issues(
            issues,
            checker=self._local_candidate_checker(),
            path_kind=(
                "local_java_security"
                if self._project_language() == "java"
                else "local_memory_concurrency"
            ),
        )

    def _detect_extension_rule_candidates(self, state: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Evaluate explicitly configured YAML packs and Python providers."""

        rules_config = getattr(getattr(self, "config", None), "rules", None)
        packs = list(getattr(rules_config, "packs", []) or [])
        providers = list(getattr(rules_config, "providers", []) or [])
        if not packs and not providers:
            return []
        registry = getattr(self, "_extension_rule_registry", None)
        if registry is None:
            registry = self.effective_rules.extension_registry
            if registry is None:
                raise RuntimeError(
                    "rule preflight did not retain the configured extension registry"
                )
            self._extension_rule_registry = registry

        impl = _as_dict(state.get("impl_result"))
        context = RuleContext(
            language=self._project_language(),
            project_root=Path(self.config.project.project_root),
            function=str(state.get("entry_func") or impl.get("function") or ""),
            file_path=str(impl.get("file") or ""),
            code=str(impl.get("code") or ""),
            annotations=(
                tuple(self._java_annotation_context(impl))
                if self._project_language() == "java"
                else ()
            ),
            metadata={"backend_profile": self._candidate_backend_profile()},
        )
        return [candidate.to_issue() for candidate in registry.evaluate(context)]

    def _detect_graph_rule_candidates(self, state: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Seed cross-function graph/protocol candidates before LLM validation."""
        entry_func = state["entry_func"]
        impl = state.get("impl_result") or {}
        budget = self._current_effective_budget(state)
        graph_depth = int(budget.get("graph_depth", 0) or 0)
        graph_functions = int(budget.get("graph_functions", 0) or 0)
        if graph_depth <= 0 or graph_functions <= 0:
            self._record_engine_capability(
                "graph_protocol",
                status="degraded",
                active=False,
                reason="deterministic_graph_budget_disabled",
            )
            return []
        # Deterministic graph facts are a prerequisite for validation, not an
        # expensive-reasoning budget.  Traverse the complete known project
        # graph from this entry.  ``GraphCandidateGenerator`` is cycle-safe,
        # and the function count provides the exact finite bound rather than
        # silently truncating at an adaptive per-entry quota.
        project_function_count = self._known_project_function_count()
        if project_function_count:
            graph_depth = max(graph_depth, project_function_count)
            graph_functions = max(graph_functions, project_function_count)
        generator = GraphCandidateGenerator(
            self.code_index,
            self._get_local_pattern_semantics(),
            semantic_overlay=self._get_semantic_overlay(),
            rule_policy=getattr(self, "rule_policy", None),
        )
        issues = generator.generate_for_entry(
            entry_func,
            impl,
            max_depth=graph_depth,
            max_functions=graph_functions,
        )
        issues = dedupe_rule_candidates(issues)
        for deferred in generator.last_deferred_functions:
            self._record_deferred_deterministic_work(
                state,
                engine="graph_protocol",
                function_name=str(deferred.get("function_name") or ""),
                reason=str(deferred.get("reason") or "graph_budget"),
                parent=str(deferred.get("parent") or ""),
            )
        for query_error in generator.last_query_errors:
            self._record_engine_failed_work(
                state,
                engine="graph_protocol",
                function_name=str(query_error.get("function_name") or entry_func),
                reason=str(query_error.get("error") or "graph_query_failed"),
            )
        graph_status = "complete"
        graph_reason = ""
        if generator.last_query_errors:
            graph_status = "failed"
            graph_reason = "graph_query_failed"
        elif generator.last_deferred_functions:
            graph_status = "degraded"
            graph_reason = "graph_fact_collection_truncated"
        self._record_engine_capability(
            "graph_protocol",
            status=graph_status,
            active=True,
            reason=graph_reason,
            candidate_count=len(issues),
            max_depth=graph_depth,
            max_functions=graph_functions,
            deferred_count=len(generator.last_deferred_functions),
            query_error_count=len(generator.last_query_errors),
        )
        return self._annotate_candidate_issues(
            issues,
            checker=self._graph_candidate_checker(),
            path_kind="cross_function_protocol",
        )

    def _known_project_function_count(self) -> int:
        """Return a finite complete bound for deterministic graph traversal.

        A CodeIndex already owns the indexed function set, so this is a cheap
        metadata query.  If a third-party index cannot enumerate functions we
        leave its configured bound untouched; any resulting truncation remains
        visible as degraded rather than being hidden.
        """

        list_functions = getattr(self.code_index, "list_functions", None)
        if not callable(list_functions):
            return 0
        try:
            functions = list_functions(limit=None)
        except Exception:
            logger.debug(
                "Unable to enumerate indexed functions for deterministic facts.", exc_info=True
            )
            return 0
        if not isinstance(functions, (list, tuple, set)):
            return 0
        return len({str(item) for item in functions if str(item)})

    @staticmethod
    def _apply_candidate_validation_budget(issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Prioritize broad candidates without turning a soft quota into loss.

        The previous implementation set ``validation_required=False`` and a
        ``deferred_budget`` disposition after a per-function quota.  That made
        an available Validator silently skip concrete security obligations.
        Quotas now affect queue priority only; every candidate keeps its normal
        validation lifecycle and an explicit telemetry marker records the soft
        overrun for later tuning.
        """
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
            category = (
                str(
                    issue.get("defect_class")
                    or issue.get("category")
                    or issue.get("subcategory")
                    or ""
                )
                .replace("-", "_")
                .lower()
            )
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
            issue["validation_budget_class"] = "generic_soft_overrun"
            issue["validation_priority"] = "normal"
            reason = (
                "Broad static candidate exceeded the per-function prioritization "
                "quota; retained for validation because budgets are observe-only."
            )
            issue["validation_budget_observation"] = reason
            pack = issue.get("evidence_pack")
            if isinstance(pack, dict):
                pack["validation_budget_observation"] = reason
                pack["validation_budget_class"] = "generic_soft_overrun"
        return ordered

    @staticmethod
    def _is_tp_sensitive_generic_candidate(issue: Dict[str, Any]) -> bool:
        category = (
            str(
                issue.get("defect_class") or issue.get("category") or issue.get("subcategory") or ""
            )
            .replace("-", "_")
            .lower()
        )
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
        return (
            group_order,
            generic_penalty,
            -confidence,
            str(issue.get("candidate_id") or issue.get("id") or ""),
        )

    def _direct_callee_rule_scan_budget(self, state: Dict[str, Any]) -> Dict[str, int]:
        budget = self._current_effective_budget(state)
        configured_breadth = int(budget.get("graph_functions") or 16)
        configured_depth = int(budget.get("graph_depth") or 2)
        limit = max(16, min(64, configured_breadth))
        max_depth = max(2, min(4, configured_depth))
        total_limit = max(80, min(256, limit * max_depth * 4))
        # As for graph candidates, direct-callee facts must not be silently
        # truncated because a local heuristic quota is small.  The indexed
        # function count is a finite, complete work bound for this traversal.
        project_function_count = self._known_project_function_count()
        if project_function_count:
            max_depth = max(max_depth, project_function_count)
            total_limit = max(total_limit, project_function_count)
        return {"limit": limit, "max_depth": max_depth, "total_limit": total_limit}

    def _detect_direct_callee_rule_candidates(
        self,
        impl: Dict[str, Any],
        generator: Any,
        *,
        state: Optional[Dict[str, Any]] = None,
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
        # Breadth is a prioritization hint only. Deterministic work must not
        # disappear without an explicit terminal disposition.
        queued = self._order_callee_work_queue(queued)
        impl_cache: Dict[str, Dict[str, Any]] = {root: impl} if root else {}
        visited: Set[str] = set()
        analyzed = 0
        engine_name = (
            "clang_ast_cfg"
            if isinstance(generator, ClangAstCfgCandidateGenerator)
            else "deterministic_local_rules"
        )
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
                self._record_engine_failed_work(
                    state,
                    engine=engine_name,
                    function_name=callee,
                    reason=f"{type(exc).__name__}: {exc}",
                    call_path=call_path,
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
                        rule_policy=getattr(self, "rule_policy", None),
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
            expand_dispatcher_siblings = depth >= max_depth and (
                self._looks_like_dispatcher_function(callee, callee_impl)
                or self._looks_like_boundary_fanout_function(callee, callee_impl)
            )
            if depth >= max_depth and not expand_dispatcher_siblings:
                for nested in callee_impl.get("callees", []):
                    nested_name = self._callee_item_name(nested)
                    if nested_name and nested_name not in visited and nested_name not in call_path:
                        self._record_deferred_deterministic_work(
                            state,
                            engine=engine_name,
                            function_name=nested_name,
                            reason="direct_callee_max_depth",
                            parent=callee,
                            call_path=call_path + [nested_name],
                        )
                continue
            nested_queue: List[tuple[str, int, List[str]]] = []
            for nested in callee_impl.get("callees", []):
                nested_name = self._callee_item_name(nested)
                if nested_name and nested_name not in visited and nested_name not in call_path:
                    nested_queue.append((nested_name, depth + 1, call_path + [nested_name]))
            queued.extend(nested_queue)
            queued = self._order_callee_work_queue(queued)
        if queued:
            for callee, _depth, call_path in queued:
                if callee in visited:
                    continue
                self._record_deferred_deterministic_work(
                    state,
                    engine=engine_name,
                    function_name=callee,
                    reason="direct_callee_total_limit",
                    call_path=call_path,
                )
        deferred_count = sum(
            1
            for item in (state or {}).get("deferred_deterministic_work", [])
            if str(item.get("engine") or "") == engine_name
            and str(item.get("candidate_disposition") or "") == "deferred_budget"
        )
        failed_count = sum(
            1
            for item in (state or {}).get("deferred_deterministic_work", [])
            if str(item.get("engine") or "") == engine_name
            and str(item.get("candidate_disposition") or "") == "engine_failed"
        )
        self._record_engine_capability(
            f"{engine_name}_callee_facts",
            status="failed" if failed_count else ("degraded" if deferred_count else "complete"),
            active=True,
            reason=(
                "direct_callee_query_failed"
                if failed_count
                else ("direct_callee_fact_collection_truncated" if deferred_count else "")
            ),
            analyzed_count=analyzed,
            deferred_count=deferred_count,
            failed_count=failed_count,
        )
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
        selected.extend(
            Analyzer._prioritize_callee_queue(remaining)[: max(0, limit - len(selected))]
        )
        return selected

    @staticmethod
    def _order_callee_work_queue(
        queue: List[tuple[str, int, List[str]]],
    ) -> List[tuple[str, int, List[str]]]:
        return sorted(queue, key=lambda item: item[1])

    @staticmethod
    def _prioritize_callee_queue(
        queue: List[tuple[str, int, List[str]]],
    ) -> List[tuple[str, int, List[str]]]:
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
            return str(
                item.get("name") or item.get("callee_name") or item.get("function") or ""
            ).strip()
        return str(item or "").strip()

    @staticmethod
    def _looks_like_dispatcher_function(func_name: str, impl: Dict[str, Any]) -> bool:
        """Return True for switch/fanout functions whose sibling callees deserve one extra scan."""
        code = str(impl.get("code") or "")
        callees = impl.get("callees") or []
        if len(callees) < 3:
            return False
        name_hint = re.search(
            r"(?:dispatch|handle|process|message|protocol|router|route)", func_name, re.I
        )
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
            callsite = self._clang_callsite_argument_refs(
                caller, callee, caller_impl
            ) or self._source_callsite_argument_refs(str(caller_impl.get("code") or ""), callee)
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
                    (
                        idx
                        for idx, row in enumerate(records)
                        if int(row.get("line") or 0) == before_line
                    ),
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
        if re.search(
            r"\b(?:bug_on|warn_on|check|validate|verify|bound|range|limit|max|min)\w*\s*\(", lowered
        ):
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
            self._record_engine_capability(
                "clang_tooling",
                status="complete",
                configured=False,
                active=False,
                reason="compile_commands_not_configured",
            )
            return {}
        cache_key = (func_name, file_path, int(start_line or 0), int(end_line or 0))
        cache = getattr(self, "_clang_tooling_evidence_cache", None)
        if isinstance(cache, dict) and cache_key in cache:
            return cast(Dict[str, Any], cache[cache_key])
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
            tooling_status = str(
                evidence.get("status") if isinstance(evidence, dict) else ""
            ).lower()
            execution_enabled = bool(
                evidence.get("execution_enabled") if isinstance(evidence, dict) else False
            )
            if tooling_status == "executed":
                ast_dump = evidence.get("ast_dump") or {}
                cfg_dump = evidence.get("cfg_dump") or {}
                if bool(ast_dump.get("ok")) and bool(cfg_dump.get("ok")):
                    capability_status = "complete"
                    reason = ""
                else:
                    capability_status = "degraded"
                    reason = "clang_ast_or_cfg_execution_failed"
            elif not execution_enabled:
                capability_status = "complete"
                reason = "optional_execution_disabled"
            else:
                capability_status = "degraded"
                reason = tooling_status or "clang_tooling_no_evidence"
            self._record_engine_capability(
                "clang_tooling",
                status=capability_status,
                configured=execution_enabled,
                active=tooling_status == "executed",
                reason=reason,
            )
            return evidence
        except Exception as exc:
            logger.warning("Unable to collect clang tooling evidence for %s: %s", func_name, exc)
            self._record_engine_capability(
                "clang_tooling",
                status="failed",
                configured=True,
                active=False,
                reason=f"{type(exc).__name__}: {exc}",
            )
            return {}

    @staticmethod
    def _clang_tooling_matcher_candidates_from_evidence(
        func_name: str,
        file_path: str,
        tooling_evidence: Dict[str, Any],
        *,
        allowed_skills: Optional[List[str]] = None,
        rule_policy: Optional[Any] = None,
    ) -> List[Dict[str, Any]]:
        return clang_tooling_matcher_candidates_from_evidence(
            func_name,
            file_path,
            tooling_evidence,
            allowed_skills=allowed_skills,
            rule_policy=rule_policy,
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
        if db is not None or profile == "joern":
            reachable_funcs = self._reachable_function_names_from_entry(
                entry_func,
                state=state,
            )
        reachable_duration = time.time() - reachable_started
        # Reuse the complete cheap reachability fact set across backends.
        # A second, smaller view silently excluded candidates already known to
        # be reachable.
        scope_reachable_funcs = reachable_funcs
        if db is not None:
            try:
                bugs, legacy_query = self._collect_enriched_taint_bugs(
                    db,
                    reachable_funcs=reachable_funcs,
                    entry_func=entry_func,
                )
            except Exception as exc:
                logger.warning("Unable to read backend taint bugs: %s", exc)
                self._record_engine_capability(
                    "svf_taint_query",
                    status="failed",
                    active=False,
                    reason=f"{type(exc).__name__}: {exc}",
                )
                self._record_engine_failed_work(
                    state,
                    engine="svf_taint_query",
                    function_name=entry_func,
                    reason=f"{type(exc).__name__}: {exc}",
                )
                bugs = []
            else:
                self._record_engine_capability(
                    "svf_taint_query",
                    status="degraded" if legacy_query else "complete",
                    active=True,
                    reason=("legacy_non_paginated_query" if legacy_query else ""),
                    candidate_count=len(bugs),
                )

            svf_candidates = SvfValueFlowCandidateGenerator(
                source_path_resolver=self._reconstruct_svf_source_path,
            ).generate_issues(
                bugs,
                entry_func=entry_func,
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

    @staticmethod
    def _collect_enriched_taint_bugs(
        db: Any,
        *,
        reachable_funcs: Set[str],
        entry_func: str,
        page_size: int = 500,
    ) -> tuple[List[Dict[str, Any]], bool]:
        """Collect the complete cheap taint fact set, paging when supported."""

        getter = db.get_enriched_taint_bugs
        supports_offset = Analyzer._callable_accepts_keyword(getter, "offset")
        if supports_offset is False:
            return (
                Analyzer._collect_legacy_enriched_taint_bugs(
                    getter,
                    reachable_funcs=reachable_funcs,
                    entry_func=entry_func,
                ),
                True,
            )
        results: List[Dict[str, Any]] = []
        offset = 0
        seen_pages: Set[str] = set()
        page_count = 0
        try:
            while True:
                page = getter(
                    func_names=sorted(reachable_funcs),
                    limit=page_size,
                    offset=offset,
                )
                raw_page = list(page or [])
                results.extend(item for item in raw_page if isinstance(item, dict))
                if len(raw_page) < page_size:
                    return results, False
                page_count += 1
                fingerprint = Analyzer._deterministic_page_fingerprint(raw_page)
                if fingerprint in seen_pages:
                    raise RuntimeError(
                        "Taint pagination did not advance; adapter may ignore offset"
                    )
                seen_pages.add(fingerprint)
                if page_count >= 10_000:
                    raise RuntimeError("Taint pagination exceeded the 5,000,000-row safety bound")
                offset += len(raw_page)
        except TypeError as exc:
            if supports_offset is not None or not Analyzer._is_unexpected_keyword_error(
                exc,
                "offset",
            ):
                raise
            return (
                Analyzer._collect_legacy_enriched_taint_bugs(
                    getter,
                    reachable_funcs=reachable_funcs,
                    entry_func=entry_func,
                ),
                True,
            )

    @staticmethod
    def _collect_legacy_enriched_taint_bugs(
        getter: Any,
        *,
        reachable_funcs: Set[str],
        entry_func: str,
    ) -> List[Dict[str, Any]]:
        """One-release fallback for adapters without pagination support."""

        supports_func_names = Analyzer._callable_accepts_keyword(
            getter,
            "func_names",
        )
        if supports_func_names is not False:
            try:
                rows = getter(
                    func_names=sorted(reachable_funcs),
                    limit=1_000_000,
                )
                return [item for item in (rows or []) if isinstance(item, dict)]
            except TypeError as exc:
                if supports_func_names is not None or not Analyzer._is_unexpected_keyword_error(
                    exc,
                    "func_names",
                ):
                    raise
        rows = getter(func_name=entry_func, limit=1_000_000)
        return [item for item in (rows or []) if isinstance(item, dict)]

    @staticmethod
    def _callable_accepts_keyword(callable_obj: Any, keyword: str) -> Optional[bool]:
        try:
            parameters = inspect.signature(callable_obj).parameters.values()
        except (TypeError, ValueError):
            return None
        return any(
            parameter.kind == inspect.Parameter.VAR_KEYWORD
            or (
                parameter.name == keyword
                and parameter.kind
                in {
                    inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    inspect.Parameter.KEYWORD_ONLY,
                }
            )
            for parameter in parameters
        )

    @staticmethod
    def _is_unexpected_keyword_error(exc: TypeError, keyword: str) -> bool:
        message = str(exc).lower()
        normalized_keyword = str(keyword).lower()
        return normalized_keyword in message and any(
            marker in message
            for marker in (
                "unexpected keyword",
                "invalid keyword",
                "keyword argument",
                "takes no keyword",
            )
        )

    @staticmethod
    def _deterministic_page_fingerprint(page: Sequence[Any]) -> str:
        return hashlib.sha256(
            json.dumps(
                list(page),
                ensure_ascii=False,
                sort_keys=True,
                default=str,
            ).encode("utf-8")
        ).hexdigest()

    def _merge_unified_evidence_candidates(
        self, candidates: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        if self._project_language() == "java":
            return merge_java_evidence_candidates(candidates)
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
    def _attach_unified_secondary_evidence(
        primary: Dict[str, Any], secondary: Dict[str, Any]
    ) -> None:
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
                state=state,
            )
        candidates: List[Dict[str, Any]] = []
        rows_seen = 0
        query_failures = 0
        legacy_queries = 0
        for acquire, release, pair_source in pairs:
            try:
                rows, legacy_query = self._collect_missing_release_rows(
                    find_missing,
                    acquire,
                    release,
                )
            except Exception as exc:
                logger.warning("Unable to query KnowledgeDB pair %s/%s: %s", acquire, release, exc)
                query_failures += 1
                self._record_engine_failed_work(
                    state,
                    engine="clang_knowledge_db",
                    function_name=f"{acquire}->{release}",
                    reason=f"{type(exc).__name__}: {exc}",
                )
                continue
            legacy_queries += int(legacy_query)
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
        capability_status = "complete"
        capability_reason = ""
        if query_failures and query_failures >= len(pairs):
            capability_status = "failed"
            capability_reason = "all_resource_pair_queries_failed"
        elif query_failures:
            capability_status = "degraded"
            capability_reason = f"{query_failures}_resource_pair_queries_failed"
        elif legacy_queries:
            capability_status = "degraded"
            capability_reason = f"{legacy_queries}_legacy_non_paginated_queries"
        self._record_engine_capability(
            "clang_knowledge_db",
            status=capability_status,
            active=True,
            reason=capability_reason,
            query_count=len(pairs),
            failed_query_count=query_failures,
            legacy_query_count=legacy_queries,
            candidate_count=len(candidates),
        )
        return candidates

    @staticmethod
    def _collect_missing_release_rows(
        query: Any,
        acquire: str,
        release: str,
        *,
        page_size: int = 500,
    ) -> tuple[List[Dict[str, Any]], bool]:
        supports_offset = Analyzer._callable_accepts_keyword(query, "offset")
        if supports_offset is False:
            legacy_rows = query(
                acquire,
                release,
                limit=1_000_000,
            )
            return [item for item in (legacy_rows or []) if isinstance(item, dict)], True
        rows: List[Dict[str, Any]] = []
        offset = 0
        seen_pages: Set[str] = set()
        page_count = 0
        try:
            while True:
                page = query(
                    acquire,
                    release,
                    limit=page_size,
                    offset=offset,
                )
                raw_page = list(page or [])
                rows.extend(item for item in raw_page if isinstance(item, dict))
                if len(raw_page) < page_size:
                    return rows, False
                page_count += 1
                fingerprint = Analyzer._deterministic_page_fingerprint(raw_page)
                if fingerprint in seen_pages:
                    raise RuntimeError(
                        "Resource-pair pagination did not advance; adapter may ignore offset"
                    )
                seen_pages.add(fingerprint)
                if page_count >= 10_000:
                    raise RuntimeError(
                        "Resource-pair pagination exceeded the 5,000,000-row safety bound"
                    )
                offset += len(raw_page)
        except TypeError as exc:
            if supports_offset is not None or not Analyzer._is_unexpected_keyword_error(
                exc,
                "offset",
            ):
                raise
            legacy_rows = query(
                acquire,
                release,
                limit=1_000_000,
            )
            return [item for item in (legacy_rows or []) if isinstance(item, dict)], True

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
        if self._candidate_backend_profile() not in {"joern", "java_unified"}:
            return []
        backend_attr = getattr(self.code_index, "backend", None)
        backend = backend_attr() if callable(backend_attr) else backend_attr
        collect_java_signals = getattr(backend, "collect_java_signal_matches", None)
        if callable(collect_java_signals):
            entry_func = str(state.get("entry_func") or "")
            try:
                matches = collect_java_signals(entry_func=entry_func)
            except Exception as exc:
                logger.warning("Unable to collect Java provider signals: %s", exc)
                self._record_engine_capability(
                    "java_signal_providers",
                    status="failed",
                    active=False,
                    reason=f"{type(exc).__name__}: {exc}",
                )
                return []
            if reachable_funcs is None:
                reachable_funcs = self._reachable_function_names_from_entry(entry_func)
            candidates = []
            for match in matches:
                if not isinstance(match, dict):
                    candidates.append(self._joern_rule_match_to_candidate(match, entry_func))
                    continue
                target = self._java_provider_signal_target_function(match, entry_func)
                if target and not self._target_in_reachable_functions(target, reachable_funcs):
                    continue
                candidates.append(java_provider_signal_to_candidate(match, entry_func=entry_func))
            self._record_engine_capability(
                "java_signal_providers",
                status="complete",
                active=True,
                candidate_count=len(candidates),
            )
            return candidates
        joern_client = getattr(backend, "joern_client", None)
        if joern_client is None:
            self._record_engine_capability(
                "joern_candidate_rules",
                status="failed",
                active=False,
                reason="joern_client_unavailable",
            )
            return []
        try:
            from ...rules.engine import RuleEngine

            engine = RuleEngine(joern_client, self.user_config)
            matches = engine.run_builtin_scan()
            matches.extend(engine.run_semantic_cpg_rule_library())
            matches.extend(engine.run_paired_function_checks())
            matches.extend(engine.run_configured_data_flow_checks())
        except Exception as exc:
            logger.warning("Unable to run Joern CPG candidate checks: %s", exc)
            self._record_engine_capability(
                "joern_candidate_rules",
                status="failed",
                active=False,
                reason=f"{type(exc).__name__}: {exc}",
            )
            return []
        entry_func = str(state.get("entry_func") or "")
        if reachable_funcs is None:
            reachable_funcs = self._reachable_function_names_from_entry(
                entry_func,
                state=state,
            )
        scoped = [
            match
            for match in matches
            if self._target_in_reachable_functions(
                str(getattr(match, "func_name", "")), reachable_funcs
            )
        ]
        candidates = [self._joern_rule_match_to_candidate(match, entry_func) for match in scoped]
        self._record_engine_capability(
            "joern_candidate_rules",
            status="complete",
            active=True,
            candidate_count=len(candidates),
        )
        return candidates

    @staticmethod
    def _java_provider_signal_target_function(signal: Dict[str, Any], entry_func: str = "") -> str:
        sink = _as_dict(signal.get("sink"))
        source = _as_dict(signal.get("source"))
        path = _as_list(signal.get("path"))
        for value in (
            sink.get("function"),
            sink.get("method"),
            source.get("function"),
            source.get("method"),
        ):
            if str(value or "").strip():
                return str(value)
        for item in reversed(path):
            if isinstance(item, dict):
                value = item.get("method") or item.get("function")
                if str(value or "").strip():
                    return str(value)
        return entry_func

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

    def _reachable_cache_state(
        self,
    ) -> tuple[Dict[tuple[str, int, int, int], Set[str]], threading.RLock]:
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
        return any(self._function_names_may_match(name, target_func) for name in reachable_funcs)

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
            self._record_engine_capability(
                "call_path_query",
                status="complete",
                active=True,
                visited_count=1,
            )
            return [entry_func]
        get_callees = getattr(self.code_index, "get_callees", None)
        if not callable(get_callees):
            self._record_engine_capability(
                "call_path_query",
                status="failed",
                active=False,
                reason="call_graph_query_unavailable",
            )
            return []
        seen = {entry_func}
        queue: List[tuple[str, int, List[str]]] = [(entry_func, 0, [entry_func])]
        while queue and len(seen) < max_nodes:
            current, depth, path = queue.pop(0)
            if depth >= max_depth:
                continue
            try:
                callees = get_callees(current, limit=100)
            except Exception as exc:
                self._record_engine_capability(
                    "call_path_query",
                    status="failed",
                    active=True,
                    reason=f"{type(exc).__name__}: {exc}",
                    failed_function=current,
                )
                continue
            for item in callees or []:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name") or item.get("callee_name") or "").strip()
                if not name or name in seen:
                    continue
                next_path = path + [name]
                if self._function_names_may_match(name, target_func):
                    self._record_engine_capability(
                        "call_path_query",
                        status="complete",
                        active=True,
                        visited_count=len(seen) + 1,
                    )
                    return next_path
                seen.add(name)
                queue.append((name, depth + 1, next_path))
        self._record_engine_capability(
            "call_path_query",
            status=("degraded" if queue or len(seen) >= max_nodes else "complete"),
            active=True,
            reason=("call_path_search_budget_exhausted" if queue or len(seen) >= max_nodes else ""),
            visited_count=len(seen),
        )
        return []

    def _reachable_function_names_from_entry(
        self,
        entry_func: str,
        *,
        max_depth: Optional[int] = None,
        max_nodes: Optional[int] = None,
        callee_limit: int = 1_000_000,
        state: Optional[Dict[str, Any]] = None,
    ) -> Set[str]:
        if not entry_func:
            return set()
        depth_limit = int(max_depth) if max_depth is not None and int(max_depth) > 0 else None
        node_limit = int(max_nodes) if max_nodes is not None and int(max_nodes) > 0 else None
        query_limit = max(1, int(callee_limit or 1_000_000))
        cache_key = (
            entry_func,
            depth_limit if depth_limit is not None else -1,
            node_limit if node_limit is not None else -1,
            query_limit,
        )
        cache, lock = self._reachable_cache_state()
        with lock:
            cached = cache.get(cache_key)
            if cached is not None:
                return set(cached)
        reachable: Set[str] = {entry_func}
        get_callees = getattr(self.code_index, "get_callees", None)
        if not callable(get_callees):
            self._record_engine_capability(
                "reachable_scope_query",
                status="failed",
                active=False,
                reason="call_graph_query_unavailable",
            )
            with lock:
                cache[cache_key] = set(reachable)
            return reachable
        queue: deque[tuple[str, int]] = deque([(entry_func, 0)])
        depth_capped = False
        while queue and (node_limit is None or len(reachable) < node_limit):
            current, depth = queue.popleft()
            if depth_limit is not None and depth >= depth_limit:
                depth_capped = True
                self._record_deferred_deterministic_work(
                    state,
                    engine="reachable_scope_query",
                    function_name=current,
                    reason="reachable_scope_max_depth",
                )
                continue
            try:
                callees = get_callees(current, limit=query_limit)
            except Exception as exc:
                self._record_engine_capability(
                    "reachable_scope_query",
                    status="failed",
                    active=True,
                    reason=f"{type(exc).__name__}: {exc}",
                    failed_function=current,
                )
                self._record_engine_failed_work(
                    state,
                    engine="reachable_scope_query",
                    function_name=current,
                    reason=f"{type(exc).__name__}: {exc}",
                )
                continue
            for item in callees or []:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name") or item.get("callee_name") or "").strip()
                if not name or name in reachable:
                    continue
                if node_limit is not None and len(reachable) >= node_limit:
                    self._record_deferred_deterministic_work(
                        state,
                        engine="reachable_scope_query",
                        function_name=name,
                        reason="reachable_scope_max_nodes",
                        parent=current,
                    )
                    continue
                reachable.add(name)
                queue.append((name, depth + 1))
        with lock:
            cache[cache_key] = set(reachable)
        if node_limit is not None and len(reachable) >= node_limit:
            for deferred_name, _depth in queue:
                self._record_deferred_deterministic_work(
                    state,
                    engine="reachable_scope_query",
                    function_name=deferred_name,
                    reason="reachable_scope_max_nodes",
                )
        budget_exhausted = (
            bool(queue) or (node_limit is not None and len(reachable) >= node_limit) or depth_capped
        )
        self._record_engine_capability(
            "reachable_scope_query",
            status="degraded" if budget_exhausted else "complete",
            active=True,
            reason=("reachable_scope_budget_exhausted" if budget_exhausted else ""),
            reachable_count=len(reachable),
            max_depth=depth_limit,
            max_nodes=node_limit,
            callee_limit=query_limit,
        )
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
        source_impl = (
            self._compact_function_impl(source_func)
            if source_func and source_func != target_func
            else {}
        )
        sink_impl = (
            self._compact_function_impl(sink_func)
            if sink_func and sink_func not in {target_func, source_func}
            else {}
        )
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
            notes.append(
                "Entry-to-target call path was not proven by CodeIndex within the bounded search."
            )
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
            bug.get("source_symbol") or bug.get("source_func") or bug.get("source") or ""
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
                symbol for symbol in object_symbols if re.search(rf"\b{re.escape(symbol)}\b", code)
            ][:8]
        notes = []
        if source_symbol and not source_event:
            notes.append(
                f"Source symbol `{source_symbol}` was not found in compact source contexts."
            )
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
        except Exception as exc:
            self._record_engine_capability(
                "source_reconstruction",
                status="degraded",
                active=True,
                reason=f"source_snippet:{type(exc).__name__}: {exc}",
                failed_file=file_path,
                failed_line=line,
            )
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
            except Exception as exc:
                self._record_engine_capability(
                    "source_reconstruction",
                    status="degraded",
                    active=True,
                    reason=f"function_impl:{type(exc).__name__}: {exc}",
                    failed_function=func_name,
                )
                return {}
        except Exception as exc:
            self._record_engine_capability(
                "source_reconstruction",
                status="degraded",
                active=True,
                reason=f"function_impl:{type(exc).__name__}: {exc}",
                failed_function=func_name,
            )
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

    def _project_language(self) -> str:
        config = getattr(self, "config", None)
        project = getattr(config, "project", None)
        language = (
            str(
                getattr(project, "language", "")
                or getattr(getattr(self, "code_index", None), "language", "")
                or "c_cpp"
            )
            .strip()
            .lower()
            .replace("-", "_")
        )
        return "java" if language in {"java", "java_src", "javasrc"} else "c_cpp"

    def _get_semantic_overlay(self) -> Dict[str, Any]:
        if self._semantic_overlay is None:
            raise RuntimeError("authoritative_security_spec_overlay_not_prepared")
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
        config = getattr(self, "config", None)
        project = getattr(config, "project", None)
        project_root = Path(
            str(
                getattr(project, "project_root", "")
                or getattr(self.code_index, "project_root", "")
                or "."
            )
        )
        project_id = str(getattr(project, "project_id", "") or project_root.name or "project")
        configured_entry_identity = ""
        configured_entry_function = str(getattr(project, "entry_function", "") or "").strip()
        if project is not None and configured_entry_function:
            configured_entry_identity = FunctionEntry(
                function_name=configured_entry_function,
                file_path=str(getattr(project, "entry_file_path", "") or "") or None,
                signature=str(getattr(project, "entry_signature", "") or "") or None,
            ).identity_key(project_root)
        revision = str(getattr(getattr(self, "candidate_ledger", None), "revision", "") or "")
        governed: List[Dict[str, Any]] = []
        for raw_issue in issues:
            issue = raw_issue
            if path_kind == "backend_signal":
                issue["candidate_kind"] = "backend_signal"
                issue.setdefault(
                    "signal_source",
                    str(issue.get("candidate_source") or issue.get("finding_kind") or checker),
                )
                issue.setdefault(
                    "native_rule_id",
                    str(issue.get("rule_id") or issue.get("rule") or ""),
                )
            else:
                rule_id = str(issue.get("rule_id") or issue.get("rule") or "")
                effective_rules = getattr(self, "effective_rules", None)
                rule_policy = getattr(self, "rule_policy", None)
                if effective_rules is not None and rule_policy is not None:
                    state = effective_rules.state_for(rule_id)
                    if state is not None and state.state == "disabled":
                        # First-layer generator filtering is an optimization.
                        # This second gate is authoritative and prevents a
                        # disabled candidate from reaching merge or reporting.
                        continue
                    issue = rule_policy.enrich_issue(issue)
                issue["candidate_kind"] = "deterministic_rule"
            raw_evidence_pack = issue.get("evidence_pack")
            evidence_pack: Dict[str, Any] = (
                raw_evidence_pack if isinstance(raw_evidence_pack, dict) else {}
            )
            issue_checker = str(
                issue.get("evidence_checker") or evidence_pack.get("checker") or checker
            )
            annotate_candidate_evidence(
                issue,
                backend_profile=profile,
                checker=issue_checker,
                overlay=overlay,
                path_kind=path_kind,
            )
            entry_identity = str(
                issue.get("entry_identity")
                or configured_entry_identity
                or issue.get("entry_function")
                or issue.get("entry_func")
                or ""
            )
            issue.setdefault("entry_identity", entry_identity)
            issue["decision_fact_graph_v1"] = True
            issue["security_obligation_v1"] = True
            issue["decision_context_v31"] = True
            issue["decision_context_v32"] = True
            issue["decision_context_v33"] = True
            envelope = annotate_issue_identity(
                issue,
                project_id=project_id,
                project_root=str(project_root),
                revision=revision,
                entry_function=entry_identity,
                default_disposition="needs_review",
                decision_fact_cache=getattr(self, "decision_fact_cache", None),
            )
            annotated_evidence_pack = issue.get("evidence_pack")
            if isinstance(annotated_evidence_pack, dict):
                annotated_evidence_pack.update(
                    {
                        "candidate_schema_version": envelope.schema_version,
                        "candidate_uid": envelope.candidate_uid,
                        "occurrence_uid": envelope.occurrence_uid,
                        "history_key": envelope.history_key,
                        "evidence_hash": envelope.evidence_hash,
                        "decision_evidence_hash": envelope.decision_evidence_hash,
                        "provenance_hash": envelope.provenance_hash,
                        "validation_cluster_uid": envelope.validation_cluster_uid,
                        "context_signature": envelope.context_signature,
                        "entry_identity": entry_identity,
                    }
                )
            governed.append(issue)
        return governed

    def _register_candidate_issues(
        self,
        state: Dict[str, Any],
        issues: Sequence[Dict[str, Any]],
        *,
        source: str,
    ) -> None:
        """Enter every discovered candidate into the scan-level lifecycle ledger."""

        ledger = state.get("candidate_ledger")
        if not isinstance(ledger, CandidateLedger):
            return
        project = self.config.project
        entry_identity = str(
            state.get("entry_identity")
            or FunctionEntry(
                function_name=str(project.entry_function or ""),
                file_path=str(getattr(project, "entry_file_path", "") or "") or None,
                signature=str(getattr(project, "entry_signature", "") or "") or None,
            ).identity_key(project.project_root)
        )
        for issue in issues:
            if not isinstance(issue, dict):
                continue
            issue.setdefault("entry_identity", entry_identity)
            issue["decision_fact_graph_v1"] = True
            issue["security_obligation_v1"] = True
            issue["decision_context_v31"] = True
            issue["decision_context_v32"] = True
            issue["decision_context_v33"] = True
            envelope = annotate_issue_identity(
                issue,
                project_id=str(getattr(project, "project_id", "") or project.project_root.name),
                project_root=str(project.project_root),
                revision=str(getattr(ledger, "revision", "") or ""),
                entry_function=entry_identity,
                run_id=str(state.get("run_id") or ""),
                default_disposition="needs_review",
                decision_fact_cache=getattr(self, "decision_fact_cache", None),
            )
            evidence = dict(issue.get("evidence_pack") or {})
            evidence.update(
                {
                    "candidate_id": str(issue.get("candidate_id") or issue.get("id") or ""),
                    "candidate_schema_version": envelope.schema_version,
                    "candidate_uid": envelope.candidate_uid,
                    "occurrence_uid": envelope.occurrence_uid,
                    "history_key": envelope.history_key,
                    "obligation_uid": envelope.obligation_uid,
                    "obligation_shape": envelope.obligation_shape,
                    "decision_context_version": envelope.decision_context_version,
                    "decision_fact_version": issue.get("decision_fact_version")
                    or envelope.decision_fact_version,
                    "decision_fact_coverage": issue.get("decision_fact_coverage"),
                    "decision_fact_slice": deepcopy(issue.get("decision_fact_slice") or {}),
                    "missing_fact_kinds": list(issue.get("missing_fact_kinds") or []),
                    "security_obligation": deepcopy(issue.get("security_obligation") or {}),
                    "candidate_promotion_eligible": issue.get("candidate_promotion_eligible"),
                    "candidate_promotion_reason": issue.get("candidate_promotion_reason"),
                    "candidate_promotion_terminal_status": issue.get(
                        "candidate_promotion_terminal_status"
                    ),
                    "evidence_hash": envelope.evidence_hash,
                    "decision_evidence_hash": envelope.decision_evidence_hash,
                    "provenance_hash": envelope.provenance_hash,
                    "validation_cluster_uid": envelope.validation_cluster_uid,
                    "context_signature": envelope.context_signature,
                    "entry_identity": entry_identity,
                    "record_role": "validation_obligation",
                    "defect_class": str(
                        issue.get("defect_class")
                        or issue.get("subcategory")
                        or issue.get("category")
                        or ""
                    ),
                    "source": issue.get("source") or evidence.get("source"),
                    "sink": issue.get("sink") or evidence.get("sink"),
                    "resource": (
                        issue.get("resource_signature")
                        or issue.get("resource")
                        or evidence.get("resource")
                    ),
                    "positive_evidence": issue.get("positive_evidence") or [],
                    "negative_evidence": issue.get("negative_evidence") or [],
                    # Preserve the reportable candidate independently from the
                    # entry workflow state.  If an entry is later interrupted,
                    # the scan-level ledger can still route this evidence to
                    # needs_review instead of emitting an identity-only record.
                    "candidate_payload": {
                        key: value
                        for key, value in issue.items()
                        if key
                        not in {
                            "evidence_pack",
                            "code_snippet",
                            "candidate_payload",
                        }
                    },
                }
            )
            raw_paths = issue.get("call_paths")
            if isinstance(raw_paths, list) and raw_paths and isinstance(raw_paths[0], list):
                call_paths = raw_paths
            else:
                raw_path = issue.get("call_path")
                call_paths = [raw_path] if isinstance(raw_path, list) else []
            if not call_paths:
                call_paths = [[entry_identity]]
            for call_path in call_paths:
                ticket = CandidateTicket(
                    id=str(issue.get("candidate_id") or issue.get("id") or envelope.run_issue_uid),
                    skill=str(
                        issue.get("skill")
                        or issue.get("defect_class")
                        or issue.get("subcategory")
                        or issue.get("category")
                        or "security_review"
                    ),
                    task=str(
                        issue.get("description") or issue.get("root_cause") or "Validate candidate"
                    ),
                    trigger=str(
                        issue.get("rule") or issue.get("sink") or issue.get("category") or ""
                    ),
                    line=int(
                        issue.get("line")
                        or parse_issue_location(str(issue.get("location") or ""))[1]
                        or 0
                    ),
                    context_slice=str(issue.get("code_snippet") or ""),
                    priority_score=self._candidate_priority_score(issue),
                    priority_reasons=[source],
                    origin=str(issue.get("source") or issue.get("location") or ""),
                    sink=str(issue.get("sink") or issue.get("location") or ""),
                    resource_kind=str(
                        issue.get("resource_signature") or issue.get("resource") or "unknown"
                    ),
                    source=str(issue.get("candidate_source") or source),
                    evidence=dict(evidence),
                )
                ledger.add(
                    ticket,
                    source=str(issue.get("candidate_source") or source),
                    call_path=call_path,
                    record_role="validation_obligation",
                    entry_identity=entry_identity,
                )
        state["candidate_ledger_context"] = ledger.to_context()
        state["candidate_ledger_summary"] = ledger.summary()

    @staticmethod
    def _candidate_priority_score(issue: Dict[str, Any]) -> int:
        explicit = issue.get("priority_score")
        if explicit not in (None, ""):
            try:
                return max(0, min(100, int(float(str(explicit)))))
            except (TypeError, ValueError):
                pass
        severity = str(issue.get("impact_level") or "").lower()
        base = {"critical": 95, "high": 85, "medium": 65, "low": 35}.get(
            severity,
            60,
        )
        try:
            confidence = float(issue.get("rule_confidence") or issue.get("confidence") or 0.0)
        except (TypeError, ValueError):
            confidence = 0.0
        return max(base, min(100, int(round(confidence * 100))))

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

    def _get_local_pattern_semantics(self) -> LocalPatternSemantics:
        """Return qualification-backed semantics compiled for this scan."""
        if self._local_pattern_semantics is None:
            raise RuntimeError("authoritative_security_spec_semantics_not_prepared")
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
    def _callgraph_cache_stat_delta(
        before: Dict[str, int], after: Dict[str, int]
    ) -> Dict[str, int]:
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
        lock = getattr(self, "_candidate_ir_persistence_lock", None)
        if lock is not None:
            with lock:
                self._persist_candidate_ir_records_locked(issues)
            return
        self._persist_candidate_ir_records_locked(issues)

    def _persist_candidate_ir_records_locked(self, issues: List[Dict[str, Any]]) -> None:
        """Persist one batch while the shared KnowledgeDB writer is held."""
        db = self._get_knowledge_db()
        if db is None:
            return

        persisted = 0
        failures: List[str] = []
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
                    contradictions=json.dumps(
                        issue.get("negative_evidence") or [], ensure_ascii=False
                    ),
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
                persisted += 1
            except Exception as exc:
                message = f"{type(exc).__name__}: {exc}"
                failures.append(message)
                logger.warning(
                    "Failed to persist candidate IR for %s: %s",
                    issue.get("id"),
                    exc,
                )
        try:
            db.commit()
        except Exception as exc:
            failures.append(f"commit:{type(exc).__name__}: {exc}")
            logger.warning("Failed to commit candidate IR records: %s", exc)

        if failures:
            self._record_engine_capability(
                "candidate_ir_persistence",
                status="failed" if persisted == 0 else "degraded",
                active=False if persisted == 0 else True,
                reason="candidate_ir_persistence_failed",
                persisted_count=persisted,
                failure_count=len(failures),
                errors=failures[:16],
            )
        else:
            self._record_engine_capability(
                "candidate_ir_persistence",
                status="complete",
                active=True,
                persisted_count=persisted,
            )

    def _step_validate_findings(self, state: Dict[str, Any]) -> None:
        # Preserve compatibility for focused callers/tests that construct the
        # legacy facade without running ``__init__``.
        if getattr(self, "defer_validation_to_scan", False):
            pending = len(state.get("pending_new_issues") or [])
            if pending:
                state.setdefault("notes", []).append(
                    f"Deferred {pending} deterministic candidate(s) to the scan-level validation queue."
                )
            # Candidate records have already been atomically registered in
            # the shared ledger.  Do not create an entry-local validation
            # future: it would race another wrapper occurrence and defeat the
            # v3 validation_cluster_uid contract.
            state["pending_new_issues"] = []
            return
        ledger = state.get("candidate_ledger")
        if isinstance(ledger, CandidateLedger):
            # Candidate-blind discovery is the final producer for a
            # single-entry scan.  Seal the obligation set before V0-V3 starts
            # so late producers cannot evade this validation pass.
            ledger.freeze()
        runner = getattr(self, "validation_runner", None)
        if runner is None:
            runner = self._make_validation_runner()
            self.validation_runner = runner
        runner.run(state)
        state.update(
            self._validator_v3_outcome_summary(
                [
                    item
                    for item in [
                        *list(state.get("issues") or []),
                        *list(state.get("observations") or []),
                    ]
                    if isinstance(item, dict)
                ]
            )
        )

    @staticmethod
    def _validator_v3_outcome_summary(issues: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregate single-entry V1→V3 fact and verdict telemetry."""

        transitions: Dict[str, int] = {}
        fact_by_kind: Dict[str, Dict[str, int]] = {}
        fact_terminal_statuses: Dict[str, int] = {}
        fact_completed = 0
        fact_requested = 0
        for issue in issues:
            raw_resolutions = issue.get("validator_fact_resolutions")
            resolutions = (
                [item for item in raw_resolutions if isinstance(item, dict)]
                if isinstance(raw_resolutions, list)
                else []
            )
            legacy = issue.get("validator_fact_resolution")
            if not resolutions and isinstance(legacy, dict):
                resolutions = [legacy]
            for resolution in resolutions:
                fact_requested += 1
                status = str(
                    resolution.get("terminal_status") or resolution.get("status") or "unknown"
                )
                if status in {"resolved", "completed", "completed_partial", "completed_with_proof"}:
                    fact_completed += 1
                fact_terminal_statuses[status] = fact_terminal_statuses.get(status, 0) + 1
                kind = str(resolution.get("fact_kind") or "unknown")
                by_status = fact_by_kind.setdefault(kind, {})
                by_status[status] = by_status.get(status, 0) + 1
            history = issue.get("validator_pass_history")
            if not isinstance(history, list):
                continue
            normalized = [item for item in history if isinstance(item, dict)]
            for before, after in zip(normalized, normalized[1:]):
                key = "{before_pass}:{before_verdict}->{after_pass}:{after_verdict}".format(
                    before_pass=str(before.get("pass") or "unknown"),
                    before_verdict=str(before.get("verdict") or "unknown"),
                    after_pass=str(after.get("pass") or "unknown"),
                    after_verdict=str(after.get("verdict") or "unknown"),
                )
                transitions[key] = int(transitions.get(key, 0) or 0) + 1
        return {
            "validator_verdict_transitions": dict(sorted(transitions.items())),
            "validator_fact_request_count": fact_requested,
            "validator_fact_resolution_success_count": fact_completed,
            "validator_fact_resolution_success_rate": (
                round(fact_completed / fact_requested, 4) if fact_requested else None
            ),
            "validator_fact_resolution_by_kind": {
                kind: dict(sorted(statuses.items()))
                for kind, statuses in sorted(fact_by_kind.items())
            },
            "validator_fact_terminal_status_counts": dict(sorted(fact_terminal_statuses.items())),
        }

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
            result_cache=getattr(self, "validation_result_cache", None),
            scheduler=getattr(self, "scheduler", None),
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

    def _score_components(
        self, issue: Dict[str, Any], val_data: Dict[str, Any]
    ) -> Dict[str, float]:
        pipeline = getattr(self, "validation_pipeline", None)
        if pipeline is None:
            user_config = getattr(self, "user_config", None)
            if user_config is None:

                class EmptyUserConfig:
                    def get_finding_baseline(self, _dedup_key: str) -> None:
                        return None

                user_config = EmptyUserConfig()
            pipeline = ValidationPipeline(
                user_config,
                issue_key_fn=self._canonical_issue_key,
            )
        return pipeline.score_components(issue, val_data)

    def _finding_baseline_for_issue(self, issue: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        pipeline = getattr(self, "validation_pipeline", None)
        if pipeline is not None:
            return cast(Optional[Dict[str, Any]], pipeline.find_baseline(issue))
        dedup_key = str(issue.get("dedup_key") or self._canonical_issue_key(issue))
        lookup = getattr(self.user_config, "get_finding_baseline_for_issue", None)
        if callable(lookup):
            baseline = lookup(issue, dedup_key)
            return cast(Optional[Dict[str, Any]], baseline)
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

    def _deduplicate_candidate_issues(self, issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Merge candidate findings that point at the same root-cause sink."""
        deduped, _summary = deduplicate_semantic_issues_programmatic(issues)
        return deduped

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
    def _issue_rank(issue: Dict[str, Any]) -> tuple[int, int, int, int, float, int]:
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
        state.setdefault("_report_tail_started", time.monotonic())
        ledger = state.get("candidate_ledger")
        snapshot = getattr(ledger, "lifecycle_snapshot", None)
        if callable(snapshot):
            state["candidate_lifecycle_snapshot"] = snapshot(
                entry_identity=str(state.get("entry_identity") or state.get("entry_func") or "")
            )
        self.report_assembler.build(state)

    def _build_workflow_metadata(self, state: Dict[str, Any]) -> Dict[str, Any]:
        engine_capabilities = self._engine_capabilities()
        state["engine_capabilities"] = engine_capabilities
        llm_usage = scan_token_usage_snapshot(self.config)
        state["llm_usage"] = llm_usage
        ledger = state.get("candidate_ledger")
        ledger_summary = (
            ledger.summary()
            if isinstance(ledger, CandidateLedger)
            else dict(state.get("candidate_ledger_summary", {}))
        )
        state["candidate_ledger_summary"] = ledger_summary
        commit_sha = self._git_commit_sha(self.config.project.project_root)
        source_tree_hash = self._git_tree_sha(self.config.project.project_root) or commit_sha
        if not source_tree_hash:
            source_tree_hash = hashlib.sha256(
                str(self.config.project.project_root).encode("utf-8")
            ).hexdigest()
        config_hash = self._config_hash()
        security_runtime = state.get("security_runtime")
        security_runtime = security_runtime if isinstance(security_runtime, dict) else {}
        spec_runtime = security_runtime.get("security_spec_runtime")
        if not isinstance(spec_runtime, dict):
            spec_runtime = state.get("security_spec_runtime")
        spec_runtime = spec_runtime if isinstance(spec_runtime, dict) else {}
        hunter_runtime = security_runtime.get("hypothesis_hunter_runtime")
        hunter_runtime = hunter_runtime if isinstance(hunter_runtime, dict) else {}
        lifecycle = state.get("candidate_lifecycle_snapshot")
        lifecycle = lifecycle if isinstance(lifecycle, dict) else {}
        outcomes = lifecycle.get("outcomes")
        outcomes = outcomes if isinstance(outcomes, list) else []
        proof_identity = [
            {
                "cluster": str(value.get("validation_cluster_uid") or ""),
                "refs": list(value.get("proof_kernel_artifact_refs") or []),
                "terminal": value.get("terminal_authority_decision") or {},
            }
            for value in outcomes
            if isinstance(value, dict)
        ]
        runtime_authority = build_runtime_authority_manifest(
            source_tree_hash=source_tree_hash,
            config_sha256=config_hash,
            backend_sha256=hashlib.sha256(
                json.dumps(
                    {
                        "profile": self._candidate_backend_profile(),
                        "knowledge_db": self._knowledge_db_version(),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest(),
            security_spec_root_sha256=str(spec_runtime.get("root_manifest_sha256") or ""),
            hypothesis_hunter_root_sha256=str(hunter_runtime.get("root_manifest_sha256") or ""),
            proof_root_sha256=hashlib.sha256(
                json.dumps(proof_identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest(),
            revisions={
                "security_spec_compiler": SecuritySpecCompiler.compiler_version,
                "hypothesis_hunter": "hypothesis-hunter.v2",
                "proof_registry": "proof-kernel.v2",
                "proof_checker": "proof-checker.v2",
                "proof_provider": "proof-provider.v2",
                "terminal_authority": "terminal-authority.v3",
            },
        )
        state["runtime_authority_manifest"] = runtime_authority
        return {
            "timestamp": datetime.datetime.now().isoformat(),
            "run_id": state.get("run_id", ""),
            "entry_identity": state.get("entry_identity", state.get("entry_func", "")),
            "entry_file_path": state.get("entry_file_path", ""),
            "entry_signature": state.get("entry_signature", ""),
            "repo": str(self.config.project.project_root),
            "project_id": str(
                getattr(self.config.project, "project_id", "")
                or self.config.project.project_root.name
            ),
            "source_root": str(self.config.project.source_root),
            "commit_sha": commit_sha,
            "source_tree_hash": source_tree_hash,
            "config_hash": config_hash,
            "runtime_authority_manifest": runtime_authority,
            "model_manifest_hash": self._model_manifest_hash(),
            "effective_rules_sha256": self._effective_rules_sha256(),
            "rule_catalog": serialize_effective_rules(self.effective_rules),
            "rule_candidate_counts": self._rule_candidate_counts(state),
            "runtime_spec": self._public_config_value(
                getattr(self.config, "runtime_provenance", None)
            ),
            "scan_depth": str(getattr(self.config.scan, "depth", "fast")),
            "effective_scan": {
                "depth": str(getattr(self.config.scan, "depth", "fast")),
                "depth_source": str(
                    getattr(self.config.scan, "depth_source", "default") or "default"
                ),
                "rollout": rollout_runtime_policy(self.config),
            },
            "rollout": rollout_runtime_policy(self.config),
            "llm_usage": llm_usage,
            "engine_capabilities": engine_capabilities,
            "version": __version__,
            "knowledge_db_version": self._knowledge_db_version(),
            "snapshot_schema_version": "semantic_snapshot_v1",
            "context_tokens": state.get("total_context_tokens", 0),
            "cumulative_prompt_tokens": state.get("total_cumulative_prompt_tokens", 0),
            "cumulative_completion_tokens": state.get("total_cumulative_completion_tokens", 0),
            "cumulative_total_tokens": state.get("total_cumulative_total_tokens", 0)
            or state.get("total_context_tokens", 0),
            "report_tail_seconds": round(
                max(
                    0.0,
                    time.monotonic() - float(state.get("_report_tail_started") or time.monotonic()),
                ),
                4,
            ),
            "workflow": (
                self.workflow_spec.name
                if self.workflow_spec
                else self.config.analysis.workflow_name
            ),
            "workflow_mode": (
                self.workflow_spec.mode
                if self.workflow_spec
                else self.config.analysis.workflow_name
            ),
            "workflow_progress": list(self.workflow_progress),
            "current_workflow_step": self.workflow_executor.current_step,
            "candidate_ledger_summary": dict(ledger_summary),
            "candidate_signal_summary": dict(state.get("candidate_signal_summary", {})),
            "security_runtime": dict(state.get("security_runtime", {}) or {}),
            "deferred_deterministic_work_count": len(state.get("deferred_deterministic_work", [])),
            "deferred_deterministic_work": list(state.get("deferred_deterministic_work", [])),
            "validation_performance": {
                "iterations": int(state.get("validation_iterations", 0) or 0),
                "tool_call_count": int(state.get("validation_tool_call_count", 0) or 0),
                "validator_fast_path_attempted": int(
                    state.get("validator_fast_path_attempted", 0) or 0
                ),
                "validator_fast_path_accepted": int(
                    state.get("validator_fast_path_accepted", 0) or 0
                ),
                "validator_cache_hit": int(state.get("validator_cache_hit", 0) or 0),
                "validator_inflight_coalesced": int(
                    state.get("validator_inflight_coalesced", 0) or 0
                ),
                "validation_group_count": int(state.get("validation_group_count", 0) or 0),
                "validation_group_merged_count": int(
                    state.get("validation_group_merged_count", 0) or 0
                ),
                "prevalidation_decision_count": int(
                    state.get("prevalidation_decision_count", 0) or 0
                ),
                "deterministic_prevalidation_decision_count": int(
                    state.get("deterministic_prevalidation_decision_count", 0) or 0
                ),
                "deterministic_prevalidation_confirmed_count": int(
                    state.get("deterministic_prevalidation_confirmed_count", 0) or 0
                ),
                "deterministic_prevalidation_rejected_count": int(
                    state.get("deterministic_prevalidation_rejected_count", 0) or 0
                ),
                "deterministic_prevalidation_conflict_count": int(
                    state.get("deterministic_prevalidation_conflict_count", 0) or 0
                ),
                "clang_prevalidation_decision_count": int(
                    state.get("clang_prevalidation_decision_count", 0) or 0
                ),
                "static_audit_observation_count": int(
                    state.get("static_audit_observation_count", 0) or 0
                ),
                "static_suppressed_count": int(state.get("static_suppressed_count", 0) or 0),
                "fact_request_count": int(state.get("validator_fact_request_count", 0) or 0),
                "fact_resolution_success_count": int(
                    state.get("validator_fact_resolution_success_count", 0) or 0
                ),
                "fact_resolution_success_rate": state.get("validator_fact_resolution_success_rate"),
                "fact_resolution_by_kind": dict(
                    state.get("validator_fact_resolution_by_kind", {}) or {}
                ),
                "fact_terminal_status_counts": dict(
                    state.get("validator_fact_terminal_status_counts", {}) or {}
                ),
                "evidence_recheck_count": int(
                    state.get("validator_evidence_recheck_count", 0) or 0
                ),
                "targeted_investigation_count": int(
                    state.get("validator_targeted_investigation_count", 0) or 0
                ),
                "verdict_transitions": dict(state.get("validator_verdict_transitions", {}) or {}),
            },
            "budget_stage": state.get("budget_stage", ""),
            "budget_hard_caps": dict(state.get("budget_hard_caps", {})),
            "effective_budget": dict(state.get("effective_budget", {})),
            "budget_scores": dict(state.get("budget_scores", {})),
            "budget_reasons": dict(state.get("budget_reasons", {})),
            "budget_observations": list(state.get("budget_observations", [])),
            "llm_iteration_budget_reached_count": sum(
                1
                for item in state.get("budget_observations", [])
                if isinstance(item, dict)
                and item.get("kind") == "llm_iteration_budget"
                and item.get("budget_reached")
            ),
            "diff_focus": dict(state.get("diff_focus", {})),
            "audit_observation_count": len(state.get("observations", [])),
            "audit_observations": list(state.get("observations", [])),
        }

    @staticmethod
    def _rule_candidate_counts(state: Dict[str, Any]) -> Dict[str, Any]:
        """Count emitted deterministic candidates without claiming rule executions.

        The cache contains the post-detector candidate lists for this entry.
        Counting those records (and not detector invocations) keeps the report
        honest when a rule is inapplicable, disabled, or unavailable.
        """

        cache = state.get("_candidate_signal_cache")
        if not isinstance(cache, dict):
            return {"by_engine": {}, "by_rule": {}, "total": 0}
        by_engine: Dict[str, int] = {}
        by_rule: Dict[str, int] = {}
        seen: Set[str] = set()
        for bucket, values in cache.items():
            if str(bucket) == "backend" or not isinstance(values, (list, tuple)):
                continue
            for raw in values:
                if not isinstance(raw, dict):
                    continue
                if str(raw.get("candidate_kind") or "") == "backend_signal":
                    continue
                rule_id = str(raw.get("rule_id") or raw.get("rule") or "")
                if not rule_id:
                    continue
                unique = str(
                    raw.get("occurrence_uid")
                    or raw.get("candidate_uid")
                    or raw.get("candidate_id")
                    or raw.get("id")
                    or f"{rule_id}:{raw.get('location') or raw.get('line') or ''}"
                )
                seen_key = f"{rule_id}:{unique}"
                if seen_key in seen:
                    continue
                seen.add(seen_key)
                engine = str(
                    raw.get("rule_engine") or raw.get("candidate_source") or bucket or "unknown"
                )
                by_rule[rule_id] = by_rule.get(rule_id, 0) + 1
                by_engine[engine] = by_engine.get(engine, 0) + 1
        return {
            "by_engine": dict(sorted(by_engine.items())),
            "by_rule": dict(sorted(by_rule.items())),
            "total": sum(by_rule.values()),
        }

    def _engine_capabilities(self) -> Dict[str, Dict[str, Any]]:
        status_getter = getattr(self.code_index, "capability_status", None)
        capabilities: Dict[str, Dict[str, Any]] = {}
        if callable(status_getter):
            try:
                value = status_getter()
                if isinstance(value, dict):
                    capabilities.update(
                        {
                            str(name): dict(details)
                            for name, details in value.items()
                            if isinstance(details, dict)
                        }
                    )
            except Exception as exc:
                logger.debug("Unable to read code-index capability status: %s", exc)

        if "index" not in capabilities:
            configured = str(getattr(self.code_index, "backend_name", "") or "regex").lower()
            backend = getattr(self.code_index, "backend", None)
            backend_status = str(getattr(backend, "_status", "") or "").lower()
            fallback = backend is None and configured != "regex"
            capabilities["index"] = {
                "configured": configured,
                "active": type(backend).__name__ if backend is not None else "regex",
                "status": "degraded" if fallback else "complete",
                "reason": ("configured_backend_unavailable_regex_fallback" if fallback else ""),
                "ready": bool(getattr(self.code_index, "_index_ready", False)),
            }
            if backend_status in {"failed", "error", "timeout"}:
                capabilities["index"]["status"] = "degraded"
                capabilities["index"]["reason"] = f"backend_{backend_status}"
            if configured in {"unified", "svf"}:
                svf_available = bool(getattr(backend, "_svf_available", False))
                capabilities["svf"] = {
                    "configured": True,
                    "active": svf_available,
                    "status": "complete" if svf_available else "failed",
                    "reason": "" if svf_available else "svf_unavailable_or_failed",
                }
        semantic_overlay = getattr(self, "_semantic_overlay", None)
        if isinstance(semantic_overlay, dict):
            overlay_status = str(semantic_overlay.get("engine_status") or "complete").lower()
            if overlay_status not in {
                "complete",
                "degraded",
                "failed",
                "interrupted",
            }:
                overlay_status = "failed"
            overlay_errors = semantic_overlay.get("engine_errors")
            if not isinstance(overlay_errors, list):
                overlay_errors = []
            capabilities["semantic_overlay"] = {
                "configured": True,
                "active": overlay_status != "failed",
                "status": overlay_status,
                "reason": ("user_config_query_failure" if overlay_errors else ""),
                "errors": overlay_errors,
            }
        runtime_capabilities = getattr(self, "_runtime_engine_capabilities", {})
        runtime_lock = getattr(
            self,
            "_runtime_engine_capabilities_lock",
            threading.RLock(),
        )
        with runtime_lock:
            for name, details in runtime_capabilities.items():
                capabilities[name] = dict(details)
        return capabilities

    def _record_engine_capability(
        self,
        name: str,
        *,
        status: str,
        reason: str = "",
        **details: Any,
    ) -> None:
        normalized = str(status or "failed").lower()
        if normalized not in {"complete", "partial", "degraded", "failed", "interrupted"}:
            normalized = "failed"
        severity = {
            "complete": 0,
            "partial": 1,
            "degraded": 2,
            "failed": 3,
            "interrupted": 4,
        }
        lock = getattr(self, "_runtime_engine_capabilities_lock", None)
        if lock is None:
            lock = threading.RLock()
            self._runtime_engine_capabilities_lock = lock
        capabilities = getattr(self, "_runtime_engine_capabilities", None)
        if not isinstance(capabilities, dict):
            capabilities = {}
            self._runtime_engine_capabilities = capabilities
        with lock:
            existing = dict(capabilities.get(name, {}))
            existing_status = str(existing.get("status") or "complete").lower()
            if severity.get(existing_status, 0) > severity[normalized]:
                normalized = existing_status
                reason = str(existing.get("reason") or reason)
            updated = dict(existing)
            updated.update(details)
            updated["status"] = normalized
            if reason or "reason" not in updated:
                updated["reason"] = reason
            capabilities[name] = updated

    def _record_deferred_deterministic_work(
        self,
        state: Optional[Dict[str, Any]],
        *,
        engine: str,
        function_name: str,
        reason: str,
        parent: str = "",
        call_path: Optional[Sequence[str]] = None,
    ) -> None:
        self._record_deterministic_work_terminal(
            state,
            engine=engine,
            function_name=function_name,
            disposition="deferred_budget",
            reason=reason,
            parent=parent,
            call_path=call_path,
        )

    def _record_engine_failed_work(
        self,
        state: Optional[Dict[str, Any]],
        *,
        engine: str,
        function_name: str,
        reason: str,
        parent: str = "",
        call_path: Optional[Sequence[str]] = None,
    ) -> None:
        self._record_deterministic_work_terminal(
            state,
            engine=engine,
            function_name=function_name,
            disposition="engine_failed",
            reason=reason,
            parent=parent,
            call_path=call_path,
        )

    def _record_deterministic_work_terminal(
        self,
        state: Optional[Dict[str, Any]],
        *,
        engine: str,
        function_name: str,
        disposition: str,
        reason: str,
        parent: str,
        call_path: Optional[Sequence[str]],
    ) -> None:
        """Make every truncated or failed deterministic unit externally visible."""

        if not isinstance(state, dict) or not function_name:
            return
        ledger = getattr(self, "candidate_ledger", None)
        project_id = str(getattr(ledger, "project_id", "") or "project")
        revision = str(getattr(ledger, "revision", "") or "")
        entry = str(state.get("entry_identity") or state.get("entry_func") or "")
        normalized_path = [str(item) for item in (call_path or [entry, function_name]) if str(item)]
        root_payload = {
            "project_id": project_id,
            "revision": revision,
            "engine": engine,
            "function_name": function_name,
        }
        history_payload = dict(root_payload)
        history_payload.pop("revision", None)
        root_json = json.dumps(root_payload, ensure_ascii=False, sort_keys=True)
        candidate_digest = hashlib.sha256(root_json.encode("utf-8")).hexdigest()[:24]
        history_digest = hashlib.sha256(
            json.dumps(
                history_payload,
                ensure_ascii=False,
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()[:24]
        occurrence_payload = {
            "candidate_uid": candidate_digest,
            "entry": entry,
            "call_path": normalized_path,
        }
        occurrence_digest = hashlib.sha256(
            json.dumps(
                occurrence_payload,
                ensure_ascii=False,
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()[:24]
        evidence_payload = {
            "engine": engine,
            "function_name": function_name,
            "reason": reason,
            "parent": parent,
            "call_path": normalized_path,
        }
        terminal = {
            "candidate_schema_version": CANDIDATE_SCHEMA_VERSION,
            "candidate_uid": f"CAND_{candidate_digest}",
            "occurrence_uid": f"OCC_{occurrence_digest}",
            "history_key": f"HIST_{history_digest}",
            "evidence_hash": hashlib.sha256(
                json.dumps(
                    evidence_payload,
                    ensure_ascii=False,
                    sort_keys=True,
                ).encode("utf-8")
            ).hexdigest(),
            "candidate_disposition": disposition,
            "status": disposition,
            "engine": engine,
            "function_name": function_name,
            "entry_identity": entry,
            "deferred_reason": reason if disposition == "deferred_budget" else "",
            "reason": reason,
            "parent": parent,
            "call_paths": [normalized_path] if normalized_path else [],
        }
        work = state.setdefault("deferred_deterministic_work", [])
        if not any(
            isinstance(item, dict)
            and item.get("occurrence_uid") == terminal["occurrence_uid"]
            and item.get("candidate_disposition") == disposition
            for item in work
        ):
            work.append(terminal)

    def _config_hash(self) -> str:
        payload = {
            "analysis": self._public_config_value(getattr(self.config, "analysis", None)),
            "indexing": self._public_config_value(getattr(self.config, "indexing", None)),
            "reporting": self._public_config_value(getattr(self.config, "reporting", None)),
            "scan": self._public_config_value(getattr(self.config, "scan", None)),
            "concurrency": self._public_config_value(getattr(self.config, "concurrency", None)),
            "rules": self._public_config_value(getattr(self.config, "rules", None)),
            "effective_rules_sha256": self._effective_rules_sha256(),
            "runtime_spec": self._public_config_value(
                getattr(self.config, "runtime_provenance", None)
            ),
            "project": {
                "project_root": str(getattr(self.config.project, "project_root", "") or ""),
                "source_root": str(getattr(self.config.project, "source_root", "") or ""),
                "entry_function": str(getattr(self.config.project, "entry_function", "") or ""),
                "entry_file_path": str(getattr(self.config.project, "entry_file_path", "") or ""),
                "entry_signature": str(getattr(self.config.project, "entry_signature", "") or ""),
                "agents": self._public_config_value(getattr(self.config.project, "agents", [])),
            },
        }
        stable = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
        return hashlib.sha256(stable.encode("utf-8")).hexdigest()

    def _effective_rules_sha256(self) -> str:
        provenance = getattr(self.config, "rule_catalog_provenance", None)
        if provenance is None:
            effective = getattr(self.config, "effective_rules", None)
            provenance = getattr(effective, "provenance", None)
        if isinstance(provenance, dict):
            return str(
                provenance.get("effective_sha256") or provenance.get("effective_rules_sha256") or ""
            )
        return str(
            getattr(provenance, "effective_sha256", "")
            or getattr(provenance, "effective_rules_sha256", "")
            or ""
        )

    def _model_manifest_hash(self) -> str:
        llms: Dict[str, Any] = getattr(self.config, "llms", {}) or {}
        payload = {
            name: {
                "base_urls": getattr(config, "base_urls", []),
                "models": getattr(config, "models", []),
                "max_tokens": getattr(config, "max_tokens", None),
                "supports_structured_output": getattr(
                    config,
                    "supports_structured_output",
                    False,
                ),
            }
            for name, config in sorted(llms.items())
        }
        stable = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
        return hashlib.sha256(stable.encode("utf-8")).hexdigest()

    @classmethod
    def _public_config_value(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {
                str(key): cls._public_config_value(item)
                for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
                if not any(
                    secret in str(key).lower()
                    for secret in ("api_key", "token", "secret", "password")
                )
            }
        if isinstance(value, (list, tuple)):
            return [cls._public_config_value(item) for item in value]
        if isinstance(value, Path):
            return value.as_posix()
        if hasattr(value, "__dict__"):
            return cls._public_config_value(vars(value))
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        return str(value)

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
        try:
            result = subprocess.run(
                ["git", "-C", str(project_root), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return ""

    @staticmethod
    def _git_tree_sha(project_root: Path) -> str:
        try:
            result = subprocess.run(
                ["git", "-C", str(project_root), "rev-parse", "HEAD^{tree}"],
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.stdout.strip()
        except (OSError, subprocess.SubprocessError):
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

    def _candidate_first_skill_selection(self, extra_skills: Sequence[str]) -> SkillSelection:
        """Return every language-compatible deterministic skill."""
        get_agent = getattr(self.spec_registry, "get_agent", None)
        active_spec = get_agent("hypothesis_hunter") if callable(get_agent) else None
        available = list(getattr(active_spec, "skills", []) or self.spec_registry.skills)
        available.extend(str(skill) for skill in extra_skills if str(skill))
        available = self._language_filtered_analysis_skills(list(dict.fromkeys(available)))
        return SkillSelection(
            skills=available,
            restricted=False,
            source="candidate_first_complete",
            confidence=1.0,
            reasons=["complete deterministic fact collection"],
        )

    @staticmethod
    def _compact_candidate_signal_items(items: Any, *, limit: int = 80) -> List[Dict[str, Any]]:
        compact: List[Dict[str, Any]] = []
        if not isinstance(items, list):
            return compact
        for item in items[:limit]:
            if not isinstance(item, dict):
                continue
            evidence_pack = _as_dict(item.get("evidence_pack"))
            compact.append(
                {
                    "candidate_id": item.get("candidate_id")
                    or item.get("id")
                    or evidence_pack.get("candidate_id"),
                    "function": item.get("function"),
                    "location": item.get("location"),
                    "defect_class": item.get("defect_class")
                    or item.get("subcategory")
                    or item.get("category"),
                    "rule": item.get("rule") or evidence_pack.get("rule"),
                    "candidate_source": item.get("candidate_source")
                    or evidence_pack.get("candidate_source"),
                    "confidence": item.get("confidence") or item.get("rule_confidence"),
                    "source": item.get("source") or evidence_pack.get("source"),
                    "sink": item.get("sink") or evidence_pack.get("sink"),
                    "validation_required": item.get(
                        "validation_required", evidence_pack.get("validation_required", True)
                    ),
                    "positive_evidence": (
                        item.get("positive_evidence")
                        or evidence_pack.get("positive_evidence")
                        or []
                    )[:4],
                    "negative_evidence": (
                        item.get("negative_evidence")
                        or evidence_pack.get("negative_evidence")
                        or []
                    )[:4],
                }
            )
        if len(items) > limit:
            compact.append({"truncated": True, "omitted_count": len(items) - limit})
        return compact

    def _get_tools(
        self,
        agent_name: Optional[str] = None,
        *,
        active_skill_names: Optional[List[str]] = None,
    ) -> List[Any]:
        """Initialize and return the set of tools."""
        from ...tools.registry import build_tool_registry

        include_advanced = getattr(self.code_index, "backend_name", "") in {
            "joern",
            "svf",
            "unified",
        }
        tools = list(
            build_tool_registry(
                self.code_index,
                self.snapshot_store,
                self.user_config,
                include_advanced=include_advanced,
            ).values()
        )
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

    @staticmethod
    def _build_trivial_snapshot(func_name: str, impl: Dict[str, Any]) -> Dict[str, Any]:
        return build_trivial_snapshot(func_name, impl)

    @staticmethod
    def _trivial_suspicious_points(
        func_name: str,
        impl: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        return trivial_suspicious_points(func_name, impl)

    @staticmethod
    def _is_lightweight_snapshot_candidate(func_name: str, impl: Dict[str, Any]) -> bool:
        return is_lightweight_snapshot_candidate(func_name, impl)

    @staticmethod
    def _build_lightweight_snapshot(func_name: str, impl: Dict[str, Any]) -> Dict[str, Any]:
        return build_lightweight_snapshot(func_name, impl)

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
        4. If code changed, fail closed and refuse the pre-P5 snapshot.
        """
        # 1. Get real implementation
        impl_result = self.tools_runtime.execute_tool("get_function_impl", args)
        if not impl_result.get("success"):
            return impl_result

        current_code = impl_result["data"]["code"]
        index_name = str(impl_result["data"].get("index_name") or "")
        if not index_name:
            return impl_result

        try:
            symbol_context = resolve_function_info(
                self.code_index,
                index_name,
                file_path=str(impl_result["data"].get("file") or ""),
                index_name=index_name,
                start_line=int(impl_result["data"].get("start_line") or 0) or None,
            )
        except SemanticModelInputError as exc:
            logger.warning(
                "Snapshot refresh context unavailable index_name=%s reason=%s",
                index_name,
                exc.reason,
            )
            return impl_result

        # 2. Check snapshot status with canonical index name
        needs_refresh, reason = self.snapshot_store.needs_refresh(
            index_name,
            current_code,
            symbol_context,
        )

        if not needs_refresh and reason != "no_snapshot":
            # Snapshot is valid and up to date (or only cosmetic changes)
            logger.info(
                "Using cached snapshot index_name=%s reason=%s",
                index_name,
                reason,
            )
            snapshot = self.snapshot_store.load_snapshot(index_name)
            return {
                "success": True,
                "data": impl_result["data"],
                "snapshot": snapshot,
                "note": "Snapshot allows skipping deep analysis if irrelevant.",
            }

        if reason == "code_changed":
            logger.info(
                "Code changed index_name=%s; invalidating legacy semantic snapshot",
                index_name,
            )
            self.snapshot_store.lock_manager.invalidate(index_name)

        # P5 consumers use source/IR facts; no model may bless a stale snapshot.
        return impl_result

    def _extract_final_report(self, text: str) -> Optional[FinalReport]:
        """Parse final report from text."""
        data = self._extract_json_block(text, "final_report")
        if not data:
            return None

        try:
            issues = [
                Issue.from_dict(
                    i, context_function=data.get("entry_function", "unknown"), issue_index=idx + 1
                )
                for idx, i in enumerate(data.get("issues", []))
            ]
            return FinalReport(
                entry_function=data.get("entry_function", ""),
                overall_verdict=data.get("overall_verdict", "insufficient_info"),
                issues=issues,
                notes=data.get("notes", []),
            )
        except Exception as e:
            logger.error(f"Failed to parse FinalReport object: {e}")
            return None

    def _extract_json_block(
        self, text: str, type_hint: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
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
                if (
                    type_hint in data
                    and isinstance(data[type_hint], dict)
                    and data[type_hint].get("type") == type_hint
                ):
                    return cast(Dict[str, Any], data[type_hint])
            else:
                # If no hint, return the first dictionary found
                return data

        return None

        return None

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
                parsed_end_line = issue.get("end_line")
                if isinstance(parsed_end_line, int) and parsed_end_line != parsed_line:
                    issue["location"] = f"{file_path}:{parsed_line}-{parsed_end_line}"
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

    def _build_java_active_audit_context(
        self,
        state: Dict[str, Any],
        *,
        active_skills: Sequence[str],
        candidate_signal_summary: Dict[str, Any],
        candidate_signals: Sequence[Dict[str, Any]],
    ) -> Dict[str, Any]:
        raw_impl = state.get("impl_result")
        impl: Dict[str, Any] = raw_impl if isinstance(raw_impl, dict) else {}
        raw_framework = impl.get("framework_semantics")
        framework: Dict[str, Any] = raw_framework if isinstance(raw_framework, dict) else {}
        entry_func = str(
            state.get("entry_func") or impl.get("qualified_name") or impl.get("function") or ""
        )
        annotations = self._compact_java_annotations(self._java_annotation_context(impl), limit=12)
        sources = self._compact_java_framework_values(
            framework, ("sources", "request_sources", "input_sources"), limit=12
        )
        guards = self._compact_java_framework_values(
            framework, ("guards", "security_guards", "authz_guards"), limit=12
        )
        policies = self._compact_java_framework_values(
            framework,
            ("security_policies", "runtime_configs", "policies"),
            limit=12,
        )
        return {
            "language": "java",
            "structure_frontend_actual": impl.get("structure_frontend_actual")
            or impl.get("structure_frontend"),
            "structure_precision": impl.get("structure_precision") or impl.get("precision"),
            "entry_function": entry_func,
            "entry_kind": self._java_entry_kind(impl, framework),
            "component": self._java_component(impl),
            "file": impl.get("file"),
            "annotations": annotations,
            "route": self._java_route_context(framework, annotations),
            "framework_sources": sources,
            "known_guards": guards,
            "runtime_security_policies": policies,
            "reachable_callees": self._java_reachable_callee_context(impl, limit=16),
            "candidate_signal_summary": candidate_signal_summary,
            "candidate_signal_candidates": self._compact_candidate_signal_items(
                list(candidate_signals), limit=24
            ),
            "candidate_ledger_summary": state.get("candidate_ledger_summary") or {},
            "active_skills": list(active_skills),
            "review_policy": (
                "LLM-only Java active findings must use candidate_source=java_llm_active_audit "
                "and are needs_review by default unless merged with a proof-carrying local/backend candidate."
            ),
        }

    @staticmethod
    def _compact_java_annotations(values: Sequence[Any], *, limit: int) -> List[Dict[str, Any]]:
        compact: List[Dict[str, Any]] = []
        for value in list(values)[:limit]:
            if isinstance(value, dict):
                compact.append(
                    {
                        "name": value.get("name") or value.get("simpleName"),
                        "fullName": value.get("fullName") or value.get("qualifiedName"),
                        "line": value.get("line") or value.get("lineNumber"),
                        "code": value.get("code"),
                    }
                )
            else:
                compact.append({"name": str(value)})
        return compact

    @staticmethod
    def _compact_java_framework_values(
        framework: Dict[str, Any],
        keys: Sequence[str],
        *,
        limit: int,
    ) -> List[Any]:
        values: List[Any] = []
        for key in keys:
            value = framework.get(key)
            if isinstance(value, list):
                values.extend(value[:limit])
            elif value not in (None, "", {}):
                values.append(value)
        return values[:limit]

    @staticmethod
    def _java_entry_kind(impl: Dict[str, Any], framework: Dict[str, Any]) -> str:
        for key in ("entry_kind", "kind", "framework_entry_kind"):
            value = impl.get(key) or framework.get(key)
            if value:
                return str(value)
        annotations = _as_list(impl.get("annotations"))
        class_annotations = _as_list(impl.get("class_annotations"))
        text = " ".join(
            (
                str(item.get("name") or item.get("code") or item)
                if isinstance(item, dict)
                else str(item)
            )
            for item in annotations + class_annotations
        ).lower()
        name = str(
            impl.get("qualified_name") or impl.get("function") or impl.get("name") or ""
        ).lower()
        if any(
            token in text
            for token in (
                "requestmapping",
                "getmapping",
                "postmapping",
                "restcontroller",
                "controller",
            )
        ):
            return "controller"
        if "filter" in name or "dofilter" in name:
            return "filter"
        if "interceptor" in name or "prehandle" in name:
            return "interceptor"
        if "mapper" in name or "repository" in name:
            return "mapper_or_repository"
        if "main:" in name or name.endswith(".main"):
            return "cli"
        return "java_public_or_framework_entry"

    @staticmethod
    def _java_component(impl: Dict[str, Any]) -> str:
        text = " ".join(
            str(impl.get(key) or "") for key in ("class_name", "qualified_name", "function", "file")
        ).lower()
        for component in (
            "controller",
            "service",
            "mapper",
            "repository",
            "filter",
            "interceptor",
            "dto",
            "config",
            "listener",
        ):
            if component in text:
                return component
        return "java_component"

    @staticmethod
    def _java_route_context(
        framework: Dict[str, Any], annotations: Sequence[Dict[str, Any]]
    ) -> Dict[str, Any]:
        route = _as_dict(framework.get("route"))
        mappings = [
            item
            for item in annotations
            if any(
                token in str(item.get("name") or item.get("code") or "").lower()
                for token in ("mapping", "route")
            )
        ]
        return {"route": route, "mappings": mappings[:8]}

    @staticmethod
    def _java_reachable_callee_context(impl: Dict[str, Any], *, limit: int) -> List[Dict[str, Any]]:
        callees = _as_list(impl.get("callees"))
        preferred: List[Dict[str, Any]] = []
        fallback: List[Dict[str, Any]] = []
        for callee in callees:
            if isinstance(callee, dict):
                name = str(callee.get("name") or callee.get("callee") or callee.get("method") or "")
                item = {
                    "name": name,
                    "file": callee.get("file") or callee.get("file_path"),
                    "line": callee.get("line") or callee.get("lineNumber"),
                }
            else:
                name = str(callee)
                item = {"name": name}
            lowered = name.lower()
            if any(
                token in lowered
                for token in (
                    "service",
                    "mapper",
                    "repository",
                    "filter",
                    "interceptor",
                    "controller",
                    "helper",
                )
            ):
                preferred.append(item)
            else:
                fallback.append(item)
        return (preferred + fallback)[:limit]

    def _normalize_java_active_audit_issues(
        self,
        raw_issues: Any,
        state: Dict[str, Any],
        candidate_signals: Sequence[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        if not isinstance(raw_issues, list):
            return []
        candidate_ids: Set[str] = set()
        for item in candidate_signals:
            if not isinstance(item, dict):
                continue
            pack = _as_dict(item.get("evidence_pack"))
            candidate_id = str(
                item.get("candidate_id") or item.get("id") or pack.get("candidate_id") or ""
            )
            if candidate_id:
                candidate_ids.add(candidate_id)
        entry_func = str(state.get("entry_func") or "")
        impl = _as_dict(state.get("impl_result"))
        entry_file = str(impl.get("file") or "")
        normalized: List[Dict[str, Any]] = []
        proof_sources = {
            "java_local_rule",
            "java_framework_flow",
            "java_project_file_rule",
            "java_mybatis_xml",
            "mybatis_xml",
            "joern_cpg",
        }
        for issue in raw_issues:
            if not isinstance(issue, dict):
                continue
            issue = dict(issue)
            pack = _as_dict(issue.get("evidence_pack"))
            candidate_id = str(
                issue.get("candidate_id") or issue.get("id") or pack.get("candidate_id") or ""
            )
            source_name = str(issue.get("candidate_source") or pack.get("candidate_source") or "")
            is_candidate_backed = (
                bool(candidate_id and candidate_id in candidate_ids) or source_name in proof_sources
            )
            issue.setdefault("language", "java")
            issue.setdefault("entry_function", entry_func)
            issue.setdefault("entry_path", [entry_func] if entry_func else [])
            if entry_file and not (
                issue.get("file") or issue.get("file_path") or issue.get("location")
            ):
                issue["file"] = entry_file
            if not is_candidate_backed:
                issue["candidate_source"] = "java_llm_active_audit"
                issue["candidate_kind"] = "llm_observation"
                issue["finding_kind"] = "java_active_audit_observation"
                issue["active_audit_review_only"] = True
                issue.setdefault("rule", "java_llm_active_audit")
                issue.setdefault("evidence_refs", [])
                pack["candidate_source"] = "java_llm_active_audit"
                pack["language"] = "java"
                pack["active_audit_review_only"] = True
                pack.setdefault("path", {})
                if isinstance(pack["path"], dict):
                    pack["path"].setdefault("entry_function", entry_func)
                    pack["path"].setdefault("entry_path", [entry_func] if entry_func else [])
                self._normalize_java_active_audit_observation(issue, pack, entry_file, entry_func)
            if pack:
                issue["evidence_pack"] = pack
            preserve_issue_location(issue)
            normalized.append(issue)
        return normalized

    def _normalize_java_active_audit_observation(
        self,
        issue: Dict[str, Any],
        pack: Dict[str, Any],
        entry_file: str,
        entry_func: str = "",
    ) -> None:
        JavaActiveAuditNormalizer.normalize(
            issue,
            pack,
            entry_func=entry_func,
            entry_file=entry_file,
            code_index=getattr(self, "code_index", None),
        )

    def _language_filtered_analysis_skills(
        self,
        skill_names: Sequence[str],
    ) -> List[str]:
        """Keep candidate-analysis skills aligned with the configured language."""
        names = list(dict.fromkeys(skill_names))
        language = self._project_language()

        def supports_language(name: str) -> bool:
            skill = self.spec_registry.get_skill(name)
            if skill is None:
                raise ValueError(f"Unknown candidate-analysis skill {name!r}")
            languages = list(getattr(skill, "languages", []))
            if not languages:
                raise ValueError(f"Skill {name!r} has no language metadata")
            return language in languages

        filtered = [name for name in names if supports_language(name)]
        if filtered:
            return filtered

        # Java defaults come from language-scoped Skill contracts rather than
        # a second hard-coded name list. Shared modeling/validation skills
        # declare both languages and are not part of this analysis fallback.
        registry_skills = getattr(self.spec_registry, "skills", {})
        return sorted(
            skill.name
            for skill in registry_skills.values()
            if list(getattr(skill, "languages", [])) == [language]
        )

    @staticmethod
    def _java_annotation_context(impl: Dict[str, Any]) -> List[Any]:
        context: List[Any] = []
        for key in ("annotations", "parameter_annotations", "class_annotations"):
            value = impl.get(key)
            if isinstance(value, list):
                context.extend(value)
            elif value:
                context.append(value)
        context.extend(Analyzer._java_annotation_context_from_code(impl))
        context.extend(Analyzer._java_annotation_context_from_framework(impl))
        return context

    @staticmethod
    def _java_annotation_context_from_code(impl: Dict[str, Any]) -> List[Dict[str, Any]]:
        code = str(impl.get("code") or "")
        if not code:
            return []
        annotations: List[Dict[str, Any]] = []
        for raw_line in code.splitlines()[:80]:
            match = re.match(
                r"\s*(?:(\d+)\s*\|\s*)?(@[A-Za-z_][\w.]*\s*(?:\([^)]*\))?)",
                raw_line.strip(),
            )
            if not match:
                continue
            code_text = match.group(2).strip()
            if "CrossOrigin" not in code_text and "Mapping" not in code_text:
                continue
            try:
                line_no = int(match.group(1) or impl.get("start_line") or 1)
            except (TypeError, ValueError):
                line_no = 1
            annotations.append(
                {
                    "name": code_text.split("(", 1)[0].lstrip("@").rsplit(".", 1)[-1],
                    "code": code_text,
                    "lineNumber": line_no,
                    "source": "java_source_context",
                }
            )
        return annotations

    @staticmethod
    def _java_annotation_context_from_framework(impl: Dict[str, Any]) -> List[Dict[str, Any]]:
        framework = (
            impl.get("framework_semantics")
            if isinstance(impl.get("framework_semantics"), dict)
            else {}
        )
        if not framework:
            return []
        text = json.dumps(framework, ensure_ascii=False, default=str)
        lowered = text.lower()
        compact = re.sub(r"[^a-z0-9*]+", "", lowered)
        if not ("cors" in compact or "crossorigin" in compact or "allowedorigins" in compact):
            return []
        if "*" not in text and "wildcard" not in lowered and "allow all" not in lowered:
            return []
        try:
            fallback_line = int(impl.get("start_line") or 1)
        except (TypeError, ValueError):
            fallback_line = 1
        line = Analyzer._java_framework_semantic_line(framework) or fallback_line
        return [
            {
                "name": "CrossOrigin",
                "code": '@CrossOrigin("*")',
                "lineNumber": line,
                "source": "framework_semantics",
            }
        ]

    @staticmethod
    def _java_framework_semantic_line(value: Any) -> int:
        if isinstance(value, dict):
            for key in ("line", "lineNumber", "start_line", "startLine"):
                try:
                    line = int(value.get(key) or 0)
                except (TypeError, ValueError):
                    line = 0
                if line > 0:
                    return line
            for nested in value.values():
                line = Analyzer._java_framework_semantic_line(nested)
                if line > 0:
                    return line
        elif isinstance(value, list):
            for item in value:
                line = Analyzer._java_framework_semantic_line(item)
                if line > 0:
                    return line
        return 0

    def _detect_java_entry_field_rule_candidates(
        self,
        generator: JavaRuleCandidateGenerator,
        *,
        entry_func: str,
        impl: Dict[str, Any],
        allowed_skills: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Attach field-level Java evidence only to entries that touch the field."""
        if allowed_skills is not None and "java_concurrency" not in set(allowed_skills):
            return []
        file_path = str(impl.get("file") or "")
        if not file_path.lower().endswith(".java"):
            return []
        source_path = self._resolve_java_source_file(file_path)
        if source_path is None:
            return []
        try:
            text = source_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []

        numbered = "\n".join(
            f"{idx} | {line}" for idx, line in enumerate(text.splitlines()[:2000], start=1)
        )
        issues = generator.generate_issues(
            entry_func,
            numbered,
            file_path,
            allowed_skills=["java_concurrency"],
        )
        issues = [
            issue for issue in issues if issue.get("rule") == "java_shared_mutable_static_state"
        ]
        if not issues:
            return []

        code = str(impl.get("code") or "")
        enriched: List[Dict[str, Any]] = []
        for issue in issues:
            variable = self._java_static_field_variable(issue, text)
            if variable and not re.search(rf"\b{re.escape(variable)}\b", code):
                continue
            enriched_issue = dict(issue)
            enriched_issue["function"] = entry_func
            enriched_issue["entry_function"] = entry_func
            enriched_issue["analyzed_from"] = entry_func
            pack = dict(enriched_issue.get("evidence_pack") or {})
            sink_line = self._java_numbered_code_line_for_symbol(code, variable) if variable else 0
            if sink_line:
                pack["sink"] = {
                    "operation": f"shared mutable static field `{variable}` is accessed by entry method",
                    "line": sink_line,
                    "file": file_path,
                    "kind": "java_shared_static_state_access",
                }
            path = dict(pack.get("path") or {})
            path.update(
                {
                    "function": entry_func,
                    "entry_function": entry_func,
                    "complete_in_function": True,
                    "field_level_evidence": True,
                }
            )
            pack["path"] = path
            enriched_issue["evidence_pack"] = pack
            positive = list(enriched_issue.get("positive_evidence") or [])
            if variable:
                message = (
                    f"Entry `{entry_func}` accesses shared static mutable field "
                    f"`{variable}` declared at `{enriched_issue.get('location')}`."
                )
                if message not in positive:
                    positive.append(message)
            enriched_issue["positive_evidence"] = positive
            enriched.append(enriched_issue)
        return enriched

    def _resolve_java_source_file(self, file_path: str) -> Optional[Path]:
        normalized = file_path.replace("\\", "/")
        candidates: List[Path] = []
        raw = Path(normalized)
        if raw.is_absolute():
            candidates.append(raw)
        for root_value in (
            getattr(self.config.project, "source_root", ""),
            getattr(self.config.project, "project_root", ""),
            ".",
        ):
            root = Path(str(root_value or "."))
            candidates.append(root / normalized)
        for candidate in candidates:
            if candidate.exists() and candidate.is_file():
                return candidate
        return None

    @staticmethod
    def _java_static_field_variable(issue: Dict[str, Any], file_text: str) -> str:
        _file, line = parse_location_file_line(str(issue.get("location") or ""))
        if line <= 0:
            return ""
        lines = str(file_text or "").splitlines()
        if line > len(lines):
            return ""
        source = lines[line - 1].strip()
        match = re.search(
            r"\bstatic\s+(?:final\s+)?[A-Za-z_$][\w$]*(?:\s*<[^;=()]+>)?\s+([A-Za-z_$][\w$]*)\b",
            source,
        )
        return match.group(1) if match else ""

    @staticmethod
    def _java_numbered_code_line_for_symbol(code: str, symbol: str) -> int:
        if not symbol:
            return 0
        match = re.search(rf"^\s*(\d+)\s*\|\s*.*\b{re.escape(symbol)}\b", str(code or ""), re.M)
        if not match:
            return 0
        try:
            return int(match.group(1))
        except ValueError:
            return 0

    def _detect_java_project_file_rule_candidates(
        self,
        generator: JavaRuleCandidateGenerator,
        allowed_skills: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        if allowed_skills is None:
            with self._java_project_file_rule_cache_lock:
                if self._java_project_file_rule_cache is not None:
                    if self._java_project_file_rule_emitted:
                        return []
                    self._java_project_file_rule_emitted = True
                    return [dict(issue) for issue in self._java_project_file_rule_cache]
        source_root = Path(
            getattr(self.config.project, "source_root", "")
            or getattr(self.config.project, "project_root", ".")
        )
        if not source_root.exists():
            return []

        mapper_interfaces = self._java_mapper_interface_index(source_root)
        candidates: List[Dict[str, Any]] = []
        for path in self._iter_java_auxiliary_rule_files(source_root):
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            if (
                path.suffix.lower() == ".java"
                and not self._java_file_may_contain_mybatis_annotation_substitution(text)
            ):
                continue
            if not self._java_auxiliary_file_may_contain_rule_signal(text):
                continue
            numbered = "\n".join(
                f"{idx} | {line}" for idx, line in enumerate(text.splitlines()[:2000], start=1)
            )
            rel_path = normalize_path(path, source_root)
            file_candidates = generator.generate_issues(
                f"<project-file>:{rel_path}",
                numbered,
                rel_path,
                allowed_skills=allowed_skills,
            )
            if path.suffix.lower() == ".xml":
                bindings = self._mybatis_xml_bindings(text, rel_path, mapper_interfaces)
                file_candidates = [
                    self._enrich_mybatis_xml_candidate(issue, bindings) for issue in file_candidates
                ]
                file_candidates.extend(
                    self._mybatis_xml_project_file_candidates(rel_path, bindings)
                )
            elif path.suffix.lower() == ".java":
                file_candidates = [
                    self._enrich_mybatis_annotation_candidate(issue, rel_path, mapper_interfaces)
                    for issue in file_candidates
                ]
            candidates.extend(self._mark_java_project_file_candidates(file_candidates))
        candidates = dedupe_rule_candidates(candidates)
        if allowed_skills is None:
            with self._java_project_file_rule_cache_lock:
                self._java_project_file_rule_cache = [dict(issue) for issue in candidates]
                self._java_project_file_rule_emitted = True
        return candidates

    @staticmethod
    def _mark_java_project_file_candidates(issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        marked: List[Dict[str, Any]] = []
        for issue in issues:
            item = dict(issue)
            item["entry_agnostic"] = True
            item["project_file_scope"] = True
            pack = item.get("evidence_pack") if isinstance(item.get("evidence_pack"), dict) else {}
            if pack:
                pack = dict(pack)
                pack["entry_agnostic"] = True
                pack["project_file_scope"] = True
                path = pack.get("path") if isinstance(pack.get("path"), dict) else {}
                if path:
                    path = dict(path)
                    path["entry_agnostic"] = True
                    path["project_file_scope"] = True
                    pack["path"] = path
                item["evidence_pack"] = pack
            marked.append(item)
        return marked

    @staticmethod
    def _java_mapper_interface_index(source_root: Path) -> Dict[str, Dict[str, Any]]:
        """Index Java mapper/interface methods by class name for XML binding evidence."""
        index: Dict[str, Dict[str, Any]] = {}
        java_root = source_root / "src" / "main" / "java"
        roots = [java_root] if java_root.exists() else [source_root]
        for root in roots:
            for path in root.rglob("*.java"):
                if any(
                    part in {".git", "target", "build", "out", ".gradle"} for part in path.parts
                ):
                    continue
                try:
                    text = path.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                package_match = re.search(r"(?m)^\s*package\s+([\w.]+)\s*;", text)
                package = package_match.group(1) if package_match else ""
                type_match = re.search(r"\b(?:interface|class)\s+([A-Za-z_$][\w$]*)\b", text)
                if not type_match:
                    continue
                class_name = type_match.group(1)
                full_name = f"{package}.{class_name}" if package else class_name
                methods: Dict[str, Dict[str, Any]] = {}
                pending_annotations: List[Dict[str, Any]] = []
                for line_no, line in enumerate(text.splitlines(), start=1):
                    stripped = line.strip()
                    if stripped.startswith("@"):
                        if re.match(r"@(Select|Insert|Update|Delete)\b", stripped):
                            pending_annotations.append({"line": line_no, "code": stripped})
                        continue
                    if re.search(r"\b(?:interface|class)\s+", stripped):
                        pending_annotations = []
                    if "(" not in stripped or ")" not in stripped or stripped.startswith("@"):
                        continue
                    method_match = re.search(
                        r"(?:public\s+|private\s+|protected\s+|default\s+|static\s+|final\s+|abstract\s+)*"
                        r"[\w$<>\[\].?,\s]+\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)",
                        stripped,
                    )
                    if not method_match:
                        continue
                    method_name = method_match.group(1)
                    params = Analyzer._java_method_parameter_names(method_match.group(2))
                    methods[method_name] = {
                        "method": method_name,
                        "parameters": params,
                        "line": line_no,
                        "signature": stripped,
                        "annotations": list(pending_annotations),
                    }
                    pending_annotations = []
                entry = {
                    "package": package,
                    "class_name": class_name,
                    "full_name": full_name,
                    "file": normalize_path(path, source_root),
                    "methods": methods,
                }
                index[full_name] = entry
                index[class_name] = entry
        return index

    @staticmethod
    def _java_method_parameter_names(parameter_text: str) -> List[str]:
        names: List[str] = []
        for raw_param in str(parameter_text or "").split(","):
            param = raw_param.strip()
            if not param:
                continue
            param_name = ""
            param_annotation = re.search(r"@Param\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", param)
            if param_annotation:
                param_name = param_annotation.group(1)
            cleaned = re.sub(r"@\w+(?:\([^)]*\))?\s*", "", param)
            cleaned = re.sub(r"\bfinal\s+", "", cleaned).strip()
            parts = cleaned.split()
            if parts:
                param_name = param_name or parts[-1].replace("...", "").replace("[]", "")
            if param_name:
                names.append(param_name)
        return names

    @staticmethod
    def _mybatis_xml_bindings(
        text: str,
        rel_path: str,
        mapper_interfaces: Dict[str, Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        namespace_match = re.search(r"<mapper\b[^>]*\bnamespace\s*=\s*['\"]([^'\"]+)['\"]", text)
        namespace = namespace_match.group(1).strip() if namespace_match else ""
        mapper = mapper_interfaces.get(namespace) or mapper_interfaces.get(
            namespace.rsplit(".", 1)[-1]
        )
        lines = text.splitlines()
        bindings: List[Dict[str, Any]] = []
        statement_re = re.compile(
            r"<(select|insert|update|delete)\b[^>]*\bid\s*=\s*['\"]([^'\"]+)['\"][^>]*>",
            re.I,
        )
        for idx, line in enumerate(lines, start=1):
            match = statement_re.search(line)
            if not match:
                continue
            tag = match.group(1).lower()
            statement_id = match.group(2).strip()
            body_lines = [line]
            end_line = idx
            end_re = re.compile(rf"</{tag}\s*>", re.I)
            if not end_re.search(line):
                for inner_idx in range(idx + 1, len(lines) + 1):
                    body_lines.append(lines[inner_idx - 1])
                    end_line = inner_idx
                    if end_re.search(lines[inner_idx - 1]):
                        break
            body = "\n".join(body_lines)
            variables = re.findall(r"\$\{\s*([^}\s]+)\s*}", body)
            variable_lines: Dict[str, int] = {}
            for offset, body_line in enumerate(body_lines):
                for variable in re.findall(r"\$\{\s*([^}\s]+)\s*}", body_line):
                    variable_lines.setdefault(variable, idx + offset)
            method = (mapper or {}).get("methods", {}).get(statement_id) if mapper else None
            parameters = method.get("parameters", []) if isinstance(method, dict) else []
            bound_variables = [
                variable
                for variable in variables
                if not parameters or variable.split(".", 1)[0] in parameters
            ]
            binding = {
                "namespace": namespace,
                "statement_id": statement_id,
                "statement_kind": tag,
                "file": rel_path,
                "start_line": idx,
                "end_line": end_line,
                "statement_text": body.strip(),
                "text_substitution_variables": variables,
                "variable_lines": variable_lines,
                "interface": mapper.get("full_name") if mapper else "",
                "interface_file": mapper.get("file") if mapper else "",
                "method": statement_id,
                "method_line": method.get("line", -1) if isinstance(method, dict) else -1,
                "method_signature": method.get("signature", "") if isinstance(method, dict) else "",
                "parameters": parameters,
                "bound_variables": bound_variables,
                "binding_precision": (
                    "xml_namespace_id_parameter_match"
                    if mapper and method and bound_variables
                    else ("xml_namespace_id_match" if mapper and method else "xml_statement_only")
                ),
            }
            bindings.append(binding)
        return bindings

    @staticmethod
    def _enrich_mybatis_xml_candidate(
        issue: Dict[str, Any],
        bindings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        if issue.get("rule") != "java_mybatis_dollar_substitution" or not bindings:
            return issue
        _file, line = parse_location_file_line(str(issue.get("location") or ""))
        binding = next(
            (
                item
                for item in bindings
                if int(item.get("start_line") or 0) <= line <= int(item.get("end_line") or 0)
            ),
            None,
        )
        if not binding:
            return issue
        enriched = dict(issue)
        binding_copy = deepcopy(binding)
        interface_name = str(binding_copy.get("interface") or "")
        method_name = str(binding_copy.get("method") or "")
        if interface_name and method_name:
            enriched["function"] = f"{interface_name}.{method_name}"
            enriched["secondary_function"] = f"<project-file>:{binding_copy.get('file')}"
        evidence = dict(enriched.get("evidence_pack") or {})
        evidence["mybatis_xml_binding"] = binding_copy
        evidence.setdefault("source", {})
        if isinstance(evidence["source"], dict):
            evidence["source"].update(
                {
                    "expression": ", ".join(
                        binding_copy.get("bound_variables")
                        or binding_copy.get("text_substitution_variables")
                        or []
                    ),
                    "kind": "mybatis_xml_mapper_parameter",
                    "mapper_interface": interface_name,
                    "mapper_method": method_name,
                    "mapper_parameters": binding_copy.get("parameters") or [],
                }
            )
        evidence.setdefault("path", {})
        if isinstance(evidence["path"], dict):
            evidence["path"].update(
                {
                    "complete_in_function": False,
                    "framework_binding": binding_copy.get("binding_precision"),
                    "path_constraints": [
                        "MyBatis XML statement uses textual ${...} substitution",
                        "XML namespace/id is matched to mapper interface method when available",
                        "validator must confirm caller-controlled values and allowlist constraints",
                    ],
                }
            )
        enriched["evidence_pack"] = evidence
        positive = list(enriched.get("positive_evidence") or [])
        positive.append(
            "MyBatis XML binding: "
            f"{binding_copy.get('namespace')}.{method_name} "
            f"variables={binding_copy.get('text_substitution_variables')} "
            f"parameters={binding_copy.get('parameters')} "
            f"precision={binding_copy.get('binding_precision')}."
        )
        enriched["positive_evidence"] = positive
        enriched["source"] = "MyBatis XML mapper parameter(s): " + ", ".join(
            binding_copy.get("bound_variables")
            or binding_copy.get("text_substitution_variables")
            or []
        )
        enriched["mybatis_xml_binding"] = binding_copy
        return enriched

    @staticmethod
    def _enrich_mybatis_annotation_candidate(
        issue: Dict[str, Any],
        rel_path: str,
        mapper_interfaces: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Any]:
        if issue.get("rule") != "java_mybatis_dollar_substitution":
            return issue
        _file, line = parse_location_file_line(str(issue.get("location") or ""))
        mapper = next(
            (
                item
                for item in mapper_interfaces.values()
                if isinstance(item, dict) and str(item.get("file") or "") == rel_path
            ),
            None,
        )
        if not mapper or line <= 0:
            return issue
        binding: Optional[Dict[str, Any]] = None
        for method in _as_dict(mapper.get("methods")).values():
            if not isinstance(method, dict):
                continue
            annotations = _as_list(method.get("annotations"))
            matched = next(
                (
                    annotation
                    for annotation in annotations
                    if isinstance(annotation, dict) and int(annotation.get("line") or 0) == line
                ),
                None,
            )
            if not matched:
                continue
            annotation_code = str(matched.get("code") or "")
            variables = re.findall(r"\$\{\s*([^}\s]+)\s*}", annotation_code)
            parameters = _as_list(method.get("parameters"))
            binding = {
                "interface": mapper.get("full_name") or "",
                "interface_file": rel_path,
                "method": method.get("method") or "",
                "method_line": method.get("line") or 0,
                "method_signature": method.get("signature") or "",
                "parameters": parameters,
                "annotation_line": line,
                "annotation_code": annotation_code,
                "text_substitution_variables": variables,
                "bound_variables": [
                    variable
                    for variable in variables
                    if not parameters or variable.split(".", 1)[0] in parameters
                ],
                "binding_precision": "annotation_method_parameter_match",
            }
            break
        if not binding:
            return issue
        enriched = dict(issue)
        binding_copy = deepcopy(binding)
        interface_name = str(binding_copy.get("interface") or "")
        method_name = str(binding_copy.get("method") or "")
        if interface_name and method_name:
            enriched["function"] = f"{interface_name}.{method_name}"
            enriched["secondary_function"] = f"<project-file>:{rel_path}"
        enriched["file"] = rel_path
        enriched["file_path"] = rel_path
        enriched["line"] = line
        enriched["start_line"] = line
        enriched["location"] = f"{rel_path}:{line}"
        evidence = dict(enriched.get("evidence_pack") or {})
        evidence["mybatis_annotation_binding"] = binding_copy
        variables = (
            binding_copy.get("bound_variables")
            or binding_copy.get("text_substitution_variables")
            or []
        )
        evidence["source"] = {
            "expression": ", ".join(variables),
            "kind": "mybatis_annotation_mapper_parameter",
            "mapper_interface": interface_name,
            "mapper_method": method_name,
            "mapper_parameters": binding_copy.get("parameters") or [],
            "line": line,
            "file": rel_path,
        }
        evidence["sink"] = {
            "operation": "MyBatis annotation ${} text substitution",
            "line": line,
            "file": rel_path,
            "kind": "mybatis_annotation_sql_text_substitution",
        }
        evidence.setdefault("path", {})
        if isinstance(evidence["path"], dict):
            evidence["path"].update(
                {
                    "complete_in_function": True,
                    "framework_binding": binding_copy.get("binding_precision"),
                    "path_constraints": [
                        "MyBatis annotation statement uses textual ${...} substitution",
                        "Mapper annotation line is the primary report coordinate",
                        "dynamic SQL identifiers require allowlist validation",
                    ],
                }
            )
        enriched["evidence_pack"] = evidence
        enriched["source"] = "MyBatis mapper annotation parameter(s): " + ", ".join(variables)
        enriched["sink"] = "MyBatis annotation ${} text substitution"
        enriched["mybatis_annotation_binding"] = binding_copy
        positive = list(enriched.get("positive_evidence") or [])
        positive.append(
            "MyBatis annotation binding: "
            f"{interface_name}.{method_name} variables={binding_copy.get('text_substitution_variables')} "
            f"parameters={binding_copy.get('parameters')} precision={binding_copy.get('binding_precision')}."
        )
        enriched["positive_evidence"] = positive
        return enriched

    @staticmethod
    def _mybatis_xml_project_file_candidates(
        rel_path: str,
        bindings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Emit project-file level MyBatis XML SQLi candidates.

        Mapper-method candidates are useful for call-chain validation, while
        regression suites and real audits also need a file-scoped finding that
        points at the XML statement itself.
        """
        candidates: List[Dict[str, Any]] = []
        for binding in bindings:
            if not isinstance(binding, dict):
                continue
            variables = [
                str(item)
                for item in (binding.get("text_substitution_variables") or [])
                if str(item)
            ]
            if not variables:
                continue
            variable_lines = _as_dict(binding.get("variable_lines"))
            line = int(variable_lines.get(variables[0]) or binding.get("start_line") or -1)
            statement_text = str(binding.get("statement_text") or "")
            sink = f"MyBatis XML ${variables[0]} text substitution"
            candidate_id = (
                "JAVA_RULE_SQL_INJECTION_XML_"
                + hashlib.sha1(
                    f"java:mybatis-xml:{rel_path}:{binding.get('statement_id')}:{line}:{','.join(variables)}".encode(
                        "utf-8"
                    )
                ).hexdigest()[:10]
            )
            function = f"<project-file>:{rel_path}"
            mapper_function = ".".join(
                part
                for part in [
                    str(binding.get("interface") or ""),
                    str(binding.get("method") or ""),
                ]
                if part
            )
            binding_copy = deepcopy(binding)
            evidence_pack: Dict[str, Any] = {
                "candidate_id": candidate_id,
                "candidate_source": "java_local_rule",
                "defect_class": "sql_injection",
                "rule": "java_mybatis_xml_project_text_substitution",
                "rule_confidence": 0.86,
                "language": "java",
                "source": {
                    "expression": ", ".join(binding.get("bound_variables") or variables),
                    "kind": "mybatis_xml_mapper_parameter",
                    "mapper_interface": binding.get("interface") or "",
                    "mapper_method": binding.get("method") or "",
                    "mapper_parameters": binding.get("parameters") or [],
                    "line": line,
                    "file": rel_path,
                },
                "sink": {
                    "operation": sink,
                    "statement": binding.get("statement_id"),
                    "statement_kind": binding.get("statement_kind"),
                    "line": line,
                    "file": rel_path,
                },
                "path": {
                    "function": function,
                    "complete_in_function": True,
                    "framework_binding": binding.get("binding_precision"),
                    "guard_status": "insufficient_or_absent",
                    "path_constraints": [
                        "MyBatis XML statement uses textual ${...} substitution",
                        "XML namespace/id is matched to mapper interface method when available",
                        "dynamic SQL identifiers require allowlist validation",
                    ],
                },
                "positive_evidence": [
                    f"MyBatis XML statement `{binding.get('statement_id')}` in `{rel_path}` uses textual substitution variables {variables}.",
                    f"Statement text: {statement_text}",
                    f"Binding precision: {binding.get('binding_precision')}.",
                ],
                "negative_evidence": [],
                "mybatis_xml_binding": binding_copy,
                "evidence_refs": [],
            }
            description = (
                "MyBatis XML mapper uses ${...} text substitution, which directly "
                "concatenates mapper parameters into SQL."
            )
            candidates.append(
                {
                    "id": candidate_id,
                    "candidate_id": candidate_id,
                    "function": function,
                    "secondary_function": mapper_function,
                    "location": f"{rel_path}:{line}",
                    "file": rel_path,
                    "file_path": rel_path,
                    "line": line,
                    "start_line": line,
                    "category": "sql_injection",
                    "subcategory": "sql_injection",
                    "defect_class": "sql_injection",
                    "finding_kind": "java_rule_candidate",
                    "candidate_source": "java_local_rule",
                    "evidence_checker": "java_local_rule_checker",
                    "rule": "java_mybatis_xml_project_text_substitution",
                    "cwe": "CWE-89",
                    "description": description,
                    "root_cause": "MyBatis `${}` performs raw SQL text substitution instead of parameter binding.",
                    "suggested_fix": "Use `#{}` for values. For ORDER BY or identifiers, map request values through an explicit allowlist or enum.",
                    "confidence": 0.86,
                    "rule_confidence": 0.86,
                    "impact_level": "high",
                    "reasoning": (
                        f"Java project-file rule `java_mybatis_xml_project_text_substitution` matched "
                        f"`{sink}` in `{rel_path}:{line}`. {description}"
                    ),
                    "code_snippet": statement_text,
                    "source": "MyBatis XML mapper parameter(s): "
                    + ", ".join(binding.get("bound_variables") or variables),
                    "sink": sink,
                    "dedup_key": "|".join(
                        [
                            "sql_injection",
                            rel_path.replace("\\", "/").lower(),
                            str(line),
                            str(binding.get("statement_id") or ""),
                            ",".join(variables),
                        ]
                    ),
                    "positive_evidence": list(evidence_pack["positive_evidence"]),
                    "negative_evidence": [],
                    "evidence_pack": evidence_pack,
                    "evidence_refs": [],
                    "mybatis_xml_binding": binding_copy,
                }
            )
        return candidates

    @staticmethod
    def _iter_java_auxiliary_rule_files(source_root: Path) -> Iterable[Path]:
        suffixes = {".java", ".xml", ".properties", ".yml", ".yaml"}
        blocked_parts = {".git", "target", "build", "out", ".gradle", ".idea", "__pycache__"}
        for path in source_root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in suffixes:
                continue
            if any(part in blocked_parts for part in path.parts):
                continue
            yield path

    @staticmethod
    def _java_file_may_contain_mybatis_annotation_substitution(text: str) -> bool:
        return "${" in str(text or "") and bool(
            re.search(r"@(Select|Insert|Update|Delete)\b", str(text or ""))
        )

    @staticmethod
    def _java_auxiliary_file_may_contain_rule_signal(text: str) -> bool:
        lowered = str(text or "").lower()
        return any(
            marker in lowered
            for marker in (
                "${",
                "password",
                "secret",
                "apikey",
                "api-key",
                "accesskey",
                "token",
                "allowed-origins",
                "allowedorigins",
                "cors",
                "mapper",
                "<select",
                "<insert",
                "<update",
                "<delete",
            )
        )
