"""Session-level scan orchestration for CLI and other frontends."""

from __future__ import annotations

import logging
import json
import os
import re
import shutil
import stat
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, cast

from ..config.config import ZScopeConfig
from ..config.function_entry import FunctionEntry, FunctionListLoader
from ..common.cancellation import CancellationToken
from ..core.analysis.analyzer import Analyzer
from .parallel_analyzer import ParallelAnalysisResult, ParallelAnalyzer
from .scheduler import ScanScheduler
from ..snapshots.store import SnapshotStore
from ..snapshots.modeling_input import (
    SemanticModelInputError,
    build_semantic_model_input,
    hydrate_project_callee_summaries,
)
from ..retrieval.code_index import CodeIndex, _JobRuntimeOutputs
from .entry_instances import EntryInstancePlan, plan_entry_instances
from ..reporting.schema import (
    EXIT_POLICIES,
    exit_code_for_report,
    report_reuse_blockers,
    unresolved_obligation_count as count_unresolved_obligations,
)
from ..reporting.json_io import write_report_atomic
from .entry_discovery import EntryDiscovery
from .java_entry_discovery import JavaEntryDiscovery
from .diff_impact import DiffImpactPlanner
from .specs import SpecRegistry, WorkflowStep
from .workflow_executor import WorkflowExecutor, WorkflowStepHandler
from ..rules.extensions import preflight_rules
from ..benchmarking.discovery_ablation import DiscoveryAblationRuntimeOverride

logger = logging.getLogger(__name__)

DISCOVERED_ENTRY_FUNCTIONS_FILENAME = "entry_functions_list.json"
DIFF_ENTRY_FUNCTIONS_FILENAME = "entry_functions_diff.json"


@dataclass
class ScanSessionResult:
    is_batch: bool
    exit_code: int
    reports: List[Path] = field(default_factory=list)
    issues_count: int = 0
    needs_review_count: int = 0
    functions_analyzed: int = 0
    verdict: str = "unknown"
    interrupted: bool = False
    interrupted_entries: List[str] = field(default_factory=list)
    project_root: Optional[Path] = None
    finding_status: str = "clean"
    completeness: str = "complete"
    scan_outcome: str = "clean"
    unresolved_obligations_count: int = 0
    task_id: str = ""
    task_slug: str = ""


class ScanSessionRunner:
    """Coordinate one full scan session across discovery, batch, and entry analysis."""

    def __init__(
        self,
        config: ZScopeConfig,
        *,
        resume: bool = False,
        maintain: bool = False,
        discover_entries: bool = False,
        diff_base: Optional[str] = None,
        diff_head: str = "HEAD",
        diff_repo_root: Optional[Path] = None,
        diff_paths: Optional[Sequence[str]] = None,
        emit: Optional[Callable[[str], None]] = None,
        exit_policy: str = "review",
        task_id: str = "",
        benchmark_ablation_override: Optional[DiscoveryAblationRuntimeOverride] = None,
    ) -> None:
        if benchmark_ablation_override is not None:
            benchmark_ablation_override.require_in_process_supported()
            benchmark_ablation_override.attest_cold_runtime(
                config,
                resume=resume,
                maintain=maintain,
            )
        self.spec_registry = SpecRegistry(project_root=config.project.project_root)
        preflight_rules(config, spec_registry=self.spec_registry)
        self.config = config
        self.task_id = str(task_id or "").strip()
        self.task_slug = _task_slug(self.task_id)
        self._benchmark_ablation_override = benchmark_ablation_override
        self.resume = resume
        self.maintain = maintain
        self.discover_entries = discover_entries
        self.diff_base = diff_base
        self.diff_head = diff_head or "HEAD"
        self.diff_repo_root = (
            Path(diff_repo_root).resolve() if diff_repo_root else config.project.source_root
        )
        self.diff_paths = [str(path).strip() for path in (diff_paths or []) if str(path).strip()]
        self.diff_scope_name = (
            config.project.source_root.name or config.project.project_root.name or "default"
        )
        self.emit = emit or (lambda message: None)
        normalized_exit_policy = str(exit_policy or "review").lower()
        if normalized_exit_policy not in EXIT_POLICIES:
            raise ValueError(f"Unsupported exit policy: {exit_policy}")
        self.exit_policy = normalized_exit_policy
        self._budget_exhaustion_policy = "observe"
        self._cancellation_token = CancellationToken()
        from ..core.validation.reproduction_planner import SessionReproductionPlanner

        self.reproduction_service = SessionReproductionPlanner(config)
        self.workflow_spec = self.spec_registry.get_workflow(config.analysis.workflow_name)
        self.session_progress: List[Dict[str, Any]] = []
        self.batch_progress: List[Dict[str, Any]] = []
        self.session_step_handlers = self._build_session_step_handlers()
        self.batch_step_handlers = self._build_batch_step_handlers()
        self.session_executor = WorkflowExecutor(
            workflow_name=self._workflow_name(),
            scope="session",
            handlers=self.session_step_handlers,
            progress=self.session_progress,
            cancellation_token=self._cancellation_token,
        )
        self.batch_executor = WorkflowExecutor(
            workflow_name=self._workflow_name(),
            scope="batch",
            handlers=self.batch_step_handlers,
            progress=self.batch_progress,
            cancellation_token=self._cancellation_token,
        )
        self.session_executor.validate(self._selected_workflow_steps())
        self.batch_executor.validate(self._selected_workflow_steps())

    def run(self) -> ScanSessionResult:
        state = self._create_state()
        try:
            self._plan_diff_impact_entries(state)
            steps = self._selected_workflow_steps()
            self.session_executor.execute(state, steps)
            self._ensure_batch_entries(state)
            self._plan_entry_instances(state)
            state["instance_execution_mode"] = self._instance_execution_mode(state)
            if state["instance_execution_mode"] == "legacy":
                self._ensure_semantic_phase(state)
            else:
                # Instance execution consumes exact per-instance native facts.
                # The project-wide semantic model is not built here: its global
                # evidence must never authorize an instance-scoped result.
                logger.info(
                    "Instance execution mode=%s; project-wide semantic modeling is not run.",
                    state["instance_execution_mode"],
                )

            if state.get("batch_mode"):
                return self._run_batch(state, steps)
            if self._benchmark_ablation_override is not None:
                raise ValueError(
                    "discovery ablation execution requires a frozen batch Candidate Ledger"
                )
            return self._run_single(state)
        finally:
            parallel_analyzer = state.get("parallel_analyzer")
            can_close_session_resources = not bool(
                getattr(parallel_analyzer, "_interrupted", False)
            )
            if state.get("wiki_compile_completed") and can_close_session_resources:
                Analyzer.close_project_knowledge_service(state.get("project_knowledge_service"))
                self._close_llm_clients(state.get("llm_clients") or {})
            code_index = state.get("code_index")
            if code_index:
                code_index.close()

    def _create_state(self) -> Dict[str, Any]:
        return {
            "code_index": None,
            "discovered_entries": [],
            "entries": [],
            "all_entries": [],
            "skipped_entries": [],
            "entries_loaded": False,
            "batch_mode": False,
            "results": {},
            "parallel_analyzer": None,
            "project_knowledge_service": None,
            "llm_clients": None,
            "wiki_compile_completed": False,
            "merged_skipped_reports": 0,
            "discovery_result": None,
            "diff_impact_result": None,
        }

    def _workflow_name(self) -> str:
        if self.workflow_spec:
            return self.workflow_spec.name
        return self.config.analysis.workflow_name

    def _selected_workflow_steps(self) -> List[WorkflowStep]:
        if self.workflow_spec and self.workflow_spec.steps:
            return self.workflow_spec.steps
        return []

    def _build_session_step_handlers(self) -> Dict[str, WorkflowStepHandler]:
        return {
            "discover_entries": self._handle_discover_entries,
            "wiki_compile": self._handle_wiki_compile,
            "plan_resume_entries": self._handle_plan_resume_entries,
        }

    def _build_batch_step_handlers(self) -> Dict[str, WorkflowStepHandler]:
        return {
            "merge_skipped_reports": self._handle_merge_skipped_reports,
        }

    def _handle_discover_entries(self, state: Dict[str, Any], step: WorkflowStep) -> bool:
        if self.diff_base:
            logger.info("Skipping full entry discovery because diff impact mode is active.")
            return False
        should_discover = self.discover_entries or self.config.project.entry_discovery.enabled
        if not should_discover:
            return False

        logger.info("Entry discovery activated.")
        if self.config.project.language == "java":
            self.emit(
                "Discovering Java web, CLI, message, scheduled, servlet, and library entries..."
            )
        else:
            self.emit(
                "Discovering scan entries from headers, communication APIs, "
                "thread creation, and input sources..."
            )
        code_index = self._ensure_code_index(state, defer_svf=True)
        discovery_cfg = self.config.project.entry_discovery
        discovery_type = (
            JavaEntryDiscovery if self.config.project.language == "java" else EntryDiscovery
        )
        discovery = discovery_type(
            code_index,
            max_functions=discovery_cfg.max_functions,
            interface_files=discovery_cfg.interface_files or None,
            project_root=self.config.project.project_root,
            source_root=self.config.project.source_root,
            search_root=discovery_cfg.search_root,
        )
        discovery_result = discovery.discover(max_candidates=discovery_cfg.max_entries)
        discovered_entries = discovery_result.to_function_entries()
        state["discovery_result"] = discovery_result.to_dict()
        state["discovered_entries"] = discovered_entries
        entry_list_path = self._write_discovered_entry_functions_list(discovery_result)
        state["discovered_entry_functions_list"] = str(entry_list_path)
        if discovered_entries and not self.config.project.entry_functions_list:
            self.config.project.entry_functions_list = entry_list_path
        self.emit(
            f"Entry discovery: {discovery_result.exposure_kind}, "
            f"{len(discovered_entries)} candidate(s), summary={discovery_result.summary}"
        )
        self.emit(f"Discovered entry function list written to: {entry_list_path}")
        if not discovered_entries and self.config.project.entry_function:
            self.emit("No discovered entries found; falling back to configured entry_function.")
        return False

    def _handle_wiki_compile(self, state: Dict[str, Any], step: WorkflowStep) -> bool:
        """Compile and pin project knowledge before any entry analysis starts."""

        wiki = getattr(getattr(self.config, "project", None), "wiki", None)
        mode = str(getattr(wiki, "mode", "off") or "off").strip().lower()
        if mode == "off":
            state["project_knowledge_service"] = None
            state["wiki_compile_completed"] = True
            return False

        logger.info("[wiki-compile] start mode=%s", mode)
        self.emit("Compiling project Wiki before entry analysis and validation...")
        llm_clients = ParallelAnalyzer._build_shared_llm_clients(self.config)
        state["llm_clients"] = llm_clients
        try:
            state["project_knowledge_service"] = Analyzer.build_project_knowledge_service(
                self.config,
                llm_clients,
            )
        except Exception:
            self._close_llm_clients(llm_clients)
            state["llm_clients"] = None
            raise
        state["wiki_compile_completed"] = True
        logger.info("[wiki-compile] end mode=%s", mode)
        self.emit("Project Wiki compile stage completed.")
        return False

    @staticmethod
    def _close_llm_clients(llm_clients: Dict[str, Any]) -> None:
        seen: set[int] = set()
        for client in llm_clients.values():
            client_id = id(client)
            if client_id in seen:
                continue
            seen.add(client_id)
            close_client = getattr(client, "close", None)
            if callable(close_client):
                close_client()

    def _plan_diff_impact_entries(self, state: Dict[str, Any]) -> None:
        if not self.diff_base or state.get("diff_impact_result"):
            return

        self.emit(
            f"Planning diff impact entries for {self.diff_scope_name}: "
            f"{self.diff_base}..{self.diff_head}"
        )
        if self.diff_paths:
            self.emit("Diff path filters: " + ", ".join(self.diff_paths))
        code_index = self._ensure_code_index(state, defer_svf=True)
        discovery_cfg = self.config.project.entry_discovery
        planner = DiffImpactPlanner(
            code_index,
            repo_root=self.diff_repo_root,
            base_ref=self.diff_base,
            head_ref=self.diff_head,
            component=self.diff_scope_name,
            interface_files=discovery_cfg.interface_files or None,
            strategy=getattr(self.config.project.diff_impact, "strategy", "semantic_obligation"),
            llm_triage=getattr(self.config.project.diff_impact, "llm_triage", "on_demand"),
            caller_search_depth_by_intent=getattr(
                self.config.project.diff_impact,
                "caller_search_depth_by_intent",
                {},
            ),
            diff_paths=self.diff_paths,
            synthetic_depth_threshold=max(1, int(self.config.analysis.max_recursion_depth or 3)),
        )
        plan = planner.plan()
        entry_list_path = self.config.project.project_root / DIFF_ENTRY_FUNCTIONS_FILENAME
        planner.write_entry_functions_file(entry_list_path, plan)
        self.config.project.entry_functions_list = entry_list_path
        state["diff_impact_result"] = plan.to_entry_functions_payload().get("diff_impact", {})
        state["discovered_entry_functions_list"] = str(entry_list_path)
        self.emit(
            "Diff impact planning: "
            f"{len(plan.changed_functions)} changed function(s), "
            f"{len(plan.entries)} entry candidate(s)."
        )
        self.emit(f"Diff impact entry function list written to: {entry_list_path}")
        if not plan.entries:
            filter_text = ", ".join(self.diff_paths) if self.diff_paths else "none"
            raise RuntimeError(
                "Diff impact planning produced no scan entries "
                f"for {self.diff_base}..{self.diff_head} "
                f"(path filters: {filter_text}). "
                f"Entry function list was written to: {entry_list_path}"
            )

    def _write_discovered_entry_functions_list(
        self,
        discovery_result: Any,
    ) -> Path:
        path = self.config.project.project_root / DISCOVERED_ENTRY_FUNCTIONS_FILENAME
        payload = discovery_result.to_entry_functions_payload()
        path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        return path

    def _handle_plan_resume_entries(self, state: Dict[str, Any], step: WorkflowStep) -> bool:
        if not self.resume:
            return False

        self._ensure_batch_entries(state)
        if self.config.project.language != "java":
            # A precise compile-instance scan never resumes from a name-only
            # saved report, and never borrows the project-wide semantic model:
            # its only authorization is the exact current instance plan, and a
            # real completion can come only from a trusted instance checkpoint.
            state.setdefault("skipped_entries", [])
            logger.info(
                "Resume: instance scanning ignores name-only saved reports and the "
                "global semantic model."
            )
            return False

        self._ensure_semantic_phase(state)
        if not state.get("batch_mode"):
            return False

        self.emit("Resuming scan: determining skip points from snapshot store...")
        snapshot_store = SnapshotStore.from_config(self.config)
        code_index = self._ensure_code_index(state, defer_svf=True)
        remaining: List[FunctionEntry] = []
        skipped: List[FunctionEntry] = []
        business_answer_store = None

        for entry in state["entries"]:
            saved_report = self._load_current_saved_report(
                snapshot_store,
                code_index,
                entry,
            )
            semantic_result = state.get("semantic_result")
            from ..snapshots.policy import semantic_experiment_requires_scan

            if semantic_experiment_requires_scan(
                self.config.analysis, (saved_report or {}).get("metadata")
            ):
                saved_report = None
            if semantic_result is not None:
                from ..snapshots.policy import SNAPSHOT_CANDIDATE_POLICY_VERSION

                if (
                    semantic_result.partial
                    or (saved_report or {}).get("metadata", {}).get("snapshot_candidate_policy")
                    != SNAPSHOT_CANDIDATE_POLICY_VERSION
                    or (saved_report or {}).get("metadata", {}).get("semantic_contract_version")
                    != semantic_result.contract_version
                ):
                    saved_report = None
            if saved_report:
                from ..semantics.business_assumptions import report_assessments

                if business_answer_store is None and any(report_assessments(saved_report)):
                    from ..config.user_config_store import UserConfigStore

                    try:
                        business_answer_store = UserConfigStore(
                            Path(
                                self.config.analysis.user_config_db
                                or self.config.analysis.snapshot_dir
                            )
                        )
                    except Exception as exc:
                        logger.warning(
                            "Business feedback unavailable; report requires revalidation: %s", exc
                        )
                blockers = report_reuse_blockers(
                    saved_report, business_answer_store=business_answer_store
                )
                if blockers:
                    logger.info(
                        "Not auto-skipping '%s': historical report is not reusable (%s).",
                        entry.function_name,
                        ", ".join(blockers),
                    )
                    remaining.append(entry)
                else:
                    logger.info(
                        "Auto-skipping '%s': complete compatible report has no unresolved terminals.",
                        entry.function_name,
                    )
                    skipped.append(entry)
            else:
                remaining.append(entry)

        state["entries"] = remaining
        state["skipped_entries"] = skipped
        self.emit(
            f"Skipped {len(skipped)} already-completed functions, " f"{len(remaining)} remaining."
        )
        return False

    def _plan_entry_instances(self, state: Dict[str, Any]) -> None:
        """Build the entry compile-instance plan before any analysis dispatch.

        The plan is the scheduling boundary: every scheduled instance is an
        exact ``(build_context_id, usr)`` pair, and anything unverifiable stays
        an explicit coverage gap instead of a wildcard.
        """

        if state.get("entry_instance_plan") is not None:
            return
        plan = self._build_entry_instance_plan(state)
        state["entry_instance_plan"] = plan
        if plan.status == "planned":
            self.emit(
                "Entry instance planning: "
                f"{len(plan.instances)} instance(s) for {plan.entry_count} entry(ies), "
                f"{len(plan.gaps)} coverage gap(s)."
            )
            if plan.gaps:
                self.emit(
                    "Variant coverage incomplete: "
                    + ", ".join(sorted({gap.reason for gap in plan.gaps}))
                )
        elif plan.status == "unavailable":
            self.emit("Entry instance planning unavailable: " + ", ".join(plan.reasons))

    def _build_entry_instance_plan(self, state: Dict[str, Any]) -> EntryInstancePlan:
        if self.config.project.language == "java":
            return EntryInstancePlan(
                status="not_applicable",
                reasons=["java_scan_has_no_compilation_instances"],
            )
        entries = list(state.get("entries") or [])
        if not entries and self.config.project.entry_function:
            entries = [
                FunctionEntry(
                    self.config.project.entry_function,
                    file_path=self.config.project.entry_file_path,
                    signature=self.config.project.entry_signature,
                )
            ]
        if not entries:
            return EntryInstancePlan(status="not_applicable", reasons=["no_scan_entries"])
        code_index = self._ensure_code_index(state, defer_svf=True)
        try:
            # The instance plan reads the exact-context store, so the index must
            # be materialized first (its batch extraction produces the
            # compilation instances).  Without this the plan would look empty
            # for a real project and the scan would fall into the coverage gap.
            backend_name = str(getattr(code_index, "backend_name", "") or "").lower()
            ensure_ready = getattr(code_index, "ensure_index_ready", None)
            if backend_name in {"clang", "unified"} and callable(ensure_ready):
                ensure_ready()
        except Exception:
            logger.exception("Index warm-up before instance planning failed.")
        try:
            return plan_entry_instances(
                code_index,
                entries,
                compile_commands_path=self.config.project.compile_commands_path,
            )
        except Exception as exc:
            logger.exception("Entry instance planning failed; coverage stays unknown.")
            return EntryInstancePlan(
                status="unavailable",
                reasons=[f"entry_instance_planning_failed:{exc}"],
                entry_count=len(entries),
            )

    @staticmethod
    def _attach_entry_instance_coverage(
        report: Dict[str, Any],
        state: Dict[str, Any],
    ) -> None:
        plan = state.get("entry_instance_plan")
        if isinstance(plan, EntryInstancePlan):
            report.setdefault("metadata", {})["entry_instances"] = plan.to_payload(
                state.get("instance_analysis")
            )

    def _instance_execution_mode(self, state: Dict[str, Any]) -> str:
        """Decide whether this scan runs on exact compile instances.

        ``legacy`` keeps the historical path (Java has no compilation
        instances; a scan with no entries at all has nothing to schedule).
        ``instances`` runs the precise ``EntryInstance`` schedule.  ``gap``
        means the project is C/C++ and no instance could be verified: the scan
        then reports the explicit coverage gap instead of silently falling
        back to a name-only analysis of an unknown build.
        """

        if self.config.project.language == "java":
            return "legacy"
        plan = state.get("entry_instance_plan")
        if not isinstance(plan, EntryInstancePlan):
            return "legacy"
        if plan.status == "not_applicable":
            return "legacy"
        if plan.status == "planned" and plan.instances:
            return "instances"
        return "gap"

    def _instance_analysis_required(self, state: Dict[str, Any]) -> bool:
        return str(state.get("instance_execution_mode") or "legacy") == "instances"

    def _write_instance_gap_report(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """A report that states the uncovered instance gap without analysis."""

        plan = state.get("entry_instance_plan")
        plan_payload = plan.to_payload() if isinstance(plan, EntryInstancePlan) else {}
        report: Dict[str, Any] = {
            "overall_verdict": "unknown",
            "issues": [],
            "summary": {
                "total_issues": 0,
                "functions_analyzed": 0,
                "needs_review_issues": 0,
            },
            "metadata": {
                "entry_instances": plan_payload,
                "instance_execution": {
                    "mode": "gap",
                    "planned_instances": len(getattr(plan, "instances", []) or []),
                    "analyzed_instances": 0,
                    "reason": "no_verifiable_compilation_instance",
                },
            },
            "completeness": "incomplete",
            "finding_status": "unknown",
            "scan_outcome": "incomplete",
        }
        self._annotate_task_report(report)
        return report

    def _ensure_semantic_phase(self, state: Dict[str, Any]) -> None:
        if self.config.project.language == "java" or state.get("semantic_result") is not None:
            return
        self._ensure_batch_entries(state)
        entries = list(state.get("all_entries") or state.get("entries") or [])
        if not entries and self.config.project.entry_function:
            entries = [
                FunctionEntry(
                    self.config.project.entry_function,
                    file_path=self.config.project.entry_file_path,
                    signature=self.config.project.entry_signature,
                )
            ]
        if not entries:
            return
        code_index = self._ensure_code_index(state, defer_svf=True)
        if state.get("llm_clients") is None:
            state["llm_clients"] = ParallelAnalyzer._build_shared_llm_clients(self.config)
        self.emit("Modeling entry-reachable functions before rule scanning...")
        helper = Analyzer(
            self.config,
            code_index=code_index,
            llm_clients=state["llm_clients"],
            project_knowledge_service=state.get("project_knowledge_service"),
            cancellation_token=self._cancellation_token,
            write_root_reports=False,
        )
        try:
            state["semantic_result"] = helper.prepare_semantics(entries)
        finally:
            helper.close()

    @staticmethod
    def _entry_report_file_path(entry: FunctionEntry) -> Optional[str]:
        focus = entry.diff_focus if isinstance(entry.diff_focus, dict) else {}
        file_path = str(entry.file_path or focus.get("entry_file_path") or "").strip()
        return file_path or None

    def _load_current_saved_report(
        self,
        snapshot_store: SnapshotStore,
        code_index: Any,
        entry: FunctionEntry,
    ) -> Optional[Dict[str, Any]]:
        try:
            context = build_semantic_model_input(
                code_index,
                entry.lookup_query(),
                file_path=self._entry_report_file_path(entry) or "",
                include_context=False,
            )
            context = hydrate_project_callee_summaries(
                context,
                code_index,
                snapshot_store,
            )
        except SemanticModelInputError:
            return None
        index_name = str(context["index_name"])
        needs_refresh, _reason = snapshot_store.needs_refresh(
            index_name,
            str(context["code"]),
            context,
        )
        if needs_refresh:
            return None
        return snapshot_store.load_final_report(index_name)

    def _handle_merge_skipped_reports(self, state: Dict[str, Any], step: WorkflowStep) -> bool:
        skipped_entries: List[FunctionEntry] = state.get("skipped_entries", [])
        if not skipped_entries:
            return False

        results: Dict[str, ParallelAnalysisResult] = state["results"]
        snapshot_store = SnapshotStore.from_config(self.config)
        code_index = self._ensure_code_index(state, defer_svf=True)
        merged_count = 0
        for entry in skipped_entries:
            fname = entry.function_name
            entry_key = ParallelAnalyzer._entry_result_key(entry)
            if entry_key in results:
                continue

            saved_report = self._load_current_saved_report(
                snapshot_store,
                code_index,
                entry,
            )
            if saved_report:
                metadata = saved_report.get("metadata", {})
                results[entry_key] = ParallelAnalysisResult(
                    function_name=fname,
                    verdict=saved_report.get("overall_verdict", "unknown"),
                    entry_identity=entry.identity_key(self.config.project.project_root),
                    entry_file_path=entry.normalized_file_path(self.config.project.project_root),
                    entry_signature=FunctionEntry.normalize_signature(entry.signature),
                    issues=saved_report.get("issues", []),
                    audit_observations=(
                        metadata.get("audit_observations", []) if isinstance(metadata, dict) else []
                    ),
                    candidate_terminal_states=saved_report.get("candidate_terminal_states", []),
                    duration_seconds=0.0,
                    diff_focus=entry.diff_focus,
                    metadata=metadata if isinstance(metadata, dict) else {},
                )
                merged_count += 1
            else:
                logger.warning(
                    "No saved report found in SQLite for skipped function '%s'",
                    fname,
                )

        state["merged_skipped_reports"] = merged_count
        if merged_count > 0:
            logger.info(
                "Loaded %d skipped function reports from snapshot database.",
                merged_count,
            )
        return False

    def _ensure_batch_entries(self, state: Dict[str, Any]) -> None:
        if state.get("entries_loaded"):
            return

        discovered_entries: List[FunctionEntry] = state.get("discovered_entries", [])
        if self.config.project.entry_functions_list:
            logger.info(
                "Batch mode activated: %s",
                self.config.project.entry_functions_list,
            )
            entries = FunctionListLoader.load(self.config.project.entry_functions_list)
            logger.info("Loaded %d function entries", len(entries))
            batch_mode = True
        elif discovered_entries:
            logger.info(
                "Discovered batch mode activated: %d entries",
                len(discovered_entries),
            )
            entries = discovered_entries
            batch_mode = True
        else:
            entries = []
            batch_mode = False

        state["entries"] = entries
        state["all_entries"] = list(entries)
        state["entries_loaded"] = True
        state["batch_mode"] = batch_mode

    def _ensure_code_index(
        self,
        state: Dict[str, Any],
        priority_functions: Optional[List[str]] = None,
        svf_entry_functions: Optional[List[Any]] = None,
        defer_svf: bool = False,
    ) -> CodeIndex:
        if state.get("code_index") is None:
            state["code_index"] = CodeIndex(
                self.config.project.project_root,
                self.config.project.compile_commands_path,
                source_root=self.config.project.source_root,
                indexing_config=self.config.indexing,
                priority_functions=priority_functions,
                include_paths=self.config.project.include_paths,
                exclude_paths=self.config.project.exclude_paths,
                svf_entry_functions=svf_entry_functions,
                defer_svf=defer_svf,
                svf_parallel_workers=(
                    self.config.concurrency.svf_workers or self.config.concurrency.index_workers
                ),
            )
        return cast(CodeIndex, state["code_index"])

    @staticmethod
    def _entry_names(entries: List[FunctionEntry]) -> List[str]:
        return [entry.function_name for entry in entries if entry.function_name]

    def _svf_scope_entries(
        self,
        state: Dict[str, Any],
        active_entries: List[FunctionEntry],
    ) -> List[FunctionEntry]:
        """Return the entry set that should define SVF cache scope."""
        if self.resume:
            all_entries: List[FunctionEntry] = state.get("all_entries", [])
            if all_entries:
                return list(all_entries)
        return list(active_entries)

    def _ensure_svf_for_entries(self, state: Dict[str, Any], entries: List[FunctionEntry]) -> None:
        code_index = state.get("code_index")
        if not code_index:
            return
        if self.resume and not entries:
            logger.info("Resume has no remaining entries; skipping deferred SVF run.")
            return
        svf_entries = self._svf_scope_entries(state, entries)
        entry_names = self._entry_names(svf_entries)
        if not entry_names and self.config.project.entry_function:
            entry_names = [self.config.project.entry_function]
        if entry_names:
            code_index.run_svf(svf_entries)

    def _run_batch(
        self,
        state: Dict[str, Any],
        steps: List[WorkflowStep],
    ) -> ScanSessionResult:
        mode = str(state.get("instance_execution_mode") or "legacy")
        if mode == "gap":
            return self._run_batch_instance_gap(state)
        if mode == "instances":
            job_context = self._job_context()
            if job_context is not None:
                return self._run_instances_via_queue(state, batch=True, context=job_context)
        entries: List[FunctionEntry] = state["entries"]
        svf_entries = self._svf_scope_entries(state, entries)
        entry_names = self._entry_names(entries) or self._entry_names(svf_entries)
        logger.info("Building shared code index...")
        if state.get("code_index") is None:
            state["code_index"] = CodeIndex(
                self.config.project.project_root,
                self.config.project.compile_commands_path,
                source_root=self.config.project.source_root,
                indexing_config=self.config.indexing,
                priority_functions=entry_names,
                include_paths=self.config.project.include_paths,
                exclude_paths=self.config.project.exclude_paths,
                svf_entry_functions=svf_entries,
                defer_svf=self.resume and not entries,
                svf_parallel_workers=(
                    self.config.concurrency.svf_workers or self.config.concurrency.index_workers
                ),
            )
            if self.resume and not entries:
                logger.info("Resume has no remaining entries; SVF initialization deferred.")
        else:
            self._ensure_svf_for_entries(state, entries)

        parallel_kwargs: Dict[str, Any] = {}
        parallel_kwargs["semantic_result"] = state.get("semantic_result")
        parallel_kwargs["reproduction_service"] = self.reproduction_service
        if state.get("wiki_compile_completed"):
            parallel_kwargs["project_knowledge_service"] = state.get("project_knowledge_service")
            parallel_kwargs["llm_clients"] = state.get("llm_clients")
        parallel_analyzer = ParallelAnalyzer(
            self.config,
            code_index=state["code_index"],
            force_ignore_history=not (self.resume or self.maintain),
            maintain_mode=self.maintain,
            cancellation_token=self._cancellation_token,
            benchmark_ablation_override=self._benchmark_ablation_override,
            **parallel_kwargs,
        )
        state["parallel_analyzer"] = parallel_analyzer
        discovery_result = state.get("discovery_result")
        if isinstance(discovery_result, dict):
            parallel_analyzer.deferred_entry_candidates = list(
                discovery_result.get("deferred_candidates") or []
            )
        try:
            if mode == "instances":
                # Exact per-instance dispatch: one real Analyzer run per
                # scheduled ``(BuildContext, USR)`` instance, sharing the scan
                # ledger, caches and the scan-level validation queue.
                state["instance_analysis"] = parallel_analyzer.analyze_entry_instances(
                    state.get("entry_instance_plan")
                )
                state["results"] = parallel_analyzer.last_instance_results()
            else:
                state["results"] = parallel_analyzer.analyze_function_entries(entries)
            self.batch_executor.execute(state, steps)

            json_report_path = self._report_path("zscope_batch_report", ".json")
            md_report_path = self._report_path("zscope_batch_report", ".md")
            self._backup_existing_batch_report(json_report_path)

            report_started = time.monotonic()
            combined_report = parallel_analyzer.generate_combined_report(
                state["results"],
                None,
            )
            parallel_analyzer.generate_combined_markdown_report(
                state["results"],
                md_report_path,
            )
            report_tail_seconds = round(time.monotonic() - report_started, 4)
            self._annotate_task_report(combined_report)
            self._attach_entry_instance_coverage(combined_report, state)
            combined_report.setdefault("summary", {})["report_tail_seconds"] = report_tail_seconds
            combined_report.setdefault("metadata", {})["report_tail_seconds"] = report_tail_seconds
            write_report_atomic(json_report_path, combined_report)

            total_issues = combined_report["summary"]["total_issues"]
            functions_analyzed = combined_report["summary"]["functions_analyzed"]
            analyzed_entries = getattr(
                parallel_analyzer,
                "_last_materialized_entries",
                entries,
            )
            interrupted_entries = self._interrupted_entry_names(
                analyzed_entries,
                state["results"],
            )
            interrupted = bool(getattr(parallel_analyzer, "_interrupted", False)) or bool(
                interrupted_entries
            )
            return ScanSessionResult(
                is_batch=True,
                exit_code=exit_code_for_report(
                    combined_report,
                    policy=self.exit_policy,
                    legacy_issue_count=total_issues,
                ),
                reports=[json_report_path, md_report_path],
                issues_count=total_issues,
                needs_review_count=self._needs_review_count_from_report(combined_report),
                unresolved_obligations_count=(
                    self._unresolved_obligations_count_from_report(combined_report)
                ),
                functions_analyzed=functions_analyzed,
                interrupted=interrupted,
                interrupted_entries=interrupted_entries,
                project_root=self.config.project.project_root,
                finding_status=str(combined_report.get("finding_status") or "clean"),
                completeness=str(combined_report.get("completeness") or "complete"),
                scan_outcome=str(combined_report.get("scan_outcome") or "clean"),
                task_id=self.task_id,
                task_slug=self.task_slug,
            )
        finally:
            if not getattr(parallel_analyzer, "_interrupted", False):
                close_parallel_analyzer = getattr(parallel_analyzer, "close", None)
                if callable(close_parallel_analyzer):
                    close_parallel_analyzer()

    def _run_single(self, state: Dict[str, Any]) -> ScanSessionResult:
        mode = str(state.get("instance_execution_mode") or "legacy")
        if mode == "gap":
            return self._run_single_instance_gap(state)
        if mode == "instances":
            return self._run_single_instances(state)
        entry_function = self.config.project.entry_function
        if not entry_function:
            raise ValueError("No entry function or entry functions list provided.")

        logger.info("Single mode: entry function = %s", entry_function)
        self._ensure_svf_for_entries(state, [FunctionEntry(entry_function)])
        scheduler = ScanScheduler(
            entry_workers=1,
            validator_workers=self.config.concurrency.validator_workers,
            investigator_workers=self.config.concurrency.investigator_workers,
        )
        analyzer: Optional[Analyzer] = None
        entry_started = time.monotonic()
        entry_budget_seconds = getattr(
            self.config.analysis,
            "entry_deadline_seconds",
            None,
        )
        try:
            analyzer_kwargs: Dict[str, Any] = {}
            analyzer_kwargs["semantic_result"] = state.get("semantic_result")
            analyzer_kwargs["reproduction_service"] = self.reproduction_service
            if state.get("wiki_compile_completed"):
                analyzer_kwargs["project_knowledge_service"] = state.get(
                    "project_knowledge_service"
                )
                analyzer_kwargs["llm_clients"] = state.get("llm_clients")
            analyzer = Analyzer(
                self.config,
                code_index=state.get("code_index"),
                force_ignore_history=not (self.resume or self.maintain),
                maintain_mode=self.maintain,
                cancellation_token=self._cancellation_token.child(None),
                scheduler=scheduler,
                **analyzer_kwargs,
            )
            result = analyzer.run()
        finally:
            close_analyzer = getattr(analyzer, "close", None)
            if callable(close_analyzer):
                close_analyzer()
            scheduler.shutdown(wait=True, cancel_futures=True)
        duration = max(0.0, time.monotonic() - entry_started)
        entry_budget = ParallelAnalyzer._entry_budget_metadata(
            duration_seconds=duration,
            budget_seconds=entry_budget_seconds,
            policy=self._budget_exhaustion_policy,
        )
        metadata = (
            dict(result.get("metadata") or {}) if isinstance(result.get("metadata"), dict) else {}
        )
        metadata.update(entry_budget)
        self._attach_entry_instance_coverage({"metadata": metadata}, state)
        result["metadata"] = metadata
        if entry_budget["entry_budget_exceeded"]:
            logger.warning(
                "Single-entry budget exceeded: entry=%s budget=%.2fs "
                "overrun=%.2fs policy=%s outcome=completed",
                entry_function,
                float(str(entry_budget_seconds)),
                entry_budget["entry_budget_overrun_seconds"],
                self._budget_exhaustion_policy,
            )
        # Analyzer persists the single-entry report before the session-level
        # elapsed budget is known.  Rewrite the JSON projection so the
        # observable overrun is not lost on disk.
        persisted_report_path = self.config.project.project_root / "report.json"
        self._annotate_task_report(result)
        persisted_report_path.write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        markdown_report_path = self.config.project.project_root / "report.md"
        report_paths: List[Path] = [persisted_report_path, markdown_report_path]
        if self.task_slug:
            persisted_report_path = self._report_path("report", ".json")
            persisted_report_path.write_text(
                json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            task_markdown_path = self._report_path("report", ".md")
            if markdown_report_path.is_file():
                shutil.copy2(markdown_report_path, task_markdown_path)
                report_paths = [persisted_report_path, task_markdown_path]
            else:
                report_paths = [persisted_report_path]
        elif result.get("error"):
            report_paths = [persisted_report_path]
        verdict = result.get("overall_verdict", "unknown")
        issues_count = len(result.get("issues", []))
        return ScanSessionResult(
            is_batch=False,
            exit_code=exit_code_for_report(
                result,
                policy=self.exit_policy,
                legacy_issue_count=issues_count,
            ),
            issues_count=issues_count,
            needs_review_count=self._needs_review_count_from_report(result),
            unresolved_obligations_count=(self._unresolved_obligations_count_from_report(result)),
            verdict=verdict,
            reports=report_paths,
            project_root=self.config.project.project_root,
            finding_status=str(result.get("finding_status") or "clean"),
            completeness=str(result.get("completeness") or "complete"),
            scan_outcome=str(result.get("scan_outcome") or "clean"),
            task_id=self.task_id,
            task_slug=self.task_slug,
        )

    def _build_instance_analyzer(self, state: Dict[str, Any]) -> ParallelAnalyzer:
        """One ParallelAnalyzer for exact-instance dispatch.

        No ``semantic_result`` is passed: the instance path must not consume
        project-wide modeling evidence, and it skips the shared semantics /
        deterministic fact pass over the unwrapped index by itself.
        """

        entries = list(state.get("entries") or []) or list(state.get("all_entries") or [])
        self._ensure_svf_for_entries(state, entries)
        code_index = self._ensure_code_index(state, defer_svf=True)
        analyzer = ParallelAnalyzer(
            self.config,
            code_index=code_index,
            llm_clients=state.get("llm_clients"),
            project_knowledge_service=state.get("project_knowledge_service"),
            force_ignore_history=not (self.resume or self.maintain),
            maintain_mode=self.maintain,
            cancellation_token=self._cancellation_token,
            benchmark_ablation_override=self._benchmark_ablation_override,
            reproduction_service=self.reproduction_service,
        )
        try:
            analyzer.freeze_instance_semantics(state.get("entry_instance_plan"))
        except BaseException:
            self._close_analyzer(analyzer)
            raise
        return analyzer

    # -- job-driven instance execution (JOB04/JOB06 session wiring) ----------

    @staticmethod
    def _job_context() -> Optional[Any]:
        """The owner-passed job attempt identity, or ``None`` when unwired."""

        from .jobs.scheduler_hook import session_job_context_from_env

        return session_job_context_from_env()

    @staticmethod
    def _instance_run_dir(context: Any) -> Path:
        """This attempt's own run directory inside the job directory."""

        return Path(str(context.run_dir))

    @staticmethod
    def _job_input_revision(context: Any) -> str:
        """Read the job row's bind revision (the scheduler re-verifies binding)."""

        try:
            from .jobs.store import JobStore

            row = JobStore(context.store_path).get_job(context.job_id)
        except Exception:
            return ""
        if not row:
            return ""
        return str(row.get("input_revision") or "")

    def _run_instances_via_queue(
        self, state: Dict[str, Any], *, batch: bool, context: Any
    ) -> ScanSessionResult:
        previous = state.get("parallel_analyzer")
        try:
            return self._run_instances_via_queue_owned(state, batch=batch, context=context)
        finally:
            analyzer = state.get("parallel_analyzer")
            if analyzer is not None and analyzer is not previous:
                self._close_analyzer(analyzer)

    def _run_instances_via_queue_owned(
        self, state: Dict[str, Any], *, batch: bool, context: Any
    ) -> ScanSessionResult:
        """Run the instance scan through this attempt's own work queue.

        The queue is per-run (``<run_dir>/work-queue.db``) so a fresh attempt
        never inherits a crashed attempt's verdicts, while the canonical job
        queue and its sidecars are never rewritten or removed.  The scheduler
        publishes its real ``session_scheduler_started`` receipt naming this
        queue, which is how the owner selects it.

        Cross-run reuse is authorized only by a *bound* completion receipt for
        this exact job/input/plan, verified against the producer's immutable
        file; every other attempt re-analyzes the current precise plan.
        """

        from .jobs.models import JobError
        from .jobs.scan_work import (
            InstanceWorkHandlers,
            compute_plan_fingerprint,
            instance_work_items,
        )
        from .jobs.scheduler_hook import JobWindowHook
        from .jobs.session_scheduler import WORK_QUEUE_FILENAME, SessionWorkScheduler

        plan = state.get("entry_instance_plan")
        run_dir = self._instance_run_dir(context)
        queue_path = run_dir / f"{WORK_QUEUE_FILENAME}.{uuid.uuid4().hex}"
        code_index = self._ensure_code_index(state, defer_svf=True)
        if batch:
            report_paths = [
                self._report_path("zscope_batch_report", suffix) for suffix in (".json", ".md")
            ]
        else:
            report_paths = [
                self.config.project.project_root / name for name in ("report.json", "report.md")
            ]
            report_paths.extend(self._report_path("report", suffix) for suffix in (".json", ".md"))
        # Pure native/namespace/physical collision checks precede every job
        # connection: even a read connection can create SQLite WAL/SHM names.
        runtime_outputs = code_index._prepare_job_runtime_outputs(
            context=context, plan=plan, queue_path=queue_path, report_paths=report_paths
        )
        input_revision = runtime_outputs.input_revision
        hook = JobWindowHook(
            context.store_path,
            job_id=context.job_id,
            run_id=context.run_id,
            owner_token=context.owner_token,
            run_dir=context.run_dir,
            input_revision=input_revision,
        )
        hook._bind_runtime_outputs(runtime_outputs)
        # Verify the current job/run/owner/input binding *before* any queue,
        # checkpoint, sidecar or report write/delete.  An invalid binding is a
        # hard stop: it is never a licence to touch a queue that another owner
        # may still be driving.
        binding = hook.stand_down_reason(expected_input_revision=input_revision or None)
        if binding is not None:
            raise JobError(
                binding,
                "the instance attempt binding is not current; refusing to touch the job queue",
                status_code=409,
            )
        analyzer = self._build_instance_analyzer(state)
        state["parallel_analyzer"] = analyzer
        semantics = analyzer.freeze_instance_semantics(plan)
        plan_fingerprint = compute_plan_fingerprint(
            plan, self.config, semantics_by_instance=semantics.snapshots
        )

        items = instance_work_items(plan)
        if not items:
            return (
                self._run_batch_instance_gap(state)
                if batch
                else self._run_single_instance_gap(state)
            )
        # Per-attempt queue inside this run's directory: no attempt inherits
        # another attempt's settled verdicts, the canonical job queue and its
        # sidecars are never rewritten or removed, and the real
        # ``session_scheduler_started`` receipt names this file for the owner.
        with runtime_outputs.writer():
            run_dir.mkdir(parents=True, exist_ok=True)
        with runtime_outputs.sql_writer():
            scheduler = SessionWorkScheduler(
                store_path=context.store_path,
                job_id=context.job_id,
                run_id=context.run_id,
                owner_token=context.owner_token,
                run_dir=context.run_dir,
                work_queue_path=queue_path,
                worker_count=1,
                claim_batch_size=1,
                lease_seconds=max(600.0, self._instance_lease_seconds()),
            )
        scheduler._hook._bind_runtime_outputs(runtime_outputs)
        # The analyzer is built with the session token before the window
        # watcher starts; every entry and validation run then observes the same
        # cooperative cancel/deadline instead of a token replaced after the run.
        handlers = InstanceWorkHandlers(
            plan=plan,
            analyzer=analyzer,
            run_dir=run_dir,
            input_revision=str(getattr(scheduler, "input_revision", "") or ""),
            store_path=context.store_path,
            job_id=context.job_id,
            run_id=context.run_id,
            owner_token=context.owner_token,
            plan_fingerprint=str(plan_fingerprint or ""),
            hook=hook,
            snapshot_fn=scheduler.snapshot,
        )
        for kind, handler in handlers.handlers().items():
            scheduler.register_handler(kind, handler)
        watcher = self._start_job_window_monitor(hook, self._cancellation_token)
        try:
            scheduler.submit(items)
            summary = scheduler.run()
        finally:
            self._stop_job_window_monitor(watcher)
            handlers.release()
        state["job_summary"] = summary
        state["instance_analysis"] = handlers.report_payload
        state["instance_recovery"] = handlers.recovery_summary
        state["results"] = analyzer.last_instance_results()
        return self._finalize_instance_run(
            state,
            batch=batch,
            context=context,
            summary=summary,
            completed=handlers.checkpoint_path is not None,
            input_revision=input_revision,
        )

    def _load_bound_completion(
        self,
        state: Dict[str, Any],
        *,
        context: Any,
        plan: Any,
        input_revision: str,
        plan_fingerprint: Optional[str],
        verify: Any,
    ) -> Optional[Dict[str, Any]]:
        """Restore a bound cross-run completion for this exact job/input/plan.

        ``JobStore.trusted_completion`` proves real coordinates only (current
        run/owner, exact input and exact plan fingerprint — the producer may be
        an earlier run of the same job).  The receipt's immutable file is then
        re-read and re-checked against the current plan by ``verify``.  Any
        missing, foreign, stale or unverifiable coordinate re-analyzes.
        """

        if not input_revision or not plan_fingerprint:
            return None
        try:
            from .jobs.store import JobStore

            receipt = JobStore(context.store_path).trusted_completion(
                context.job_id,
                run_id=context.run_id,
                owner_token=context.owner_token,
                input_revision=input_revision,
                plan_fingerprint=str(plan_fingerprint),
            )
        except Exception:
            logger.warning("bound completion lookup failed; re-analyzing", exc_info=True)
            return None
        if not receipt:
            return None
        restored = verify(receipt, plan=plan, input_revision=input_revision)
        if restored is None:
            logger.warning("bound completion receipt did not verify; re-analyzing")
            return None
        # The immutable file verified, but the attempt binding can flip between
        # that read and publishing the report.  Re-check the real
        # job/run/owner/input under the job row's write lock (store.bound_attempt
        # raises JobError on drift) so a handoff aborts this reader instead of
        # projecting a stale completion onto the current attempt.  Nothing is
        # written inside the block, so no second store write can self-deadlock.
        from .jobs.store import JobStore

        with JobStore(context.store_path).bound_attempt(
            job_id=context.job_id,
            run_id=context.run_id,
            owner_token=context.owner_token,
            expected_input_revision=input_revision,
        ):
            pass
        logger.info(
            "Restoring the bound instance completion produced by run %s; "
            "nothing is re-analyzed this run.",
            receipt.get("run_id"),
        )
        state["results"] = {}
        state["instance_analysis"] = restored.get("instance_analysis")
        return dict(restored)

    @staticmethod
    def _start_job_window_monitor(hook: Any, token: CancellationToken) -> Any:
        """Cooperatively cancel the scan token when the job window closes.

        The owner watchdog force-terminates a scanner that ignores its window;
        this watcher cancels the shared token instead, so the real
        Analyzer/Validator stop at a cooperative boundary and the unfinished
        queue is persisted before the owner's grace expires.
        """

        stopped = threading.Event()

        def _watch() -> None:
            while not stopped.wait(0.1):
                try:
                    if hook.cancel_requested():
                        token.cancel("job_cancel_requested")
                        return
                    if hook.stop_new_work():
                        token.cancel("job_deadline_exceeded")
                        return
                except Exception:
                    return

        thread = threading.Thread(target=_watch, name="zscope-job-window-monitor", daemon=True)
        thread.start()
        return (stopped, thread)

    @staticmethod
    def _stop_job_window_monitor(watcher: Any) -> None:
        if not watcher:
            return
        stopped, thread = watcher
        stopped.set()
        thread.join(timeout=5.0)

    @staticmethod
    def _close_analyzer(analyzer: Any) -> None:
        close = getattr(analyzer, "close", None)
        if callable(close):
            close()

    def _instance_lease_seconds(self) -> float:
        entry_deadline = getattr(self.config.analysis, "entry_deadline_seconds", None)
        if entry_deadline is None:
            return 1800.0
        try:
            return max(600.0, float(entry_deadline) * 2.0)
        except (TypeError, ValueError):
            return 1800.0

    def _finalize_instance_run(
        self,
        state: Dict[str, Any],
        *,
        batch: bool,
        context: Any,
        summary: Dict[str, Any],
        completed: bool,
        input_revision: str = "",
    ) -> ScanSessionResult:
        analyzer = state.get("parallel_analyzer")
        results = dict(state.get("results") or {})
        if analyzer is not None:
            combined = analyzer.generate_combined_report(results, None)
        else:
            combined = {
                "summary": {"total_issues": 0, "functions_analyzed": 0, "needs_review_issues": 0},
                "metadata": {},
            }
        self._annotate_task_report(combined)
        self._attach_entry_instance_coverage(combined, state)
        metadata = combined.setdefault("metadata", {})
        recovery = state.get("instance_recovery") or {}
        analyzed = int(recovery.get("analyzed_instances") or 0)
        reused = int(recovery.get("restored_instances") or 0)
        executed = int(recovery.get("executed_instances") or 0)
        restored_runs = recovery.get("restored_from_run_ids") or []
        if analyzed != reused + executed:
            raise ValueError("instance_report_settlement_partition_invalid")
        metadata["job"] = {
            "schema": "zscope.scan-session-job.v1",
            "job_id": context.job_id,
            "run_id": context.run_id,
            "status": summary.get("status"),
            "counts": summary.get("counts"),
            "remaining_count": summary.get("remaining_count"),
            "window_closed": summary.get("window_closed"),
            "cancel_observed": summary.get("cancel_observed"),
            "discovery_blocked": summary.get("discovery_blocked"),
            "pending_path": summary.get("pending_path"),
            "checkpointed": completed,
            # Reuse is reported separately from this run's own Analyzer work, and
            # the producing run is named so identical content never blurs runs.
            "restored_from_run_id": restored_runs[0] if len(restored_runs) == 1 else None,
            "restored_from_run_ids": list(restored_runs),
            "restored_instances": reused,
            "cached_instances": reused,
            "executed_instances": executed,
            "analyzed_instances": analyzed,
            "instance_recovery": recovery,
        }
        if not completed:
            combined["completeness"] = "incomplete"
            combined["scan_outcome"] = "partial"
        with self._publication_fence(context, input_revision):
            if analyzer is not None:
                analyzer.require_current_instance_inputs(require_complete=completed)
            runtime_outputs = (
                getattr(analyzer.code_index, "_job_runtime_outputs", None)
                if analyzer is not None
                else None
            )
            from ..retrieval.code_index import _JobRuntimeOutputs

            if not isinstance(runtime_outputs, _JobRuntimeOutputs):
                raise ValueError("job_runtime_output_publication_scope_missing")
            with runtime_outputs.writer():
                report_paths = self._publish_instance_reports(
                    batch=batch,
                    combined=combined,
                    results=results,
                    analyzer=analyzer,
                    restored_markdown=None,
                    runtime_outputs=runtime_outputs,
                )
        issues_count = int(combined.get("summary", {}).get("total_issues") or 0)
        return ScanSessionResult(
            is_batch=batch,
            exit_code=exit_code_for_report(
                combined, policy=self.exit_policy, legacy_issue_count=issues_count
            ),
            reports=report_paths,
            issues_count=issues_count,
            needs_review_count=self._needs_review_count_from_report(combined),
            unresolved_obligations_count=self._unresolved_obligations_count_from_report(combined),
            verdict=str(combined.get("overall_verdict") or "unknown"),
            functions_analyzed=int(combined.get("summary", {}).get("functions_analyzed") or 0),
            project_root=self.config.project.project_root,
            finding_status=str(combined.get("finding_status") or "unknown"),
            completeness=str(combined.get("completeness") or "complete"),
            scan_outcome=str(combined.get("scan_outcome") or "clean"),
            task_id=self.task_id,
            task_slug=self.task_slug,
        )

    @contextmanager
    def _publication_fence(self, context: Any, input_revision: str) -> Iterator[None]:
        """Hold the job row's write lock across the whole report publication.

        A check-only transaction is not a fence: the owner can hand the attempt
        to a newer run between an empty check and the actual file writes.  This
        keeps the same ``BEGIN IMMEDIATE`` lock (``store.bound_attempt``) open
        while the current/task JSON and Markdown are published, so a competing
        job-store writer is blocked or, if it already won, this publication is
        refused with ``JobError`` instead of rewriting the new run's report.
        The attempt ``input_revision`` captured when this run was bound is used
        as-is (never re-read here), and no scanner/model work runs in the block.
        """

        if context is None:
            yield
            return
        from .jobs.store import JobStore

        with JobStore(context.store_path).bound_attempt(
            job_id=context.job_id,
            run_id=context.run_id,
            owner_token=context.owner_token,
            expected_input_revision=input_revision or None,
        ):
            yield

    def _publish_instance_reports(
        self,
        *,
        batch: bool,
        combined: Dict[str, Any],
        results: Dict[str, ParallelAnalysisResult],
        analyzer: Optional[ParallelAnalyzer],
        restored_markdown: Optional[str],
        runtime_outputs: Optional[_JobRuntimeOutputs] = None,
    ) -> List[Path]:
        """Write the current, task and Markdown reports (inside the fence)."""

        report_paths: List[Path] = []
        if batch:
            json_report_path = self._report_path("zscope_batch_report", ".json")
            md_report_path = self._report_path("zscope_batch_report", ".md")
            self._backup_existing_batch_report(json_report_path, runtime_outputs=runtime_outputs)
            if analyzer is not None:
                analyzer.generate_combined_markdown_report(results, md_report_path)
            elif restored_markdown:
                md_report_path.write_text(restored_markdown, encoding="utf-8")
            write_report_atomic(json_report_path, combined)
            report_paths = [json_report_path, md_report_path]
        else:
            json_report_path = self.config.project.project_root / "report.json"
            md_report_path = self.config.project.project_root / "report.md"
            if analyzer is not None:
                analyzer.generate_combined_markdown_report(results, md_report_path)
            elif restored_markdown:
                md_report_path.write_text(restored_markdown, encoding="utf-8")
            write_report_atomic(json_report_path, combined)
            report_paths = [json_report_path, md_report_path]
            if self.task_slug:
                task_json = self._report_path("report", ".json")
                write_report_atomic(task_json, combined)
                task_md = self._report_path("report", ".md")
                if md_report_path.is_file():
                    shutil.copy2(md_report_path, task_md)
                    report_paths = [task_json, task_md]
                else:
                    report_paths = [task_json]
        return report_paths

    def _run_single_instances(self, state: Dict[str, Any]) -> ScanSessionResult:
        plan = state.get("entry_instance_plan")
        job_context = self._job_context()
        if job_context is not None:
            return self._run_instances_via_queue(state, batch=False, context=job_context)
        logger.info(
            "Single mode: exact compile instances = %d",
            len(getattr(plan, "instances", []) or []),
        )
        parallel_analyzer = self._build_instance_analyzer(state)
        state["parallel_analyzer"] = parallel_analyzer
        try:
            state["instance_analysis"] = parallel_analyzer.analyze_entry_instances(plan)
            state["results"] = parallel_analyzer.last_instance_results()
            combined_report = parallel_analyzer.generate_combined_report(state["results"], None)
            self._annotate_task_report(combined_report)
            self._attach_entry_instance_coverage(combined_report, state)
            markdown_report_path = self.config.project.project_root / "report.md"
            parallel_analyzer.generate_combined_markdown_report(
                state["results"], markdown_report_path
            )
            persisted_report_path = self.config.project.project_root / "report.json"
            write_report_atomic(persisted_report_path, combined_report)
            report_paths: List[Path] = [persisted_report_path, markdown_report_path]
            if self.task_slug:
                task_json = self._report_path("report", ".json")
                write_report_atomic(task_json, combined_report)
                task_md = self._report_path("report", ".md")
                if markdown_report_path.is_file():
                    shutil.copy2(markdown_report_path, task_md)
                    report_paths = [task_json, task_md]
                else:
                    report_paths = [task_json]
            issues_count = int(combined_report["summary"]["total_issues"])
            return ScanSessionResult(
                is_batch=False,
                exit_code=exit_code_for_report(
                    combined_report,
                    policy=self.exit_policy,
                    legacy_issue_count=issues_count,
                ),
                reports=report_paths,
                issues_count=issues_count,
                needs_review_count=self._needs_review_count_from_report(combined_report),
                unresolved_obligations_count=(
                    self._unresolved_obligations_count_from_report(combined_report)
                ),
                verdict=str(combined_report.get("overall_verdict") or "unknown"),
                functions_analyzed=int(combined_report["summary"].get("functions_analyzed") or 0),
                project_root=self.config.project.project_root,
                finding_status=str(combined_report.get("finding_status") or "clean"),
                completeness=str(combined_report.get("completeness") or "complete"),
                scan_outcome=str(combined_report.get("scan_outcome") or "clean"),
                task_id=self.task_id,
                task_slug=self.task_slug,
            )
        finally:
            close_analyzer = getattr(parallel_analyzer, "close", None)
            if callable(close_analyzer):
                close_analyzer()

    def _run_single_instance_gap(self, state: Dict[str, Any]) -> ScanSessionResult:
        report = self._write_instance_gap_report(state)
        json_path = self.config.project.project_root / "report.json"
        write_report_atomic(json_path, report)
        markdown_path = self.config.project.project_root / "report.md"
        markdown_path.write_text(self._instance_gap_markdown(report), encoding="utf-8")
        report_paths: List[Path] = [json_path, markdown_path]
        if self.task_slug:
            task_json = self._report_path("report", ".json")
            write_report_atomic(task_json, report)
            task_md = self._report_path("report", ".md")
            shutil.copy2(markdown_path, task_md)
            report_paths = [task_json, task_md]
        elif report.get("error"):
            report_paths = [json_path]
        return ScanSessionResult(
            is_batch=False,
            exit_code=exit_code_for_report(report, policy=self.exit_policy, legacy_issue_count=0),
            reports=report_paths,
            verdict="unknown",
            project_root=self.config.project.project_root,
            finding_status="unknown",
            completeness="incomplete",
            scan_outcome="incomplete",
            task_id=self.task_id,
            task_slug=self.task_slug,
        )

    def _run_batch_instance_gap(self, state: Dict[str, Any]) -> ScanSessionResult:
        report = self._write_instance_gap_report(state)
        json_report_path = self._report_path("zscope_batch_report", ".json")
        md_report_path = self._report_path("zscope_batch_report", ".md")
        self._backup_existing_batch_report(json_report_path)
        write_report_atomic(json_report_path, report)
        md_report_path.write_text(self._instance_gap_markdown(report), encoding="utf-8")
        return ScanSessionResult(
            is_batch=True,
            exit_code=exit_code_for_report(report, policy=self.exit_policy, legacy_issue_count=0),
            reports=[json_report_path, md_report_path],
            project_root=self.config.project.project_root,
            finding_status="unknown",
            completeness="incomplete",
            scan_outcome="incomplete",
            task_id=self.task_id,
            task_slug=self.task_slug,
        )

    @staticmethod
    def _instance_gap_markdown(report: Dict[str, Any]) -> str:
        plan = (report.get("metadata") or {}).get("entry_instances") or {}
        lines = [
            "# Z-SCOPE report",
            "",
            "No verifiable compilation instance was scheduled for this scan; the",
            "scan did not fall back to a name-only analysis of an unknown build.",
            "",
            f"- status: {plan.get('status')}",
            f"- reasons: {', '.join(plan.get('reasons') or [])}",
            f"- planned_instances: {plan.get('planned_instances')}",
        ]
        for gap in (plan.get("gaps") or [])[:50]:
            lines.append(
                f"- gap {gap.get('reason')}: {gap.get('function_name')} "
                f"({gap.get('build_context_id')})"
            )
        return "\n".join(lines) + "\n"

    def _report_path(self, stem: str, suffix: str) -> Path:
        filename = f"{stem}_{self.task_slug}{suffix}" if self.task_slug else f"{stem}{suffix}"
        return self.config.project.project_root / filename

    def _annotate_task_report(self, report: Dict[str, Any]) -> None:
        if not self.task_id:
            return
        report["task_id"] = self.task_id
        report["task_slug"] = self.task_slug
        for section_name in ("summary", "metadata", "run_manifest"):
            section = report.get(section_name)
            if isinstance(section, dict):
                section["task_id"] = self.task_id
                section["task_slug"] = self.task_slug

    @staticmethod
    def _needs_review_count_from_report(report: Dict[str, Any]) -> int:
        """Count review findings that are actually visible in the report view."""
        summary = report.get("summary")
        if isinstance(summary, dict) and "needs_review_issues" in summary:
            return int(summary.get("needs_review_issues") or 0)

        views = report.get("report_views")
        if isinstance(views, dict):
            with_review = views.get("with_needs_review")
            if isinstance(with_review, dict):
                return int(with_review.get("included_needs_review_count") or 0)

        # Older reports did not expose report views. Preserve their best
        # available count without letting the manifest override newer,
        # user-visible view accounting.
        run_manifest = report.get("run_manifest")
        if isinstance(run_manifest, dict) and "needs_review_count" in run_manifest:
            return int(run_manifest.get("needs_review_count") or 0)
        return 0

    @staticmethod
    def _unresolved_obligations_count_from_report(report: Dict[str, Any]) -> int:
        """Count all unresolved candidate obligations, including ledger-only work."""
        run_manifest = report.get("run_manifest")
        if isinstance(run_manifest, dict):
            if "unresolved_obligation_count" in run_manifest:
                return int(run_manifest.get("unresolved_obligation_count") or 0)
            if "needs_review_count" in run_manifest:
                return int(run_manifest.get("needs_review_count") or 0)

        terminal_candidates = report.get("candidate_terminal_states")
        if isinstance(terminal_candidates, list):
            terminal_count = count_unresolved_obligations(
                (),
                terminal_candidates,
            )
            if terminal_count:
                return terminal_count

        metadata = report.get("metadata")
        ledger_summary = (
            metadata.get("candidate_ledger_summary") if isinstance(metadata, dict) else None
        )
        if isinstance(ledger_summary, dict):
            by_disposition = ledger_summary.get("by_disposition")
            if isinstance(by_disposition, dict):
                return sum(
                    int(by_disposition.get(disposition) or 0)
                    for disposition in (
                        "needs_review",
                        "deferred_budget",
                        "engine_failed",
                    )
                )
            by_status = ledger_summary.get("by_status")
            if isinstance(by_status, dict):
                terminal = {
                    "confirmed",
                    "rejected_with_proof",
                    "deduplicated_alias",
                    "shadow_observation",
                }
                return sum(
                    int(count or 0)
                    for status, count in by_status.items()
                    if str(status).lower() not in terminal
                )
        return 0

    @staticmethod
    def _interrupted_entry_names(
        entries: List[FunctionEntry],
        results: Dict[str, ParallelAnalysisResult],
    ) -> List[str]:
        missing: List[str] = []
        seen = set()
        for entry in entries:
            entry_key = ParallelAnalyzer._entry_result_key(entry)
            if entry_key in results:
                continue
            name = entry.function_name
            if name in seen:
                continue
            seen.add(name)
            missing.append(name)
        return missing

    def _backup_existing_batch_report(
        self,
        json_report_path: Path,
        *,
        runtime_outputs: Optional[_JobRuntimeOutputs] = None,
    ) -> None:
        if not json_report_path.exists():
            return
        if runtime_outputs is not None:
            backup_dir = self.config.project.project_root / ".zscope_knowledge" / "backups"
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            backup_path = backup_dir / f"zscope_batch_report_{timestamp}.json"
            # A live job's precise target is checked by the original factory
            # declaration before any copy or best-effort exception handler.
            parents = runtime_outputs.prepare_backup(backup_path)
            self._copy_job_batch_backup(json_report_path, backup_path, parents)
            logger.info("Created failsafe backup of previous batch report at %s", backup_path)
            return
        try:
            backup_dir = self.config.project.project_root / ".zscope_knowledge" / "backups"
            backup_dir.mkdir(parents=True, exist_ok=True)
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            backup_path = backup_dir / f"zscope_batch_report_{timestamp}.json"
            shutil.copy2(json_report_path, backup_path)
            logger.info(
                "Created failsafe backup of previous batch report at %s",
                backup_path,
            )
        except Exception as exc:
            logger.warning("Failed to create backup of batch report: %s", exc)

    @staticmethod
    def _copy_job_batch_backup(
        source: Path, target: Path, parents: Dict[str, tuple[int, int, int, int]]
    ) -> None:
        """Publish through checked directory descriptors without following links.

        This pure filesystem block runs inside the existing Store -> namespace
        writer. Unpredictable temporary names remain inside that same fence;
        they are neither registered nor ignored by a namespace wildcard.
        """
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        directory_fd = os.open(target.anchor, directory_flags)
        temporary = f".batch-backup-{uuid.uuid4().hex}.tmp"
        temporary_created = False
        try:
            current = Path(target.anchor)
            for component in target.parent.parts:
                if component == target.anchor:
                    continue
                current /= component
                expected = parents.get(str(current))
                created = False
                try:
                    child_fd = os.open(component, directory_flags, dir_fd=directory_fd)
                except FileNotFoundError:
                    if expected is not None:
                        raise ValueError("job_runtime_output_backup_parent_disappeared")
                    os.mkdir(component, mode=0o700, dir_fd=directory_fd)
                    created = True
                    child_fd = os.open(component, directory_flags, dir_fd=directory_fd)
                child = os.fstat(child_fd)
                actual = (child.st_dev, child.st_ino, child.st_uid, child.st_mode)
                if (expected is not None and expected != actual) or (
                    expected is None and (not created or child.st_uid != os.geteuid())
                ):
                    os.close(child_fd)
                    raise ValueError("job_runtime_output_backup_parent_changed")
                os.close(directory_fd)
                directory_fd = child_fd
            actual_directory = os.fstat(directory_fd)
            visible_directory = target.parent.lstat()
            if (
                actual_directory.st_dev != visible_directory.st_dev
                or actual_directory.st_ino != visible_directory.st_ino
                or not stat.S_ISDIR(visible_directory.st_mode)
                or actual_directory.st_uid != os.geteuid()
            ):
                raise ValueError("job_runtime_output_backup_directory_not_current")
            source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(source_fd, "rb") as original:
                before = os.fstat(original.fileno())
                if not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid():
                    raise ValueError("job_runtime_output_backup_source_not_regular")
                temporary_fd = os.open(
                    temporary,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=directory_fd,
                )
                temporary_created = True
                with os.fdopen(temporary_fd, "wb") as backup:
                    shutil.copyfileobj(original, backup)
                    backup.flush()
                    after = os.fstat(original.fileno())
                    if (
                        before.st_dev,
                        before.st_ino,
                        before.st_size,
                        before.st_mtime_ns,
                        before.st_ctime_ns,
                        before.st_mode,
                        before.st_uid,
                    ) != (
                        after.st_dev,
                        after.st_ino,
                        after.st_size,
                        after.st_mtime_ns,
                        after.st_ctime_ns,
                        after.st_mode,
                        after.st_uid,
                    ):
                        raise ValueError("job_runtime_output_backup_source_changed")
                    os.fchmod(backup.fileno(), stat.S_IMODE(before.st_mode))
                    os.utime(backup.fileno(), ns=(before.st_atime_ns, before.st_mtime_ns))
                    os.fsync(backup.fileno())
                os.replace(
                    temporary,
                    target.name,
                    src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd,
                )
                temporary_created = False
        finally:
            try:
                if temporary_created:
                    os.unlink(temporary, dir_fd=directory_fd)
            finally:
                os.close(directory_fd)


def _task_slug(task_id: str) -> str:
    raw = str(task_id or "").strip()
    if not raw:
        return ""
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", raw)
    slug = re.sub(r"_+", "_", slug).strip("._-")
    if not slug:
        raise ValueError("task_id must contain at least one file-safe character")
    return slug[:120]
