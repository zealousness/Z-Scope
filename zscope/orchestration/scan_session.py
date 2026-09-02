"""Session-level scan orchestration for CLI and other frontends."""

from __future__ import annotations

import logging
import json
import re
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, cast

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
from ..retrieval.code_index import CodeIndex
from ..reporting.schema import (
    EXIT_POLICIES,
    exit_code_for_report,
    report_reuse_blockers,
    unresolved_obligation_count as count_unresolved_obligations,
)
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
        if not state.get("batch_mode"):
            return False

        self.emit("Resuming scan: determining skip points from snapshot store...")
        snapshot_store = SnapshotStore.from_config(self.config)
        code_index = self._ensure_code_index(state, defer_svf=True)
        remaining: List[FunctionEntry] = []
        skipped: List[FunctionEntry] = []

        for entry in state["entries"]:
            saved_report = self._load_current_saved_report(
                snapshot_store,
                code_index,
                entry,
            )
            if saved_report:
                blockers = report_reuse_blockers(saved_report)
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
            state["results"] = parallel_analyzer.analyze_function_entries(entries)
            self.batch_executor.execute(state, steps)

            json_report_path = self._report_path("zscope_batch_report", ".json")
            md_report_path = self._report_path("zscope_batch_report", ".md")
            self._backup_existing_batch_report(json_report_path)

            report_started = time.monotonic()
            combined_report = parallel_analyzer.generate_combined_report(
                state["results"],
                json_report_path,
            )
            parallel_analyzer.generate_combined_markdown_report(
                state["results"],
                md_report_path,
            )
            report_tail_seconds = round(time.monotonic() - report_started, 4)
            self._annotate_task_report(combined_report)
            combined_report.setdefault("summary", {})["report_tail_seconds"] = report_tail_seconds
            combined_report.setdefault("metadata", {})["report_tail_seconds"] = report_tail_seconds
            json_report_path.write_text(
                json.dumps(combined_report, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )

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

    def _backup_existing_batch_report(self, json_report_path: Path) -> None:
        if not json_report_path.exists():
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


def _task_slug(task_id: str) -> str:
    raw = str(task_id or "").strip()
    if not raw:
        return ""
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", raw)
    slug = re.sub(r"_+", "_", slug).strip("._-")
    if not slug:
        raise ValueError("task_id must contain at least one file-safe character")
    return slug[:120]
